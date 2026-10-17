// Package server exposes the HTTP API and the embedded web UI.
package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"byhz-go/internal/backend"
	"byhz-go/internal/config"
	"byhz-go/internal/playback"
	webassets "byhz-go/web"
)

// Server serves the viewer UI and the JSON API.
type Server struct {
	cfg      *config.Config
	state    *backend.State
	builder  *playback.Builder
	relay    *http.Client
	relayAlt *http.Client
}

// New creates a server.
func New(cfg *config.Config, state *backend.State, builder *playback.Builder) *Server {
	newRelayTransport := func(proxy *url.URL) *http.Transport {
		return &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) { return proxy, nil },
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConns:          50,
			IdleConnTimeout:       90 * time.Second,
		}
	}
	proxyURL := (*url.URL)(nil)
	if cfg.RelayProxy != "" {
		if parsed, err := url.Parse(cfg.RelayProxy); err == nil {
			proxyURL = parsed
		}
	}
	server := &Server{
		cfg:     cfg,
		state:   state,
		builder: builder,
		// No overall Client.Timeout: live HLS/FLV segments must stream.
		relay: &http.Client{Transport: newRelayTransport(proxyURL)},
	}
	if proxyURL != nil {
		// Prefer the proxy, but fall back to a direct connection for CDNs
		// that reject proxy egress.
		server.relayAlt = &http.Client{Transport: newRelayTransport(nil)}
	}
	return server
}

// Start runs the server until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	httpServer := &http.Server{
		Addr:              s.cfg.Addr(),
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	log.Printf("[server] listening on %s", s.cfg.Addr())
	err := httpServer.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Handler builds the HTTP handler (useful for tests).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/base", s.handleBase)
	mux.HandleFunc("/api/relogin", s.handleRelogin)
	mux.HandleFunc("/api/member_login", s.handleMemberLogin)
	mux.HandleFunc("/api/logout", s.handleLogout)
	mux.HandleFunc("/api/session", s.handleSession)
	mux.HandleFunc("/api/plats", s.handlePlats)
	mux.HandleFunc("/api/rooms", s.handleRooms)
	mux.HandleFunc("/api/search", s.handleSearch)
	mux.HandleFunc("/api/gentoken", s.handleGentoken)
	mux.HandleFunc("/api/room", s.handleRoom)
	mux.HandleFunc("/api/proxy", s.handleProxy)
	return recoverMiddleware(corsMiddleware(mux))
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

// webFiles serves the embedded UI: index.html plus css/ and js/ assets.
var webFiles = http.FileServer(http.FS(webassets.Files))

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	webFiles.ServeHTTP(w, r)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDetail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.state.EnsureBase(r.Context())
	writeJSON(w, http.StatusOK, s.state.Info())
}

func (s *Server) handleBase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeDetail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Base string `json:"base"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeDetail(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	if err := s.state.SetBase(r.Context(), body.Base); err != nil {
		writeDetail(w, http.StatusBadGateway, backend.FriendlyError(err))
		return
	}
	info := s.state.Info()
	writeJSON(w, http.StatusOK, map[string]any{"base": info.Base, "logged_in": info.LoggedIn})
}

func (s *Server) handleRelogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeDetail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.state.Relogin(r.Context()); err != nil {
		writeDetail(w, http.StatusBadGateway, backend.FriendlyError(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"logged_in": true, "base": s.state.Info().Base})
}

func (s *Server) handleMemberLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeDetail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Kind     string `json:"kind"`
		Account  string `json:"account"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeDetail(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	info, err := s.state.LoginMember(r.Context(), body.Kind, body.Account, body.Password)
	if err != nil {
		writeDetail(w, http.StatusBadRequest, backend.FriendlyError(err))
		return
	}
	out := map[string]any{"ok": true, "base": s.state.Info().Base}
	for k, v := range info {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeDetail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	info := s.state.Info()
	if err := s.state.LogoutMember(r.Context()); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":        true,
			"member":    info.Member,
			"logged_in": info.LoggedIn,
			"warning":   err.Error(),
		})
		return
	}
	info = s.state.Info()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"member":    info.Member,
		"logged_in": info.LoggedIn,
	})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDetail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	info := s.state.Info()
	writeJSON(w, http.StatusOK, map[string]any{
		"member":    info.Member,
		"account":   info.Account,
		"logged_in": info.LoggedIn,
		"base":      info.Base,
		"device":    info.Device,
		"pid":       info.PID,
	})
}

func (s *Server) handlePlats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDetail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	page := intQuery(r, "page", 1)
	pageSize := intQuery(r, "page_size", 50)
	data, err := s.state.Call(r.Context(), "/api/live/plat/list", map[string]any{
		"page": page, "page_size": pageSize,
	}, http.MethodGet, true)
	if err != nil {
		writeDetail(w, http.StatusBadGateway, backend.FriendlyError(err))
		return
	}
	obj := asMap(data)
	writeJSON(w, http.StatusOK, map[string]any{
		"count": intOf(obj["count"]),
		"list":  listOf(obj["list"]),
	})
}

func (s *Server) handleRooms(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDetail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	page := intQuery(r, "page", 1)
	pageSize := intQuery(r, "page_size", 20)
	platID := r.URL.Query().Get("plat_id")
	roomType := intQuery(r, "room_type", 0)

	var data any
	var err error
	if platID != "" {
		data, err = s.state.Call(r.Context(), "/api/live/room/list", map[string]any{
			"id":        platID,
			"room_type": roomType,
			"page":      page,
			"page_size": pageSize,
		}, http.MethodGet, true)
	} else {
		data, err = s.state.Call(r.Context(), "/api/live/room/list/hot", map[string]any{
			"page": page, "page_size": pageSize,
		}, http.MethodGet, true)
	}
	if err != nil {
		writeDetail(w, http.StatusBadGateway, backend.FriendlyError(err))
		return
	}
	obj := asMap(data)
	writeJSON(w, http.StatusOK, map[string]any{
		"count": intOf(obj["count"]),
		"list":  listOf(obj["list"]),
	})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDetail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	key := r.URL.Query().Get("key")
	page := intQuery(r, "page", 1)
	pageSize := intQuery(r, "page_size", 20)
	data, err := s.state.Call(r.Context(), "/api/live/search_room", map[string]any{
		"key": key, "page": page, "page_size": pageSize,
	}, http.MethodGet, true)
	if err != nil {
		writeDetail(w, http.StatusBadGateway, backend.FriendlyError(err))
		return
	}
	obj := asMap(data)
	writeJSON(w, http.StatusOK, map[string]any{
		"count": intOf(obj["count"]),
		"list":  listOf(obj["list"]),
	})
}

func (s *Server) handleGentoken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDetail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	data, err := s.state.GentokenData(r.Context())
	if err != nil {
		writeDetail(w, http.StatusBadGateway, backend.FriendlyError(err))
		return
	}
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	appID := strOf(data["app_id"])
	if appID == "" {
		appID = strOf(data["appid"])
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"app_id":           appID,
		"appkey_present":   strOf(data["appkey"]) != "",
		"version":          strOf(data["version"]),
		"appVersion":       strOf(data["appVersion"]),
		"appname":          strOf(data["appname"]),
		"ws_token_present": strOf(data["ws_token"]) != "",
		"raw_keys":         keys,
	})
}

func (s *Server) handleRoom(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDetail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	roomID := r.URL.Query().Get("room_id")
	if roomID == "" {
		writeDetail(w, http.StatusBadRequest, "缺少 room_id")
		return
	}
	platID := r.URL.Query().Get("plat_id")
	pwd := r.URL.Query().Get("pwd")

	var model any
	var err error
	if pwd != "" {
		if _, err := s.state.Call(r.Context(), "/api/live/room/enter_pwd", map[string]any{
			"room_id": roomID, "password": pwd,
		}, http.MethodGet, true); err != nil {
			writeDetail(w, http.StatusBadGateway, backend.FriendlyError(err))
			return
		}
		model, err = s.state.Call(r.Context(), "/api/live/room/get_pwd_room_detail", map[string]any{
			"room_id": roomID, "pwd": pwd,
		}, http.MethodGet, true)
	} else {
		model, err = s.state.Call(r.Context(), "/api/live/room/detail", map[string]any{
			"id": roomID, "plat_id": platID,
		}, http.MethodGet, true)
	}
	if err != nil {
		writeDetail(w, http.StatusBadGateway, backend.FriendlyError(err))
		return
	}
	info, err := s.builder.BuildPlayback(r.Context(), asMap(model))
	if err != nil {
		writeDetail(w, http.StatusBadGateway, "解析播放参数失败："+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// ---------------------------------------------------------------------------
// relay
// ---------------------------------------------------------------------------

var uriAttrRe = regexp.MustCompile(`URI="([^"]+)"`)

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDetail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	target := r.URL.Query().Get("url")
	parsed, err := validateRelayURL(target)
	if err != nil {
		writeDetail(w, http.StatusBadRequest, err.Error())
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		writeDetail(w, http.StatusBadRequest, "URL 格式不正确："+err.Error())
		return
	}
	req.Header.Set("user-agent", s.state.RelayUA())
	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	resp, err := s.relay.Do(req)
	if err != nil && s.relayAlt != nil {
		// Some CDNs accept direct connections but reset proxied ones.
		resp, err = s.relayAlt.Do(req)
	}
	if err != nil {
		writeDetail(w, http.StatusBadGateway, fmt.Sprintf("拉流失败（%T）：%v", err, err))
		return
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	isPlaylist := strings.HasSuffix(strings.ToLower(parsed.Path), ".m3u8") ||
		strings.Contains(strings.ToLower(contentType), "mpegurl")

	// Some CDNs serve the playlist from an extensionless URL and a generic
	// content type. Sniff the first bytes so those playlists still get their
	// relative segment/key URLs rewritten.
	var buffered []byte
	if !isPlaylist {
		head := make([]byte, 2048)
		n, readErr := io.ReadFull(resp.Body, head)
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			writeDetail(w, http.StatusBadGateway, "读取响应失败："+readErr.Error())
			return
		}
		buffered = head[:n]
		sniff := bytes.TrimPrefix(bytes.TrimLeft(buffered, " \t\r\n"), []byte{0xEF, 0xBB, 0xBF})
		if bytes.HasPrefix(sniff, []byte("#EXTM3U")) {
			isPlaylist = true
		}
	}

	if isPlaylist {
		var raw []byte
		if buffered != nil {
			rest, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
			if err != nil {
				writeDetail(w, http.StatusBadGateway, "读取播放列表失败："+err.Error())
				return
			}
			raw = append(append([]byte(nil), buffered...), rest...)
		} else {
			var err error
			raw, err = io.ReadAll(io.LimitReader(resp.Body, 32<<20))
			if err != nil {
				writeDetail(w, http.StatusBadGateway, "读取播放列表失败："+err.Error())
				return
			}
		}
		text := string(raw)
		if strings.HasPrefix(strings.TrimLeft(text, " \t\r\n"), "#EXTM3U") {
			base := parsed
			if resp.Request != nil && resp.Request.URL != nil {
				base = resp.Request.URL
			}
			text = rewritePlaylist(text, base)
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS")
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, text)
		return
	}

	for _, name := range []string{"Content-Length", "Accept-Ranges", "Content-Range", "ETag", "Last-Modified"} {
		if value := resp.Header.Get(name); value != "" {
			w.Header().Set(name, value)
		}
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(buffered)
	_, _ = io.Copy(w, resp.Body)
}

func validateRelayURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("缺少 url 参数")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("URL 格式不正确：%v", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("只允许 http/https 地址")
	}
	host := strings.ToLower(parsed.Hostname())
	switch host {
	case "", "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return nil, fmt.Errorf("不允许代理本机地址")
	}
	return parsed, nil
}

func rewritePlaylist(text string, base *url.URL) string {
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for i, line := range lines {
		stripped := strings.TrimSpace(line)
		if stripped == "" {
			continue
		}
		if strings.HasPrefix(stripped, "#") {
			lines[i] = uriAttrRe.ReplaceAllStringFunc(line, func(match string) string {
				groups := uriAttrRe.FindStringSubmatch(match)
				if len(groups) < 2 {
					return match
				}
				return `URI="` + proxied(resolveURL(base, groups[1])) + `"`
			})
		} else {
			lines[i] = proxied(resolveURL(base, stripped))
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

func resolveURL(base *url.URL, ref string) string {
	parsed, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return base.ResolveReference(parsed).String()
}

func proxied(rawURL string) string {
	return "/api/proxy?url=" + url.QueryEscape(rawURL)
}

// ---------------------------------------------------------------------------
// middleware / helpers
// ---------------------------------------------------------------------------

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("[server] panic: %v", recovered)
				writeDetail(w, http.StatusInternalServerError, fmt.Sprintf("服务内部错误：%v", recovered))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeDetail(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]any{"detail": detail})
}

func intQuery(r *http.Request, key string, def int) int {
	value := r.URL.Query().Get(key)
	if value == "" {
		return def
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return def
	}
	return n
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func listOf(v any) []any {
	if list, ok := v.([]any); ok {
		return list
	}
	return []any{}
}

func intOf(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(n))
		return i
	default:
		return 0
	}
}

func strOf(v any) string {
	if v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	case json.Number:
		return s.String()
	case int:
		return strconv.Itoa(s)
	case int64:
		return strconv.FormatInt(s, 10)
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64)
	case bool:
		if s {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprint(s)
	}
}
