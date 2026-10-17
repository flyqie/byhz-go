// Package playback turns a room-detail model into browser playback parameters.
package playback

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"byhz-go/internal/backend"
	"byhz-go/internal/kiwi"
)

const (
	tokenTTL = 10 * time.Minute
	loginTTL = 30 * time.Minute
)

type loginEntry struct {
	expires time.Time
	info    map[string]string
}

type tokenEntry struct {
	expires time.Time
	info    map[string]string
}

// nativeSession mirrors the app's UserManager cache: the guest JWT, user id,
// APNs code and generated device UUID survive process restarts.
type nativeSession struct {
	Token    string `json:"guest_token,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	ApnsCode string `json:"apns_code,omitempty"`
	UUID     string `json:"uuid,omitempty"`
	SavedAt  int64  `json:"saved_at"`
}

type nativeStore struct {
	Sessions map[string]nativeSession `json:"sessions"`
}

// Builder resolves playback parameters and caches Agora tokens.
type Builder struct {
	state *backend.State
	debug bool

	mu      sync.Mutex
	clients map[string]*kiwi.Client
	logins  map[string]loginEntry
	tokens  map[string]tokenEntry

	fileMu   sync.Mutex
	sessions map[string]nativeSession
}

// New creates a playback builder.
func New(state *backend.State, debug bool) *Builder {
	b := &Builder{
		state:    state,
		debug:    debug,
		clients:  map[string]*kiwi.Client{},
		logins:   map[string]loginEntry{},
		tokens:   map[string]tokenEntry{},
		sessions: map[string]nativeSession{},
	}
	b.loadNativeSessions()
	return b
}

// NativeAgoraPlay reproduces AgoraPlayManager: open the kiwi_live tunnel,
// guest-login, then ask /stream/generate_agora_token for a token.
func (b *Builder) NativeAgoraPlay(appkey string, gentoken map[string]any, channelID string) (map[string]string, error) {
	now := time.Now()
	appkeyMD5 := md5Hex(appkey)
	cacheKey := appkeyMD5 + "|" + channelID

	b.mu.Lock()
	if hit, ok := b.tokens[cacheKey]; ok && hit.expires.After(now) {
		out := cloneMap(hit.info)
		b.mu.Unlock()
		return out, nil
	}
	client := b.clients[appkeyMD5]
	b.mu.Unlock()

	if client == nil {
		created, err := kiwi.NewClient(appkey)
		if err != nil {
			return nil, err
		}
		b.mu.Lock()
		if existing := b.clients[appkeyMD5]; existing != nil {
			client = existing
		} else {
			b.clients[appkeyMD5] = created
			client = created
		}
		b.mu.Unlock()
	}
	native := kiwi.NewNativeAgora(client)
	if b.debug {
		log.Printf("[agora] appkey_md5=%s channel=%s generate-token=%v",
			appkeyMD5, channelID, gentoken["generate-token"])
	}

	b.mu.Lock()
	cachedLogin, hasLogin := b.logins[appkeyMD5]
	b.mu.Unlock()

	storedUUID := b.deviceUUID(appkeyMD5)

	doLogin := func() (map[string]string, error) {
		info, err := native.GuestLogin(strOf(gentoken["generate-token"]), storedUUID)
		if err != nil {
			return nil, err
		}
		expires := loginExpiry(info["guest_token"])
		b.mu.Lock()
		b.logins[appkeyMD5] = loginEntry{expires: expires, info: cloneMap(info)}
		b.mu.Unlock()
		if info["uuid"] != "" {
			storedUUID = info["uuid"]
		}
		b.saveNativeSession(appkeyMD5, nativeSession{
			Token:    info["guest_token"],
			UserID:   info["user_id"],
			ApnsCode: info["apns_code"],
			UUID:     info["uuid"],
		})
		return info, nil
	}

	login := cachedLogin.info
	if !hasLogin || cachedLogin.expires.Before(now) || login == nil {
		var err error
		login, err = doLogin()
		if err != nil {
			return nil, err
		}
	}

	appVersion := strOf(gentoken["appVersion"])
	if appVersion == "" {
		appVersion = "20260226001"
	}
	token, err := native.RequestAgoraToken(channelID, login["user_id"], login["guest_token"], login["apns_code"], appVersion)
	if err != nil {
		// The cached guest JWT may be expired: drop it (keeping the device
		// UUID) and log in once more.
		b.dropNativeToken(appkeyMD5)
		login, err = doLogin()
		if err != nil {
			return nil, err
		}
		token, err = native.RequestAgoraToken(channelID, login["user_id"], login["guest_token"], login["apns_code"], appVersion)
		if err != nil {
			return nil, err
		}
	}

	appID := strOf(gentoken["appid"])
	if appID == "" {
		appID = kiwi.AgoraAppID
	}
	info := map[string]string{
		"appId":     appID,
		"token":     token,
		"channelId": channelID,
		"uid":       login["user_id"],
	}
	b.mu.Lock()
	b.tokens[cacheKey] = tokenEntry{expires: time.Now().Add(tokenTTL), info: cloneMap(info)}
	b.mu.Unlock()
	return info, nil
}

// BuildPlayback resolves the playback route for a room-detail model.
func (b *Builder) BuildPlayback(ctx context.Context, model map[string]any) (map[string]any, error) {
	if model == nil {
		return nil, fmt.Errorf("房间详情格式异常")
	}
	encrypt := model["encrypt"]
	encryptType := strings.TrimSpace(strOf(model["encrypt_type"]))
	yunceng := boolOf(model["yunceng"])
	ext := mapValue(model["encrypt_ext"])
	playURL := strings.TrimSpace(strOf(model["play_url"]))
	realRoomID := strOf(model["real_room_id"])

	baseInfo := map[string]any{
		"room_id":      model["room_id"],
		"real_room_id": realRoomID,
		"name":         strOf(model["name"]),
		"cover":        strOf(model["cover"]),
		"encrypt_type": encryptType,
		"yunceng":      yunceng,
		"encrypt":      encrypt,
	}

	agora := pickAgora(model)
	if encryptType == "agora" {
		if agora["appId"] != "" && agora["token"] != "" && agora["channelId"] != "" {
			out := clone(baseInfo)
			out["mode"] = "agora"
			out["format"] = "agora"
			out["appId"] = agora["appId"]
			out["token"] = agora["token"]
			out["channelId"] = agora["channelId"]
			out["uid"] = agora["uid"]
			out["renew"] = false
			out["note"] = "服务端下发的 Agora token；浏览器以观众身份加入频道。"
			return out, nil
		}
		gentoken := b.gentoken(ctx)
		appkey := strOf(model["appkey"])
		if appkey == "" {
			appkey = strOf(gentoken["appkey"])
		}
		channel := realRoomID
		if channel == "" {
			channel = strOf(model["room_id"])
		}
		if appkey != "" && channel != "" {
			if native, err := b.NativeAgoraPlay(appkey, gentoken, channel); err == nil {
				out := clone(baseInfo)
				out["mode"] = "agora"
				out["format"] = "agora"
				for k, v := range native {
					out[k] = v
				}
				out["renew"] = false
				out["note"] = "服务端参数不完整，已通过 native Kiwi 流程实时生成 Agora token。"
				return out, nil
			}
		}
		return nil, fmt.Errorf("Agora 播放参数不完整（appId/token/channelId 为空）")
	}

	if yunceng {
		gentoken := b.gentoken(ctx)
		if agora["appId"] != "" && agora["token"] != "" && agora["channelId"] != "" {
			out := clone(baseInfo)
			out["mode"] = "agora"
			out["format"] = "agora"
			out["appId"] = agora["appId"]
			out["token"] = agora["token"]
			out["channelId"] = agora["channelId"]
			out["uid"] = agora["uid"]
			out["renew"] = false
			out["note"] = "服务端下发的 Agora token。"
			return out, nil
		}
		appkey := strOf(model["appkey"])
		if appkey == "" {
			appkey = strOf(gentoken["appkey"])
		}
		channelID := realRoomID
		if channelID == "" {
			channelID = strOf(model["room_id"])
		}
		note := ""
		if appkey != "" && channelID != "" {
			if native, err := b.NativeAgoraPlay(appkey, gentoken, channelID); err == nil {
				out := clone(baseInfo)
				out["mode"] = "agora"
				out["format"] = "agora"
				for k, v := range native {
					out[k] = v
				}
				out["renew"] = false
				out["note"] = "通过纯 Go 复刻的 libkiwi（kiwi_live 隧道 + 游客登录 + protobuf/Rabbit）实时生成的 Agora token。"
				return out, nil
			} else {
				note = "native Agora token 获取失败：" + err.Error() +
					"（该错误由上游 kiwi_live 返回，通常是风控或登录频率限制，稍后重试）"
			}
		} else {
			note = "房间详情缺少 appkey/real_room_id，无法生成 token"
		}
		out := clone(baseInfo)
		out["mode"] = "unsupported"
		out["reason"] = "yunceng"
		out["appId"] = strOf(gentoken["appid"])
		out["channelId"] = channelID
		out["uid"] = ""
		out["note"] = note + "；请稍后重试或选择其他直播间。"
		return out, nil
	}

	if boolOf(encrypt) && encryptType == "xnm" {
		reqURL := strings.TrimSpace(strOf(ext["reqUrl"]))
		if b.debug {
			log.Printf("[xnm] url=%s token_len=%d butter_len=%d",
				reqURL, len(strOf(ext["token"])), len(strOf(ext["butter"])))
		}
		if reqURL == "" {
			return nil, fmt.Errorf("xnm 房间缺少 encrypt_ext.reqUrl")
		}
		pull, err := b.xnmPlay(ctx, reqURL, strOf(ext["token"]), strOf(ext["butter"]))
		if err != nil {
			return nil, err
		}
		out := clone(baseInfo)
		out["mode"] = "hls"
		playable, converted := browserPlayable(pull)
		out["format"] = guessFormat(playable)
		out["url"] = proxied(playable)
		out["origin"] = pull
		if converted != "" {
			out["note"] = "小奶猫 pull_url（" + converted + "），经本地 relay 转发。"
		} else {
			out["note"] = "小奶猫 pull_url，经本地 relay 转发。"
		}
		return out, nil
	}

	if playURL != "" {
		playable, converted := browserPlayable(playURL)
		out := clone(baseInfo)
		out["mode"] = "hls"
		out["format"] = guessFormat(playable)
		out["url"] = proxied(playable)
		out["origin"] = playURL
		if converted != "" {
			out["note"] = "play_url " + converted + "，经本地 relay 转发（解决 CORS 与地址改写）。"
		} else {
			out["note"] = "play_url 经本地 relay 转发（解决 CORS 与地址改写）。"
		}
		return out, nil
	}

	return nil, fmt.Errorf("没有可用的播放地址（主播可能已离线）")
}

func (b *Builder) gentoken(ctx context.Context) map[string]any {
	data, err := b.state.GentokenData(ctx)
	if err != nil || data == nil {
		return map[string]any{}
	}
	return data
}

func (b *Builder) xnmPlay(ctx context.Context, reqURL, token, butter string) (string, error) {
	parsed, err := url.Parse(reqURL)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Host = parsed.Host
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Live-Butter2", butter)
	req.Header.Set("knockknock", "synergy")
	req.Header.Set("X-Live-Pretty", "spring")
	req.Header.Set("x-accept-puzzle", "cola,tiger,tiger2,panda")
	req.Header.Set("user-agent", "okhttp/4.8.0")
	resp, err := b.state.HTTPClient().Do(req)
	if err != nil {
		// Some playback APIs reject proxy egress; retry directly.
		req = req.Clone(ctx)
		resp, err = b.state.DirectHTTPClient().Do(req)
		if err != nil {
			return "", err
		}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	body := strings.TrimSpace(string(raw))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("小奶猫接口 HTTP %d（content-type=%s，body=%s）",
			resp.StatusCode, resp.Header.Get("Content-Type"), previewText(body, 120))
	}

	// XnmHttp.GetPlayUrl derives AES-128 key/IV from md5(token):
	// key = md5Hex(token)[0:16], iv = md5Hex(token)[16:32].
	sum := md5.Sum([]byte(strings.TrimSpace(token)))
	digest := hex.EncodeToString(sum[:])
	key := []byte(digest[:16])
	iv := []byte(digest[16:32])
	plain := []byte(body)
	if decoded, err := base64.StdEncoding.DecodeString(body); err == nil {
		if decrypted, err := aesCBCDecrypt(decoded, key, iv); err == nil {
			plain = decrypted
		}
	}
	var obj map[string]any
	if err := json.Unmarshal(plain, &obj); err != nil {
		if b.debug {
			log.Printf("[xnm] url=%s content-type=%s len=%d body=%s",
				reqURL, resp.Header.Get("Content-Type"), len(body), body)
		}
		return "", fmt.Errorf("小奶猫接口返回格式异常：%v（content-type=%s，body=%s）",
			err, resp.Header.Get("Content-Type"), previewText(body, 120))
	}
	if code, ok := obj["code"]; ok && code != nil && floatOf(code) != 0 {
		return "", fmt.Errorf("%s", strOf(obj["msg"]))
	}
	data := mapValue(obj["data"])
	if online, ok := data["online"]; ok && !boolOf(online) {
		return "", fmt.Errorf("主播已离线")
	}
	stream := mapValue(data["stream"])
	pull := strOf(stream["pull_url"])
	if pull == "" {
		pull = strOf(stream["pullUrl"])
	}
	if pull == "" {
		return "", fmt.Errorf("小奶猫接口没有返回 pull_url")
	}
	return pull, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func pickAgora(model map[string]any) map[string]string {
	ext := mapValue(model["encrypt_ext"])
	agora := mapValue(model["agora_play_info"])
	pick := func(key string) string {
		value := strOf(agora[key])
		if value == "" {
			value = strOf(ext[key])
		}
		return value
	}
	return map[string]string{
		"appId":     pick("appId"),
		"token":     pick("token"),
		"channelId": pick("channelId"),
		"uid":       pick("uid"),
	}
}

// browserPlayable converts protocols the browser cannot open into an
// equivalent HTTP endpoint. RTMP live streams on Tencent/Ali style CDNs are
// also served as HTTP-FLV by appending ".flv" to the stream path.
func browserPlayable(raw string) (string, string) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw, ""
	}
	switch strings.ToLower(parsed.Scheme) {
	case "rtmp", "rtmps":
		if !strings.HasSuffix(strings.ToLower(parsed.Path), ".flv") {
			parsed.Path += ".flv"
		}
		parsed.Scheme = "https"
		return parsed.String(), "RTMP 已转换为 HTTPS-FLV"
	default:
		return raw, ""
	}
}

func guessFormat(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	path := rawURL
	if err == nil {
		path = parsed.Path
	}
	path = strings.ToLower(path)
	switch {
	case strings.HasSuffix(path, ".m3u8"):
		return "hls"
	case strings.HasSuffix(path, ".flv"):
		return "flv"
	case strings.HasSuffix(path, ".mp4"):
		return "mp4"
	case strings.HasSuffix(path, ".ts"):
		return "ts"
	default:
		return "hls"
	}
}

func proxied(rawURL string) string {
	return "/api/proxy?url=" + url.QueryEscape(rawURL)
}

func aesCBCDecrypt(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid ciphertext length")
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	if len(out) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}
	n := int(out[len(out)-1])
	if n == 0 || n > aes.BlockSize || n > len(out) {
		return nil, fmt.Errorf("invalid padding")
	}
	for _, b := range out[len(out)-n:] {
		if int(b) != n {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return out[:len(out)-n], nil
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

func boolOf(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != "" && t != "0" && strings.ToLower(t) != "false"
	default:
		return floatOf(v) != 0
	}
}

func floatOf(v any) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case float64:
		return n
	case json.Number:
		f, _ := n.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(n), 64)
		return f
	case bool:
		if n {
			return 1
		}
		return 0
	default:
		return 0
	}
}

func mapValue(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func clone(source map[string]any) map[string]any {
	out := make(map[string]any, len(source)+8)
	for k, v := range source {
		out[k] = v
	}
	return out
}

func cloneMap(source map[string]string) map[string]string {
	out := make(map[string]string, len(source))
	for k, v := range source {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// persistent native guest session
// ---------------------------------------------------------------------------

func nativeStorePath() string {
	// Keep the session next to the executable, not in %LOCALAPPDATA%.
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		return filepath.Join(filepath.Dir(exe), "native_guest.json")
	}
	return "native_guest.json"
}

// loadNativeSessions restores the app's cached guest account so a restart
// does not create a brand-new guest (which upstream risk control dislikes).
func (b *Builder) loadNativeSessions() {
	b.fileMu.Lock()
	defer b.fileMu.Unlock()
	raw, err := os.ReadFile(nativeStorePath())
	if err != nil {
		return
	}
	var doc nativeStore
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Sessions == nil {
		return
	}
	b.sessions = doc.Sessions
	now := time.Now()
	for key, entry := range doc.Sessions {
		if entry.Token == "" || entry.UserID == "" {
			continue
		}
		expires := loginExpiry(entry.Token)
		if !expires.After(now) {
			continue
		}
		b.mu.Lock()
		b.logins[key] = loginEntry{expires: expires, info: map[string]string{
			"guest_token": entry.Token,
			"user_id":     entry.UserID,
			"apns_code":   entry.ApnsCode,
			"uuid":        entry.UUID,
		}}
		b.mu.Unlock()
	}
}

func (b *Builder) saveNativeSession(key string, session nativeSession) {
	b.fileMu.Lock()
	defer b.fileMu.Unlock()
	session.SavedAt = time.Now().Unix()
	b.sessions[key] = session
	b.persistLocked()
}

// dropNativeToken clears an expired JWT but keeps the device UUID so the next
// guest login reuses the same identity.
func (b *Builder) dropNativeToken(key string) {
	b.fileMu.Lock()
	defer b.fileMu.Unlock()
	session := b.sessions[key]
	session.Token = ""
	session.UserID = ""
	b.sessions[key] = session
	b.persistLocked()
}

func (b *Builder) deviceUUID(key string) string {
	b.fileMu.Lock()
	defer b.fileMu.Unlock()
	return b.sessions[key].UUID
}

func (b *Builder) persistLocked() {
	path := nativeStorePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	raw, err := json.MarshalIndent(nativeStore{Sessions: b.sessions}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, raw, 0o600)
}

func loginExpiry(token string) time.Time {
	if exp, ok := jwtExpiry(token); ok {
		return exp
	}
	return time.Now().Add(loginTTL)
}

// jwtExpiry reads "exp" from a JWT without verifying the signature.
func jwtExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}

// previewText shortens a response body for error messages.
func previewText(text string, limit int) string {
	text = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, text)
	if len(text) > limit {
		text = text[:limit] + "..."
	}
	return text
}

func md5Hex(text string) string {
	sum := md5.Sum([]byte(text))
	return hex.EncodeToString(sum[:])
}
