// Package backend implements the app's own HTTP API protocol: MD5 signing,
// AES-CBC payload encryption, guest/member login, room browsing and playback
// parameter requests.
package backend

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"byhz-go/internal/config"
)

const (
	AppVersion = "1.2.11"
	APISalt    = "kk_baoyu"

	dohName         = "bydoh.h8ghweg.com"
	apiConfSalt     = "201906xsevMNBG01"
	apiConfAlphabet = "GHI9+JKLxyz012MNOPYbcRSTUVW8/ABCw3DEZaFXefghijklm7=nopqrsdQtuv456"
	retryAttempts   = 3
)

type dohProvider struct {
	URL    string
	Accept string
}

var (
	apiKey       = []byte("433204914B1B8C53EAA43267A3AEE87D")
	cdnPackages  = []string{"6vd-pub-api1", "6vd-pub-api2"}
	dohProviders = []dohProvider{
		{"https://1.1.1.1/dns-query", "application/dns-json"},
		{"https://1.0.0.1/dns-query", "application/dns-json"},
		{"https://8.8.8.8/resolve", "application/json"},
		{"https://8.8.4.4/resolve", "application/json"},
		{"https://223.5.5.5/resolve", "application/json"},
		{"https://223.6.6.6/resolve", "application/json"},
		{"https://101.101.101.101/resolve", "application/json"},
		{"https://9.9.9.9:5053/dns-query", "application/dns-json"},
	}
	retryStatus    = map[int]bool{429: true, 502: true, 503: true, 504: true}
	authInvalid    = map[int]bool{400: true, 401: true, 403: true, 1035: true, 1009: true}
	quotedQuotesRe = regexp.MustCompile(`"\s*"`)
)

// Error is an upstream API error, optionally carrying the raw JSON object.
type Error struct {
	Code    int
	Msg     string
	Payload map[string]any
}

func (e *Error) Error() string { return fmt.Sprintf("[%d] %s", e.Code, e.Msg) }

func newError(code int, msg string, payload map[string]any) *Error {
	return &Error{Code: code, Msg: msg, Payload: payload}
}

// State is the process-wide app session state.
type State struct {
	client *http.Client
	direct *http.Client

	loginMu sync.Mutex
	mu      sync.RWMutex
	discMu  sync.Mutex

	base    string
	token   string
	pid     string
	device  string
	ua      string
	relayUA string
	aesIV   []byte
	ivs     [][]byte

	candidates []string

	member         bool
	account        string
	memberKind     string
	memberAccount  string
	memberPassword string
}

// New builds a State from configuration.
func New(cfg *config.Config) *State {
	newTransport := func(proxy *url.URL) *http.Transport {
		return &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) { return proxy, nil },
			DialContext: (&net.Dialer{
				Timeout:   20 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // App 端同样忽略证书错误
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConns:          50,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     true,
		}
	}
	transport := newTransport(nil)
	if cfg.Proxy != "" {
		if proxyURL, err := url.Parse(cfg.Proxy); err == nil {
			transport = newTransport(proxyURL)
		}
	} else {
		transport.Proxy = http.ProxyFromEnvironment
	}

	device := cfg.Device
	if device == "" {
		device = randomHex(16)
	}
	aesIV := []byte(cfg.AESIV)
	if len(aesIV) != 16 {
		aesIV = append([]byte(nil), apiKey[:16]...)
	}
	ivs := make([][]byte, 0, 3)
	for _, iv := range [][]byte{aesIV, apiKey[:16], apiKey[16:32]} {
		if len(iv) != 16 {
			continue
		}
		dup := false
		for _, existing := range ivs {
			if bytes.Equal(existing, iv) {
				dup = true
				break
			}
		}
		if !dup {
			ivs = append(ivs, append([]byte(nil), iv...))
		}
	}

	s := &State{
		client:  &http.Client{Timeout: 60 * time.Second, Transport: transport},
		direct:  &http.Client{Timeout: 60 * time.Second, Transport: newTransport(nil)},
		base:    strings.TrimRight(cfg.APIBase, "/"),
		token:   cfg.Token,
		pid:     cfg.PID,
		device:  device,
		ua:      cfg.UserAgent,
		relayUA: cfg.RelayUA,
		aesIV:   aesIV,
		ivs:     ivs,
	}
	if s.pid == "" {
		s.pid = "0"
	}
	return s
}

// HTTPClient returns the shared upstream client.
func (s *State) HTTPClient() *http.Client { return s.client }

// DirectHTTPClient returns a client that never uses a proxy. Playback APIs
// sometimes reject proxy egress; callers can retry with this as a fallback.
func (s *State) DirectHTTPClient() *http.Client { return s.direct }

// UA returns the upstream user agent.
func (s *State) UA() string { return s.ua }

// RelayUA returns the user agent used when relaying streams.
func (s *State) RelayUA() string { return s.relayUA }

// Device returns the device id used for logins.
func (s *State) Device() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.device
}

// PID returns the invite code used for guest login.
func (s *State) PID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pid
}

// Info is a snapshot exposed to the status endpoints.
type Info struct {
	Base       string   `json:"base"`
	Candidates []string `json:"candidates"`
	LoggedIn   bool     `json:"logged_in"`
	Member     bool     `json:"member"`
	Account    string   `json:"account"`
	Device     string   `json:"device"`
	PID        string   `json:"pid"`
}

// Info returns the current snapshot.
func (s *State) Info() Info {
	s.mu.RLock()
	defer s.mu.RUnlock()
	candidates := append([]string(nil), s.candidates...)
	return Info{
		Base:       s.base,
		Candidates: candidates,
		LoggedIn:   s.token != "",
		Member:     s.member,
		Account:    s.account,
		Device:     s.device,
		PID:        s.pid,
	}
}

func (s *State) snapshotAuth() (base, token string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.base, s.token
}

// ---------------------------------------------------------------------------
// AES / signing
// ---------------------------------------------------------------------------

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded length")
	}
	n := int(data[len(data)-1])
	if n == 0 || n > blockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	for _, b := range data[len(data)-n:] {
		if int(b) != n {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-n], nil
}

func aesCBCEncrypt(plain, key, iv []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	plain = pkcs7Pad(plain, aes.BlockSize)
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return base64.StdEncoding.EncodeToString(out), nil
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
	return pkcs7Unpad(out, aes.BlockSize)
}

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func (s *State) encryptPayload(payload map[string]any) (string, error) {
	if payload == nil {
		payload = map[string]any{}
	}
	raw, err := marshalNoEscape(payload)
	if err != nil {
		return "", err
	}
	return aesCBCEncrypt(raw, apiKey, s.aesIV)
}

// DecryptResponse decrypts an upstream response, falling back to plain JSON.
func (s *State) DecryptResponse(text string) (map[string]any, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("empty response")
	}
	if raw, err := base64.StdEncoding.DecodeString(text); err == nil {
		for _, iv := range s.ivs {
			plain, err := aesCBCDecrypt(raw, apiKey, iv)
			if err != nil {
				continue
			}
			var obj map[string]any
			if err := json.Unmarshal(plain, &obj); err == nil {
				return obj, nil
			}
		}
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(text), &obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// SignedParams builds the common query/body signature fields.
func (s *State) SignedParams(payload map[string]any) (map[string]any, error) {
	ts := time.Now().Unix()
	auth := md5Hex(strconv.FormatInt(ts, 10) + APISalt)
	once := md5Hex(uuidV4() + "once" + strconv.FormatInt(ts, 10))
	data, err := s.encryptPayload(payload)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"version":          AppVersion,
		"auth":             auth,
		"once":             once,
		"auth_timestamp_s": ts,
		"os":               "android",
		"data":             data,
	}, nil
}

func paramsToValues(params map[string]any) url.Values {
	values := url.Values{}
	for key, value := range params {
		switch v := value.(type) {
		case string:
			values.Set(key, v)
		case int:
			values.Set(key, strconv.Itoa(v))
		case int64:
			values.Set(key, strconv.FormatInt(v, 10))
		case float64:
			values.Set(key, strconv.FormatFloat(v, 'f', -1, 64))
		case bool:
			values.Set(key, strconv.FormatBool(v))
		case nil:
			values.Set(key, "")
		default:
			values.Set(key, fmt.Sprint(value))
		}
	}
	return values
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

// DiscoverCandidates finds API bases via DoH and the jsDelivr npm payload.
func (s *State) DiscoverCandidates(ctx context.Context, refresh bool) ([]string, error) {
	s.discMu.Lock()
	defer s.discMu.Unlock()

	s.mu.RLock()
	cached := append([]string(nil), s.candidates...)
	s.mu.RUnlock()
	if len(cached) > 0 && !refresh {
		return cached, nil
	}

	// Do not tie discovery to the request context: browsers often abort the
	// first page load, and a cancelled discovery would cache a partial list.
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()

	candidates := make([]string, 0, 8)

	// Query all DoH providers concurrently; take the first answer instead of
	// waiting for the slowest one.
	dohCh := make(chan string, len(dohProviders))
	for _, provider := range dohProviders {
		provider := provider
		go func() { dohCh <- s.dohTXT(dctx, provider) }()
	}

	// The jsDelivr payload is a fallback; start it at the same time.
	confCh := make(chan map[string]any, len(cdnPackages))
	for _, pkg := range cdnPackages {
		pkg := pkg
		go func() { confCh <- s.fetchAPIConf(dctx, pkg) }()
	}

	appendConf := func(conf map[string]any) {
		if conf == nil {
			return
		}
		if sites, ok := conf["bbs_site"]; ok {
			switch v := sites.(type) {
			case string:
				if strings.TrimSpace(v) != "" {
					candidates = append(candidates, strings.TrimSpace(v))
				}
			case []any:
				for _, item := range v {
					if site, ok := item.(string); ok && strings.TrimSpace(site) != "" {
						candidates = append(candidates, strings.TrimSpace(site))
					}
				}
			}
		}
		if base, ok := conf["base_url"].(string); ok && strings.TrimSpace(base) != "" {
			candidates = append(candidates, strings.TrimSpace(base))
		}
	}

	txt := ""
	dohDeadline := time.After(4 * time.Second)
waitDoH:
	for range dohProviders {
		select {
		case value := <-dohCh:
			if value != "" {
				txt = value
				break waitDoH
			}
		case <-dohDeadline:
			break waitDoH
		}
	}
	if txt != "" {
		sep := "?"
		if strings.Contains(txt, "?") {
			sep = "&"
		}
		probeURL := txt + sep + "t=" + strconv.FormatInt(time.Now().UnixMilli(), 10)
		body, err := s.getText(dctx, probeURL, 5*time.Second)
		body = strings.TrimSpace(body)
		if err == nil && strings.HasPrefix(body, "http") &&
			!strings.Contains(strings.ToLower(body), "<html") && len(body) < 500 {
			candidates = append(candidates, body)
		} else {
			candidates = append(candidates, txt)
		}
		// Opportunistically pick up CDN results that already arrived, but do
		// not block the first page load on them.
		drained := false
		for !drained {
			select {
			case conf := <-confCh:
				appendConf(conf)
			default:
				drained = true
			}
		}
	} else {
		// No DoH answer: wait for the CDN payload with a hard cap.
		cdnDeadline := time.After(6 * time.Second)
	cdnWait:
		for range cdnPackages {
			select {
			case conf := <-confCh:
				appendConf(conf)
			case <-cdnDeadline:
				break cdnWait
			}
		}
	}

	seen := map[string]bool{}
	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimRight(strings.TrimSpace(candidate), "/")
		if candidate == "" {
			continue
		}
		if !strings.HasPrefix(candidate, "http") {
			candidate = "https://" + candidate
		}
		if !seen[candidate] {
			seen[candidate] = true
			result = append(result, candidate)
		}
	}

	// Keep the previous list if discovery found nothing this time.
	if len(result) == 0 {
		return cached, nil
	}

	s.mu.Lock()
	s.candidates = result
	s.mu.Unlock()
	return append([]string(nil), result...), nil
}

func (s *State) dohTXT(ctx context.Context, provider dohProvider) string {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, provider.URL, nil)
	if err != nil {
		return ""
	}
	q := req.URL.Query()
	q.Set("name", dohName)
	q.Set("type", "TXT")
	req.URL.RawQuery = q.Encode()
	req.Header.Set("accept", provider.Accept)
	resp, err := s.client.Do(req)
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	var data struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return ""
	}
	for _, ans := range data.Answer {
		if ans.Type != 16 {
			continue
		}
		txt := quotedQuotesRe.ReplaceAllString(ans.Data, "")
		txt = strings.Trim(strings.TrimSpace(txt), `"`)
		if txt != "" {
			if strings.HasPrefix(txt, "http") {
				return txt
			}
			return "https://" + txt
		}
	}
	return ""
}

func (s *State) fetchAPIConf(ctx context.Context, pkg string) map[string]any {
	metaURL := "https://data.jsdelivr.com/v1/package/npm/" + pkg
	body, err := s.getTextCtx(ctx, metaURL, 10*time.Second, nil)
	if err != nil {
		return nil
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(body), &meta); err != nil {
		return nil
	}
	latest := ""
	if tags, ok := meta["tags"].(map[string]any); ok {
		if v, ok := tags["latest"].(string); ok {
			latest = v
		}
	}
	if latest == "" {
		if versions, ok := meta["versions"].([]any); ok && len(versions) > 0 {
			if v, ok := versions[0].(string); ok {
				latest = v
			}
		}
	}
	if latest == "" {
		return nil
	}
	urls := []string{
		"https://cdn.jsdelivr.net/npm/" + pkg + "@" + latest + "/info.json",
		"https://registry.npmmirror.com/" + pkg + "/" + latest + "/files/info.json",
		"https://mirrors.cloud.tencent.com/npm/" + pkg + "/" + latest + "/files/info.json",
		"https://mirrors.huaweicloud.com/repository/npm/" + pkg + "/" + latest + "/files/info.json",
	}
	for _, rawURL := range urls {
		text, err := s.getTextCtx(ctx, rawURL, 12*time.Second, nil)
		if err != nil {
			continue
		}
		plain := apiConfDecrypt(text)
		if strings.HasPrefix(strings.TrimSpace(plain), "{") {
			var conf map[string]any
			if err := json.Unmarshal([]byte(plain), &conf); err == nil {
				return conf
			}
		}
	}
	return nil
}

func apiConfDecrypt(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	last := text[len(text)-1:]
	start := strings.Index(apiConfAlphabet, last)
	if start < 0 {
		return ""
	}
	digest := md5Hex(apiConfSalt + last)
	var out strings.Builder
	for i, ch := range text[:len(text)-1] {
		idx := strings.IndexRune(apiConfAlphabet, ch)
		if idx < 0 {
			return ""
		}
		value := (idx - start - int(digest[i%len(digest)])) % 65
		if value < 0 {
			value += 65
		}
		out.WriteByte(apiConfAlphabet[value])
	}
	b64 := out.String()
	if pad := len(b64) % 4; pad != 0 {
		b64 += strings.Repeat("=", 4-pad)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ""
	}
	return string(raw)
}

func (s *State) getText(ctx context.Context, rawURL string, timeout time.Duration) (string, error) {
	return s.getTextCtx(ctx, rawURL, timeout, nil)
}

func (s *State) getTextCtx(ctx context.Context, rawURL string, timeout time.Duration, headers map[string]string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

func (s *State) postSigned(ctx context.Context, rawURL string, payload map[string]any, token string) (*http.Response, error) {
	params, err := s.SignedParams(payload)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("user-agent", s.ua)
	req.Header.Set("content-type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	return s.client.Do(req)
}

func (s *State) loginOnceLocked(ctx context.Context) error {
	base, _ := s.snapshotAuth()
	var lastErr error
	for attempt := 0; attempt < retryAttempts; attempt++ {
		resp, err := s.postSigned(ctx, base+"/api/tourist_login", map[string]any{
			"source": "android",
			"pid":    s.pid,
			"device": s.device,
		}, "")
		if err != nil {
			lastErr = err
			if attempt == retryAttempts-1 {
				break
			}
			if !sleepCtx(ctx, time.Duration(350*(attempt+1))*time.Millisecond) {
				return err
			}
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		obj, err := s.DecryptResponse(string(body))
		if err != nil {
			lastErr = err
			break
		}
		code := intValue(obj["code"])
		if code != 200 && code != 40000 {
			return newError(code, strOr(obj["msg"], "游客登录失败"), obj)
		}
		data := mapValue(obj["data"])
		access := strOr(data["access_token"], strOr(data["token"], ""))
		tokenType := strOr(data["token_type"], "Bearer")
		if access == "" {
			return newError(-1, "游客登录响应中没有 access_token", obj)
		}
		s.mu.Lock()
		s.token = tokenType + " " + access
		s.member = false
		s.account = ""
		s.mu.Unlock()
		return nil
	}
	return fmt.Errorf("%v", lastErr)
}

func (s *State) memberLoginOnceLocked(ctx context.Context) (map[string]any, error) {
	base, token := s.snapshotAuth()
	kind := s.memberKind
	if kind == "" {
		kind = "mobile"
	}
	payload := map[string]any{
		"source":     "android",
		"device":     s.device,
		"login_type": kind,
		kind:         s.memberAccount,
		"password":   s.memberPassword,
	}
	var lastErr error
	for attempt := 0; attempt < retryAttempts; attempt++ {
		resp, err := s.postSigned(ctx, base+"/api/login", payload, token)
		if err != nil {
			lastErr = err
			if attempt == retryAttempts-1 {
				break
			}
			if !sleepCtx(ctx, time.Duration(350*(attempt+1))*time.Millisecond) {
				return nil, err
			}
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		obj, err := s.DecryptResponse(string(body))
		if err != nil {
			return nil, newError(-1, "登录响应解析失败："+err.Error(), nil)
		}
		code := intValue(obj["code"])
		if code != 200 && code != 40000 {
			return nil, newError(code, strOr(obj["msg"], "登录失败"), obj)
		}
		data := mapValue(obj["data"])
		access := strOr(data["access_token"], strOr(data["token"], ""))
		tokenType := strOr(data["token_type"], "Bearer")
		if access == "" {
			return nil, newError(-1, "登录响应中没有 access_token", obj)
		}
		s.mu.Lock()
		s.token = tokenType + " " + access
		s.member = true
		s.account = s.memberAccount
		s.mu.Unlock()
		return data, nil
	}
	return nil, fmt.Errorf("%v", lastErr)
}

// EnsureLogin makes sure a usable token exists.
func (s *State) EnsureLogin(ctx context.Context, force bool) error {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()

	s.mu.RLock()
	token := s.token
	member := s.member
	password := s.memberPassword
	account := s.memberAccount
	base := s.base
	s.mu.RUnlock()

	if token != "" && !force {
		return nil
	}

	// A member token expired: try the cached credentials before falling back
	// to a guest login, so we don't silently downgrade.
	if force && member && password != "" && account != "" {
		if _, err := s.memberLoginOnceLocked(ctx); err == nil {
			return nil
		}
	}

	candidates := make([]string, 0, 4)
	if base != "" {
		candidates = append(candidates, base)
	}
	if discovered, err := s.DiscoverCandidates(ctx, force); err == nil {
		for _, candidate := range discovered {
			if !containsString(candidates, candidate) {
				candidates = append(candidates, candidate)
			}
		}
	}
	if len(candidates) == 0 {
		return newError(-1, "没有可用的 API 地址；请设置 API_BASE 或在页面里手动填写", nil)
	}

	var lastErr error
	for _, candidate := range candidates {
		s.mu.Lock()
		s.base = candidate
		s.token = ""
		s.mu.Unlock()
		if err := s.loginOnceLocked(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return newError(-1, fmt.Sprintf("游客登录失败：%v", lastErr), nil)
}

// LoginMember logs in with a phone/email account and password.
func (s *State) LoginMember(ctx context.Context, kind, account, password string) (map[string]any, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" {
		kind = "mobile"
	}
	if kind != "mobile" && kind != "email" {
		return nil, newError(-1, "登录类型只能是 email 或 mobile", nil)
	}
	account = strings.TrimSpace(account)
	if account == "" {
		return nil, newError(-1, "请填写账号", nil)
	}
	if len(password) < 6 {
		return nil, newError(-1, "密码至少 6 位", nil)
	}

	s.mu.RLock()
	base := s.base
	s.mu.RUnlock()
	if base == "" {
		if err := s.EnsureLogin(ctx, true); err != nil {
			return nil, err
		}
	} else if err := s.EnsureLogin(ctx, false); err != nil {
		return nil, err
	}

	s.loginMu.Lock()
	s.memberKind = kind
	s.memberAccount = account
	s.memberPassword = password
	data, err := s.memberLoginOnceLocked(ctx)
	if err != nil {
		s.memberPassword = ""
	}
	s.loginMu.Unlock()
	if err != nil {
		return nil, err
	}

	profile := map[string]any{}
	if got, err := s.Call(ctx, "/api/my/profile", nil, http.MethodGet, true); err == nil {
		if m, ok := got.(map[string]any); ok {
			profile = m
		}
	}
	name := strOr(profile["nickname"], strOr(profile["username"], ""))
	return map[string]any{
		"account":    account,
		"name":       name,
		"member":     true,
		"expires_in": data["expires_in"],
	}, nil
}

// LogoutMember clears member credentials and returns to a guest session.
func (s *State) LogoutMember(ctx context.Context) error {
	s.loginMu.Lock()
	s.mu.Lock()
	s.member = false
	s.account = ""
	s.token = ""
	s.memberKind = ""
	s.memberAccount = ""
	s.memberPassword = ""
	s.mu.Unlock()
	s.loginMu.Unlock()
	return s.EnsureLogin(ctx, true)
}

// SetBase sets or clears the API base, then forces a login.
func (s *State) SetBase(ctx context.Context, base string) error {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	s.loginMu.Lock()
	s.mu.Lock()
	s.token = ""
	if base != "" {
		s.base = base
		s.candidates = nil
	} else {
		s.base = ""
	}
	s.mu.Unlock()
	s.loginMu.Unlock()
	return s.EnsureLogin(ctx, true)
}

// Relogin forces a fresh login.
func (s *State) Relogin(ctx context.Context) error {
	s.loginMu.Lock()
	s.mu.Lock()
	s.token = ""
	s.mu.Unlock()
	s.loginMu.Unlock()
	return s.EnsureLogin(ctx, true)
}

// EnsureBase performs discovery if no base is configured yet.
func (s *State) EnsureBase(ctx context.Context) {
	s.mu.RLock()
	base := s.base
	s.mu.RUnlock()
	if base != "" {
		return
	}
	candidates, err := s.DiscoverCandidates(ctx, false)
	if err != nil || len(candidates) == 0 {
		return
	}
	s.mu.Lock()
	if s.base == "" {
		s.base = candidates[0]
	}
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Business requests
// ---------------------------------------------------------------------------

// Call performs a signed business request and returns the response data.
func (s *State) Call(ctx context.Context, path string, payload map[string]any, method string, retry bool) (any, error) {
	if err := s.EnsureLogin(ctx, false); err != nil {
		return nil, err
	}
	base, token := s.snapshotAuth()
	rawURL := base + path
	method = strings.ToUpper(method)
	if method == "" {
		method = http.MethodGet
	}

	var body []byte
	var statusCode int
	var decrypted map[string]any
	var lastErr error
	for attempt := 0; attempt < retryAttempts; attempt++ {
		params, err := s.SignedParams(payload)
		if err != nil {
			return nil, newError(-1, err.Error(), nil)
		}
		req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
		if err != nil {
			return nil, newError(-1, err.Error(), nil)
		}
		req.Header.Set("user-agent", s.ua)
		if token != "" {
			req.Header.Set("Authorization", token)
		}
		if method == http.MethodGet {
			req.URL.RawQuery = paramsToValues(params).Encode()
		} else {
			encoded, err := json.Marshal(params)
			if err != nil {
				return nil, newError(-1, err.Error(), nil)
			}
			req.Body = io.NopCloser(bytes.NewReader(encoded))
			req.ContentLength = int64(len(encoded))
			req.Header.Set("content-type", "application/json")
		}

		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			if attempt == retryAttempts-1 {
				return nil, newError(-1, fmt.Sprintf("上游请求失败（%T）：%v", err, err), nil)
			}
			if !sleepCtx(ctx, time.Duration(350*(attempt+1))*time.Millisecond) {
				return nil, newError(-1, err.Error(), nil)
			}
			continue
		}
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		statusCode = resp.StatusCode
		if retryStatus[statusCode] && attempt < retryAttempts-1 {
			if !sleepCtx(ctx, time.Duration(350*(attempt+1))*time.Millisecond) {
				return nil, newError(-1, fmt.Sprintf("上游 HTTP %d", statusCode), nil)
			}
			continue
		}
		decrypted, lastErr = s.DecryptResponse(string(body))
		if lastErr != nil {
			preview := string(body)
			if len(preview) > 300 {
				preview = preview[:300]
			}
			return nil, newError(-1, fmt.Sprintf("响应解析失败：%v；HTTP %d；body=%s", lastErr, statusCode, preview), nil)
		}
		break
	}
	if decrypted == nil {
		return nil, newError(-1, fmt.Sprintf("上游请求失败：%v", lastErr), nil)
	}

	code := intValue(decrypted["code"])
	if authInvalid[code] && retry {
		if err := s.EnsureLogin(ctx, true); err != nil {
			return nil, err
		}
		return s.Call(ctx, path, payload, method, false)
	}
	if code != 200 && code != 40000 {
		return nil, newError(code, strOr(decrypted["msg"], "请求失败"), decrypted)
	}
	return decrypted["data"], nil
}

// GentokenData fetches the gentoken payload. code=20000 still has valid data.
func (s *State) GentokenData(ctx context.Context) (map[string]any, error) {
	data, err := s.Call(ctx, "/api/collect/live/gentoken", nil, http.MethodGet, true)
	if err == nil {
		if m, ok := data.(map[string]any); ok {
			return m, nil
		}
		return map[string]any{}, nil
	}
	if apiErr, ok := err.(*Error); ok && apiErr.Payload != nil {
		if m, ok := apiErr.Payload["data"].(map[string]any); ok {
			return m, nil
		}
	}
	return nil, err
}

// FriendlyError translates upstream errors into user-facing text.
func FriendlyError(err error) string {
	apiErr, ok := err.(*Error)
	if !ok {
		return err.Error()
	}
	code := apiErr.Code
	msg := apiErr.Msg
	if msg == "" {
		msg = "请求失败"
	}
	switch {
	case authInvalid[code] || strings.Contains(msg, "登录已失效"):
		return msg + "（已自动尝试重新登录，请再点一次房间）"
	case code == 1003 || strings.Contains(msg, "观看次数不足"):
		return msg + "（游客观看配额已用尽，请用手机号/邮箱登录会员账号后再试）"
	case strings.Contains(msg, "获取数据失败"):
		return msg + "（上游平台拉取房间失败：该平台或房间暂时不可用，换一个房间/平台，或稍后再试）"
	case code == 1001:
		return msg + "（上游参数校验失败，通常是房间已下线或平台接口变动）"
	default:
		return msg
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func md5Hex(text string) string {
	sum := md5.Sum([]byte(text))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func uuidV4() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0F) | 0x40
	b[8] = (b[8] & 0x3F) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func intValue(v any) int {
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
	case bool:
		if n {
			return 1
		}
		return 0
	default:
		return 0
	}
}

func strOr(v any, def string) string {
	if v == nil {
		return def
	}
	switch s := v.(type) {
	case string:
		if s == "" {
			return def
		}
		return s
	case json.Number:
		return s.String()
	case int:
		return strconv.Itoa(s)
	case int64:
		return strconv.FormatInt(s, 10)
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64)
	default:
		text := fmt.Sprint(v)
		if text == "" {
			return def
		}
		return text
	}
}

func mapValue(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
