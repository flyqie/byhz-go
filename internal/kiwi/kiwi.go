// Package kiwi is a pure-Go reimplementation of libkiwi.so's network tunnel
// used by the app for live streaming (yunceng). It covers:
//
//	KiwiAppkey::ParseAppkey / DecryptData / GenerateCodeTable / GetKiwiItem
//	KiwiCore::Init / TryRequestAPIServer / Dns / DnsEx
//	KiwiProxy::TcpProxy / TcpSession / TcpBridge
//	IntSecret::Encode / Decode
package kiwi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	appKeyAESKey = "IG8n1jWzj8qajhZB"
	appKeyAESIV  = "fRNo%9vxfVEIj1sa"

	RouteMagic         = 0xB2A1
	RouteHandshakeSize = 16
	APIRouteType       = 2
	APIC2SKey          = 0x3F
	DefaultPortKey     = 53931
	SDKVersion         = "A521"
	SessionInit        = "init"
	DefaultAppName     = "鲍鱼盒子##co.rjm1tdo8oef0"
)

// Error is a Kiwi protocol/network error.
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

func errorf(format string, args ...any) error { return fmt.Errorf(format, args...) }

// MD5Hex returns the lowercase hex MD5 of s.
func MD5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func bswap32(v uint32) uint32 {
	return v<<24 | (v&0xFF00)<<8 | (v>>8)&0xFF00 | v>>24
}

// DecryptAppkey decrypts base64(AES-128-CBC(JSON)) into a config object.
func DecryptAppkey(appkeyB64 string) (map[string]any, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(appkeyB64))
	if err != nil {
		return nil, errorf("appkey base64: %w", err)
	}
	block, err := aes.NewCipher([]byte(appKeyAESKey))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw)%aes.BlockSize != 0 {
		return nil, errorf("appkey ciphertext length %d", len(raw))
	}
	out := make([]byte, len(raw))
	cipher.NewCBCDecrypter(block, []byte(appKeyAESIV)).CryptBlocks(out, raw)

	padLen := int(out[len(out)-1])
	if padLen >= 1 && padLen <= aes.BlockSize {
		out = out[:len(out)-padLen]
	} else {
		out = []byte(strings.TrimRight(string(out), "\x00"))
	}
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		return nil, errorf("appkey json: %w", err)
	}
	return obj, nil
}

// CodeTable mirrors GenerateCodeTable: placeholders are filled with the
// current local time and random numbers.
func CodeTable() map[string]string {
	now := time.Now()
	rnd := func(n int) string { return fmt.Sprintf("%02d", randomInt(n)) }
	return map[string]string{
		"#H#":    now.Format("2006-01-02 15"),
		"#D#":    now.Format("2006-01-02"),
		"#M#":    now.Format("2006-01"),
		"#R1#":   "00",
		"#R5#":   rnd(5),
		"#R10#":  rnd(10),
		"#R20#":  rnd(20),
		"#R50#":  rnd(50),
		"#R100#": rnd(100),
	}
}

var placeholders = []string{"#H#", "#D#", "#M#", "#R100#", "#R50#", "#R20#", "#R10#", "#R5#", "#R1#"}

func subst(text string, table map[string]string) string {
	for _, key := range placeholders {
		text = strings.ReplaceAll(text, key, table[key])
	}
	return text
}

// Node is one host entry from the appkey content table.
type Node struct {
	Kind      string // TCP-D / TCP-I-H / HTTP
	Host      string
	Port      int
	Tag       string
	KeyPrefix string
}

func (n Node) String() string { return fmt.Sprintf("%s %s:%d", n.Kind, n.Host, n.Port) }

func nodesFromContent(content []map[string]any, table map[string]string) []Node {
	if table == nil {
		table = CodeTable()
	}
	var nodes []Node
	for _, item := range content {
		kind := toString(item["t"])
		body := toString(item["v"])
		idx := strings.Index(body, ";")
		if idx < 0 {
			continue
		}
		tag := subst(body[:idx], table)
		keyPrefix := MD5Hex(tag)
		hosts := strings.Split(body[idx+1:], "|")
		expanded := make([]string, 0, len(hosts))
		for _, h := range hosts {
			expanded = append(expanded, subst(strings.ReplaceAll(h, "#KIWIKEY#", keyPrefix), table))
		}
		if kind == "TCP-I-H" && len(expanded) > 0 {
			expanded = []string{expanded[randomInt(len(expanded))]}
		}
		for _, hostPort := range expanded {
			pos := strings.LastIndex(hostPort, ":")
			if pos < 0 {
				continue
			}
			port, err := strconv.Atoi(hostPort[pos+1:])
			if err != nil {
				continue
			}
			nodes = append(nodes, Node{Kind: kind, Host: hostPort[:pos], Port: port, Tag: tag, KeyPrefix: keyPrefix})
		}
	}
	return nodes
}

// AppKey is the parsed appkey configuration.
type AppKey struct {
	AppID   int
	PortKey int
	Content []map[string]any
	Raw     map[string]any
}

// ParseAppKey parses a base64 appkey.
func ParseAppKey(appkeyB64 string) (*AppKey, error) {
	data, err := DecryptAppkey(appkeyB64)
	if err != nil {
		return nil, err
	}
	content := make([]map[string]any, 0)
	if list, ok := data["content"].([]any); ok {
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				content = append(content, m)
			}
		}
	}
	return &AppKey{
		AppID:   toInt(data["app_id"]),
		PortKey: intOr(data["port_key"], DefaultPortKey),
		Content: content,
		Raw:     data,
	}, nil
}

// Nodes expands the content table.
func (a *AppKey) Nodes(table map[string]string) []Node {
	return nodesFromContent(a.Content, table)
}

// Route is a raw 56-byte Kiwi route.
type Route struct{ Raw []byte }

// RouteFromBase64 decodes a route from the API config.
func RouteFromBase64(text string) (*Route, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil {
		return nil, err
	}
	if len(raw) < 20 {
		return nil, errorf("route too short: %d", len(raw))
	}
	return &Route{Raw: raw}, nil
}

func (r *Route) Kind() int       { return int(r.Raw[3]) }
func (r *Route) RouteID() uint32 { return binary.LittleEndian.Uint32(r.Raw[4:8]) }
func (r *Route) Key() byte       { return r.Raw[18] }
func (r *Route) ServiceID() uint32 {
	return binary.BigEndian.Uint32(r.Raw[20:24])
}

// BuildAPIRoute mirrors KiwiProxy::NewApiRoute / NewRoute (type=2).
func BuildAPIRoute(routeID uint32, timestamp int64) []byte {
	r := make([]byte, 56)
	binary.LittleEndian.PutUint16(r[0:2], RouteMagic)
	r[2] = randomBytes(1)[0]
	r[3] = APIRouteType
	binary.LittleEndian.PutUint32(r[4:8], bswap32(routeID))
	binary.LittleEndian.PutUint32(r[12:16], bswap32(uint32(timestamp)))
	r[16] = 3
	r[17] = 0
	copy(r[18:], randomBytes(38))
	r[18] = APIC2SKey
	r[19] = APIC2SKey
	d4 := binary.LittleEndian.Uint32(r[4:8])
	d12 := binary.LittleEndian.Uint32(r[12:16])
	x := d4 ^ uint32(r[2]) ^ bswap32(d12) ^ 0x12345678
	binary.BigEndian.PutUint32(r[8:12], x)
	return r
}

// EncodePort is IntSecret::Encode.
func EncodePort(port, portKey int) int {
	return (portKey + modinv(port, 65537)) & 0xFFFF
}

// DecodePort is IntSecret::Decode.
func DecodePort(value, portKey int) int {
	return modinv((value-portKey)&0xFFFF, 65537)
}

func modinv(a, m int) int {
	a %= m
	if a < 0 {
		a += m
	}
	if a == 0 {
		return 0
	}
	oldR, r := a, m
	oldS, s := 1, 0
	for r != 0 {
		q := oldR / r
		oldR, r = r, oldR-q*r
		oldS, s = s, oldS-q*s
	}
	if oldR != 1 {
		return 0
	}
	oldS %= m
	if oldS < 0 {
		oldS += m
	}
	return oldS
}

// NodeInfo is one node in the API config (node / back_node).
type NodeInfo struct {
	IP   string
	Port int
	GID  int
}

// DNSRecord is one service entry; Route is a server-signed type=4 route.
type DNSRecord struct {
	Name      string
	Route     string
	GID       int
	LocalPort int
}

// Config is the parsed API config response.
type Config struct {
	Raw      map[string]any
	Code     int
	CTL      int
	KCP      int
	Session  string
	Node     []NodeInfo
	BackNode []NodeInfo
	DNS      []DNSRecord
}

// ParseConfig parses the JSON object returned by the API server.
func ParseConfig(raw map[string]any) *Config {
	cfg := &Config{
		Raw:     raw,
		Code:    toInt(raw["code"]),
		CTL:     toInt(raw["ctl"]),
		KCP:     toInt(raw["kcp"]),
		Session: toString(raw["session"]),
	}
	cfg.Node = parseNodeList(raw["node"])
	cfg.BackNode = parseNodeList(raw["back_node"])
	if list, ok := raw["dns"].([]any); ok {
		for _, item := range list {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			cfg.DNS = append(cfg.DNS, DNSRecord{
				Name:      toString(m["name"]),
				Route:     toString(m["route"]),
				GID:       toInt(m["gid"]),
				LocalPort: toInt(m["local_port"]),
			})
		}
	}
	return cfg
}

func parseNodeList(value any) []NodeInfo {
	list, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]NodeInfo, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ip := toString(firstValue(m, "IP", "ip"))
		port := toInt(firstValue(m, "Port", "port"))
		if ip == "" || port == 0 {
			continue
		}
		out = append(out, NodeInfo{IP: ip, Port: port, GID: toInt(m["gid"])})
	}
	return out
}

func (c *Config) Record(name string) *DNSRecord {
	for i := range c.DNS {
		if c.DNS[i].Name == name {
			return &c.DNS[i]
		}
	}
	return nil
}

// RouteFor returns the service route for name.
func (c *Config) RouteFor(name string) (*Route, error) {
	item := c.Record(name)
	if item == nil {
		names := make([]string, 0, len(c.DNS))
		for _, d := range c.DNS {
			names = append(names, d.Name)
		}
		return nil, errorf("DNS 记录里没有服务 %q；可用：%s", name, strings.Join(names, ", "))
	}
	if item.Route == "" {
		return nil, errorf("服务 %q 没有 route", name)
	}
	return RouteFromBase64(item.Route)
}

// NodesFor returns gid-matching nodes first, then the rest.
func (c *Config) NodesFor(name string) []NodeInfo {
	gid := 0
	if item := c.Record(name); item != nil {
		gid = item.GID
	}
	same := make([]NodeInfo, 0, len(c.Node))
	other := make([]NodeInfo, 0, len(c.Node))
	for _, n := range c.Node {
		if n.GID == gid {
			same = append(same, n)
		} else {
			other = append(other, n)
		}
	}
	return append(same, other...)
}

// Tunnel is a TCP tunnel to a Kiwi node/service.
//
// Protocol: send the route (raw) -> server sends a 16-byte handshake (dropped)
// -> both directions are XORed with route[18].
type Tunnel struct {
	conn      net.Conn
	route     []byte
	key       byte
	skip      int
	writeMu   sync.Mutex
	closeOnce sync.Once
}

// NewTunnel writes the route and consumes the handshake.
func NewTunnel(conn net.Conn, route []byte, handshakeTimeout time.Duration) (*Tunnel, error) {
	t := &Tunnel{conn: conn, route: route, key: route[18], skip: RouteHandshakeSize}
	if _, err := conn.Write(route); err != nil {
		conn.Close()
		return nil, err
	}
	if handshakeTimeout <= 0 {
		handshakeTimeout = 2 * time.Second
	}
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	n := 0
	buf := make([]byte, RouteHandshakeSize)
	for n < len(buf) {
		m, err := conn.Read(buf[n:])
		n += m
		if err != nil {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	if n > RouteHandshakeSize {
		n = RouteHandshakeSize
	}
	t.skip = RouteHandshakeSize - n
	return t, nil
}

// Send XORs data with the route key and writes it.
func (t *Tunnel) Send(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	out := data
	if t.key != 0 {
		out = make([]byte, len(data))
		for i, b := range data {
			out[i] = b ^ t.key
		}
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, err := t.conn.Write(out)
	return err
}

// Recv reads up to n bytes. A timeout yields (nil, nil).
func (t *Tunnel) Recv(n int, timeout time.Duration) ([]byte, error) {
	if n <= 0 {
		n = 65536
	}
	if timeout > 0 {
		_ = t.conn.SetReadDeadline(time.Now().Add(timeout))
	} else {
		_ = t.conn.SetReadDeadline(time.Time{})
	}
	buf := make([]byte, n)
	m, err := t.conn.Read(buf)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, nil
		}
		return nil, err
	}
	data := buf[:m]
	if t.skip > 0 {
		if len(data) <= t.skip {
			t.skip -= len(data)
			return nil, nil
		}
		data = data[t.skip:]
		t.skip = 0
	}
	if t.key != 0 {
		out := make([]byte, len(data))
		for i, b := range data {
			out[i] = b ^ t.key
		}
		data = out
	}
	return data, nil
}

// RecvUntilEOF reads until the peer closes or idle elapses without new data.
func (t *Tunnel) RecvUntilEOF(timeout, idle time.Duration, maxBytes int) ([]byte, error) {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	if idle <= 0 {
		idle = 350 * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	last := time.Now()
	out := make([]byte, 0, 4096)
	for len(out) < maxBytes && time.Now().Before(deadline) {
		wait := idle
		if remaining := time.Until(deadline); remaining < wait {
			wait = remaining
		}
		if wait < 50*time.Millisecond {
			wait = 50 * time.Millisecond
		}
		chunk, err := t.Recv(65536, wait)
		if len(chunk) > 0 {
			out = append(out, chunk...)
			last = time.Now()
			continue
		}
		if err != nil {
			break
		}
		if time.Since(last) >= idle {
			break
		}
	}
	return out, nil
}

// Close closes the tunnel.
func (t *Tunnel) Close() error {
	t.closeOnce.Do(func() {
		if t.conn != nil {
			_ = t.conn.Close()
		}
	})
	return nil
}

// Client: appkey -> nodes -> API config -> service route -> tunnel.
type Client struct {
	AppKeyString string
	AppKey       *AppKey
	AppName      string
	Umid         string
	SDKVer       string
	Network      string
	Session      string
	Device       map[string]any
	Timeout      time.Duration

	mu         sync.Mutex
	config     *Config
	nodesTable map[string]string
	nodeCache  map[string]NodeInfo
}

// NewClient parses the appkey and prepares a client.
func NewClient(appkey string) (*Client, error) {
	ak, err := ParseAppKey(appkey)
	if err != nil {
		return nil, err
	}
	return &Client{
		AppKeyString: appkey,
		AppKey:       ak,
		AppName:      DefaultAppName,
		Umid:         "0#0#0#" + hex.EncodeToString(randomBytes(16)),
		SDKVer:       SDKVersion,
		Network:      "wifi",
		Session:      SessionInit,
		Device:       map[string]any{},
		Timeout:      6 * time.Second,
		nodeCache:    map[string]NodeInfo{},
	}, nil
}

// Nodes expands the appkey node table with the current time table.
func (c *Client) Nodes() []Node {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nodesTable == nil {
		c.nodesTable = CodeTable()
	}
	return c.AppKey.Nodes(c.nodesTable)
}

// APINodes returns domain nodes first, then IP nodes.
func (c *Client) APINodes() []Node {
	nodes := c.Nodes()
	out := make([]Node, 0, len(nodes))
	for _, n := range nodes {
		if n.Kind == "TCP-D" {
			out = append(out, n)
		}
	}
	for _, n := range nodes {
		if n.Kind == "TCP-I-H" {
			out = append(out, n)
		}
	}
	return out
}

func (c *Client) buildPayload() []byte {
	body := map[string]any{
		"appid":                   c.AppKey.AppID,
		"umid":                    c.Umid,
		"sdkver":                  c.SDKVer,
		"appname":                 c.AppName,
		"connection_detail":       []any{},
		"connection_count":        0,
		"connection_count_failed": 0,
		"connection_avg":          0,
		"connection_avg_success":  0,
		"network":                 c.Network,
		"session":                 c.Session,
		"device":                  c.Device,
	}
	raw, _ := json.Marshal(body)
	return raw
}

// RequestConfig asks the API server for node/back_node/dns.
func (c *Client) RequestConfig(refresh bool) (*Config, error) {
	c.mu.Lock()
	if c.config != nil && !refresh {
		cfg := c.config
		c.mu.Unlock()
		return cfg, nil
	}
	c.mu.Unlock()

	payload := c.buildPayload()
	var errs []string
	for _, node := range c.APINodes() {
		raw, err := c.apiExchange(node, payload)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", node, err))
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			errs = append(errs, fmt.Sprintf("%s: bad json %v", node, err))
			continue
		}
		if toInt(obj["code"]) != 0 {
			errs = append(errs, fmt.Sprintf("%s: code=%v msg=%v", node, obj["code"], obj["msg"]))
			continue
		}
		cfg := ParseConfig(obj)
		c.mu.Lock()
		c.config = cfg
		if cfg.Session != "" {
			c.Session = cfg.Session
		}
		c.mu.Unlock()
		return cfg, nil
	}
	return nil, errorf("所有 API 节点都失败：\n  %s", strings.Join(errs, "\n  "))
}

func (c *Client) apiExchange(node Node, payload []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(node.Host, strconv.Itoa(node.Port)), c.Timeout)
	if err != nil {
		return nil, err
	}
	route := BuildAPIRoute(0, time.Now().Unix())
	tunnel, err := NewTunnel(conn, route, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer tunnel.Close()
	if err := tunnel.Send(payload); err != nil {
		return nil, err
	}
	return tunnel.RecvUntilEOF(c.Timeout, 400*time.Millisecond, 4<<20)
}

// Config returns the cached config, fetching it if needed.
func (c *Client) Config() (*Config, error) { return c.RequestConfig(false) }

// RouteFor returns the route of a service.
func (c *Client) RouteFor(name string) (*Route, error) {
	cfg, err := c.Config()
	if err != nil {
		return nil, err
	}
	return cfg.RouteFor(name)
}

// ServiceNames lists DNS service names.
func (c *Client) ServiceNames() ([]string, error) {
	cfg, err := c.Config()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(cfg.DNS))
	for _, d := range cfg.DNS {
		out = append(out, d.Name)
	}
	return out, nil
}

// Open establishes a tunnel to a service such as kiwi_live.
func (c *Client) Open(name string, timeout time.Duration) (*Tunnel, error) {
	cfg, err := c.Config()
	if err != nil {
		return nil, err
	}
	route, err := cfg.RouteFor(name)
	if err != nil {
		return nil, err
	}
	nodes := cfg.NodesFor(name)

	c.mu.Lock()
	cached, hasCached := c.nodeCache[name]
	c.mu.Unlock()
	if hasCached {
		reordered := make([]NodeInfo, 0, len(nodes)+1)
		reordered = append(reordered, cached)
		for _, n := range nodes {
			if n.IP != cached.IP || n.Port != cached.Port {
				reordered = append(reordered, n)
			}
		}
		nodes = reordered
	}

	connectTimeout := 3 * time.Second
	if timeout > 0 && timeout < connectTimeout {
		connectTimeout = timeout
	}
	var errs []string
	for _, item := range nodes {
		if item.IP == "" || item.Port == 0 {
			continue
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(item.IP, strconv.Itoa(item.Port)), connectTimeout)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s:%d %v", item.IP, item.Port, err))
			continue
		}
		tunnel, err := NewTunnel(conn, route.Raw, 2*time.Second)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s:%d %v", item.IP, item.Port, err))
			continue
		}
		c.mu.Lock()
		c.nodeCache[name] = item
		c.mu.Unlock()
		return tunnel, nil
	}
	// Fall back to nodes from the appkey itself.
	for _, candidate := range c.APINodes() {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(candidate.Host, strconv.Itoa(candidate.Port)), connectTimeout)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s %v", candidate, err))
			continue
		}
		tunnel, err := NewTunnel(conn, route.Raw, 2*time.Second)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s %v", candidate, err))
			continue
		}
		c.mu.Lock()
		c.nodeCache[name] = NodeInfo{IP: candidate.Host, Port: candidate.Port}
		c.mu.Unlock()
		return tunnel, nil
	}
	return nil, errorf("没有可用的隧道节点：\n  %s", strings.Join(errs, "\n  "))
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case float32:
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

func intOr(v any, def int) int {
	if v == nil {
		return def
	}
	return toInt(v)
}

func toString(v any) string {
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
	case nil:
		return ""
	default:
		return fmt.Sprint(s)
	}
}

func firstValue(m map[string]any, keys ...string) any {
	for _, key := range keys {
		if v, ok := m[key]; ok && v != nil {
			return v
		}
	}
	return nil
}

func randomInt(n int) int {
	if n <= 0 {
		return 0
	}
	b := randomBytes(4)
	v := binary.BigEndian.Uint32(b) % uint32(n)
	return int(v)
}
