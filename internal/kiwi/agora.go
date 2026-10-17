package kiwi

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Native Agora token flow (com.example.untitled.AgoraPlayManager):
//
//  1. POST /go/<encryptPath("login/quick")>?z=1&nobase64=1 over the kiwi_live
//     tunnel, carrying a Rabbit-encrypted LoginQuickRequest protobuf.
//  2. WebSocket /go/<encryptPath("/ws/chat")>?z=1&nobase64=1, send
//     /login/init and /stream/generate_agora_token.

const (
	aesKeyString      = "064392d90fde936b13a5a100c471bdf0"
	aesIVHex          = "475DD5A0DB3BF782021B12E5A2C64ABF"
	defaultChannel    = "tui1"
	defaultVersion    = "8.5.3"
	defaultAppVersion = "20260226001"
	defaultAppName    = "多彩"

	// AgoraAppID is the app id used by the app.
	AgoraAppID = "663d3b54f13b4a1b88acc31e69189889"
)

var fixedKeyBytes = []byte{
	106, 81, 66, 85, 79, 38, 50, 112, 102, 83, 53, 115, 67, 227, 128, 141,
	194, 165, 63, 65, 116, 103, 108, 88, 118, 42, 119, 43, 80, 99, 82, 75,
	56, 37, 105,
}

var fixedKeyString = string(fixedKeyBytes)

// ---------------------------------------------------------------------------
// Utils.java equivalents
// ---------------------------------------------------------------------------

func generateIV(size int) []byte { return randomBytes(size) }

func generateWithoutJWTKey() string {
	hour := time.Now().Unix() / 3600
	return MD5Hex(fixedKeyString + strconv.FormatInt(hour, 10))
}

func generateKey(jwtToken string) string {
	hour := time.Now().Unix() / 3600
	return MD5Hex(fixedKeyString + strconv.FormatInt(hour, 10) + jwtToken)
}

func formatUUID(b []byte) string {
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func generateUUIDv3() string {
	// UUID.nameUUIDFromBytes(new SecureRandom().nextBytes(16)): MD5-name UUID v3.
	sum := md5.Sum(randomBytes(16))
	b := sum[:]
	b[6] = (b[6] & 0x0F) | 0x30
	b[8] = (b[8] & 0x3F) | 0x80
	return formatUUID(b)
}

func normalizeUUID(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return "", false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", false
	}
	return formatUUID(b), true
}

func generateAPNSCode(uuidStr string) (string, error) {
	iv, err := hex.DecodeString(aesIVHex)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(aesKeyString))
	if err != nil {
		return "", err
	}
	plain := pkcs7Pad([]byte(uuidStr), aes.BlockSize)
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return base64.StdEncoding.EncodeToString(out), nil
}

func generateClientToken(uuidStr, channel string) string {
	return MD5Hex("token:" + uuidStr + "_" + channel)
}

func xorWithKey(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

// encryptPath is Utils.encryptPath (URL-safe base64, Android URL_SAFE flag).
func encryptPath(path string) string {
	iv1 := generateIV(11)
	iv2 := generateIV(13)
	step := reverseBytes(xorWithKey([]byte(path), iv1))
	step = reverseBytes(xorWithKey(append(iv1, step...), iv2))
	return base64.URLEncoding.EncodeToString(append(step, iv2...))
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded length %d", len(data))
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

func aesCBCEncrypt(plain, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain = pkcs7Pad(plain, aes.BlockSize)
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return out, nil
}

// ---------------------------------------------------------------------------
// Minimal protobuf encoder/decoder
// ---------------------------------------------------------------------------

func pbVarint(value uint64) []byte {
	out := make([]byte, 0, 10)
	for {
		b := byte(value & 0x7F)
		value >>= 7
		if value != 0 {
			out = append(out, b|0x80)
		} else {
			out = append(out, b)
			return out
		}
	}
}

func pbFieldVarint(field int, value uint64) []byte {
	out := pbVarint(uint64(field) << 3)
	return append(out, pbVarint(value)...)
}

func pbFieldBytes(field int, value []byte, force bool) []byte {
	if len(value) == 0 && !force {
		return nil
	}
	out := pbVarint(uint64(field)<<3 | 2)
	out = append(out, pbVarint(uint64(len(value)))...)
	return append(out, value...)
}

func pbFieldString(field int, value string, force bool) []byte {
	return pbFieldBytes(field, []byte(value), force)
}

type pbValue struct {
	wire int
	num  uint64
	data []byte
}

func readVarint(data []byte, i int) (uint64, int, error) {
	var value uint64
	var shift uint
	for {
		if i >= len(data) {
			return 0, i, fmt.Errorf("protobuf: truncated varint")
		}
		b := data[i]
		i++
		value |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return value, i, nil
		}
		shift += 7
		if shift >= 64 {
			return 0, i, fmt.Errorf("protobuf: varint overflow")
		}
	}
}

func pbParse(data []byte) (map[int][]pbValue, error) {
	out := make(map[int][]pbValue)
	i := 0
	for i < len(data) {
		tag, next, err := readVarint(data, i)
		if err != nil {
			return nil, err
		}
		i = next
		field := int(tag >> 3)
		wire := int(tag & 7)
		switch wire {
		case 0:
			value, next, err := readVarint(data, i)
			if err != nil {
				return nil, err
			}
			i = next
			out[field] = append(out[field], pbValue{wire: 0, num: value})
		case 2:
			length, next, err := readVarint(data, i)
			if err != nil {
				return nil, err
			}
			i = next
			end := i + int(length)
			if end > len(data) || end < i {
				return nil, fmt.Errorf("protobuf: truncated bytes field")
			}
			out[field] = append(out[field], pbValue{wire: 2, data: data[i:end]})
			i = end
		case 1:
			if i+8 > len(data) {
				return nil, fmt.Errorf("protobuf: truncated fixed64")
			}
			out[field] = append(out[field], pbValue{wire: 1, data: data[i : i+8]})
			i += 8
		case 5:
			if i+4 > len(data) {
				return nil, fmt.Errorf("protobuf: truncated fixed32")
			}
			out[field] = append(out[field], pbValue{wire: 5, data: data[i : i+4]})
			i += 4
		default:
			return nil, fmt.Errorf("protobuf: bad wire type %d", wire)
		}
	}
	return out, nil
}

func pbFirstString(fields map[int][]pbValue, field int) string {
	for _, v := range fields[field] {
		if v.wire == 2 {
			return string(v.data)
		}
	}
	return ""
}

func pbFirstInt(fields map[int][]pbValue, field int) int {
	for _, v := range fields[field] {
		if v.wire == 0 {
			return int(v.num)
		}
	}
	return 0
}

func pbFirstMsg(fields map[int][]pbValue, field int) []byte {
	for _, v := range fields[field] {
		if v.wire == 2 {
			return v.data
		}
	}
	return nil
}

func buildLoginQuick(parentIcode, validate, captchaID, apnsCode, version, appVersion,
	deviceType, channel, openChannelID, machineInfo, osVersion string,
	isPodcast bool, packageName, clientToken string) []byte {
	var out []byte
	out = append(out, pbFieldString(1, parentIcode, true)...)
	out = append(out, pbFieldString(2, validate, true)...)
	out = append(out, pbFieldString(3, captchaID, true)...)
	out = append(out, pbFieldString(4, apnsCode, false)...)
	out = append(out, pbFieldString(5, "", false)...)
	out = append(out, pbFieldString(6, version, false)...)
	out = append(out, pbFieldString(7, appVersion, false)...)
	out = append(out, pbFieldString(8, deviceType, false)...)
	out = append(out, pbFieldString(9, "", false)...)
	out = append(out, pbFieldString(10, channel, false)...)
	out = append(out, pbFieldString(11, openChannelID, true)...)
	out = append(out, pbFieldString(12, machineInfo, false)...)
	out = append(out, pbFieldString(13, osVersion, false)...)
	if isPodcast {
		out = append(out, pbFieldVarint(14, 1)...)
	}
	out = append(out, pbFieldString(15, packageName, false)...)
	out = append(out, pbFieldString(16, clientToken, false)...)
	return out
}

func buildRequest(randomID, method int, path string, data []byte) []byte {
	var out []byte
	if randomID != 0 {
		out = append(out, pbFieldVarint(1, uint64(randomID))...)
	}
	if method != 0 {
		out = append(out, pbFieldVarint(2, uint64(method))...)
	}
	out = append(out, pbFieldString(3, path, false)...)
	out = append(out, pbFieldBytes(4, data, false)...)
	return out
}

func buildLoginInit(apnsCode, jwtToken, appVersion string) []byte {
	var out []byte
	out = append(out, pbFieldString(1, apnsCode, true)...)
	out = append(out, pbFieldString(2, jwtToken, true)...)
	out = append(out, pbFieldString(3, appVersion, true)...)
	return out
}

func buildRequestAgora(channelName string, userID int) []byte {
	var out []byte
	out = append(out, pbFieldString(2, channelName, true)...)
	if userID != 0 {
		out = append(out, pbFieldVarint(3, uint64(userID))...)
	}
	return out
}

// ---------------------------------------------------------------------------
// WebSocket frames
// ---------------------------------------------------------------------------

const (
	opCont   = 0x0
	opText   = 0x1
	opBinary = 0x2
	opClose  = 0x8
	opPing   = 0x9
	opPong   = 0xA
)

func maskPayload(payload, key []byte) []byte {
	out := make([]byte, len(payload))
	for i, b := range payload {
		out[i] = b ^ key[i%4]
	}
	return out
}

func makeFrame(payload []byte, opcode int) []byte {
	out := make([]byte, 0, len(payload)+14)
	out = append(out, byte(0x80|opcode))
	n := len(payload)
	switch {
	case n < 126:
		out = append(out, byte(0x80|n))
	case n < 65536:
		out = append(out, 0x80|126)
		out = append(out, byte(n>>8), byte(n))
	default:
		out = append(out, 0x80|127)
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(n))
		out = append(out, length[:]...)
	}
	key := randomBytes(4)
	out = append(out, key...)
	out = append(out, maskPayload(payload, key)...)
	return out
}

type frameReader struct {
	tunnel *Tunnel
	buf    []byte
}

func (r *frameReader) fill(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for len(r.buf) < n {
		left := time.Until(deadline)
		if left <= 0 {
			return false
		}
		wait := left
		if wait > time.Second {
			wait = time.Second
		}
		chunk, err := r.tunnel.Recv(65536, wait)
		if err != nil {
			return false
		}
		if len(chunk) > 0 {
			r.buf = append(r.buf, chunk...)
		}
	}
	return true
}

func (r *frameReader) read(timeout time.Duration) (int, []byte, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if !r.fill(2, timeout) {
		return 0, nil, fmt.Errorf("等待 WebSocket 帧超时")
	}
	opcode := int(r.buf[0] & 0x0F)
	masked := r.buf[1]&0x80 != 0
	length := int(r.buf[1] & 0x7F)
	offset := 2
	if length == 126 {
		if !r.fill(4, timeout) {
			return 0, nil, fmt.Errorf("帧头不完整")
		}
		length = int(binary.BigEndian.Uint16(r.buf[2:4]))
		offset = 4
	} else if length == 127 {
		if !r.fill(10, timeout) {
			return 0, nil, fmt.Errorf("帧头不完整")
		}
		length = int(binary.BigEndian.Uint64(r.buf[2:10]))
		offset = 10
	}
	need := offset + length
	if masked {
		need += 4
	}
	if !r.fill(need, timeout) {
		return 0, nil, fmt.Errorf("帧负载不完整")
	}
	var maskKey []byte
	if masked {
		maskKey = r.buf[offset : offset+4]
		offset += 4
	}
	payload := r.buf[offset : offset+length]
	r.buf = r.buf[need:]
	if masked && len(maskKey) == 4 {
		payload = maskPayload(payload, maskKey)
	}
	return opcode, payload, nil
}

// ---------------------------------------------------------------------------
// HTTP over tunnel
// ---------------------------------------------------------------------------

func readHTTPResponse(t *Tunnel, timeout time.Duration) (int, map[string]string, []byte, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	deadline := time.Now().Add(timeout)
	var buf []byte
	for !bytes.Contains(buf, []byte("\r\n\r\n")) && time.Now().Before(deadline) {
		chunk, err := t.Recv(65536, time.Second)
		if err != nil {
			break
		}
		if len(chunk) > 0 {
			buf = append(buf, chunk...)
		}
	}
	idx := bytes.Index(buf, []byte("\r\n\r\n"))
	if idx < 0 {
		return 0, nil, nil, fmt.Errorf("HTTP 响应为空")
	}
	head := buf[:idx]
	body := append([]byte(nil), buf[idx+4:]...)
	lines := bytes.Split(head, []byte("\r\n"))
	if len(lines) == 0 {
		return 0, nil, nil, fmt.Errorf("HTTP 响应为空")
	}
	parts := bytes.SplitN(lines[0], []byte(" "), 3)
	if len(parts) < 2 {
		return 0, nil, nil, fmt.Errorf("HTTP 状态行异常：%q", lines[0])
	}
	status, err := strconv.Atoi(string(parts[1]))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("HTTP 状态行异常：%q", lines[0])
	}
	headers := make(map[string]string)
	for _, line := range lines[1:] {
		if i := bytes.IndexByte(line, ':'); i > 0 {
			key := strings.ToLower(strings.TrimSpace(string(line[:i])))
			headers[key] = strings.TrimSpace(string(line[i+1:]))
		}
	}
	if lengthText, ok := headers["content-length"]; ok {
		need, err := strconv.Atoi(lengthText)
		if err == nil {
			for len(body) < need && time.Now().Before(deadline) {
				chunk, err := t.Recv(65536, time.Second)
				if err != nil || len(chunk) == 0 {
					break
				}
				body = append(body, chunk...)
			}
			if len(body) > need {
				body = body[:need]
			}
		}
	} else if strings.Contains(strings.ToLower(headers["transfer-encoding"]), "chunked") {
		body, err = readChunked(t, body, deadline)
		if err != nil {
			return 0, headers, nil, err
		}
	} else {
		for time.Now().Before(deadline) {
			chunk, err := t.Recv(65536, 500*time.Millisecond)
			if err != nil || len(chunk) == 0 {
				break
			}
			body = append(body, chunk...)
		}
	}
	switch strings.ToLower(headers["content-encoding"]) {
	case "gzip":
		if reader, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
			if plain, err := io.ReadAll(reader); err == nil {
				body = plain
			}
		}
	case "deflate":
		if reader, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			if plain, err := io.ReadAll(reader); err == nil {
				body = plain
			}
		}
	}
	return status, headers, body, nil
}

func readChunked(t *Tunnel, rest []byte, deadline time.Time) ([]byte, error) {
	var out []byte
	buf := rest
	for {
		for !bytes.Contains(buf, []byte("\r\n")) {
			chunk, err := t.Recv(65536, time.Second)
			if err != nil || len(chunk) == 0 {
				return out, nil
			}
			buf = append(buf, chunk...)
		}
		idx := bytes.Index(buf, []byte("\r\n"))
		line := buf[:idx]
		buf = buf[idx+2:]
		if semi := bytes.IndexByte(line, ';'); semi >= 0 {
			line = line[:semi]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(string(line)), 16, 64)
		if err != nil {
			return out, fmt.Errorf("chunked: bad size %q", line)
		}
		if size == 0 {
			return out, nil
		}
		for len(buf) < int(size)+2 {
			chunk, err := t.Recv(65536, time.Second)
			if err != nil || len(chunk) == 0 {
				return out, nil
			}
			buf = append(buf, chunk...)
		}
		out = append(out, buf[:size]...)
		buf = buf[size+2:]
		if time.Now().After(deadline) {
			return out, nil
		}
	}
}

// ---------------------------------------------------------------------------
// NativeAgora
// ---------------------------------------------------------------------------

// NativeAgora implements the app's AgoraPlayManager flow.
type NativeAgora struct {
	client *Client
}

// NewNativeAgora wraps a Kiwi client.
func NewNativeAgora(client *Client) *NativeAgora { return &NativeAgora{client: client} }

// GuestLogin performs login/quick and returns jwt_token/user_id/apns_code.
// apnsUUID, when set, reuses a previously registered device identity instead
// of creating a new random one.
func (n *NativeAgora) GuestLogin(generateToken, apnsUUID string) (map[string]string, error) {
	gt := map[string]any{}
	if strings.TrimSpace(generateToken) != "" {
		_ = json.Unmarshal([]byte(generateToken), &gt)
	}

	uuidStr := strings.TrimSpace(toString(gt["apns_code"]))
	if normalized, ok := normalizeUUID(uuidStr); ok {
		uuidStr = normalized
	} else if normalized, ok := normalizeUUID(apnsUUID); ok {
		uuidStr = normalized
	} else {
		uuidStr = generateUUIDv3()
	}
	channel := strOr(gt["channel_id"], defaultChannel)
	apns, err := generateAPNSCode(uuidStr)
	if err != nil {
		return nil, err
	}
	clientToken := generateClientToken(uuidStr, channel)

	req := buildLoginQuick(
		strOr(gt["parent_icode"], ""),
		strOr(gt["validate"], ""),
		strOr(gt["captcha_id"], ""),
		apns,
		strOr(gt["version"], defaultVersion),
		strOr(gt["app_version"], defaultAppVersion),
		strOr(gt["device_type"], "android"),
		channel,
		strOr(gt["open_channel_id"], ""),
		strOr(gt["machine_info"], "google_flame"),
		strOr(gt["os_version"], "QQ2A.200405.005_10_29"),
		truthy(gt["is_podcast"]),
		strOr(gt["app_name"], defaultAppName),
		clientToken,
	)

	rabbit := &RabbitCipher{}
	keyBytes, err := hex.DecodeString(generateWithoutJWTKey())
	if err != nil {
		return nil, err
	}
	rabbit.SetupKey(keyBytes)
	iv := generateIV(8)
	rabbit.SetupIV(iv)
	ciphertext := rabbit.EncryptDecrypt(req, rabbit.KeyStream(len(req)))
	sum := md5.Sum(req)
	checksum := hex.EncodeToString(sum[:])

	path := "/go/" + encryptPath("login/quick") + "?z=1&nobase64=1"
	headers := map[string]string{
		"user-agent":      "Dart/3.10 (dart:io)",
		"accept":          "application/proto",
		"accept-encoding": "gzip",
		"host":            "127.0.0.1:1088",
		"checksum":        checksum,
		"content-type":    "application/proto",
		"cipher":          base64.StdEncoding.EncodeToString(iv),
	}

	tunnel, err := n.client.Open("kiwi_live", 15*time.Second)
	if err != nil {
		return nil, err
	}
	defer tunnel.Close()

	body, err := postOverTunnel(tunnel, path, ciphertext, headers)
	if err != nil {
		return nil, err
	}
	plain := rabbit.EncryptDecrypt(body, rabbit.KeyStream(len(body)))

	anyObj, err := pbParse(plain)
	if err != nil {
		return nil, fmt.Errorf("游客登录响应解析失败：%w", err)
	}
	reply, err := pbParse(pbFirstMsg(anyObj, 2))
	if err != nil {
		return nil, fmt.Errorf("游客登录响应解析失败：%w", err)
	}
	jwtToken := pbFirstString(reply, 3)
	data, err := pbParse(pbFirstMsg(reply, 4))
	if err != nil {
		return nil, fmt.Errorf("游客登录响应解析失败：%w", err)
	}
	userID := pbFirstString(data, 2)
	if jwtToken == "" {
		// Error replies come back as Response{error{code,msg}} instead of
		// AnyObj{obj}; surface the upstream code/message when available.
		if errPayload := pbFirstMsg(anyObj, 1); errPayload != nil {
			if fields, parseErr := pbParse(errPayload); parseErr == nil {
				code := int64(pbFirstInt(fields, 1))
				msg := pbFirstString(fields, 2)
				if msg != "" {
					return nil, fmt.Errorf("kiwi_live 拒绝游客登录（code=%d）：%s", code, msg)
				}
			}
		}
		preview := plain
		if len(preview) > 200 {
			preview = preview[:200]
		}
		return nil, fmt.Errorf("游客登录失败，响应=%q", preview)
	}
	return map[string]string{
		"guest_token":  jwtToken,
		"user_id":      userID,
		"apns_code":    apns,
		"uuid":         uuidStr,
		"client_token": clientToken,
	}, nil
}

func postOverTunnel(tunnel *Tunnel, path string, body []byte, headers map[string]string) ([]byte, error) {
	var b strings.Builder
	b.WriteString("POST " + path + " HTTP/1.1\r\n")
	for key, value := range headers {
		b.WriteString(key + ": " + value + "\r\n")
	}
	b.WriteString("content-length: " + strconv.Itoa(len(body)) + "\r\n")
	b.WriteString("connection: keep-alive\r\n\r\n")
	raw := append([]byte(b.String()), body...)
	if err := tunnel.Send(raw); err != nil {
		return nil, err
	}
	status, respHeaders, respBody, err := readHTTPResponse(tunnel, 10*time.Second)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("HTTP %d，响应头=%v", status, respHeaders)
	}
	return respBody, nil
}

// RequestAgoraToken opens the chat WebSocket and asks for an Agora token.
func (n *NativeAgora) RequestAgoraToken(channelID, userID, jwtToken, apnsCode, appVersion string) (string, error) {
	keyBytes, err := hex.DecodeString(generateKey(jwtToken))
	if err != nil {
		return "", err
	}
	iv := generateIV(8)
	sendCipher := &RabbitCipher{}
	sendCipher.SetupKey(keyBytes)
	sendCipher.SetupIV(iv)
	recvCipher := &RabbitCipher{}
	recvCipher.SetupKey(keyBytes)
	recvCipher.SetupIV(iv)

	tunnel, err := n.client.Open("kiwi_live", 15*time.Second)
	if err != nil {
		return "", err
	}
	defer tunnel.Close()

	path := "/go/" + encryptPath("/ws/chat") + "?z=1&nobase64=1"
	wsKey := base64.StdEncoding.EncodeToString(randomBytes(16))
	handshake := "GET " + path + " HTTP/1.1\r\n" +
		"Host: 127.0.0.1:1088\r\n" +
		"user-agent: Dart/3.5 (dart:io)\r\n" +
		"cache-control: no-cache\r\n" +
		"authorization: Bearer " + jwtToken + "\r\n" +
		"cipher: " + base64.StdEncoding.EncodeToString(iv) + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + wsKey + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if err := tunnel.Send([]byte(handshake)); err != nil {
		return "", err
	}

	const timeout = 15 * time.Second
	deadline := time.Now().Add(timeout)
	var head []byte
	for !bytes.Contains(head, []byte("\r\n\r\n")) && time.Now().Before(deadline) {
		chunk, err := tunnel.Recv(4096, time.Second)
		if err != nil {
			break
		}
		if len(chunk) > 0 {
			head = append(head, chunk...)
		}
	}
	if !bytes.Contains(head, []byte(" 101 ")) {
		preview := head
		if len(preview) > 200 {
			preview = preview[:200]
		}
		return "", fmt.Errorf("WS 握手失败：%q", preview)
	}
	idx := bytes.Index(head, []byte("\r\n\r\n"))
	reader := &frameReader{tunnel: tunnel}
	if idx >= 0 && idx+4 < len(head) {
		reader.buf = append([]byte(nil), head[idx+4:]...)
	}

	sendRequest := func(randomID int, rpath string, data []byte) error {
		msg := buildRequest(randomID, 3, rpath, data)
		ct := sendCipher.EncryptDecrypt(msg, sendCipher.KeyStream(len(msg)))
		return tunnel.Send(makeFrame(ct, opBinary))
	}

	recvResponse := func(expectedRandom int) (int, []byte, error) {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			remaining := time.Until(deadline)
			if remaining < 500*time.Millisecond {
				remaining = 500 * time.Millisecond
			}
			opcode, payload, err := reader.read(remaining)
			if err != nil {
				return 0, nil, err
			}
			if opcode == opClose {
				return 0, nil, fmt.Errorf("WS 关闭：%q", payload)
			}
			if opcode != opBinary {
				continue
			}
			plain := recvCipher.EncryptDecrypt(payload, recvCipher.KeyStream(len(payload)))
			if len(plain) >= 2 && plain[0] == 0x78 &&
				(plain[1] == 0x9C || plain[1] == 0x01 || plain[1] == 0xDA) {
				if zr, err := zlib.NewReader(bytes.NewReader(plain)); err == nil {
					if inflated, err := io.ReadAll(zr); err == nil {
						plain = inflated
					}
				}
			}
			fields, err := pbParse(plain)
			if err != nil {
				continue
			}
			randomID := pbFirstInt(fields, 1)
			status := pbFirstInt(fields, 3)
			body := pbFirstMsg(fields, 2)
			if expectedRandom != 0 && randomID != expectedRandom {
				continue
			}
			return status, body, nil
		}
		return 0, nil, fmt.Errorf("等待 Agora 响应超时")
	}

	if err := sendRequest(1, "/login/init", buildLoginInit(apnsCode, jwtToken, appVersion)); err != nil {
		return "", err
	}
	status, _, err := recvResponse(1)
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", fmt.Errorf("/login/init 返回 %d", status)
	}

	userIDInt, _ := strconv.Atoi(userID)
	if err := sendRequest(2, "/stream/generate_agora_token", buildRequestAgora(channelID, userIDInt)); err != nil {
		return "", err
	}
	status, body, err := recvResponse(2)
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", fmt.Errorf("/stream/generate_agora_token 返回 %d", status)
	}
	reply, err := pbParse(body)
	if err != nil {
		return "", err
	}
	token := pbFirstString(reply, 2)
	if token == "" {
		preview := body
		if len(preview) > 200 {
			preview = preview[:200]
		}
		return "", fmt.Errorf("Agora token 为空：%q", preview)
	}
	return token, nil
}

// PlayInfo is a one-shot login + token request.
func (n *NativeAgora) PlayInfo(appkeyData map[string]any, channelID string) (map[string]string, error) {
	login, err := n.GuestLogin(strOr(appkeyData["generate-token"], ""), "")
	if err != nil {
		return nil, err
	}
	token, err := n.RequestAgoraToken(
		channelID,
		login["user_id"],
		login["guest_token"],
		login["apns_code"],
		strOr(appkeyData["appVersion"], defaultAppVersion),
	)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"appId":     strOr(appkeyData["appid"], AgoraAppID),
		"token":     token,
		"channelId": channelID,
		"uid":       login["user_id"],
	}, nil
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

func strOr(v any, def string) string {
	s := strings.TrimSpace(toString(v))
	if s == "" {
		return def
	}
	return s
}

func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != "" && t != "0" && strings.ToLower(t) != "false"
	default:
		return toInt(v) != 0
	}
}
