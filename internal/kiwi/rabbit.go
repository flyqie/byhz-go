package kiwi

import "math/bits"

// RabbitCipher is a literal port of com.rabbit.RabbitCipher. The Java version
// has a few quirks compared to textbook Rabbit: the key stream rebuilds the
// 32-bit word every 16 bytes, and the IV is XORed into x0/x1 followed by four
// state iterations.
type RabbitCipher struct {
	x        [8]uint32
	c        [8]uint32
	keySetup bool
}

// SetupKey initialises the cipher with a 16-byte key.
func (r *RabbitCipher) SetupKey(key []byte) {
	if len(key) != 16 {
		panic("rabbit: key must be 16 bytes")
	}
	r.x = [8]uint32{}
	r.c = [8]uint32{}
	r.keySetup = true
	var s [8]uint32
	for i := 0; i < 8; i++ {
		s[i] = uint32(key[2*i])<<8 | uint32(key[2*i+1])
	}
	r.x[0] = s[0]<<16 | s[1]
	r.x[1] = s[1]<<16 | s[2]
	r.x[2] = s[2]<<16 | s[3]
	r.x[3] = s[3]<<16 | s[4]
	r.x[4] = s[4]<<16 | s[5]
	r.x[5] = s[5]<<16 | s[6]
	r.x[6] = s[6]<<16 | s[7]
	r.x[7] = s[7]<<16 | s[0]
	r.c[0] = s[4]<<16 | s[5]
	r.c[1] = s[5]<<16 | s[6]
	r.c[2] = s[6]<<16 | s[7]
	r.c[3] = s[7]<<16 | s[0]
	r.c[4] = s[0]<<16 | s[1]
	r.c[5] = s[1]<<16 | s[2]
	r.c[6] = s[2]<<16 | s[3]
	r.c[7] = s[3]<<16 | s[4]
}

// SetupIV XORs an 8-byte IV into the state and warms it up.
func (r *RabbitCipher) SetupIV(iv []byte) {
	if !r.keySetup {
		panic("rabbit: SetupKey must be called before SetupIV")
	}
	if len(iv) != 8 {
		panic("rabbit: iv must be 8 bytes")
	}
	i0 := uint32(iv[0])<<24 | uint32(iv[1])<<16 | uint32(iv[2])<<8 | uint32(iv[3])
	i1 := uint32(iv[4])<<24 | uint32(iv[5])<<16 | uint32(iv[6])<<8 | uint32(iv[7])
	r.x[0] ^= i0
	r.x[1] ^= i1
	for i := 0; i < 4; i++ {
		r.nextState()
	}
}

func (r *RabbitCipher) nextState() {
	var carry uint64
	for i := 0; i < 8; i++ {
		total := uint64(r.c[i]) + uint64(r.x[i]) + carry
		r.c[i] = uint32(total)
		carry = total >> 32
	}
	var g [8]uint32
	for i := 0; i < 8; i++ {
		v := r.x[i] + r.c[i]
		sq := v * v
		g[i] = sq ^ (sq >> 16)
	}
	r.x[0] = g[0] + bits.RotateLeft32(g[7], 16) + bits.RotateLeft32(g[6], 16)
	r.x[1] = g[1] + bits.RotateLeft32(g[0], 8) + g[7]
	r.x[2] = g[2] + bits.RotateLeft32(g[1], 16) + bits.RotateLeft32(g[0], 16)
	r.x[3] = g[3] + bits.RotateLeft32(g[2], 8) + g[1]
	r.x[4] = g[4] + bits.RotateLeft32(g[3], 16) + bits.RotateLeft32(g[2], 16)
	r.x[5] = g[5] + bits.RotateLeft32(g[4], 8) + g[3]
	r.x[6] = g[6] + bits.RotateLeft32(g[5], 16) + bits.RotateLeft32(g[4], 16)
	r.x[7] = g[7] + bits.RotateLeft32(g[6], 8) + g[5]
}

// KeyStream generates size bytes of key stream.
func (r *RabbitCipher) KeyStream(size int) []byte {
	out := make([]byte, size)
	var s uint32
	for i := 0; i < size; i++ {
		if i&15 == 0 {
			r.nextState()
			s = r.x[5] ^ r.x[0]
		}
		out[i] = byte(s)
		if i&3 == 3 {
			j := ((i >> 2) + 1) & 7
			s = r.x[j] ^ r.x[(j+5)&7]
		} else {
			s >>= 8
		}
	}
	return out
}

// EncryptDecrypt XORs data with the provided key stream.
func (r *RabbitCipher) EncryptDecrypt(data, keyStream []byte) []byte {
	n := len(data)
	if len(keyStream) < n {
		n = len(keyStream)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = data[i] ^ keyStream[i]
	}
	return out
}
