package chacha20

import (
	"crypto/cipher"
	"encoding/binary"
	"math/bits"
)

var constants = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}

type state [16]uint32

func NewCipher(key [32]byte, count uint32, nonce [12]byte) cipher.Stream {
	c := new(state)
	copy(c[0:4], constants[:])
	copy(c[4:12], []uint32{
		binary.LittleEndian.Uint32(key[0:4]),
		binary.LittleEndian.Uint32(key[4:8]),
		binary.LittleEndian.Uint32(key[8:12]),
		binary.LittleEndian.Uint32(key[12:16]),
		binary.LittleEndian.Uint32(key[16:20]),
		binary.LittleEndian.Uint32(key[20:24]),
		binary.LittleEndian.Uint32(key[24:28]),
		binary.LittleEndian.Uint32(key[28:32]),
	})
	copy(c[13:16], []uint32{
		binary.LittleEndian.Uint32(nonce[0:4]),
		binary.LittleEndian.Uint32(nonce[4:8]),
		binary.LittleEndian.Uint32(nonce[8:12]),
	})
	c[12] = count
	return c
}

func (c *state) XORKeyStream(dst, src []byte) {
	// NOTE: Skip error handling because this implementation is learning purpose.
	stream := c.keyStream()
	for len(src) > 0 {
		n := copy(dst, src)
		for i := 0; i < n; i++ {
			dst[i] ^= stream[i]
		}
		dst = dst[n:]
	}
}

func (c *state) keyStream() [64]byte {
	x := *c
	for i := 0; i < 10; i++ {
		// column round
		x[0], x[4], x[8], x[12] = qr(x[0], x[4], x[8], x[12])
		x[1], x[5], x[9], x[13] = qr(x[1], x[5], x[9], x[13])
		x[2], x[6], x[10], x[14] = qr(x[2], x[6], x[10], x[14])
		x[3], x[7], x[11], x[15] = qr(x[3], x[7], x[11], x[15])
		// diagonal round
		x[0], x[5], x[10], x[15] = qr(x[0], x[5], x[10], x[15])
		x[1], x[6], x[11], x[12] = qr(x[1], x[6], x[11], x[12])
		x[2], x[7], x[8], x[13] = qr(x[2], x[7], x[8], x[13])
		x[3], x[4], x[9], x[14] = qr(x[3], x[4], x[9], x[14])
	}
	z := state{}
	for i, v := range x {
		z[i] = c[i] + v
	}
	var stream [64]byte
	for i, v := range z {
		stream[i*4] = byte(v)
		stream[i*4+1] = byte(v >> 8)
		stream[i*4+2] = byte(v >> 16)
		stream[i*4+3] = byte(v >> 24)
	}
	return stream
}

func qr(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 16)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 12)
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 8)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 7)
	return a, b, c, d
}
