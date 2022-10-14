package ordenc

import (
	"crypto/subtle"
	"encoding/binary"
	"io"

	"github.com/zeebo/blake3"
)

type Key struct {
	rm *blake3.Hasher
	hm *blake3.Hasher
	mk u256
}

func NewDerivedKey(mat []byte) (*Key, error) {
	var buf [24 + 32 + 32]byte
	blake3.DeriveKey("ordenc v0 root key derivation", mat, buf[:])

	// we pick a limb size so that it is divisible by 3 but also
	// so that we have n bits of padding to encode how many bytes
	// of plaintext are included in the limb as well as 1 bit at
	// the high end to avoid ciphertext overlap in the low areas
	// of the plaintext. we want at most 8 bytes in the limb for
	// cpu efficiency. we use 7 bytes of plaintext, set the 62nd
	// to 58th bits high and use the lower 3 bits for padding.
	// Additionally, we require that M * k < 2^256, and so we
	// have M < 2^(256 * 3/11) < 2^69.

	// M = 2^63
	// l > 8/3 * 63 = 168
	// k in [2^l, 2^(l+1))
	//   in [2^168, 2^169)
	//   in [2^168, 2^168 + 2^168)
	//   in [0, 2^168) + 2^168

	// pick mk in [0, 2^168) then add 2^168
	mk := u256{
		l0: binary.LittleEndian.Uint64(buf[0:8]),
		l1: binary.LittleEndian.Uint64(buf[8:16]),
		l2: binary.LittleEndian.Uint64(buf[16:24]) >> 24, // (64-24)+64+64 == 168
	}
	mk = u256Add(mk, u256{l2: 1 << 40}) // 64+64+40 == 168

	rm, err := blake3.NewKeyed(buf[24:56])
	if err != nil {
		return nil, err
	}

	hm, err := blake3.NewKeyed(buf[56:88])
	if err != nil {
		return nil, err
	}

	return &Key{
		rm: rm,
		hm: hm,
		mk: mk,
	}, nil
}

func NewRandomKey(r io.Reader) (*Key, error) {
	var tmp [56]byte
	if _, err := io.ReadFull(r, tmp[:]); err != nil {
		return nil, err
	}
	return NewDerivedKey(tmp[:])
}

func Encrypt(k *Key, plaintext, buf []byte) []byte {
	rm := k.rm.Clone()

	var btmp [29]byte
	var cnt uint64

	include := func(p []byte) {
		var mtmp [8]byte
		n := copy(mtmp[1:], plaintext)
		m := binary.BigEndian.Uint64(mtmp[:])
		m = 0b1111<<59 | m<<3 | uint64(n)
		encryptOne(k.mk, rm, m, &cnt, &btmp)
		buf = append(buf, btmp[:]...)
	}

	for len(plaintext) > 7 {
		include(plaintext[:7])
		plaintext = plaintext[7:]
	}
	include(plaintext)

	if len(plaintext) == 7 {
		encryptOne(k.mk, rm, 0b1111<<59, &cnt, &btmp)
		buf = append(buf, btmp[:]...)
	}

	hm := k.hm.Clone()
	hm.Write(buf)
	buf = hm.Sum(buf)

	return buf
}

func encryptOne(mk u256, rm *blake3.Hasher, msg uint64, cnt *uint64, buf *[29]byte) {
	// TODO: this is really expensive to determinisitcally generate the
	// randomness. is there a better way?

	var mtmp [16]byte
	binary.BigEndian.PutUint64(mtmp[0:8], msg)
	binary.BigEndian.PutUint64(mtmp[8:16], *cnt)
	*cnt++
	rm.Reset()
	rm.Write(mtmp[:])

	var hmtmp [24]byte
	rbuf := rm.Sum(hmtmp[:0])

	// k in [2^168, 2^169)
	// r in (k^(3/4), k - k^(3/4))
	//   in (2^169^(3/4), 2^168 - (2^169)^(3/4))
	//   in (2^126.75, 2^168 - 2^126.75)
	//   in (2^127, 2^167 + 2^127)
	//   in (0, 2^167) + 2^127

	// pick 0 < r < 2^167 then add 2^127
	r := u256{
		l0: binary.LittleEndian.Uint64(rbuf[0:8]),
		l1: binary.LittleEndian.Uint64(rbuf[8:16]),
		l2: binary.LittleEndian.Uint64(rbuf[16:24]) >> 25, // (64-25)+64+64 == 167
	}
	r = u256Add(r, u256{l1: 1 << 63}) // 63+64 == 121

	c := u256Add(u256Scale(mk, msg), r)

	buf[0] = byte(c.l3 >> 32)
	binary.BigEndian.PutUint32(buf[1:5], uint32(c.l3))
	binary.BigEndian.PutUint64(buf[5:13], c.l2)
	binary.BigEndian.PutUint64(buf[13:21], c.l1)
	binary.BigEndian.PutUint64(buf[21:29], c.l0)
}

func Decrypt(k *Key, ciphertext, buf []byte) ([]byte, bool) {
	if len(ciphertext) < 32 {
		return buf, false
	}

	hm := k.hm.Clone()

	var mac [32]byte
	hm.Write(ciphertext[:len(ciphertext)-32])
	got := hm.Sum(mac[:0])
	if subtle.ConstantTimeCompare(ciphertext[len(ciphertext)-32:], got) != 1 {
		return buf, false
	}
	ciphertext = ciphertext[:len(ciphertext)-32]

	var mtmp [8]byte
	for len(ciphertext) > 29 {
		m := decryptOne(k.mk, ciphertext)
		if m&7 != 7 {
			return buf, false
		} else if m>>59 != 0b01111 {
			return buf, false
		}
		binary.BigEndian.PutUint64(mtmp[:], (m&^(0b1111<<59))>>3)
		buf = append(buf, mtmp[1:]...)
		ciphertext = ciphertext[29:]
	}

	m := decryptOne(k.mk, ciphertext)
	if m>>59 != 0b01111 {
		return buf, false
	}
	binary.BigEndian.PutUint64(mtmp[:], (m&^(0b1111<<59))>>3)
	buf = append(buf, mtmp[1:1+m&7]...)

	return buf, true
}

func decryptOne(mk u256, msg []byte) uint64 {
	p := u256{
		l0: binary.BigEndian.Uint64(msg[21:29]),
		l1: binary.BigEndian.Uint64(msg[13:21]),
		l2: binary.BigEndian.Uint64(msg[5:13]),
		l3: uint64(binary.BigEndian.Uint32(msg[1:5])) | uint64(msg[0])<<32,
	}
	return u256Div(p, mk)
}
