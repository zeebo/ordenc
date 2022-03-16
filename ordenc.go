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
	mk u192
}

func NewDerivedKey(mat []byte) (*Key, error) {
	var buf [24 + 32 + 32]byte
	blake3.DeriveKey("ordenc v0 root key derivation", mat, buf[:])

	mk := u192{
		l0: binary.LittleEndian.Uint64(buf[0:8]),
		l1: binary.LittleEndian.Uint64(buf[8:16]),
		l2: binary.LittleEndian.Uint64(buf[16:24])>>56 | 1<<8,
	}

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

	var btmp [24]byte

	for len(plaintext) > 6 {
		var mtmp [8]byte
		n := copy(mtmp[2:], plaintext)
		m := binary.BigEndian.Uint64(mtmp[:])
		m = m<<3 | uint64(n)

		encryptOne(k.mk, rm, m, &btmp)
		buf = append(buf, btmp[:]...)

		plaintext = plaintext[6:]
	}

	var mtmp [8]byte
	n := copy(mtmp[2:], plaintext)
	m := binary.BigEndian.Uint64(mtmp[:])
	m = m<<3 | uint64(n)

	encryptOne(k.mk, rm, m, &btmp)
	buf = append(buf, btmp[:]...)

	if n == 6 {
		encryptOne(k.mk, rm, 0, &btmp)
		buf = append(buf, btmp[:]...)
	}

	hm := k.hm.Clone()
	hm.Write(buf)
	buf = hm.Sum(buf)

	return buf
}

func encryptOne(mk u192, rm *blake3.Hasher, msg uint64, buf *[24]byte) {
	// TODO: this is really expensive to determinisitcally generate the
	// randomness. is there a better way?

	var mtmp [8]byte
	binary.BigEndian.Uint64(mtmp[:])
	rm.Reset()
	rm.Write(mtmp[:])

	var hmtmp [32]byte
	mac := rm.Sum(hmtmp[:0])

	r := u192{
		l0: binary.LittleEndian.Uint64(mac[0:8]),
		l1: binary.LittleEndian.Uint64(mac[8:16]),
		l2: binary.LittleEndian.Uint64(mac[16:24]) >> 57,
	}
	r = u192Add(r, u192{l0: 0, l1: 1 << 39, l2: 0})

	c := u192Add(u192Scale(mk, msg), r)

	binary.BigEndian.PutUint64(buf[0:8], c.l2)
	binary.BigEndian.PutUint64(buf[8:16], c.l1)
	binary.BigEndian.PutUint64(buf[16:24], c.l0)
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
	for len(ciphertext) > 24 {
		m := decryptOne(k.mk, ciphertext)
		if m&7 != 6 {
			return buf, false
		}
		binary.BigEndian.PutUint64(mtmp[:], m>>3)
		buf = append(buf, mtmp[2:]...)
		ciphertext = ciphertext[24:]
	}

	m := decryptOne(k.mk, ciphertext)
	if m&7 >= 6 {
		return buf, false
	}
	binary.BigEndian.PutUint64(mtmp[:], m>>3)
	buf = append(buf, mtmp[2:2+m&7]...)

	return buf, true
}

func decryptOne(mk u192, msg []byte) uint64 {
	p := u192{
		l0: binary.BigEndian.Uint64(msg[16:24]),
		l1: binary.BigEndian.Uint64(msg[8:16]),
		l2: binary.BigEndian.Uint64(msg[0:8]),
	}
	return u192Div(p, mk)
}
