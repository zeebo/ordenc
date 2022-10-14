package ordenc

import (
	"sort"
	"testing"

	"github.com/zeebo/assert"
	"github.com/zeebo/mwc"
)

func TestEncrypt(t *testing.T) {
	rng := mwc.Rand()
	var e1, e2 []byte

	for i := 0; i < 100000; i++ {
		k, err := NewRandomKey(&rng)
		assert.NoError(t, err)

		b1 := make([]byte, rng.Intn(15))
		rng.Read(b1)
		b2 := make([]byte, rng.Intn(15))
		rng.Read(b2)

		e1 := Encrypt(k, b1, e1[:0])
		e2 := Encrypt(k, b2, e2[:0])

		if string(b1) < string(b2) {
			assert.That(t, string(e1) < string(e2))
		} else if string(b1) > string(b2) {
			assert.That(t, string(e1) > string(e2))
		}
	}
}

func TestCiphertextRange(t *testing.T) {
	rng := mwc.Rand()

	var (
		ldist [256]uint64
		hdist [256]uint64
	)

	low := []byte{}
	high := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	buf := make([]byte, 128)

	for i := 0; i < 100000; i++ {
		k, err := NewRandomKey(&rng)
		assert.NoError(t, err)

		ldist[Encrypt(k, low, buf[:0])[0]]++
		hdist[Encrypt(k, high, buf[:0])[0]]++
	}

	var l1norm uint64
	for i := 0; i < 256; i++ {
		if hdist[i] > ldist[i] {
			l1norm += hdist[i] - ldist[i]
		} else {
			l1norm += ldist[i] - hdist[i]
		}
	}

	t.Logf("%-4d", ldist)
	t.Logf("%-4d", hdist)
	t.Log(l1norm)
}

func TestEncryptSpecialCases(t *testing.T) {
	rng := mwc.Rand()

	specials := []string{
		"",
		"\x00",
		"\x00\x00",
		"\x00\x00\x00",
		"\x00\x00\x00\x00",
		"\x00\x00\x00\x00\x00",
		"\x00\x00\x00\x00\x00\x00",
		"\x00\x00\x00\x00\x00\x00\x00",
		"\x00\x00\x00\x00\x00\x00\x00\x00",
		"\x01",
		"\x01\x00",
		"\x01\x00\x00",
		"\x01\x00\x00\x00",
		"\x01\x00\x00\x00\x00",
		"\x01\x00\x00\x00\x00\x00",
		"\x01\x00\x00\x00\x00\x00\x00",
		"\x01\x00\x00\x00\x00\x00\x00\x00",
		"\x01\x00\x00\x00\x00\x00\x00\x01",
		"\xff\xff\xff\xff\xff\xff\xff",
	}

	sort.Strings(specials)

	for i := 0; i < 10000; i++ {
		k, err := NewRandomKey(&rng)
		assert.NoError(t, err)

		for i := 0; i < len(specials)-1; i++ {
			assert.That(t, specials[i] < specials[i+1])

			e1 := string(Encrypt(k, []byte(specials[i]), nil))
			e2 := string(Encrypt(k, []byte(specials[i+1]), nil))

			assert.That(t, e1 < e2)
		}
	}
}

func TestDecrypt(t *testing.T) {
	rng := mwc.Rand()
	var e, d []byte
	var ok bool

	for i := 0; i < 100000; i++ {
		k, err := NewRandomKey(&rng)
		assert.NoError(t, err)

		p := make([]byte, rng.Intn(15))
		rng.Read(p)

		e := Encrypt(k, p, e[:0])
		d, ok = Decrypt(k, e, d[:0])

		assert.That(t, ok)
		assert.Equal(t, p, d)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	rng := mwc.Rand()
	k, err := NewRandomKey(&rng)
	assert.NoError(b, err)

	plain := make([]byte, 24)
	cipher := make([]byte, 5*24)

	b.SetBytes(int64(len(plain)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cipher = Encrypt(k, plain, cipher[:0])
	}
}

func BenchmarkDecrypt(b *testing.B) {
	rng := mwc.Rand()
	k, err := NewRandomKey(&rng)
	assert.NoError(b, err)

	plain := make([]byte, 24)
	cipher := Encrypt(k, plain, nil)

	b.SetBytes(int64(len(plain)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		plain, _ = Decrypt(k, cipher, plain[:0])
	}
}
