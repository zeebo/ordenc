package ordenc

import (
	"math/big"
	"runtime"
	"testing"

	"github.com/zeebo/assert"
	"github.com/zeebo/mwc"
)

//
// helpers
//

var b256 = new(big.Int).Lsh(big.NewInt(1), 256)

func u256ToBig(x u256) *big.Int {
	b := big.NewInt(0)
	b = b.Add(b, big.NewInt(0).SetUint64(x.l3))
	b = b.Lsh(b, 64)
	b = b.Add(b, big.NewInt(0).SetUint64(x.l2))
	b = b.Lsh(b, 64)
	b = b.Add(b, big.NewInt(0).SetUint64(x.l1))
	b = b.Lsh(b, 64)
	b = b.Add(b, big.NewInt(0).SetUint64(x.l0))
	return b
}

//
// tests
//

func TestU256_Add(t *testing.T) {
	rng := mwc.Rand()

	for i := 0; i < 1000000; i++ {
		n := u256{rng.Uint64(), rng.Uint64(), rng.Uint64(), rng.Uint64()}
		m := u256{rng.Uint64(), rng.Uint64(), rng.Uint64(), rng.Uint64()}
		p := u256Add(n, m)

		pb := new(big.Int).Add(u256ToBig(n), u256ToBig(m))
		pb = pb.Mod(pb, b256)

		assert.Equal(t, u256ToBig(p).Bytes(), pb.Bytes())
	}
}

func TestU256_Sub(t *testing.T) {
	rng := mwc.Rand()

	for i := 0; i < 1000000; i++ {
		n := u256{rng.Uint64(), rng.Uint64(), rng.Uint64(), rng.Uint64()}
		m := u256{rng.Uint64(), rng.Uint64(), rng.Uint64(), rng.Uint64()}
		p := u256Sub(n, m)

		pb := new(big.Int).Sub(u256ToBig(n), u256ToBig(m))
		pb = pb.Mod(pb, b256)

		assert.Equal(t, u256ToBig(p).Bytes(), pb.Bytes())
	}
}

func TestU256_Scale(t *testing.T) {
	r := mwc.Rand()

	for i := 0; i < 1000000; i++ {
		n := u256{r.Uint64(), r.Uint64(), r.Uint64(), r.Uint64()}
		s := r.Uint64()
		p := u256Scale(n, s)

		pb := new(big.Int).Mul(u256ToBig(n), new(big.Int).SetUint64(s))
		pb = pb.Mod(pb, b256)

		assert.Equal(t, u256ToBig(p).Bytes(), pb.Bytes())
	}
}

func TestU256_Div(t *testing.T) {
	rng := mwc.Rand()

	for i := 0; i < 10000000; i++ {
		// o in [0, 2^60)
		o := rng.Uint64n(1 << 60)

		// q \in [2^160, 2^161)
		q := u256{
			l0: rng.Uint64(),
			l1: rng.Uint64(),
			l2: rng.Uint64() >> 32, // (64-32)+64+64 == 160
		}
		q = u256Add(q, u256{l2: 1 << 32}) // 64+64+32 == 160

		// r in (k^(3/4), k - k^(3/4))
		//   in (2^161^(3/4), 2^160 - (2^161)^(3/4))
		//   in (2^120.75, 2^160 - 2^120.75)
		//   in (2^121, 2^159 + 2^121)
		//   in (0, 2^159) + 2^121
		r := u256{
			l0: rng.Uint64(),
			l1: rng.Uint64(),
			l2: rng.Uint64() >> 33, // (64-33)+64+64 == 159
		}
		r = u256Add(r, u256{l1: 1 << 57}) // 57+64 == 121

		p := u256Add(u256Scale(q, o), r)

		assert.Equal(t, o, u256Div(p, q))
	}
}

//
// benchmarks
//

func BenchmarkU256_Add(b *testing.B) {
	rng := mwc.Rand()

	n := u256{rng.Uint64(), rng.Uint64(), rng.Uint64(), rng.Uint64()}

	var p u256
	for i := 0; i < b.N; i++ {
		p = u256Add(n, p)
	}
	runtime.KeepAlive(p)
}

func BenchmarkU256_Sub(b *testing.B) {
	rng := mwc.Rand()

	n := u256{rng.Uint64(), rng.Uint64(), rng.Uint64(), rng.Uint64()}

	var p u256
	for i := 0; i < b.N; i++ {
		p = u256Sub(n, p)
	}
	runtime.KeepAlive(p)
}

func BenchmarkU256_Scale(b *testing.B) {
	rng := mwc.Rand()

	n := u256{rng.Uint64(), rng.Uint64(), rng.Uint64(), rng.Uint64()}
	s := rng.Uint64()

	var p u256
	for i := 0; i < b.N; i++ {
		p = u256Scale(n, s)
	}
	runtime.KeepAlive(p)
}

func BenchmarkU256_Div(b *testing.B) {
	rng := mwc.Rand()

	q := u256{l0: rng.Uint64(), l1: rng.Uint64(), l2: rng.Uint64() >> 32}
	q = u256Add(q, u256{l2: 1 << 32})
	r := u256{l0: rng.Uint64(), l1: rng.Uint64(), l2: rng.Uint64() >> 33}
	r = u256Add(r, u256{l1: 1 << 57})
	p := u256Scale(q, rng.Uint64n(1<<60))

	var o uint64
	for i := 0; i < b.N; i++ {
		o = u256Div(p, q)
	}
	runtime.KeepAlive(o)
}
