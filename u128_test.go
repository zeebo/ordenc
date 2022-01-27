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

var b192 = new(big.Int).Lsh(big.NewInt(1), 192)

func u192ToBig(x u192) *big.Int {
	b := big.NewInt(0)
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

func TestU192_Add(t *testing.T) {
	rng := mwc.Rand()

	for i := 0; i < 1000000; i++ {
		n := u192{rng.Uint64(), rng.Uint64(), rng.Uint64()}
		m := u192{rng.Uint64(), rng.Uint64(), rng.Uint64()}
		p := u192Add(n, m)

		pb := new(big.Int).Add(u192ToBig(n), u192ToBig(m))
		pb = pb.Mod(pb, b192)

		assert.Equal(t, u192ToBig(p).Bytes(), pb.Bytes())
	}
}

func TestU192_Sub(t *testing.T) {
	rng := mwc.Rand()

	for i := 0; i < 1000000; i++ {
		n := u192{rng.Uint64(), rng.Uint64(), rng.Uint64()}
		m := u192{rng.Uint64(), rng.Uint64(), rng.Uint64()}
		p := u192Sub(n, m)

		pb := new(big.Int).Sub(u192ToBig(n), u192ToBig(m))
		pb = pb.Mod(pb, b192)

		assert.Equal(t, u192ToBig(p).Bytes(), pb.Bytes())
	}
}

func TestU192_Scale(t *testing.T) {
	r := mwc.Rand()

	for i := 0; i < 1000000; i++ {
		n := u192{r.Uint64(), r.Uint64(), r.Uint64()}
		s := r.Uint64()
		p := u192Scale(n, s)

		pb := new(big.Int).Mul(u192ToBig(n), new(big.Int).SetUint64(s))
		pb = pb.Mod(pb, b192)

		assert.Equal(t, u192ToBig(p).Bytes(), pb.Bytes())
	}
}

func TestU192_Div(t *testing.T) {
	rng := mwc.Rand()

	for i := 0; i < 10000000; i++ {
		// for i := 0; i < 10; i++ {
		// o in [0, 2^51)
		o := rng.Uint64n(1 << 51)

		// q in [2^136, 2^137)
		q := u192{
			l0: rng.Uint64(),
			l1: rng.Uint64(),
			l2: rng.Uint64()>>56 | 1<<8,
		}

		// r in (k^.75, k - k^.75)
		//   in (2^102.75, k - k^.75)
		//   in (2^103, k - k^.75)
		//   in (2^103, 2^136 - 2^102)
		//   in (2^103, 2^135 + 2^103)
		//   in 2^103 + (0, 2^135)
		r := u192{
			l0: rng.Uint64(),
			l1: rng.Uint64(),
			l2: rng.Uint64() >> 57,
		}
		r = u192Add(r, u192{
			l0: 0,
			l1: 1 << 39,
			l2: 0,
		})

		p := u192Add(u192Scale(q, o), r)

		// t.Logf("o: %016x", o)
		// t.Logf("q: %036x", u192ToBig(q).Bytes())
		// t.Logf("r: %036x", u192ToBig(r).Bytes())
		// t.Logf("p: %x", u192ToBig(p).Bytes())
		// t.Log()

		assert.Equal(t, o, u192Div(p, q))
	}
}

//
// benchmarks
//

func BenchmarkU192_Add(b *testing.B) {
	rng := mwc.Rand()

	n := u192{rng.Uint64(), rng.Uint64(), rng.Uint64()}

	var p u192
	for i := 0; i < b.N; i++ {
		p = u192Add(n, p)
	}
	runtime.KeepAlive(p)
}

func BenchmarkU192_Sub(b *testing.B) {
	rng := mwc.Rand()

	n := u192{rng.Uint64(), rng.Uint64(), rng.Uint64()}

	var p u192
	for i := 0; i < b.N; i++ {
		p = u192Sub(n, p)
	}
	runtime.KeepAlive(p)
}

func BenchmarkU192_Scale(b *testing.B) {
	rng := mwc.Rand()

	n := u192{rng.Uint64(), rng.Uint64(), rng.Uint64()}
	s := rng.Uint64()

	var p u192
	for i := 0; i < b.N; i++ {
		p = u192Scale(n, s)
	}
	runtime.KeepAlive(p)
}

func BenchmarkU192_Div(b *testing.B) {
	rng := mwc.Rand()

	q := u192{rng.Uint64(), rng.Uint64(), 0}
	q.l1 |= 1 << 63
	r := u192{rng.Uint64(), rng.Uint64n(1 << 62), 0}
	r = u192Add(r, u192{0, 1 << 32, 0})
	p := u192Scale(q, rng.Uint64n(1<<48))

	var o uint64
	for i := 0; i < b.N; i++ {
		o = u192Div(p, q)
	}
	runtime.KeepAlive(o)
}
