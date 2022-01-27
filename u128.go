package ordenc

import (
	"fmt"
	"math/bits"
)

type u192 struct{ l0, l1, l2 uint64 }

func (u u192) String() string {
	return fmt.Sprintf("%016x %016x %016x", u.l2, u.l1, u.l0)
}

// q + p
func u192Add(p, q u192) (o u192) {
	var c uint64
	o.l0, c = bits.Add64(q.l0, p.l0, 0)
	o.l1, c = bits.Add64(q.l1, p.l1, c)
	o.l2, _ = bits.Add64(q.l2, p.l2, c)
	return
}

// p - q
func u192Sub(p, q u192) (o u192) {
	var b uint64
	o.l0, b = bits.Sub64(p.l0, q.l0, 0)
	o.l1, b = bits.Sub64(p.l1, q.l1, b)
	o.l2, _ = bits.Sub64(p.l2, q.l2, b)
	return
}

func u192Scale(p u192, s uint64) (o u192) {
	var q u192
	q.l1, o.l0 = bits.Mul64(p.l0, s)
	q.l2, o.l1 = bits.Mul64(p.l1, s)
	_, o.l2 = bits.Mul64(p.l2, s)
	return u192Add(o, q)
}

func u192Div(p, q u192) (o uint64) {
	// p ~ 188 bits
	// q ~ 137 bits
	// r ~ 135 bits
	// o ~ 51  bits

	// p = o * q + r

	// b^2          b            1
	// -----------------------------------
	// r.l2         r.l1         r.l0
	//              h(q.l0*o)    l(q.l0*o)
	// h(q.l1*o)    l(q.l1*o)
	// l(q.l2*o)

	// p.l2 = r.l2 + h(q.l1*o) + l(q.l2*o)
	// p.l1 = r.l1 + h(q.l0*o) + l(q.l1*o)
	// p.l0 = r.l0 + l(q.l0*o)

	for p.l2 > q.l2 {
		ql := p.l2 / (q.l2 + 1)
		p = u192Sub(p, u192Scale(q, ql))
		o += ql
	}

	if p.l2 == q.l2 {
		o++
	}

	return o
}
