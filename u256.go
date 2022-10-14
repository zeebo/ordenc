package ordenc

import (
	"fmt"
	"math/bits"
)

type u256 struct{ l0, l1, l2, l3 uint64 }

func (u u256) String() string {
	return fmt.Sprintf("0x%016x_%016x_%016x_%016x", u.l3, u.l2, u.l1, u.l0)
}

// q + p
func u256Add(p, q u256) (o u256) {
	var c uint64
	o.l0, c = bits.Add64(q.l0, p.l0, 0)
	o.l1, c = bits.Add64(q.l1, p.l1, c)
	o.l2, c = bits.Add64(q.l2, p.l2, c)
	o.l3, _ = bits.Add64(q.l3, p.l3, c)
	return
}

// p - q
func u256Sub(p, q u256) (o u256) {
	var b uint64
	o.l0, b = bits.Sub64(p.l0, q.l0, 0)
	o.l1, b = bits.Sub64(p.l1, q.l1, b)
	o.l2, b = bits.Sub64(p.l2, q.l2, b)
	o.l3, _ = bits.Sub64(p.l3, q.l3, b)
	return
}

// s * p
func u256Scale(p u256, s uint64) (o u256) {
	var q u256
	q.l1, o.l0 = bits.Mul64(p.l0, s)
	q.l2, o.l1 = bits.Mul64(p.l1, s)
	q.l3, o.l2 = bits.Mul64(p.l2, s)
	_, o.l3 = bits.Mul64(p.l3, s)
	return u256Add(o, q)
}

// floor(p / q)
func u256Div(p, q u256) (o uint64) {
	// p < 221 bits
	// q < 161 bits
	// r < 160 bits
	// o < 60  bits

	// p = o * q + r

	// p: 0xaaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbb_cccccccccccccccc_dddddddddddddddd
	// q: 0x0000000000000000_xxxxxxxxxxxxxxxx_yyyyyyyyyyyyyyyy_zzzzzzzzzzzzzzzz

	// first, eliminate the highest word of p. underapproximate the division by
	// assuming b,c,d == 0 and that y,z == 0 and add 1 to x. thus, we compute
	// a<<64 / (x + 1) == a*2^64 / (x + 1)
	//                 == a * (2^64 / (x+1))
	//                 == a * ((2 ^ 64 - 1) + 1) / (x+1)
	//                 == a * (2^64 - 1) / (x + 1) + 1/(x+1)
	//                 =~ a * (2^64 - 1) / (x + 1)
	for p.l3 > 0 {
		ql := p.l3 * ((1<<64 - 1) / (q.l2 + 1))
		p = u256Sub(p, u256Scale(q, ql))
		o += ql
	}

	// now we have p.l3 == q.l3 == 0. we again underapproximate the division by
	// assuming that c,d == 0 and that y,z == 0 and add 1 to x. thus, we compute
	// b / (x + 1).
	for p.l2 > q.l2 {
		ql := p.l2 / (q.l2 + 1)
		p = u256Sub(p, u256Scale(q, ql))
		o += ql
	}

	// here, we fix the underapproximation by adding 1 to the output if the limbs
	// are equal.
	if p.l2 == q.l2 {
		o++
	}

	return o
}
