// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ristretto

import (
	"encoding/base64"
	"errors"

	"filippo.io/edwards25519"
)

// A Scalar is an element of the ristretto255 scalar field, as specified in
// RFC 9496, Section 4.4. That is, an integer modulo
//
//	l = 2^252 + 27742317777372353535851937790883648493
//
// The zero value is a valid zero element.
type Scalar struct {
	s edwards25519.Scalar
}

// NewScalar returns a Scalar set to the value 0.
func NewScalar() *Scalar {
	return &Scalar{}
}

// Set sets the value of s to x and returns s.
func (s *Scalar) Set(x *Scalar) *Scalar {
	*s = *x
	return s
}

// Add sets s = x + y mod l and returns s.
func (s *Scalar) Add(x, y *Scalar) *Scalar {
	s.s.Add(&x.s, &y.s)
	return s
}

// Subtract sets s = x - y mod l and returns s.
func (s *Scalar) Subtract(x, y *Scalar) *Scalar {
	s.s.Subtract(&x.s, &y.s)
	return s
}

// Negate sets s = -x mod l and returns s.
func (s *Scalar) Negate(x *Scalar) *Scalar {
	s.s.Negate(&x.s)
	return s
}

// Multiply sets s = x * y mod l and returns s.
func (s *Scalar) Multiply(x, y *Scalar) *Scalar {
	s.s.Multiply(&x.s, &y.s)
	return s
}

// MultiplyAdd sets s = x * y + z mod l, and returns s. It is equivalent to
// using Multiply and then Add.
func (s *Scalar) MultiplyAdd(x, y, z *Scalar) *Scalar {
	// Make a copy of z in case it aliases s.
	zCopy := new(Scalar).Set(z)
	return s.Multiply(x, y).Add(s, zCopy)
}

// Invert sets s = 1 / x such that s * x = 1 mod l and returns s.
//
// If x is 0, the result is undefined.
func (s *Scalar) Invert(x *Scalar) *Scalar {
	s.s.Invert(&x.s)
	return s
}

// FromUniformBytes sets s to a uniformly distributed value given 64 uniformly
// distributed random bytes.
//
// Deprecated: use SetUniformBytes. This API will be removed before v1.0.0.
func (s *Scalar) FromUniformBytes(x []byte) *Scalar {
	if _, err := s.SetUniformBytes(x); err != nil {
		panic(err.Error())
	}
	return s
}

// SetBytesWithClamping applies the buffer pruning described in RFC 8032,
// Section 5.1.5 (also known as clamping) and sets s to the result. The input
// must be 32 bytes, and it is not modified. If x is not of the right length,
// SetBytesWithClamping returns nil and an error, and the receiver is unchanged.
//
// Note that since Scalar values are always reduced modulo the prime order of
// the curve, the resulting value will not preserve any of the cofactor-clearing
// properties that clamping is meant to provide. It will however work as
// expected as long as it is applied to points on the prime order subgroup, like
// in Ed25519. In fact, it is lost to history why RFC 8032 adopted the
// irrelevant RFC 7748 clamping, but it is now required for compatibility.
func (s *Scalar) SetBytesWithClamping(x []byte) (*Scalar, error) {
	// The description above omits the purpose of the high bits of the clamping
	// for brevity, but those are also lost to reductions, and are also
	// irrelevant to edwards25519 as they protect against a specific
	// implementation bug that was once observed in a generic Montgomery ladder.
	if len(x) != 32 {
		return nil, errors.New("edwards25519: invalid SetBytesWithClamping input length")
	}

	// We need to use the wide reduction from SetUniformBytes, since clamping
	// sets the 2^254 bit, making the value higher than the order.
	var wideBytes [64]byte
	copy(wideBytes[:], x[:])
	wideBytes[0] &= 248
	wideBytes[31] &= 63
	wideBytes[31] |= 64
	return s.SetUniformBytes(wideBytes[:])
}

// SetUniformBytes sets s to a uniformly distributed value given 64 uniformly
// distributed random bytes by interpreting the 64-byte string as a 512-bit
// unsigned integer in little-endian order and reducing the integer modulo l.
//
// If x is not of the right length, SetUniformBytes returns nil and an error,
// and the receiver is unchanged.
func (s *Scalar) SetUniformBytes(x []byte) (*Scalar, error) {
	if _, err := s.s.SetUniformBytes(x); err != nil {
		return nil, errors.New("ristretto255: SetUniformBytes input is not 64 bytes long")
	}
	return s, nil
}

// Decode sets s = x, where x is a 32 bytes little-endian encoding of s. If x is
// not a canonical encoding of s, Decode returns an error and the receiver is
// unchanged.
//
// Deprecated: use SetCanonicalBytes. This API will be removed before v1.0.0.
func (s *Scalar) Decode(x []byte) error {
	_, err := s.SetCanonicalBytes(x)
	return err
}

// SetCanonicalBytes sets s = x, where x is a 32 bytes little-endian encoding of
// s. If x is not a canonical encoding of s, SetCanonicalBytes returns nil and
// an error and the receiver is unchanged.
func (s *Scalar) SetCanonicalBytes(x []byte) (*Scalar, error) {
	if _, err := s.s.SetCanonicalBytes(x); err != nil {
		return nil, errors.New("ristretto255: " + err.Error())
	}
	return s, nil
}

// Encode appends a 32 bytes little-endian encoding of s to b.
//
// Deprecated: use Bytes. This API will be removed before v1.0.0.
func (s *Scalar) Encode(b []byte) []byte {
	ret, out := sliceForAppend(b, 32)
	copy(out, s.s.Bytes())
	return ret
}

// Bytes returns the 32 bytes little-endian canonical encoding of s.
func (s *Scalar) Bytes() []byte {
	return s.s.Bytes()
}

// Equal returns 1 if v and u are equal, and 0 otherwise.
func (s *Scalar) Equal(u *Scalar) int {
	return s.s.Equal(&u.s)
}

// Zero sets s = 0 and returns s.
func (s *Scalar) Zero() *Scalar {
	s.s = edwards25519.Scalar{}
	return s
}

// MarshalText implements encoding/TextMarshaler interface
func (s *Scalar) MarshalText() (text []byte, err error) {
	b := s.Encode([]byte{})
	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}

// UnmarshalText implements encoding/TextMarshaler interface
func (s *Scalar) UnmarshalText(text []byte) error {
	sb, err := base64.StdEncoding.DecodeString(string(text))
	if err == nil {
		return s.Decode(sb)
	}
	return err
}

// String implements the Stringer interface
func (s *Scalar) String() string {
	result, _ := s.MarshalText()
	return string(result)
}
