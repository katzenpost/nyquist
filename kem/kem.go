// Copyright (C) 2021 Yawning Angel. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Package kem implments the PQNoise Key Encapsulation Mechanism function
// abstract interface and "standard" functions.
package kem // import "gitlab.com/yawning/nyquist.git/kem"

import (
	"encoding"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/schemes"
)

var (
	// ErrMalformedPrivateKey is the error returned when a serialized
	// private key is malformed.
	ErrMalformedPrivateKey = errors.New("nyquist/kem: malformed private key")

	// ErrMalformedPublicKey is the error returned when a serialized public
	// key is malformed.
	ErrMalformedPublicKey = errors.New("nyquist/kem: malformed public key")

	// ErrMalformedCiphertext is the error returns when a serialized
	// ciphertext is malformed.
	ErrMalformedCiphertext = errors.New("nyquist/kem: malformed ciphertext")

	// ErrMismatchedPublicKey is the error returned when a public key for an
	// unexpected algorithm is provided to a KEM operation.
	ErrMismatchedPublicKey = errors.New("nyquist/kem: mismatched public key")

	// Kyber512 is the Kyber512.CCAKEM.
	Kyber512 = mustCirclToKEM("Kyber512")

	// Kyber768 is the Kyber768.CCAKEM.
	Kyber768 = mustCirclToKEM("Kyber768")

	// Kyber1024 is the Kyber1024.CCAKEM.
	Kyber1024 = mustCirclToKEM("Kyber1024")

	supportedKEMs = map[string]KEM{
		"Kyber512":  Kyber512,
		"Kyber768":  Kyber768,
		"Kyber1024": Kyber1024,
	}
)

// KEM is a Key Encapsulation Mechanism algorithm.
type KEM interface {
	fmt.Stringer

	// GenerateKeypair generates a new KEM keypair using the provided
	// entropy source.
	GenerateKeypair(rng io.Reader) (Keypair, error)

	// Enc generates a shared key and ciphertext that encapsulates it
	// for the provided public key using the provided entropy source,
	// and returns the shared key and ciphertext.
	Enc(rng io.Reader, dest PublicKey) ([]byte, []byte, error)

	// ParsePrivateKey parses a binary encoded private key.
	ParsePrivateKey(data []byte) (Keypair, error)

	// ParsePublicKey parses a binary encoded public key.
	ParsePublicKey(data []byte) (PublicKey, error)

	// PrivateKeySize returns the size of private keys in bytes.
	PrivateKeySize() int

	// PublicKeySize returns the size of public keys in bytes.
	PublicKeySize() int

	// CiphertextSize returns the size of encapsualted ciphertexts in bytes.
	CiphertextSize() int

	// SharedKeySize returns the size of the shared output in bytes.
	SharedKeySize() int
}

// FromString returns a KEM by algorithm name, or nil.
func FromString(s string) KEM {
	return supportedKEMs[s]
}

// Keypair is a KEM keypair.
type Keypair interface {
	encoding.BinaryMarshaler

	// Public returns the public key of the keypair.
	Public() PublicKey

	// Dec decapsulates the ciphertext and returns the encapsulated key.
	Dec(ct []byte) ([]byte, error)
}

// PublicKey is a KEM public key.
type PublicKey interface {
	encoding.BinaryMarshaler

	// Bytes returns the binary serialized public key.
	//
	// Warning: Altering the returned slice is unsupported and will lead
	// to unexpected behavior.
	Bytes() []byte
}

// kemCIRCL is a generic wrapper around a KEM scheme provided by CIRCL.
type kemCIRCL struct {
	name   string
	scheme kem.Scheme
}

func (impl *kemCIRCL) String() string {
	return impl.name
}

func (impl *kemCIRCL) GenerateKeypair(rng io.Reader) (Keypair, error) {
	seed := make([]byte, impl.scheme.SeedSize())
	if _, err := io.ReadFull(rng, seed); err != nil {
		return nil, err
	}

	pub, priv := impl.scheme.DeriveKeyPair(seed)

	return &keypairCIRCL{
		privateKey: priv,
		publicKey:  mustCirclToPublic(pub),
	}, nil
}

func (impl *kemCIRCL) Enc(rng io.Reader, dest PublicKey) ([]byte, []byte, error) {
	pubTo, ok := dest.(*publicKeyCIRCL)
	if !ok || pubTo.inner.Scheme() != impl.scheme {
		return nil, nil, ErrMismatchedPublicKey
	}

	seed := make([]byte, impl.scheme.EncapsulationSeedSize())
	if _, err := io.ReadFull(rng, seed); err != nil {
		return nil, nil, err
	}

	ct, ss, err := impl.scheme.EncapsulateDeterministically(pubTo.inner, seed)
	if err != nil {
		// This should NEVER happen.
		panic("nyquist/kem: failed to encapsulate: " + err.Error())
	}

	return ct, ss, nil
}

func (impl *kemCIRCL) ParsePrivateKey(data []byte) (Keypair, error) {
	priv, err := impl.scheme.UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, ErrMalformedPrivateKey
	}

	kp := &keypairCIRCL{
		privateKey: priv,
		publicKey:  mustCirclToPublic(priv.Public()),
	}

	return kp, nil
}

func (impl *kemCIRCL) ParsePublicKey(data []byte) (PublicKey, error) {
	pub, err := impl.scheme.UnmarshalBinaryPublicKey(data)
	if err != nil {
		return nil, ErrMalformedPublicKey
	}

	return mustCirclToPublic(pub), nil
}

func (impl *kemCIRCL) PrivateKeySize() int {
	return impl.scheme.PrivateKeySize()
}

func (impl *kemCIRCL) PublicKeySize() int {
	return impl.scheme.PublicKeySize()
}

func (impl *kemCIRCL) CiphertextSize() int {
	return impl.scheme.CiphertextSize()
}

func (impl *kemCIRCL) SharedKeySize() int {
	return impl.scheme.SharedKeySize()
}

// keypairCIRCL is a generic wrapper around a keypair backed by CIRCL.
type keypairCIRCL struct {
	privateKey kem.PrivateKey
	publicKey  *publicKeyCIRCL
}

func (kp *keypairCIRCL) MarshalBinary() ([]byte, error) {
	return kp.privateKey.MarshalBinary()
}

func (kp *keypairCIRCL) Dec(ct []byte) ([]byte, error) {
	kpScheme := kp.privateKey.Scheme()

	if len(ct) != kpScheme.CiphertextSize() {
		return nil, ErrMalformedCiphertext
	}

	ss, err := kpScheme.Decapsulate(kp.privateKey, ct)
	if err != nil {
		// This should NEVER happen, all KEMs that are currently still
		// in the NIST competition return a deterministic random value
		// on decapsulation failure.
		panic("nyquist/kem: failed to decapsulate: " + err.Error())
	}

	return ss, nil
}

func (kp *keypairCIRCL) Public() PublicKey {
	return kp.publicKey
}

// publicKeyCIRCL is a generic wrapper around a public key backed by CIRCL.
type publicKeyCIRCL struct {
	inner      kem.PublicKey
	innerBytes []byte
}

func (pubKey *publicKeyCIRCL) MarshalBinary() ([]byte, error) {
	return pubKey.inner.MarshalBinary()
}

func (pubKey *publicKeyCIRCL) Bytes() []byte {
	return pubKey.innerBytes
}

func mustCirclToKEM(s string) *kemCIRCL {
	scheme := schemes.ByName(s)
	if scheme == nil {
		panic("nyquist/kem: invalid scheme: " + s)
	}
	return &kemCIRCL{
		name:   s,
		scheme: scheme,
	}
}

func mustCirclToPublic(inner kem.PublicKey) *publicKeyCIRCL {
	innerBytes, _ := inner.MarshalBinary()
	return &publicKeyCIRCL{
		inner:      inner,
		innerBytes: innerBytes,
	}
}
