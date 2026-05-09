// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package dh

import (
	"io"

	"github.com/katzenpost/hpqc/nike"
)

// FromNIKE returns a DH that wraps an hpqc nike.Scheme. This permits the
// use of arbitrary NIKE schemes, including post-quantum hybrids such as
// X25519-CTIDH1024, with classical Noise patterns (NK, NK1, XX, XK, ...).
//
// DHLEN is taken from the scheme's public key size. The shared secret
// returned by DH() is whatever the scheme's DeriveSecret returns; for a
// hybrid NIKE this is the concatenation of each component's shared secret.
func FromNIKE(scheme nike.Scheme) DH {
	return &nikeDH{scheme: scheme}
}

type nikeDH struct {
	scheme nike.Scheme
}

func (n *nikeDH) String() string {
	return n.scheme.Name()
}

func (n *nikeDH) GenerateKeypair(rng io.Reader) (Keypair, error) {
	_, priv, err := n.scheme.GenerateKeyPairFromEntropy(rng)
	if err != nil {
		return nil, err
	}
	return &nikeKeypair{scheme: n.scheme, priv: priv}, nil
}

func (n *nikeDH) ParsePrivateKey(data []byte) (Keypair, error) {
	priv, err := n.scheme.UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, ErrMalformedPrivateKey
	}
	return &nikeKeypair{scheme: n.scheme, priv: priv}, nil
}

func (n *nikeDH) ParsePublicKey(data []byte) (PublicKey, error) {
	pub, err := n.scheme.UnmarshalBinaryPublicKey(data)
	if err != nil {
		return nil, ErrMalformedPublicKey
	}
	return &nikePublicKey{scheme: n.scheme, pub: pub}, nil
}

func (n *nikeDH) Size() int {
	return n.scheme.PublicKeySize()
}

type nikeKeypair struct {
	scheme nike.Scheme
	priv   nike.PrivateKey
}

func (kp *nikeKeypair) MarshalBinary() ([]byte, error) {
	return kp.priv.MarshalBinary()
}

func (kp *nikeKeypair) UnmarshalBinary(data []byte) error {
	priv, err := kp.scheme.UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return ErrMalformedPrivateKey
	}
	kp.priv = priv
	return nil
}

func (kp *nikeKeypair) DropPrivate() {
	if kp.priv != nil {
		kp.priv.Reset()
	}
}

func (kp *nikeKeypair) Public() PublicKey {
	return &nikePublicKey{scheme: kp.scheme, pub: kp.priv.Public()}
}

func (kp *nikeKeypair) DH(publicKey PublicKey) ([]byte, error) {
	pk, ok := publicKey.(*nikePublicKey)
	if !ok {
		return nil, ErrMismatchedPublicKey
	}
	return kp.scheme.DeriveSecret(kp.priv, pk.pub), nil
}

type nikePublicKey struct {
	scheme nike.Scheme
	pub    nike.PublicKey
}

func (pk *nikePublicKey) MarshalBinary() ([]byte, error) {
	return pk.pub.MarshalBinary()
}

func (pk *nikePublicKey) UnmarshalBinary(data []byte) error {
	pub, err := pk.scheme.UnmarshalBinaryPublicKey(data)
	if err != nil {
		return ErrMalformedPublicKey
	}
	pk.pub = pub
	return nil
}

func (pk *nikePublicKey) Bytes() []byte {
	return pk.pub.Bytes()
}
