// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package nyquist

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/hybrid"

	"github.com/katzenpost/nyquist/cipher"
	"github.com/katzenpost/nyquist/dh"
	"github.com/katzenpost/nyquist/hash"
	"github.com/katzenpost/nyquist/pattern"
)

// TestNK1HybridNIKE drives the classical NK1 Noise pattern with a hybrid
// post-quantum NIKE (X25519-CTIDH1024) supplied via dh.FromNIKE.
func TestNK1HybridNIKE(t *testing.T) {
	require := require.New(t)

	protocol := &Protocol{
		Pattern: pattern.NK1,
		DH:      dh.FromNIKE(hybrid.X25519CTIDH1024),
		Cipher:  cipher.ChaChaPoly,
		Hash:    hash.BLAKE2s,
	}

	bobStatic, err := protocol.DH.GenerateKeypair(rand.Reader)
	require.NoError(err, "Generate Bob's static keypair")

	aliceCfg := &HandshakeConfig{
		Protocol: protocol,
		DH: &DHConfig{
			RemoteStatic: bobStatic.Public(),
		},
		IsInitiator: true,
	}
	bobCfg := &HandshakeConfig{
		Protocol: protocol,
		DH: &DHConfig{
			LocalStatic: bobStatic,
		},
		IsInitiator: false,
	}

	aliceHs, err := NewHandshake(aliceCfg)
	require.NoError(err, "NewHandshake(aliceCfg)")
	defer aliceHs.Reset()

	bobHs, err := NewHandshake(bobCfg)
	require.NoError(err, "NewHandshake(bobCfg)")
	defer bobHs.Reset()

	// NK1: -> e
	alicePayload := []byte("alice -> e")
	aliceMsg1, err := aliceHs.WriteMessage(nil, alicePayload)
	require.NoError(err, "aliceHs.WriteMessage(1)")

	bobRecv, err := bobHs.ReadMessage(nil, aliceMsg1)
	require.NoError(err, "bobHs.ReadMessage(1)")
	require.Equal(alicePayload, bobRecv)

	// NK1: <- e, ee, es  (handshake completes here)
	bobPayload := []byte("bob -> e, ee, es")
	bobMsg1, err := bobHs.WriteMessage(nil, bobPayload)
	require.Equal(ErrDone, err, "bobHs.WriteMessage(2)")

	aliceRecv, err := aliceHs.ReadMessage(nil, bobMsg1)
	require.Equal(ErrDone, err, "aliceHs.ReadMessage(2)")
	require.Equal(bobPayload, aliceRecv)

	aliceStatus := aliceHs.GetStatus()
	bobStatus := bobHs.GetStatus()

	require.Equal(aliceStatus.HandshakeHash, bobStatus.HandshakeHash, "Handshake hashes match")
	require.Equal(aliceStatus.DH.LocalEphemeral.Bytes(), bobStatus.DH.RemoteEphemeral.Bytes())
	require.Equal(bobStatus.DH.LocalEphemeral.Bytes(), aliceStatus.DH.RemoteEphemeral.Bytes())
	require.Equal(aliceStatus.DH.RemoteStatic.Bytes(), bobStatic.Public().Bytes())

	aliceTx, aliceRx := aliceStatus.CipherStates[0], aliceStatus.CipherStates[1]
	bobRx, bobTx := bobStatus.CipherStates[0], bobStatus.CipherStates[1]
	defer func() {
		aliceTx.Reset()
		aliceRx.Reset()
		bobTx.Reset()
		bobRx.Reset()
	}()

	plaintext := []byte("hello via NK1 over X25519-CTIDH1024")
	ct, err := aliceTx.EncryptWithAd(nil, nil, plaintext)
	require.NoError(err, "aliceTx.EncryptWithAd")

	pt, err := bobRx.DecryptWithAd(nil, nil, ct)
	require.NoError(err, "bobRx.DecryptWithAd")
	require.Equal(plaintext, pt)

	ack := []byte("ack")
	ct2, err := bobTx.EncryptWithAd(nil, nil, ack)
	require.NoError(err, "bobTx.EncryptWithAd")

	pt2, err := aliceRx.DecryptWithAd(nil, nil, ct2)
	require.NoError(err, "aliceRx.DecryptWithAd")
	require.Equal(ack, pt2)
}
