// Copyright (C) 2019, 2021 Yawning Angel. All rights reserved.
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

package nyquist

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"

	"gitlab.com/yawning/nyquist.git/cipher"
	"gitlab.com/yawning/nyquist.git/dh"
	"gitlab.com/yawning/nyquist.git/hash"
	"gitlab.com/yawning/nyquist.git/kem"
	"gitlab.com/yawning/nyquist.git/pattern"
)

const (
	// DefaultMaxMessageSize is the default maximum message size.
	DefaultMaxMessageSize = 65535

	// PreSharedKeySize is the size of the pre-shared symmetric key.
	PreSharedKeySize = 32

	protocolPrefix  = "Noise"
	invalidProtocol = "[invalid protocol]"
)

var (
	errTruncatedE = errors.New("nyquist/HandshakeState/ReadMessage/e: truncated message")
	errTruncatedS = errors.New("nyquist/HandshakeState/ReadMessage/s: truncated message")
	errMissingS   = errors.New("nyquist/HandshakeState/WriteMessage/s: s not set")

	errMissingPSK = errors.New("nyquist/New: missing or excessive PreSharedKey(s)")
	errBadPSK     = errors.New("nyquist/New: malformed PreSharedKey(s)")
)

// Protocol is a the protocol to be used with a handshake.
type Protocol struct {
	Pattern pattern.Pattern

	DH  dh.DH
	KEM kem.KEM

	Cipher cipher.Cipher
	Hash   hash.Hash
}

// String returns the string representation of the protocol name.
func (pr *Protocol) String() string {
	if pr.Pattern == nil || pr.Cipher == nil || pr.Hash == nil {
		return invalidProtocol
	}

	var kexStr string
	if pr.Pattern.IsKEM() {
		if pr.KEM == nil || pr.DH != nil {
			return invalidProtocol
		}
		kexStr = pr.KEM.String()
	} else {
		if pr.KEM != nil || pr.DH == nil {
			return invalidProtocol
		}
		kexStr = pr.DH.String()
	}

	parts := []string{
		protocolPrefix,
		pr.Pattern.String(),
		kexStr,
		pr.Cipher.String(),
		pr.Hash.String(),
	}
	return strings.Join(parts, "_")
}

// NewProtocol returns a Protocol from the provided (case-sensitive) protocol
// name.  Returned protocol objects may be reused across multiple
// HandshakeConfigs.
//
// Note: Only protocols that can be built with the built-in crypto and patterns
// are supported.  Using custom crypto/patterns will require manually building
// a Protocol object.
func NewProtocol(s string) (*Protocol, error) {
	parts := strings.Split(s, "_")
	if len(parts) != 5 || parts[0] != protocolPrefix {
		return nil, ErrProtocolNotSupported
	}

	var pr Protocol
	if pr.Pattern = pattern.FromString(parts[1]); pr.Pattern != nil {
		if pr.Pattern.IsKEM() {
			pr.KEM = kem.FromString(parts[2])
		} else {
			pr.DH = dh.FromString(parts[2])
		}
	}
	pr.Cipher = cipher.FromString(parts[3])
	pr.Hash = hash.FromString(parts[4])

	if pr.Pattern == nil || (pr.DH == nil && pr.KEM == nil) || pr.Cipher == nil || pr.Hash == nil {
		return nil, ErrProtocolNotSupported
	}

	return &pr, nil
}

// HandshakeConfig is a handshake configuration.
//
// Warning: While the config may contain sensitive material like DH private
// keys or a pre-shared key, sanitizing such things are the responsibility of
// the caller, after the handshake completes (or aborts due to an error).
//
// Altering any of the members of this structure while a handshake is in
// progress will result in undefined behavior.
type HandshakeConfig struct {
	// Protocol is the noise protocol to use for this handshake.
	Protocol *Protocol

	// Prologue is the optional pre-handshake prologue input to be included
	// in the handshake hash.
	Prologue []byte

	// DH is the Diffie-Hellman keys for this handshake.
	DH *DHConfig

	// PreSharedKeys is the vector of pre-shared symmetric key for PSK mode
	// handshakes.
	PreSharedKeys [][]byte

	// Observer is the optional handshake observer.
	Observer HandshakeObserver

	// Rng is the entropy source to be used when entropy is required.
	// If the value is `nil`, `crypto/rand.Reader` will be used.
	Rng io.Reader

	// MaxMessageSize specifies the maximum Noise message size the handshake
	// and session will process or generate.  If the value is `0`,
	// `DefaultMaxMessageSize` will be used.  A negative value will disable
	// the maximum message size enforcement entirely.
	//
	// Warning: Values other than the default is a non-standard extension
	// to the protocol.
	MaxMessageSize int

	// IsInitiator should be set to true if this handshake is in the
	// initiator role.
	IsInitiator bool
}

// DHConfig is the Diffie-Hellman (DH) key configuration of a handshake.
type DHConfig struct {
	// LocalStatic is the local static keypair, if any (`s`).
	LocalStatic dh.Keypair

	// LocalEphemeral is the local ephemeral keypair, if any (`e`).
	LocalEphemeral dh.Keypair

	// RemoteStatic is the remote static public key, if any (`rs`).
	RemoteStatic dh.PublicKey

	// RemoteEphemeral is the remote ephemeral public key, if any (`re`).
	RemoteEphemeral dh.PublicKey
}

// HandshakeStatus is the status of a handshake.
//
// Warning: It is the caller's responsibility to sanitize the CipherStates
// if desired.  Altering any of the members of this structure while a handshake
// is in progress will result in undefined behavior.
type HandshakeStatus struct {
	// Err is the error representing the status of the handshake.
	//
	// It will be `nil` if the handshake is in progess, `ErrDone` if the
	// handshake is complete, and any other error if the handshake has failed.
	Err error

	// DH is the Diffie-Hellman public keys of the handshake.
	DH *DHStatus

	// CipherStates is the resulting CipherState pair (`(cs1, cs2)`).
	//
	// Note: To prevent misuse, for one-way patterns `cs2` will be nil.
	CipherStates []*CipherState

	// HandshakeHash is the handshake hash (`h`).  This field is only set
	// once the handshake is completed.
	HandshakeHash []byte
}

// DHStatus is the Diffie-Hellman (DH) status of a handshake.
type DHStatus struct {
	// LocalEphemeral is the local ephemeral public key, if any (`e`).
	LocalEphemeral dh.PublicKey

	// RemoteStatic is the remote static public key, if any (`rs`).
	RemoteStatic dh.PublicKey

	// RemoteEphemeral is the remote ephemeral public key, if any (`re`).
	RemoteEphemeral dh.PublicKey
}

// HandshakeObserver is a handshake observer for monitoring handshake status.
type HandshakeObserver interface {
	// OnPeerPublicKeyDH will be called when a Diffie-Hellman public key
	// is received from the peer, with the handshake pattern token
	// (`pattern.Token_e`, `pattern.Token_s`) and public key.
	//
	// Returning a non-nil error will abort the handshake immediately.
	OnPeerPublicKeyDH(pattern.Token, dh.PublicKey) error
}

func (cfg *HandshakeConfig) getRng() io.Reader {
	if cfg.Rng == nil {
		return rand.Reader
	}
	return cfg.Rng
}

func (cfg *HandshakeConfig) getMaxMessageSize() int {
	if cfg.MaxMessageSize > 0 {
		return cfg.MaxMessageSize
	}
	if cfg.MaxMessageSize == 0 {
		return DefaultMaxMessageSize
	}
	return 0
}

// HandshakeState is the per-handshake state.
type HandshakeState struct {
	cfg *HandshakeConfig

	patterns []pattern.Message

	dh *dhState
	ss *SymmetricState

	status *HandshakeStatus

	patternIndex   int
	pskIndex       int
	maxMessageSize int
	isInitiator    bool
}

type dhState struct {
	impl dh.DH

	s  dh.Keypair
	e  dh.Keypair
	rs dh.PublicKey
	re dh.PublicKey

	pkLen int // aka DHLEN
}

// SymmetricState returns the HandshakeState's encapsulated SymmetricState.
//
// Warning: There should be no reason to call this, ever.
func (hs *HandshakeState) SymmetricState() *SymmetricState {
	return hs.ss
}

// GetStatus returns the HandshakeState's status.
func (hs *HandshakeState) GetStatus() *HandshakeStatus {
	return hs.status
}

// Reset clears the HandshakeState, to prevent future calls.
//
// Warning: If either of the local keypairs were provided by the
// HandshakeConfig, they will be left intact.
func (hs *HandshakeState) Reset() {
	if hs.ss != nil {
		hs.ss.Reset()
		hs.ss = nil
	}
	if hs.cfg.DH != nil && hs.dh != nil {
		if hs.dh.s != nil && hs.dh.s != hs.cfg.DH.LocalStatic {
			// Having a local static key, that isn't from the config currently can't
			// happen, but this is harmless.
			hs.dh.s.DropPrivate()
		}
		if hs.dh.e != nil && hs.dh.e != hs.cfg.DH.LocalEphemeral {
			hs.dh.e.DropPrivate()
		}
	}
	// TODO: Should this set hs.status.Err?
}

func (hs *HandshakeState) onWriteTokenE(dst []byte) []byte {
	dh := hs.dh

	// hs.cfg.DH.LocalEphemeral can be used to pre-generate the ephemeral key,
	// so only generate when required.
	if dh.e == nil {
		if dh.e, hs.status.Err = dh.impl.GenerateKeypair(hs.cfg.getRng()); hs.status.Err != nil {
			return nil
		}
	}
	eBytes := dh.e.Public().Bytes()
	hs.ss.MixHash(eBytes)
	if hs.cfg.Protocol.Pattern.NumPSKs() > 0 {
		hs.ss.MixKey(eBytes)
	}
	hs.status.DH.LocalEphemeral = dh.e.Public()
	return append(dst, eBytes...)
}

func (hs *HandshakeState) onReadTokenE(payload []byte) []byte {
	dh := hs.dh

	dhLen := dh.pkLen
	if len(payload) < dhLen {
		hs.status.Err = errTruncatedE
		return nil
	}
	eBytes, tail := payload[:dhLen], payload[dhLen:]
	if dh.re, hs.status.Err = dh.impl.ParsePublicKey(eBytes); hs.status.Err != nil {
		return nil
	}
	hs.status.DH.RemoteEphemeral = dh.re
	if hs.cfg.Observer != nil {
		if hs.status.Err = hs.cfg.Observer.OnPeerPublicKeyDH(pattern.Token_e, dh.re); hs.status.Err != nil {
			return nil
		}
	}
	hs.ss.MixHash(eBytes)
	if hs.cfg.Protocol.Pattern.NumPSKs() > 0 {
		hs.ss.MixKey(eBytes)
	}
	return tail
}

func (hs *HandshakeState) onWriteTokenS(dst []byte) []byte {
	dh := hs.dh

	if dh.s == nil {
		hs.status.Err = errMissingS
		return nil
	}
	sBytes := dh.s.Public().Bytes()
	return hs.ss.EncryptAndHash(dst, sBytes)
}

func (hs *HandshakeState) onReadTokenS(payload []byte) []byte {
	dh := hs.dh

	tempLen := dh.pkLen
	if hs.ss.cs.HasKey() {
		// The spec says `DHLEN + 16`, but doing it this way allows this
		// implementation to support any AEAD implementation, regardless of
		// tag size.
		tempLen += hs.ss.cs.aead.Overhead()
	}
	if len(payload) < tempLen {
		hs.status.Err = errTruncatedS
		return nil
	}
	temp, tail := payload[:tempLen], payload[tempLen:]

	var sBytes []byte
	if sBytes, hs.status.Err = hs.ss.DecryptAndHash(nil, temp); hs.status.Err != nil {
		return nil
	}
	if dh.rs, hs.status.Err = dh.impl.ParsePublicKey(sBytes); hs.status.Err != nil {
		return nil
	}
	hs.status.DH.RemoteStatic = dh.rs
	if hs.cfg.Observer != nil {
		if hs.status.Err = hs.cfg.Observer.OnPeerPublicKeyDH(pattern.Token_s, dh.rs); hs.status.Err != nil {
			return nil
		}
	}
	return tail
}

func (hs *HandshakeState) onTokenEE() {
	var eeBytes []byte
	if eeBytes, hs.status.Err = hs.dh.e.DH(hs.dh.re); hs.status.Err != nil {
		return
	}
	hs.ss.MixKey(eeBytes)
}

func (hs *HandshakeState) onTokenES() {
	var esBytes []byte
	if hs.isInitiator {
		esBytes, hs.status.Err = hs.dh.e.DH(hs.dh.rs)
	} else {
		esBytes, hs.status.Err = hs.dh.s.DH(hs.dh.re)
	}
	if hs.status.Err != nil {
		return
	}
	hs.ss.MixKey(esBytes)
}

func (hs *HandshakeState) onTokenSE() {
	var seBytes []byte
	if hs.isInitiator {
		seBytes, hs.status.Err = hs.dh.s.DH(hs.dh.re)
	} else {
		seBytes, hs.status.Err = hs.dh.e.DH(hs.dh.rs)
	}
	if hs.status.Err != nil {
		return
	}
	hs.ss.MixKey(seBytes)
}

func (hs *HandshakeState) onTokenSS() {
	var ssBytes []byte
	if ssBytes, hs.status.Err = hs.dh.s.DH(hs.dh.rs); hs.status.Err != nil {
		return
	}
	hs.ss.MixKey(ssBytes)
}

func (hs *HandshakeState) onTokenPsk() {
	// PSK is validated at handshake creation.
	hs.ss.MixKeyAndHash(hs.cfg.PreSharedKeys[hs.pskIndex])
	hs.pskIndex++
}

func (hs *HandshakeState) onDone(dst []byte) ([]byte, error) {
	hs.patternIndex++
	if hs.patternIndex < len(hs.patterns) {
		return dst, nil
	}

	hs.status.Err = ErrDone
	cs1, cs2 := hs.ss.Split()
	if hs.cfg.Protocol.Pattern.IsOneWay() {
		cs2.Reset()
		cs2 = nil
	}
	hs.status.CipherStates = []*CipherState{cs1, cs2}
	hs.status.HandshakeHash = hs.ss.GetHandshakeHash()

	// This will end up being called redundantly if the developer has any
	// sense at al, but it's cheap foot+gun avoidance.
	hs.Reset()

	return dst, hs.status.Err
}

// WriteMessage processes a write step of the handshake protocol, appending the
// handshake protocol message to dst, and returning the potentially new slice.
//
// Iff the handshake is complete, the error returned will be `ErrDone`.
func (hs *HandshakeState) WriteMessage(dst, payload []byte) ([]byte, error) {
	if hs.status.Err != nil {
		return nil, hs.status.Err
	}

	if hs.isInitiator != (hs.patternIndex&1 == 0) {
		hs.status.Err = ErrOutOfOrder
		return nil, hs.status.Err
	}

	baseLen := len(dst)
	for _, v := range hs.patterns[hs.patternIndex] {
		switch v {
		case pattern.Token_e:
			dst = hs.onWriteTokenE(dst)
		case pattern.Token_s:
			dst = hs.onWriteTokenS(dst)
		case pattern.Token_ee:
			hs.onTokenEE()
		case pattern.Token_es:
			hs.onTokenES()
		case pattern.Token_se:
			hs.onTokenSE()
		case pattern.Token_ss:
			hs.onTokenSS()
		case pattern.Token_psk:
			hs.onTokenPsk()
		default:
			hs.status.Err = errors.New("nyquist/HandshakeState/WriteMessage: invalid token: " + v.String())
		}

		if hs.status.Err != nil {
			return nil, hs.status.Err
		}
	}

	dst = hs.ss.EncryptAndHash(dst, payload)
	if hs.maxMessageSize > 0 && len(dst)-baseLen > hs.maxMessageSize {
		hs.status.Err = ErrMessageSize
		return nil, hs.status.Err
	}

	return hs.onDone(dst)
}

// ReadMessage processes a read step of the handshake protocol, appending the
// authentiated/decrypted message payload to dst, and returning the potentially
// new slice.
//
// Iff the handshake is complete, the error returned will be `ErrDone`.
func (hs *HandshakeState) ReadMessage(dst, payload []byte) ([]byte, error) {
	if hs.status.Err != nil {
		return nil, hs.status.Err
	}

	if hs.maxMessageSize > 0 && len(payload) > hs.maxMessageSize {
		hs.status.Err = ErrMessageSize
		return nil, hs.status.Err
	}

	if hs.isInitiator != (hs.patternIndex&1 != 0) {
		hs.status.Err = ErrOutOfOrder
		return nil, hs.status.Err
	}

	for _, v := range hs.patterns[hs.patternIndex] {
		switch v {
		case pattern.Token_e:
			payload = hs.onReadTokenE(payload)
		case pattern.Token_s:
			payload = hs.onReadTokenS(payload)
		case pattern.Token_ee:
			hs.onTokenEE()
		case pattern.Token_es:
			hs.onTokenES()
		case pattern.Token_se:
			hs.onTokenSE()
		case pattern.Token_ss:
			hs.onTokenSS()
		case pattern.Token_psk:
			hs.onTokenPsk()
		default:
			hs.status.Err = errors.New("nyquist/HandshakeState/ReadMessage: invalid token: " + v.String())
		}

		if hs.status.Err != nil {
			return nil, hs.status.Err
		}
	}

	dst, hs.status.Err = hs.ss.DecryptAndHash(dst, payload)
	if hs.status.Err != nil {
		return nil, hs.status.Err
	}

	return hs.onDone(dst)
}

type bytesAble interface {
	Bytes() []byte
}

func (hs *HandshakeState) handlePreMessages() error {
	preMessages := hs.cfg.Protocol.Pattern.PreMessages()
	if len(preMessages) == 0 {
		return nil
	}

	// Gather all the public keys from the config, from the initiator's
	// point of view.
	var s, e, rs, re bytesAble
	if dh := hs.dh; dh != nil {
		rs, re = dh.rs, dh.re
		if dh.s != nil {
			s = dh.s.Public()
		}
		if dh.e != nil {
			e = dh.e.Public()
		}
	} else {
		panic("not implemented")
	}
	if !hs.isInitiator {
		s, e, rs, re = rs, re, s, e
	}

	for i, keys := range []struct {
		s, e bytesAble
		side string
	}{
		{s, e, "initiator"},
		{rs, re, "responder"},
	} {
		if i+1 > len(preMessages) {
			break
		}

		for _, v := range preMessages[i] {
			switch v {
			case pattern.Token_e:
				// While the specification allows for `e` tokens in the
				// pre-messages, there are currently no patterns that use
				// such a construct.
				//
				// While it is possible to generate `e` if it is the local
				// one that is missing, that would be stretching a use-case
				// that is already somewhat nonsensical.
				if keys.e == nil {
					return fmt.Errorf("nyquist/New: %s e not set", keys.side)
				}
				pkBytes := keys.e.Bytes()
				hs.ss.MixHash(pkBytes)
				if hs.cfg.Protocol.Pattern.NumPSKs() > 0 {
					hs.ss.MixKey(pkBytes)
				}
			case pattern.Token_s:
				if keys.s == nil {
					return fmt.Errorf("nyquist/New: %s s not set", keys.side)
				}
				hs.ss.MixHash(keys.s.Bytes())
			default:
				return errors.New("nyquist/New: invalid pre-message token: " + v.String())
			}
		}
	}

	return nil
}

// NewHandshake constructs a new HandshakeState with the provided configuration.
// This call is equivalent to the `Initialize` HandshakeState call in the
// Noise Protocol Framework specification.
func NewHandshake(cfg *HandshakeConfig) (*HandshakeState, error) {
	// TODO: Validate the config further?

	if cfg.Protocol.Pattern.NumPSKs() != len(cfg.PreSharedKeys) {
		return nil, errMissingPSK
	}
	for _, v := range cfg.PreSharedKeys {
		if len(v) != PreSharedKeySize {
			return nil, errBadPSK
		}
	}

	maxMessageSize := cfg.getMaxMessageSize()
	hs := &HandshakeState{
		cfg:            cfg,
		patterns:       cfg.Protocol.Pattern.Messages(),
		ss:             newSymmetricState(cfg.Protocol.Cipher, cfg.Protocol.Hash, maxMessageSize),
		status:         &HandshakeStatus{},
		maxMessageSize: maxMessageSize,
		isInitiator:    cfg.IsInitiator,
	}
	if cfg.Protocol.Pattern.IsKEM() {
		// TODO: Handle PQConfig
		panic("not implemented")
	} else {
		hs.dh = &dhState{
			impl:  cfg.Protocol.DH,
			pkLen: cfg.Protocol.DH.Size(),
		}
		hs.status.DH = &DHStatus{}
		if dhCfg := cfg.DH; dhCfg != nil {
			hs.dh.s = dhCfg.LocalStatic
			hs.dh.e = dhCfg.LocalEphemeral
			hs.dh.rs = dhCfg.RemoteStatic
			hs.dh.re = dhCfg.RemoteEphemeral
			hs.status.DH.RemoteStatic = dhCfg.RemoteStatic
			hs.status.DH.RemoteEphemeral = dhCfg.RemoteEphemeral

			if dhCfg.LocalEphemeral != nil {
				hs.status.DH.LocalEphemeral = dhCfg.LocalEphemeral.Public()
			}
		}
	}

	hs.ss.InitializeSymmetric([]byte(cfg.Protocol.String()))
	hs.ss.MixHash(cfg.Prologue)
	if err := hs.handlePreMessages(); err != nil {
		return nil, err
	}

	return hs, nil
}
