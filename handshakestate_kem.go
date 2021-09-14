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

package nyquist

import "gitlab.com/yawning/nyquist.git/pattern"

func (hs *HandshakeState) onWriteTokenE_KEM(dst []byte) []byte {
	// hs.cfg.KEM.LocalEphemeral can be used to pre-generate the ephemeral key,
	// so only generate when required.
	if hs.kem.e == nil {
		if hs.kem.e, hs.status.Err = hs.kem.impl.GenerateKeypair(hs.cfg.getRng()); hs.status.Err != nil {
			return nil
		}
	}

	eBytes := hs.kem.e.Public().Bytes()
	hs.status.KEM.LocalEphemeral = hs.kem.e.Public()

	hs.ss.MixHash(eBytes)
	if hs.cfg.Protocol.Pattern.NumPSKs() > 0 {
		hs.ss.MixKey(eBytes)
	}
	return append(dst, eBytes...)
}

func (hs *HandshakeState) onReadTokenE_KEM(payload []byte) []byte {
	pkLen := hs.kem.pkLen
	if len(payload) < pkLen {
		hs.status.Err = errTruncatedE
		return nil
	}
	eBytes, tail := payload[:pkLen], payload[pkLen:]
	if hs.kem.re, hs.status.Err = hs.kem.impl.ParsePublicKey(eBytes); hs.status.Err != nil {
		return nil
	}
	hs.status.KEM.RemoteEphemeral = hs.kem.re
	if hs.cfg.KEM != nil && hs.cfg.KEM.Observer != nil {
		if hs.status.Err = hs.cfg.KEM.Observer.OnPeerPublicKey(pattern.Token_e, hs.kem.re); hs.status.Err != nil {
			return nil
		}
	}
	hs.ss.MixHash(eBytes)
	if hs.cfg.Protocol.Pattern.NumPSKs() > 0 {
		hs.ss.MixKey(eBytes)
	}
	return tail
}

func (hs *HandshakeState) onWriteTokenS_KEM(dst []byte) []byte {
	if hs.kem.s == nil {
		hs.status.Err = errMissingS
		return nil
	}
	sBytes := hs.kem.s.Public().Bytes()
	return hs.ss.EncryptAndHash(dst, sBytes)
}

func (hs *HandshakeState) onReadTokenS_KEM(payload []byte) []byte {
	tempLen := hs.kem.pkLen
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
	if hs.kem.rs, hs.status.Err = hs.kem.impl.ParsePublicKey(sBytes); hs.status.Err != nil {
		return nil
	}
	hs.status.KEM.RemoteStatic = hs.kem.rs
	if hs.cfg.KEM != nil && hs.cfg.KEM.Observer != nil {
		if hs.status.Err = hs.cfg.KEM.Observer.OnPeerPublicKey(pattern.Token_s, hs.kem.rs); hs.status.Err != nil {
			return nil
		}
	}
	return tail
}
