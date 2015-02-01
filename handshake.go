// Copyright 2015 JPH <jph@hackworth.be>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cryptoauth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

type Challenge struct {
	Type                                uint8
	Lookup                              [7]byte
	RequirePacketAuthAndDerivationCount uint16
	Additional                          uint16
}

type Handshake struct {
	Stage                                  uint32
	Challenge                              *Challenge // We use a generic container initially then decode it into appropriate struct later
	Nonce                                  [24]byte   // 24 bytes
	PublicKey                              *[32]byte
	AuthenticatorAndEncryptedTempPublicKey []byte
	Authenticator                          [16]byte // 16 bytes
	TempPublicKey                          [32]byte // 32 bytes
	Data                                   []byte
}

func (h *Handshake) Len() int {
	return len(h.Data)
}

func (h *Handshake) Marshal(peer *Peer) ([]byte, error) {

	var out []byte

	authenticatedAndEncryptedTempPubKey := box.SealAfterPrecomputation(out, peer.TempKeyPair.PublicKey[:], &h.Nonce, peer.Secret)
	//encryptRandomNonce(h.Nonce, peer.TempKeyPair.PublicKey[:], peer.Secret)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, h.Stage)
	binary.Write(buf, binary.BigEndian, h.Challenge.Type)
	binary.Write(buf, binary.BigEndian, h.Challenge.Lookup)
	binary.Write(buf, binary.BigEndian, h.Challenge.RequirePacketAuthAndDerivationCount)
	binary.Write(buf, binary.BigEndian, h.Challenge.Additional)
	binary.Write(buf, binary.BigEndian, h.Nonce)
	binary.Write(buf, binary.BigEndian, h.PublicKey)
	binary.Write(buf, binary.BigEndian, authenticatedAndEncryptedTempPubKey)

	return buf.Bytes(), nil
}

func parseHandshake(data []byte) (*Handshake, error) {

	h := new(Handshake)
	h.Challenge = new(Challenge)

	// Store the raw data for quick manipulations later
	copy(h.Data, data)

	if len(data) < 120 {
		return nil, fmt.Errorf("CryptoAuthHandshake header too short")
	}

	r := bytes.NewReader(data)
	binary.Read(r, binary.BigEndian, &h.Stage)
	binary.Read(r, binary.BigEndian, &h.Challenge.Type)
	binary.Read(r, binary.BigEndian, &h.Challenge.Lookup)
	binary.Read(r, binary.BigEndian, &h.Challenge.RequirePacketAuthAndDerivationCount)
	binary.Read(r, binary.BigEndian, &h.Challenge.Additional)
	binary.Read(r, binary.BigEndian, &h.Nonce)
	binary.Read(r, binary.BigEndian, &h.PublicKey)
	binary.Read(r, binary.BigEndian, &h.Authenticator)
	binary.Read(r, binary.BigEndian, &h.TempPublicKey)
	return h, nil
}

func (peer *Peer) newHandshake(msg []byte, isSetup int, state *CryptoAuthState) (*Handshake, error) {

	var err error

	h := new(Handshake)
	h.Challenge = new(Challenge)

	h.Stage = peer.NextNonce

	// Generate a new random 24 byte nonce.
	newNonce := make([]byte, 24)
	rand.Read(newNonce)
	copy(h.Nonce[:], newNonce)

	h.PublicKey = state.KeyPair.PublicKey

	if isEmpty(peer.PasswordHash) == false {
		panic("encryptHandshake: got here")
		h.Challenge.Type = 1
	} else {
		h.Challenge.Type = 0
	}

	h.Challenge.RequirePacketAuthAndDerivationCount |= (1 << 15)
	h.Challenge.Additional &= ^uint16(1 << 15)

	if peer.NextNonce == 0 || peer.NextNonce == 2 {
		if peer.TempKeyPair == nil {
			peer.TempKeyPair, err = createTempKeyPair()
			if err != nil {
				return nil, err
			}
		}
	}

	if peer.NextNonce < 2 {
		peer.Secret = computeSharedSecretWithPasswordHash(state.KeyPair.PrivateKey, peer.PublicKey, peer.PasswordHash)
		peer.Initiator = true
		peer.NextNonce = 1
	} else {
		peer.Secret = computeSharedSecret(state.KeyPair.PrivateKey, peer.TempPublicKey)
		peer.NextNonce = 3
	}

	// Key Packet
	if peer.NextNonce == 2 {
		peer.Secret = computeSharedSecretWithPasswordHash(state.KeyPair.PrivateKey, peer.TempPublicKey, peer.PasswordHash)
	}

	return h, nil

}

func computeSharedSecret(privateKey *[32]byte, herPublicKey [32]byte) (secret *[32]byte) {

	// TODO: check this, is this right way to check for empty [32]byte?
	box.Precompute(secret, &herPublicKey, privateKey)
	return secret
}

func computeSharedSecretWithPasswordHash(privateKey *[32]byte, herPublicKey [32]byte, passwordHash [32]byte) *[32]byte {

	// TODO: check this, is this right way to check for empty [32]byte?

	var computedKey [32]byte
	curve25519.ScalarMult(&computedKey, privateKey, &herPublicKey)

	buff := make([]byte, 64)
	copy(buff[:32], computedKey[:])
	copy(buff[32:64], passwordHash[:])

	secret := sha256.Sum256(buff)

	return &secret
}
