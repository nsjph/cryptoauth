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
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"log"
	"math"
)

type Handshake struct {
	Stage               uint32     // 4 bytes (4)
	Challenge           *Challenge // 12 bytes (16)
	Nonce               [24]byte   // 24 bytes (40)
	PublicKey           [32]byte   // 32 bytes (72)
	EncryptedTempPubKey [32]byte
	Payload             []byte
}

func isKeyPacket(nonce uint32) bool {
	if nonce == 2 || nonce == 3 {
		return true
	}
	return false
}

func isHelloPacket(nonce uint32) bool {
	if nonce == 1 {
		return true
	}
	return false
}

func isHandshakePacket(nonce uint32) bool {
	if nonce < 4 && nonce != math.MaxUint32 {
		return true
	}
	return false
}

func requiresTempKeyPair(stage uint32) bool {
	switch stage {
	case 0:
		log.Print("stage 0 requires tempkey")
		return true
	case 2:
		log.Print("stage 2 requires tempkey")
		return true
	default:
		log.Print("stage default requires tempkey")
		return false
	}

	if debugHandshake {
		log.Print("requiresTempPublicKey (fell through): ", stage)
	}
	return false
}

func NewHandshake(stage uint32, challenge *Challenge, local *CryptoState, remote *CryptoState, passwordHash *[32]byte) ([]byte, error) {

	var err error
	var secret [32]byte

	h := &Handshake{
		Stage:     stage,
		PublicKey: local.perm.PublicKey,
	}

	if h.Nonce, err = newNonce(); err != nil {
		return nil, err
	}

	if isHelloPacket(stage) == true {
		secret = computeSharedSecretWithPasswordHash(&local.perm.PrivateKey, &remote.perm.PublicKey, passwordHash)
	} else if isKeyPacket(stage) == true {
		secret = computeSharedSecret(&local.perm.PrivateKey, &remote.temp.PublicKey)
	} else {
		return nil, errInvalid.setInfo(fmt.Sprintf("Don't know how to compute a shared secret for stage: %u", stage))
	}

	// Build the packet
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, h.Stage)
	binary.Write(buf, binary.BigEndian, challenge.Type)
	binary.Write(buf, binary.BigEndian, challenge.Lookup)
	binary.Write(buf, binary.BigEndian, challenge.Derivations)
	binary.Write(buf, binary.BigEndian, challenge.Additional)
	binary.Write(buf, binary.BigEndian, h.Nonce)
	binary.Write(buf, binary.BigEndian, h.PublicKey)

	var out []byte

	if local.temp == nil {
		local.temp, _ = createTempKeyPair()
	}

	encryptedTempPubKey := box.SealAfterPrecomputation(out, local.temp.PublicKey[:], &h.Nonce, &secret)

	if debugHandshake {
		log.Printf("encryptedTempPubKey:\n\tnonce [%x]\n\tsecret [%x]\n\tmyTempPubKey [%x]", h.Nonce, secret, local.temp.PublicKey)
		log.Printf("buf.Bytes() len [%d]", len(buf.Bytes()))
	}

	binary.Write(buf, binary.BigEndian, encryptedTempPubKey)

	if debugHandshake {
		log.Print("length of new handshake: ", len(buf.Bytes()))
	}

	return buf.Bytes(), nil

}

func (c *Connection) DecodeHandshake2(nonce uint32, p []byte) error {

	var nextNonce uint32 = 0

	if len(p) < 120 {
		if debugHandshake {
			log.Printf("Received undersized message: %d long", len(p))
		}
		return errUndersizeMessage
	}

	h := new(Handshake)
	h.Challenge = new(Challenge)

	r := bytes.NewReader(p)
	binary.Read(r, binary.BigEndian, &h.Stage)
	binary.Read(r, binary.BigEndian, &h.Challenge.Type)
	binary.Read(r, binary.BigEndian, &h.Challenge.Lookup)
	binary.Read(r, binary.BigEndian, &h.Challenge.Derivations)
	binary.Read(r, binary.BigEndian, &h.Challenge.Additional)
	binary.Read(r, binary.BigEndian, &h.Nonce)
	binary.Read(r, binary.BigEndian, &h.PublicKey)

	// Get the password hash
	if err := authenticateChallenge(c.passwordHash, p[4:16]); err != nil {
		return err
	}

	if isHelloPacket(nonce) == true {
		c.remote.perm.PublicKey = h.PublicKey
		c.secret = computeSharedSecretWithPasswordHash(&c.local.perm.PrivateKey, &c.remote.perm.PublicKey, &c.passwordHash)
		nextNonce = 2
	} else {
		if constantTimeCompare(h.PublicKey[:], c.remote.perm.PublicKey[:]) == 0 {
			debugHandshakeLogWithDetails("DecodeHandshake2", "permanent public key is different!")
			return errAuthentication.setInfo("Permanent public key doesn't match known")
		}
		if c.local.isInitiator == false {
			debugHandshakeLogWithDetails("DecodeHandshake2", "drop stray key packet")
			return errAuthentication.setInfo("drop stray key packet")
		}
		c.secret = computeSharedSecretWithPasswordHash(&c.local.temp.PrivateKey, &c.remote.perm.PublicKey, &c.passwordHash)
		nextNonce = 4
	}

	decrypted, success := box.OpenAfterPrecomputation(p[72:], p[72:], &h.Nonce, &c.secret)
	if success == false {
		panic("failed to decrypt temp public key")
		return errAuthentication.setInfo("failed to decrypt temp public key")
	}

	herTempPublicKey := decrypted[88:120]

	// post-decryption checks

	if nonce == 0 {
		if constantTimeCompare(c.remote.temp.PublicKey[:], herTempPublicKey) == 1 {
			debugHandshakeLogWithDetails("DecodeHandshake2", "dupe hello with same temp key")
			return errAuthentication.setInfo("hello packet with duplicate temp key")
		}
	} else if nonce == 2 && c.local.nextNonce >= 4 {
		if constantTimeCompare(c.remote.temp.PublicKey[:], herTempPublicKey) == 1 {
			debugHandshakeLogWithDetails("DecodeHandshake2", "dupe hello with same temp key")
			return errAuthentication.setInfo("hello packet with duplicate temp key")
		}
	} else if nonce == 3 && c.local.nextNonce >= 4 {
		if constantTimeCompare(c.remote.temp.PublicKey[:], herTempPublicKey) == 0 {
			debugHandshakeLogWithDetails("DecodeHandshake2", "repeat key apcket with diff temp public key")
		}
	}

	if nextNonce == 4 {
		if c.local.nextNonce <= 4 {
			c.local.nextNonce = nextNonce
			constantTimeCopy(1, c.remote.temp.PublicKey[:], herTempPublicKey)
		} else {
			c.secret = computeSharedSecret(&c.local.temp.PrivateKey, &c.remote.temp.PublicKey)
		}

	} else if nextNonce != 2 {
		panic("should never get here")
	} else if c.local.isInitiator == false || c.isEstablished == true {
		if c.isEstablished == true {
			c.resetSession()
		}

		if c.local.nextNonce == 3 {
			nextNonce = 3
		}

		if c.local.nextNonce > nextNonce {
			panic("beep beep ritchie")
		}
		c.local.nextNonce = nextNonce

		if c.remote.temp == nil {
			debugHandshakeLogWithDetails("DecodeHandshake2", "remote temp keypair is nil, allocating a new struct")
			c.remote.temp = new(KeyPair)
		}

		constantTimeCopy(1, c.remote.temp.PublicKey[:32], herTempPublicKey[:])
	} else if bytes.Compare(h.PublicKey[:], c.remote.perm.PublicKey[:]) == -1 {
		debugHandshakeLogWithDetails("DecodeHandshake2", "Incoming hello from client with lower public key, resetting session")
		c.resetSession()
		if c.local.nextNonce > nextNonce {
			panic("beep beep ritchie")
		}
		c.local.nextNonce = nextNonce
		constantTimeCopy(1, c.remote.temp.PublicKey[:], herTempPublicKey[:])
	} else {
		debugHandshakeLogWithDetails("DecodeHandshake2", "Incoming hello from client with higher pubkey, not resetting session")
	}

	if constantTimeCompare(c.remote.perm.PublicKey[:32], h.PublicKey[:32]) == 0 {
		constantTimeCopy(1, c.remote.perm.PublicKey[:32], h.PublicKey[:])
	}

	return nil
}
