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
	"encoding/binary"
	_ "fmt"
	"github.com/davecgh/go-spew/spew"
	"golang.org/x/crypto/nacl/box"
	"io"
	"log"
)

type Handshake struct {
	Stage               uint32     // 4 bytes (4)
	Challenge           *Challenge // 12 bytes (16)
	Nonce               [24]byte   // 24 bytes (40)
	PublicKey           [32]byte   // 32 bytes (72)
	EncryptedTempPubKey [32]byte
	Payload             []byte
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

func NewHandshake(stage uint32, challenge *Challenge, local *CryptoState, remote *CryptoState, passwordHash [32]byte) ([]byte, error) {

	var err error

	if debugHandshake {
		log.Println("NewHandshake")
		spew.Printf("Stage: [%v] Challenge: %v Local: %v Remote: %v\n", stage, challenge, local, remote)
	}

	h := &Handshake{
		Stage:     stage,
		PublicKey: local.perm.PublicKey,
	}

	// Generate random bytes for nonce... We trust that is is random and unique but
	// we don't currently implement a way to track/verify
	nonce := make([]byte, 24)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	copy(h.Nonce[:], nonce)

	// Check if we need a temp key pair at this stage of handshake. If so, generate them
	//
	// TODO (#design): I'm assuming that during a handshake, we will always, eventually need a temp key pair.
	// Does it make sense to create it by default each time if it doesn't exist?
	// if requiresTempKeyPair(stage) == true {
	// 	local.temp = new(KeyPair)
	// 	pk, sk, err := box.GenerateKey(rand.Reader)
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	copy(local.temp.PublicKey[:], pk[:])
	// 	copy(local.temp.PrivateKey[:], sk[:])

	// 	if debugHandshake {
	// 		spew.Printf("Generated new temporary keypair: %v\n", local.temp)
	// 	}
	// }

	// Get the shared secret to use

	secret := getSharedSecret(local, remote, passwordHash)

	// TODO: verify we have a temp public key set before attempting to encrypt it

	// Build the packet
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, h.Stage)
	binary.Write(buf, binary.BigEndian, challenge.Type)
	binary.Write(buf, binary.BigEndian, challenge.Lookup)
	binary.Write(buf, binary.BigEndian, challenge.Derivations)
	binary.Write(buf, binary.BigEndian, challenge.Additional)
	//binary.Write(buf, binary.BigEndian, challenge)
	binary.Write(buf, binary.BigEndian, h.Nonce)
	binary.Write(buf, binary.BigEndian, h.PublicKey)

	// Encrypt the temp public key. Add it to the handshake.

	var out []byte

	if local.temp == nil {
		local.temp, _ = createTempKeyPair()
	}

	spew.Dump(local.temp)

	encryptedTempPubKey := box.SealAfterPrecomputation(out, local.temp.PublicKey[:], &h.Nonce, secret)

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

func (c *Connection) DecodeHandshake(nonce uint32, p []byte) error {

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

	//var herPermPublicKey [32]byte
	nextNonce := 0
	nextNonce++ // compile hack so it is 'declared and used'

	//nextNonce = 0

	if nonce < 2 {
		if nonce == 0 {
			if debugHandshake == true {
				log.Printf("Received hello packet")
			}
		} else {
			if debugHandshake == true {
				log.Printf("Received repeate hello packet")
			}
		}

		if isEmpty(c.remote.perm.PublicKey) == true {
			c.remote.perm.PublicKey = h.PublicKey
		} else {
			// compare known public key against received
			if c.remote.perm.PublicKey != h.PublicKey {
				if debugHandshake == true {
					log.Println("receievd public key doesn't match known")
				}
				return errAuthentication
			}
		}
		c.secret = *getSharedSecret(c.local, c.remote, c.passwordHash)
		nextNonce = 2
	} else {
		if nonce == 2 {
			if debugHandshake == true {
				log.Println("Received a key packet")
			}
		} else if nonce == 3 {
			if debugHandshake == true {
				log.Println("Received a repeat key packet")
			}
		} else {
			if debugHandshake == true {
				log.Printf("Received unknown packet: nonce [%u]", nonce)
			}
			return errAuthentication
		}
		if c.local.isInitiator == false {
			if debugHandshake == true {
				log.Println("Dropping stray key packet")
			}
			return errAuthentication
		}

		if c.remote.perm.PublicKey != h.PublicKey {
			if debugHandshake == true {
				log.Println("received public key doesn't match known")
			}
			return errAuthentication
		}

		c.secret = *getSharedSecret(c.local, c.remote, c.passwordHash)
		nextNonce = 4
	}

	if debugHandshake == true {
		log.Printf("decrypting temp public key with\n\tsecret: [%x]\n\tnonce: [%x]", c.secret, h.Nonce)
	}

	// byte 72 of a handshake is where the authenticated and encrypted temp public key begins

	decrypted, success := box.OpenAfterPrecomputation(p[72:], p[72:], &h.Nonce, &c.secret)
	if success == false {
		if debugHandshake {
			log.Printf("Error decrypting temp public key from peer")
		}
		return errUndeliverable
	} else {
		// successfully decrypted
		if debugHandshake == true {
			log.Println("decrypted temp pub key successfully")
		}
		// byte 88 is where the actual temp public key is in the decrypted variable
		copy(c.remote.temp.PublicKey[:], decrypted[88:120])
	}
	// 88 - 120 is the public key part
	h.EncryptedTempPubKey = c.remote.temp.PublicKey
	//copy(h.EncryptedTempPubKey[:], decrypted[88:120])

	// Put the decrypted portion longer than 120 into handshake payload
	copy(h.Payload, decrypted[120:])

	if isEmpty(c.remote.perm.PublicKey) {
		copy(c.remote.perm.PublicKey[:], p[40:72])
		if !isValidIPv6PublicKey(c.remote.perm.PublicKey) {
			return errAuthentication.setInfo("Remote perm Public Key is not valid for IPv6")
		}
	}

	return nil
}

// func (h *Handshake) Marshal(peer *Peer) ([]byte, error) {

// 	var out []byte

// 	authenticatedAndEncryptedTempPubKey := box.SealAfterPrecomputation(out, peer.LocalTempKeyPair.PublicKey[:], &h.Nonce, peer.Secret)
// 	//encryptRandomNonce(h.Nonce, peer.LocalTempKeyPair.PublicKey[:], peer.Secret)

// 	buf := new(bytes.Buffer)
// 	binary.Write(buf, binary.BigEndian, h.Stage)
// 	binary.Write(buf, binary.BigEndian, h.Challenge.Type)
// 	binary.Write(buf, binary.BigEndian, h.Challenge.Lookup)
// 	binary.Write(buf, binary.BigEndian, h.Challenge.RequirePacketAuthAndDerivationCount)
// 	binary.Write(buf, binary.BigEndian, h.Challenge.Additional)
// 	binary.Write(buf, binary.BigEndian, h.Nonce)
// 	binary.Write(buf, binary.BigEndian, h.PublicKey)
// 	binary.Write(buf, binary.BigEndian, authenticatedAndEncryptedTempPubKey)

// 	return buf.Bytes(), nil
// }

// // Logic to validate if an inbound handshake is correct based
// // on the existing state of the peer

// // TODO: Some of this should be split into pre-handshake creation and post-handshake creation
// // Validate is also a misnomer, since validation happens here and in validate.go... :\

// func (peer *Peer) parseHandshake(stage uint32, data []byte) (*Handshake, error) {

// 	log.Println("parseHandshake: stage is %d", stage)

// 	h := new(Handshake)
// 	h.Challenge = new(Challenge)
// 	h.Data = make([]byte, len(data))

// 	// Store the raw data for quick manipulations later
// 	copy(h.Data[:], data)

// 	//
// 	if len(data) < 120 && stage >= 4 {
// 		return nil, fmt.Errorf("CryptoAuthHandshake header too short")
// 	}

// 	r := bytes.NewReader(data)
// 	binary.Read(r, binary.BigEndian, &h.Stage)
// 	binary.Read(r, binary.BigEndian, &h.Challenge.Type)
// 	binary.Read(r, binary.BigEndian, &h.Challenge.Lookup)
// 	binary.Read(r, binary.BigEndian, &h.Challenge.RequirePacketAuthAndDerivationCount)
// 	binary.Read(r, binary.BigEndian, &h.Challenge.Additional)
// 	binary.Read(r, binary.BigEndian, &h.Nonce)
// 	binary.Read(r, binary.BigEndian, &h.PublicKey)
// 	binary.Read(r, binary.BigEndian, &h.Authenticator)
// 	binary.Read(r, binary.BigEndian, &h.TempPublicKey)

// 	spew.Dump(h)

// 	return h, nil
// }

// // func (peer *Peer) newHandshake(msg []byte, isSetup int) (*Handshake, error) {

// // 	var err error

// // 	h := new(Handshake)
// // 	h.Challenge = new(Challenge)

// // 	h.Stage = peer.NextNonce

// // 	// Generate a new random 24 byte nonce.
// // 	newNonce := make([]byte, 24)
// // 	rand.Read(newNonce)
// // 	copy(h.Nonce[:], newNonce)

// // 	copy(h.PublicKey[:], peer.Local.KeyPair.PublicKey[:])

// // 	if isEmpty(peer.PasswordHash) == false && peer.Initiator == true {
// // 		panic("encryptHandshake: got here")
// // 		h.Challenge.Type = 1
// // 	} else {
// // 		h.Challenge.Type = 0
// // 	}

// // 	h.Challenge.RequirePacketAuthAndDerivationCount |= (1 << 15)
// // 	h.Challenge.Additional &= ^uint16(1 << 15)

// // 	// TODO: The following code has nothing to do with a handshake, just updating
// // 	// the state of the Peer. This code should probably be moved somewhere else

// // 	if peer.NextNonce == 0 || peer.NextNonce == 2 {
// // 		if peer.LocalTempKeyPair == nil {
// // 			peer.LocalTempKeyPair, err = createTempKeyPair()
// // 			if err != nil {
// // 				return nil, err
// // 			}
// // 		}
// // 	}

// // 	if peer.NextNonce < 2 {
// // 		peer.Secret = computeSharedSecretWithPasswordHash(peer.Local.KeyPair.PrivateKey, peer.PublicKey, peer.PasswordHash)
// // 		peer.Initiator = true
// // 		peer.NextNonce = 1
// // 	} else {
// // 		peer.Secret = computeSharedSecret(peer.Local.KeyPair.PrivateKey, peer.TempPublicKey)
// // 		peer.NextNonce = 3
// // 	}

// // 	// Key Packet
// // 	if peer.NextNonce == 2 {
// // 		peer.Secret = computeSharedSecretWithPasswordHash(peer.Local.KeyPair.PrivateKey, peer.TempPublicKey, peer.PasswordHash)
// // 	}

// // 	return h, nil

// // }
