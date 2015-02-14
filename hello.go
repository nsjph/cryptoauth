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
	"github.com/looplab/fsm"
	"golang.org/x/crypto/nacl/box"
	"log"
	"reflect"
)

func (c *Connection) CanSendHelloPacket(e *fsm.Event) {

}

func (c *Connection) NewHelloPacket(e *fsm.Event) {

}

func (c *Connection) ValidateHelloPacket(e *fsm.Event) {

	if c.isEstablished == true {
		log.Printf("Received hello packet for established session. Resetting")
		c.resetSession()
	}

	v := reflect.ValueOf(e.Args[0])
	p := v.Bytes()

	if len(p) < 120 {
		log.Println("ValidateHelloPacket: Undersize hello packet")
		e.Cancel(errUndersizeMessage)
	}

}

func (c *Connection) DecodeHelloPacket(e *fsm.Event) {

	v := reflect.ValueOf(e.Args[0])
	p := v.Bytes()

	var nextNonce uint32 = 0

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
		e.Cancel(err)
	}

	c.remote.perm.PublicKey = h.PublicKey
	c.secret = computeSharedSecretWithPasswordHash(&c.local.perm.PrivateKey, &c.remote.perm.PublicKey, &c.passwordHash)
	nextNonce = 2

	decrypted, success := box.OpenAfterPrecomputation(p[72:], p[72:], &h.Nonce, &c.secret)
	if success == false {
		panic("failed to decrypt temp public key")
		e.Cancel(errAuthentication.setInfo("failed to decrypt temp public key"))
	}

	herTempPublicKey := decrypted[88:120]

	if c.local.isInitiator == false || c.isEstablished == true {
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
}

func (c *Connection) decodeHello(e *fsm.Event) {

}
