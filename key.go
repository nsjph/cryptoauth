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
	"errors"
	"github.com/looplab/fsm"
	"golang.org/x/crypto/nacl/box"
	"log"
)

var (
	errKeySendDuringEstablished = errors.New("Can't send key packet during established session")
)

func (c *Connection) CanSendKeyPacket(e *fsm.Event) {
	log.Printf("CanSendKeyPacket")

	if c.isEstablished == true {
		e.Cancel(errKeySendDuringEstablished)
	}
}

func (c *Connection) NewKeyPacket(e *fsm.Event) {
	log.Printf("NewKeyPacket")

	var err error
	var secret [32]byte

	challenge, err := c.NewChallenge()
	if err != nil {
		e.Cancel(err)
		return
	}

	h := &Handshake{
		Stage:     c.local.nextNonce,
		PublicKey: c.local.perm.PublicKey,
	}

	if h.Nonce, err = newNonce(); err != nil {
		e.Cancel(err)
		return
	}

	secret = computeSharedSecret(&c.local.perm.PrivateKey, &c.remote.temp.PublicKey)

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

	if c.local.temp == nil {
		c.local.temp, _ = createTempKeyPair()
	}

	encryptedTempPubKey := box.SealAfterPrecomputation(out, c.local.temp.PublicKey[:], &h.Nonce, &secret)

	if debugHandshake {
		log.Printf("encryptedTempPubKey:\n\tnonce [%x]\n\tsecret [%x]\n\tmyTempPubKey [%x]", h.Nonce, secret, c.local.temp.PublicKey)
	}

	binary.Write(buf, binary.BigEndian, encryptedTempPubKey)

	//handshake, err := NewHandshake(c.local.nextNonce, challenge, c.local, c.remote, &c.passwordHash)
	n, err := c.conn.WriteToUDP(buf.Bytes(), c.raddr)
	if err != nil {
		e.Cancel(err)
		return
	}
	log.Printf("wrote %d to %s", n, c.raddr.String())
}

func (c *Connection) ValidateKeyPacket(e *fsm.Event) {
	log.Printf("ValidateKeyPacket")
}

func (c *Connection) validateKey(e *fsm.Event) {
	log.Printf("Validate Key: event args are: %v", e.Args)
}
