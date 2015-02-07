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
	"log"
)

type Challenge struct {
	Type        uint8
	Lookup      [7]byte
	Derivations uint16
	Additional  uint16
}

// By default, the authentication/challenge type is always 1
var AuthType uint8 = 1

func requiresPasswordHash(remote *CryptoState) bool {
	// If we know the password to use for the remote peer,
	// then we should generate and include a password hash
	if len(remote.password) > 0 {
		return true
	}
	return false
}

func (c *Connection) NewChallenge() (*Challenge, error) {

	// if we're initiator, we should have a password to use

	// if this is a key packet, we should have identified the correct user/pass already

	if c.isEstablished == false && c.local.isInitiator == true {
		log.Printf("creating an authenticated challenge")
		if len(c.password) > 0 {
			challenge := make([]byte, 12)
			pwhash := HashPassword([]byte(c.password))
			copy(challenge[:], pwhash[:12])
		} else {
			panic("help!")
		}
	} else {
		log.Println("creating a key packet challenge")
		ch := new(Challenge)
		ch.Type = 0
		ch.Derivations |= (1 << 15)
		ch.Additional &= ^uint16(1 << 15)

		return ch, nil

	}

	panic("supermannnnnnnn")

	return nil, nil
}

// Use the challenge from remote peer's Handshake packet to identity
// password they are trying to authenticate with.
//
// (I'm not really sure if I understand this either) --jph

func authenticateChallenge(passwordHash [32]byte, challenge []byte) error {
	if challenge[0] != 1 {
		return errAuthentication.setInfo("Invalid authentication type")
	}

	if len(challenge) != 12 {
		panic("challenge too big")
	}

	if isEmpty(passwordHash) {
		if debugHandshake == true {
			log.Println("You need to provide a passwordHash")
		}
		return errAuthentication.setInfo("Empty password hash provided")
	}

	var a []byte
	var b []byte

	copy(a, challenge[0:8])
	copy(b, passwordHash[:])

	if bytes.Compare(a, b) == 0 {
		if debugHandshake == true {
			log.Println("getAuth: found matching password")
		}

		return nil
	}

	return errAuthentication.setInfo("No matching password found")
}
