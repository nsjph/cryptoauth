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
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"log"
	"math"
)

var (
	errExistingSession  = errors.New("Session with peer already exists")
	errRequirePublicKey = errors.New("Require peer public key to connect")
	errRequirePassword  = errors.New("Require password to connect to peer")
)

func isDataPacket(nonce uint32) bool {

	if nonce >= 4 && nonce != math.MaxUint32 {
		return true
	}

	return false
}

func (c *Connection) HandlePacket2(p []byte) error {
	nonce := binary.BigEndian.Uint32(p[:4])

	log.Printf("received packet with nonce: %d", nonce)

	if c.isEstablished == false {
		if isDataPacket(nonce) == true {

			// if we dont know anything about the remote peer's temp keys,
			// then we might've restarted and received a packet from previously
			// valid session. We can't decrypt it without knowing their temp keys,
			// so let's ignore it...

			if c.remote.temp == nil {
				c.resetSession()
				return errUndeliverable
			}

			c.secret = computeSharedSecret(&c.local.temp.PrivateKey, &c.remote.temp.PublicKey)
			c.local.nextNonce++
			if _, err := c.DecodeData(nonce, p); err != nil {
				debugHandshakeLogWithError("Error decoding data message", err)
				return errUndeliverable
			} else {
				debugHandshakeLog("Handshake Complete!")
				c.remote.temp = nil
				c.local.temp = nil
				c.isEstablished = true
				return nil
			}

			panic("beep beep ritchie")
		}

		debugHandshakeLog("decoding handshake. our next nonce is")
		if err := c.DecodeHandshake2(nonce, p); err != nil {
			debugHandshakeLogWithError("HandlePacket: error decoding handshake", err)
			return err
		} else {
			debugHandshakeLog(fmt.Sprintf("HandlePacket: successfully decoded handshake [%d]", c.local.nextNonce))
			c.writePacket([]byte{})
			return nil
		}

		panic("decrypt handshake here")
	} else if isDataPacket(nonce) == true {
		if _, err := c.DecodeData(nonce, p); err != nil {
			debugHandshakeLogWithError("Error decoding data message", err)
			return errUndeliverable
		} else {
			debugHandshakeLog("Decrypted message successfully")
			return nil
		}
		panic("decrypt message here")
	} else if isHelloPacket(nonce) == true {
		debugHandshakeLog("Received hello packet for established session")
		if err := c.DecodeHandshake2(nonce, p); err != nil {
			debugHandshakeLogWithError("HandlePacket: error decoding handshake", err)
			return err
		} else {
			debugHandshakeLog(fmt.Sprintf("HandlePacket: successfully decoded handshake [%d]", c.local.nextNonce))
			c.writePacket([]byte{})
			return nil
		}
		panic("decrypt handshake here")
	} else {
		return errUndeliverable
	}

	log.Fatalf("fell through, nonce: %u", nonce)

	panic("fell through")

	return errUnknown
}

func (c *Connection) HandlePacket(p []byte) error {

	if len(p) < 20 {
		return errUndersizeMessage
	}

	nonce := binary.BigEndian.Uint32(p[:4])

	// Establish session
	if c.isEstablished == false {
		if nonce > 3 && nonce != math.MaxUint32 {
			if c.local.nextNonce < 3 {
				debugHandshakeLog("Dropping inbound message to unconfigured session")

				return errUndeliverable
			}

			debugHandshakeLogWithDetails("Trying final handshake step with", c.raddr.String())

			if debugHandshake {
				log.Println("Trying final handshake step with remote peer: ", c.raddr.String())
			}
			c.secret = computeSharedSecret(&c.local.temp.PrivateKey, &c.remote.temp.PublicKey)
			c.local.nextNonce += 3
			if _, err := c.DecodeData(nonce, p); err != nil {
				if debugHandshake {
					log.Printf("Error decrypting data packet: %s", err.Error())
				}
				return errUndeliverable.setInfo(err.Error())
			}

			if debugHandshake {
				log.Println("Final handshake stage complete with: ", c.raddr.String())
			}

			c.isEstablished = true

			return nil

		}

		if err := c.DecodeHandshake2(nonce, p); err != nil {
			debugHandshakeLogWithError("HandlePacket: error decoding handshake", err)
			return err
		} else {
			// success!
			debugHandshakeLog(fmt.Sprintf("HandlePacket: successfully decoded handshake [%d]", c.local.nextNonce))
			c.local.nextNonce++
			c.writePacket([]byte{})
			panic("bing")
			return nil
		}
	} else if nonce > 3 && nonce != math.MaxUint32 {
		if _, err := c.DecodeData(nonce, p); err != nil {
			debugHandshakeLogWithError("HandlePacket: failed to decrypt data packet", err)

			return errUndeliverable.setInfo(err.Error())
		} else {
			debugHandshakeLogWithDetails("HandlePacket: successfully decrypted data packet from", c.raddr.String())

			return nil
		}
	} else if nonce < 2 {
		if err := c.DecodeHandshake2(nonce, p); err != nil {
			if debugHandshake == true {
				log.Print("Error decoding handshake: ", err)
			}
			return err
		} else {
			// do something with the packet
			if debugHandshake == true {
				log.Printf("Decoded handshake successfully: nextnonce %d", c.local.nextNonce)
			}
			panic("reply")
		}
	} else {
		if debugHandshake {
			log.Printf("Dropping key packet during established session with nonce of %d", nonce)
		}
		return errUndeliverable
	}

	spew.Dump(c)

	panic("shouldnt be here")

	return errUnknown

}

func (c *Connection) resetSession() {
	log.Printf("resetting session!!!!!!!!!!!!!!!")
	c.local.nextNonce = 0
	c.local.temp = nil

	// TODO: Check this next bit for logic
	c.local.isInitiator = false
	c.remote = NewCryptoState(new(KeyPair), nil, c.local.isInitiator)
	c.isEstablished = false

}
