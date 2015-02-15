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
	_ "github.com/davecgh/go-spew/spew"
	"github.com/looplab/fsm"
	"log"
	"math"
)

var (
	errExistingSession  = errors.New("Session with peer already exists")
	errRequirePublicKey = errors.New("Require peer public key to connect")
	errRequirePassword  = errors.New("Require password to connect to peer")
	connectPacketType   = uint32(0)
	helloPacketType     = uint32(1)
	keyPacketType       = uint32(2)
	dataPacketType      = uint32(3)
)

func isDataPacket(nonce uint32) bool {

	if nonce >= 4 && nonce != math.MaxUint32 {
		return true
	}

	return false
}

func (c *Connection) HandlePacket(p []byte) (data []byte, err error) {

	if len(p) < 20 {
		return nil, errUndersizeMessage
	}

	nonce := binary.BigEndian.Uint32(p[:4])

	if isDataPacket(nonce) == true {
		log.Printf("Received data packet: %d", nonce)
		err := c.CanDecodeDataPacket()
		if err != nil {
			return nil, err
		}
		if c.isEstablished == true {
			decrypted, success := decryptDataPacket(p[4:], nonce, c.local.isInitiator, &c.secret)
			if success == false {
				return nil, errAuthentication.setInfo("Unable to decrypt data packet")
			} else {
				return decrypted, nil
			}
		} else {
			log.Printf("Session isn't established")
			// If we successfully decrypt this packet, the handshake is complete.
			c.secret = computeSharedSecret(&c.local.temp.PrivateKey, &c.remote.temp.PublicKey)
			c.local.nextNonce++
			decrypted, success := decryptDataPacket(p[4:], nonce, c.local.isInitiator, &c.secret)
			if success == true {
				c.state.Event("Established")
				return decrypted, nil
			} else {
				return nil, errAuthentication.setInfo("Unable to decrypt data packet")
			}
		}
	} else {
		switch nonce {
		case keyPacketType:
			log.Printf("Received key packet type: %d", nonce)
			if err = c.state.Event("KeyReceive", nonce, p); err != nil {
				log.Print("Error setting state to key received: ", err)
			}
		case helloPacketType:
			log.Printf("Received hello packet type: %d", nonce)
			if err = c.state.Event("HelloReceive", p); err != nil {
				log.Print("Error setting state to hello received: ", err)
			} else {
				if err = c.state.Event("KeySend"); err != nil {
					log.Print("Error sending key: ", err)
					return nil, err
				} else {
					log.Println("Successfully sent key")
				}
			}
		case connectPacketType:
			log.Printf("Received connect packet type: %d", nonce)
		default:
			panic("fuck what do i do now?")
		}
	}
	return nil, nil
}

func (c *Connection) resetConnection(e *fsm.Event) {
	c.resetSession()
}

func (c *Connection) resetSession() {
	if err := c.state.Event("Reset"); err != nil {
		log.Println(err)
	}
	log.Printf("resetting session!!!!!!!!!!!!!!!")
	c.local.nextNonce = 0
	c.local.temp = nil

	// TODO: Check this next bit for logic
	c.local.isInitiator = false
	c.remote = NewCryptoState(new(KeyPair), nil, c.local.isInitiator)
	c.isEstablished = false

}

func (c *Connection) HandshakeComplete(e *fsm.Event) {
	log.Println("HandshakeComplete")
	c.isEstablished = true
	c.local.temp = nil
	c.remote.temp = nil
}
