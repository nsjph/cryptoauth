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
	_ "github.com/davecgh/go-spew/spew"
	"log"
	"math"
)

var (
	errExistingSession  = errors.New("Session with peer already exists")
	errRequirePublicKey = errors.New("Require peer public key to connect")
	errRequirePassword  = errors.New("Require password to connect to peer")
	helloPacketType     = 1
	keyPacketType       = 2
	dataPacketType      = 3
)

func isDataPacket(nonce uint32) bool {

	if nonce >= 4 && nonce != math.MaxUint32 {
		return true
	}

	return false
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

func getPacketType(nonce uint32) int {

	if result := isDataPacket(nonce); result == true {
		return dataPacketType
	} else if result := isKeyPacket(nonce); result == true {
		return keyPacketType
	} else if result := isHelloPacket(nonce); result == true {
		return helloPacketType
	} else {
		log.Fatalf("getPacketType: Don't know what packet type is with nonce [%d]", nonce)
	}

	return -1

}

// Migrating HandlePacket2 to statemachine
//

// Former handlepacket2 is now handlepacket

func (c *Connection) HandlePacket2(p []byte) (err error) {
	nonce := binary.BigEndian.Uint32(p[:4])

	packetType := getPacketType(nonce)
	log.Printf("packet type is %d", packetType)

	switch packetType {
	case dataPacketType:
		if err = c.state.Event("DataReceive", nonce, p); err != nil {
			log.Print("Error setting state to data received: ", err)
		}
	case keyPacketType:
		if err = c.state.Event("KeyReceive", nonce, p); err != nil {
			log.Print("Error setting state to key received: ", err)
		}
	case helloPacketType:
		if err = c.state.Event("HelloReceive", nonce, p); err != nil {
			log.Print("Error setting state to hello received: ", err)
		}
	default:
		panic("fuck what do i do now")
	}

	// log.Printf("received packet with nonce: %d", nonce)
	// log.Println(c.state.Current())
	// if c.isEstablished == false {
	// 	if isDataPacket(nonce) == true {

	// 		if err = c.state.Event("DataReceive"); err != nil {
	// 			log.Println(err)
	// 		}

	// 		// if we dont know anything about the remote peer's temp keys,
	// 		// then we might've restarted and received a packet from previously
	// 		// valid session. We can't decrypt it without knowing their temp keys,
	// 		// so let's ignore it...

	// 		if c.remote.temp == nil {
	// 			c.resetSession()
	// 			return errUndeliverable
	// 		}

	// 		c.secret = computeSharedSecret(&c.local.temp.PrivateKey, &c.remote.temp.PublicKey)
	// 		c.local.nextNonce++
	// 		if _, err = c.DecodeData(nonce, p); err != nil {
	// 			debugHandshakeLogWithError("Error decoding data message", err)
	// 			return errUndeliverable
	// 		} else {
	// 			if err = c.state.Event("Established"); err != nil {
	// 				log.Println(err)
	// 			}
	// 			debugHandshakeLog("Handshake Complete!")
	// 			c.remote.temp = nil
	// 			c.local.temp = nil
	// 			c.isEstablished = true
	// 			return nil
	// 		}

	// 		panic("beep beep ritchie")
	// 	}

	// 	debugHandshakeLog("decoding handshake. our next nonce is")

	// 	if err = c.state.Event("HelloReceive", nonce, p); err != nil {
	// 		log.Println(err)
	// 	}

	// 	if err = c.DecodeHandshake2(nonce, p); err != nil {
	// 		debugHandshakeLogWithError("HandlePacket: error decoding handshake", err)
	// 		return err
	// 	} else {
	// 		if err = c.state.Event("KeySend"); err != nil {
	// 			log.Println(err)
	// 		}
	// 		debugHandshakeLog(fmt.Sprintf("HandlePacket: successfully decoded handshake [%d]", c.local.nextNonce))
	// 		c.writePacket([]byte{})
	// 		return nil
	// 	}

	// 	panic("decrypt handshake here")
	// } else if isDataPacket(nonce) == true {

	// 	if err = c.state.Event("DataReceive", nonce, p); err != nil {
	// 		log.Println(err)
	// 	}

	// 	if _, err = c.DecodeData(nonce, p); err != nil {
	// 		debugHandshakeLogWithError("Error decoding data message", err)
	// 		return errUndeliverable
	// 	} else {
	// 		debugHandshakeLog("Decrypted message successfully")
	// 		return nil
	// 	}
	// 	panic("decrypt message here")
	// } else if isHelloPacket(nonce) == true {
	// 	if err = c.state.Event("HelloReceive", nonce, p); err != nil {
	// 		log.Println(err)
	// 	}
	// 	debugHandshakeLog("Received hello packet for established session")
	// 	if err = c.DecodeHandshake2(nonce, p); err != nil {
	// 		debugHandshakeLogWithError("HandlePacket: error decoding handshake", err)
	// 		return err
	// 	} else {

	// 		debugHandshakeLog(fmt.Sprintf("HandlePacket: successfully decoded handshake [%d]", c.local.nextNonce))
	// 		if err = c.state.Event("KeySend"); err != nil {
	// 			log.Println(err)
	// 		}
	// 		c.writePacket([]byte{})
	// 		return nil
	// 	}
	// 	panic("decrypt handshake here")
	// } else {
	// 	return errUndeliverable
	// }

	// log.Fatalf("fell through, nonce: %u", nonce)

	return nil
}

func (c *Connection) HandlePacket(p []byte) (err error) {
	nonce := binary.BigEndian.Uint32(p[:4])

	log.Printf("received packet with nonce: %d", nonce)
	log.Println(c.state.Current())
	if c.isEstablished == false {
		if isDataPacket(nonce) == true {

			if err = c.state.Event("DataReceive"); err != nil {
				log.Println(err)
			}

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
			if _, err = c.DecodeData(nonce, p); err != nil {
				debugHandshakeLogWithError("Error decoding data message", err)
				return errUndeliverable
			} else {
				if err = c.state.Event("Established"); err != nil {
					log.Println(err)
				}
				debugHandshakeLog("Handshake Complete!")
				c.remote.temp = nil
				c.local.temp = nil
				c.isEstablished = true
				return nil
			}

			panic("beep beep ritchie")
		}

		debugHandshakeLog("decoding handshake. our next nonce is")

		if err = c.state.Event("HelloReceive", nonce, p); err != nil {
			log.Println(err)
		}

		if err = c.DecodeHandshake2(nonce, p); err != nil {
			debugHandshakeLogWithError("HandlePacket: error decoding handshake", err)
			return err
		} else {
			if err = c.state.Event("KeySend"); err != nil {
				log.Println(err)
			}
			debugHandshakeLog(fmt.Sprintf("HandlePacket: successfully decoded handshake [%d]", c.local.nextNonce))
			c.writePacket([]byte{})
			return nil
		}

		panic("decrypt handshake here")
	} else if isDataPacket(nonce) == true {

		if err = c.state.Event("DataReceive", nonce, p); err != nil {
			log.Println(err)
		}

		if _, err = c.DecodeData(nonce, p); err != nil {
			debugHandshakeLogWithError("Error decoding data message", err)
			return errUndeliverable
		} else {
			debugHandshakeLog("Decrypted message successfully")
			return nil
		}
		panic("decrypt message here")
	} else if isHelloPacket(nonce) == true {
		if err = c.state.Event("HelloReceive", nonce, p); err != nil {
			log.Println(err)
		}
		debugHandshakeLog("Received hello packet for established session")
		if err = c.DecodeHandshake2(nonce, p); err != nil {
			debugHandshakeLogWithError("HandlePacket: error decoding handshake", err)
			return err
		} else {

			debugHandshakeLog(fmt.Sprintf("HandlePacket: successfully decoded handshake [%d]", c.local.nextNonce))
			if err = c.state.Event("KeySend"); err != nil {
				log.Println(err)
			}
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
