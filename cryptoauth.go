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
	"log"
	"math"
)

var (
	errExistingSession  = errors.New("Session with peer already exists")
	errRequirePublicKey = errors.New("Require peer public key to connect")
	errRequirePassword  = errors.New("Require password to connect to peer")
)

func (c *Connection) HandlePacket(p []byte) error {

	// Check minimum length

	if len(p) < 20 {
		return errUndersizeMessage
	}

	nonce := binary.BigEndian.Uint32(p[:4])

	// Establish session
	if c.isEstablished == false {
		if nonce > 3 && nonce != math.MaxUint32 {
			if c.local.nextNonce < 3 {
				if debugHandshake {
					log.Println("Dropping inbound message to unconfigured session")
				}
				return errUndeliverable
			}
			if debugHandshake {
				log.Println("Trying final handshake step with remote peer: ", c.raddr.String())
			}
			c.secret = *computeSharedSecret(&c.local.temp.PrivateKey, c.remote.temp.PublicKey)
			c.local.nextNonce += 3
			if _, err := c.HandleDataPacket(nonce, p); err != nil {
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

		return c.HandleHandshakePacket(nonce, p)
	} else if nonce > 3 && nonce != math.MaxUint32 {
		if _, err := c.HandleDataPacket(nonce, p); err != nil {
			if debugHandshake {
				log.Printf("Error decrypting data packet: %s", err.Error())
			}
			return errUndeliverable.setInfo(err.Error())
		} else {
			if debugHandshake {
				log.Printf("Successfully decrypted message from %s with nonce %x", c.raddr.String(), nonce)
			}
			return nil
		}
	} else if nonce < 2 {
		return c.HandleHandshakePacket(nonce, p)
	} else {
		if debugHandshake {
			log.Printf("Dropping key packet during established session with nonce of %d", nonce)
		}
		return errUndeliverable
	}

	panic("shouldnt be here")

	return errUnknown

}

// func (peer *Peer) ParseMessage(msg []byte) ([]byte, error) {

// 	if len(msg) < 20 {
// 		return nil, errUndersizeMessage
// 	}

// 	nonce := binary.BigEndian.Uint32(msg[:4])

// 	// Prioritize established sessions and ensure the nonce matches expectations
// 	// for established session. We may have an established session, but the
// 	// peer may have reset it (hence the >=4 check)
// 	if peer.Established == true && nonce >= 4 && nonce != math.MaxUint32 {
// 		d, err := peer.parseDataPacket(nonce, msg[4:])
// 		if err != nil {
// 			return nil, err
// 		} else {
// 			// successfully parsed...
// 			return d.Message, nil
// 		}
// 	} else if nonce > 3 && nonce != math.MaxUint32 {
// 		log.Println("trying to complete handshake")
// 		peer.Secret = computeSharedSecret(peer.LocalTempKeyPair.PrivateKey, peer.TempPublicKey)
// 		peer.NextNonce += 3

// 		d, err := peer.parseDataPacket(nonce, msg)
// 		if err != nil {
// 			checkFatal(err)
// 		} else {
// 			peer.Established = true
// 			log.Println("handshake completed")
// 			return d.Message, nil
// 		}

// 	}

// 	handshake, err := peer.parseHandshake(nonce, msg)
// 	checkFatal(err)
// 	err = peer.validateHandshake(handshake, msg)
// 	checkFatal(err)

// 	switch peer.NextNonce {
// 	case 0:
// 		panic("nextnonce is 0")
// 	case 1:
// 		panic("nextnonce is 1")
// 	case 2:
// 		log.Println("nextnonce is 2")
// 		handshake, err := peer.newHandshake([]byte{}, 1)
// 		checkFatal(err)
// 		msg, err := handshake.Marshal(peer)
// 		checkFatal(err)
// 		return nil, peer.sendMessage(msg)
// 	case 3:
// 		log.Println("nextnonce is 3")
// 		handshake, err := peer.newHandshake([]byte{}, 1)
// 		checkFatal(err)
// 		msg, err := handshake.Marshal(peer)
// 		checkFatal(err)
// 		return nil, peer.sendMessage(msg)
// 	case 4:
// 		log.Println("nextnonce is 4")
// 	default:
// 		log.Printf("what do I do with nonce [%d]", peer.NextNonce)
// 		return nil, errUnknown
// 	}

// 	return nil, nil
// }

// func (peer *Peer) sendMessage(msg []byte) error {
// 	if peer.NextNonce >= 0xfffffff0 {
// 		panic("write nonce resetting code")
// 	}
// 	_, err := peer.Local.Conn.WriteToUDP(msg, peer.Addr)
// 	return err
// }

func (c *Connection) resetSession() {
	c.local.nextNonce = 0
	c.local.temp = nil

	// TODO: Check this next bit for logic
	c.local.isInitiator = false
	c.remote = nil

}
