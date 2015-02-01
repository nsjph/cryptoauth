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

func (peer *Peer) connect(state *State) error {

	if peer.Established == true {
		return errExistingSession
	}

	if isEmpty(&peer.PublicKey) == true {
		return errRequirePublicKey
	}

	if isEmpty(&peer.PasswordHash) == true {
		return errRequirePassword
	}

	handshake, err := peer.newHandshake([]byte{}, 1, state)
	if err != nil {
		return err
	}

	msg, err := handshake.Marshal(peer)
	if err != nil {
		return err
	}

	err = peer.sendMessage(msg, state)
	if err != nil {
		return err
	}

	return nil

}

func (peer *Peer) parseMessage(msg []byte, state *State) ([]byte, error) {

	if len(msg) < 20 {
		return nil, errUndersizeMessage
	}

	nonce := binary.BigEndian.Uint32(msg[:4])

	// Prioritize established sessions
	if peer.Established == true && nonce != math.MaxUint32 {
		d, err := peer.parseDataPacket(nonce, msg[4:])
		if err != nil {
			return nil, err
		} else {
			// successfully parsed...
			return d.Message, nil
		}
	}

	handshake, err := peer.parseHandshake(nonce, msg)
	checkFatal(err)
	err = peer.validateHandshake(handshake, state)
	checkFatal(err)

	switch peer.NextNonce {
	case 0:
		panic("nextnonce is 0")
	case 1:
		panic("nextnonce is 1")
	case 2:
		handshake, err := peer.newHandshake([]byte{}, 1, state)
		checkFatal(err)
		msg, err := handshake.Marshal(peer)
		checkFatal(err)
		return nil, peer.sendMessage(msg, state)
	case 3:
		handshake, err := peer.newHandshake([]byte{}, 1, state)
		checkFatal(err)
		msg, err := handshake.Marshal(peer)
		checkFatal(err)
		return nil, peer.sendMessage(msg, state)
	default:
		log.Printf("what do I do with nonce [%d]", peer.NextNonce)
		return nil, errUnknown
	}

	return nil, nil
}

func (peer *Peer) sendMessage(msg []byte, state *State) error {
	if peer.NextNonce >= 0xfffffff0 {
		panic("write nonce resetting code")
	}
	_, err := peer.Conn.WriteToUDP(msg, peer.Addr)
	return err
}

func (peer *Peer) resetSession() {
	peer.NextNonce = 0
	peer.Initiator = false
	peer.TempKeyPair = &KeyPair{}

	//peer.tempKeyPair.privateKey = [32]byte{}

	// TODO: work on replay protection
	//peer.replayProtector = new(ReplayProtector)
}
