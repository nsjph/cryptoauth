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
)

func isShortPacket(data []byte) error {
	if len(data) < 20 {
		return errUndersizeMessage.setInfo("Packet too short")
	}
	return nil
}

// Check that the existing peer permanent public key matches the received
// handshake's public key
func (handshake *Handshake) isDifferentPublicKeyToPeer(peer *Peer) error {
	if isEmpty(peer.PublicKey) == false && peer.PublicKey != handshake.PublicKey {
		return errAuthentication.setInfo("Received handshake with different public key than existing session")
	}
	return nil
}

func (handshake *Handshake) isExtraKeyPacket(peer *Peer) error {
	if handshake.Stage >= 2 {
		if peer.Initiator == false {
			return errInvalid.setInfo("Extra Key Packet")
		}
	}
	return nil
}

func (handshake *Handshake) isDuplicateHelloPacket(peer *Peer, herTempPublicKey [32]byte) error {
	if handshake.Stage == 0 && peer.TempPublicKey == herTempPublicKey {
		return errAuthentication.setInfo("Duplicate hello packet with same temporary public key")
	}
	return nil
}

func (handshake *Handshake) isDuplicateKeyPacket(peer *Peer, herTempPublicKey [32]byte) error {
	if handshake.Stage == 2 && peer.NextNonce >= 4 && peer.TempPublicKey == herTempPublicKey {
		return errAuthentication.setInfo("Duplicate key packet with same temporary public key")
	}
	return nil
}

func (handshake *Handshake) isKeyPacketWithDifferentTemporaryPublicKey(peer *Peer, herTempPublicKey [32]byte) error {
	if handshake.Stage == 3 && peer.NextNonce >= 4 && peer.TempPublicKey != herTempPublicKey {
		return errAuthentication.setInfo("Key packet with different temporary public key")
	}
	return nil
}

func (handshake *Handshake) isRepeatKeyPacketDuringSetup(peer *Peer, nextNonce uint32, herTempPublicKey [32]byte) error {
	if nextNonce == 4 {
		if peer.NextNonce <= 4 {
			peer.NextNonce = nextNonce
			peer.TempPublicKey = herTempPublicKey
			return nil
		} else {
			peer.Secret = computeSharedSecret(peer.LocalTempKeyPair.PrivateKey, peer.TempPublicKey)
		}
	} else if nextNonce != 2 {
		panic("shouldn't reach here")
	} else if peer.Initiator == false || peer.Established == true {
		if peer.Established == true {
			peer.resetSession()
		}

		if peer.NextNonce == 3 {
			nextNonce = 3
		}

		peer.NextNonce = nextNonce
		peer.TempPublicKey = herTempPublicKey

	} else if bytes.Compare([]byte(peer.PublicKey[:]), []byte(peer.Local.KeyPair.PublicKey[:])) < 0 {
		peer.resetSession()
		peer.NextNonce = nextNonce
		peer.TempPublicKey = herTempPublicKey
	}

	return nil

}
