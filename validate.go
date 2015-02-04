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
	_ "bytes"
	_ "golang.org/x/crypto/nacl/box"
	_ "log"
)

// func (peer *Peer) validateHandshake(handshake *Handshake, origData []byte) error {

// 	var err error

// 	err = handshake.isDifferentPublicKeyToPeer(peer)
// 	if err != nil {
// 		return err
// 	}

// 	// The remote peer presents a hashed password for authentication, which we need
// 	// to compare against our known passwords. Here we return an error if there's a problem
// 	// with the supplied challenge (we can't find a matching password)

// 	log.Printf("stage is %d", handshake.Stage)

// 	var challengeAsBytes [12]byte
// 	copy(challengeAsBytes[:], handshake.Data[4:16])
// 	password, err := peer.checkChallenge(challengeAsBytes)
// 	if err != nil {
// 		return err
// 	}

// 	peer.PasswordHash = password.Hash
// 	var NextNonce uint32

// 	log.Printf("public key from handshake: [%x]", handshake.PublicKey)

// 	if handshake.Stage < 2 {
// 		if isEmpty(peer.PublicKey) || peer.NextNonce == 0 {
// 			copy(peer.PublicKey[:], handshake.PublicKey[:])
// 		}
// 		peer.Secret = computeSharedSecretWithPasswordHash(peer.Local.KeyPair.PrivateKey, peer.PublicKey, peer.PasswordHash)
// 		NextNonce = 2
// 	} else {
// 		if peer.Initiator == false {
// 			return errAuthentication.setInfo("Unecessary additional key packet received")
// 		}

// 		peer.Secret = computeSharedSecretWithPasswordHash(peer.Local.KeyPair.PrivateKey, peer.PublicKey, peer.PasswordHash)
// 		NextNonce = 4
// 	}

// 	// Decrypting peer's temp public key

// 	payload := handshake.Data[72:]
// 	var herTempPublicKey [32]byte

// 	decrypted, success := box.OpenAfterPrecomputation(handshake.Data[72:], payload, &handshake.Nonce, peer.Secret)
// 	if success == false {
// 		peer.Established = false
// 		return errAuthentication.setInfo("Decryption of temporary public key failed")
// 	}

// 	copy(herTempPublicKey[:], decrypted[88:120])

// 	// Post-decryption checks

// 	err = handshake.isDuplicateHelloPacket(peer, herTempPublicKey)
// 	if err != nil {
// 		return err
// 	}

// 	err = handshake.isDuplicateKeyPacket(peer, herTempPublicKey)
// 	if err != nil {
// 		return err
// 	}

// 	err = handshake.isKeyPacketWithDifferentTemporaryPublicKey(peer, herTempPublicKey)
// 	if err != nil {
// 		return err
// 	}

// 	err = handshake.isRepeatKeyPacketDuringSetup(peer, NextNonce, herTempPublicKey)
// 	if err != nil {
// 		return err
// 	}

// 	if isEmpty(peer.PublicKey) == true && isEmpty(handshake.PublicKey) == false {
// 		copy(peer.PublicKey[:], handshake.PublicKey[:])
// 	}

// 	// TODO: handle data as part of handhsake
// 	if len(handshake.Data) <= 160 {
// 		if handshake.Challenge.Additional&(1<<15) != 0 {
// 			return errNone
// 		}
// 	} else {
// 		panic("got here")
// 	}

// 	return nil
// }

// func isShortPacket(data []byte) error {
// 	if len(data) < 20 {
// 		return errUndersizeMessage.setInfo("Packet too short")
// 	}
// 	return nil
// }

// // Check that the existing peer permanent public key matches the received
// // handshake's public key
// func (handshake *Handshake) isDifferentPublicKeyToPeer(peer *Peer) error {
// 	if isEmpty(peer.PublicKey) == false && peer.PublicKey != handshake.PublicKey {
// 		return errAuthentication.setInfo("Received handshake with different public key than existing session")
// 	}
// 	return nil
// }

// func (handshake *Handshake) isExtraKeyPacket(peer *Peer) error {
// 	if handshake.Stage >= 2 {
// 		if peer.Initiator == false {
// 			return errInvalid.setInfo("Extra Key Packet")
// 		}
// 	}
// 	return nil
// }

// func (handshake *Handshake) isDuplicateHelloPacket(peer *Peer, herTempPublicKey [32]byte) error {
// 	if handshake.Stage == 0 && peer.TempPublicKey == herTempPublicKey {
// 		return errAuthentication.setInfo("Duplicate hello packet with same temporary public key")
// 	}
// 	return nil
// }

// func (handshake *Handshake) isDuplicateKeyPacket(peer *Peer, herTempPublicKey [32]byte) error {
// 	if handshake.Stage == 2 && peer.NextNonce >= 4 && peer.TempPublicKey == herTempPublicKey {
// 		return errAuthentication.setInfo("Duplicate key packet with same temporary public key")
// 	}
// 	return nil
// }

// func (handshake *Handshake) isKeyPacketWithDifferentTemporaryPublicKey(peer *Peer, herTempPublicKey [32]byte) error {
// 	if handshake.Stage == 3 && peer.NextNonce >= 4 && peer.TempPublicKey != herTempPublicKey {
// 		return errAuthentication.setInfo("Key packet with different temporary public key")
// 	}
// 	return nil
// }

// func (handshake *Handshake) isRepeatKeyPacketDuringSetup(peer *Peer, nextNonce uint32, herTempPublicKey [32]byte) error {
// 	if nextNonce == 4 {
// 		if peer.NextNonce <= 4 {
// 			peer.NextNonce = nextNonce
// 			peer.TempPublicKey = herTempPublicKey
// 			return nil
// 		} else {
// 			peer.Secret = computeSharedSecret(peer.LocalTempKeyPair.PrivateKey, peer.TempPublicKey)
// 		}
// 	} else if nextNonce != 2 {
// 		panic("shouldn't reach here")
// 	} else if peer.Initiator == false || peer.Established == true {
// 		if peer.Established == true {
// 			c.resetSession()
// 		}

// 		if peer.NextNonce == 3 {
// 			nextNonce = 3
// 		}

// 		peer.NextNonce = nextNonce
// 		peer.TempPublicKey = herTempPublicKey

// 	} else if bytes.Compare([]byte(peer.PublicKey[:]), []byte(peer.Local.KeyPair.PublicKey[:])) < 0 {
// 		c.resetSession()
// 		peer.NextNonce = nextNonce
// 		peer.TempPublicKey = herTempPublicKey
// 	}

// 	return nil

// }
