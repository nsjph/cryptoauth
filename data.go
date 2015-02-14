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
)

func convertNonce(nonce uint32, isInitiator bool) [24]byte {

	n := make([]byte, 8)
	convertedNonce := [24]byte{}

	switch isInitiator {
	case true:
		binary.LittleEndian.PutUint32(n[:4], nonce)
	case false:
		binary.LittleEndian.PutUint32(n[4:], nonce)
	}

	copy(convertedNonce[:], n)

	log.Printf("convertedNonce: [%x]", convertedNonce)

	return convertedNonce

}

func (c *Connection) CanDecodeDataPacket() error {

	if c.isEstablished == false {
		if c.local.temp == nil {
			return errors.New("CanDecodeDataPacket: No local temp keypair, can't decode data packet")
		} else if c.remote.temp == nil {
			return errors.New("CanDecodeDataPacket: No remote temp public key, can't decode data packet")
		}
		log.Println("connection is not established")
		if isEmpty(c.remote.temp.PublicKey) == true {
			log.Println("remote temp public key is empty")
			return errors.New("CanDecodeDataPacket: No remote temp public key, can't decode data packet")
		} else if isEmpty(c.local.temp.PrivateKey) == true {
			log.Println("local temp privatekey is empty")
			return errors.New("CanDecodeDataPacket: No local temporary private key, can't decode data packet")
		}
	}
	return nil
}
