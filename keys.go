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
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"net"
)

type CryptoAuthKeys struct {
	PublicKey  *[32]byte
	PrivateKey *[32]byte
	IPv6       net.IP
}

func createTempKeyPair() (*KeyPair, error) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	return &KeyPair{publicKey, privateKey}, err
}

func keyToBase32(key [32]uint8) string {
	return fmt.Sprintf("%s.k", base32Encode(key[:])[:52])
}

func hashPublicKey(publicKey *[32]byte) []byte {
	firstHash := sha512.Sum512(publicKey[:])
	secondHash := sha512.Sum512(firstHash[:])
	return secondHash[0:16]
}

func isValidIPv6Key(publicKey *[32]byte) bool {

	ip := net.IP.To16(publicKey[:])

	if ip[0] == 0xFC {
		return true
	}

	return false

	// if ip == nil {
	// 	return false
	// }

	// return false
}

func generateKeys() (*CryptoAuthKeys, error) {

	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	for isValidIPv6Key(publicKey) != true {
		publicKey, privateKey, err = box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	return &CryptoAuthKeys{publicKey, privateKey, hashPublicKey(publicKey)}, nil
}
