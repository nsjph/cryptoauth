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
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"net"
)

func createTempKeyPair() (*KeyPair, error) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	return &KeyPair{publicKey, privateKey}, err
}

func keyToBase32(key [32]uint8) string {
	return fmt.Sprintf("%s.k", Base32Encode(key[:])[:52])
}

func DecodePublicKeyString(pubKeyString string) *[32]byte {

	pubkey, err := Base32Decode([]byte(pubKeyString[:52]))
	checkFatal(err)

	var publicKey [32]byte

	copy(publicKey[:], pubkey)

	return &publicKey
}

func DecodePrivateKeyString(privateKeyString string) *[32]byte {
	fmt.Printf("length of privateKeyString is %d", len(privateKeyString))
	var privateKey [32]byte
	_, err := hex.Decode(privateKey[:], []byte(privateKeyString))
	checkFatal(err)

	return &privateKey
}

func hashPublicKey(publicKey *[32]byte) []byte {
	firstHash := sha512.Sum512(publicKey[:])
	secondHash := sha512.Sum512(firstHash[:])
	return secondHash[0:16]
}

func HashPassword(password []byte) (passwordHash [32]byte) {
	return sha256.Sum256(password)
}

func isValidIPv6PublicKey(k *[32]byte) bool {
	h := hashPublicKey(k)
	ip := net.IP.To16(h[:])

	if ip[0] == 0xFC {
		return true
	}
	return false
}

func isValidIPv6Key(k []byte) bool {

	//ip := hashPublicKey(k[:])
	ip := net.IP.To16(k[:])

	if ip[0] == 0xFC {
		return true
	}

	return false

	// if ip == nil {
	// 	return false
	// }

	// return false
}

func NewIdentityKeys() (*IdentityKeyPair, error) {

	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	ipv6 := hashPublicKey(publicKey)

	for isValidIPv6Key(ipv6) != true {
		publicKey, privateKey, err = box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		ipv6 = hashPublicKey(publicKey)
	}

	return &IdentityKeyPair{publicKey, privateKey, ipv6}, nil
}
