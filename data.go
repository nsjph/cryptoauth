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
	"github.com/looplab/fsm"
	_ "golang.org/x/crypto/nacl/box"
	"log"
	"reflect"
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

// func (c *Connection) DecodeData(nonce uint32, p []byte) ([]byte, error) {

// 	convertedNonce := c.convertNonce(nonce)

// 	if decrypted, success := decryptDataPacket(p, &convertedNonce, &c.secret); success != true {
// 		return nil, errAuthentication.setInfo("Decrypting data packet failed")
// 	} else {
// 		return decrypted, nil
// 	}
// }

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

func (c *Connection) DecodeDataPacket(e *fsm.Event) {

	log.Println("DecodeDataPacket")

	if c.isEstablished == false {
		log.Printf("Received data packet for established session. Resetting")
		c.secret = computeSharedSecret(&c.local.temp.PrivateKey, &c.remote.temp.PublicKey)
		c.local.nextNonce++
	}

	log.Printf("DecodeDataPacket:\n\tsecret [%x]", c.secret)

	v := reflect.ValueOf(e.Args[0])
	p := v.Bytes()

	// TODO: This is already done in cryptoauth.HandlePacket, so we're
	// duplicating effort here. Figure out how to get a uint32 out of an interface{}
	// and use fsm.Event.Args to retrieve the existing nonce from HandlePacket instead
	nonce := binary.BigEndian.Uint32(p[:4])

	//convertedNonce := c.convertNonce(nonce)

	decrypted, success := decryptDataPacket(p, nonce, c.local.isInitiator, &c.secret)
	if success != true {
		e.Cancel(errAuthentication.setInfo("Decrypting data packet failed"))
		return
	} else {
		log.Println("decrypted data packet ok")
	}

	if c.isEstablished == false {
		c.isEstablished = true
		c.local.temp = nil
		c.remote.temp = nil
	}

	log.Printf("DecodeDataPacket: length of decrypted bytes is %d", len(decrypted))

	c.Incoming <- decrypted

}

// type DataPacket struct {
// 	Nonce   uint32
// 	Message []byte
// }

// func (c *Connection) convertNonce(nonce uint32) [24]byte {

// 	n := make([]byte, 8)
// 	convertedNonce := [24]byte{}

// 	switch c.isInitiator {
// 	case true:
// 		binary.LittleEndian.PutUint32(n[:4], nonce)
// 	case false:
// 		binary.LittleEndian.PutUint32(n[4:], nonce)
// 	}

// 	copy(convertedNonce[:], n)

// 	return convertedNonce

// }

// func (c *Connection) handleDataPacket(nonce uint32, p []byte) error {

// 	convertedNonce := c.convertNonce(nonce)

// 	_, success := box.OpenAfterPrecomputation(p, p[4:], &convertedNonce, &c.secret)
// 	if success == false {
// 		return errAuthentication.setInfo("Decryption failed")
// 	}

// 	// d := &DataPacket{
// 	// 	Nonce:   nonce,
// 	// 	Message: decrypted,
// 	// }

// 	// TODO: is this the right spot?
// 	c.nextNonce++

// 	return nil

// }

// func (d *DataPacket) Marshal(peer *Peer) ([]byte, error) {

// 	// Initialise the []byte buffer and in-place convert nonce to bigendian.
// 	// See encoding/binary/putuint32 for explanation: https://golang.org/src/encoding/binary/binary.go
// 	b := make([]byte, len(d.Message)+4)
// 	//b := []byte{byte(d.Nonce >> 24), byte(d.Nonce >> 16), byte(d.Nonce >> 8), byte(d.Nonce)}
// 	b[0] = byte(d.Nonce >> 24)
// 	b[1] = byte(d.Nonce >> 16)
// 	b[2] = byte(d.Nonce >> 8)
// 	b[3] = byte(d.Nonce)

// 	copy(b[4:], d.Message)

// 	return b, nil

// }

// func (peer *Peer) parseDataPacket(nonce uint32, data []byte) (*DataPacket, error) {

// 	n := make([]byte, 8)
// 	convertedNonce := [24]byte{}

// 	switch peer.Initiator {
// 	case true:
// 		binary.LittleEndian.PutUint32(n[:4], nonce)
// 	case false:
// 		binary.LittleEndian.PutUint32(n[4:], nonce)
// 	}

// 	copy(convertedNonce[:], n)

// 	decrypted, success := box.OpenAfterPrecomputation(data, data[4:], &convertedNonce, peer.Secret)
// 	if success == false {
// 		return nil, errAuthentication.setInfo("Decryption failed")
// 	}

// 	d := &DataPacket{
// 		Nonce:   binary.BigEndian.Uint32(data[:4]),
// 		Message: decrypted,
// 	}

// 	return d, nil
// }

// func (peer *Peer) newDataPacket(msg []byte) (*DataPacket, error) {

// 	n := make([]byte, 8)
// 	var convertedNonce [24]byte

// 	if peer.Initiator == true {
// 		binary.LittleEndian.PutUint32(n[4:], peer.NextNonce)
// 	} else {
// 		binary.LittleEndian.PutUint32(n[:4], peer.NextNonce)
// 	}

// 	peer.NextNonce++

// 	copy(convertedNonce[:], n)

// 	var out []byte
// 	encrypted := box.SealAfterPrecomputation(out, msg, &convertedNonce, peer.Secret)
// 	// if err != nil {
// 	// 	return nil, errAuthentication.setInfo("Encryption failed")
// 	// }

// 	return &DataPacket{peer.NextNonce, encrypted}, nil

// }
