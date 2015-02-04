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
	"io"
	"net"
)

type KeyPair struct {
	PublicKey  [32]byte
	PrivateKey [32]byte
}

type CryptoState struct {
	perm        *KeyPair
	temp        *KeyPair
	password    string
	isInitiator bool
	nextNonce   uint32
}

// Each session is represented by a connection
type Connection struct {
	conn               *net.UDPConn
	laddr              net.Addr
	raddr              *net.UDPAddr
	isEstablished      bool
	lastPacketReceived uint32
	local              *CryptoState
	remote             *CryptoState
	incoming           chan []byte // data received from remote
	outgoing           chan []byte // data destined for remote
	rand               io.Reader
	secret             [32]byte
	password           string
	passwordHash       [32]byte
}

func NewConnection(conn *net.UDPConn, raddr *net.UDPAddr, local, remote *CryptoState) *Connection {

	// TODO: local should not be nil

	// TODO: local should have hostKeys initiated and assigned

	// TODO: if isInitiator is set, remote address, publicKey and password should be set

	// TODO: isEstablished should default to false

	if remote == nil {
		kp := new(KeyPair)
		remote = NewCryptoState(kp, false)
	}

	if local == nil {
		return nil
	}

	c := &Connection{
		conn:          conn,
		laddr:         conn.LocalAddr(),
		raddr:         raddr,
		isEstablished: false,
		local:         local,
		remote:        remote,
		incoming:      make(chan []byte, 16),
		outgoing:      make(chan []byte, 16),
		rand:          rand.Reader,
	}
	return c
}

func NewCryptoState(kp *KeyPair, initiator bool) *CryptoState {
	cs := &CryptoState{
		perm:        kp,
		temp:        nil,
		nextNonce:   0,
		isInitiator: initiator,
	}

	return cs

	// // If we have a permanent private key set, we're the server
	// if isEmpty(cs.perm.PrivateKey) == false {
	// 	cs.isInitiator == true
	// }
}

func (c *Connection) SetPassword(password string) {
	c.password = password
	pwhash := sha256.Sum256([]byte(c.password))
	copy(c.passwordHash[:], pwhash[:32])
}

func (c *CryptoState) NewTempKeys() (err error) {
	c.temp, err = createTempKeyPair()
	return err
}
