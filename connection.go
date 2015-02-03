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
	"io"
	"net"
)

type CryptoState struct {
	host     *KeyPair
	temp     *KeyPair
	password string
}

// Each session is represented by a connection
type Connection struct {
	conn               *net.UDPConn
	laddr              net.Addr
	raddr              *net.UDPAddr
	isInitiator        bool
	isEstablished      bool
	lastPacketReceived uint32
	local              *CryptoState
	remote             *CryptoState
	incoming           chan []byte // data received from remote
	outgoing           chan []byte // data destined for remote
	rand               io.Reader
	secret             [32]byte
	nextNonce          uint32
}

func NewConnection(conn *net.UDPConn, laddr net.Addr, raddr *net.UDPAddr, isInitiator bool, local, remote *CryptoState) *Connection {

	// TODO: local should not be nil

	// TODO: local should have hostKeys initiated and assigned

	// TODO: if isInitiator is set, remote address, publicKey and password should be set

	// TODO: isEstablished should default to false

	return &Connection{
		conn:          conn,
		laddr:         laddr,
		raddr:         raddr,
		isInitiator:   isInitiator,
		isEstablished: false,
		local:         local,
		remote:        remote,
		incoming:      make(chan []byte, 16),
		outgoing:      make(chan []byte, 16),
		rand:          rand.Reader,
	}
}

func NewCryptoState(kp *KeyPair) *CryptoState {
	return &CryptoState{
		host: kp,
	}
}

func (c *CryptoState) SetPassword(password string) {
	c.password = password
}

func (c *CryptoState) NewTempKeys() (err error) {
	c.temp, err = createTempKeyPair()
	return err
}
