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
	_ "bufio"
	"crypto/rand"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"io"
	"log"
	"net"
)

// Each session is represented by a connection
type Connection struct {
	conn               *net.UDPConn
	raddr              *net.UDPAddr
	isEstablished      bool
	lastPacketReceived uint32
	local              *CryptoState
	remote             *CryptoState
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
		remote.perm = new(KeyPair)
		remote.temp = new(KeyPair)
	}

	if local == nil {
		return nil
	}

	c := &Connection{
		conn:          conn,
		raddr:         raddr,
		isEstablished: false,
		local:         local,
		remote:        remote,
		rand:          rand.Reader,
	}

	return c
}

func (c *Connection) readPacket() ([]byte, error) {

	return nil, nil
}

func (c *Connection) writePacket(p []byte) error {

	//NewHandshake(stage uint32, challenge *Challenge, local *CryptoState, remote *CryptoState, passwordHash [32]byte) ([]byte, error) {

	// Create a handshake packet to send back
	if c.isEstablished == false {
		//NewChallenge(lookup [7]byte, derivations uint16, additional uint16) (*Challenge, error) {
		challenge, err := c.NewChallenge()
		if err != nil {
			panic(err)
		}
		log.Printf("creating a new handshake, current nonce is %d, password hash is %x", c.local.nextNonce, c.passwordHash)
		handshake, err := NewHandshake(c.local.nextNonce, challenge, c.local, c.remote, c.passwordHash)
		n, err := c.conn.WriteToUDP(handshake, c.raddr)
		if err != nil {
			return err
		}
		log.Printf("wrote %d to %s", n, c.raddr.String())
		return nil
	} else {
		panic("how to send data packet?")
	}

	if n, err := c.conn.WriteToUDP(p, c.raddr); err != nil {
		debugHandshakeLogWithError("writePacket", err)
	} else {
		debugHandshakeLog(fmt.Sprintf("writePacket: wrote [%d] bytes to %s", n, c.raddr.String()))
	}

	log.Print("writePacket")
	spew.Dump(c.conn)

	return nil
}
