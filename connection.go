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
	"fmt"
	"github.com/looplab/fsm"
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
	state              *fsm.FSM
	//out                chan []byte

}

func NewConnection(conn *net.UDPConn, raddr *net.UDPAddr, local, remote *CryptoState) *Connection {

	// TODO: local should not be nil

	// TODO: local should have hostKeys initiated and assigned

	// TODO: if isInitiator is set, remote address, publicKey and password should be set

	// TODO: isEstablished should default to false

	if remote == nil {
		remote = NewCryptoState(new(KeyPair), nil, false)
	}

	if local == nil {
		panic("local is nil, fixme")
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

	c.state = fsm.NewFSM("Reset", serverEvents, fsm.Callbacks{
		"before_Reset":        func(e *fsm.Event) { log.Println("before_resetEvent") },
		"enter_Reset":         func(e *fsm.Event) { log.Println("enter_resetEvent") },
		"after_Reset":         func(e *fsm.Event) { log.Println("after_resetEvent") },
		"before_HelloSend":    func(e *fsm.Event) { c.CanSendHelloPacket(e) },
		"enter_HelloSend":     func(e *fsm.Event) { c.NewHelloPacket(e) },
		"after_HelloSend":     func(e *fsm.Event) { log.Println("after_HelloSend") },
		"before_HelloReceive": func(e *fsm.Event) { c.ValidateHelloPacket(e) },
		"enter_HelloReceive":  func(e *fsm.Event) { c.DecodeHelloPacket(e) },
		"after_HelloReceive":  func(e *fsm.Event) { c.state.Event("KeySend") },
		"before_KeySend":      func(e *fsm.Event) { c.CanSendKeyPacket(e) },
		"enter_KeySend":       func(e *fsm.Event) { c.NewKeyPacket(e) },
		"after_KeySend":       func(e *fsm.Event) { log.Println("after_KeySend") },
		"before_KeyReceive":   func(e *fsm.Event) { c.ValidateKeyPacket(e) },
		"enter_KeyReceive":    func(e *fsm.Event) { log.Println("enter_keyReceivedEvent") },
		"after_KeyReceive":    func(e *fsm.Event) { log.Println("after_keyReceivedEvent") },
		"before_DataSend":     func(e *fsm.Event) { log.Println("before_dataSendEvent") },
		"enter_DataSend":      func(e *fsm.Event) { log.Println("enter_dataSentEvent") },
		"after_DataSend":      func(e *fsm.Event) { log.Println("after_dataSentEvent") },
		"before_DataReceive":  func(e *fsm.Event) { log.Println("before_dataReceiveEvent") },
		"enter_DataReceive":   func(e *fsm.Event) { log.Println("enter_dataReceivedEvent") },
		"after_DataReceive":   func(e *fsm.Event) { log.Println("after_dataReceivedEvent") },
		"before_Established":  func(e *fsm.Event) { log.Println("before_establishedEvent") },
		"enter_Established":   func(e *fsm.Event) { log.Println("enter_establishedEvent") },
	})

	return c
}

func (c *Connection) writePacket(p []byte) error {

	// Create a handshake packet to send back
	if c.isEstablished == false {
		challenge, err := c.NewChallenge()
		if err != nil {
			panic(err)
		}
		handshake, err := NewHandshake(c.local.nextNonce, challenge, c.local, c.remote, &c.passwordHash)
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

	return nil
}
