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
	"github.com/looplab/fsm"
	"io"
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
	Incoming           chan []byte // Buffered channel to store decrypted data packets
	Outbound           chan []byte
}

func NewConnection(conn *net.UDPConn, raddr *net.UDPAddr, local, remote *CryptoState) *Connection {

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

	c.state = fsm.NewFSM("Reset", serverEvents, c.serverEventCallbacks())

	return c
}
