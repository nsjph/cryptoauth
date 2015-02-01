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
	"net"
)

// Need a type to hold local state

type State struct {
	KeyPair   *KeyPair
	Passwords map[[32]byte]*Passwd
}

// Need a type to hold peer-side state

type Peer struct {
	Addr               *net.UDPAddr // remote address
	Conn               *net.UDPConn // local connection
	Name               string
	NextNonce          uint32
	Secret             *[32]byte
	PublicKey          [32]byte
	TempKeyPair        *KeyPair // Our Temporary Keypair
	TempPublicKey      [32]byte // peer temporary public key
	PasswordHash       [32]byte // hashed version of password
	Initiator          bool
	Established        bool
	AuthRequired       bool
	LastPacketReceived uint32
}

type ReplayProtection struct {
	bits              uint64
	offset            uint32
	dupes             uint32
	packetsLost       uint32
	packetsOutOfRange uint32
}

type KeyPair struct {
	PublicKey  *[32]byte
	PrivateKey *[32]byte
}

// Neet a type to hold passwords

type Passwd struct {
	user     string
	password string
	hash     [32]string
}
