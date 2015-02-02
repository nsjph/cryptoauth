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
	"sync"
)

// Need a type to hold local state

type Server struct {
	KeyPair     *KeyPair
	IPv6        net.IP
	Listen      string
	Conn        *net.UDPConn
	Passwords   map[[32]byte]*Passwd
	Connections map[string]*Peer
}

type Peer struct {
	sync.RWMutex
	Name               string
	Addr               *net.UDPAddr
	PublicKey          [32]byte // peer's permanent public key
	TempPublicKey      [32]byte // peer's temporary public key
	LocalTempKeyPair   *KeyPair // local temporary keys
	Local              *Server
	NextNonce          uint32
	Secret             *[32]byte // shared secret
	PasswordHash       [32]byte  // static password hash for use in authentication
	AuthRequired       bool
	Established        bool
	Initiator          bool
	LastPacketReceived uint32
}

// Need a type to hold peer-side state

// type Peer struct {
// 	Addr               *net.UDPAddr // remote address
// 	Conn               *net.UDPConn // local connection
// 	Name               string
// 	NextNonce          uint32
// 	Secret             *[32]byte
// 	PublicKey          [32]byte
// 	TempKeyPair        *KeyPair // Our Temporary Keypair
// 	TempPublicKey      [32]byte // peer temporary public key
// 	PasswordHash       [32]byte // hashed version of password
// 	Initiator          bool
// 	Established        bool
// 	AuthRequired       bool
// 	LastPacketReceived uint32
// }

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

type IdentityKeyPair struct {
	PublicKey  *[32]byte
	PrivateKey *[32]byte
	IPv6       net.IP
}

// Neet a type to hold passwords

type Passwd struct {
	User     string
	Password string
	Hash     [32]byte
}
