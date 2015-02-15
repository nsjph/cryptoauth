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

// TODO: this needs cleaning up

type Node struct {
	Identity    *Identity
	Bind        string
	Conn        *net.UDPConn
	Servers     []*Credential // remote servers
	Credentials []*Credential // credentials for incoming clients
	Password    string        // for testing just one password at a time
	Connections map[string]*Connection
}

type Credential struct {
	Addr      *net.Addr // optional for incoming peers
	Username  string    // optional
	Password  string    `json:"password"`
	Hashed    [32]byte
	PublicKey string `json:"publicKey"` // not required for incoming peers
}

type ReplayProtection struct {
	bits              uint64
	offset            uint32
	dupes             uint32
	packetsLost       uint32
	packetsOutOfRange uint32
}

type Identity struct {
	Keys *KeyPair
	IPv6 net.IP
	// PublicKey  *[32]byte
	// PrivateKey *[32]byte
}

// Neet a type to hold passwords

type Passwd struct {
	User     string
	Password string
	Hash     [32]byte
}
