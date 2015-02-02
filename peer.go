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

func NewPeer(name string, addr *net.UDPAddr, localServer *Server, initiator bool, password []byte, publicKey [32]byte) *Peer {

	var passwordHash [32]byte

	if password != nil {
		hash := HashPassword(password)
		copy(passwordHash[:], hash[:])
	}

	return &Peer{
		Name:         name,
		Addr:         addr,
		Local:        localServer,
		Initiator:    initiator,
		PasswordHash: passwordHash,
		PublicKey:    publicKey,
	}
}
