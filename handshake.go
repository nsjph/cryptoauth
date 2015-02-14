// // Copyright 2015 JPH <jph@hackworth.be>

// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at

// //     http://www.apache.org/licenses/LICENSE-2.0

// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.

package cryptoauth

type Handshake struct {
	Stage               uint32     // 4 bytes (4)
	Challenge           *Challenge // 12 bytes (16)
	Nonce               [24]byte   // 24 bytes (40)
	PublicKey           [32]byte   // 32 bytes (72)
	EncryptedTempPubKey [32]byte
	Payload             []byte
}
