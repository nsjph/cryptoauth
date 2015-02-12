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
	"github.com/looplab/fsm"
	"log"
	"reflect"
)

func (c *Connection) validateHello(e *fsm.Event) {
	log.Printf("Validate Hello event args are: %v", e.Args)

	p := reflect.ValueOf(e.Args[2]).([]Byte)

	if len(p) < 120 {
		if debugHandshake {
			log.Printf("Received undersized message: %d long", len(p))
		}
		return errUndersizeMessage
	}
}

func (c *Connection) decodeHello(e *fsm.Event) {

}
