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
)

var (
	clientStateMachine = 1
	serverStateMachine = 2
	resetEvent         = fsm.EventDesc{
		Name: "Reset",
		Src:  []string{"HelloSend", "HelloReceive", "KeySend", "KeyReceive", "Established"},
		Dst:  "Reset"}
	helloSendEvent    = fsm.EventDesc{Name: "HelloSend", Src: []string{}, Dst: "HelloSend"}
	helloReceiveEvent = fsm.EventDesc{Name: "HelloReceive", Src: []string{"Reset", "KeySend", "HelloReceive", "Established"}, Dst: "HelloReceive"}
	keySendEvent      = fsm.EventDesc{Name: "KeySend", Src: []string{"HelloReceive", "KeyReceive"}, Dst: "KeySend"}
	keyReceiveEvent   = fsm.EventDesc{Name: "KeyReceive", Src: []string{"KeySend", "HelloSend"}, Dst: "KeyReceive"}
	establishedEvent  = fsm.EventDesc{Name: "Established", Src: []string{"KeyReceive", "KeySend"}, Dst: "Established"}
	clientEvents      = fsm.Events{resetEvent, helloSendEvent, keyReceiveEvent, keySendEvent, establishedEvent}
	serverEvents      = fsm.Events{resetEvent, helloReceiveEvent, keySendEvent, keyReceiveEvent, establishedEvent}
)

func (c *Connection) serverEventCallbacks() map[string]fsm.Callback {
	callbacks := fsm.Callbacks{
		"enter_Reset":         func(e *fsm.Event) { c.CanSendHelloPacket(e) },
		"before_HelloSend":    func(e *fsm.Event) { c.CanSendHelloPacket(e) },
		"enter_HelloSend":     func(e *fsm.Event) { c.NewHelloPacket(e) },
		"before_HelloReceive": func(e *fsm.Event) { c.ValidateHelloPacket(e) },
		"enter_HelloReceive":  func(e *fsm.Event) { c.DecodeHelloPacket(e) },
		"before_KeySend":      func(e *fsm.Event) { c.CanSendKeyPacket(e) },
		"enter_KeySend":       func(e *fsm.Event) { c.NewKeyPacket(e) },
		"before_KeyReceive":   func(e *fsm.Event) { c.ValidateKeyPacket(e) },
		"enter_KeyReceive":    func(e *fsm.Event) { log.Println("enter_keyReceivedEvent") },
		"enter_Established":   func(e *fsm.Event) { c.HandshakeComplete(e) }}
	return callbacks
}
