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
	resetEvent         = fsm.EventDesc{Name: "Reset", Src: []string{"HelloSend", "HelloReceive", "KeySend", "KeyReceive", "DataSend", "DataReceive"}, Dst: "Reset"}
	helloSendEvent     = fsm.EventDesc{Name: "HelloSend", Src: []string{}, Dst: "HelloSend"}
	helloReceiveEvent  = fsm.EventDesc{Name: "HelloReceive", Src: []string{"Reset", "DataReceive", "KeySend", "HelloReceive"}, Dst: "HelloReceive"}
	keySendEvent       = fsm.EventDesc{Name: "KeySend", Src: []string{"HelloReceive", "KeyReceive"}, Dst: "KeySend"}
	keyReceiveEvent    = fsm.EventDesc{Name: "KeyReceive", Src: []string{"KeySend", "HelloSend"}, Dst: "KeyReceive"}
	dataSendEvent      = fsm.EventDesc{Name: "DataSend", Src: []string{"KeyReceive", "DataReceive"}, Dst: "DataSend"}
	dataReceiveEvent   = fsm.EventDesc{Name: "DataReceive", Src: []string{"KeySend", "DataSend", "DataReceive"}, Dst: "DataReceive"}
	establishedEvent   = fsm.EventDesc{Name: "Established", Src: []string{"DataReceive", "DataSend"}, Dst: "Established"}
	clientEvents       = fsm.Events{helloSendEvent, keyReceiveEvent, keySendEvent, dataReceiveEvent, dataSendEvent}
	serverEvents       = fsm.Events{helloReceiveEvent, keySendEvent, keyReceiveEvent, dataSendEvent, dataReceiveEvent}
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
		"before_DataSend":     func(e *fsm.Event) { log.Println("before_dataSendEvent") },
		"enter_DataSend":      func(e *fsm.Event) { log.Println("enter_dataSentEvent") },
		"after_DataSend":      func(e *fsm.Event) { log.Println("after_dataSentEvent") },
		"before_DataReceive":  func(e *fsm.Event) { c.ValidateDataPacket(e) },
		"enter_DataReceive":   func(e *fsm.Event) { c.DecodeDataPacket(e) },
		"after_DataReceive":   func(e *fsm.Event) { log.Println("after_dataReceivedEvent") }}

	return callbacks
}
