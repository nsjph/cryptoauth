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
		Src:  []string{"Established", "HelloSend", "HelloReceive", "KeySend", "KeyReceive", "DataSend", "DataReceive"},
		Dst:  "Reset"} // dont forget the key lower/higher scenario that triggers reset
	helloSendEvent    = fsm.EventDesc{Name: "HelloSend", Src: []string{"Reset"}, Dst: "HelloSend"}
	helloReceiveEvent = fsm.EventDesc{Name: "HelloReceive", Src: []string{"Reset", "Established", "KeySend", "HelloReceive"}, Dst: "HelloReceive"}
	keySendEvent      = fsm.EventDesc{Name: "KeySend", Src: []string{"HelloReceive", "KeyReceive"}, Dst: "KeySend"}
	keyReceiveEvent   = fsm.EventDesc{Name: "KeyReceive", Src: []string{"KeySend", "HelloSend"}, Dst: "KeyReceive"}
	dataSendEvent     = fsm.EventDesc{Name: "DataSend", Src: []string{"KeyReceive", "DataReceive", "Established"}, Dst: "DataSend"}
	dataReceiveEvent  = fsm.EventDesc{
		Name: "DataReceive", Src: []string{"KeySend", "DataSend", "Established", "DataReceive"}, Dst: "DataReceive"}
	establishedEvent = fsm.EventDesc{Name: "Established", Src: []string{"DataReceive"}, Dst: "Established"}
	clientEvents     = fsm.Events{
		resetEvent,
		helloSendEvent,
		keyReceiveEvent,
		keySendEvent,
		dataReceiveEvent,
		establishedEvent,
	}
	serverEvents = fsm.Events{
		resetEvent,
		helloReceiveEvent,
		keySendEvent,
		keyReceiveEvent,
		dataSendEvent,
		dataReceiveEvent,
		establishedEvent,
	}
	eventCallbacks = fsm.Callbacks{
		"before_Reset": func(e *fsm.Event) {
			log.Println("before_resetEvent")
		},
		"before_HelloSend": func(e *fsm.Event) {
			log.Println("before_helloSendEvent")
		},
		"before_HelloReceive": func(e *fsm.Event) {
			//validateHello
		},
		"before_KeySend": func(e *fsm.Event) {
			log.Println("before_keySendEvent")
		},
		"before_KeyReceive": func(e *fsm.Event) {
			log.Println("before_keyReceivedEvent")
		},
		"before_DataSend": func(e *fsm.Event) {
			log.Println("before_dataSendEvent")
		},
		"before_DataReceive": func(e *fsm.Event) {
			log.Println("before_dataReceiveEvent")
		},
		"before_Established": func(e *fsm.Event) {
			log.Println("before_establishedEvent")
		},
		"enter_Reset": func(e *fsm.Event) {
			log.Println("enter_resetEvent")
		},
		"enter_HelloReceive": func(e *fsm.Event) {
			log.Println("enter_HelloReceive")
		},
		"enter_KeySend": func(e *fsm.Event) {
			log.Println("enter_KeySend")
		},
		"enter_KeyReceive": func(e *fsm.Event) {
			log.Println("enter_keyReceivedEvent")
		},
		"enter_DataSend": func(e *fsm.Event) {
			log.Println("enter_dataSentEvent")
		},
		"enter_DataReceive": func(e *fsm.Event) {
			log.Println("enter_dataReceivedEvent")
		},
		"enter_Established": func(e *fsm.Event) {
			log.Println("enter_establishedEvent")
		},
	}
)

func newStateMachine(smType int, initial string) (state *fsm.FSM, err error) {

	switch smType {
	case clientStateMachine:
		panic("dont support client state machines yet. please write me")
	case serverStateMachine:
		state = fsm.NewFSM(initial, serverEvents, nil)
	default:
		panic("what statemachine you want")
	}

	return
}
