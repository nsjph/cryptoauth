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
	_ "log"
)

var (
	clientStateMachine = 1
	serverStateMachine = 2
	clientEvents       = fsm.Events{
		{Name: "Disconnected", Src: []string{"Established"}, Dst: "Disconnected"},
		{Name: "SentHelloPacket", Src: []string{"Disconnected"}, Dst: "SentHelloPacket"},
		{Name: "ReceivedKeyPacket", Src: []string{"SentHelloPacket"}, Dst: "ReceivedKeyPacket"},
		{Name: "SentKeyPacket", Src: []string{"ReceivedKeyPacket"}, Dst: "SentKeyPacket"},
		{Name: "ReceivedDataPacket", Src: []string{"SentKeyPacket"}, Dst: "ReceivedDataPacket"},
		{Name: "Established", Src: []string{"ReceivedDataPacket"}, Dst: "Established"},
	}
	serverEvents = fsm.Events{
		{Name: "Disconnected", Src: []string{"Established"}, Dst: "Disconnected"},
		{Name: "ReceivedHelloPacket", Src: []string{"Disconnected", "Established"}, Dst: "ReceivedHelloPacket"},
		{Name: "SentKeyPacket", Src: []string{"ReceivedHelloPacket"}, Dst: "SentKeyPacket"},
		{Name: "ReceivedKeyPacket", Src: []string{"SentKeyPacket"}, Dst: "ReceivedKeyPacket"},
		{Name: "SentDataPacket", Src: []string{"ReceivedKeyPacket"}, Dst: "SentDataPacket"},
		{Name: "ReceivedDataPacket", Src: []string{"SentDataPacket"}, Dst: "ReceivedDataPacket"},
		{Name: "Established", Src: []string{"ReceivedDataPacket"}, Dst: "Established"},
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
