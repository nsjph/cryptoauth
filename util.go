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
	"log"
)

func isEmpty(x [32]byte) bool {
	if x == [32]byte{} {
		return true
	}
	return false
}

func checkFatal(err error) {
	if err != nil {
		log.Fatalf("Error: %s", err.Error())
	}
}

func debugHandshakeLog(msg string) {
	if debugHandshake == true {
		log.Print("[DEBUG] ", msg)
	}
}

func debugHandshakeLogWithDetails(msg string, details string) {
	if debugHandshake == true {
		log.Printf("[DEBUG] %s: %s", msg, details)
	}
}

func debugHandshakeLogWithError(msg string, err error) {
	if debugHandshake == true {
		log.Printf("[ERROR] %s: %s", msg, err.Error())
	}
}
