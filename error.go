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
	"fmt"
)

var (
	errNone              = newCryptoAuthError(0, "No error")
	errMalformedAddress  = newCryptoAuthError(1, "Malformed address")
	errFlood             = newCryptoAuthError(2, "Traffic flood")
	errLinkLimitExceeded = newCryptoAuthError(3, "Link limit exceeded")
	errOverSizeMessage   = newCryptoAuthError(4, "Oversize message")
	errUndersizeMessage  = newCryptoAuthError(5, "Undersize message")
	errAuthentication    = newCryptoAuthError(6, "Authentication error")
	errInvalid           = newCryptoAuthError(7, "Invalid") // TODO: check what/when raises this type of error
	errUndeliverable     = newCryptoAuthError(8, "Undeliverable")
	errLoopRoute         = newCryptoAuthError(9, "Invalid route due to loop")
	errReturnPathInvalid = newCryptoAuthError(10, "Invalid return path")
	errUnknown           = newCryptoAuthError(11, "Unknown Error")
	errNotImplemented    = newCryptoAuthError(12, "Feature not implemented")
)

type CryptoAuthError struct {
	Code  int
	Class string // the class of error - authentication, undeliverable
	Info  string // extra info about the error
}

func newCryptoAuthError(code int, class string) *CryptoAuthError {
	err := &CryptoAuthError{
		Code:  code,
		Class: class,
		Info:  "",
	}
	return err
}

func (err *CryptoAuthError) Error() string {
	if err.Info != "" {
		return fmt.Sprintf("%s: %s", err.Class, err.Info)
	}
	return err.Class
}

func (err *CryptoAuthError) setInfo(info string) *CryptoAuthError {
	err.Info = info
	return err
}
