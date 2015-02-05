// +build libsodium1.0
//
// TODO: provide a common api for crypto functions across all crypto*.go files

package cryptoauth

import (
	"fmt"
	"unsafe"
)

/*
#cgo CFLAGS: -I/usr/local/include -I/usr/local/include/sodium
#cgo LDFLAGS: /usr/local/lib/libsodium.a
#include <stdio.h>
#include <sodium.h>
*/
import "C"

func InitSodium() {
	result := int(C.sodium_init())
	if result != 0 {
		panic(fmt.Sprintf("Sodium init failed, errcode %d.", result))
	}
}

func MemZero(b1 []byte) {
	if len(b1) > 0 {
		C.sodium_memzero(unsafe.Pointer(&b1[0]), C.size_t(len(b1)))
	}
}

func crypto_box_keypair(pk []byte, sk []byte) int {
	result := C.crypto_box_keypair((*C.uchar)(&pk[0]), (*C.uchar)(&sk[0]))
	return int(result)
}
