// +build libsodium1.0
// +test libsodium1.0

package cryptoauth

import (
	"testing"
)

func BenchmarkCrypto_box_keypair(*testing.B) {
	pk := make([]byte, 32)
	sk := make([]byte, 32)

	crypto_box_keypair(pk, sk)
}
