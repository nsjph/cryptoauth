// +build libsodium1.0
// +test libsodium1.0

package cryptoauth

import (
	_ "fmt"
	"testing"
)

func BenchmarkCrypto_box_keypair(*testing.B) {
	pk := make([]byte, 32)
	sk := make([]byte, 32)

	//result :=
	crypto_box_keypair(pk, sk)
	//if result == 0 {
	//	fmt.Printf("pk: [%x]\nsk: [%x]\n", pk, sk)
	//}
}
