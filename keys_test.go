package cryptoauth

import (
	_ "log"
	"testing"
)

func BenchmarkNewIdentityKeys(b *testing.B) {
	NewIdentityKeys()
	// identityKeyPair, err := NewIdentityKeys()
	// if err != nil {
	// 	log.Printf("Error generating new identity keys: %s", err.Error())
	// } else {
	// 	log.Printf("ip = %s", identityKeyPair.IPv6)
	// }
}
