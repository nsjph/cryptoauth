package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

// func (c *ServerConfig) getServerKeyPair() *KeyPair {

// 	kp := &KeyPair{}

// 	pubkey, err := base32Decode([]byte(c.PublicKey[:52]))
// 	check(err)
// 	copy(kp.publicKey[:], pubkey[:32])

// 	_, err = hex.Decode(kp.privateKey[:], []byte(c.PrivateKey))
// 	check(err)

// 	return kp

// }

func readConfigFile(path string) *Config {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error %s\n", err)
		os.Exit(1)
	}

	var config Config

	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("Error reading config: %s\n", err)
	}

	return &config
}

func check(err error) {
	if err != nil {
		log.Printf("Error detected: %s\n", err)
	}
}

func checkFatal(err error) {
	if err != nil {
		log.Fatalf("Error detected: %s\n", err)
	}
}
