package main

import (
	"github.com/nsjph/cryptoauth"
	"net"
)

type UDPServer struct {
	conn   *net.UDPConn
	peers  map[string]*cryptoauth.Peer
	state  *cryptoauth.State
	config *Config
}

type Config struct {
	Bind       string `json:"bind"`
	PublicKey  string
	PrivateKey string
	IPv6       string
	Password   string
}
