package main

import (
	"github.com/nsjph/cryptoauth"
	"log"
	"net"
	"syscall"
	"time"
)

type Config struct {
	Bind       string `json:"bind"`
	PublicKey  string
	PrivateKey string
	IPv6       string
	Password   string
}

func listen(s *cryptoauth.Server) {

	localAddr, err := net.ResolveUDPAddr("udp4", s.Listen)
	checkFatal(err)

	s.Conn, err = net.ListenUDP("udp4", localAddr)
	checkFatal(err)

	f, err := s.Conn.File()
	defer f.Close()
	checkFatal(err)
	fd := int(f.Fd())
	// This one makes sure all packets we send out do not have DF set on them.
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DONT)
	checkFatal(err)

	log.Println("Going into read loop")
	go readLoop(s)
}

func readLoop(s *cryptoauth.Server) {
	defer s.Conn.Close()
	payload := make([]byte, 8192) // TODO: optimize
	oob := make([]byte, 4096)     // TODO: optimize

	for {
		n, oobn, _, addr, err := s.Conn.ReadMsgUDP(payload, oob)
		log.Printf("UDPServer.readLoop(): payload[%d], oob[%d]", n, oobn)
		check(err)

		peerName := addr.String()

		peer, present := s.Connections[peerName]
		if present == false {
			log.Printf("New peer from %s", peerName)
			peer = &cryptoauth.Peer{
				Addr:         addr,
				Name:         peerName,
				Local:        s,
				AuthRequired: true,
				Established:  false,
				NextNonce:    0,
				PublicKey:    [32]byte{},
			}
			s.Connections[peerName] = peer
		}

		peer.ParseMessage(payload[:n])
	}
}

func main() {
	s := new(cryptoauth.Server)
	s.Connections = make(map[string]*cryptoauth.Peer)
	s.KeyPair = new(cryptoauth.KeyPair)

	config := readConfigFile("config.json")

	s.KeyPair.PublicKey = cryptoauth.DecodePublicKeyString(config.PublicKey)
	s.KeyPair.PrivateKey = cryptoauth.DecodePrivateKeyString(config.PrivateKey)
	s.Listen = config.Bind

	if len(config.Password) > 0 {
		passwd := new(cryptoauth.Passwd)
		passwd.Hash = cryptoauth.HashPassword([]byte(config.Password))
		s.Passwords = make(map[[32]byte]*cryptoauth.Passwd)
		s.Passwords[passwd.Hash] = passwd
	} else {
		log.Fatal("Set a password in config.json")
	}

	sleepInterval := 60

	listen(s)

	for {
		time.Sleep(time.Duration(sleepInterval) * time.Second)
	}
}
