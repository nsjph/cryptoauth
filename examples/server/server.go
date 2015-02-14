package main

import (
	"encoding/json"
	"fmt"
	"github.com/nsjph/cryptoauth"
	"io/ioutil"
	"log"
	"net"
	"os"
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

func checkFatal(err error) {
	if err != nil {
		log.Fatalf("Error detected: %s\n", err)
	}
}

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
	go readUDPPacket(s)
	//go readDataPacket(s)
}

func readUDPPacket(s *cryptoauth.Server) {
	defer s.Conn.Close()
	payload := make([]byte, 8192) // TODO: optimize
	oob := make([]byte, 4096)     // TODO: optimize

	for {
		n, _, _, addr, err := s.Conn.ReadMsgUDP(payload, oob)
		//log.Printf("UDPServer.readLoop(): payload[%d], oob[%d]", n, oobn)
		if err != nil {
			log.Fatalf("Error reading UDP message: %s", err.Error())
		}

		peerName := addr.String()

		connection, present := s.Connections[peerName]
		if present == false {
			log.Printf("New peer from %s", peerName)
			//NewConnection(conn *net.UDPConn, laddr, raddr net.UDPAddr, isInitiator bool, local, remote *CryptoState) *Connection {
			//func NewConnection(conn *net.UDPConn, raddr *net.UDPAddr, local, remote *CryptoState) *Connection {
			connection = cryptoauth.NewConnection(s.Conn, addr, s.Keys, nil)
			connection.SetPassword(s.Password)
			s.Connections[peerName] = connection
		}

		// Do something with the packet
		_, err = connection.HandlePacket(payload[:n])
		if err != nil {
			log.Println(err)
		}
	}
}

func readDataPacket(s *cryptoauth.Server) {
	for {
		for _, v := range s.Connections {
			log.Println(v)
			// if v.isEstablished == true {
			// 	log.Println("hi")
			// } else {
			// 	log.Println("%s is not established", k)
			// }
		}
	}
}

func main() {
	s := new(cryptoauth.Server)
	s.Connections = make(map[string]*cryptoauth.Connection)
	s.KeyPair = new(cryptoauth.KeyPair)

	config := readConfigFile("config.json")

	keys := &cryptoauth.KeyPair{
		PublicKey:  *cryptoauth.DecodePublicKeyString(config.PublicKey),
		PrivateKey: *cryptoauth.DecodePrivateKeyString(config.PrivateKey),
	}

	s.Keys = cryptoauth.NewCryptoState(keys, nil, false)

	s.Listen = config.Bind
	s.Password = config.Password

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
