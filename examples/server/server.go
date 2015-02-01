package main

import (
	"github.com/nsjph/cryptoauth"
	"log"
	"net"
	"syscall"
	"time"
)

func (u *UDPServer) listen() {

	localAddr, err := net.ResolveUDPAddr("udp4", u.config.Bind)
	checkFatal(err)

	u.conn, err = net.ListenUDP("udp4", localAddr)
	checkFatal(err)

	f, err := u.conn.File()
	defer f.Close()
	checkFatal(err)
	fd := int(f.Fd())
	// This one makes sure all packets we send out do not have DF set on them.
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DONT)
	checkFatal(err)

	log.Println("Going into read loop")
	go u.readLoop()
}

func (u *UDPServer) readLoop() {
	defer u.conn.Close()
	payload := make([]byte, 8192) // TODO: optimize
	oob := make([]byte, 4096)     // TODO: optimize

	for {
		n, oobn, _, addr, err := u.conn.ReadMsgUDP(payload, oob)
		log.Printf("UDPServer.readLoop(): payload[%d], oob[%d]", n, oobn)
		check(err)

		peerName := addr.String()

		peer, present := u.peers[peerName]
		if present == false {
			log.Printf("New peer from %s", peerName)
			peer = &cryptoauth.Peer{
				Addr:         addr,
				Name:         peerName,
				Conn:         u.conn,
				AuthRequired: true,
				Established:  false,
				NextNonce:    0,
				PublicKey:    [32]byte{},
			}
			u.peers[peerName] = peer
		}

		peer.ParseMessage(payload[:n], u.state)
	}
}

func main() {
	u := new(UDPServer)
	u.peers = make(map[string]*cryptoauth.Peer)
	u.state = new(cryptoauth.State)
	u.state.KeyPair = new(cryptoauth.KeyPair)

	u.config = readConfigFile("config.json")

	u.state.KeyPair.PublicKey = cryptoauth.DecodePublicKeyString(u.config.PublicKey)
	u.state.KeyPair.PrivateKey = cryptoauth.DecodePrivateKeyString(u.config.PrivateKey)

	if len(u.config.Password) > 0 {
		passwd := new(cryptoauth.Passwd)
		passwd.Hash = cryptoauth.HashPassword([]byte(u.config.Password))
		u.state.Passwords = make(map[[32]byte]*cryptoauth.Passwd)
		u.state.Passwords[passwd.Hash] = passwd
	} else {
		log.Fatal("Set a password in config.json")
	}

	sleepInterval := 60

	u.listen()

	for {
		time.Sleep(time.Duration(sleepInterval) * time.Second)
	}

	log.Print(u.config.Bind)
	log.Print(u.config.IPv6)
	log.Print(u.config.PublicKey)
	log.Print(u.config.PrivateKey)
	log.Print(u.config.Password)

	//u.state.
	//	u.listen()

}
