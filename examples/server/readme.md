# example server for testing cryptoauth

## Instructions

1. Make sure you have built and installed cryptoauth package
2. Run go build in this directory
3. Configure a cjdroute instance to connect to the example server with a connectTo entry like:

	"10.0.0.1:37703":{"password":"thisismylongtestpassword12345","publicKey":"pb1ugg08gt415nfqrdhtldpv81695rscq57r4um86fj440upksx0.k"}

NOTE: Replace 10.0.0.1 with the IP address of your local system.

## Running

1. Run cjdroute (now configured to talk to your example server), and 
2. Run ./server

You should see some debug logs like like the following

    ~/src/github.com/nsjph/cryptoauth/examples/server$ ./server
    2015/02/07 12:12:03 DecodePublicKeyString:
            string [pb1ugg08gt415nfqrdhtldpv81695rscq57r4um86fj440upksx0.k] -> hex [5505ed1c402e935068b397bd2c59dd2898542e5eb69c4bf444a6414280ae1177]
    2015/02/07 12:12:03 Going into read loop
    2015/02/07 12:12:21 UDPServer.readLoop(): payload[160], oob[0]
    2015/02/07 12:12:21 New peer from 10.0.0.1:57354
    2015/02/07 12:12:21 received packet with nonce: 0
    2015/02/07 12:12:21 [DEBUG] decoding handshake. our next nonce is
    2015/02/07 12:12:21 getAuth: found matching password
    2015/02/07 12:12:21 [DEBUG] DecodeHandshake2: permanent public key is different!
    2015/02/07 12:12:21 [ERROR] HandlePacket: error decoding handshake: Authentication error: Permanent public key doesn't match known
    2015/02/07 12:12:22 UDPServer.readLoop(): payload[160], oob[0]
    2015/02/07 12:12:22 received packet with nonce: 1
    2015/02/07 12:12:22 [DEBUG] decoding handshake. our next nonce is
    2015/02/07 12:12:22 getAuth: found matching password
    2015/02/07 12:12:22 [DEBUG] DecodeHandshake2: remote temp keypair is nil, allocating a new struct
    2015/02/07 12:12:22 [DEBUG] HandlePacket: successfully decoded handshake [2]
    2015/02/07 12:12:22 creating a key packet challenge
    2015/02/07 12:12:22 computing shared secret with:
            privateKey: [&affe464f278ec699badd824afd4cd976b78c9aa851f9083015dcab4c8af1ed2e]
            herPublicKey: [&b98227934aaf6165be1f59e2ce2c094f35b88975edd127ba3ca9ee0c04ce8356]
    2015/02/07 12:12:22 encryptedTempPubKey:
            nonce [c9cd742d1cd30a2cae304ed40b450402c3609905b138e9bc]
            secret [3eab27a59c25bade5228c2e8dc91601014fe41ee8aa5acc1f6d6759831932fd7]
            myTempPubKey [2e438826f25cdb3d2c2a2ecbc1f1c890d3f22ec4e97687e284095b8140169779]
    2015/02/07 12:12:22 buf.Bytes() len [72]
    2015/02/07 12:12:22 length of new handshake: 120
    2015/02/07 12:12:22 wrote 120 to 10.0.0.1:57354
    2015/02/07 12:12:23 UDPServer.readLoop(): payload[60], oob[0]
    2015/02/07 12:12:23 received packet with nonce: 4
    2015/02/07 12:12:23 computing shared secret with:
            privateKey: [&7e8d7b00082231fb1218ba52458ad60e7b20e7f1994b0d45566ce430bf1fbdd7]
            herPublicKey: [&b98227934aaf6165be1f59e2ce2c094f35b88975edd127ba3ca9ee0c04ce8356]
    2015/02/07 12:12:23 convertedNonce: [000000000400000000000000000000000000000000000000]
    2015/02/07 12:12:23 [DEBUG] Handshake Complete!
    2015/02/07 12:12:24 UDPServer.readLoop(): payload[60], oob[0]
    2015/02/07 12:12:24 received packet with nonce: 5
    2015/02/07 12:12:24 convertedNonce: [000000000500000000000000000000000000000000000000]
    2015/02/07 12:12:24 [DEBUG] Decrypted message successfully
    2015/02/07 12:12:25 UDPServer.readLoop(): payload[60], oob[0]
    2015/02/07 12:12:25 received packet with nonce: 6
    2015/02/07 12:12:25 convertedNonce: [000000000600000000000000000000000000000000000000]
    2015/02/07 12:12:25 [DEBUG] Decrypted message successfully
