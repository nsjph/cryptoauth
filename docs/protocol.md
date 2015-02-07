# cryptoauth protocol for implementors

*Filling out sections over time*

## Shared Secrets

Shared secrets are used as a key for encrypting communications between peers during handshake establishment and regular data packets.

The inputs used to generate a shared secret is different depending on the stage of the connection.

### Shared Secrets for Hello Packets (Handshake)

Hello packets are sent by a client initiating a session with a remote server. 

The shared secret is computed using the client permanent public key, the server permanent public key, and a sha256 hash of the password being used by the client to authenticate with the server. It is computed using [ScalarMult(dst, in, base *[32]byte)](https://godoc.org/golang.org/x/crypto/curve25519#ScalarMult)

NOTE: The password hash the client is using is identified as part of the handshake challenge.

### Shared Secrets for Key Packets (Handshake)

Key packets are responses from the Server to the Client (initiator), with an encrypted temporary public key in the handshake packet.

The shared secret is used as an input for encrypting the temporary public key (along with a randomly generated nonce)

The shared secret is computed using the server private key, the client temporary public key, using the [box.Precompute(sharedKey, peersPublicKey, privateKey *[32]byte)](http://godoc.org/golang.org/x/crypto/nacl/box#Precompute) function.

### Shared Secrets for Data Packets 
