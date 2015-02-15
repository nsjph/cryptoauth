# Cryptoauth protocol guide

This is a supplement for those already familiar with the cjdns [whitepaper](https://github.com/cjdelisle/cjdns/blob/master/doc/Whitepaper.md). It is designed as a 'cheatsheet' for those looking to understand or implement the cryptoauth protocol.

**WARNING**: This guide is incomplete and probably contains errors

## High Level

![Cryptoauth handshake flow](https://raw.githubusercontent.com/nsjph/cryptoauth/master/docs/handshake.png)

## Terminology

* **Keypair**: A Curve25519 pair of cryptographic keys, publickey and privatekey. These are [32]byte arrays (in golang, "byte" is the same as uint8)
* **Shared Secret**: A unique shared secret key ([32]byte) is generated based on the state of the cryptoauth session. A shared secret and a unique nonce is used to encrypt/decrypt temporary public keys and data packets. The method for computing the shared secret is different for key packets and data packets.
* **Permanent Keypair**: Both parties must have a permanent (long-term) curve25519-dervived keypair. Clients must know the server's permanent publickey to send a "Hello Packet". Servers use the client permanent public key as an input for encrypting the server's temporary public key in a "Key Packet"
* **Temporary Keypair**: The temporary keypair is used to generate the final secret key, used as an input for encrypting/decrypting data packets. Temporary public keys are exchanged via "Key Packets".

### Disambiguation - Stage vs Nonce(s)

Within cryptoauth reference material, the handshake stage and "nonces" have different meanings based on the state of the cryptoauth session.

**Before Established**

In Hello and Key Packets, the "Stage" (uint32) is a number (0-4) used to indicate what type of cryptoauth packet has been received:

1. *Hello Packet*: Client to Server
2. *Key Packet*: Server to Client
3. *Key Packet*: Client to Server
4. *Data Packet*: From either client or server

A "Challenge Nonce" is included in Key Packets, which is used as an input for encrypting/decrypting temporary public keys.

**After Established**

In data packets, the nonce (uint32) is converted to a [24]byte array for use as an input in encrypting/decryting data packets.

## Hello Packets

Hello Packets are used by clients to authenticate to a server and share the client's permanent public key.

* A Hello Packet is 120 bytes in size.
* A Hello Packet includes a Challenge which is 12 bytes in size
* The Hello.Stage is either 0 for initial Hello or 1 for repeat Hello Packets
* The Challenge.Type is currently always "1", used to indicate password-based authentication to the server. This could change in the future 
* The Challenge.Lookup includes 8 bytes of the hashed password used by the client to authenticate to the server. (TODO: describe this in detail)
* A server must never accept a client's permanent public key unless they have authenticated

### Packet Structure

    type Challenge struct {
      Type        uint8 
      Lookup      [7]byte
      Derivations uint16
      Additional  uint16
    }

    type Handshake struct {
      Stage               uint32
      Challenge           *Challenge
      Padding             [24]byte
      PublicKey           [32]byte
      Padding             [48]byte
    }

## Key Packets

Key Packets include an encrypted and authenticated temporary public key. Once both client and server know each other's temporary public key, they can compute a shared secret for use in data packets.

* Key Packets must not be sent from a server to a client unless the client has successfully authenticated
* Key Packets must not be sent from a client to a server unless the client knows server temporary public key
* Key Packets must not be accepted from a client unless the client has successfully authenticated
* Key Packets are 160 bytes in size

### Packet Structure

    type Challenge struct {
      Type        uint8 
      Lookup      [7]byte
      Derivations uint16
      Additional  uint16
    }

    type Handshake struct {
      Stage               uint32
      Challenge           *Challenge
      Nonce               [24]byte
      PublicKey           [32]byte
      EncryptedTempPubKey [32]byte
    }

## Data Packets

### Packet Structure

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
