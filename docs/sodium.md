# libsodium support

## Introduction

libsodium is a portable, cross-platform port of DJB's NaCl (Networking and Cryptographic library). 
NaCl provides high performance and easy to use cryptographic functionality.

## Goal

The goal is to provide a common crypto api that can leverage either native golang /x/crypto/* packages or libsodium via cGo.

The expectation is there may be performance benefits on some architectures when using libsodium compared to /x/crypto packages

## Status - Incomplete

libsodium is not fully integrated at this time, as the API for crypto-related functions in cryptoauth haven't yet stablized.

## Roadmap

1. Stabilize the functions in crypto.go (incomplete)
2. Implement tests for crypto.go (incomplete)
3. Implement benchmarks for crypto.go (incomplete)
4. Mirror functionality in crypto_sodium.go using CGo (incomplete)
5. Mirror tests and benchmarks for crypto_sodium (incomplete)

## Installing libsodium 

Visit http://doc.libsodium.org and follow the instructions.

## Building with libsodium support

		go build -tags 'libsodium1.0'

## Testing with libsodium support

		go test -tags 'libsodium1.0'

## Benchmarking libsodium

		go test -tags 'libsodium1.0' -bench=.
