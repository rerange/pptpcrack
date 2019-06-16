// Copyright 2019 Orange. All rights reserved.
// A Generic EAP/MPPE implementation in Go
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.
// RFC Reference:
//    https://tools.ietf.org/html/rfc2759#section-8
//    https://tools.ietf.org/html/rfc3078
//    https://tools.ietf.org/html/rfc3079
// RADIUS server is the Authenticator
// Client is the Station or Peer

package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"./eap"
)

func main() {
	userName := "vpnuser"
	password := "vpnuser123"
	authenticatorChallenge := h2b("d3e250af8c49b62418d5292170c85f71")
	peerChallenge := h2b("6a73eac6c3b458bf549eb0ad26e1b717")
	keyLength := 128
	Verify2(userName, password, authenticatorChallenge, peerChallenge, keyLength)
}

func Verify2(userName, password string, authenticatorChallenge, peerChallenge []byte, keyLength int) {
	passwordHash := eap.NtPasswordHash(password)
	passwordHashHash := eap.HashNtPasswordHash(passwordHash)
	challenge := eap.ChallengeHash(peerChallenge, authenticatorChallenge, userName)
	ntResponse := eap.ChallengeResponse(challenge, passwordHash)
	masterKey := eap.GetMasterKey(passwordHashHash, ntResponse)
	authenticatorResponse := eap.GenerateAuthenticatorResponse(password, ntResponse, peerChallenge, authenticatorChallenge, userName)

	var length int
	if keyLength == 40 || keyLength == 56 {
		length = 8
	} else if keyLength == 128 {
		length = 16
	} else if keyLength == 256 {
		length = 32
	}

	masterSendKey := eap.GetAsymmetricStartKey(masterKey, length, true, true)
	masterReceiveKey := eap.GetAsymmetricStartKey(masterKey, length, false, true)
	sendSessionKey := eap.GetNewKeyFromSHA(masterSendKey, masterSendKey, length)
	receiveSessionKey := eap.GetNewKeyFromSHA(masterReceiveKey, masterReceiveKey, length)
	sendSessionKey = eap.ReduceSessionKey(sendSessionKey, keyLength)
	receiveSessionKey = eap.ReduceSessionKey(receiveSessionKey, keyLength)
	SendRC4, err := eap.NewRC4key(sendSessionKey)
	ReceiveRC4, err := eap.NewRC4key(receiveSessionKey)
	if err != nil {
		log.Fatal(err)
	}

	// MS-CHAP-V2
	fmt.Printf("UserName: %s\n", userName)
	fmt.Printf("Password: %s\n", password)
	fmt.Printf("AuthenticatorChallenge: %x\n", authenticatorChallenge)
	fmt.Printf("PeerChallenge: %x\n", peerChallenge)
	fmt.Printf("Challenge: %x\n", challenge)
	fmt.Printf("NTResponse: %x\n", ntResponse)
	fmt.Printf("AuthenticatorResponse: %s\n", authenticatorResponse)

	// MPPE
	fmt.Printf("PasswordHash: %x\n", passwordHash)
	fmt.Printf("PasswordHashHash: %x\n", passwordHashHash)
	fmt.Printf("MasterKey: %x%s\n", masterKey, " (EAP-eap: Derived Master Key)")
	fmt.Printf("MasterSendKey: %x\n", masterSendKey)
	fmt.Printf("MasterReceiveKey: %x\n", masterReceiveKey)
	fmt.Printf("EAP-eap: Derived key: %x%x\n", masterReceiveKey, masterSendKey)
	fmt.Printf("SendSessionKey: %x\n", sendSessionKey)
	fmt.Printf("ReceiveSessionKey: %x\n", receiveSessionKey)

	// Encrypt
	testMsg1 := "test message"
	testMsg2 := "test message"
	sendRC4 := make([]byte, len(testMsg1))
	SendRC4.XORKeyStream(sendRC4, []byte(testMsg1))
	receiveRC4 := make([]byte, len(testMsg2))
	ReceiveRC4.XORKeyStream(receiveRC4, []byte(testMsg2))
	fmt.Printf("Send RC4(%s): %x\n", testMsg1, sendRC4)
	fmt.Printf("Receive RC4(%s): %x\n", testMsg2, receiveRC4)

	// Decrypt
	SendRC4, _ = eap.NewRC4key(sendSessionKey)
	ReceiveRC4, _ = eap.NewRC4key(receiveSessionKey)
	msg1 := make([]byte, len(sendRC4))
	SendRC4.XORKeyStream(msg1, sendRC4)
	msg2 := make([]byte, len(receiveRC4))
	ReceiveRC4.XORKeyStream(msg2, receiveRC4)
	fmt.Printf("Send(Decrypted): %s\n", msg1)
	fmt.Printf("Receive(Decrypted): %s\n", msg2)
}

func h2b(h string) []byte {
	src := []byte(h)
	dst := make([]byte, hex.DecodedLen(len(src)))
	n, err := hex.Decode(dst, src)
	if err != nil {
		log.Fatal(err)
	}
	return dst[:n]
}
