// By Orange
// A Generic MSCHAPv2/MPPE implementation in Go
//    https://tools.ietf.org/html/rfc2759#section-8
//    https://tools.ietf.org/html/rfc3078
//    https://tools.ietf.org/html/rfc3079
// RADIUS server is the Authenticator
// Client is the Station or Peer

package eap

import (
	"bytes"
	"crypto/des"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/hex"
	"log"
	"strings"

	"golang.org/x/crypto/md4"
	"golang.org/x/text/encoding/unicode"
)

var (
	desParityKeyTable []byte
)

func init() {
	desParityKeyTable = makeDesParityKeyTable()
}

func makeDesParityKeyTable() []byte {
	tbl := make([]byte, 128)

	for i := uint8(0); i < 128; i++ {
		c := 0
		for j := uint(0); j < 7; j++ {
			if i&(0x01<<j) != 0 {
				c++
			}
		}

		if c%2 == 0 {
			tbl[i] = (i << 1) | 1
		} else {
			tbl[i] = (i << 1) | 0
		}
	}

	return tbl
}

func makeDesParityKey(key []byte) []byte {
	if len(key) != 7 {
		return key
	}

	pkey := []byte{
		key[0] >> 1,
		((key[0] & 0x01) << 6) | (key[1] >> 2),
		((key[1] & 0x03) << 5) | (key[2] >> 3),
		((key[2] & 0x07) << 4) | (key[3] >> 4),
		((key[3] & 0x0f) << 3) | (key[4] >> 5),
		((key[4] & 0x1f) << 2) | (key[5] >> 6),
		((key[5] & 0x3f) << 1) | (key[6] >> 7),
		key[6] & 0x7f,
	}
	for i, v := range pkey {
		pkey[i] = desParityKeyTable[v]
	}

	return pkey
}

func ChallengeHash(peerChallenge, authenticatorChallenge []byte, userName string) []byte {
	sha := sha1.New()
	sha.Write(peerChallenge)
	sha.Write(authenticatorChallenge)
	sha.Write([]byte(userName))
	digest := sha.Sum(nil)
	return digest[:8]
}

func NtPasswordHash(password string) []byte {
	encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	pwd, err := encoder.Bytes([]byte(password))
	if err != nil {
		log.Fatal(err)
	}
	hash := md4.New()
	hash.Write([]byte(pwd))
	return hash.Sum(nil)
}

func HashNtPasswordHash(passwordHash []byte) []byte {
	hash := md4.New()
	hash.Write(passwordHash)
	return hash.Sum(nil)
}

func ChallengeResponse(challenge, passwordHash []byte) []byte {
	// Generate the NTResponse the client sends the AP
	// This is the response part asleap/JtR/hashcat crack

	if len(passwordHash) < 21 {
		padding := make([]byte, 21-len(passwordHash))
		passwordHash = append(passwordHash, padding...)
	}
	one := DesEncrypt(challenge, passwordHash[:7])
	two := DesEncrypt(challenge, passwordHash[7:14])
	three := DesEncrypt(challenge, passwordHash[14:21])
	response := append(one, two...)
	response = append(response, three...)
	return response
}

func DesEncrypt(text, key []byte) []byte {
	cb, err := des.NewCipher(makeDesParityKey(key))
	if err != nil {
		log.Fatal(err)
	}
	blockSize := cb.BlockSize()
	padding := blockSize - len(text)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	text = append(text, padtext...)
	cipher := make([]byte, len(text))
	cb.Encrypt(cipher, text)
	return cipher[:8]
}

func GetMasterKey(passwordHashHash, ntResponse []byte) []byte {
	// Generate Master Key used to derive PMK part of MPPE not MSCHAP
	// https://tools.ietf.org/html/rfc3079#section-3.4

	Magic1 := []byte("\x54\x68\x69\x73\x20\x69\x73\x20\x74\x68\x65\x20\x4d\x50\x50\x45\x20\x4d\x61\x73\x74\x65\x72\x20\x4b\x65\x79")
	sha := sha1.New()
	sha.Write(passwordHashHash)
	sha.Write(ntResponse)
	sha.Write(Magic1)
	digest := sha.Sum(nil)
	return digest[:16]
}

func GenerateAuthenticatorResponse(password string, ntResponse, peerChallenge, authenticatorChallenge []byte, userName string) []byte {
	// Create the response the AP sends to the Client to prove it knows the password too
	// Defined in https://tools.ietf.org/html/rfc2759#section-8

	Magic1 := []byte("\x4D\x61\x67\x69\x63\x20\x73\x65\x72\x76\x65\x72\x20\x74\x6F\x20\x63\x6C\x69\x65\x6E\x74\x20\x73\x69\x67\x6E\x69\x6E\x67\x20\x63\x6F\x6E\x73\x74\x61\x6E\x74")
	Magic2 := []byte("\x50\x61\x64\x20\x74\x6F\x20\x6D\x61\x6B\x65\x20\x69\x74\x20\x64\x6F\x20\x6D\x6F\x72\x65\x20\x74\x68\x61\x6E\x20\x6F\x6E\x65\x20\x69\x74\x65\x72\x61\x74\x69\x6F\x6E")

	passwordHash := NtPasswordHash(password)
	passwordHashHash := HashNtPasswordHash(passwordHash)

	challenge := ChallengeHash(peerChallenge, authenticatorChallenge, userName)

	sha := sha1.New()
	sha.Write(passwordHashHash)
	sha.Write(ntResponse)
	sha.Write(Magic1)
	digest := sha.Sum(nil)

	sha.Reset()

	sha.Write(digest)
	sha.Write(challenge)
	sha.Write(Magic2)
	digest = sha.Sum(nil)
	return []byte(strings.ToUpper("S=" + hex.EncodeToString(digest)))
}

func GetAsymmetricStartKey(masterKey []byte, sessionKeyLength int, isSend, isServer bool) []byte {
	// Generate MS-MPEE-Send/Recv-Key
	// From https://tools.ietf.org/html/rfc3079#section-3.4

	Magic2 := []byte("\x4f\x6e\x20\x74\x68\x65\x20\x63\x6c\x69\x65\x6e\x74\x20\x73\x69\x64\x65\x2c\x20\x74\x68\x69\x73\x20\x69\x73\x20\x74\x68\x65\x20\x73\x65\x6e\x64\x20\x6b\x65\x79\x3b\x20\x6f\x6e\x20\x74\x68\x65\x20\x73\x65\x72\x76\x65\x72\x20\x73\x69\x64\x65\x2c\x20\x69\x74\x20\x69\x73\x20\x74\x68\x65\x20\x72\x65\x63\x65\x69\x76\x65\x20\x6b\x65\x79\x2e")
	Magic3 := []byte("\x4f\x6e\x20\x74\x68\x65\x20\x63\x6c\x69\x65\x6e\x74\x20\x73\x69\x64\x65\x2c\x20\x74\x68\x69\x73\x20\x69\x73\x20\x74\x68\x65\x20\x72\x65\x63\x65\x69\x76\x65\x20\x6b\x65\x79\x3b\x20\x6f\x6e\x20\x74\x68\x65\x20\x73\x65\x72\x76\x65\x72\x20\x73\x69\x64\x65\x2c\x20\x69\x74\x20\x69\x73\x20\x74\x68\x65\x20\x73\x65\x6e\x64\x20\x6b\x65\x79\x2e")
	SHSPad1 := []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	SHSPad2 := []byte("\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2")
	var s []byte
	if isSend {
		if isServer {
			s = Magic3
		} else {
			s = Magic2
		}

	} else {
		if isServer {
			s = Magic2
		} else {
			s = Magic3
		}
	}

	sha := sha1.New()
	sha.Write(masterKey)
	sha.Write(SHSPad1)
	sha.Write(s)
	sha.Write(SHSPad2)
	digest := sha.Sum(nil)
	return digest[:sessionKeyLength]
}

func GetNewKeyFromSHA(startKey, sessionKey []byte, sessionKeyLength int) []byte {
	// Generate the initial send session key MPPE
	// https://tools.ietf.org/html/rfc3078 Section 7.3

	SHAPad1 := []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	SHAPad2 := []byte("\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2")

	sha := sha1.New()
	sha.Write(startKey[:sessionKeyLength])
	sha.Write(SHAPad1)
	sha.Write(sessionKey[:sessionKeyLength])
	sha.Write(SHAPad2)
	digest := sha.Sum(nil)

	return digest[:sessionKeyLength]
}

func ReduceSessionKey(sendSessionKey []byte, keyLength int) []byte {
	// Reduce key size appropriately
	// https://tools.ietf.org/html/rfc3079#section-3.1 3.2 & 3.3

	if keyLength == 40 {
		return append([]byte("\xd1\x26\x9e"), sendSessionKey[3:]...)
	}

	if keyLength == 56 {
		return append([]byte("\xd1"), sendSessionKey[1:]...)
	}

	if keyLength == 128 || keyLength == 256 {
		return sendSessionKey
	}
	return nil
}

func NewRC4key(key []byte) (*rc4.Cipher, error) {
	return rc4.NewCipher(key)
}
