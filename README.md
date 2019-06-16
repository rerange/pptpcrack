# PPTP-Crack
 
A Generic EAP/MPPE Implementation in Go By  [Orange](https://github.com/rerange)

## RFC Reference

1. Microsoft PPP CHAP Extensions, Version 2: [RFC2759](https://tools.ietf.org/html/rfc2759)
2. Microsoft Point-To-Point Encryption (MPPE) Protocol: [RFC3078](https://tools.ietf.org/html/rfc3078)
3. Deriving Keys for use with Microsoft Point-to-Point Encryption (MPPE): [RFC3079](https://tools.ietf.org/html/rfc3079)

## Usage

```bash
pptpcrack -f dump.pcap -o dump_decrypt.pcap -w wordlist.txt 
```

> -f string Filename of dump file to read from

>-o string Filename of decrypted packets to write to

>-w string Filename of password list to crack MS-CHAP-V2 handshake