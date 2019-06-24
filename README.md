<h1 align="center">Welcome to PPTP-Crack 👋</h1>
<p>
  <img src="https://img.shields.io/badge/version-0.1-blue.svg?cacheSeconds=2592000" />
</p>

> A Generic EAP/MPPE Implementation in Go

### 🏠 [Homepage](https://github.com/rerange/pptpcrack)

## Install

```sh
make install
```

## Prerequisite

Install [WinPcap_4_1_3](https://www.winpcap.org/install/default.htm) for Windows or [libpcap](https://formulae.brew.sh/formula/libpcap) for MacOS and other linux distributions

For MacOS users:

```sh
brew install tcpdump
```

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

## Run tests

```sh
make test
```

## Author

👤 **orange**

* Github: [@rerange](https://github.com/rerange)

## 🤝 Contributing

Contributions, issues and feature requests are welcome!<br />Feel free to check [issues page](https://github.com/rerange/pptpcrack/issues).

## Show your support

Give a ⭐️ if this project helped you!
