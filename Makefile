NAME="pptpcrack"

all: darwin windows

clean:
	rm -f ${NAME}_darwin64
	rm -f ${NAME}_linux64
	rm -f ${NAME}_win32.exe
run:
	rm -f data/test_decrypt.pcap
	go run ${NAME}.go -f data/test.pcap -o data/test_decrypt.pcap -w wordlist.txt
test:
	go run verify.go
darwin:
	GOOS=darwin GOARCH=amd64 go build -o ${NAME}_darwin64 ${NAME}.go
windows:
	GOOS=windows GOARCH=386 go build -o ${NAME}_win32.exe ${NAME}.go
linux:
	GOOS=linux GOARCH=amd64 go build -o ${NAME}_linux64 ${NAME}.go
install: darwin
	cp ./${NAME}_darwin64 /usr/local/bin/${NAME}