package main

import (
	"syscall"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

var r = rand.New(rand.NewSource(time.Now().UnixNano()))

func main() {
	hostname := "www.google.com"
	sockFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		panic(err)
	}
	
	defer syscall.Close(sockFd)
	
	err = syscall.SetsockoptInt(sockFd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err != nil {
		panic(err)
	}
	err = syscall.Bind(sockFd, &syscall.SockaddrInet4{Port:0})
	if err != nil {
		panic(err)
	}
	sa, err := syscall.Getsockname(sockFd)
	if err != nil {
		panic(err)
	}
	boundPort := sa.(*syscall.SockaddrInet4).Port
	fmt.Printf("Opened UDP socket on port %d\n", boundPort)
	query := makeDNSQuery(hostname)
	dnsServer := syscall.SockaddrInet4{
		Addr: [4]byte{8,8,8,8},
		Port: 53,
	}
	// fmt.Printf("%v\n", query)
	err = syscall.Sendto(sockFd, query, 0, &dnsServer)
	if err != nil {
		panic(err)
	}
	response := make([]byte, 65536)
	bytesRead := 0
	for bytesRead <= 0 {
		bytesRead, _, err = syscall.Recvfrom(sockFd, response, 0)
		if err != nil {
			panic(err)
		}
	}
	response = response[:bytesRead]
	decoded := decodeResponse(response)
	fmt.Printf("%s\n", buildOutput(decoded))
}

func buildOutput(payload *DNSPayload) string {
	queryType := "Recursive query for"
	if !payload.RecursionDesired() {
		queryType = "Iterative query for"
	}
	sep := " "
	hostname := string(payload.Questions[0].Name) + "\n"
	if len(payload.Questions) > 1 {
		sep = ":\n\t"
		for _, q := range payload.Questions[1:] {
			hostname = fmt.Sprintf("%s\t%s\n", hostname, string(q.Name))
		}
	}
	output := fmt.Sprintf("%s%s%s\n", queryType, sep, hostname)
	output = fmt.Sprintf("%sGot answer:\nopcode: %s, status: %s, id: %d\n", output, OPCODES[payload.Opcode()], RCODES[payload.ResponseCode()], payload.TransactionId)
	flags := "flags:"
	if payload.IsResponse() {
		flags += " qr"
	}
	if payload.AuthoritativeAnswer() {
		flags += " aa"
	}
	if payload.Truncated() {
		flags += " tc"
	}
	if payload.RecursionDesired() {
		flags += " rd"
	}
	if payload.RecursionAvailable() {
		flags += " ra"
	}
	output = fmt.Sprintf("%s%s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n\n", output, flags, payload.QDCount, payload.ANCount, payload.NSCount, payload.ARCount)
	// EDNS
	// if payload.ARCount > 0 {
	// 	edns := ""
	// 	arStart := int(payload.QDCount) + int(payload.ANCount) + int(payload.NSCount)
	// 	for _, a := range payload.Records[arStart:] {
	// 		if
	// 	}
	// }
	questionSection := "QUESTION:\n"
	for _, q := range payload.Questions {
		questionSection = fmt.Sprintf("%s%s\t\t%s\t%s\n", questionSection, string(q.Name), QTYPES[int(q.Type)], QCLASSES[int(q.Class)])
	}
	answerSection := ""
	if int(payload.ANCount) > 0 {
		answerSection = "ANSWER:\n"
		for i := 0; i < int(payload.ANCount); i++ {
			a := payload.Records[i]
			ip := fmt.Sprintf("%d", a.RData[0])
			for _, piece := range a.RData[1:] {
				ip = fmt.Sprintf("%s.%d", ip, piece)
			}
			answerSection = fmt.Sprintf("%s%s\t%d\t%s\t%s\t%s\n", answerSection, string(a.Name), a.TTL, QTYPES[int(a.Type)], QCLASSES[int(a.Class)], ip)
		}
	}
	output = fmt.Sprintf("%s%s\n%s\n",output, questionSection, answerSection)
	return output
}

func makeDNSQuery(hostname string) []byte {
	txId := uint16(r.Uint32() >> 16)
	query := makeDNSQueryHeader(txId, true)
	question := makeDNSQuestion(hostname, 1, 1)
	query = append(query, question...)
	return query
}

func makeDNSQuestion(hostname string, qType uint16, qClass uint16) []byte {
	question := []byte{}
	parts := strings.Split(hostname, ".")
	for _, p := range parts {
		question = append(question, byte(len(p)))
		question = append(question, []byte(p)...)
	}
	question = append(question, 0)
	t1 := byte((qType & 0xFF00) >> 8)
	t2 := byte(qType & 0xFF)
	c1 := byte((qClass & 0xFF00) >> 8)
	c2 := byte(qClass & 0xFF)
	question = append(question, []byte{t1, t2, c1,c2}...)
	return question
}

func makeDNSQueryHeader(txId uint16, recurse bool) []byte {
	header := make([]byte, 12)
	header[0] = byte((txId & 0xFF00) >> 8)
	header[1] = byte(txId & 0xFF)
	if recurse {
		header[2] = 1
	} else {
		header[2] = 0
	}
	header[5] = 1
	return header
}
