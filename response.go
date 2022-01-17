package main

type DNSResourceRecord struct {
	Type 		uint16
	Class		uint16
	TTL		uint32
	RDLength 	uint16
	Name		[]byte
	RData		[]byte
}

type DNSQuestion struct {
	Type	uint16
	Class	uint16
	Name	[]byte
}

type DNSPayload struct {
	TransactionId	uint16
	lFlagBits		byte
	rFlagBits		byte
	QDCount	 	uint16
	ANCount		uint16
	NSCount		uint16
	ARCount		uint16
  Size			int
	Questions		[]DNSQuestion
	Records		[]DNSResourceRecord
}

func (h DNSPayload) IsResponse() bool {
	return h.lFlagBits & 0x80 == 1
}

func (h DNSPayload) Opcode() int {
	return int((h.lFlagBits >> 3) & 0xF)
}

func (h DNSPayload) AuthoritativeAnswer() bool {
	return h.lFlagBits & 4 == 1
}

func (h DNSPayload) Truncated() bool {
	return h.lFlagBits & 2 == 1
}

func (h DNSPayload) RecursionDesired() bool {
	return h.lFlagBits & 1 == 1
}

func (h DNSPayload) RecursionAvailable() bool {
	return h.rFlagBits & 0x80 == 1
}

func (h DNSPayload) Z() int {
	return int((h.rFlagBits >> 4) & 0x7)
}

func (h DNSPayload) ResponseCode() int {
	return int(h.rFlagBits & 0xF)
}

func decodeResponse(response []byte) *DNSPayload {
	payload := decodeHeader(response)
	pos := 12
	numQuestions := int(payload.QDCount)
	questions := make([]DNSQuestion, numQuestions)
	for i := 0; i < numQuestions; i++ {
		question := &DNSQuestion{}
		pos = decodeQuestion(response, question, pos)
		questions[i] = *question
	}
	numRecords := int(payload.ANCount) + int(payload.NSCount) + int(payload.ARCount)
	records := make([]DNSResourceRecord, numRecords)
	for i := 0; i < numRecords; i++ {
		record := &DNSResourceRecord{}
		pos = decodeRecord(response, record, pos)
		records[i] = *record
	}
	payload.Questions = questions
	payload.Records = records
	return payload
}

func decodeHeader(response []byte) *DNSPayload {
	return &DNSPayload{
		TransactionId: bytesToUint16(response[0:2]),
		lFlagBits: response[2],
		rFlagBits: response[3],
		QDCount: bytesToUint16(response[4:6]),
		ANCount: bytesToUint16(response[6:8]),
		NSCount: bytesToUint16(response[8:10]),
		ARCount: bytesToUint16(response[10:12]),
		Size: len(response),
	}
}

func decodeQuestion(response []byte, question *DNSQuestion, pos int) int {
	question.Name = []byte{}
	pos = decodeName(response, question.Name, pos)
	question.Type = bytesToUint16(response[pos:pos+2])
	question.Class = bytesToUint16(response[pos+2:pos+4])
	return pos + 4
}

func decodeRecord(response []byte, record *DNSResourceRecord, pos int) int {
	record.Name = []byte{}
	pos = decodeName(response, record.Name, pos)
	record.Type = bytesToUint16(response[pos:pos+2])
	record.Class = bytesToUint16(response[pos+2:pos+4])
	record.TTL = bytesToUint32(response[pos+4:pos+8])
	record.RDLength = bytesToUint16(response[pos+8:pos+10])
	dataLen := int(record.RDLength)
	pos += 10
	record.RData = response[pos : pos+dataLen]
	return pos + dataLen
}


func decodeName(response, name []byte, pos int) int {
	offset := pos
	var pointer uint16
	for b := response[offset]; b != 0; {
		if b&0xC0 == 0xC0 { // we have a pointer
			pointer = bytesToUint16(response[offset : offset+2])
			offset = int(pointer & 0x3FFF)
		} else { // we have a number
			size := int(b)
			for i := 1; i <= size; i++ {
				name = append(name, response[offset+i])
			}
			name = append(name, '.')
			offset += size + 1
		}
		b = response[offset]
	}
	if pointer == 0 {
		return offset + 1
	}
	return pos + 2
}

func bytesToUint16(b []byte) uint16 {
	return (uint16(b[0]) << 8) | uint16(b[1])
}

func bytesToUint32(b []byte) uint32 {
	result := uint32(b[0])
	for _, n := range b[1:] {
		result = (result << 8) | uint32(n)
	}
	return result
}
