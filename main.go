package main

import (
	"fmt"
	"net/netip"
	"strings"
)

type BytePacketBuffer struct {
	Buf [512]byte
	Pos uint
	Err error
}

func (buf *BytePacketBuffer) setErr(err error) {
	if buf.Err == nil && err != nil {
		buf.Err = err
	}
}

// Step forward a given number of steps
func (buf *BytePacketBuffer) step(steps uint) {
	if buf.Err != nil {
		return
	}
	if buf.Pos+steps > 511 {
		buf.setErr(fmt.Errorf("overstepped buffer by %d bytes", (buf.Pos+steps)-511))
		return
	}
	buf.Pos += steps
}

// Seek to a given position
func (buf *BytePacketBuffer) seek(pos uint) {
	if buf.Err != nil {
		return
	}
	if pos > 511 {
		buf.setErr(fmt.Errorf("oversought buffer by %d bytes", pos-511))
		return
	}
	buf.Pos = pos
}

// Read a single byte and step forward
func (buf *BytePacketBuffer) read() byte {
	if buf.Err != nil {
		return 0
	}
	if buf.Pos > 511 {
		buf.setErr(fmt.Errorf("end of buffer"))
		return 0
	}
	res := buf.Buf[buf.Pos]
	buf.Pos++
	return res
}

// Get a single byte without changing position
func (buf *BytePacketBuffer) get(pos uint) byte {
	if buf.Err != nil {
		return 0
	}
	if pos > 511 {
		buf.setErr(fmt.Errorf("end of buffer"))
		return 0
	}
	return buf.Buf[pos]
}

// Get a range of bytes
func (buf *BytePacketBuffer) getRange(start uint, len uint) []byte {
	if buf.Err != nil {
		return nil
	}
	if start+len > 511 {
		buf.setErr(fmt.Errorf("end of buffer"))
		return nil
	}
	return buf.Buf[start : start+len]
}

// Read a two-byte number
func (buf *BytePacketBuffer) readUint16() uint16 {
	b1 := buf.read()
	b2 := buf.read()
	return uint16(b1)<<8 | uint16(b2)
}

// Read a four-byte number
func (buf *BytePacketBuffer) readUint32() uint32 {
	b1 := buf.read()
	b2 := buf.read()
	b3 := buf.read()
	b4 := buf.read()
	return uint32(b1)<<24 | uint32(b2)<<16 | uint32(b3)<<8 | uint32(b4)
}

// Read a qname
func (buf *BytePacketBuffer) readQueryName() (string, error) {
	if buf.Err != nil {
		return "", buf.Err
	}

	var outstr strings.Builder
	pos := buf.Pos
	jumped := false
	const maxJumps = 5
	jumpsPerformed := 0
	delim := ""

	for {
		if jumpsPerformed > maxJumps {
			return "", fmt.Errorf("jump limit of %d exceeded", maxJumps)
		}

		length := buf.get(pos)
		if buf.Err != nil {
			return "", buf.Err
		}

		if (length & 0xC0) == 0xC0 {
			if !jumped {
				buf.seek(pos + 2)
			}

			b2 := buf.get(pos + 1)
			offset := ((uint16(length) ^ 0xC0) << 8) | uint16(b2)
			pos = uint(offset)

			jumped = true
			jumpsPerformed++
			continue
		}

		pos++
		if length == 0 {
			break
		}

		outstr.WriteString(delim)
		strBuf := buf.getRange(pos, uint(length))
		if buf.Err != nil {
			return "", buf.Err
		}

		outstr.WriteString(strings.ToLower(string(strBuf)))
		delim = "."
		pos += uint(length)
	}

	if !jumped {
		buf.seek(pos)
	}

	return outstr.String(), buf.Err
}

type ResponseCode uint8

const (
	NoError ResponseCode = iota
	FormErr
	ServFail
	NXDomain
	NotImp
	Refused
)

func ToResponseCode(val uint8) (ResponseCode, error) {
	switch ResponseCode(val) {
	case NoError, FormErr, ServFail, NXDomain, NotImp, Refused:
		return ResponseCode(val), nil
	default:
		return NoError, fmt.Errorf("unknown response code: %d", val)
	}
}

type DNSHeader struct {
	ID      uint16
	QR      bool
	OpCode  byte
	AA      bool
	TC      bool
	RD      bool
	RA      bool
	Z       byte
	RCode   ResponseCode
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func (h *DNSHeader) read(buf *BytePacketBuffer) error {
	h.ID = buf.readUint16()

	flags := buf.readUint16()
	a := byte(flags >> 8)
	b := byte(flags & 0x00FF)

	h.QR = ((a & 0x80) == 0x80)
	h.OpCode = ((a >> 3) & 0x0F)
	h.AA = ((a & 0x04) == 0x04)
	h.TC = ((a & 0x02) == 0x02)
	h.RD = ((a & 0x01) == 0x01)

	h.RA = ((b & 0x80) == 0x80)
	h.Z = ((b >> 4) & 0x07)

	rcode, err := ToResponseCode(b & 0x0F)
	if err != nil {
		buf.setErr(err)
	}
	h.RCode = rcode

	h.QDCount = buf.readUint16()
	h.ANCount = buf.readUint16()
	h.NSCount = buf.readUint16()
	h.ARCount = buf.readUint16()

	if err := buf.Err; err != nil {
		return fmt.Errorf("couldn't read header: %w", err)
	}
	return nil
}

type QueryType uint16

const (
	Unknown QueryType = iota
	A
)

func ToQueryType(val uint16) (QueryType, error) {
	switch QueryType(val) {
	case A:
		return QueryType(val), nil
	default:
		return Unknown, fmt.Errorf("unknown query type: %d", val)
	}
}

type DNSQuestion struct {
	Name  string
	QType QueryType
}

func (q *DNSQuestion) read(buf *BytePacketBuffer) error {
	name, err := buf.readQueryName()
	if err != nil {
		return fmt.Errorf("couldn't read question name: %w", err)
	}
	q.Name = name

	qtype, err := ToQueryType(buf.readUint16())
	if err != nil {
		buf.setErr(err)
		return fmt.Errorf("couldn't read question type: %w", err)
	}
	q.QType = qtype

	buf.readUint16() // class

	if err := buf.Err; err != nil {
		return fmt.Errorf("couldn't read question: %w", err)
	}
	return nil
}

type DNSRecord struct {
	// Common preamble
	Domain string
	Type   QueryType
	TTL    uint32
	Len    uint16

	// A
	Addr netip.Addr

	// Unknown
	RawData []byte
}

func main() {
	fmt.Println("bottom text")
}
