package main

import (
	"fmt"
	"strings"
)

// So here's a byte arr the size of a standard DNS packet
// and a way of keeping track of where we are. Shrimple.
type BytePacketBuffer struct {
	Buf [512]uint8
	Pos uint
	Err error
}

// Step forward a given number of steps
func (buf *BytePacketBuffer) step(steps uint) {
	if buf.Err != nil {
		return
	}
	newPos := buf.Pos + steps
	if newPos > 511 {
		buf.Err = fmt.Errorf("overstepped buffer by %d bytes", newPos-511)
		return
	}
	buf.Pos = newPos
	return
}

// Seek to a given position
func (buf *BytePacketBuffer) seek(pos uint) {
	if buf.Err != nil {
		return
	}
	if pos > 511 {
		buf.Err = fmt.Errorf("oversought buffer by %d bytes", pos-511)
		return
	}
	buf.Pos = pos
	return
}

// Read a single byte and step forward
func (buf *BytePacketBuffer) read() uint8 {
	if buf.Err != nil {
		return 0
	}
	if buf.Pos > 511 {
		buf.Err = fmt.Errorf("end of buffer")
		return 0
	}
	res := buf.Buf[buf.Pos]
	buf.Pos++
	return res
}

// Get a single byte without changing position
func (buf *BytePacketBuffer) get(pos uint) uint8 {
	if buf.Err != nil {
		return 0
	}
	if pos > 511 {
		buf.Err = fmt.Errorf("end of buffer")
		return 0
	}
	return buf.Buf[pos]
}

// Get a range of bytes
func (buf *BytePacketBuffer) getRange(start uint, len uint) []uint8 {
	if buf.Err != nil {
		return nil
	}
	end := start + len
	if end > 511 {
		buf.Err = fmt.Errorf("end of buffer")
		return nil
	}
	return buf.Buf[start:end]
}

// Read a two-byte number
func (buf *BytePacketBuffer) readUint16() (uint16, error) {
	b1 := buf.read()
	b2 := buf.read()
	if buf.Err != nil {
		return 0, fmt.Errorf("couldn't read u16: %w", buf.Err)
	}
	return uint16(b1)<<8 | uint16(b2), nil
}

// Read four-byte number
func (buf *BytePacketBuffer) readUint32() (uint32, error) {
	b1 := buf.read()
	b2 := buf.read()
	b3 := buf.read()
	b4 := buf.read()
	if buf.Err != nil {
		return 0, fmt.Errorf("couldn't read u32: %w", buf.Err)
	}
	return uint32(b1)<<24 |
			uint32(b2)<<16 |
			uint32(b3)<<8 |
			uint32(b4),
		nil
}

func (buf *BytePacketBuffer) readQueryName(outstr *string) error {
	// These are all meant to make dealing with jumps possible
	pos := buf.Pos
	jumped := false
	const maxJumps = 5
	jumpsPerformed := 0

	delim := ""
	for true {
		if jumpsPerformed > 3 {
			return fmt.Errorf("jump limit of %d exceeded", maxJumps)
		}

		// At this point we're looking at the length byte of some label
		length := buf.get(pos)

		// Two MSB set <=> jump to the offset given by the remaining 6+8=14 bits
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
		} else {
			// Otherwise we're looking at a regular label
			pos++

			// Zero-length label <=> end of domain name
			if length == 0 {
				break
			}

			*outstr += delim
			strBuf := buf.getRange(pos, uint(length))
			// Might explore alternatives to plain old type casting later
			*outstr += strings.ToLower(string(strBuf))
			delim = "."

			// Move on to the next label
			pos += uint(length)
		}
	}
	if !jumped {
		buf.seek(pos)
	}
	if buf.Err != nil {
		return fmt.Errorf("couldn't read query name: %w", buf.Err)
	}
	return nil
}

// Go has a pretty cool way of expressing the idea of an enum.
type ResponseCode uint8

const (
	NoError = iota
	FormErr
	ServFail
	NXDomain
	NotImp
	Refused
)

type DNSHeader struct {
	ID uint16

	QR     bool
	OPCODE uint8
	AA     bool
	TC     bool
	RD     bool
	RA     bool
	Z      uint8
	RCODE  ResponseCode

	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}

func (hdr *DNSHeader) read(buf *BytePacketBuffer) error {
	hdr.ID = buf.readUint16()

}

func main() {
	fmt.Println("bottom text")
}
