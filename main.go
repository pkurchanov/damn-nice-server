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
}

// Step forward a given number of steps
func (buf *BytePacketBuffer) step(steps uint) error {
	newPos := buf.Pos + steps
	if newPos > 511 {
		return fmt.Errorf("Overstepped buffer by %d bytes.", newPos-511)
	}
	buf.Pos = newPos
	return nil
}

// Seek to a given position
func (buf *BytePacketBuffer) seek(pos uint) error {
	if pos > 511 {
		return fmt.Errorf("Oversought buffer by %d bytes.", pos-511)
	}
	buf.Pos = pos
	return nil
}

// Read a single byte and step forward
func (buf *BytePacketBuffer) read() (uint8, error) {
	if buf.Pos > 511 {
		return 0, fmt.Errorf("End of buffer.")
	}
	res := buf.Buf[buf.Pos]
	buf.Pos++
	return res, nil
}

// Get a single byte without changing position
func (buf *BytePacketBuffer) get(pos uint) (uint8, error) {
	if pos > 511 {
		return 0, fmt.Errorf("End of buffer.")
	}
	return buf.Buf[pos], nil
}

// Get a range of bytes
func (buf *BytePacketBuffer) getRange(start uint, len uint) ([]uint8, error) {
	end := start + len
	if end > 511 {
		return nil, fmt.Errorf("End of buffer.")
	}
	return buf.Buf[start:end], nil
}

// Read a two-byte number
func (buf *BytePacketBuffer) readUint16() (uint16, error) {
	firstByte, err := buf.read()
	if err != nil {
		return 0, fmt.Errorf("Couldn't read u16 1/2: %w", err)
	}
	secondByte, err := buf.read()
	if err != nil {
		return 0, fmt.Errorf("Couldn't read u16 2/2: %w", err)
	}
	return uint16(firstByte)<<8 | uint16(secondByte), nil
}

// Read four-byte number
func (buf *BytePacketBuffer) readUint32() (uint32, error) {
	firstByte, err := buf.read()
	if err != nil {
		return 0, fmt.Errorf("Couldn't read u32 1/4: %w", err)
	}
	secondByte, err := buf.read()
	if err != nil {
		return 0, fmt.Errorf("Couldn't read u32 2/4: %w", err)
	}
	thirdByte, err := buf.read()
	if err != nil {
		return 0, fmt.Errorf("Couldn't read u32 3/4: %w", err)
	}
	fourthByte, err := buf.read()
	if err != nil {
		return 0, fmt.Errorf("Couldn't read u32 4/4: %w", err)
	}
	return uint32(firstByte)<<24 |
			uint32(secondByte)<<16 |
			uint32(thirdByte)<<8 |
			uint32(fourthByte),
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
		// I don't think you should reasonably need more than 3, for that matter
		if jumpsPerformed > 5 {
			return fmt.Errorf("Jump limit of %d exceeded.", maxJumps)
		}

		// At this point we're looking at the length byte of some label
		len, err := buf.get(pos)
		if err != nil {
			return fmt.Errorf("Couldn't read label: %w", err)
		}

		// Two MSB set <=> jump to the offset given by the remaining 6+8=14 bits
		if (len & 0xC0) == 0xC0 {
			if !jumped {
				buf.seek(pos + 2)
			}

			b2, err := buf.get(pos + 1)
			if err != nil {
				return fmt.Errorf("Couldn't read lower byte of jump label: %w", err)
			}
			offset := ((uint16(len) ^ 0xC0) << 8) | uint16(b2)
			pos = uint(offset)

			jumped = true
			jumpsPerformed++

			continue
		} else {
			// Otherwise we're looking at a regular label
			pos++

			// Zero-length label <=> end of domain name
			if len == 0 {
				break
			}

			*outstr += delim
			strBuf, err := buf.getRange(pos, uint(len))
			if err != nil {
				return fmt.Errorf("Couldn't get byte range from domain name: %w", err)
			}
			// Might explore alternatives to plain old type casting later
			*outstr += strings.ToLower(string(strBuf))
			delim = "."

			// Move on to the next label
			pos += uint(len)
		}
	}
	if !jumped {
		err := buf.seek(pos)
		if err != nil {
			return fmt.Errorf("Couldn't seek to end of domain name: %w", err)
		}
	}
	return nil
}

// Go has a pretty cool way of expressing the idea of an enum.
type ResponseCode uint8

const (
	NOERROR = iota
	FORMERR
	SERVFAIL
	NXDOMAIN
	NOTIMP
	REFUSED
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

// Go also has a pretty cool way of handling errors, I've just...
// gotta step back and let it steep for a moment.
func (hdr *DNSHeader) read(buf *BytePacketBuffer) error {
	hdr.id, err = buf.readUint16()
	if err != nil {
		return fmt.Errorf("Couldn't read id from buffer: %w", err)
	}
}

func main() {
	fmt.Println("bottom text")
}
