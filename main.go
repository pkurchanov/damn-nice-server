package main

import "fmt"

// So here's a byte arr the size of a standard DNS packet
// and a way of keeping track of where we are. Shrimple.
type BytePacketBuffer struct {
	buffer   [512]uint8
	position uint
}

// Step forward a given number of steps
func (buf *BytePacketBuffer) step(steps uint) {
	buf.position += steps
}

// Jump to a given position
func (buf *BytePacketBuffer) seek(pos uint) {
	buf.position = pos
}

// Read a single byte and step forward
func (buf *BytePacketBuffer) read() (uint8, error) {
	if buf.position > 511 {
		return 0, fmt.Errorf("end of buffer\n")
	}
	res := buf.buffer[buf.position]
	buf.position++
	return res, nil
}

// Get a single byte without changing position
func (buf *BytePacketBuffer) get(pos uint) (uint8, error) {
	if pos > 511 {
		return 0, fmt.Errorf("end of buffer\n")
	}
	return buf.buffer[pos], nil
}

// Get a range of bytes
func (buf *BytePacketBuffer) getRange(start uint, len uint) ([]uint8, error) {
	end := start + len
	if end > 511 {
		return nil, fmt.Errorf("end of buffer\n")
	}
	return buf.buffer[start:end], nil
}

// Read a two-byte number
func (buf *BytePacketBuffer) readUint16() (uint16, error) {
	firstByte, err := buf.read()
	if err != nil {
		return 0, fmt.Errorf("Couldn't read a u16 1/2: %s", err)
	}
	secondByte, err := buf.read()
	if err != nil {
		return 0, fmt.Errorf("Couldn't read a u16 2/2: %s", err)
	}
	return (uint16)(firstByte)<<8 | (uint16)(secondByte), nil
}

// Read a four-byte number
func (buf *BytePacketBuffer) readUint32() (uint32, error) {
	firstByte, err := buf.read()
	if err != nil {
		return 0, fmt.Errorf("Couldn't read a u32 1/4: %s", err)
	}
	secondByte, err := buf.read()
	if err != nil {
		return 0, fmt.Errorf("Couldn't read a u32 2/4: %s", err)
	}
	thirdByte, err := buf.read()
	if err != nil {
		return 0, fmt.Errorf("Couldn't read a u32 3/4: %s", err)
	}
	fourthByte, err := buf.read()
	if err != nil {
		return 0, fmt.Errorf("Couldn't read a u32 4/4: %s", err)
	}
	return (uint32)(firstByte)<<24 |
			(uint32)(secondByte)<<16 |
			(uint32)(thirdByte)<<8 |
			(uint32)(fourthByte),
		nil
}

func (buf *BytePacketBuffer) readQueryName(outstr *string) error {
	// These are all meant to make dealing with jumps possible
	pos := buf.position
	jumped := false
	const maxJumps = 5
	jumpsPerformed := 0

	delimiter := ""
	for true {
		// I don't think you should reasonably need more than 3, for that matter
		if jumpsPerformed > 5 {
			return fmt.Errorf("Jump limit of %d exceeded", maxJumps)
		}

		// At this point we're looking at the length byte of some label
		len, err := buf.get(pos)
		if err != nil {
			return fmt.Errorf("Couldn't read a label: %s", err)
		}

		// Two MSB set <=> jump to the offset given by the remaining 6+8=14 bits
		if (len & 0xC0) == 0xC0 {
			if !jumped {
				buf.seek(pos + 2)
			}

		}

	}
}

func main() {
	fmt.Println("bottom text")
}
