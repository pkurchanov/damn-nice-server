package main

import "fmt"

// So here's a byte arr the size of a standard DNS packet
// and a way of keeping track of where we are. Shrimple.
type BytePacketBuffer struct {
	buf [512]uint8
	pos uint
}

// Step forward a given number of steps
func (buf *BytePacketBuffer) step(steps uint) {
	buf.pos += steps
}

// Jump to a given position
func (buf *BytePacketBuffer) seek(pos uint) {
	buf.pos = pos
}

// Read a single byte and step forward
func (buf *BytePacketBuffer) read() (uint8, error) {
	if buf.pos > 511 {
		return 0, fmt.Errorf("end of buffer.")
	}
	res := buf.buf[buf.pos]
	buf.pos++
	return res, nil
}

// Get a single byte without changing position
func (buf *BytePacketBuffer) get() (uint8, error) {
	if buf.pos > 511 {
		return 0, fmt.Errorf("end of buffer.")
	}
	return buf.buf[buf.pos], nil
}

// Get a range of bytes
func (buf *BytePacketBuffer) getRange(start uint, len uint) ([]uint8, error) {
	end := start + len
	if end > 511 {
		return nil, fmt.Errorf("end of buffer.")
	}
	return buf.buf[start:end], nil
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

func main() {
	buffy := BytePacketBuffer{}
	buffy.buf[0] = 0xC0
	buffy.buf[1] = 0x0C
	buffy.buf[2] = 0x0D
	buffy.buf[3] = 0x0E

	num1, _ := buffy.readUint16()
	fmt.Println("first two bytes:", num1)

	buffy.seek(0)
	num2, _ := buffy.readUint32()
	fmt.Println("first four bytes:", num2)
}
