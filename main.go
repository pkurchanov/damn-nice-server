package main

import "fmt"

// So here's a byte arr the size of a standard DNS packet
// and a way of keeping track of where we are. Shrimple.
type BytePacketBuffer struct {
	buf [512]uint8
	pos uint
}

func main() {
	// Missing fields will default to their zero values.
	buffy := BytePacketBuffer{}
	fmt.Println("default position:", buffy.pos)
	fmt.Println("first cell:", buffy.buf[0])
	fmt.Println("last cell:", buffy.buf[511])
}
