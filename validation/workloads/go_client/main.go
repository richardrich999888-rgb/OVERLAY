package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: static_go_client HOST:PORT PAYLOAD")
		os.Exit(2)
	}
	conn, err := net.DialTimeout("tcp", os.Args[1], 3*time.Second)
	if err != nil {
		fmt.Printf("connect failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		fmt.Printf("write failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("connect succeeds")
}
