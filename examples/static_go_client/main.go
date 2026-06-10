package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: static_go_client HOST:PORT")
		os.Exit(2)
	}
	conn, err := net.DialTimeout("tcp", os.Args[1], 3*time.Second)
	if err != nil {
		fmt.Printf("connect failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Println("connect succeeds")
}
