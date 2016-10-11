package service

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func echoConnection(conn net.Conn) error {
	if _, err := io.Copy(conn, conn); err != nil {
		fmt.Println(err.Error())
		return err
	}
	return nil
}

func TestMortalService(t *testing.T) {
	fmt.Println("- TestMortalService")
	network := "tcp"
	address := "127.0.0.1:5388"
	l := NewMortalService(network, address, echoConnection)
	defer l.Stop()
	go l.Start()

	time.Sleep(time.Second)

	// In this test, we start 10 clients, each making a single connection
	// to the server. Then each will write 10 messages to the server, and
	// read the same 10 messages back. After that the client quits.
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() {
				fmt.Printf("Quiting client #%d", id)
			}()

			conn, err := net.Dial("tcp", "127.0.0.1:5388")
			if err != nil {
				fmt.Println(err.Error())
				return
			}
			defer conn.Close()

			for i := 0; i < 10; i++ {
				fmt.Fprintf(conn, "client #%d, count %d\n", id, i)
				res, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err.Error())
					return
				}
				fmt.Printf("Received: %s", res)
				time.Sleep(100 * time.Millisecond)
			}
		}(i)
	}

	// We sleep for a couple of seconds, let the clients run their jobs,
	// then we exit, which triggers the defer function that will shutdown
	// the server.
	time.Sleep(2 * time.Second)
}
