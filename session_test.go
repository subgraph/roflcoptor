package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/subgraph/go-procsnitch"
	"github.com/yawning/bulb"
)

type MockProcInfo struct {
	procInfo *procsnitch.Info
}

func NewMockProcInfo(procInfo *procsnitch.Info) MockProcInfo {
	p := MockProcInfo{
		procInfo: procInfo,
	}
	return p
}

func (r MockProcInfo) Set(procInfo *procsnitch.Info) {
	r.procInfo = procInfo
}

func (r MockProcInfo) LookupTCPSocketProcess(srcPort uint16, dstAddr net.IP, dstPort uint16) *procsnitch.Info {
	return r.procInfo
}

func (r MockProcInfo) LookupUNIXSocketProcess(socketFile string) *procsnitch.Info {
	info := procsnitch.Info{
		UID:       1,
		Pid:       1,
		ParentPid: 1,
		ExePath:   "/usr/local/bin/ricochet",
		CmdLine:   "testing_cmd_line",
	}
	return &info
}

type AccumulatingListener struct {
	net, address string
	buffer       bytes.Buffer
}

func NewAccumulatingListener(net, address string) *AccumulatingListener {
	l := AccumulatingListener{
		net:     net,
		address: address,
	}
	return &l
}

func (a *AccumulatingListener) AcceptLoop() {
	listener, err := net.Listen(a.net, a.address)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}

		go a.SessionWorker(conn)
	}

}

func (a *AccumulatingListener) SessionWorker(conn net.Conn) {
	for {
		connReader := bufio.NewReader(conn)
		line, err := connReader.ReadBytes('\n')
		if err != nil {
			panic(err)
		}
		lineStr := strings.TrimSpace(string(line))
		a.buffer.WriteString(lineStr + "\n")

		if string(lineStr) == "PROTOCOLINFO" {
			conn.Write([]byte(`250-PROTOCOLINFO 1
250-AUTH METHODS=NULL
250-VERSION Tor="0.2.7.6"
250 OK` + "\n"))
		} else {
			conn.Write([]byte("250 OK\r\n"))
		}
	}
}

func TestProxyListenerSession(t *testing.T) {
	var err error
	listeners := []AddrString{
		{
			Net:     "tcp",
			Address: "127.0.0.1:4356",
		},
	}
	config := RoflcoptorConfig{
		LogFile:           "-",
		FiltersPath:       "./filters",
		Listeners:         listeners,
		TorControlNet:     "unix",
		TorControlAddress: "tor_control",
	}

	policyList := NewPolicyList()
	if err = policyList.LoadFilters(config.FiltersPath); err != nil {
		panic(fmt.Sprintf("Unable to load filters: %s\n", err))
	}

	watch := false

	accListener := NewAccumulatingListener(config.TorControlNet, config.TorControlAddress)
	go accListener.AcceptLoop()
	proxyListener := NewProxyListener(&config, watch)
	ricochetProcInfo := procsnitch.Info{
		UID:       1,
		Pid:       1,
		ParentPid: 1,
		ExePath:   "/usr/local/bin/ricochet",
		CmdLine:   "testing_cmd_line",
	}
	proxyListener.procInfo = NewMockProcInfo(&ricochetProcInfo)
	proxyListener.StartListeners()

	// test legit connection from ricochet
	var proxyConn *bulb.Conn
	proxyConn, err = bulb.Dial("tcp", "127.0.0.1:4356")
	if err != nil {
		t.Errorf("Failed to connect to tor control port: %v", err)
		t.Fail()
	}
	defer proxyConn.Close()
	proxyConn.Debug(true)
	defer os.Remove(config.TorControlAddress)

	err = proxyConn.Authenticate("")
	if err != nil {
		panic(err)
	}

	fmt.Printf("acc -%s-\n", accListener.buffer.String())
	if accListener.buffer.String() != "PROTOCOLINFO\nAUTHENTICATE\nPROTOCOLINFO\nAUTHENTICATE\n" {
		t.Errorf("accumulated control commands don't match", err)
		t.Fail()
	}

	// test auth failure from non policy connection exec path
	failProcInfo := procsnitch.Info{
		UID:       1,
		Pid:       1,
		ParentPid: 1,
		ExePath:   "/usr/bin/false",
		CmdLine:   "123456789101112",
	}
	proxyListener.procInfo = NewMockProcInfo(&failProcInfo)

	var proxyConn2 *bulb.Conn
	proxyConn2, err = bulb.Dial("tcp", "127.0.0.1:4356")
	if err != nil {
		t.Errorf("Failed to connect to tor control port: %v", err)
		t.Fail()
	}
	defer proxyConn2.Close()
	proxyConn2.Debug(true)
	defer os.Remove(config.TorControlAddress)

	err = proxyConn2.Authenticate("")
	if err == nil {
		t.Error("did not receive auth error")
		t.Fail()
	}
	if fmt.Sprintf("%s", err) != "510 Unrecognized command: Tor Control proxy connection denied." {
		t.Errorf("err string not match")
		t.Fail()
	}

	var proxyAuthConn *bulb.Conn
	proxyAuthConn, err = bulb.Dial("tcp", "127.0.0.1:6651")
	if err != nil {
		t.Errorf("Failed to connect to tor control port: %v", err)
		t.Fail()
	}
	defer proxyAuthConn.Close()
	proxyAuthConn.Debug(true)
	err = proxyAuthConn.Authenticate("")
	if err == nil {
		t.Errorf("expected an authentication error")
		t.Fail()
	}
	if fmt.Sprintf("%s", err) != "510 Unrecognized command: Tor Control proxy connection denied." {
		t.Errorf("err string not match")
		t.Fail()
	}

	proxyListener.StopListeners()
}

func echoConnection(conn net.Conn) error {
	if _, err := io.Copy(conn, conn); err != nil {
		log.Println(err.Error())
		return err
	}
	return nil
}

func TestMortalListener(t *testing.T) {
	network := "tcp"
	address := "127.0.0.1:5388"
	l := NewMortalListener(network, address, echoConnection)
	defer l.Stop()
	go l.Start()

	time.Sleep(time.Second)

	// In this test, we start 10 clients, each making a single connection
	// to the server. Then each will write 10 messages to the server, and
	// read the same 10 messages back. After that the client quits.
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() {
				log.Printf("Quiting client #%d", id)
			}()

			conn, err := net.Dial("tcp", "127.0.0.1:5388")
			if err != nil {
				log.Println(err.Error())
				return
			}
			defer conn.Close()

			for i := 0; i < 10; i++ {
				fmt.Fprintf(conn, "client #%d, count %d\n", id, i)
				res, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					log.Println(err.Error())
					return
				}
				log.Printf("Received: %s", res)
				time.Sleep(100 * time.Millisecond)
			}
		}(i)
	}

	// We sleep for a couple of seconds, let the clients run their jobs,
	// then we exit, which triggers the defer function that will shutdown
	// the server.
	time.Sleep(2 * time.Second)
}
