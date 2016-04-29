package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/subgraph/go-procsnitch"
	"github.com/yawning/bulb"
)

type MockProcInfo struct {
}

func (r MockProcInfo) LookupTCPSocketProcess(srcPort uint16, dstAddr net.IP, dstPort uint16) *procsnitch.Info {
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
	socketPath string
	buffer     bytes.Buffer
}

func NewAccumulatingListener(socketPath string) *AccumulatingListener {
	l := AccumulatingListener{
		socketPath: socketPath,
	}
	return &l
}

func (a *AccumulatingListener) AcceptLoop() {
	listener, err := net.Listen("unix", a.socketPath)
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
	config := RoflcoptorConfig{
		LogFile:              "-",
		FiltersPath:          "./filters",
		ListenTCPPort:        "4356",
		ListenIP:             "127.0.0.1",
		TorControlSocketPath: "tor_control",
	}

	if _, err = loadFilters(config.FiltersPath); err != nil {
		panic(fmt.Sprintf("Unable to load filters: %s\n", err))
	}

	wg := sync.WaitGroup{}
	watch := false

	accListener := NewAccumulatingListener(config.TorControlSocketPath)
	go accListener.AcceptLoop()

	proxyListener, err := NewProxyListener(&config, &wg, watch)
	if err != nil {
		t.Errorf("failed to create proxy listener: %s", err)
		t.Fail()
	}

	proxyListener.procInfo = MockProcInfo{}

	go proxyListener.FilterTCPAcceptLoop()

	var torConn *bulb.Conn
	torConn, err = bulb.Dial("tcp", "127.0.0.1:4356")
	if err != nil {
		t.Errorf("Failed to connect to tor control port: %v", err)
		t.Fail()
	}
	defer torConn.Close()
	torConn.Debug(true)
	defer os.Remove(config.TorControlSocketPath)

	err = torConn.Authenticate("")
	if err != nil {
		panic(err)
	}

	fmt.Printf("acc -%s-\n", accListener.buffer.String())
	if accListener.buffer.String() != "PROTOCOLINFO\nAUTHENTICATE\nPROTOCOLINFO\nAUTHENTICATE\n" {
		t.Errorf("accumulated control commands don't match", err)
		t.Fail()
	}
}
