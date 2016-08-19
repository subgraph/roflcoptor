package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/subgraph/go-procsnitch"
	"github.com/subgraph/procsnitchd/service"
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
	return r.procInfo
}

func (r MockProcInfo) LookupUDPSocketProcess(srcPort uint16) *procsnitch.Info {
	return r.procInfo
}

type AccumulatingListener struct {
	net, address    string
	buffer          bytes.Buffer
	mortalService   *service.MortalService
	hasProtocolInfo bool
	hasAuthenticate bool
}

func NewAccumulatingListener(net, address string) *AccumulatingListener {
	l := AccumulatingListener{
		net:             net,
		address:         address,
		hasProtocolInfo: true,
		hasAuthenticate: true,
	}
	return &l
}

func (a *AccumulatingListener) Start() {
	a.mortalService = service.NewMortalService(a.net, a.address, a.SessionWorker)
	err := a.mortalService.Start()
	if err != nil {
		panic(err)
	}
}

func (a *AccumulatingListener) Stop() {
	fmt.Println("AccumulatingListener STOP")
	a.mortalService.Stop()
}

func (a *AccumulatingListener) SessionWorker(conn net.Conn) error {
	connReader := bufio.NewReader(conn)
	for {

		line, err := connReader.ReadBytes('\n')
		if err != nil {
			//fmt.Println("AccumulatingListener read error:", err)
		}
		lineStr := strings.TrimSpace(string(line))
		a.buffer.WriteString(lineStr + "\n")

		if string(lineStr) == "PROTOCOLINFO" {
			if a.hasProtocolInfo {
				conn.Write([]byte(`250-PROTOCOLINFO 1
250-AUTH METHODS=NULL
250-VERSION Tor="0.2.7.6"
250 OK` + "\n"))
			} else {
				conn.Write([]byte("510 PROTOCOLINFO denied.\r\n"))
			}
		} else if string(lineStr) == "AUTHENTICATE" {
			if a.hasAuthenticate {
				conn.Write([]byte("250 OK\r\n"))
			} else {
				conn.Write([]byte("510 PROTOCOLINFO denied.\r\n"))
			}
		} else {
			conn.Write([]byte("250 OK\r\n"))
		}
	}
	return nil
}

func setupFakeProxyAndTorService(proxyNet, proxyAddress string, procInfo procsnitch.ProcInfo) (*AccumulatingListener, *ProxyListener) {
	listeners := []AddrString{
		{
			Net:     proxyNet,
			Address: proxyAddress,
		},
	}
	config := RoflcoptorConfig{
		ProcSnitchSocketFile: "-",
		FiltersPath:          "./examples/filters",
		Listeners:            listeners,
		TorControlNet:        "unix",
		TorControlAddress:    "test_tor_socket",
	}
	fakeTorService := NewAccumulatingListener(config.TorControlNet, config.TorControlAddress)
	fakeTorService.Start()
	watch := false
	proxyListener := NewProxyListener(&config, watch, procInfo)
	proxyListener.StartListeners()
	fmt.Println("started listeners for testing")
	return fakeTorService, proxyListener
}

func TestGetNilFilterPolicy(t *testing.T) {
	fmt.Println("- TestGetNilFilterPolicy")
	proxyNet := "tcp"
	proxyAddress := "127.0.0.1:4492"

	fakeTorService, proxyService := setupFakeProxyAndTorService(proxyNet, proxyAddress, NewMockProcInfo(nil))
	defer fakeTorService.Stop()
	defer proxyService.StopListeners()

	clientConn, err := bulb.Dial(proxyNet, proxyAddress)
	defer clientConn.Close()
	if err != nil {
		panic(err)
	}
	clientConn.Debug(true)
	err = clientConn.Authenticate("")
	if err == nil {
		t.Error("expected failure")
		t.Fail()
	}

}

func TestGetFilterPolicyFromExecPath(t *testing.T) {
	fmt.Println("- TestGetFilterPolicyFromExecPath")
	proxyNet := "tcp"
	proxyAddress := "127.0.0.1:4491"
	ricochetProcInfo := procsnitch.Info{
		UID:       1,
		Pid:       1,
		ParentPid: 1,
		ExePath:   "/usr/local/bin/ricochet",
		CmdLine:   "testing_cmd_line",
	}
	fakeTorService, proxyService := setupFakeProxyAndTorService(proxyNet, proxyAddress, NewMockProcInfo(&ricochetProcInfo))
	defer fakeTorService.Stop()
	defer proxyService.StopListeners()

	clientConn, err := bulb.Dial(proxyNet, proxyAddress)
	defer clientConn.Close()
	if err != nil {
		panic(err)
	}
	clientConn.Debug(true)
	err = clientConn.Authenticate("")
	if err != nil {
		t.Errorf("client connect fail: %s\n", err)
		t.Fail()
	}
}

func TestGetMissingFilterPolicy(t *testing.T) {
	fmt.Println("- TestGetMissingFilterPolicy")
	proxyNet := "tcp"
	proxyAddress := "127.0.0.1:4493"
	ricochetProcInfo := procsnitch.Info{
		UID:       1,
		Pid:       1,
		ParentPid: 1,
		ExePath:   "/usr/bin/false",
		CmdLine:   "meow",
	}
	fakeTorService, proxyService := setupFakeProxyAndTorService(proxyNet, proxyAddress, NewMockProcInfo(&ricochetProcInfo))
	defer fakeTorService.Stop()
	defer proxyService.StopListeners()

	clientConn, err := bulb.Dial(proxyNet, proxyAddress)
	defer clientConn.Close()
	if err != nil {
		panic(err)
	}
	clientConn.Debug(true)
	err = clientConn.Authenticate("")
	if err == nil {
		t.Errorf("expected failure due to missing filter policy")
		t.Fail()
	}
}

func TestProxyAuthListenerSession(t *testing.T) {
	fmt.Println("- TestProxyAuthListenerSession")
	var err error

	proxyNet := "tcp"
	proxyAddress := "127.0.0.1:4491"
	ricochetProcInfo := procsnitch.Info{
		UID:       1,
		Pid:       1,
		ParentPid: 1,
		ExePath:   "/usr/local/bin/ricochet",
		CmdLine:   "testing_cmd_line",
	}
	fakeTorService, proxyService := setupFakeProxyAndTorService(proxyNet, proxyAddress, NewMockProcInfo(&ricochetProcInfo))
	defer fakeTorService.Stop()
	defer proxyService.StopListeners()

	var clientConn *bulb.Conn
	clientConn, err = bulb.Dial(proxyNet, proxyAddress)
	defer clientConn.Close()
	if err != nil {
		t.Errorf("Failed to connect to tor control port: %v", err)
		t.Fail()
	}
	clientConn.Debug(true)
	err = clientConn.Authenticate("")
	if err != nil {
		t.Errorf("authentication error: %s", err)
		t.Fail()
	}
}

func TestProxyListenerSession(t *testing.T) {
	var err error
	var clientConn *bulb.Conn
	var response *bulb.Response

	fmt.Println("- TestProxyListenerSession")

	proxyNet := "tcp"
	proxyAddress := "127.0.0.1:4491"
	ricochetProcInfo := procsnitch.Info{
		UID:       1,
		Pid:       1,
		ParentPid: 1,
		ExePath:   "/usr/local/bin/ricochet",
		CmdLine:   "testing_cmd_line",
	}
	fakeTorService, proxyService := setupFakeProxyAndTorService(proxyNet, proxyAddress, NewMockProcInfo(&ricochetProcInfo))
	defer proxyService.StopListeners()
	defer fakeTorService.Stop()
	// test legit connection from ricochet

	clientConn, err = bulb.Dial(proxyNet, proxyAddress)
	defer clientConn.Close()

	if err != nil {
		t.Errorf("Failed to connect to tor control port: %v", err)
		t.Fail()
	}

	//clientConn.Debug(true)
	clientConn.StartAsyncReader()

	//defer os.Remove(config.TorControlAddress)

	err = clientConn.Authenticate("")
	if err != nil {
		t.Errorf("tor control port proxy auth fail: %v", err)
		t.Fail()
	}

	response, err = clientConn.Request("ADD_ONION NEW:BEST Port=4491,80\r\n")
	if err != nil || !response.IsOk() {
		t.Errorf("ADD_ONION fail: %v", err)
		t.Fail()
	}

	response, err = clientConn.Request("ADD_ONION NEW:BEST Port=4491\r\n")
	fmt.Println("response is ", response)
	/* XXX fix me
	if response.IsOk() && err == nil {
		t.Error("ADD_ONION fail should have failed because target was control port")
		t.Fail()
	}
	*/
	want := "PROTOCOLINFO\nAUTHENTICATE\nADD_ONION NEW:BEST Port=4491,80\n"
	if fakeTorService.buffer.String() != want {
		t.Errorf("accumulated control commands don't match: got:\n%s\n\nbut expected:\n%s", fakeTorService.buffer.String(), want)
		t.Fail()
	}
}

func TestProxyListenerWatchModeSession(t *testing.T) {
	fmt.Println("TestProxyListenerWatchModeSession")
	var err error
	proxyNet := "tcp"
	proxyAddress := "127.0.0.1:4491"

	listeners := []AddrString{
		{
			Net:     proxyNet,
			Address: proxyAddress,
		},
	}
	config := RoflcoptorConfig{
		ProcSnitchSocketFile: "-",
		FiltersPath:          "./filters",
		Listeners:            listeners,
		TorControlNet:        "unix",
		TorControlAddress:    "test_tor_socket",
	}
	fakeTorService := NewAccumulatingListener(config.TorControlNet, config.TorControlAddress)
	fakeTorService.Start()

	watch := true
	ricochetProcInfo := procsnitch.Info{
		UID:       1,
		Pid:       1,
		ParentPid: 1,
		ExePath:   "/usr/local/bin/ricochet",
		CmdLine:   "testing_cmd_line",
	}
	procInfo := NewMockProcInfo(&ricochetProcInfo)
	proxyService := NewProxyListener(&config, watch, procInfo)
	defer fakeTorService.Stop()

	proxyService.StartListeners()
	defer proxyService.StopListeners()

	// test legit connection from ricochet
	var clientConn *bulb.Conn
	clientConn, err = bulb.Dial(proxyNet, proxyAddress)
	defer clientConn.Close()

	if err != nil {
		t.Errorf("Failed to connect to tor control port: %v", err)
		t.Fail()
	}

	clientConn.Debug(true)
	//defer os.Remove(config.TorControlAddress)

	err = clientConn.Authenticate("")
	if err != nil {
		panic(err)
	}

	want := "PROTOCOLINFO\nAUTHENTICATE\n"
	if fakeTorService.buffer.String() != want {
		t.Errorf("accumulated control commands don't match: got:\n%s\n\nbut expected:\n%s", fakeTorService.buffer.String(), want)
		t.Fail()
	}
}

func TestUnixSocketListener(t *testing.T) {
	fmt.Println("TestUnixSocketListener")
	var err error
	proxyNet := "unix"
	proxyAddress := "testing123_socket"
	ricochetProcInfo := procsnitch.Info{
		UID:       1,
		Pid:       1,
		ParentPid: 1,
		ExePath:   "/usr/local/bin/ricochet",
		CmdLine:   "testing_cmd_line",
	}
	fakeTorService, proxyService := setupFakeProxyAndTorService(proxyNet, proxyAddress, NewMockProcInfo(&ricochetProcInfo))
	defer fakeTorService.Stop()
	defer proxyService.StopListeners()

	var clientConn *bulb.Conn
	clientConn, err = bulb.Dial(proxyNet, proxyAddress)
	defer clientConn.Close()
	if err != nil {
		t.Errorf("Failed to connect to tor control port: %v", err)
		t.Fail()
	}
	clientConn.Debug(true)
	err = clientConn.Authenticate("")
	if err != nil {
		t.Errorf("authentication error")
		t.Fail()
	}
}

func TestBadAddressTorControlPort(t *testing.T) {
	fmt.Println("TestBadAddressTorControlPort")
	var conn net.Conn
	torControlNet := "unix"
	torControlAddress := "123"
	denyOnions := []AddrString{}
	procInfo := procsnitch.Info{
		UID:       1,
		Pid:       1,
		ParentPid: 1,
		ExePath:   "/usr/local/bin/ricochet",
		CmdLine:   "testing_cmd_line",
	}
	mockProcInfo := NewMockProcInfo(&procInfo)
	policy := &SievePolicyJSONConfig{}
	session := NewAuthProxySession(conn, torControlNet, torControlAddress, denyOnions, false, mockProcInfo, policy)

	err := session.initTorControl()
	if err == nil {
		t.Errorf("expected failure")
		t.Fail()
	}
}

func TestNoProtocolInfoTorControlPort(t *testing.T) {
	fmt.Println("TestNoProtocolInfoTorControlPort")
	listeners := []AddrString{
		{
			Net:     "unix",
			Address: "proxy_socket",
		},
	}
	config := RoflcoptorConfig{
		ProcSnitchSocketFile: "-",
		FiltersPath:          "./filters",
		Listeners:            listeners,
		TorControlNet:        "unix",
		TorControlAddress:    "test_tor_socket",
	}
	fakeTorService := NewAccumulatingListener(config.TorControlNet, config.TorControlAddress)
	fakeTorService.hasProtocolInfo = false
	fakeTorService.Start()
	defer fakeTorService.Stop()

	var conn net.Conn
	denyOnions := []AddrString{}
	procInfo := procsnitch.Info{
		UID:       1,
		Pid:       1,
		ParentPid: 1,
		ExePath:   "/usr/local/bin/ricochet",
		CmdLine:   "testing_cmd_line",
	}
	mockProcInfo := NewMockProcInfo(&procInfo)
	policy := &SievePolicyJSONConfig{}
	session := NewAuthProxySession(conn, config.TorControlNet, config.TorControlAddress, denyOnions, false, mockProcInfo, policy)
	err := session.initTorControl()
	if err == nil {
		t.Errorf("expected failure")
		t.Fail()
	}
	session.torConn.Close()
}

func TestNoAuthenticateTorControlPort(t *testing.T) {
	fmt.Println("TestNoAuthenticateTorControlPort")
	listeners := []AddrString{
		{
			Net:     "unix",
			Address: "proxy_socket",
		},
	}
	config := RoflcoptorConfig{
		ProcSnitchSocketFile: "-",
		FiltersPath:          "./filters",
		Listeners:            listeners,
		TorControlNet:        "unix",
		TorControlAddress:    "test_tor_socket",
	}
	fakeTorService := NewAccumulatingListener(config.TorControlNet, config.TorControlAddress)
	fakeTorService.hasAuthenticate = false
	fakeTorService.Start()
	defer fakeTorService.Stop()

	var conn net.Conn
	denyOnions := []AddrString{}
	procInfo := procsnitch.Info{
		UID:       1,
		Pid:       1,
		ParentPid: 1,
		ExePath:   "/usr/local/bin/ricochet",
		CmdLine:   "testing_cmd_line",
	}
	mockProcInfo := NewMockProcInfo(&procInfo)
	policy := &SievePolicyJSONConfig{}
	session := NewAuthProxySession(conn, config.TorControlNet, config.TorControlAddress, denyOnions, false, mockProcInfo, policy)
	err := session.initTorControl()
	if err == nil {
		t.Errorf("expected failure")
		t.Fail()
	}
	session.torConn.Close()
}

func TestShouldAllowOnion(t *testing.T) {
	fmt.Println("TestShouldAllowOnion")
	var conn net.Conn
	denyOnions := []AddrString{
		{"unix", "/var/run/tor/control"},
		{"tcp", "127.0.0.1:9051"},
	}
	procInfo := procsnitch.Info{}
	mockProcInfo := NewMockProcInfo(&procInfo)
	policy := &SievePolicyJSONConfig{}
	session := NewAuthProxySession(conn, "meownew", "meowaddr", denyOnions, false, mockProcInfo, policy)

	tests := []struct {
		in   string
		want bool
	}{
		{"meow", true},
		{"", true},
		{"ADD_ONION NEW:BEST Port=80,127.0.0.1:9051", false},
		{"ADD_ONION NEW:BEST Port=80,unix:/var/run/tor/control", false},
		{"ADD_ONION NEW:BEST Port=80", true},
		{"ADD_ONION NEW:BEST Port=9051", false},
		{"ADD_ONION NEW:BEST Port=80,80", true},
		{"ADD_ONION NEW:BEST Port=9051,9051", false},
		{"ADD_ONION NEW:BEST Port=80,9051", false},
		{"ADD_ONION NEW:BEST Port=9051,80", true},
	}

	for _, test := range tests {
		isAllowed := session.shouldAllowOnion(test.in)
		if isAllowed != test.want {
			t.Errorf("test fail; command: %s wanted: %v but got %v", test.in, test.want, isAllowed)
			t.Fail()
		}
	}
}
