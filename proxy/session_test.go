package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/subgraph/roflcoptor/common"
	"github.com/subgraph/roflcoptor/filter"
	"github.com/subgraph/roflcoptor/service"
	"github.com/yawning/bulb"
)

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

func setupProxyTest(proxyNet, proxyAddress string) (*ProxyListener, *AccumulatingListener) {
	filterContent := string(`
{
    "AuthNetAddr" : "%s",
    "AuthAddr" : "%s",
    "client-allowed" : ["SETEVENTS SIGNAL CONF_CHANGED",
			"GETCONF __owningcontrollerprocess",
			"GETINFO version",
			"SETEVENTS SIGNAL HS_DESC CONF_CHANGED",
			"GETCONF DisableNetwork",
			"SETEVENTS STATUS_CLIENT",
			"GETINFO status/circuit-established status/bootstrap-phase net/listeners/socks"
		       ],
    "client-allowed-prefixes" : ["ADD_ONION", "DEL_ONION"],
    "client-replacements" : {},
    "client-replacement-prefixes" : {},
    "server-allowed" : ["250 OK",
		       "250 __OwningControllerProcess",
			"650 STATUS_CLIENT NOTICE CONSENSUS_ARRIVED", "550 Onion address collision", "650 STATUS_CLIENT NOTICE CIRCUIT_ESTABLISHED"],
    "server-allowed-prefixes" : ["250-ServiceID=", "250-VERSION","250-version",
				 "250-PrivateKey=", "650 STREAM",
				"650 HS_DESC", "250 DisableNetwork=","250-status/circuit-established=1", "650 STATUS_CLIENT NOTICE CIRCUIT_NOT_ESTABLISHED"],
    "server-replacement-prefixes" : {},
    "request-oz-onion-forwarder": false
}`)
	filterContent = fmt.Sprintf(filterContent, proxyNet, proxyAddress)
	filterDir, err := ioutil.TempDir("", "filter_load_test")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(filterDir)
	filterFile := filepath.Join(filterDir, "valid_app_filter.json")
	if err := ioutil.WriteFile(filterFile, []byte(filterContent), 0666); err != nil {
		panic(err)
	}

	config := common.RoflcoptorConfig{
		FiltersPath:       filterDir,
		TorControlNet:     "unix",
		TorControlAddress: "test_tor_socket",
	}
	fakeTorService := NewAccumulatingListener(config.TorControlNet, config.TorControlAddress)
	fakeTorService.Start()

	proxyListener := NewProxyListener(&config, false)
	proxyListener.StartListeners()
	return proxyListener, fakeTorService
}

func TestProxyListenerSession(t *testing.T) {
	var err error
	var clientConn *bulb.Conn
	var response *bulb.Response
	fmt.Println("- TestProxyListenerSession")

	proxyNet := "tcp"
	proxyAddress := "127.0.0.1:4491"
	proxyListener, fakeTorService := setupProxyTest(proxyNet, proxyAddress)
	defer proxyListener.StopListeners()
	defer fakeTorService.Stop()

	clientConn, err = bulb.Dial(proxyNet, proxyAddress)
	defer clientConn.Close()

	if err != nil {
		t.Errorf("Failed to connect to tor control port: %v", err)
		t.Fail()
	}

	clientConn.Debug(true)
	clientConn.StartAsyncReader()
	err = clientConn.Authenticate("")
	if err != nil {
		t.Errorf("tor control port proxy auth fail: %v", err)
		t.Fail()
	}

	response, err = clientConn.Request("ADD_ONION NEW:BEST Port=80,4491")
	if err == nil || response.IsOk() {
		t.Errorf("ADD_ONION should have failed: %v", err)
		t.Fail()
	}

	response, err = clientConn.Request("ADD_ONION NEW:BEST Port=4491")
	fmt.Println("response is ", response)
	if err == nil || response.IsOk() {
		t.Error("yo ADD_ONION fail should have failed because target was control port")
		t.Fail()
	}

	want := "PROTOCOLINFO\nAUTHENTICATE\n"
	if fakeTorService.buffer.String() != want {
		t.Errorf("accumulated control commands don't match: got:\n%s\n\nbut expected:\n%s", fakeTorService.buffer.String(), want)
		t.Fail()
	}
	response, err = clientConn.Request("ADD_ONION NEW:BEST Port=3391")
	fmt.Println("response is ", response)
	if !response.IsOk() {
		t.Error("ADD_ONION failed")
		t.Fail()
	}
	want = "PROTOCOLINFO\nAUTHENTICATE\nADD_ONION NEW:BEST Port=3391\n"
	if fakeTorService.buffer.String() != want {
		t.Errorf("accumulated control commands don't match: got:\n%s\n\nbut expected:\n%s", fakeTorService.buffer.String(), want)
		t.Fail()
	}

	response, err = clientConn.Request("ADD_ONION NEW:BEST Port=4491,80")
	if err != nil || !response.IsOk() {
		t.Errorf("ADD_ONION failed")
		t.Fail()
	}
	want = "PROTOCOLINFO\nAUTHENTICATE\nADD_ONION NEW:BEST Port=3391\nADD_ONION NEW:BEST Port=4491,80\n"
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
	proxyListener, fakeTorService := setupProxyTest(proxyNet, proxyAddress)
	defer proxyListener.StopListeners()
	defer fakeTorService.Stop()
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
	var clientConn *bulb.Conn

	proxyNet := "unix"
	proxyAddress := "ricochet.socket"

	proxyListener, fakeTorService := setupProxyTest(proxyNet, proxyAddress)
	defer proxyListener.StopListeners()
	defer fakeTorService.Stop()
	// as defined in test_filters/ricochet.json

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
	denyOnions := []common.AddrString{}
	policy := &filter.SievePolicyJSONConfig{}
	session := NewAuthProxySession(conn, torControlNet, torControlAddress, denyOnions, false, policy)

	err := session.initTorControl()
	if err == nil {
		t.Errorf("expected failure")
		t.Fail()
	}
}

func TestNoProtocolInfoTorControlPort(t *testing.T) {
	fmt.Println("TestNoProtocolInfoTorControlPort")
	config := common.RoflcoptorConfig{
		FiltersPath:       "./filters",
		TorControlNet:     "unix",
		TorControlAddress: "test_tor_socket",
	}
	fakeTorService := NewAccumulatingListener(config.TorControlNet, config.TorControlAddress)
	fakeTorService.hasProtocolInfo = false
	fakeTorService.Start()
	defer fakeTorService.Stop()

	var conn net.Conn
	denyOnions := []common.AddrString{}
	policy := &filter.SievePolicyJSONConfig{}
	session := NewAuthProxySession(conn, config.TorControlNet, config.TorControlAddress, denyOnions, false, policy)
	err := session.initTorControl()
	if err == nil {
		t.Errorf("expected failure")
		t.Fail()
	}
	session.torConn.Close()
}

func TestNoAuthenticateTorControlPort(t *testing.T) {
	fmt.Println("TestNoAuthenticateTorControlPort")
	config := common.RoflcoptorConfig{
		FiltersPath:       "./filters",
		TorControlNet:     "unix",
		TorControlAddress: "test_tor_socket",
	}
	fakeTorService := NewAccumulatingListener(config.TorControlNet, config.TorControlAddress)
	fakeTorService.hasAuthenticate = false
	fakeTorService.Start()
	defer fakeTorService.Stop()

	var conn net.Conn
	denyOnions := []common.AddrString{}
	policy := &filter.SievePolicyJSONConfig{}
	session := NewAuthProxySession(conn, config.TorControlNet, config.TorControlAddress, denyOnions, false, policy)
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
	denyOnions := []common.AddrString{
		{"unix", "/var/run/tor/control"},
		{"tcp", "127.0.0.1:9051"},
	}
	policy := &filter.SievePolicyJSONConfig{}
	session := NewAuthProxySession(conn, "meownew", "meowaddr", denyOnions, false, policy)

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
