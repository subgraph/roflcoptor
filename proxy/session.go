package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/op/go-logging"
	"github.com/subgraph/roflcoptor/common"
	"github.com/subgraph/roflcoptor/filter"
	"github.com/subgraph/roflcoptor/ozclient"
	"github.com/subgraph/roflcoptor/service"
	"github.com/yawning/bulb"
)

var log = logging.MustGetLogger("roflcoptor")

const (
	cmdProtocolInfo  = "PROTOCOLINFO"
	cmdAuthenticate  = "AUTHENTICATE"
	cmdAuthChallenge = "AUTHCHALLENGE"
	cmdQuit          = "QUIT"
	cmdGetInfo       = "GETINFO"
	cmdSignal        = "SIGNAL"

	responseOk = "250 OK\r\n"

	errAuthenticationRequired = "514 Authentication required\r\n"
	errUnrecognizedCommand    = "510 Unrecognized command\r\n"
)

// ProxyListener is used to listen for
// Tor Control port connections and
// dispatches them to worker sessions
// to implement the filtering proxy pipeline.
type ProxyListener struct {
	cfg            *common.RoflcoptorConfig
	watch          bool
	authedServices []*service.MortalService
	onionDenyAddrs []common.AddrString
	errChan        chan error
	policyList     filter.PolicyList
}

// NewProxyListener creates a new ProxyListener given
// a configuration structure.
func NewProxyListener(cfg *common.RoflcoptorConfig, watch bool) *ProxyListener {
	p := ProxyListener{
		cfg:        cfg,
		watch:      watch,
		policyList: filter.NewPolicyList(),
	}
	return &p
}

// StartListeners initialize all tor control port proxy listeners.
// - each listener will be associated with a specific filter policy
func (p *ProxyListener) StartListeners() {
	var err error

	log.Info("StartListeners")

	err = p.policyList.LoadFilters(p.cfg.FiltersPath)
	if err != nil {
		log.Criticalf("failed to load filter policy: %s", err)
		panic(fmt.Sprintf("failed to load filter policy: %s", err))
	}

	// compile a list of all control ports;
	// we black list them from being the onion target address
	p.compileOnionAddrBlacklist()
	p.initAuthenticatedListeners()
}

// StopListeners stops all the listeners
func (p *ProxyListener) StopListeners() {
	for _, service := range p.authedServices {
		service.Stop()
	}
}

func (p *ProxyListener) compileOnionAddrBlacklist() {
	p.onionDenyAddrs = p.policyList.GetListenerAddresses()
	p.onionDenyAddrs = append(p.onionDenyAddrs, common.AddrString{
		Net:     p.cfg.TorControlNet,
		Address: p.cfg.TorControlAddress,
	})
}

// InitAuthenticatedListeners runs each auth listener
// in it's own goroutine.
func (p *ProxyListener) initAuthenticatedListeners() {

	locations, err := p.policyList.GetAuthenticatedPolicyAddresses()
	if err != nil {
		log.Criticalf("ProxyListener.initAuthenticatedListeners failure: %s", err)
		panic(err)
	}

	for location, policy := range locations {
		copyPolicy := policy
		handleNewConnection := func(conn net.Conn) error {
			log.Debugf("connection received %s:%s -> %s:%s\n", conn.RemoteAddr().Network(),
				conn.RemoteAddr().String(), conn.LocalAddr().Network(), conn.LocalAddr().String())
			s := NewAuthProxySession(conn, p.cfg.TorControlNet, p.cfg.TorControlAddress, p.onionDenyAddrs, p.watch, &copyPolicy)
			s.sessionWorker()

			return nil
		}
		log.Noticef("%s listener starting on %s:%s", policy.Name, location.Net, location.Address)
		p.authedServices = append(p.authedServices, service.NewMortalService(location.Net, location.Address, handleNewConnection))
		err = p.authedServices[len(p.authedServices)-1].Start()
		if err != nil {
			log.Criticalf("ProxyListener.initAuthenticatedListeners: roflcoptor failed to start service listeners: %s", err)
			return
		}
	}
}

// FilterAcceptLoop and listens and accepts new
// connections and passes them into our filter proxy pipeline

// ProxySession is used to manage is single Tor Control port filter proxy session
type ProxySession struct {
	sync.WaitGroup

	appConn          net.Conn
	appConnReader    *bufio.Reader
	appConnWriteLock sync.Mutex

	torControlNet     string
	torControlAddress string

	addOnionDenyList []common.AddrString

	isPreAuth bool
	watch     bool

	policy     *filter.SievePolicyJSONConfig
	policyList filter.PolicyList

	clientSieve *filter.Sieve
	serverSieve *filter.Sieve

	torConn   *bulb.Conn
	protoInfo *bulb.ProtocolInfo
	errChan   chan error
}

// NewAuthProxySession creates an instance of ProxySession that is prepared with a previously
// authenticated policy.
func NewAuthProxySession(conn net.Conn, torControlNet, torControlAddress string, addOnionDenyList []common.AddrString, watch bool, policy *filter.SievePolicyJSONConfig) *ProxySession {
	s := ProxySession{
		torControlNet:     torControlNet,
		torControlAddress: torControlAddress,
		addOnionDenyList:  addOnionDenyList,
		policy:            policy,
		watch:             watch,
		appConn:           conn,
		appConnReader:     bufio.NewReader(conn),
		errChan:           make(chan error, 2),
		isPreAuth:         true,
	}
	return &s
}

// initTorControl connects and authenticates with the tor control port.
// XXX TODO - authenticate properly for the cases when password or cookie
// authentication schemes are used.
func (s *ProxySession) initTorControl() error {
	var err error
	// Connect to the real control port.
	if s.torConn, err = bulb.Dial(s.torControlNet, s.torControlAddress); err != nil {
		return fmt.Errorf("Failed to connect to tor control port: %v", err)
	}
	// Issue a PROTOCOLINFO, so we can send a realistic response.
	if s.protoInfo, err = s.torConn.ProtocolInfo(); err != nil {
		s.torConn.Close()
		return fmt.Errorf("Failed to issue PROTOCOLINFO: %v", err)
	}
	// Authenticate with the real tor control port.
	// XXX: Pull password out of `b.s.cfg`.
	if err = s.torConn.Authenticate(""); err != nil {
		s.torConn.Close()
		return fmt.Errorf("Failed to authenticate: %v", err)
	}
	return nil
}

func (s *ProxySession) Close() {
	s.appConn.Close()
	s.torConn.Close()
	s.Done()
}

func (s *ProxySession) TorVersion() string {
	return s.protoInfo.TorVersion
}

func (s *ProxySession) appConnWrite(fromServer bool, b []byte) (int, error) {
	s.appConnWriteLock.Lock()
	defer s.appConnWriteLock.Unlock()
	return s.appConn.Write(b)
}

func (s *ProxySession) appConnReadLine() (cmd string, splitCmd []string, rawLine []byte, err error) {
	if rawLine, err = s.appConnReader.ReadBytes('\n'); err != nil {
		return
	}
	trimmedLine := bytes.TrimSpace(rawLine)
	splitCmd = strings.Split(string(trimmedLine), " ")
	cmd = strings.ToUpper(strings.TrimSpace(splitCmd[0]))
	return
}

func (s *ProxySession) sendErrAuthenticationRequired() error {
	_, err := s.appConnWrite(false, []byte(errAuthenticationRequired))
	return err
}

func (s *ProxySession) sendErrUnrecognizedCommand() error {
	_, err := s.appConnWrite(false, []byte(errUnrecognizedCommand))
	return err
}

func (s *ProxySession) onCmdProtocolInfo(splitCmd []string) error {
	for i := 1; i < len(splitCmd); i++ {
		v := splitCmd[i]
		if _, err := strconv.ParseInt(v, 10, 32); err != nil {
			log.Errorf("PROTOCOLINFO received with invalid arg")
			respStr := "513 No such version \"" + v + "\"\r\n"
			_, err := s.appConnWrite(false, []byte(respStr))
			return err
		}
	}
	torVersion := s.TorVersion()
	respStr := "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL,HASHEDPASSWORD\r\n250-VERSION Tor=\"" + torVersion + "\"\r\n" + responseOk
	_, err := s.appConnWrite(false, []byte(respStr))
	return err
}

func (s *ProxySession) processPreAuth() error {
	sentProtocolInfo := false
	for {
		cmd, splitCmd, _, err := s.appConnReadLine()
		if err != nil {
			log.Errorf("[PreAuth]: Failed reading client request: %s", err)
			return err
		}

		switch cmd {
		case cmdProtocolInfo:
			if sentProtocolInfo {
				s.sendErrAuthenticationRequired()
				return errors.New("Client already sent PROTOCOLINFO already")
			}
			sentProtocolInfo = true
			if err = s.onCmdProtocolInfo(splitCmd); err != nil {
				return err
			}
		case cmdAuthenticate:
			_, err = s.appConnWrite(false, []byte(responseOk))
			s.isPreAuth = false
			return err
		case cmdAuthChallenge:
			// WTF?  We should never see this since PROTOCOLINFO lies about the
			// supported authentication types.
			s.sendErrUnrecognizedCommand()
			return errors.New("Client sent AUTHCHALLENGE, when not supported")
		case cmdQuit:
			return errors.New("Client requested connection close")
		default:
			s.sendErrAuthenticationRequired()
			return fmt.Errorf("Invalid app command: '%s'", cmd)
		}
	}
	return nil
}

func (s *ProxySession) sessionWorker() {
	defer s.appConn.Close()
	var err error = nil

	if s.policy == nil {
		panic("wtf")
	}
	s.clientSieve, s.serverSieve = s.policy.GetSieves()

	// Authenticate with the real control port
	err = s.initTorControl()
	if err != nil {
		log.Errorf("Failed to authenticate with the tor control port: %s\n", err)
		return
	}
	defer s.torConn.Close()

	// Handle all of the allowed commands till the client authenticates.
	if err := s.processPreAuth(); err != nil {
		log.Errorf("[PreAuth]: %s", err)
		return
	}

	s.Add(2)
	go s.proxyFilterTorToApp()
	go s.proxyFilterAppToTor()

	// Wait till all sessions are finished, log and return.
	s.Wait()

	if len(s.errChan) > 0 {
		err = <-s.errChan
	}
	log.Noticef("Closed client connection from: %s:%s", s.appConn.LocalAddr().Network(), s.appConn.LocalAddr().String())
	if err != nil {
		log.Notice(err)
	}
}

// proxyFilterTorToApp is used to filter the tor control
// port message sent to the client. Either we let a message
// pass if there is an allow rule otherwise we send nothing.
// If watch-mode is enabled we pass the message through.
func (s *ProxySession) proxyFilterTorToApp() {
	defer s.Close()
	appName := s.policy.Name

	for {
		response, err := s.torConn.ReadResponse()
		if err != nil {
			s.errChan <- err
			break
		}
		responseStr := strings.Join(response.RawLines, "\r\n")
		redactedResponse := responseStr
		if strings.Contains(responseStr, "250-PrivateKey=") {
			redactedResponse = "<redacted because response contained private key blob>"
		}
		if s.watch && s.policy == nil {
			log.Infof("watch-mode: %s A<-T: [%q]\n", appName, redactedResponse)
			_, err = s.appConnWrite(true, []byte(responseStr))
		} else {
			outputMessage := s.serverSieve.Filter(responseStr)
			if outputMessage == "" {
				log.Errorf("filter policy for %s DENY: A<-T: [%q]\n", s.policy.Name, redactedResponse)
			} else {
				_, err = s.appConnWrite(true, []byte(outputMessage+"\r\n"))
			}
		}
		if err != nil {
			s.errChan <- err
			break
		}
	}
}

// proxyFilterAppToTor is used for message routing to accomplish
// unidirectional filtration, message replacement
// and policy denied error message forwarding back to the client
// like this:
//
// client message ---> sieve ---> message
//                      | \-----> replacement message
// error message <------/
//
// If watch-mode is enabled we pipeline messages without filtration.
func (s *ProxySession) proxyFilterAppToTor() {
	defer s.Close()
	appName := ""

	for {
		cmd, splitCmd, raw, err := s.appConnReadLine()
		cmdLine := strings.TrimSpace(string(raw))
		if err != nil {
			s.errChan <- err
			break
		}
		redactedCommand := cmdLine
		if cmd == "ADD_ONION" {
			keytype, _, flags, onionPort, localPort, _ := s.dissectOnion(cmdLine)
			redactedCommand = "ADD_ONION " + keytype + ":" + "<redacted key>" +
				flags + " Port=" + onionPort + ","
			if len(localPort) > 0 {
				redactedCommand = redactedCommand + "127.0.0.1:" + localPort
			}
		}

		if s.watch && s.policy == nil {
			log.Infof("watch-mode: %s A->T: [%s]\n", appName, redactedCommand)
			_, err = s.torConn.Write([]byte(raw))
		} else {
			if cmd == cmdProtocolInfo {
				err = s.onCmdProtocolInfo(splitCmd)
				if err != nil {
					s.errChan <- err
					break
				}
				continue
			}

			outputMessage := s.clientSieve.Filter(cmdLine)
			if outputMessage == "" {
				log.Errorf("filter policy for %s DENY: A->T: [%s]\n", s.policy.Name, redactedCommand)
				_, err = s.appConnWrite(false, []byte("510 Tor Control command proxy denied: filtration policy.\r\n"))
				continue
			} else {
				// handle the ADD_ONION special case
				splitCmd := strings.Split(outputMessage, " ")
				cmd := strings.ToUpper(splitCmd[0])
				if cmd == "ADD_ONION" {
					ok := s.shouldAllowOnion(cmdLine)
					if !ok {
						_, err = s.appConnWrite(false, []byte("510 Tor Control proxy ADD_ONION denied.\r\n"))
						log.Errorf("Denied A->T: [%s]\n", redactedCommand)
						log.Error("Attempt to use ADD_ONION with a control port as target.")
						if err != nil {
							s.errChan <- err
						}
						continue
					} else {
						if s.policy.OzForwardOnion == true {
							if s.policy.OzApp == "" {
								log.Errorf("Missing Oz profile name, filter policy syntax error on %s so DENY: A->T: [%s]\n", s.policy.Name, redactedCommand)
								_, err = s.appConnWrite(false, []byte("510 Tor Control command proxy denied: filtration policy.\r\n"))
								if err != nil {
									s.errChan <- err
								}
								continue
							}
							id, err := s.findOzSandbox(s.policy.OzApp)
							if err != nil {
								log.Errorf("Could not lookup %s sandbox ID for %s so DENY: A->T: [%s]\n", s.policy.OzApp, s.policy.Name, redactedCommand)
								_, err = s.appConnWrite(false, []byte("510 Tor Control command proxy denied: filtration policy.\r\n"))
								if err != nil {
									s.errChan <- err
								}
								continue
							}
							keytype, keyblob, flags, onionPort, localPort, err := s.dissectOnion(cmdLine)
							if err != nil {
								log.Errorf("Error parsing ADD_ONION command.")
								_, err = s.appConnWrite(false, []byte("510 Tor Control command proxy denied: filtration policy.\r\n"))
								if err != nil {
									s.errChan <- err
								}
								continue
							}

							log.Noticef("ADD_ONION request for %s: %s", s.policy.OzApp, redactedCommand)
							log.Noticef("Requesting new forwarder from Oz for %d, %s, %s", id, s.policy.OzAppForwarderName, localPort)
							socketPath, err := s.requestOzForwarder(id, s.policy.OzAppForwarderName, localPort)
							if err != nil {
								log.Errorf("Error creating Oz forwarder for app %s (%s): %v", s.policy.OzApp, s.policy.OzAppForwarderName, err)
								_, err = s.appConnWrite(false, []byte("510 Tor Control command proxy denied: filtration policy.\r\n"))
								if err != nil {
									s.errChan <- err
								}
								continue
							}
							log.Noticef("Oz dynamic forwarder %s for %s sandbox %d created: %s => 127.0.0.1:%s", s.policy.OzAppForwarderName, s.policy.OzApp, id, socketPath, localPort)
							// The syntax is:
							// "ADD_ONION" SP KeyType ":" KeyBlob
							//         [SP "Flags=" Flag *("," Flag)]
							//         1*(SP "Port=" VirtPort ["," Target]) CRLF
							newOut := "ADD_ONION " + keytype + ":" + keyblob + flags + " Port=" + onionPort + "," + "unix:" + socketPath
							outputMessage = newOut
							redactedOutput := "ADD_ONION " + keytype + ":" + "<redacted key>" +
								flags + " Port=" + onionPort + "," + "unix:" + socketPath
							log.Noticef("rewrote ADD_ONION with %s", redactedOutput)
						}
						log.Noticef("allowed ADD_ONION with %s", redactedCommand)
					}
				}
				// send command to tor
				_, err = s.torConn.Write([]byte(outputMessage + "\r\n"))
			}
			if err != nil {
				s.errChan <- err
			}
		}
	}
}

// ADD_ONION filtration -
var addOnionRegexp = regexp.MustCompile("ADD_ONION (?P<keytype>[^ ]+):(?P<keyblob>[^ ]+)(?P<flags> Flags=[^ ]+)? Port=(?P<ports>[^ ]+)")

// shouldAllowOnion implements our deny policy for ADD_ONION.
// If the application filter policy specified an allow rule
// for an ADD_ONION command then we apply additional filtration
// rules here. Namely we disallow onion services to list be bound
// to any of our control ports.
//
// if no target is specified then the target port is the same
// as the virtport :
// ADD_ONION NEW:BEST Port=1234
//
// here virtport is different than target port :
// ADD_ONION NEW:BEST Port=80,127.0.0.1:2345
func (s *ProxySession) shouldAllowOnion(command string) bool {
	portString := ""
	m := addOnionRegexp.FindStringSubmatch(command)
	if m == nil {
		return true
	}
	for i, name := range addOnionRegexp.SubexpNames() {
		if name == "ports" {
			portString = m[i]
			break
		}
	}
	getEndpointTuple := func(desc string) (string, string) {
		fields := strings.Split(desc, ":")
		if len(fields) == 2 {
			if strings.ToUpper(fields[0]) == "UNIX" {
				return "unix", fields[1]
			}
			return "tcp", desc
		}
		return "tcp", fmt.Sprintf("127.0.0.1:%s", desc)
	}
	ports := strings.Split(portString, ",")
	if len(ports) == 2 {
		net, addr := getEndpointTuple(ports[1])
		if s.isAddrDenied(net, addr) {
			return false
		} else {
			return true
		}
	} else {
		return !s.isAddrDenied("tcp", fmt.Sprintf("127.0.0.1:%s", portString))
	}
	return false
}

func (s *ProxySession) dissectOnion(command string) (keytype, keyblob, flags, onionPort, localPort string, err error) {
	target := ""
	ports := ""
	m := addOnionRegexp.FindStringSubmatch(command)
	if m == nil {
		return "", "", "", "", "", errors.New("Error ADD_ONION command doesn't match regex\n")
	}
	for i, name := range addOnionRegexp.SubexpNames() {
		if name == "flags" {
			flags = m[i]
			fmt.Println("FLAGS", flags)
		} else if name == "ports" {
			ports = m[i]
		} else if name == "keytype" {
			keytype = m[i]
		} else if name == "keyblob" {
			keyblob = m[i]
		}
	}
	redactedCommand := fmt.Sprintf("ADD_ONION %s:<redacted_key> %s", keytype, ports)
	if ports == "" {
		return "", "", "", "", "", fmt.Errorf("Error extracting ports from %s\n", redactedCommand)
	}

	fields := strings.Split(ports, ",")

	if len(fields) == 2 {
		target = fields[1]
		targetSplit := strings.Split(target, ":")
		if len(targetSplit) == 2 {
			if targetSplit[0] != "127.0.0.1" {
				return "", "", "", "", "", fmt.Errorf("Unimplemented: forwarding to non-localhost target %s\n", target)
			} else {
				localPort = targetSplit[1]
			}
		} else {
			localPort = fields[1]
		}
		onionPort = fields[0]
	} else {
		if len(ports) > 0 {
			onionPort = ports[1:len(ports)]
			localPort = ports[1:len(ports)]
		} else {
			return "", "", "", "", "", fmt.Errorf("Bad ADD_ONION command string: %s\n", redactedCommand)
		}
	}
	return keytype, keyblob, flags, onionPort, localPort, nil
}

func (s *ProxySession) isAddrDenied(net, addr string) bool {
	for i := 0; i < len(s.addOnionDenyList); i++ {
		if net == s.addOnionDenyList[i].Net && addr == s.addOnionDenyList[i].Address {
			return true
		}
	}
	return false
}

func (s *ProxySession) findOzSandbox(profile string) (id int, err error) {
	sandboxes, err := ozclient.ListSandboxes()
	if err != nil {
		return -1, err
	}
	for _, s := range sandboxes {
		if s.Profile == profile {
			return s.Id, nil
		}
	}
	return -1, fmt.Errorf("Sandbox %s not running.\n", profile)
}

func (s *ProxySession) requestOzForwarder(id int, name, port string) (path string, err error) {
	return ozclient.AskForwarder(id, name, port)
}
