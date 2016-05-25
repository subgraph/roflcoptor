package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/subgraph/go-procsnitch"
	"github.com/yawning/bulb"
)

// ProcInfo represents an api that can be used to query process information about
// the far side of a network connection
type ProcInfo interface {
	LookupTCPSocketProcess(srcPort uint16, dstAddr net.IP, dstPort uint16) *procsnitch.Info
	LookupUNIXSocketProcess(socketFile string) *procsnitch.Info
}

// RealProcInfo represents our real ProcInfo api. This aids in the construction of unit tests.
type RealProcInfo struct {
}

// LookupTCPSocketProcess returns the process information for a given TCP connection.
func (r RealProcInfo) LookupTCPSocketProcess(srcPort uint16, dstAddr net.IP, dstPort uint16) *procsnitch.Info {
	return procsnitch.LookupTCPSocketProcess(srcPort, dstAddr, dstPort)
}

// LookupUNIXSocketProcess returns the process information for a given UNIX socket connection.
func (r RealProcInfo) LookupUNIXSocketProcess(socketFile string) *procsnitch.Info {
	return procsnitch.LookupUNIXSocketProcess(socketFile)
}

// ProxyListener is used to listen for
// Tor Control port connections and
// dispatches them to worker sessions
// to implement the filtering proxy pipeline.
type ProxyListener struct {
	cfg            *RoflcoptorConfig
	watch          bool
	services       []*MortalService
	authedServices []*MortalService
	onionDenyAddrs []AddrString
	errChan        chan error
	procInfo       ProcInfo
	policyList     PolicyList
}

// NewProxyListener creates a new ProxyListener given
// a configuration structure.
func NewProxyListener(cfg *RoflcoptorConfig, watch bool) *ProxyListener {
	p := ProxyListener{
		cfg:        cfg,
		watch:      watch,
		procInfo:   RealProcInfo{},
		policyList: NewPolicyList(),
	}
	return &p
}

// StartListeners initialize all tor control port proxy listeners.
// There are currently two types of listeners with two types of authentication:
//
// - Applications which are not in the Oz jail will have their kernel enforced unique
// exec path which we use to determine which filter policy to apply.
//
// - "previously authenticated" listeners designate the policy based on the
// client's ability to connect, therefore access to this listener must be restricted
// by other means. All applications running from an Oz shell will appear to have
// the same exec path of "/usr/sbin/oz-daemon"
func (p *ProxyListener) StartListeners() {
	p.policyList.LoadFilters(p.cfg.FiltersPath)
	// compile a list of all control ports;
	// we black list them from being the onion target address
	p.compileOnionAddrBlacklist()

	// Previously authenticated listeners can be any network type
	// including UNIX domain sockets.
	p.initAuthenticatedListeners()

	// start the main listeners
	handleNewConnection := func(conn net.Conn) error {
		log.Printf("CONNECTION received %s:%s -> %s:%s\n", conn.RemoteAddr().Network(),
			conn.RemoteAddr().String(), conn.LocalAddr().Network(), conn.LocalAddr().String())
		s := NewProxySession(conn,
			p.cfg.TorControlNet, p.cfg.TorControlAddress, p.onionDenyAddrs, p.watch, p.procInfo, p.policyList)
		s.sessionWorker()
		return nil
	}
	for _, location := range p.cfg.Listeners {
		p.services = append(p.services, NewMortalService(location.Net, location.Address, handleNewConnection))
		p.services[len(p.services)-1].Start()
	}
}

// StopListeners stops all the listeners
func (p *ProxyListener) StopListeners() {
	stopServices := func(services []*MortalService) {
		for _, service := range services {
			service.Stop()
		}
	}
	stopServices(p.services)
	stopServices(p.authedServices)
}

func (p *ProxyListener) compileOnionAddrBlacklist() {
	p.onionDenyAddrs = p.policyList.getListenerAddresses()
	p.onionDenyAddrs = append(p.onionDenyAddrs, AddrString{
		Net:     p.cfg.TorControlNet,
		Address: p.cfg.TorControlAddress,
	})
	for _, listener := range p.cfg.Listeners {
		p.onionDenyAddrs = append(p.onionDenyAddrs, AddrString{
			Net:     listener.Net,
			Address: listener.Address,
		})
	}
}

// InitAuthenticatedListeners runs each auth listener
// in it's own goroutine.
func (p *ProxyListener) initAuthenticatedListeners() {
	locations := p.policyList.getAuthenticatedPolicyAddresses()
	for location, policy := range locations {
		handleNewConnection := func(conn net.Conn) error {
			log.Printf("connection received %s:%s -> %s:%s\n", conn.RemoteAddr().Network(),
				conn.RemoteAddr().String(), conn.LocalAddr().Network(), conn.LocalAddr().String())
			s := NewAuthProxySession(conn, p.cfg.TorControlNet, p.cfg.TorControlAddress, p.onionDenyAddrs, p.watch, p.procInfo, policy)
			s.sessionWorker()
			return nil
		}
		p.authedServices = append(p.authedServices, NewMortalService(location.Net, location.Address, handleNewConnection))
		p.authedServices[len(p.authedServices)-1].Start()
	}
}

// FilterAcceptLoop and listens and accepts new
// connections and passes them into our filter proxy pipeline

// ProxySession is used to manage is single Tor Control port filter proxy session
type ProxySession struct {
	appConn           net.Conn
	torControlNet     string
	torControlAddress string
	addOnionDenyList  []AddrString
	watch             bool
	procInfo          ProcInfo
	policy            *SievePolicyJSONConfig
	policyList        PolicyList

	clientSieve *Sieve
	serverSieve *Sieve
	torConn     *bulb.Conn
	protoInfo   *bulb.ProtocolInfo
	appConnLock sync.Mutex
	errChan     chan error

	sync.WaitGroup
}

// NewAuthProxySession creates an instance of ProxySession that is prepared with a previously
// authenticated policy.
func NewAuthProxySession(conn net.Conn, torControlNet, torControlAddress string, addOnionDenyList []AddrString, watch bool, procInfo ProcInfo, policy *SievePolicyJSONConfig) *ProxySession {
	s := ProxySession{
		torControlNet:     torControlNet,
		torControlAddress: torControlAddress,
		addOnionDenyList:  addOnionDenyList,
		policy:            policy,
		watch:             watch,
		appConn:           conn,
		procInfo:          procInfo,
		errChan:           make(chan error, 2),
	}
	return &s
}

// NewProxySession creates a ProxySession given a client's connection
// to our proxy listener and a watch bool.
func NewProxySession(conn net.Conn, torControlNet, torControlAddress string, addOnionDenyList []AddrString, watch bool, procInfo ProcInfo, policyList PolicyList) *ProxySession {
	s := &ProxySession{
		torControlNet:     torControlNet,
		torControlAddress: torControlAddress,
		addOnionDenyList:  addOnionDenyList,
		watch:             watch,
		appConn:           conn,
		errChan:           make(chan error, 2),
		procInfo:          procInfo,
		policyList:        policyList,
	}
	return s
}

func (s *ProxySession) getProcInfo() *procsnitch.Info {
	var procInfo *procsnitch.Info
	// XXX fix me for tcp4 and tcp6?
	if s.appConn.LocalAddr().Network() == "tcp" {
		fields := strings.Split(s.appConn.RemoteAddr().String(), ":")
		dstPortStr := fields[1]

		fields = strings.Split(s.appConn.LocalAddr().String(), ":")
		dstIP := net.ParseIP(fields[0])
		// XXX not necessary; should never fail to parse!
		//if dstIP == nil {
		//	s.appConn.Close()
		//	panic(fmt.Sprintf("impossible error: net.ParseIP fail for: %s\n", fields[1]))
		//}
		srcP, _ := strconv.ParseUint(dstPortStr, 10, 16)
		dstP, _ := strconv.ParseUint(fields[1], 10, 16)
		procInfo = s.procInfo.LookupTCPSocketProcess(uint16(srcP), dstIP, uint16(dstP))
	} else if s.appConn.LocalAddr().Network() == "unix" {
		procInfo = s.procInfo.LookupUNIXSocketProcess(s.appConn.LocalAddr().String())
	}
	return procInfo
}

// getFilterPolicy returns a *ServerClientFilterConfig
// (session policy) if one can be found, otherwise nil is returned.
// Note that the calling party should decide whether or not to close
// the connection.
func (s *ProxySession) getFilterPolicy() *SievePolicyJSONConfig {
	procInfo := s.getProcInfo()
	if procInfo == nil {
		log.Printf("Could not find process information for connection %s:%s", s.appConn.LocalAddr().Network(), s.appConn.LocalAddr().String())
		return nil
	}
	filter := s.policyList.getFilterForPathAndUID(procInfo.ExePath, procInfo.UID)
	if filter == nil {
		filter = s.policyList.getFilterForPath(procInfo.ExePath)
	}
	if filter == nil {
		log.Println("Filter policy not found for:", procInfo.ExePath)
		return nil
	}
	return filter
}

// initTorControl connects and authenticates with the tor control port.
// XXX TODO - authenticate properly for the cases when password or cookie
// authentication schemes are used.
func (s *ProxySession) initTorControl() error {
	var err error
	// Connect to the real control port.
	if s.torConn, err = bulb.Dial(s.torControlNet, s.torControlAddress); err != nil {
		return fmt.Errorf("ERR/tor: Failed to connect to tor control port: %v", err)
	}
	// Issue a PROTOCOLINFO, so we can send a realistic response.
	if s.protoInfo, err = s.torConn.ProtocolInfo(); err != nil {
		s.torConn.Close()
		return fmt.Errorf("ERR/tor: Failed to issue PROTOCOLINFO: %v", err)
	}
	// Authenticate with the real tor control port.
	// XXX: Pull password out of `b.s.cfg`.
	if err = s.torConn.Authenticate(""); err != nil {
		s.torConn.Close()
		return fmt.Errorf("ERR/tor: Failed to authenticate: %v", err)
	}
	return nil
}

func (s *ProxySession) sessionWorker() {
	defer s.appConn.Close()
	var err error

	clientAddr := s.appConn.RemoteAddr()
	log.Printf("INFO/tor: New ctrl connection from: %s", clientAddr)

	if s.policy == nil {
		s.policy = s.getFilterPolicy()
		if s.policy == nil && !s.watch {
			_, err = s.writeAppConn([]byte("510 Tor Control proxy connection denied.\r\n"))
			if err != nil {
				s.errChan <- err
			}
			return
		}
	} else {
		procInfo := s.getProcInfo()
		if procInfo == nil {
			panic("wtf! impossible proc query failure.")
		}
		if procInfo.ExePath != "/usr/sbin/oz-daemon" {
			// denied!
			log.Printf("ALERT/tor: pre auth socket was connected to by a app other than the oz-daemon")
			_, err = s.writeAppConn([]byte("510 Tor Control proxy connection denied.\r\n"))
			if err != nil {
				s.errChan <- err
			}
			return
		}
	}
	if s.policy != nil {
		s.clientSieve, s.serverSieve = s.policy.GetSieves()
	}

	// Authenticate with the real control port
	err = s.initTorControl()
	if err != nil {
		log.Printf("RoflcopTor: Failed to authenticate with the tor control port: %s\n", err)
		return
	}
	defer s.torConn.Close()

	s.Add(2)
	go s.proxyFilterTorToApp()
	go s.proxyFilterAppToTor()

	// Wait till all sessions are finished, log and return.
	s.Wait()

	if len(s.errChan) > 0 {
		err := <-s.errChan
		log.Printf("INFO/tor: Closed client connection from: %s: %v", clientAddr, err)
	} else {
		log.Printf("INFO/tor: Closed client connection from: %v", clientAddr)
	}
}

// writeAppConn uses a lock so that both connection processing goroutines
// can write to the client connection.
func (s *ProxySession) writeAppConn(b []byte) (int, error) {
	s.appConnLock.Lock()
	defer s.appConnLock.Unlock()
	return s.appConn.Write(b)
}

// proxyFilterTorToApp is used to filter the tor control
// port message sent to the client. Either we let a message
// pass if there is an allow rule otherwise we send nothing.
// If watch-mode is enabled we pass the message through.
func (s *ProxySession) proxyFilterTorToApp() {
	defer s.Done()

	rd := bufio.NewReader(s.torConn)
	for {
		line, err := rd.ReadBytes('\n')
		if err != nil {
			s.errChan <- err
			break
		}
		lineStr := strings.TrimSpace(string(line))
		log.Printf("A<-T: [%s]\n", lineStr)
		if s.watch {
			_, err = s.writeAppConn([]byte(lineStr + "\r\n"))
		} else {
			outputMessage := s.serverSieve.Filter(lineStr)
			if outputMessage != "" {
				_, err = s.writeAppConn([]byte(outputMessage + "\r\n"))
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
	defer s.Done()
	appConnReader := bufio.NewReader(s.appConn)
	for {
		line, err := appConnReader.ReadBytes('\n')
		if err != nil {
			s.errChan <- err
			break
		}
		lineStr := strings.TrimSpace(string(line))

		if s.watch {
			log.Printf("A->T: [%s]\n", lineStr)
			_, err = s.torConn.Write([]byte(lineStr + "\r\n"))
		} else {
			outputMessage := s.clientSieve.Filter(lineStr)
			if outputMessage == "" {
				_, err = s.writeAppConn([]byte("250 Tor Control command proxy denied: filtration policy.\r\n"))
				continue
			} else {
				// handle the ADD_ONION special case
				splitCmd := strings.Split(outputMessage, " ")
				cmd := strings.ToUpper(splitCmd[0])
				if cmd == "ADD_ONION" {
					ok := s.shouldAllowOnion(lineStr)
					if !ok {
						_, err = s.writeAppConn([]byte("510 Tor Control proxy ADD_ONION denied.\r\n"))
						log.Printf("Denied A->T: [%s]\n", lineStr)
						log.Print("Attempt to use ADD_ONION with a control port as target.")
						if err != nil {
							s.errChan <- err
						}
						continue
					}
				}

				// send command to tor
				log.Printf("A->T: [%s]\n", lineStr)
				_, err = s.torConn.Write([]byte(outputMessage + "\r\n"))
			}
			if err != nil {
				s.errChan <- err
			}
		}
	}
}

// ADD_ONION filtration -
var addOnionRegexp = regexp.MustCompile("=([^ ]+)")

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
	target := ""
	ports := addOnionRegexp.FindString(command)
	fields := strings.Split(ports, ",")

	if len(fields) == 2 {
		target = fields[1]
		fields = strings.Split(target, ":")
		if len(fields) == 2 {
			if strings.ToUpper(fields[0]) == "UNIX" {
				return !s.isAddrDenied("unix", fields[1])
			}
			return !s.isAddrDenied("tcp", target)
		}
		// target only specifies a port
		return !s.isAddrDenied("tcp", fmt.Sprintf("127.0.0.1:%s", target))
	}
	// target not specified, default to port only specified as virtport
	if len(ports) > 0 {
		ports = ports[1:len(ports)]
	}
	return !s.isAddrDenied("tcp", fmt.Sprintf("127.0.0.1:%s", ports))
}

func (s *ProxySession) isAddrDenied(net, addr string) bool {
	for i := 0; i < len(s.addOnionDenyList); i++ {
		if net == s.addOnionDenyList[i].Net && addr == s.addOnionDenyList[i].Address {
			return true
		}
	}
	return false
}
