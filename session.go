package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/subgraph/go-procsnitch"
	"github.com/yawning/bulb"
)

type ProcInfo interface {
	LookupTCPSocketProcess(srcPort uint16, dstAddr net.IP, dstPort uint16) *procsnitch.Info
}

type RealProcInfo struct {
}

func (r RealProcInfo) LookupTCPSocketProcess(srcPort uint16, dstAddr net.IP, dstPort uint16) *procsnitch.Info {
	return procsnitch.LookupTCPSocketProcess(srcPort, dstAddr, dstPort)
}

// ProxyListener is used to listen for
// Tor Control port connections and
// dispatches them to worker sessions
// to implement the filtering proxy pipeline.
type ProxyListener struct {
	cfg      *RoflcoptorConfig
	watch    bool
	wg       *sync.WaitGroup
	listener net.Listener
	errChan  chan error
	procInfo ProcInfo
}

// NewProxyListener creates a new ProxyListener given
// a configuration structure.
func NewProxyListener(cfg *RoflcoptorConfig, wg *sync.WaitGroup, watch bool) *ProxyListener {
	p := ProxyListener{
		cfg:      cfg,
		wg:       wg,
		watch:    watch,
		procInfo: RealProcInfo{},
	}
	return &p
}

// InitAuthenticatedListeners runs each auth listener
// in it's own goroutine.
func (p *ProxyListener) InitAuthenticatedListeners() {
	listenerPolicyMap := getAuthenticatedPolicyListeners()
	for listener, policy := range listenerPolicyMap {
		go p.AuthListener(listener, policy)
	}
}

// AuthListener implements a connection accept loop
// where we dispatch a new session worker for each connection
// with a previously authenticated policy
func (p *ProxyListener) AuthListener(listener net.Listener, policy *SievePolicyJSONConfig) {
	p.wg.Add(1)
	defer listener.Close()
	defer p.wg.Done()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				log.Printf("ERR/tor: Failed to Accept(): %v", err)
			}
		}

		log.Printf("CONNECTION received %s:%s -> %s:%s\n", conn.RemoteAddr().Network(), conn.RemoteAddr().String(), conn.LocalAddr().Network(), conn.LocalAddr().String())

		// Create the appropriate session instance.
		s := NewAuthProxySession(conn, p.cfg.TorControlNet, p.cfg.TorControlAddress, p.watch, p.procInfo, policy)
		go s.sessionWorker()
	}
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

	// Previously authenticated listeners can be any network type
	// including UNIX domain sockets.
	p.InitAuthenticatedListeners()
	p.wg.Add(1)
	go p.FilterAcceptLoop()
}

// FilterAcceptLoop and listens and accepts new
// connections and passes them into our filter proxy pipeline
func (p *ProxyListener) FilterAcceptLoop() {
	var err error
	defer p.wg.Done()

	p.listener, err = net.Listen(p.cfg.ListenNet, p.cfg.ListenAddress)
	if err != nil {
		panic(fmt.Sprintf("Failed to listen on the filter port: %s\n", err))
	}
	defer p.listener.Close()

	// Listen for incoming connections, and dispatch workers.
	// XXX TODO use a select statement to implement a stop/shutdown channel?
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				log.Printf("ERR/tor: Failed to Accept(): %v", err)
			}
		}

		log.Printf("CONNECTION received %s:%s -> %s:%s\n", conn.RemoteAddr().Network(), conn.RemoteAddr().String(), conn.LocalAddr().Network(), conn.LocalAddr().String())

		// Create the appropriate session instance.
		s := NewProxySession(conn, p.cfg.TorControlNet, p.cfg.TorControlAddress, p.watch, p.procInfo)
		go s.sessionWorker()
	}
}

// ProxySession is used to manage is single Tor Control port filter proxy session
type ProxySession struct {
	policy      *SievePolicyJSONConfig
	clientSieve *Sieve
	serverSieve *Sieve

	torControlNet     string
	torControlAddress string

	torConn   *bulb.Conn
	protoInfo *bulb.ProtocolInfo

	appConn     net.Conn
	appConnLock sync.Mutex

	procInfo ProcInfo

	watch   bool
	errChan chan error
	sync.WaitGroup
}

// NewAuthProxySession creates an instance of ProxySession that is prepared with a previously
// authenticated policy.
func NewAuthProxySession(conn net.Conn, torControlNet, torControlAddress string, watch bool, procInfo ProcInfo, policy *SievePolicyJSONConfig) *ProxySession {
	s := ProxySession{
		torControlNet:     torControlNet,
		torControlAddress: torControlAddress,
		policy:            policy,
		watch:             watch,
		appConn:           conn,
		errChan:           make(chan error, 2),
	}
	return &s
}

// NewProxySession creates a ProxySession given a client's connection
// to our proxy listener and a watch bool.
func NewProxySession(conn net.Conn, torControlNet, torControlAddress string, watch bool, procInfo ProcInfo) *ProxySession {
	s := &ProxySession{
		torControlNet:     torControlNet,
		torControlAddress: torControlAddress,
		watch:             watch,
		appConn:           conn,
		errChan:           make(chan error, 2),
		procInfo:          procInfo,
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
		if dstIP == nil {
			s.appConn.Close()
			panic(fmt.Sprintf("impossible error: net.ParseIP fail for: %s\n", fields[1]))
		}
		srcP, _ := strconv.ParseUint(dstPortStr, 10, 16)
		dstP, _ := strconv.ParseUint(fields[1], 10, 16)
		procInfo = s.procInfo.LookupTCPSocketProcess(uint16(srcP), dstIP, uint16(dstP))
	} else if s.appConn.LocalAddr().Network() == "unix" {
		// XXX todo implement unix domain socket match
		panic("unix domain socket proc info matching not yet implemented")
	}
	return procInfo
}

// getFilterPolicy returns a *ServerClientFilterConfig
// (session policy) if one can be found, otherwise nil is returned.
// Note that the connection is closed upon fatal error,
// when we fail to lookup the proc info, we return nil and an error.
func (s *ProxySession) getFilterPolicy() (*SievePolicyJSONConfig, error) {
	procInfo := s.getProcInfo()
	if procInfo == nil {
		s.appConn.Close()
		return nil, fmt.Errorf("Could not find process information for connection %s:%s", s.appConn.LocalAddr().Network(), s.appConn.LocalAddr().String())
	}
	filter := getFilterForPathAndUID(procInfo.ExePath, procInfo.UID)
	if filter == nil {
		filter = getFilterForPath(procInfo.ExePath)
	} else {
		log.Printf("No filters found for: %s (%d)\n", procInfo.ExePath, procInfo.UID)
		filter = nil
	}
	return filter, nil
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
		s.policy, err = s.getFilterPolicy()
		if err != nil || s.policy == nil {
			log.Printf("proc info query failure; connection from %s aborted: %s\n", clientAddr, err)
			return
		}
	} else {
		log.Printf("Applying existing policy %v\n", s.policy)
		procInfo := s.getProcInfo()
		if procInfo == nil {
			panic("proc query fail")
		}
		log.Printf("exec path %s\n", procInfo.ExePath)
		if procInfo.ExePath != "/usr/sbin/oz-daemon" {
			// denied!
			log.Printf("ALERT/tor: pre auth socket was connected to by a app other than the oz-daemon")
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
			if _, err = s.writeAppConn([]byte(lineStr + "\r\n")); err != nil {
				s.errChan <- err
				break
			}
		} else {
			outputMessage := s.serverSieve.Filter(lineStr)
			if outputMessage != "" {
				_, err := s.writeAppConn([]byte(outputMessage + "\r\n"))
				if err != nil {
					s.errChan <- err
					break
				}
			}
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
		log.Printf("A->T: [%s]\n", lineStr)

		if s.watch {
			_, err := s.torConn.Write([]byte(lineStr + "\r\n"))
			if err != nil {
				s.errChan <- err
			}
		} else {
			outputMessage := s.clientSieve.Filter(lineStr)
			if outputMessage == "" {
				_, err = s.writeAppConn([]byte("510 Tor Control command proxy denied: filtration policy.\r\n"))
			} else {
				_, err = s.torConn.Write([]byte(outputMessage + "\r\n"))
			}
			if err != nil {
				s.errChan <- err
			}
		}
	}
}
