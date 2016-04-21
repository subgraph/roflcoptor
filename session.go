package main

import (
	"github.com/subgraph/fw-daemon/proc"
	"github.com/yawning/bulb"

	"bufio"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
)

// ProxyListener is used to listen for
// Tor Control port connections and
// dispatches them to worker sessions
// to implement the filtering proxy pipeline.
type ProxyListener struct {
	cfg         *RoflcoptorConfig
	watch       bool
	wg          *sync.WaitGroup
	tcpListener *net.TCPListener
	errChan     chan error
}

// NewProxyListener creates a new ProxyListener given
// a configuration structure.
func NewProxyListener(cfg *RoflcoptorConfig, wg *sync.WaitGroup, watch bool) (*ProxyListener, error) {
	p := ProxyListener{
		cfg:   cfg,
		wg:    wg,
		watch: watch,
	}
	return &p, nil
}

// InitAllListeners initialize all tor control port proxy listeners
func (p *ProxyListener) InitAllListeners() {
	// XXX TODO add UNIX domain socket listener
	p.wg.Add(1)
	p.FilterTcpAcceptLoop()
}

// FilterAcceptLoop and listens and accepts new
// connections and passes them into our filter proxy pipeline
func (p *ProxyListener) FilterTcpAcceptLoop() {
	defer p.wg.Done()

	tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%s", p.cfg.ListenIP, p.cfg.ListenTCPPort))
	if err != nil {
		panic(fmt.Sprintf("Failed to resolve TCP configured filter port: %s\n", err))
	}
	p.tcpListener, err = net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		panic(fmt.Sprintf("Failed to listen on the filter port: %s\n", err))
	}
	defer p.tcpListener.Close()

	// Listen for incoming connections, and dispatch workers.
	// XXX TODO use a select statement to implement a stop/shutdown channel?
	for {
		conn, err := p.tcpListener.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				log.Printf("ERR/tor: Failed to Accept(): %v", err)
			}
		}

		// Create the appropriate session instance.
		s := NewProxySession(p.cfg, conn, p.watch)
		go s.sessionWorker()
	}
}

// ProxySession is used to manage is single Tor Control port filter proxy session
type ProxySession struct {
	cfg                *RoflcoptorConfig
	clientFilterPolicy *FilterConfig
	serverFilterPolicy *FilterConfig

	appConn          net.Conn
	appConnReader    *bufio.Reader
	appConnWriteLock sync.Mutex

	torConn   *bulb.Conn
	protoInfo *bulb.ProtocolInfo

	watch   bool
	errChan chan error
	sync.WaitGroup
}

func NewProxySession(cfg *RoflcoptorConfig, conn net.Conn, watch bool) *ProxySession {
	s := &ProxySession{
		cfg:           cfg,
		watch:         watch,
		appConn:       conn,
		appConnReader: bufio.NewReader(conn),
		errChan:       make(chan error, 2),
	}
	return s
}

// getFilterPolicy returns a *ServerClientFilterConfig
// (session policy) if one can be found, otherwise nil is returned.
// Note that the connection is closed upon fatal error,
// when we fail to lookup the proc info, we return nil and an error.
func (s *ProxySession) getFilterPolicy() (*ServerClientFilterConfig, error) {

	fields := strings.Split(s.appConn.RemoteAddr().String(), ":")
	dstPortStr := fields[1]
	dstIP := net.ParseIP(s.cfg.ListenIP)

	if dstIP == nil {
		s.appConn.Close()
		return nil, fmt.Errorf("net.ParseIP fail for: %s\n", s.cfg.ListenIP)
	}

	srcP, _ := strconv.ParseUint(dstPortStr, 10, 16)
	dstP, _ := strconv.ParseUint(s.cfg.ListenTCPPort, 10, 16)
	procInfo := proc.LookupTCPSocketProcess(uint16(srcP), dstIP, uint16(dstP))
	if procInfo == nil {
		s.appConn.Close()
		return nil, fmt.Errorf("Could not find process information for: %d %s %d\n", srcP, dstIP, dstP)
	}

	filter := getFilterForPathAndUID(procInfo.ExePath, procInfo.Uid)
	if filter == nil {
		filter = getFilterForPath(procInfo.ExePath)
	} else {
		log.Printf("No filters found for: %s (%d)\n", procInfo.ExePath, procInfo.Uid)
		filter = nil
	}
	return filter, nil
}

func (s *ProxySession) initTorControl() error {
	var err error

	// Connect to the real control port.
	if s.torConn, err = bulb.Dial("unix", s.cfg.TorControlSocketPath); err != nil {
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

	var policy *ServerClientFilterConfig
	var err error

	clientAddr := s.appConn.RemoteAddr()
	log.Printf("INFO/tor: New ctrl connection from: %s", clientAddr)

	policy, err = s.getFilterPolicy()
	if err != nil {
		log.Printf("proc info query failure; connection from %s aborted: %s\n", clientAddr, err)
		return
	}
	if policy == nil {
		s.clientFilterPolicy = nil
		s.serverFilterPolicy = nil
	} else {
		s.clientFilterPolicy = &FilterConfig{
			Allowed:             policy.ClientAllowed,
			AllowedPrefixes:     policy.ClientAllowedPrefixes,
			Replacements:        policy.ClientReplacements,
			ReplacementPrefixes: policy.ClientReplacementPrefixes,
		}
		s.serverFilterPolicy = &FilterConfig{
			Allowed:             policy.ServerAllowed,
			AllowedPrefixes:     policy.ServerAllowedPrefixes,
			Replacements:        policy.ServerReplacements,
			ReplacementPrefixes: policy.ServerReplacementPrefixes,
		}
	}

	// Authenticate with the real control port
	err = s.initTorControl()
	defer s.torConn.Close()

	if err != nil {
		log.Printf("RoflcopTor: Failed to authenticate with the tor control port: %s\n", err)
		return
	}

	s.appConnReader = bufio.NewReader(s.appConn)
	s.Add(2)
	go s.proxyFilterTorToApp()
	go s.proxyFilterAppToTor()

	// Wait till all sessions are finished, log and return.
	s.Wait()
	s.torConn.Close()
	s.appConn.Close()

	if len(s.errChan) > 0 {
		err := <-s.errChan
		log.Printf("INFO/tor: Closed client connection from: %s: %v", clientAddr, err)
	} else {
		log.Printf("INFO/tor: Closed client connection from: %v", clientAddr)
	}
}

func (s *ProxySession) proxyFilterTorToApp() {
	defer s.Done()

	var appConnLock sync.Mutex
	writeAppConn := func(b []byte) (int, error) {
		appConnLock.Lock() // XXX is the lock really needed here?
		defer appConnLock.Unlock()
		return s.appConn.Write(b)
	}

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
			if _, err = writeAppConn([]byte(lineStr + "\n")); err != nil {
				s.errChan <- err
				break
			}
		} else {
			filterCommand(lineStr, "250 OK", writeAppConn, s.errChan, s.serverFilterPolicy)
		}
	}
}

func (s *ProxySession) proxyFilterAppToTor() {
	defer s.Done()

	writeToTor := func(line []byte) (int, error) {
		n, err := s.torConn.Write([]byte(line))
		return n, err
	}

	for {
		line, err := s.appConnReader.ReadBytes('\n')
		if err != nil {
			s.errChan <- err
			break
		}
		lineStr := strings.TrimSpace(string(line))
		log.Printf("A->T: [%s]\n", lineStr)

		if s.watch {
			_, err = writeToTor([]byte(lineStr + "\n"))
			if err != nil {
				s.errChan <- err
			}
		} else {
			filterCommand(lineStr, "", writeToTor, s.errChan, s.clientFilterPolicy)
		}
	}
}
