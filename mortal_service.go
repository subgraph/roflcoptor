package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

// MortalService can be killed at any time.
type MortalService struct {
	network            string
	address            string
	connectionCallback func(net.Conn) error

	conns    []net.Conn
	quit     chan bool
	listener net.Listener
}

// NewMortalService creates a new MortalService
func NewMortalService(network, address string, connectionCallback func(net.Conn) error) *MortalService {
	l := MortalService{
		network:            network,
		address:            address,
		connectionCallback: connectionCallback,

		conns: make([]net.Conn, 0, 10),
		quit:  make(chan bool),
	}
	return &l
}

// Stop will kill our listener and all it's connections
func (l *MortalService) Stop() {
	log.Printf("stopping listener service %s:%s", l.network, l.address)
	close(l.quit)
	if l.listener != nil {
		l.listener.Close()
	}
}

func (l *MortalService) AcceptLoop() {
	defer func() {
		log.Printf("stoping listener service %s:%s", l.network, l.address)
		for i, conn := range l.conns {
			if conn != nil {
				log.Printf("Closing connection #%d", i)
				conn.Close()
			}
		}
	}()
	defer l.listener.Close()

	for {
		log.Printf("Listening for connections on %s:%s", l.network, l.address)
		conn, err := l.listener.Accept()

		if err != nil {
			log.Printf("MortalService connection accept failure: %s\n", err)
			select {
			case <-l.quit:
				return
			default:
			}
			continue
		}
		l.conns = append(l.conns, conn)
		go l.handleConnection(conn, len(l.conns)-1)
	}
}

func (l *MortalService) createDeadlinedListener() error {
	if l.network == "tcp" {
		tcpAddr, err := net.ResolveTCPAddr("tcp", l.address)
		if err != nil {
			return fmt.Errorf("MortalService.createDeadlinedListener %s %s failure: %s", l.network, l.address, err)
		}
		tcpListener, err := net.ListenTCP("tcp", tcpAddr)
		if err != nil {
			return fmt.Errorf("MortalService.createDeadlinedListener %s %s failure: %s", l.network, l.address, err)
		}
		tcpListener.SetDeadline(time.Now().Add(1e9))
		l.listener = tcpListener
		return nil
	} else if l.network == "unix" {
		unixAddr, err := net.ResolveUnixAddr("unix", l.address)
		if err != nil {
			return fmt.Errorf("MortalService.createDeadlinedListener %s %s failure: %s", l.network, l.address, err)
		}
		unixListener, err := net.ListenUnix("unix", unixAddr)
		if err != nil {
			return fmt.Errorf("MortalService.createDeadlinedListener %s %s failure: %s", l.network, l.address, err)
		}
		unixListener.SetDeadline(time.Now().Add(1e9))
		l.listener = unixListener
		return nil
	} else {
		panic("")
	}
	return nil
}

// Start the MortalService
func (l *MortalService) Start() error {
	var err error
	err = l.createDeadlinedListener()
	if err != nil {
		return err
	}
	go l.AcceptLoop()
	return nil
}

func (l *MortalService) handleConnection(conn net.Conn, id int) error {
	defer func() {
		log.Printf("Closing connection #%d", id)
		conn.Close()
		l.conns[id] = nil
	}()

	log.Printf("Starting connection #%d", id)

	for {
		// If l.connectionCallback returns, then it's either
		// because the socket is closed (err == nil), or there's some type of
		// real error.
		if err := l.connectionCallback(conn); err != nil {
			log.Println(err.Error())
			return err
		}
		return nil
	}
}
