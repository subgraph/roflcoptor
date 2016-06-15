package main

import (
	"log"
	"net"
	"sync"
)

// MortalService can be killed at any time.
type MortalService struct {
	network            string
	address            string
	connectionCallback func(net.Conn) error

	conns     []net.Conn
	stopping  bool
	listener  net.Listener
	waitGroup *sync.WaitGroup
}

// NewMortalService creates a new MortalService
func NewMortalService(network, address string, connectionCallback func(net.Conn) error) *MortalService {
	l := MortalService{
		network:            network,
		address:            address,
		connectionCallback: connectionCallback,

		conns:     make([]net.Conn, 0, 10),
		stopping:  false,
		waitGroup: &sync.WaitGroup{},
	}
	return &l
}

// Stop will kill our listener and all it's connections
func (l *MortalService) Stop() {
	log.Printf("stopping listener service %s:%s", l.network, l.address)
	l.stopping = true
	if l.listener != nil {
		l.listener.Close()
	}
	l.waitGroup.Wait()
}

func (l *MortalService) acceptLoop() {
	defer l.waitGroup.Done()
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
		conn, err := l.listener.Accept()
		if err != nil {
			log.Printf("MortalService connection accept failure: %s\n", err)
			if l.stopping {
				return
			} else {
				continue
			}
		}

		l.conns = append(l.conns, conn)
		go l.handleConnection(conn, len(l.conns)-1)
	}
}

// Start the MortalService
func (l *MortalService) Start() error {
	var err error
	l.listener, err = net.Listen(l.network, l.address)
	if err != nil {
		return err
	}
	l.waitGroup.Add(1)
	go l.acceptLoop()
	return nil
}

func (l *MortalService) handleConnection(conn net.Conn, id int) error {
	defer func() {
		log.Printf("Closing connection #%d", id)
		conn.Close()
		l.conns[id] = nil
	}()

	log.Printf("Starting connection #%d", id)
	if err := l.connectionCallback(conn); err != nil {
		//log.Println(err.Error())
		return err
	}
	return nil
}
