package service

import (
	"net"
	"os"
	"sync"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("mortal_service")

// SetLogger allows setting a custom go-logging instance
func SetLogger(logger *logging.Logger) {
	log = logger
}

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

// Start the MortalService
func (l *MortalService) Start() error {
	var err error
	log.Debugf("starting listener service %s:%s", l.network, l.address)
	if l.network == "unix" {
		log.Debugf("removing unix socket file %s", l.address)
		os.Remove(l.address)
	}
	l.listener, err = net.Listen(l.network, l.address)
	if err != nil {
		return err
	}
	l.waitGroup.Add(1)
	go l.acceptLoop()
	return nil
}

// Stop will kill our listener and all it's connections
func (l *MortalService) Stop() {
	log.Debugf("stopping listener service %s:%s", l.network, l.address)
	l.stopping = true
	if l.listener != nil {
		l.listener.Close()
	}
	l.waitGroup.Wait()
	if l.network == "unix" {
		log.Debugf("removing unix socket file %s", l.address)
		os.Remove(l.address)
	}
}

func (l *MortalService) acceptLoop() {
	defer l.waitGroup.Done()
	defer func() {
		log.Debugf("acceptLoop stopping for listener service %s:%s", l.network, l.address)
		for i, conn := range l.conns {
			if conn != nil {
				log.Debugf("Closing connection #%d", i)
				conn.Close()
			}
		}
	}()
	defer l.listener.Close()

	for {
		conn, err := l.listener.Accept()
		if err != nil {
			log.Errorf("MortalService connection accept failure: %s\n", err)
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

func (l *MortalService) handleConnection(conn net.Conn, id int) error {
	defer func() {
		log.Debugf("Closing connection #%d", id)
		conn.Close()
		l.conns[id] = nil
	}()

	log.Debugf("Starting connection #%d", id)
	if err := l.connectionCallback(conn); err != nil {
		// log.Println(err.Error())
		return err
	}
	return nil
}
