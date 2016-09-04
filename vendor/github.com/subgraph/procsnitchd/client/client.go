package client

import (
	"net"
	"net/rpc"
	"time"

	"github.com/op/go-logging"
	"github.com/subgraph/go-procsnitch"
	"github.com/subgraph/procsnitchd/protocol"
)

var log = logging.MustGetLogger("procsnitchd_client")

// SetLogger allows setting a custom go-logging instance
func SetLogger(logger *logging.Logger) {
	log = logger
}

type Options struct {
	// Max number of connect retries upon failure
	MaxRetry   int
	RetrySleep time.Duration
}

var defaultOptions = Options{
	MaxRetry:   5,
	RetrySleep: 300 * time.Millisecond,
}

type SnitchClient struct {
	options    *Options
	conn       net.Conn
	client     *rpc.Client
	socketFile string
}

// NewSnitchClient is used to talk to procsnitchd
// options can set to nil in order to utilize defaults
func NewSnitchClient(socketFile string, options *Options) *SnitchClient {
	s := SnitchClient{
		socketFile: socketFile,
	}
	if options == nil {
		s.options = &defaultOptions
	} else {
		s.options = options
	}
	return &s
}

func (s *SnitchClient) Start() error {
	return s.Dial()
}

func (s *SnitchClient) Dial() error {
	var err error

	// implement "retry" for net.Dial()
	for i := 0; i < 5; i++ {
		s.conn, err = net.Dial("unix", s.socketFile)
		if err == nil {
			break
		}
		log.Warningf("SnitchClient connect failure: %s. Retrying.", err)
		// arbitrary "sleep" value
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil {
		log.Errorf("SnitchClient Start aborted. Failed to connect: %s", err)
		return err
	}
	s.client = rpc.NewClient(s.conn)

	return nil
}

func (s *SnitchClient) Stop() error {
	return s.client.Close()
}

// implements the go-procsnitch ProcInfo interface

func (s *SnitchClient) LookupUNIXSocketProcess(socketFile string) *procsnitch.Info {
	var err error
	info := procsnitch.Info{}
	err = s.client.Call("ProcsnitchRPC.LookupUNIXSocketProcess", socketFile, &info)
	if err != nil {
		err = s.Dial()
		if err != nil {
			log.Errorf("LookupUNIXSocketProcess received a nil Info struct: %s", err)
		} else {
			err = s.client.Call("ProcsnitchRPC.LookupUNIXSocketProcess", socketFile, &info)
			if err != nil {
				log.Errorf("LookupUNIXSocketProcess received a nil Info struct: %s", err)
			}
		}
	}
	return &info
}

func (s *SnitchClient) LookupTCPSocketProcess(srcPort uint16, dstAddr net.IP, dstPort uint16) *procsnitch.Info {
	var err error
	info := procsnitch.Info{}
	tcpDescriptor := protocol.TCPDescriptor{
		SrcPort: srcPort,
		DstAddr: dstAddr,
		DstPort: dstPort,
	}
	err = s.client.Call("ProcsnitchRPC.LookupTCPSocketProcess", tcpDescriptor, &info)
	if err != nil {
		err = s.Dial()
		if err != nil {
			log.Errorf("LookupTCPSocketProcess received a nil Info struct: %s", err)
		} else {
			err = s.client.Call("ProcsnitchRPC.LookupTCPSocketProcess", tcpDescriptor, &info)
			if err != nil {
				log.Errorf("LookupTCPSocketProcess received a nil Info struct: %s", err)
			}
		}
	}
	return &info
}

func (s *SnitchClient) LookupUDPSocketProcess(srcPort uint16) *procsnitch.Info {
	var err error
	info := procsnitch.Info{}
	err = s.client.Call("ProcsnitchRPC.LookupUDPSocketProcess", srcPort, &info)
	if err != nil {
		err = s.Dial()
		if err != nil {
			log.Errorf("LookupUDPSocketProcess received a nil Info struct: %s", err)
		} else {
			err = s.client.Call("ProcsnitchRPC.LookupUDPSocketProcess", srcPort, &info)
			if err != nil {
				log.Errorf("LookupUDPSocketProcess received a nil Info struct: %s", err)
			}
		}
	}
	return &info
}
