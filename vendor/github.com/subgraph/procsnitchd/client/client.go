package client

import (
	"net"
	"net/rpc"

	"github.com/op/go-logging"
	"github.com/subgraph/go-procsnitch"
	"github.com/subgraph/procsnitchd/protocol"
)

var log = logging.MustGetLogger("procsnitchd_client")

// SetLogger allows setting a custom go-logging instance
func SetLogger(logger *logging.Logger) {
	log = logger
}

type SnitchClient struct {
	conn       net.Conn
	client     *rpc.Client
	socketFile string
}

func NewSnitchClient(socketFile string) *SnitchClient {
	s := SnitchClient{
		socketFile: socketFile,
	}
	return &s
}

func (s *SnitchClient) Start() error {
	var err error
	s.conn, err = net.Dial("unix", s.socketFile)
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
		log.Error("LookupUNIXSocketProcess received a nil Info struct")
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
		log.Error("LookupTCPSocketProcess received a nil Info struct")
	}
	return &info
}

func (s *SnitchClient) LookupUDPSocketProcess(srcPort uint16) *procsnitch.Info {
	var err error
	info := procsnitch.Info{}
	err = s.client.Call("ProcsnitchRPC.LookupUDPSocketProcess", srcPort, &info)
	if err != nil {
		log.Error("LookupUDPSocketProcess received a nil Info struct")
	}
	return &info
}
