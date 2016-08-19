package procsnitch

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
)

type socketAddr struct {
	ip   net.IP
	port uint16
}

func (sa socketAddr) String() string {
	return fmt.Sprintf("%v:%d", sa.ip, sa.port)
}

type socketStatus struct {
	local  socketAddr
	remote socketAddr
	//status ConnectionStatus
	uid         int
	inode       uint64
	remoteInode uint64
	line        string
	path        string
}

type ConnectionStatus int

const (
	ESTABLISHED ConnectionStatus = iota
	SYN_SENT
	SYN_RECV
	FIN_WAIT1
	FIN_WAIT2
	TIME_WAIT
	CLOSE
	CLOSE_WAIT
	LAST_ACK
	LISTEN
	CLOSING
)

func (c ConnectionStatus) String() string {
	switch c {
	case ESTABLISHED:
		return "ESTABLISHED"
	case SYN_SENT:
		return "SYN_SENT"
	case SYN_RECV:
		return "SYN_RECV"
	case FIN_WAIT1:
		return "FIN_WAIT1"
	case FIN_WAIT2:
		return "FIN_WAIT2"
	case TIME_WAIT:
		return "TIME_WAIT"
	case CLOSE:
		return "CLOSE"
	case CLOSE_WAIT:
		return "CLOSE_WAIT"
	case LAST_ACK:
		return "LAST_ACK"
	case LISTEN:
		return "LISTEN"
	case CLOSING:
		return "CLOSING"
	default:
		return "Invalid Connection Status"
	}
}

func (ss *socketStatus) String() string {
	return fmt.Sprintf("%s -> %s uid=%d inode=%d", ss.local, ss.remote, ss.uid, ss.inode)
}

func findUDPSocket(srcPort uint16) *socketStatus {
	return findSocket("udp", func(ss socketStatus) bool {
		return ss.local.port == srcPort
	})
}

func findTCPSocket(srcPort uint16, dstAddr net.IP, dstPort uint16) *socketStatus {
	return findSocket("tcp", func(ss socketStatus) bool {
		return ss.remote.port == dstPort && ss.remote.ip.Equal(dstAddr) && ss.local.port == srcPort
	})
}

func findUNIXSocket(socketFile string) *socketStatus {
	proto := "unix"

	// /proc/net/unix
	// Num       RefCount Protocol Flags    Type St Inode Path
	// 0000000000000000: 00000003 00000000 00000000 0001 03 10893 P13838
	// local_inode -> remote_inode
	// 13838 -> 10893
	var candidateInodes []uint64
	inodeMap := make(map[uint64]uint64)
	for _, line := range getSocketLines(proto) {
		if len(line) == 0 {
			continue
		}
		ss := socketStatus{}
		if err := ss.parseUnixProcLine(line); err != nil {
			log.Warningf("Unable to parse line from /proc/net/%s [%s]: %v", proto, line, err)
			continue
		}
		if ss.remoteInode != 0 {
			inodeMap[ss.remoteInode] = ss.inode
		}
		if ss.path == socketFile {
			candidateInodes = append(candidateInodes, ss.inode)
		}
	}
	for i := 0; i < len(candidateInodes); i++ {
		remoteInode, ok := inodeMap[candidateInodes[i]]
		if ok {
			ss := socketStatus{}
			ss.inode = remoteInode
			return &ss
		}
	}
	return nil
}

func findSocket(proto string, matcher func(socketStatus) bool) *socketStatus {
	var ss socketStatus
	for _, line := range getSocketLines(proto) {
		if len(line) == 0 {
			continue
		}
		if err := ss.parseLine(line); err != nil {
			log.Warningf("Unable to parse line from /proc/net/%s [%s]: %v", proto, line, err)
			continue
		}
		if matcher(ss) {
			ss.line = line
			return &ss
		}
	}
	return nil
}

func (ss *socketStatus) parseLine(line string) error {
	fs := strings.Fields(line)
	if len(fs) < 10 {
		return errors.New("insufficient fields")
	}
	if err := ss.local.parse(fs[1]); err != nil {
		return err
	}
	/*
		st64, err := strconv.ParseInt(fmt.Sprintf("0x%s", fs[3]), 0, 32)
		if err != nil {
			return fmt.Errorf("Error parsing ConnectionStatus: %s", err)
		}
		ss.status = ConnectionStatus(st64)
	*/
	if err := ss.remote.parse(fs[2]); err != nil {
		return err
	}
	uid, err := strconv.ParseUint(fs[7], 10, 32)
	if err != nil {
		return err
	}
	ss.uid = int(uid)
	inode, err := strconv.ParseUint(fs[9], 10, 64)
	if err != nil {
		return err
	}
	ss.inode = inode
	return nil
}

// parseUnixProcLine parses lines in /proc/net/unix
func (ss *socketStatus) parseUnixProcLine(line string) error {
	var err error
	fs := strings.Fields(line)
	if len(fs) < 7 || len(fs) > 8 {
		return errors.New("number of fields don't match parser")
	}
	ss.inode, err = strconv.ParseUint(fs[6], 10, 64)
	if err != nil {
		return err
	}
	if len(fs) == 8 {
		ss.path = fs[7]
		if strings.HasPrefix(ss.path, "P") {
			ss.remoteInode, err = strconv.ParseUint(ss.path[1:], 10, 64)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func getSocketLines(proto string) []string {
	path := fmt.Sprintf("/proc/net/%s", proto)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warningf("Error reading %s: %v", path, err)
		return nil
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > 0 {
		lines = lines[1:]
	}
	return lines
}
