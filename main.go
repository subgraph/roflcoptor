// roflcoptor is a Tor Control Port filter daemon which does bidirectional
// filtering.
//
// It is not only limited to the use case "I want to run Tor Browser on my desktop with a
// system tor service and have 'about:tor' and 'New Identity' work while
// disallowing scary control port commands", but could also be used to trick a program
// into thinking that it gathered the "real" data from the tor control port when instead
// our proxy feed it a bunch of lies, such as:
//
//    "server-replacement-prefixes": {
//	     "250-address=":"250-address=127.0.0.1"
//    },
//

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/op/go-logging"
	"github.com/subgraph/procsnitchd/client"
)

var log = logging.MustGetLogger("roflcoptor")

var logFormat = logging.MustStringFormatter(
	"%{level:.4s} %{id:03x} %{message}",
)
var ttyFormat = logging.MustStringFormatter(
	"%{color}%{time:15:04:05} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}",
)

const ioctlReadTermios = 0x5401

func isTerminal(fd int) bool {
	var termios syscall.Termios
	_, _, err := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), ioctlReadTermios, uintptr(unsafe.Pointer(&termios)), 0, 0, 0)
	return err == 0
}

func setupLoggerBackend() logging.LeveledBackend {
	format := logFormat
	if isTerminal(int(os.Stderr.Fd())) {
		format = ttyFormat
	}
	backend := logging.NewLogBackend(os.Stderr, "", 0)
	formatter := logging.NewBackendFormatter(backend, format)
	leveler := logging.AddModuleLevel(formatter)
	leveler.SetLevel(logging.INFO, "roflcoptor")
	return leveler
}

// RoflcoptorConfig is used to configure our
// tor contorl port filtering proxy daemon
type RoflcoptorConfig struct {
	// ProcSnitchSocketFile is the UNIX domain socket on which procsnitchd listens
	ProcSnitchSocketFile string
	// FiltersPath is the directory where filter rules are kept
	FiltersPath string
	// Listeners for non-Oz applications
	Listeners []AddrString
	// TorControlNet network for tor control port
	TorControlNet string
	// TorControlNet address for tor control port
	TorControlAddress string
}

// AddrString represents a network endpoint with two strings
type AddrString struct {
	Net     string
	Address string
}

func loadConfiguration(configFilePath string) (*RoflcoptorConfig, error) {
	config := RoflcoptorConfig{}
	file, err := os.Open(configFilePath)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(file)
	bs := ""
	for scanner.Scan() {
		line := scanner.Text()
		if !commentRegexp.MatchString(line) {
			bs += line + "\n"
		}
	}
	if err := json.Unmarshal([]byte(bs), &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func main() {
	var configFilePath string
	var watchMode bool
	var config *RoflcoptorConfig
	var err error

	flag.StringVar(&configFilePath, "config", "", "configuration file")
	flag.BoolVar(&watchMode, "watch", false, "watch-mode of operation will default to unfiltered-allow policy")
	flag.Parse()

	// Load configuration file
	config, err = loadConfiguration(configFilePath)
	if err != nil {
		panic(err)
	}

	logBackend := setupLoggerBackend()
	log.SetBackend(logBackend)

	if os.Geteuid() == 0 {
		log.Error("Must be run as a non-root user!")
		os.Exit(1)
	}

	sigKillChan := make(chan os.Signal, 1)
	signal.Notify(sigKillChan, os.Interrupt, os.Kill)

	log.Notice("roflcoptor startup!")
	procsnitchClient := client.NewSnitchClient(config.ProcSnitchSocketFile)
	err = procsnitchClient.Start()
	if err != nil {
		log.Criticalf("procsnitchClient failed to connect: %s", err)
		return
	}
	defer procsnitchClient.Stop()

	proxyListener := NewProxyListener(config, watchMode, procsnitchClient)
	proxyListener.StartListeners()
	defer proxyListener.StopListeners()
	for {
		select {
		case <-sigKillChan:
			log.Notice("roflcoptor shutdown!")
			return
		}
	}
}
