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
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/op/go-logging"
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

func stringToLogLevel(level string) (logging.Level, error) {

	switch level {
	case "DEBUG":
		return logging.DEBUG, nil
	case "INFO":
		return logging.INFO, nil
	case "NOTICE":
		return logging.NOTICE, nil
	case "WARNING":
		return logging.WARNING, nil
	case "ERROR":
		return logging.ERROR, nil
	case "CRITICAL":
		return logging.CRITICAL, nil
	}
	return -1, fmt.Errorf("invalid logging level %s", level)
}

func setupLoggerBackend(level logging.Level) logging.LeveledBackend {
	format := logFormat
	if isTerminal(int(os.Stderr.Fd())) {
		format = ttyFormat
	}
	backend := logging.NewLogBackend(os.Stderr, "", 0)
	formatter := logging.NewBackendFormatter(backend, format)
	leveler := logging.AddModuleLevel(formatter)
	leveler.SetLevel(level, "roflcoptor")
	return leveler
}

// RoflcoptorConfig is used to configure our
// tor contorl port filtering proxy daemon
type RoflcoptorConfig struct {
	// FiltersPath is the directory where filter rules are kept
	FiltersPath string
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
	var logLevel string
	var config *RoflcoptorConfig
	var level logging.Level
	var err error

	flag.StringVar(&configFilePath, "config", "", "configuration file")
	flag.BoolVar(&watchMode, "watch", false, "watch-mode of operation will default to unfiltered-allow policy")
	flag.StringVar(&logLevel, "log_level", "INFO", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	flag.Parse()

	if configFilePath == "" {
		log.Error("you must specify a configuration file")
		flag.Usage()
		os.Exit(1)
	}

	// Load configuration file
	config, err = loadConfiguration(configFilePath)
	if err != nil {
		panic(err)
	}

	level, err = stringToLogLevel(logLevel)
	if err != nil {
		log.Critical("Invalid logging-level specified.")
		os.Exit(1)
	}
	logBackend := setupLoggerBackend(level)
	log.SetBackend(logBackend)

	if os.Geteuid() == 0 {
		log.Error("Must be run as a non-root user!")
		os.Exit(1)
	}

	sigKillChan := make(chan os.Signal, 1)
	signal.Notify(sigKillChan, os.Interrupt, os.Kill)

	log.Notice("roflcoptor startup!")
	proxyListener := NewProxyListener(config, watchMode)
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
