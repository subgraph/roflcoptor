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
	"log"
	"os"
	"os/signal"
)

// RoflcoptorConfig is used to configure our
// tor contorl port filtering proxy daemon
type RoflcoptorConfig struct {
	LogFile           string
	FiltersPath       string
	Listeners         []AddrString
	TorControlNet     string
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

	fmt.Println(config)

	log.SetPrefix("ROFLCopTor ")
	if config.LogFile == "-" {
		log.SetOutput(os.Stderr)
	} else if config.LogFile != "" {
		f, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("Failed to create log file: %s\n", err)
		}
		log.SetOutput(f)
	}

	sigKillChan := make(chan os.Signal, 1)
	signal.Notify(sigKillChan, os.Interrupt, os.Kill)

	proxyListener := NewProxyListener(config, watchMode)
	proxyListener.StartListeners()
	defer proxyListener.StopListeners()
	for {
		select {
		case <-sigKillChan:
			return
		}
	}
}
