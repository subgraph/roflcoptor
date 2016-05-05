/*
 * main.go - or-ctl-filter
 * Copyright (C) 2014  Yawning Angel
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// or-ctl-filter is a Tor Control Port filter daemon which does bidirectional
// filtering of Tor control port commands with, blocking everything by
// default and only allowing commands specified on one of the "white-lists".
// or-ctl-filter uses several different kinds of white-lists, namely:
//
// - client-allowed: requires exact string match
// - client-allowed-prefixes: allows the commands if it matches one of the prefixes
// - client-replacements: replaces commands with exact string match with another string
// - client-replacement-prefixes: replaces commands with a prefix match
// - server-...
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
	"sync"
)

// RoflcoptorConfig is used to configure our
// tor contorl port filtering proxy daemon
type RoflcoptorConfig struct {
	LogFile           string
	FiltersPath       string
	ListenNet         string
	ListenAddress     string
	TorControlNet     string
	TorControlAddress string
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

	var wg sync.WaitGroup
	proxyListener := NewProxyListener(config, &wg, watchMode)
	proxyListener.StartListeners()
	wg.Wait()
}
