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

// or-ctl-filter is a Tor Control Port filter which does bidirectional
// filtering of Tor control port commands with, blocking everything by
// default and only allowing commands specified on one of the "white-lists".
// or-ctl-filter uses several different kinds of white-lists, namely:
// - client-allowed: requires exact string match
// - client-allowed-prefixes: allows the commands if it matches one of the prefixes
// - client-replacements: replaces commands with exact string match with another string
// - client-replacement-prefixes: replaces commands with a prefix match
// - server-...
// It is not only limited to the use case "I want to run Tor Browser on my desktop with a
// system tor service and have 'about:tor' and 'New Identity' work while
// disallowing scary control port commands", but could also be used to trick a program
// into thinking that it gathered the "real" data from the tor control port when instead
// our proxy feed it a bunch of lies, such as:
//    "server-replacement-prefixes": {
//	"250-address=":"250-address=127.0.0.1"
//    },
//

package main

import (
	"github.com/subgraph/fw-daemon/proc"

	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	defaultLogFile    = "or-ctl-filter.log"
	defaultConfigFile = "or-ctl-filter.json"

	controlSocketFile = "/var/run/tor/control"
	torControlAddr    = "127.0.0.1:8851" // Match ControlPort in torrc-defaults.

	cmdProtocolInfo  = "PROTOCOLINFO"
	cmdAuthenticate  = "AUTHENTICATE"
	cmdAuthChallenge = "AUTHCHALLENGE"
	cmdGetInfo       = "GETINFO"
	cmdSignal        = "SIGNAL"

	argSignalNewnym = "NEWNYM"
	argGetinfoSocks = "net/listeners/socks"
	argServerHash   = "SERVERHASH="
	argServerNonce  = "SERVERNONCE="

	respProtocolInfoAuth       = "250-AUTH"
	respProtocolInfoMethods    = "METHODS="
	respProtocolInfoCookieFile = "COOKIEFILE="

	respAuthChallenge = "250 AUTHCHALLENGE "

	authMethodNull       = "NULL"
	authMethodCookie     = "COOKIE"
	authMethodSafeCookie = "SAFECOOKIE"

	authNonceLength   = 32
	authServerHashKey = "Tor safe cookie authentication server-to-controller hash"
	authClientHashKey = "Tor safe cookie authentication controller-to-server hash"

	errAuthenticationRequired = "514 Authentication required\n"
	errUnrecognizedCommand    = "510 Unrecognized command\n"
)

var filteredControlAddr *net.UnixAddr

type ServerClientFilterConfig struct {
	ClientAllowed             []string          `json:"client-allowed"`
	ClientAllowedPrefixes     []string          `json:"client-allowed-prefixes"`
	ClientReplacements        map[string]string `json:"client-replacements"`
	ClientReplacementPrefixes map[string]string `json:"client-replacement-prefixes"`

	ServerAllowed             []string          `json:"server-allowed"`
	ServerAllowedPrefixes     []string          `json:"server-allowed-prefixes"`
	ServerReplacements        map[string]string `json:"server-replacements"`
	ServerReplacementPrefixes map[string]string `json:"server-replacement-prefixes"`
}

type FilterConfig struct {
	Allowed             []string          `json:"allowed"`
	AllowedPrefixes     []string          `json:"allowed-prefixes"`
	Replacements        map[string]string `json:"replacements"`
	ReplacementPrefixes map[string]string `json:"replacement-prefixes"`
}

func hasReplacementCommand(cmd string, replacements map[string]string) (string, bool) {
	log.Print("maybeReplaceCommand\n")
	replacement, ok := replacements[cmd]
	if ok {
		log.Printf("%v true", replacement)
		return replacement, true
	} else {
		log.Printf("%v false", replacement)
		return cmd, false
	}
}

func hasReplacementPrefix(cmd string, replacements map[string]string) (string, bool) {
	log.Print("hasReplacementPrefix")
	for prefix, replacement := range replacements {
		log.Printf("does cmd %s contain prefix %s\n", cmd, prefix)
		if strings.HasPrefix(cmd, prefix) {
			log.Print("true")
			return replacement, true
		}
	}
	log.Print("false")
	return cmd, false
}

func isCommandAllowed(cmd string, allowed []string) bool {
	log.Print("isCommandAllowed")
	for i := 0; i < len(allowed); i++ {
		if cmd == allowed[i] {
			log.Print("true")
			return true
		}
	}
	log.Print("false")
	return false
}

func isPrefixAllowed(cmd string, allowed []string) bool {
	log.Print("isPrefixAllowed")
	for i := 0; i < len(allowed); i++ {
		if strings.HasPrefix(cmd, allowed[i]) {
			log.Print("true")
			return true
		}
	}
	log.Print("false")
	return false
}

func readAuthCookie(path string) ([]byte, error) {
	log.Print("read auth cookie")
	// Read the cookie auth file.
	cookie, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading cookie auth file: %s", err)
	}
	return cookie, nil
}

func authSafeCookie(conn net.Conn, connReader *bufio.Reader, cookie []byte) ([]byte, error) {
	log.Print("auth safe cookie")
	clientNonce := make([]byte, authNonceLength)
	if _, err := rand.Read(clientNonce); err != nil {
		return nil, fmt.Errorf("generating AUTHCHALLENGE nonce: %s", err)
	}
	clientNonceStr := hex.EncodeToString(clientNonce)

	// Send and process the AUTHCHALLENGE.
	authChallengeReq := []byte(fmt.Sprintf("%s %s %s\n", cmdAuthChallenge, authMethodSafeCookie, clientNonceStr))
	if _, err := conn.Write(authChallengeReq); err != nil {
		return nil, fmt.Errorf("writing AUTHCHALLENGE request: %s", err)
	}
	line, err := connReader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("reading AUTHCHALLENGE response: %s", err)
	}
	lineStr := strings.TrimSpace(string(line))
	respStr := strings.TrimPrefix(lineStr, respAuthChallenge)
	if respStr == lineStr {
		return nil, fmt.Errorf("parsing AUTHCHALLENGE response")
	}
	splitResp := strings.SplitN(respStr, " ", 2)
	if len(splitResp) != 2 {
		return nil, fmt.Errorf("parsing AUTHCHALLENGE response")
	}
	hashStr := strings.TrimPrefix(splitResp[0], argServerHash)
	serverHash, err := hex.DecodeString(hashStr)
	if err != nil {
		return nil, fmt.Errorf("decoding AUTHCHALLENGE ServerHash: %s", err)
	}
	serverNonceStr := strings.TrimPrefix(splitResp[1], argServerNonce)
	serverNonce, err := hex.DecodeString(serverNonceStr)
	if err != nil {
		return nil, fmt.Errorf("decoding AUTHCHALLENGE ServerNonce: %s", err)
	}

	// Validate the ServerHash.
	m := hmac.New(sha256.New, []byte(authServerHashKey))
	m.Write([]byte(cookie))
	m.Write([]byte(clientNonce))
	m.Write([]byte(serverNonce))
	dervServerHash := m.Sum(nil)
	if !hmac.Equal(serverHash, dervServerHash) {
		return nil, fmt.Errorf("AUTHCHALLENGE ServerHash is invalid")
	}

	// Calculate the ClientHash.
	m = hmac.New(sha256.New, []byte(authClientHashKey))
	m.Write([]byte(cookie))
	m.Write([]byte(clientNonce))
	m.Write([]byte(serverNonce))

	return m.Sum(nil), nil
}

func authenticate(torConn net.Conn, torConnReader *bufio.Reader, appConn net.Conn, appConnReader *bufio.Reader) error {
	var canNull, canCookie, canSafeCookie bool
	var cookiePath string

	log.Print("authenticate")
	// Figure out the best auth method, and where the cookie is if any.
	protocolInfoReq := []byte(fmt.Sprintf("%s\n", cmdProtocolInfo))
	if _, err := torConn.Write(protocolInfoReq); err != nil {
		return fmt.Errorf("writing PROTOCOLINFO request: %s", err)
	}
	for {
		line, err := torConnReader.ReadBytes('\n')
		if err != nil {
			return fmt.Errorf("reading PROTOCOLINFO response: %s", err)
		}
		lineStr := strings.TrimSpace(string(line))
		if !strings.HasPrefix(lineStr, "250") {
			return fmt.Errorf("parsing PROTOCOLINFO response")
		} else if lineStr == "250 OK" {
			break
		}
		splitResp := strings.SplitN(lineStr, " ", 3)
		if splitResp[0] == respProtocolInfoAuth {
			if len(splitResp) == 1 {
				continue
			}

			methodsStr := strings.TrimPrefix(splitResp[1], respProtocolInfoMethods)
			if methodsStr == splitResp[1] {
				continue
			}
			methods := strings.Split(methodsStr, ",")
			for _, method := range methods {
				switch method {
				case authMethodNull:
					canNull = true
				case authMethodCookie:
					canCookie = true
				case authMethodSafeCookie:
					canSafeCookie = true
				}
			}
			log.Print("after method for loop")
			if (canCookie || canSafeCookie) && len(splitResp) == 3 {
				log.Print("can cookie")
				cookiePathStr := strings.TrimPrefix(splitResp[2], respProtocolInfoCookieFile)
				if cookiePathStr == splitResp[2] {
					continue
				}
				cookiePath, err = strconv.Unquote(cookiePathStr)
				if err != nil {
					continue
				}
			}
			log.Print("end?")
		}
	}
	log.Print("end of auth detection")

	// Authenticate using the best possible authentication method.
	var authReq []byte
	if canNull {
		if _, err := torConn.Write([]byte(cmdAuthenticate + "\n")); err != nil {
			return fmt.Errorf("writing AUTHENTICATE request: %s", err)
		}
	} else if (canCookie || canSafeCookie) && (cookiePath != "") {
		// Read the auth cookie.
		cookie, err := readAuthCookie(cookiePath)
		if err != nil {
			return err
		}
		if canSafeCookie {
			cookie, err = authSafeCookie(torConn, torConnReader, cookie)
			if err != nil {
				return err
			}
		}
		cookieStr := hex.EncodeToString(cookie)
		authReq = []byte(fmt.Sprintf("%s %s\n", cmdAuthenticate, cookieStr))
		if _, err := torConn.Write(authReq); err != nil {
			return fmt.Errorf("writing AUTHENTICATE request: %s", err)
		}
	} else {
		return fmt.Errorf("no supported authentication methods")
	}
	_, err := torConnReader.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("reading AUTHENTICATE response: %s", err)
	}
	return nil
}

func syncedWrite(l *sync.Mutex, conn net.Conn, buf []byte) (int, error) {
	log.Print("synced write")
	l.Lock()
	defer l.Unlock()
	return conn.Write(buf)
}

func filterCommand(cmd, failureCmd string, writeFunc func([]byte) (int, error), errChan chan error, filterConfig *FilterConfig) {
	var err error
	replacement, ok := hasReplacementPrefix(cmd, filterConfig.ReplacementPrefixes)
	if ok {
		log.Printf("replacing %s with %s", cmd, replacement)
		if _, err = writeFunc([]byte(replacement + "\n")); err != nil {
			errChan <- err
		}
		return
	}
	replacement, ok = hasReplacementCommand(cmd, filterConfig.Replacements)
	if ok {
		log.Printf("replacing %s with %s", cmd, replacement)
		if _, err = writeFunc([]byte(replacement + "\n")); err != nil {
			errChan <- err
		}
		return
	}
	if isPrefixAllowed(cmd, filterConfig.AllowedPrefixes) {
		log.Printf("%s has an allowed prefix", cmd)
		if _, err = writeFunc([]byte(cmd + "\n")); err != nil {
			errChan <- err
		}
		return
	}
	if isCommandAllowed(cmd, filterConfig.Allowed) {
		log.Printf("%s is allowed", cmd)
		if _, err = writeFunc([]byte(cmd + "\n")); err != nil {
			errChan <- err
		}
		return
	}
	log.Printf("denied %s", cmd)
	if failureCmd != "" {
		if _, err = writeFunc([]byte(failureCmd + "\n")); err != nil {
			errChan <- err
		}
	}
}

func filterConnection(appConn net.Conn, filterConfig *ServerClientFilterConfig) {
	defer appConn.Close()

	clientAddr := appConn.RemoteAddr()
	log.Printf("New app connection from: %s\n", clientAddr)

	torConn, err := net.DialUnix("unix", nil, filteredControlAddr)
	if err != nil {
		log.Printf("Failed to connect to the tor control port: %s\n", err)
		return
	}
	defer torConn.Close()

	// Authenticate with the real control port, and wait for the application to
	// authenticate.
	torConnReader := bufio.NewReader(torConn)
	appConnReader := bufio.NewReader(appConn)
	if err = authenticate(torConn, torConnReader, appConn, appConnReader); err != nil {
		log.Printf("Failed to authenticate: %s\n", err)
		return
	}

	// Start filtering commands as appropriate.
	errChan := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	var appConnLock sync.Mutex
	writeAppConn := func(b []byte) (int, error) {
		appConnLock.Lock()
		defer appConnLock.Unlock()
		return appConn.Write(b)
	}

	// tor to application chatter.
	go func() {
		defer wg.Done()
		defer appConn.Close()
		defer torConn.Close()

		for {
			line, err := torConnReader.ReadBytes('\n')
			if err != nil {
				errChan <- err
				break
			}
			lineStr := strings.TrimSpace(string(line))
			log.Printf("A<-T: [%s]\n", lineStr)

			serverFilterConfig := FilterConfig{
				Allowed:             filterConfig.ServerAllowed,
				AllowedPrefixes:     filterConfig.ServerAllowedPrefixes,
				Replacements:        filterConfig.ServerReplacements,
				ReplacementPrefixes: filterConfig.ServerReplacementPrefixes,
			}
			filterCommand(lineStr, "250 OK", writeAppConn, errChan, &serverFilterConfig)
		}
	}()

	// application to tor chatter
	go func() {
		defer wg.Done()
		defer torConn.Close()
		defer appConn.Close()

		for {
			line, err := appConnReader.ReadBytes('\n')
			if err != nil {
				errChan <- err
				break
			}
			lineStr := strings.TrimSpace(string(line))
			log.Printf("A->T: [%s]\n", lineStr)

			clientFilterConfig := FilterConfig{
				Allowed:             filterConfig.ClientAllowed,
				AllowedPrefixes:     filterConfig.ClientAllowedPrefixes,
				Replacements:        filterConfig.ClientReplacements,
				ReplacementPrefixes: filterConfig.ClientReplacementPrefixes,
			}

			writeToTor := func(line []byte) (int, error) {
				var err error
				n := 0
				if n, err = torConn.Write([]byte(line)); err != nil { // XXX need \n ?
					errChan <- err
				}
				return n, err
			}
			filterCommand(lineStr, "", writeToTor, errChan, &clientFilterConfig)
		}
	}()

	wg.Wait()
	if len(errChan) > 0 {
		err = <-errChan
		log.Printf("Closed client connection from: %s: %s\n", clientAddr, err)
	} else {
		log.Printf("Closed client connection from: %s\n", clientAddr)
	}
}

func main() {
	var enableLogging bool
	var logFile string
	var configFile string
	var filterConfig ServerClientFilterConfig
	var listenPort, listenIp string
	var err error

	flag.BoolVar(&enableLogging, "enable-logging", false, "enable logging")
	flag.StringVar(&logFile, "log-file", defaultLogFile, "log file")
	flag.StringVar(&configFile, "config-file", defaultConfigFile, "filtration config file")
	flag.StringVar(&listenPort, "listen-port", "", "TCP port to listen on")
	flag.StringVar(&listenIp, "listen-ip", "", "IP address to listen on")
	flag.Parse()

	// Deal with filtration configuration.
	if configFile != "" {
		file, e := ioutil.ReadFile(configFile)
		if e != nil {
			panic("failed to read JSON filter config")
		}
		json.Unmarshal(file, &filterConfig)
	} else {
		panic("no filter config specified")
	}

	// Deal with logging.
	if !enableLogging {
		log.SetOutput(ioutil.Discard)
	} else if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("Failed to create log file: %s\n", err)
		}
		log.SetOutput(f)
	}

	filteredControlAddr, err = net.ResolveUnixAddr("unix", controlSocketFile)
	if err != nil {
		log.Fatalf("Failed to resolve the control port: %s\n", err)
	}

	// Initialize the listener
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%s", listenIp, listenPort))
	if err != nil {
		log.Fatalf("Failed to listen on the filter port: %s\n", err)
	}
	defer ln.Close()

	// Listen for incoming connections, and dispatch workers.
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to Accept(): %s\n", err)
			continue
		}

		var dstIp net.IP

		fields := strings.Split(conn.RemoteAddr().String(), ":")
		port_str := fields[1]

		dstIp = net.ParseIP(listenIp)
		if dstIp == nil {
			panic("net.ParseIP fail")
		}

		aP, _ := strconv.ParseUint(port_str, 10, 16)
		bP, _ := strconv.ParseUint(listenPort, 10, 16)
		procInfo := proc.LookupTCPSocketProcess(uint16(aP), dstIp, uint16(bP))
		if procInfo == nil {
			panic("No proc found")
		}

		fmt.Printf("proc info: uid %d pid %d execPath %s CmdLine %s\n", procInfo.Uid, procInfo.Pid, procInfo.ExePath, procInfo.CmdLine)
		go filterConnection(conn, &filterConfig)
	}
}
