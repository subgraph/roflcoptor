package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"
)

// SievePolicyJSONConfig defines the bidirectional filtration policy
type SievePolicyJSONConfig struct {
	AuthNetAddr string `json:"AuthNetAddr"`
	AuthAddr    string `json:"AuthAddr"`
	ExecPath    string `json:"exec-path"`
	UserID      int    `json:"user-id",omitempty`

	ClientAllowed             []string          `json:"client-allowed"`
	ClientAllowedPrefixes     []string          `json:"client-allowed-prefixes"`
	ClientRegexes             []string          `json:"client-regex"`
	ClientScrubRegexes        map[string]string `json:"client-scrub-regexes"` // not likely to be used
	ClientReplacements        map[string]string `json:"client-replacements"`
	ClientReplacementPrefixes map[string]string `json:"client-replacement-prefixes"`

	ServerAllowed             []string          `json:"server-allowed"`
	ServerAllowedPrefixes     []string          `json:"server-allowed-prefixes"`
	ServerRegexes             []string          `json:"server-regexes"`
	ServerScrubRegexes        map[string]string `json:"server-scrub-regexes"`
	ServerReplacements        map[string]string `json:"server-replacements"`
	ServerReplacementPrefixes map[string]string `json:"server-replacement-prefixes"`
}

// GetSieves -> client sieve, server sieve
func (p *SievePolicyJSONConfig) GetSieves() (*Sieve, *Sieve) {
	clientSieve := NewSieve(p.ClientAllowed, p.ClientAllowedPrefixes, p.ClientRegexes, p.ClientScrubRegexes, p.ClientReplacements, p.ClientReplacementPrefixes)
	serverSieve := NewSieve(p.ServerAllowed, p.ServerAllowedPrefixes, p.ServerRegexes, p.ServerScrubRegexes, p.ServerReplacements, p.ServerReplacementPrefixes)
	return clientSieve, serverSieve
}

// Sieve represents unidirectional message filtration
type Sieve struct {
	Allowed             []string
	AllowedPrefixes     []string
	Regexes             []string
	ScrubRegexes        map[string]string
	Replacements        map[string]string
	ReplacementPrefixes map[string]string
}

// NewSieve creates a new Sieve
func NewSieve(allowed, allowedPrefixes, regexes []string, scrubs, replacements, replacementPrefixes map[string]string) *Sieve {
	s := Sieve{
		Allowed:             allowed,
		AllowedPrefixes:     allowedPrefixes,
		Regexes:             regexes,
		ScrubRegexes:        scrubs,
		Replacements:        replacements,
		ReplacementPrefixes: replacementPrefixes,
	}
	return &s
}

// Filter performs filtration on the message
// Filter(message) -> outputMessage
// If an empty string is returned this means the
// message was denied because our default policy is deny
// if there is no allow or replace rule specified.
func (s *Sieve) Filter(message string) string {
	replacement, ok := s.hasReplacementPrefix(message)
	if ok {
		return replacement
	}

	replacement, ok = s.hasReplacementCommand(message)
	if ok {
		return replacement
	}

	scrubbed, ok := s.isScrubbed(message)
	if ok {
		return scrubbed
	}

	if s.isPrefixAllowed(message) {
		return message
	}

	if s.isMatchedRegex(message) {
		return message
	}

	if s.isCommandAllowed(message) {
		return message
	}

	return ""
}

func (s *Sieve) hasReplacementPrefix(message string) (string, bool) {
	for prefix, replacement := range s.ReplacementPrefixes {
		if strings.HasPrefix(message, prefix) {
			return replacement, true
		}
	}
	return message, false
}

func (s *Sieve) hasReplacementCommand(message string) (string, bool) {
	replacement, ok := s.Replacements[message]
	if ok {
		return replacement, true
	}
	return message, false
}

func (s *Sieve) isScrubbed(message string) (string, bool) {
	/* Multiple may match. Return replacement for first match. */
	for regexstr, replacement := range s.ScrubRegexes {
		reg, err := regexp.Compile(regexstr)
		if err != nil {
			log.Fatal(err)
		}
		if reg.MatchString(message) {
			scrubbed := reg.ReplaceAllString(message, replacement)
			return scrubbed, true
		}
	}
	return message, false
}

func (s *Sieve) isPrefixAllowed(message string) bool {
	for i := 0; i < len(s.AllowedPrefixes); i++ {
		if strings.HasPrefix(message, s.AllowedPrefixes[i]) {
			return true
		}
	}
	return false
}

func (s *Sieve) isMatchedRegex(message string) bool {
	for i := 0; i < len(s.Regexes); i++ {
		reg, err := regexp.Compile(s.Regexes[i])
		if err != nil {
			log.Fatal(err)
		}
		if reg.MatchString(message) {
			return true
		}
	}
	return false
}

func (s *Sieve) isCommandAllowed(message string) bool {
	for i := 0; i < len(s.Allowed); i++ {
		if message == s.Allowed[i] {
			return true
		}
	}
	return false
}

var commentRegexp = regexp.MustCompile("^[ \t]*#")

// PolicyList represents a list of policies
type PolicyList struct {
	loadedFilters []*SievePolicyJSONConfig
}

// NewPolicyList creates a new PolicyList
func NewPolicyList() PolicyList {
	policyList := PolicyList{}
	return policyList
}

func (p *PolicyList) ListenerExists(policy *SievePolicyJSONConfig) bool {
	for _, n := range p.loadedFilters {
		if policy.AuthNetAddr == n.AuthNetAddr && policy.AuthAddr == n.AuthAddr {
			return true
		}
	}
	return false
}

// LoadFilters loads filter files
func (p *PolicyList) LoadFilters(directoryPath string) error {
	fs, err := ioutil.ReadDir(directoryPath)
	if err != nil {
		return err
	}
	lf := []*SievePolicyJSONConfig{}
	for _, f := range fs {
		if !f.IsDir() {
			name := path.Join(directoryPath, f.Name())
			if strings.HasSuffix(f.Name(), ".json") {
				ff, err := p.LoadFilterFile(name)
				if err != nil || ff == nil {
					log.Noticef("error loading '%s': %v", f.Name(), err)
					continue
				}
				if ff.AuthNetAddr != "" {
					if p.ListenerExists(ff) {
						return fmt.Errorf("listener already configured: %s:%s", ff.AuthNetAddr, ff.AuthAddr)
					}
				}
				log.Noticef("Loaded filter for: %s (%d)\n", ff.ExecPath, ff.UserID)
				lf = append([]*SievePolicyJSONConfig(lf), ff)
				p.loadedFilters = lf
			}
		}
	}
	p.loadedFilters = lf
	return nil
}

// LoadFilterFile loads the specified filter file
func (p *PolicyList) LoadFilterFile(filePath string) (*SievePolicyJSONConfig, error) {
	//if err := checkConfigPermissions(fpath); err != nil {
	//	return nil, err
	//}

	file, err := os.Open(filePath)
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
	f := &SievePolicyJSONConfig{
		UserID: -1,
	}
	if err := json.Unmarshal([]byte(bs), f); err != nil {
		return nil, err
	}
	if f.ExecPath == "" {
		return nil, nil
	}
	return f, nil
}

func (p *PolicyList) getListenerAddresses() []AddrString {
	addrList := []AddrString{}
	for _, filter := range p.loadedFilters {
		if filter.AuthNetAddr != "" && filter.AuthAddr != "" {
			l := AddrString{
				Net:     filter.AuthNetAddr,
				Address: filter.AuthAddr,
			}
			addrList = append(addrList, l)
		}
	}
	return addrList
}

func (p *PolicyList) getAuthenticatedPolicyAddresses() (map[AddrString]*SievePolicyJSONConfig, error) {
	listenerMap := make(map[AddrString]*SievePolicyJSONConfig)
	for _, filter := range p.loadedFilters {
		if filter.AuthNetAddr != "" && filter.AuthAddr != "" {
			addrString := AddrString{
				Net:     filter.AuthNetAddr,
				Address: filter.AuthAddr,
			}
			listenerMap[addrString] = filter
		}
	}
	return listenerMap, nil
}

func (p *PolicyList) getFilterForPath(path string) *SievePolicyJSONConfig {
	for _, filter := range p.loadedFilters {
		if filter.ExecPath == path && filter.UserID == -1 {
			return filter
		}
	}
	return nil
}

func (p *PolicyList) getFilterForPathAndUID(path string, uid int) *SievePolicyJSONConfig {
	for _, filter := range p.loadedFilters {
		if filter.ExecPath == path && filter.UserID == uid {
			return filter
		}
	}
	return nil
}
