package main

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path"
	"regexp"
	"strings"
)

var commentRegexp = regexp.MustCompile("^[ \t]*#")

// ServerClientFilterConfig defines an application filter policy
type ServerClientFilterConfig struct {
	ExecPath                  string            `json:"exec-path"`
	UserID                    int               `json:"user-id",omitempty`
	ClientAllowed             []string          `json:"client-allowed"`
	ClientAllowedPrefixes     []string          `json:"client-allowed-prefixes"`
	ClientReplacements        map[string]string `json:"client-replacements"`
	ClientReplacementPrefixes map[string]string `json:"client-replacement-prefixes"`

	ServerAllowed             []string          `json:"server-allowed"`
	ServerAllowedPrefixes     []string          `json:"server-allowed-prefixes"`
	ServerReplacements        map[string]string `json:"server-replacements"`
	ServerReplacementPrefixes map[string]string `json:"server-replacement-prefixes"`
}

// FilterConfig defines a return filter policy
type FilterConfig struct {
	Allowed             []string          `json:"allowed"`
	AllowedPrefixes     []string          `json:"allowed-prefixes"`
	Replacements        map[string]string `json:"replacements"`
	ReplacementPrefixes map[string]string `json:"replacement-prefixes"`
}

func newDefaultFilter() *ServerClientFilterConfig {
	return &ServerClientFilterConfig{
		UserID: -1,
	}
}

var loadedFilters []*ServerClientFilterConfig

func loadFilters(dpath string) ([]*ServerClientFilterConfig, error) {
	fs, err := ioutil.ReadDir(dpath)
	if err != nil {
		return nil, err
	}
	lf := []*ServerClientFilterConfig{}
	for _, f := range fs {
		if !f.IsDir() {
			name := path.Join(dpath, f.Name())
			if strings.HasSuffix(f.Name(), ".json") {
				ff, err := loadFilterFile(name)
				if err != nil || ff == nil {
					log.Printf("error loading '%s': %v", f.Name(), err)
					continue
				}
				log.Printf("Loaded filter for: %s (%d)\n", ff.ExecPath, ff.UserID)
				lf = append(lf, ff)
			}
		}
	}

	loadedFilters = lf
	return lf, nil
}

func loadFilterFile(fpath string) (*ServerClientFilterConfig, error) {
	//if err := checkConfigPermissions(fpath); err != nil {
	//	return nil, err
	//}

	file, err := os.Open(fpath)
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
	f := newDefaultFilter()
	if err := json.Unmarshal([]byte(bs), f); err != nil {
		return nil, err
	}
	if f.ExecPath == "" {
		return nil, nil
	}
	return f, nil
}

func getFilterForPath(path string) *ServerClientFilterConfig {
	for _, filter := range loadedFilters {
		if filter.ExecPath == path && filter.UserID == -1 {
			return filter
		}
	}
	return nil
}

func getFilterForPathAndUID(path string, uid int) *ServerClientFilterConfig {
	for _, filter := range loadedFilters {
		if filter.ExecPath == path && filter.UserID == uid {
			return filter
		}
	}
	return nil
}

func hasReplacementCommand(cmd string, replacements map[string]string) (string, bool) {
	log.Print("maybeReplaceCommand\n")
	replacement, ok := replacements[cmd]
	if ok {
		log.Printf("%v true", replacement)
		return replacement, true
	}
	log.Printf("%v false", replacement)
	return cmd, false
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
