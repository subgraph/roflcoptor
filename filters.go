package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"regexp"
	"strings"
	"syscall"
)

var commentRegexp = regexp.MustCompile("^[ \t]*#")

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
				fmt.Printf("Loaded filter for: %s (%d)\n", ff.ExecPath, ff.UserID)
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

func getFilterForPathAndUid(path string, uid int) *ServerClientFilterConfig {
	for _, filter := range loadedFilters {
		if filter.ExecPath == path && filter.UserID == uid {
			return filter
		}
	}
	return nil
}

func checkConfigPermissions(fpath string) error {
	pd := path.Dir(fpath)
	for _, fp := range []string{pd, fpath} {
		if err := checkPathRootPermissions(fp); err != nil {
			return fmt.Errorf("file `%s` is %s", fp, err)
		}
	}
	return nil
}

func checkPathRootPermissions(fpath string) error {
	fstat, err := os.Stat(fpath)
	if err != nil {
		return err
	}
	if (fstat.Mode().Perm() & syscall.S_IWOTH) != 0 {
		return fmt.Errorf("writable by everyone!")
	}
	if (fstat.Mode().Perm()&syscall.S_IWGRP) != 0 && fstat.Sys().(*syscall.Stat_t).Gid != 0 {
		return fmt.Errorf("writable by someone else than root!")
	}
	return nil
}
