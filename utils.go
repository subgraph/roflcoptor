package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"syscall"

	"github.com/subgraph/roflcoptor/common"
)

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
		return fmt.Errorf("writable by everyone")
	}
	if (fstat.Mode().Perm()&syscall.S_IWGRP) != 0 && fstat.Sys().(*syscall.Stat_t).Gid != 0 {
		return fmt.Errorf("writable by someone else than root")
	}
	return nil
}

func loadConfiguration(configFilePath string) (*common.RoflcoptorConfig, error) {
	config := common.RoflcoptorConfig{}
	file, err := os.Open(configFilePath)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(file)
	bs := ""
	for scanner.Scan() {
		line := scanner.Text()
		if !common.CommentRegexp.MatchString(line) {
			bs += line + "\n"
		}
	}
	if err := json.Unmarshal([]byte(bs), &config); err != nil {
		return nil, err
	}
	return &config, nil
}
