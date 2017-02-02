package common

import (
	"regexp"
)

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

var CommentRegexp = regexp.MustCompile("^[ \t]*#")
