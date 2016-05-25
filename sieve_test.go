package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestFilter(t *testing.T) {
	allowed := []string{"meow", "dow"}
	allowedPrefixes := []string{"fu", "do"}
	replacements := map[string]string{
		"123":     "456",
		"how now": "brown cow",
	}
	replacementPrefixes := map[string]string{
		"the quick brown": "but not the burning of books",
	}
	sieve := NewSieve(allowed, allowedPrefixes, replacements, replacementPrefixes)

	tests := []struct {
		in   string
		want string
	}{
		{
			"dow",
			"dow",
		},
		{
			"cow",
			"",
		},
		{
			"meow",
			"meow",
		},
		{
			"fufuyyyyyyyyyy",
			"fufuyyyyyyyyyy",
		},
		{
			"do not want",
			"do not want",
		},
		{
			"1234",
			"",
		},
		{
			"123",
			"456",
		},
		{
			"how now brown cow",
			"",
		},
		{
			"how now",
			"brown cow",
		},
		{
			"the quick brown fox jumped over the capitalist",
			"but not the burning of books",
		},
		{
			"the quick car broke down",
			"",
		},
	}

	for _, test := range tests {
		output := sieve.Filter(test.in)
		if output != test.want {
			t.Errorf("input '%s'\nproduced output '%s'\nbut wanted '%s'\n", test.in, output, test.want)
			t.Fail()
		}
	}
}

func TestLoadFilters(t *testing.T) {
	p := NewPolicyList()

	err := p.LoadFilters("not_exist")
	if err == nil {
		t.Errorf("LoadFilters should have err`ed")
		t.Fail()
	}

	// we have no policies loaded so this should fail
	policy := p.getFilterForPath("not_an_existent_exec_path")
	if policy != nil {
		t.Errorf("getFilterForPath should have err`ed")
		t.Fail()
	}

	invalidContent := []byte("temporary file's content")
	validContent := []byte(`
{
    "AuthNetAddr" : "tcp",
    "AuthAddr" : "127.0.0.1:6651",
    "user-id" : 123,
    "exec-path": "/srv/oz/rootfs/home/user/.local/share/torbrowser/tbb/x86_64/tor-browser_en-US/Browser/firefox",
    "client-allowed" : ["SIGNAL NEWNYM","GETINFO net/listeners/socks", "GETCONF UseBridges", "GETCONF Bridge",
			"GETCONF Socks4Proxy", "GETCONF Socks5Proxy", "GETCONF HTTPSProxy",
		       "GETCONF ReachableAddresses"],
    "client-allowed-prefixes" : ["AUTHENTICATE"],
    "client-replacements" : {},
    "client-replacement-prefixes" : {},
    "server-allowed" : ["250 OK", "250-net/listeners/socks=\"127.0.0.1:9050\"", "250 UseBridges=0",
		       "250 ReachableAddresses"],
    "server-allowed-prefixes" : ["650 STREAM"],
    "server-replacement-prefixes" : {}
}`)

	dir, err := ioutil.TempDir("", "filter_load_test")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	file1 := filepath.Join(dir, "invalid_app_filter.json")
	if err := ioutil.WriteFile(file1, invalidContent, 0666); err != nil {
		panic(err)
	}

	file2 := filepath.Join(dir, "valid_app_filter.json")
	if err := ioutil.WriteFile(file2, validContent, 0666); err != nil {
		panic(err)
	}

	err = p.LoadFilters(dir)
	if err != nil {
		t.Errorf("LoadFilters should have succeeded")
		t.Fail()
	}

	// we have no policies with this exec path; should fail
	policy = p.getFilterForPath("not_an_existent_exec_path")
	if policy != nil {
		t.Errorf("getFilterForPath should have err`ed")
		t.Fail()
	}

	policy = p.getFilterForPathAndUID("/srv/oz/rootfs/home/user/.local/share/torbrowser/tbb/x86_64/tor-browser_en-US/Browser/firefox", 123)
	if policy == nil {
		t.Errorf("getFilterForPathAndUID should have succeeded")
		t.Fail()
	}

	if len(p.loadedFilters) != 1 {
		t.Errorf("LoadFilters should have loaded one filter.")
		t.Fail()
	}
}

func TestLoadFilterFile(t *testing.T) {
	p := NewPolicyList()
	policy, err := p.LoadFilterFile("not_exist")
	if err == nil {
		t.Errorf("LoadFilterFile should have err`ed")
		t.Fail()
	}
	dir, err := ioutil.TempDir("", "filter_load_filter_file")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	file1 := filepath.Join(dir, "vlad")
	invalidContent := "{}"
	if err := ioutil.WriteFile(file1, []byte(invalidContent), 0666); err != nil {
		panic(err)
	}
	policy, err = p.LoadFilterFile(file1)
	if policy != nil && err != nil {
		t.Errorf("LoadFilterFile should have err`ed")
		t.Fail()
	}
}
