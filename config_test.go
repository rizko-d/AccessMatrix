package accessmatrix

import (
	"strings"
	"testing"
)

const exampleConfig = `{"version":1,"base_url":"http://127.0.0.1:8080","identities":[{"name":"alice","header":"Authorization","prefix":"Bearer ","token_env":"ALICE_TOKEN","check":{"path":"/me","assertions":[{"pointer":"/id","equals":"alice"}]}},{"name":"anonymous","anonymous":true}],"tests":[{"id":"alice-invoice","method":"GET","path":"/invoices/alice-1","control":"alice","assertions":[{"pointer":"/id","equals":"alice-1"},{"pointer":"/owner","equals":"alice"}],"expectations":{"alice":{"access":"allow","statuses":[200]},"anonymous":{"access":"deny","statuses":[401,403,404]}}}]}`

func configFor(t *testing.T, base string) Config {
	t.Helper()
	c, err := Load(strings.NewReader(exampleConfig))
	if err != nil {
		t.Fatal(err)
	}
	c.BaseURL = base
	return c
}

func TestLoadRejectsUnsafeOrAmbiguousJSON(t *testing.T) {
	cases := map[string]string{
		"unknown":           strings.Replace(exampleConfig, `"version":1`, `"unknown":1,"version":1`, 1),
		"trailing":          exampleConfig + `{}`,
		"duplicate":         strings.Replace(exampleConfig, `"version":1`, `"version":0,"version":1`, 1),
		"nested duplicate":  strings.Replace(exampleConfig, `"equals":"alice"`, `"equals":{"id":1,"id":2}`, 1),
		"escaped duplicate": strings.Replace(exampleConfig, `"version":1`, `"vers\u0069on":0,"version":1`, 1),
		"null":              `null`,
		"malformed":         `{"version":`,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(strings.NewReader(text)); err == nil {
				t.Fatal("accepted invalid JSON")
			}
		})
	}
}

func TestValidateSecurityBoundaries(t *testing.T) {
	cases := map[string]func(*Config){
		"version":              func(c *Config) { c.Version = 2 },
		"public http":          func(c *Config) { c.BaseURL = "http://example.com" },
		"userinfo":             func(c *Config) { c.BaseURL = "https://alice:secret@example.com" },
		"origin path":          func(c *Config) { c.BaseURL += "/" },
		"origin query":         func(c *Config) { c.BaseURL += "?token=secret" },
		"timeout":              func(c *Config) { c.TimeoutMS = 120001 },
		"negative timeout":     func(c *Config) { c.TimeoutMS = -1 },
		"body limit":           func(c *Config) { c.MaxBodyBytes = 16*1024*1024 + 1 },
		"negative body":        func(c *Config) { c.MaxBodyBytes = -1 },
		"duplicate identity":   func(c *Config) { c.Identities[1].Name = "alice" },
		"unreadable identity":  func(c *Config) { c.Identities[0].Name = "alice\n" },
		"duplicate test":       func(c *Config) { c.Tests = append(c.Tests, c.Tests[0]) },
		"mutation":             func(c *Config) { c.Tests[0].Method = "POST" },
		"no identity check":    func(c *Config) { c.Identities[0].Check = nil },
		"anonymous credential": func(c *Config) { c.Identities[1].TokenEnv = "SECRET" },
		"anonymous check":      func(c *Config) { c.Identities[1].Check = c.Identities[0].Check },
		"cookie":               func(c *Config) { c.Identities[0].Header = "Cookie" },
		"header injection":     func(c *Config) { c.Identities[0].Prefix = "Bearer\r\n" },
		"invalid env":          func(c *Config) { c.Identities[0].TokenEnv = "TOKEN=bad" },
		"no control":           func(c *Config) { c.Tests[0].Control = "missing" },
		"denied control":       func(c *Config) { c.Tests[0].Control = "anonymous" },
		"empty expectations":   func(c *Config) { c.Tests[0].Expectations = nil },
		"unknown expectation":  func(c *Config) { c.Tests[0].Expectations["other"] = Expectation{Access: "deny", Statuses: []int{403}} },
		"bad access": func(c *Config) {
			c.Tests[0].Expectations["anonymous"] = Expectation{Access: "maybe", Statuses: []int{403}}
		},
		"unsafe status": func(c *Config) {
			c.Tests[0].Expectations["anonymous"] = Expectation{Access: "deny", Statuses: []int{500}}
		},
		"empty statuses":    func(c *Config) { c.Tests[0].Expectations["anonymous"] = Expectation{Access: "deny"} },
		"no resource proof": func(c *Config) { v := true; c.Tests[0].Assertions = []Assertion{{Pointer: "/id", Exists: &v}} },
		"no identity proof": func(c *Config) { c.Identities[0].Check.Assertions = nil },
		"head assertions":   func(c *Config) { c.Tests[0].Method = "HEAD" },
		"both assertions":   func(c *Config) { v := true; c.Tests[0].Assertions[0].Exists = &v },
		"missing assertion": func(c *Config) { c.Tests[0].Assertions[0].Equals = nil },
		"bad pointer":       func(c *Config) { c.Tests[0].Assertions[0].Pointer = "/bad~2escape" },
		"bad equality":      func(c *Config) { c.Tests[0].Assertions[0].Equals = []byte(`{"a":1,"a":2}`) },
	}
	for _, path := range []string{"//evil.example/path", "https://evil.example", "/a/../b", "/%2e%2e/b", "/a\\b", "/a%5cb", "/a#fragment", "/%0d%0a", "/%2f%2fevil.example", "/%252e%252e/b"} {
		cases["path "+path] = func(c *Config) { c.Tests[0].Path = path }
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := configFor(t, "http://127.0.0.1:8080")
			change(&c)
			if err := Validate(c); err == nil {
				t.Fatal("accepted unsafe config")
			}
		})
	}
}

func TestLoadRejectsSchemaAliasesNullsAndUnicodeRepair(t *testing.T) {
	for _, text := range []string{
		strings.Replace(exampleConfig, `"version":1`, `"Version":1`, 1),
		strings.Replace(exampleConfig, `"version":1`, `"VERSION":0,"version":1`, 1),
		strings.Replace(exampleConfig, `"anonymous":true`, `"anonymous":true,"prefix":null`, 1),
		strings.Replace(exampleConfig, `"equals":"alice"`, `"equals":"alice","exists":null`, 1),
		strings.Replace(exampleConfig, `"equals":"alice"`, `"equals":"\ud800"`, 1),
		strings.Replace(exampleConfig, `"equals":"alice"`, `"equals":"\udc00"`, 1),
	} {
		if _, err := Load(strings.NewReader(text)); err == nil {
			t.Errorf("ambiguous configuration accepted: %s", text)
		}
	}
}

func TestValidateURLAndHeaderBoundaryCases(t *testing.T) {
	for _, origin := range []string{"http://localhost:8080", "http://[::1]:8080", "http://127.9.8.7", "https://api.example.com:443"} {
		c := configFor(t, origin)
		if err := Validate(c); err != nil {
			t.Errorf("valid origin %q: %v", origin, err)
		}
	}
	for _, origin := range []string{"ftp://127.0.0.1", "http://127.0.0.1.evil.example", "http://2130706433", "http://127.1", "https://example.com:0", "https://example.com:65536", "https://example.com:", "https://example.com#", "https://example.com?", "http://[::ffff:192.0.2.1]", "https://[::1%25zone]"} {
		c := configFor(t, origin)
		if err := Validate(c); err == nil {
			t.Errorf("unsafe origin accepted %q", origin)
		}
	}
	for _, header := range []string{"Host", "Cookie", "Proxy-Authorization", "Content-Length", "Connection", "Accept", "Transfer-Encoding", "X-Key\r\n"} {
		c := configFor(t, "http://localhost")
		c.Identities[0].Header = header
		if err := Validate(c); err == nil {
			t.Errorf("unsafe header accepted %q", header)
		}
	}
	for _, path := range []string{"/me?x=%0d%0a", "/me?x=%00", "/me?x=%250a", "/me?x=%xx"} {
		c := configFor(t, "http://localhost")
		c.Tests[0].Path = path
		if err := Validate(c); err == nil {
			t.Errorf("unsafe query accepted %q", path)
		}
	}
	c := configFor(t, "https://example.com")
	c.Identities[0].Header = "X-API-Key"
	c.Tests[0].Path = "/v1/items?owner=alice&name=first%20last"
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
}

func TestLoadValidConfig(t *testing.T) {
	c := configFor(t, "http://127.0.0.1:8080")
	if c.Version != 1 || c.Identities[0].Check.Path != "/me" || c.Tests[0].Expectations["anonymous"].Access != "deny" {
		t.Fatalf("unexpected configuration: %+v", c)
	}
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
}
