// Package accessmatrix checks authorization expectations against explicit endpoints.
package accessmatrix

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

type Config struct {
	Version      int        `json:"version"`
	BaseURL      string     `json:"base_url"`
	TimeoutMS    int        `json:"timeout_ms"`
	MaxBodyBytes int64      `json:"max_body_bytes"`
	Identities   []Identity `json:"identities"`
	Tests        []Test     `json:"tests"`
}

type Identity struct {
	Name      string `json:"name"`
	Header    string `json:"header,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	TokenEnv  string `json:"token_env,omitempty"`
	Anonymous bool   `json:"anonymous,omitempty"`
	Check     *Probe `json:"check,omitempty"`
}

type Probe struct {
	Path       string      `json:"path"`
	Assertions []Assertion `json:"assertions"`
}

type Test struct {
	ID           string                 `json:"id"`
	Method       string                 `json:"method"`
	Path         string                 `json:"path"`
	Control      string                 `json:"control"`
	Assertions   []Assertion            `json:"assertions,omitempty"`
	Expectations map[string]Expectation `json:"expectations"`
}

type Expectation struct {
	Access   string `json:"access"`
	Statuses []int  `json:"statuses"`
}

type Assertion struct {
	Pointer string          `json:"pointer"`
	Equals  json.RawMessage `json:"equals,omitempty"`
	Exists  *bool           `json:"exists,omitempty"`
}

const maxConfigBytes = 4 << 20

var readableName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
var keyHeader = regexp.MustCompile(`(?i)^X-[A-Z0-9]+(?:-[A-Z0-9]+)*$`)

// Load reads one strict JSON configuration, bounded to 4 MiB. Errors never echo input.
func Load(r io.Reader) (Config, error) {
	if r == nil {
		return Config{}, errors.New("configuration reader is required")
	}
	b, err := io.ReadAll(io.LimitReader(r, maxConfigBytes+1))
	if err != nil || len(b) > maxConfigBytes {
		return Config{}, errors.New("configuration read failed or limit exceeded")
	}
	value, err := decodeJSON(b)
	if err != nil || !configShape(value, reflect.TypeOf(Config{})) {
		return Config{}, errors.New("invalid configuration JSON")
	}
	var c Config
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return Config{}, errors.New("invalid configuration JSON")
	}
	if err := Validate(c); err != nil {
		return Config{}, err
	}
	return c, nil
}

// encoding/json accepts case aliases and null scalar fields; the schema does not.
func configShape(v any, typ reflect.Type) bool {
	if typ == reflect.TypeOf(json.RawMessage{}) {
		return true
	}
	if v == nil {
		return false
	}
	if typ.Kind() == reflect.Pointer {
		return configShape(v, typ.Elem())
	}
	switch typ.Kind() {
	case reflect.Struct:
		object, ok := v.(map[string]any)
		if !ok {
			return false
		}
		if typ == reflect.TypeOf(Identity{}) && object["anonymous"] == true {
			for _, key := range []string{"header", "prefix", "token_env", "check"} {
				if _, present := object[key]; present {
					return false
				}
			}
		}
		for key, value := range object {
			found := false
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if strings.Split(field.Tag.Get("json"), ",")[0] == key {
					found = true
					if !configShape(value, field.Type) {
						return false
					}
					break
				}
			}
			if !found {
				return false
			}
		}
	case reflect.Map:
		object, ok := v.(map[string]any)
		if !ok {
			return false
		}
		for _, value := range object {
			if !configShape(value, typ.Elem()) {
				return false
			}
		}
	case reflect.Slice:
		array, ok := v.([]any)
		if !ok {
			return false
		}
		for _, value := range array {
			if !configShape(value, typ.Elem()) {
				return false
			}
		}
	}
	return true
}

// Validate checks configuration without requests, environment reads, or mutation.
func Validate(c Config) error {
	if c.Version != 1 {
		return errors.New("configuration version must be 1")
	}
	if !validOrigin(c.BaseURL) {
		return errors.New("invalid base origin")
	}
	if c.TimeoutMS < 0 || c.TimeoutMS > 120000 || c.MaxBodyBytes < 0 || c.MaxBodyBytes > 16<<20 {
		return errors.New("invalid request limits")
	}
	if len(c.Identities) == 0 || len(c.Identities) > 128 || len(c.Tests) == 0 || len(c.Tests) > 1024 {
		return errors.New("invalid matrix size")
	}
	names := make(map[string]bool)
	for _, id := range c.Identities {
		if !readableName.MatchString(id.Name) || names[id.Name] {
			return errors.New("invalid or duplicate identity name")
		}
		names[id.Name] = true
		if id.Anonymous {
			if id.Header != "" || id.Prefix != "" || id.TokenEnv != "" || id.Check != nil {
				return errors.New("anonymous identity cannot carry credentials or a check")
			}
			continue
		}
		if !(strings.EqualFold(id.Header, "Authorization") || keyHeader.MatchString(id.Header)) || len(id.Header) > 128 || !envName.MatchString(id.TokenEnv) || !printable(id.Prefix) || len(id.Prefix) > 256 {
			return errors.New("invalid credential configuration")
		}
		if id.Check == nil || !validPath(id.Check.Path) || !validAssertions(id.Check.Assertions, true) {
			return errors.New("identity check requires a safe path and equality proof")
		}
	}
	ids := make(map[string]bool)
	for _, test := range c.Tests {
		if !readableName.MatchString(test.ID) || ids[test.ID] {
			return errors.New("invalid or duplicate test ID")
		}
		ids[test.ID] = true
		if test.Method != "GET" && test.Method != "HEAD" {
			return errors.New("only GET and HEAD are supported")
		}
		if !validPath(test.Path) {
			return errors.New("invalid test path")
		}
		if test.Method == "HEAD" && len(test.Assertions) != 0 || test.Method == "GET" && !validAssertions(test.Assertions, true) {
			return errors.New("invalid resource assertions")
		}
		if !names[test.Control] || test.Expectations[test.Control].Access != "allow" {
			return errors.New("test requires an explicit allowed control")
		}
		for name, exp := range test.Expectations {
			if !names[name] || exp.Access != "allow" && exp.Access != "deny" || len(exp.Statuses) == 0 || len(exp.Statuses) > 100 {
				return errors.New("invalid expectation")
			}
			seen := make(map[int]bool)
			for _, status := range exp.Statuses {
				if seen[status] || exp.Access == "allow" && (status < 200 || status > 299) || exp.Access == "deny" && (status < 400 || status > 499 || status == 429) {
					return errors.New("invalid expected status")
				}
				seen[status] = true
			}
		}
	}
	return nil
}

func printable(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}

func validOrigin(s string) bool {
	if len(s) > 2048 || !printable(s) || strings.ContainsAny(s, "?#\\") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.Opaque != "" {
		return false
	}
	host := u.Hostname()
	if host == "" || strings.Contains(host, "%") {
		return false
	}
	if strings.HasSuffix(u.Host, ":") {
		return false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(host)
		return strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback()
	}
	return true
}

func validPath(s string) bool {
	if len(s) == 0 || len(s) > 8192 || s[0] != '/' || !printable(s) || strings.ContainsAny(s, "#\\") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil {
		return false
	}
	query := u.RawQuery
	for i := 0; ; i++ {
		if !printable(query) || strings.Contains(query, "\\") {
			return false
		}
		if !strings.Contains(query, "%") {
			break
		}
		if i >= 8 {
			return false
		}
		query, err = url.QueryUnescape(query)
		if err != nil {
			return false
		}
	}
	p := u.EscapedPath()
	for i := 0; i < 8; i++ {
		if strings.HasPrefix(p, "//") || !printable(p) || strings.Contains(p, "\\") {
			return false
		}
		for _, segment := range strings.Split(p, "/") {
			if segment == "." || segment == ".." {
				return false
			}
		}
		if !strings.Contains(p, "%") {
			return true
		}
		p, err = url.PathUnescape(p)
		if err != nil {
			return false
		}
	}
	return false
}

func validAssertions(assertions []Assertion, requireEquality bool) bool {
	if len(assertions) > 128 {
		return false
	}
	hasEquality := false
	for _, a := range assertions {
		if !validPointer(a.Pointer) || (len(a.Equals) > 0) == (a.Exists != nil) {
			return false
		}
		if len(a.Equals) > 0 {
			if len(a.Equals) > maxConfigBytes {
				return false
			}
			if _, err := decodeJSON(a.Equals); err != nil {
				return false
			}
			hasEquality = true
		}
	}
	return !requireEquality || hasEquality
}

func validPointer(p string) bool {
	if len(p) > 4096 || !printable(p) || p != "" && p[0] != '/' {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] == '~' {
			if i+1 == len(p) || p[i+1] != '0' && p[i+1] != '1' {
				return false
			}
			i++
		}
	}
	return true
}
