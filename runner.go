package accessmatrix

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type Report struct {
	Version string   `json:"version"`
	Results []Result `json:"results"`
}

type Result struct {
	Test       string            `json:"test"`
	Identity   string            `json:"identity"`
	Expected   string            `json:"expected"`
	Verdict    string            `json:"verdict"`
	Status     int               `json:"status,omitempty"`
	Reason     string            `json:"reason"`
	Assertions []AssertionResult `json:"assertions,omitempty"`
}

type AssertionResult struct {
	Pointer string `json:"pointer"`
	Matched bool   `json:"matched"`
}

// Run validates and snapshots configuration, then resolves every credential before
// traffic. Request failures are rows; invalid setup and cancellation return errors.
func Run(ctx context.Context, c Config, lookup func(string) (string, bool)) (report Report, runErr error) {
	report = Report{Version: "0.1", Results: []Result{}}
	if err := Validate(c); err != nil {
		return report, err
	}
	if ctx == nil {
		return report, errors.New("context is required")
	}
	// Own all maps, slices, pointers and raw equality bytes before invoking caller code.
	b, err := json.Marshal(c)
	if err != nil {
		return report, errors.New("configuration snapshot failed")
	}
	c = Config{}
	if err = json.Unmarshal(b, &c); err != nil {
		return report, errors.New("configuration snapshot failed")
	}
	if c.TimeoutMS == 0 {
		c.TimeoutMS = 5000
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = 1 << 20
	}
	values := make([]string, len(c.Identities))
	defer func() {
		redact := func(s string) string {
			for _, secret := range values {
				if secret != "" && strings.Contains(s, secret) {
					return "[REDACTED]"
				}
			}
			return s
		}
		for i := range report.Results {
			r := &report.Results[i]
			r.Test = redact(r.Test)
			r.Identity = redact(r.Identity)
			for j := range r.Assertions {
				r.Assertions[j].Pointer = redact(r.Assertions[j].Pointer)
			}
		}
	}()
	for i, id := range c.Identities {
		if id.Anonymous {
			continue
		}
		if lookup == nil {
			return report, errors.New("credential lookup is required")
		}
		v, ok := lookup(id.TokenEnv)
		if !ok || strings.TrimSpace(v) == "" || len(v) > 8192 || !printable(v) {
			return report, errors.New("credential unavailable or invalid")
		}
		values[i] = v
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 64 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for i, id := range c.Identities {
		if id.Anonymous {
			continue
		}
		if err := ctx.Err(); err != nil {
			return report, err
		}
		obs := request(ctx, client, c, id, values[i], "GET", id.Check.Path, id.Check.Assertions)
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if obs.reason != "" || obs.status != 200 || !obs.matched {
			for _, test := range c.Tests {
				for _, identity := range c.Identities {
					if _, explicit := test.Expectations[identity.Name]; !explicit {
						continue
					}
					report.Results = append(report.Results, row(test, identity, "ERROR", "identity_verification_failed"))
				}
			}
			return report, nil
		}
	}
	for _, test := range c.Tests {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		controlIndex := 0
		for i, id := range c.Identities {
			if id.Name == test.Control {
				controlIndex = i
				break
			}
		}
		control := c.Identities[controlIndex]
		obs := request(ctx, client, c, control, values[controlIndex], test.Method, test.Path, test.Assertions)
		if err := ctx.Err(); err != nil {
			return report, err
		}
		controlRow := classify(test, control, obs)
		rows := make([]Result, 0, len(test.Expectations))
		for i, id := range c.Identities {
			if _, explicit := test.Expectations[id.Name]; !explicit {
				continue
			}
			if i == controlIndex {
				rows = append(rows, controlRow)
				continue
			}
			if controlRow.Verdict != "PASS" {
				rows = append(rows, row(test, id, "ERROR", "control_not_verified"))
				continue
			}
			if err := ctx.Err(); err != nil {
				return report, err
			}
			obs := request(ctx, client, c, id, values[i], test.Method, test.Path, test.Assertions)
			if err := ctx.Err(); err != nil {
				return report, err
			}
			rows = append(rows, classify(test, id, obs))
		}
		report.Results = append(report.Results, rows...)
	}
	return report, nil
}

type observation struct {
	status     int
	reason     string
	matched    bool
	assertions []AssertionResult
}

func request(ctx context.Context, client *http.Client, c Config, id Identity, token, method, path string, assertions []Assertion) observation {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.TimeoutMS)*time.Millisecond)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, nil)
	if err != nil {
		return observation{reason: "request_failed"}
	}
	if !id.Anonymous {
		r.Header.Set(id.Header, id.Prefix+token)
	}
	response, err := client.Do(r)
	if err != nil {
		return observation{reason: "request_failed"}
	}
	defer response.Body.Close()
	o := observation{status: response.StatusCode}
	if method == "HEAD" {
		o.matched = true
		return o
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, c.MaxBodyBytes+1))
	if err != nil {
		o.reason = "response_read_failed"
		return o
	}
	if int64(len(body)) > c.MaxBodyBytes {
		o.reason = "response_too_large"
		return o
	}
	value, err := decodeJSON(body)
	if err != nil {
		o.reason = "invalid_response_json"
		return o
	}
	o.matched = true
	for _, a := range assertions {
		v, exists := pointerValue(value, a.Pointer)
		match := false
		if a.Exists != nil {
			match = exists == *a.Exists
		} else {
			expected, _ := decodeJSON(a.Equals)
			match = exists && reflect.DeepEqual(v, expected)
		}
		o.assertions = append(o.assertions, AssertionResult{Pointer: a.Pointer, Matched: match})
		o.matched = o.matched && match
	}
	return o
}

func row(test Test, id Identity, verdict, reason string) Result {
	return Result{Test: test.ID, Identity: id.Name, Expected: test.Expectations[id.Name].Access, Verdict: verdict, Reason: reason}
}

func classify(test Test, id Identity, o observation) Result {
	r := row(test, id, "INCONCLUSIVE", "unexpected_response")
	r.Status = o.status
	r.Assertions = o.assertions
	if o.status == 429 || o.status >= 500 || o.status >= 300 && o.status <= 399 {
		r.Reason = "ambiguous_status"
		return r
	}
	if o.reason != "" {
		r.Verdict = "ERROR"
		r.Reason = o.reason
		return r
	}
	exp := test.Expectations[id.Name]
	expectedStatus := false
	for _, s := range exp.Statuses {
		expectedStatus = expectedStatus || s == o.status
	}
	if exp.Access == "allow" {
		if o.status == 401 || o.status == 403 || o.status == 404 {
			r.Verdict = "FAIL"
			r.Reason = "access_denied"
		} else if expectedStatus && o.matched {
			r.Verdict = "PASS"
			r.Reason = "resource_verified"
			if test.Method == "HEAD" {
				r.Reason = "status_verified"
			}
		}
	} else {
		if test.Method == "GET" && o.matched {
			r.Verdict = "FAIL"
			r.Reason = "protected_resource_returned"
		} else if expectedStatus {
			r.Verdict = "PASS"
			r.Reason = "expected_denial"
		}
	}
	return r
}

func pointerValue(value any, pointer string) (any, bool) {
	if pointer == "" {
		return value, true
	}
	for _, part := range strings.Split(pointer[1:], "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		switch current := value.(type) {
		case map[string]any:
			var ok bool
			value, ok = current[part]
			if !ok {
				return nil, false
			}
		case []any:
			if part == "" || len(part) > 1 && part[0] == '0' {
				return nil, false
			}
			for _, r := range part {
				if r < '0' || r > '9' {
					return nil, false
				}
			}
			i, err := strconv.Atoi(part)
			if err != nil || i >= len(current) {
				return nil, false
			}
			value = current[i]
		default:
			return nil, false
		}
	}
	return value, true
}
