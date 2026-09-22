package accessmatrix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRunExistsAssertionsAndJSONEscapes(t *testing.T) {
	present, absent := true, false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/me" {
			fmt.Fprint(w, `{"id":"alice"}`)
			return
		}
		fmt.Fprint(w, `{"id":"alice-1","null":null,"escaped":"\\ud800","emoji":"\ud83d\ude00","items":[null]}`)
	}))
	defer s.Close()
	c := configFor(t, s.URL)
	c.Tests[0].Assertions = []Assertion{
		{Pointer: "/id", Equals: json.RawMessage(`"alice-1"`)},
		{Pointer: "/null", Exists: &present},
		{Pointer: "/missing", Exists: &absent},
		{Pointer: "/items/0", Exists: &present},
		{Pointer: "/items/1", Exists: &absent},
		{Pointer: "/items/0/nested", Exists: &absent},
		{Pointer: "/escaped", Equals: json.RawMessage(`"\\ud800"`)},
		{Pointer: "/emoji", Equals: json.RawMessage(`"😀"`)},
	}
	r, err := Run(context.Background(), c, credentials)
	if err != nil {
		t.Fatal(err)
	}
	if r.Results[0].Verdict != "PASS" || r.Results[1].Verdict != "FAIL" {
		t.Fatalf("assertions failed: %+v", r)
	}
}

func TestRunSeparateIdentitiesAndConcurrentRuns(t *testing.T) {
	var leak atomic.Bool
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" && r.Header.Get("X-API-Key") != "" {
			leak.Store(true)
		}
		if r.URL.Path == "/me" {
			switch {
			case r.Header.Get("Authorization") == "Bearer secret-alice":
				fmt.Fprint(w, `{"id":"alice"}`)
			case r.Header.Get("X-API-Key") == "secret-bob":
				fmt.Fprint(w, `{"id":"bob"}`)
			default:
				leak.Store(true)
				w.WriteHeader(401)
				fmt.Fprint(w, `{}`)
			}
			return
		}
		if r.Header.Get("Authorization") == "Bearer secret-alice" {
			fmt.Fprint(w, protectedBody)
		} else {
			w.WriteHeader(403)
			fmt.Fprint(w, `{}`)
		}
	}))
	defer s.Close()
	c := configFor(t, s.URL)
	c.Identities = append(c.Identities, Identity{Name: "bob", Header: "X-API-Key", TokenEnv: "BOB_TOKEN", Check: &Probe{Path: "/me", Assertions: []Assertion{{Pointer: "/id", Equals: json.RawMessage(`"bob"`)}}}})
	c.Tests[0].Expectations["bob"] = Expectation{Access: "deny", Statuses: []int{403}}
	before, _ := json.Marshal(c)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := Run(context.Background(), c, func(name string) (string, bool) {
				if name == "BOB_TOKEN" {
					return "secret-bob", true
				}
				return credentials(name)
			})
			if err != nil || len(r.Results) != 3 {
				t.Errorf("concurrent run: %+v %v", r, err)
				return
			}
			for _, row := range r.Results {
				if row.Verdict != "PASS" {
					t.Errorf("identity crossed: %+v", row)
				}
			}
		}()
	}
	wg.Wait()
	after, _ := json.Marshal(c)
	if !reflect.DeepEqual(before, after) || leak.Load() {
		t.Fatal("config mutation or identity leakage")
	}
}

func TestRunControlFailureDoesNotPoisonOtherTests(t *testing.T) {
	var order []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, r.URL.Path+" "+r.Header.Get("Authorization"))
		if r.URL.Path == "/me" {
			fmt.Fprint(w, `{"id":"alice"}`)
			return
		}
		if r.URL.Path == "/first" || r.Header.Get("Authorization") == "" {
			w.WriteHeader(403)
			fmt.Fprint(w, `{}`)
			return
		}
		fmt.Fprint(w, protectedBody)
	}))
	defer s.Close()
	c := configFor(t, s.URL)
	c.Tests = append(c.Tests, c.Tests[0])
	c.Tests[0].Path = "/first"
	c.Tests[1].ID = "second"
	c.Tests[1].Path = "/second"
	r, err := Run(context.Background(), c, credentials)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"FAIL", "ERROR", "PASS", "PASS"}
	if len(r.Results) != len(want) {
		t.Fatal(r)
	}
	for i, w := range want {
		if r.Results[i].Verdict != w {
			t.Fatalf("bad order: %+v", r)
		}
	}
	if !reflect.DeepEqual(order, []string{"/me Bearer secret-alice", "/first Bearer secret-alice", "/second Bearer secret-alice", "/second "}) {
		t.Fatalf("request sequence: %v", order)
	}
}

func TestRunValidationBeforeCredentialsAndRequests(t *testing.T) {
	var called bool
	c := configFor(t, "http://127.0.0.1:1")
	c.Tests[0].Path = "//other.example"
	r, err := Run(context.Background(), c, func(string) (string, bool) { called = true; return "secret", true })
	if err == nil || called || len(r.Results) != 0 {
		t.Fatalf("validation order: %+v %v", r, err)
	}
	c = configFor(t, "http://127.0.0.1:1")
	if _, err := Run(nil, c, credentials); err == nil {
		t.Fatal("nil context accepted")
	}
}

func TestRunAnonymousOnlyNeedsNoLookup(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("credential on anonymous request")
		}
		fmt.Fprint(w, protectedBody)
	}))
	defer s.Close()
	c := configFor(t, s.URL)
	c.Identities = c.Identities[1:]
	c.Tests[0].Control = "anonymous"
	c.Tests[0].Expectations = map[string]Expectation{"anonymous": {Access: "allow", Statuses: []int{200}}}
	r, err := Run(context.Background(), c, nil)
	if err != nil || len(r.Results) != 1 || r.Results[0].Verdict != "PASS" {
		t.Fatalf("anonymous control: %+v %v", r, err)
	}
}

func TestRunCancellationBetweenTestsReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var secondHits atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/me" {
			fmt.Fprint(w, `{"id":"alice"}`)
			return
		}
		if r.URL.Path == "/second" {
			secondHits.Add(1)
			cancel()
			<-r.Context().Done()
			return
		}
		if r.Header.Get("Authorization") != "" {
			fmt.Fprint(w, protectedBody)
		} else {
			w.WriteHeader(403)
			fmt.Fprint(w, `{}`)
		}
	}))
	defer s.Close()
	c := configFor(t, s.URL)
	c.Tests = append(c.Tests, c.Tests[0], c.Tests[0])
	c.Tests[1].ID = "second"
	c.Tests[1].Path = "/second"
	c.Tests[2].ID = "third"
	r, err := Run(ctx, c, credentials)
	if !errors.Is(err, context.Canceled) || len(r.Results) != 2 || secondHits.Load() != 1 {
		t.Fatalf("successful partial result or continued requests: %+v %v", r, err)
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("secret-reader-error") }

func TestLoadReadAndResourceLimits(t *testing.T) {
	for _, r := range []io.Reader{nil, brokenReader{}, strings.NewReader(strings.Repeat(" ", 4<<20) + exampleConfig), strings.NewReader(strings.Replace(exampleConfig, `"equals":"alice"`, `"equals":`+strings.Repeat("[", 130)+`null`+strings.Repeat("]", 130), 1)), strings.NewReader(strings.Replace(exampleConfig, `"equals":"alice"`, `"equals":`+strings.Repeat("1", 4097), 1))} {
		_, err := Load(r)
		if err == nil || strings.Contains(err.Error(), "secret-reader-error") {
			t.Fatalf("unsafe load: %v", err)
		}
	}
}

func TestRunUntrustedResponseNeverEntersDiagnostics(t *testing.T) {
	for _, body := range []string{`{"id":"\ud800"}`, strings.Repeat("[", 130) + `null` + strings.Repeat("]", 130), `{"secret":"remote-secret-reflection"`, strings.Repeat("1", 4097)} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/me" {
				fmt.Fprint(w, `{"id":"alice"}`)
				return
			}
			if r.Header.Get("Authorization") != "" {
				fmt.Fprint(w, protectedBody)
				return
			}
			w.WriteHeader(403)
			fmt.Fprint(w, body)
		}))
		r, err := Run(context.Background(), configFor(t, s.URL), credentials)
		s.Close()
		if err != nil || r.Results[1].Verdict != "ERROR" {
			t.Fatalf("invalid response passed: %+v %v", r, err)
		}
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), "remote-secret-reflection") {
			t.Fatal("remote body leaked")
		}
	}
}

func TestRunPreservesExplicitOriginAndQuery(t *testing.T) {
	var observed atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/me" {
			fmt.Fprint(w, `{"id":"alice"}`)
			return
		}
		if r.RequestURI != "/invoices/alice-1?owner=alice&label=first%20last" {
			t.Errorf("changed explicit endpoint: %q", r.RequestURI)
		}
		if r.Header.Get("Authorization") == "Bearer secret-alice" {
			fmt.Fprint(w, protectedBody)
		} else {
			w.WriteHeader(403)
			fmt.Fprint(w, `{}`)
		}
		observed.Add(1)
	}))
	defer s.Close()
	c := configFor(t, s.URL)
	c.Tests[0].Path = "/invoices/alice-1?owner=alice&label=first%20last"
	r, err := Run(context.Background(), c, credentials)
	if err != nil || observed.Load() != 2 || r.Results[0].Verdict != "PASS" || r.Results[1].Verdict != "PASS" {
		t.Fatalf("same-origin query: %+v %v", r, err)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "label=") || strings.Contains(string(b), s.URL) {
		t.Fatal("request URL leaked")
	}
}

func TestRunDefaultBodyLimit(t *testing.T) {
	for _, size := range []int{1048576, 1048577} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/me" {
					fmt.Fprint(w, `{"id":"alice"}`)
					return
				}
				if r.Header.Get("Authorization") != "" {
					fmt.Fprint(w, protectedBody)
					return
				}
				fmt.Fprint(w, `{"padding":"`+strings.Repeat("x", size-len(`{"padding":""}`))+`"}`)
			}))
			defer s.Close()
			c := configFor(t, s.URL)
			c.Tests[0].Expectations["anonymous"] = Expectation{Access: "allow", Statuses: []int{200}}
			r, err := Run(context.Background(), c, credentials)
			if err != nil {
				t.Fatal(err)
			}
			want := "INCONCLUSIVE"
			if size > 1048576 {
				want = "ERROR"
			}
			if r.Results[1].Verdict != want {
				t.Fatalf("default limit not enforced: %+v", r)
			}
		})
	}
}

func FuzzLoadNeverPanics(f *testing.F) {
	f.Add(exampleConfig)
	f.Add(`null`)
	f.Add(`{"version":1,"version":2}`)
	f.Add(`"\ud800"`)
	f.Fuzz(func(t *testing.T, input string) {
		c, err := Load(strings.NewReader(input))
		if err == nil {
			if err := Validate(c); err != nil {
				t.Fatalf("Load accepted invalid config: %v", err)
			}
		}
	})
}
