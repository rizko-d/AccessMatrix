package accessmatrix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunRedactsReflectedMetadata(t *testing.T) {
	const secret = "reflected-secret"
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/me" {
			fmt.Fprint(w, `{"id":"alice"}`)
			return
		}
		fmt.Fprintf(w, `{"%s":"resource"}`, secret)
	}))
	defer s.Close()
	c := configFor(t, s.URL)
	c.Tests[0].ID = secret
	c.Tests[0].Path = "/" + secret + "?token=" + secret
	c.Identities[0].Name = secret
	c.Tests[0].Control = secret
	c.Tests[0].Expectations[secret] = c.Tests[0].Expectations["alice"]
	delete(c.Tests[0].Expectations, "alice")
	c.Tests[0].Assertions = []Assertion{{Pointer: "/" + secret, Equals: json.RawMessage(`"resource"`)}}
	r, err := Run(context.Background(), c, func(string) (string, bool) { return secret, true })
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), secret) {
		t.Fatalf("secret leaked: %s", b)
	}
	if r.Results[0].Verdict != "PASS" || r.Results[1].Verdict != "FAIL" {
		t.Fatalf("redaction changed behavior: %+v", r)
	}
}

func TestRunResponseVerdicts(t *testing.T) {
	cases := []struct {
		name, access, body, verdict string
		status                      int
		limit                       int64
	}{
		{"deny 403", "deny", `{"error":"forbidden"}`, "PASS", 403, 0},
		{"deny 401", "deny", `{}`, "PASS", 401, 0},
		{"deny 404", "deny", `null`, "PASS", 404, 0},
		{"resource in 403", "deny", protectedBody, "FAIL", 403, 0},
		{"resource in 400", "deny", protectedBody, "FAIL", 400, 0},
		{"resource in 200", "deny", protectedBody, "FAIL", 200, 0},
		{"200 error", "deny", `{"error":"not found"}`, "INCONCLUSIVE", 200, 0},
		{"unexpected 400", "deny", `{}`, "INCONCLUSIVE", 400, 0},
		{"rate limit", "deny", protectedBody, "INCONCLUSIVE", 429, 0},
		{"server error", "deny", protectedBody, "INCONCLUSIVE", 500, 0},
		{"redirect", "deny", protectedBody, "INCONCLUSIVE", 302, 0},
		{"malformed denial", "deny", `{"error":`, "ERROR", 403, 0},
		{"empty denial", "deny", ``, "ERROR", 403, 0},
		{"duplicate denial", "deny", `{"id":"alice-1","id":"other"}`, "ERROR", 403, 0},
		{"trailing denial", "deny", `{} {}`, "ERROR", 403, 0},
		{"invalid utf8", "deny", string([]byte{'"', 255, '"'}), "ERROR", 403, 0},
		{"oversized denial", "deny", `{"error":"` + strings.Repeat("x", 100) + `"}`, "ERROR", 403, 64},
		{"allow resource", "allow", protectedBody, "PASS", 200, 0},
		{"allow forbidden", "allow", `{}`, "FAIL", 403, 0},
		{"allow unauthorized", "allow", `{}`, "FAIL", 401, 0},
		{"allow missing", "allow", `{}`, "FAIL", 404, 0},
		{"allow wrong resource", "allow", `{"id":"other"}`, "INCONCLUSIVE", 200, 0},
		{"allow bad request", "allow", `{}`, "INCONCLUSIVE", 400, 0},
		{"allow other 2xx", "allow", protectedBody, "INCONCLUSIVE", 201, 0},
		{"allow rate limited", "allow", `{}`, "INCONCLUSIVE", 429, 0},
		{"allow server error", "allow", `{}`, "INCONCLUSIVE", 503, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/me" {
					fmt.Fprint(w, `{"id":"alice"}`)
					return
				}
				if r.Header.Get("Authorization") != "" {
					fmt.Fprint(w, protectedBody)
					return
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer s.Close()
			c := configFor(t, s.URL)
			c.MaxBodyBytes = tc.limit
			if tc.access == "allow" {
				c.Tests[0].Expectations["anonymous"] = Expectation{Access: "allow", Statuses: []int{200}}
			}
			r, err := Run(context.Background(), c, credentials)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Results) != 2 || r.Results[0].Verdict != "PASS" || r.Results[1].Verdict != tc.verdict {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

func TestRunCredentialPreflightHasNoTraffic(t *testing.T) {
	for _, value := range []string{"", "   ", "secret\r\ninjected", "secret\n", "secret\x00", strings.Repeat("x", 8193)} {
		t.Run(fmt.Sprintf("length-%d", len(value)), func(t *testing.T) {
			var requests atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
			defer s.Close()
			c := configFor(t, s.URL)
			bob := c.Identities[0]
			bob.Name = "bob"
			bob.TokenEnv = "BOB_TOKEN"
			c.Identities = append(c.Identities, bob)
			c.Tests[0].Expectations["bob"] = Expectation{Access: "deny", Statuses: []int{403}}
			r, err := Run(context.Background(), c, func(name string) (string, bool) {
				if name == "BOB_TOKEN" {
					return value, value != ""
				}
				return credentials(name)
			})
			if err == nil || requests.Load() != 0 || len(r.Results) != 0 {
				t.Fatalf("preflight failed: %+v %v requests=%d", r, err, requests.Load())
			}
		})
	}
	c := configFor(t, "http://127.0.0.1:1")
	for _, lookup := range []func(string) (string, bool){nil, func(string) (string, bool) { return "", false }} {
		if _, err := Run(context.Background(), c, lookup); err == nil {
			t.Fatal("missing credentials accepted")
		}
	}
}

func TestRunIdentityAndControlGateMatrix(t *testing.T) {
	for _, stage := range []string{"identity", "control"} {
		for _, bad := range []struct {
			status int
			body   string
		}{{200, `{"id":"wrong"}`}, {401, `{}`}, {403, protectedBody}, {302, `{}`}, {429, `{}`}, {500, `{}`}, {200, `invalid`}} {
			t.Run(fmt.Sprintf("%s-%d-%s", stage, bad.status, bad.body), func(t *testing.T) {
				var matrix, anonymous atomic.Int32
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/me" {
						if stage == "identity" {
							w.WriteHeader(bad.status)
							fmt.Fprint(w, bad.body)
						} else {
							fmt.Fprint(w, `{"id":"alice"}`)
						}
						return
					}
					matrix.Add(1)
					if r.Header.Get("Authorization") == "" {
						anonymous.Add(1)
					}
					w.WriteHeader(bad.status)
					fmt.Fprint(w, bad.body)
				}))
				defer s.Close()
				r, err := Run(context.Background(), configFor(t, s.URL), credentials)
				if err != nil {
					t.Fatal(err)
				}
				if len(r.Results) != 2 || r.Results[1].Verdict != "ERROR" || anonymous.Load() != 0 {
					t.Fatalf("unsafe gate: %+v", r)
				}
				if stage == "identity" && (matrix.Load() != 0 || r.Results[0].Verdict != "ERROR") {
					t.Fatalf("matrix ran before verification: %+v", r)
				}
			})
		}
	}
}

func TestRunTransportIsolation(t *testing.T) {
	var sinkHits atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sinkHits.Add(1) }))
	defer sink.Close()
	t.Setenv("HTTP_PROXY", sink.URL)
	t.Setenv("HTTPS_PROXY", sink.URL)
	t.Setenv("ALL_PROXY", sink.URL)
	t.Setenv("NO_PROXY", "")
	var cookieHits atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			cookieHits.Add(1)
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "secret", Path: "/"})
		if r.URL.Path == "/me" {
			fmt.Fprint(w, `{"id":"alice"}`)
			return
		}
		if r.Header.Get("Authorization") != "" {
			fmt.Fprint(w, protectedBody)
			return
		}
		http.Redirect(w, r, sink.URL+"/capture", http.StatusFound)
	}))
	defer s.Close()
	r, err := Run(context.Background(), configFor(t, s.URL), credentials)
	if err != nil || len(r.Results) != 2 || r.Results[1].Verdict != "INCONCLUSIVE" || sinkHits.Load() != 0 || cookieHits.Load() != 0 {
		t.Fatalf("transport isolation: %+v %v sink=%d cookie=%d", r, err, sinkHits.Load(), cookieHits.Load())
	}
	// An authenticated redirect must not leak even the control credential.
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, sink.URL+"/capture", 302) }))
	defer redirect.Close()
	r, err = Run(context.Background(), configFor(t, redirect.URL), credentials)
	if err != nil || r.Results[0].Verdict != "ERROR" || sinkHits.Load() != 0 {
		t.Fatalf("authenticated redirect followed: %+v %v", r, err)
	}
}

func TestRunRejectsInvalidTLSAndNetworkFailure(t *testing.T) {
	var hits atomic.Int32
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	defer s.Close()
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed.Close()
	for _, origin := range []string{s.URL, closed.URL} {
		r, err := Run(context.Background(), configFor(t, origin), credentials)
		if err != nil || len(r.Results) != 2 || r.Results[0].Verdict != "ERROR" || hits.Load() != 0 {
			t.Fatalf("unsafe transport: %+v %v", r, err)
		}
	}
}

func TestRunCancellationAndTimeout(t *testing.T) {
	for _, cancelRun := range []bool{true, false} {
		t.Run(fmt.Sprint(cancelRun), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var requests atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if cancelRun {
					cancel()
				}
				<-r.Context().Done()
			}))
			defer s.Close()
			c := configFor(t, s.URL)
			c.TimeoutMS = 20
			r, err := Run(ctx, c, credentials)
			if cancelRun {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation lost: %+v %v", r, err)
				}
			} else if err != nil || r.Results[0].Verdict != "ERROR" {
				t.Fatalf("timeout passed: %+v %v", r, err)
			}
			if requests.Load() != 1 {
				t.Fatalf("new requests after cancellation: %d", requests.Load())
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, configFor(t, "http://127.0.0.1:1"), credentials); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestRunHEADHasNoBodyProof(t *testing.T) {
	for _, status := range []int{200, 403, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/me" {
					fmt.Fprint(w, `{"id":"alice"}`)
					return
				}
				if r.Method != "HEAD" {
					t.Error("non-HEAD resource request")
				}
				if r.Header.Get("Authorization") == "" {
					w.WriteHeader(status)
				}
			}))
			defer s.Close()
			c := configFor(t, s.URL)
			c.Tests[0].Method = "HEAD"
			c.Tests[0].Assertions = nil
			r, err := Run(context.Background(), c, credentials)
			if err != nil {
				t.Fatal(err)
			}
			if r.Results[0].Reason != "status_verified" {
				t.Fatalf("HEAD claims body proof: %+v", r.Results[0])
			}
			want := "INCONCLUSIVE"
			if status == 403 {
				want = "PASS"
			}
			if r.Results[1].Verdict != want {
				t.Fatalf("HEAD verdict: %+v", r)
			}
		})
	}
}

func TestRunDoesNotRetry(t *testing.T) {
	var hits atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		conn.Close()
	}))
	defer s.Close()
	r, err := Run(context.Background(), configFor(t, s.URL), credentials)
	if err != nil || r.Results[0].Verdict != "ERROR" || hits.Load() != 1 {
		t.Fatalf("unexpected retry: %+v %v requests=%d", r, err, hits.Load())
	}
}

func TestRunTimeoutIncludesBody(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer s.Close()
	c := configFor(t, s.URL)
	c.TimeoutMS = 20
	r, err := Run(context.Background(), c, credentials)
	if err != nil || r.Results[0].Verdict != "ERROR" {
		t.Fatalf("body timeout not enforced: %+v %v", r, err)
	}
}
