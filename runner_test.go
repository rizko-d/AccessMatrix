package accessmatrix

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

const protectedBody = `{"id":"alice-1","owner":"alice"}`

func credentials(name string) (string, bool) {
	if name == "ALICE_TOKEN" {
		return "secret-alice", true
	}
	return "", false
}

func TestRunOwnsConfigurationBeforeCredentialLookup(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/me" {
			fmt.Fprint(w, `{"id":"alice"}`)
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
	r, err := Run(context.Background(), c, func(name string) (string, bool) {
		c.Tests[0].ID = "mutated"
		c.Tests[0].Expectations["anonymous"] = Expectation{Access: "allow", Statuses: []int{200}}
		c.Tests[0].Assertions[0].Equals[1] = 'X'
		c.Identities[0].Name = "mutated"
		return credentials(name)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Results) != 2 || r.Results[0].Test != "alice-invoice" || r.Results[0].Identity != "alice" || r.Results[0].Verdict != "PASS" || r.Results[1].Verdict != "PASS" {
		t.Fatalf("caller mutation escaped into run: %+v", r)
	}
}

func TestRunExactJSONAssertions(t *testing.T) {
	cases := []struct {
		name, body, pointer, equals string
		verdict                     string
	}{
		{"escaped object key", `{"a/b":{"~key":"yes"}}`, "/a~1b/~0key", `"yes"`, "PASS"},
		{"array", `{"items":["one","two"]}`, "/items/1", `"two"`, "PASS"},
		{"array leading zero", `{"items":["one"]}`, "/items/00", `"one"`, "INCONCLUSIVE"},
		{"array negative", `{"items":["one"]}`, "/items/-1", `"one"`, "INCONCLUSIVE"},
		{"array huge index", `{"items":["one"]}`, "/items/99999999999999999999999999", `"one"`, "INCONCLUSIVE"},
		{"null exists", `{"id":null}`, "/id", `null`, "PASS"},
		{"null missing", `{}`, "/id", `null`, "INCONCLUSIVE"},
		{"large exact number", `{"id":9007199254740993}`, "/id", `9007199254740993`, "PASS"},
		{"large different number", `{"id":9007199254740992}`, "/id", `9007199254740993`, "INCONCLUSIVE"},
		{"numeric equivalent", `{"id":123e-2}`, "/id", `1.2300`, "PASS"},
		{"extreme exponent equivalent", `{"id":1e999999999999999999999}`, "/id", `10e999999999999999999998`, "PASS"},
		{"negative zero", `{"id":-0.00e999999999999}`, "/id", `0`, "PASS"},
		{"types distinct", `{"id":"123"}`, "/id", `123`, "INCONCLUSIVE"},
		{"object order", `{"b":[true,null,1.0],"a":false}`, "", `{"a":false,"b":[true,null,1]}`, "PASS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/me" {
					fmt.Fprint(w, `{"id":"alice"}`)
				} else {
					fmt.Fprint(w, tc.body)
				}
			}))
			defer s.Close()
			c := configFor(t, s.URL)
			c.Tests[0].Assertions = []Assertion{{Pointer: tc.pointer, Equals: json.RawMessage(tc.equals)}}
			r, err := Run(context.Background(), c, credentials)
			if err != nil {
				t.Fatal(err)
			}
			if r.Results[0].Verdict != tc.verdict {
				t.Fatalf("got %+v", r.Results[0])
			}
		})
	}
}

func TestRunVerifiedMatrixInConfigOrder(t *testing.T) {
	var requests []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		if r.URL.Path == "/me" {
			fmt.Fprint(w, `{"id":"alice"}`)
			return
		}
		if r.Header.Get("Authorization") == "Bearer secret-alice" {
			fmt.Fprint(w, protectedBody)
			return
		}
		w.WriteHeader(403)
		fmt.Fprint(w, `{"error":"forbidden"}`)
	}))
	defer s.Close()
	c := configFor(t, s.URL)
	c.Identities[0], c.Identities[1] = c.Identities[1], c.Identities[0]
	r, err := Run(context.Background(), c, credentials)
	if err != nil {
		t.Fatal(err)
	}
	want := []Result{
		{Test: "alice-invoice", Identity: "anonymous", Expected: "deny", Verdict: "PASS", Status: 403, Reason: "expected_denial", Assertions: []AssertionResult{{Pointer: "/id", Matched: false}, {Pointer: "/owner", Matched: false}}},
		{Test: "alice-invoice", Identity: "alice", Expected: "allow", Verdict: "PASS", Status: 200, Reason: "resource_verified", Assertions: []AssertionResult{{Pointer: "/id", Matched: true}, {Pointer: "/owner", Matched: true}}},
	}
	if r.Version != "0.1" || !reflect.DeepEqual(r.Results, want) {
		t.Fatalf("report = %+v", r)
	}
	if !reflect.DeepEqual(requests, []string{"GET /me Bearer secret-alice", "GET /invoices/alice-1 Bearer secret-alice", "GET /invoices/alice-1 "}) {
		t.Fatalf("unsafe request order or credentials: %v", requests)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "secret-alice") || strings.Contains(string(b), s.URL) {
		t.Fatal("report leaks request data")
	}
}
