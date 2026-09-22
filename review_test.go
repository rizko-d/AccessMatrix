package accessmatrix

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunRejectsExcessiveJSONNodes(t *testing.T) {
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
		fmt.Fprint(w, "["+strings.Repeat("[],", 65536)+"[]]")
	}))
	defer s.Close()
	report, err := Run(context.Background(), configFor(t, s.URL), credentials)
	if err != nil {
		t.Fatal(err)
	}
	if report.Results[1].Verdict != "ERROR" {
		t.Fatalf("excessive JSON accepted: %+v", report.Results[1])
	}
}

func TestRunPartialResourceEvidenceCannotPass(t *testing.T) {
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
		fmt.Fprint(w, `{"id":"alice-1","error":"forbidden"}`)
	}))
	defer s.Close()
	report, err := Run(context.Background(), configFor(t, s.URL), credentials)
	if err != nil {
		t.Fatal(err)
	}
	if report.Results[1].Verdict != "INCONCLUSIVE" {
		t.Fatalf("partial disclosure passed: %+v", report.Results[1])
	}
}

func TestRunMalformedRedirectRemainsObserved(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/me" {
			fmt.Fprint(w, `{"id":"alice"}`)
			return
		}
		if r.Header.Get("Authorization") != "" {
			fmt.Fprint(w, protectedBody)
			return
		}
		w.Header().Set("Location", "http://[invalid")
		w.WriteHeader(302)
	}))
	defer s.Close()
	report, err := Run(context.Background(), configFor(t, s.URL), credentials)
	if err != nil {
		t.Fatal(err)
	}
	got := report.Results[1]
	if got.Status != 302 || got.Verdict != "INCONCLUSIVE" {
		t.Fatalf("lost redirect observation: %+v", got)
	}
}
