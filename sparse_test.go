package accessmatrix_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	matrix "github.com/rizko-d/AccessMatrix"
)

func TestOmittedExpectationsNeverExecute(t *testing.T) {
	for _, mode := range []string{"pass", "identity-fails", "control-fails"} {
		t.Run(mode, func(t *testing.T) {
			var anonymousRequests atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "" {
					anonymousRequests.Add(1)
				}
				if r.URL.Path == "/me" {
					if mode == "identity-fails" {
						w.WriteHeader(401)
						fmt.Fprint(w, `{}`)
						return
					}
					fmt.Fprint(w, `{"id":"alice"}`)
					return
				}
				if mode == "control-fails" {
					w.WriteHeader(403)
					fmt.Fprint(w, `{}`)
					return
				}
				fmt.Fprint(w, `{"id":"invoice-1"}`)
			}))
			defer s.Close()
			raw := `{"version":1,"base_url":"` + s.URL + `","identities":[{"name":"alice","header":"Authorization","prefix":"Bearer ","token_env":"ALICE_TOKEN","check":{"path":"/me","assertions":[{"pointer":"/id","equals":"alice"}]}},{"name":"anonymous","anonymous":true}],"tests":[{"id":"invoice","method":"GET","path":"/invoice","control":"alice","assertions":[{"pointer":"/id","equals":"invoice-1"}],"expectations":{"alice":{"access":"allow","statuses":[200]}}}]}`
			c, err := matrix.Load(strings.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			report, err := matrix.Run(context.Background(), c, func(string) (string, bool) { return "synthetic-token", true })
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Results) != 1 || report.Results[0].Identity != "alice" {
				t.Fatalf("unexpected matrix rows: %+v", report.Results)
			}
			if anonymousRequests.Load() != 0 {
				t.Fatal("omitted identity executed")
			}
			want := map[string]string{"pass": "PASS", "identity-fails": "ERROR", "control-fails": "FAIL"}[mode]
			if report.Results[0].Verdict != want {
				t.Fatalf("verdict=%s want=%s", report.Results[0].Verdict, want)
			}
		})
	}
}
