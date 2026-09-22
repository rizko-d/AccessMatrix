package demo_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rizko-d/AccessMatrix/internal/demo"
)

func TestInvoiceOwnership(t *testing.T) {
	for _, vulnerable := range []bool{false, true} {
		server := httptest.NewServer(demo.Handler(vulnerable))
		for _, tt := range []struct {
			token, path string
			want        int
		}{
			{"demo-alice-token", "/invoices/alice-1", 200},
			{"demo-bob-token", "/invoices/alice-1", 403},
			{"demo-admin-token", "/invoices/alice-1", 200},
			{"", "/invoices/alice-1", 401},
			{"wrong", "/me", 401},
			{"demo-alice-token", "/admin/users", 403},
			{"demo-admin-token", "/admin/users", 200},
			{"demo-alice-token", "/invoices/missing", 404},
		} {
			want := tt.want
			if vulnerable && tt.token == "demo-bob-token" && tt.path == "/invoices/alice-1" {
				want = 200
			}
			req, _ := http.NewRequest(http.MethodGet, server.URL+tt.path, nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]any
			err = json.NewDecoder(resp.Body).Decode(&body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != want {
				t.Fatalf("vulnerable=%v path=%s status=%d want=%d", vulnerable, tt.path, resp.StatusCode, want)
			}
			if resp.StatusCode == 200 && tt.path == "/invoices/alice-1" && body["owner"] != "alice" {
				t.Fatal("wrong invoice owner")
			}
		}
		server.Close()
	}
}
