// Package demo provides a loopback-only fixture API for the CLI's local demo.
package demo

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Handler exposes synthetic invoices; vulnerable deliberately skips ownership checks.
// Callers must bind this handler only to a loopback address.
func Handler(vulnerable bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		reply := func(status int, body any) {
			w.WriteHeader(status)
			if r.Method != http.MethodHead {
				_ = json.NewEncoder(w).Encode(body)
			}
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			reply(405, map[string]string{"error": "method not allowed"})
			return
		}
		subject := map[string]string{"Bearer demo-alice-token": "alice", "Bearer demo-bob-token": "bob", "Bearer demo-admin-token": "admin"}[r.Header.Get("Authorization")]
		if subject == "" {
			reply(401, map[string]string{"error": "authentication required"})
			return
		}
		switch {
		case r.URL.Path == "/me":
			reply(200, map[string]string{"id": subject})
		case r.URL.Path == "/admin/users":
			if subject != "admin" {
				reply(403, map[string]string{"error": "forbidden"})
				return
			}
			reply(200, map[string]any{"kind": "user-list", "users": []string{"alice", "bob", "admin"}})
		case strings.HasPrefix(r.URL.Path, "/invoices/"):
			id := strings.TrimPrefix(r.URL.Path, "/invoices/")
			owner := map[string]string{"alice-1": "alice", "bob-1": "bob"}[id]
			if owner == "" {
				reply(404, map[string]string{"error": "not found"})
				return
			}
			if !vulnerable && subject != owner && subject != "admin" {
				reply(403, map[string]string{"error": "forbidden"})
				return
			}
			reply(200, map[string]any{"id": id, "owner": owner, "amount": 125, "currency": "USD"})
		default:
			reply(404, map[string]string{"error": "not found"})
		}
	})
}
