package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rizko-d/AccessMatrix/internal/demo"
)

func TestCLIValidationAndRun(t *testing.T) {
	for _, vulnerable := range []bool{false, true} {
		server := httptest.NewServer(demo.Handler(vulnerable))
		data, err := os.ReadFile("../../examples/demo.json")
		if err != nil {
			t.Fatal(err)
		}
		data = bytes.ReplaceAll(data, []byte("http://127.0.0.1:8080"), []byte(server.URL))
		path := filepath.Join(t.TempDir(), "config.json")
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("ALICE_TOKEN", "demo-alice-token")
		t.Setenv("BOB_TOKEN", "demo-bob-token")
		t.Setenv("ADMIN_TOKEN", "demo-admin-token")
		var out, stderr bytes.Buffer
		if code := run(context.Background(), []string{"validate", "-config", path}, &out, &stderr); code != 0 {
			t.Fatalf("validate code=%d stderr=%s", code, stderr.String())
		}
		out.Reset()
		stderr.Reset()
		want := 0
		if vulnerable {
			want = 1
		}
		if code := run(context.Background(), []string{"run", "-config", path, "-format", "json"}, &out, &stderr); code != want {
			t.Fatalf("run code=%d want=%d stderr=%s output=%s", code, want, stderr.String(), out.String())
		}
		var report struct{ Results []struct{ Verdict string } }
		if err = json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if len(report.Results) != 12 {
			t.Fatalf("results=%d want=12", len(report.Results))
		}
		counts := map[string]int{}
		for _, r := range report.Results {
			counts[r.Verdict]++
		}
		if vulnerable && (counts["FAIL"] != 2 || counts["PASS"] != 10) {
			t.Fatalf("counts=%v", counts)
		}
		if !vulnerable && counts["PASS"] != 12 {
			t.Fatalf("counts=%v", counts)
		}
		if strings.Contains(out.String(), "demo-alice-token") {
			t.Fatal("credential in report")
		}
		// Report files are private and existing files are not replaced.
		destination := filepath.Join(t.TempDir(), "result.json")
		if code := run(context.Background(), []string{"run", "-config", path, "-format", "json", "-output", destination}, &out, &stderr); code != want {
			t.Fatalf("file code=%d", code)
		}
		info, err := os.Stat(destination)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0077 != 0 {
			t.Fatal("report permissions too broad")
		}
		before, err := os.ReadFile(destination)
		if err != nil {
			t.Fatal(err)
		}
		if code := run(context.Background(), []string{"run", "-config", path, "-output", destination}, &out, &stderr); code != 2 {
			t.Fatalf("overwrite code=%d", code)
		}
		after, _ := os.ReadFile(destination)
		if !bytes.Equal(before, after) {
			t.Fatal("report overwritten")
		}
		server.Close()
	}
}

func TestCLIUsageErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"unknown"}, {"run"}, {"run", "-format", "xml"}, {"version", "extra"}, {"demo", "-listen", "0.0.0.0:8080"}, {"validate", "-config", "missing.json"}} {
		var out, stderr bytes.Buffer
		if code := run(context.Background(), args, &out, &stderr); code != 2 {
			t.Fatalf("%v code=%d", args, code)
		}
	}
	var out, stderr bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &out, &stderr); code != 0 || !strings.Contains(out.String(), "0.1.0") {
		t.Fatal("version failed")
	}
}
