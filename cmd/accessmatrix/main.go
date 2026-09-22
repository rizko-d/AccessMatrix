// AccessMatrix verifies explicit API authorization expectations.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"text/tabwriter"
	"time"

	matrix "github.com/rizko-d/AccessMatrix"
	"github.com/rizko-d/AccessMatrix/internal/demo"
)

const version = "0.1.0"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, out, errout io.Writer) int {
	fail := func(message string) int { fmt.Fprintln(errout, "accessmatrix:", message); return 2 }
	if len(args) == 0 {
		return fail("usage: accessmatrix <validate|run|demo|version> [options]")
	}
	if args[0] == "version" {
		if len(args) != 1 {
			return fail("version accepts no arguments")
		}
		if _, err := fmt.Fprintln(out, "AccessMatrix", version); err != nil {
			return 2
		}
		return 0
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprintln(out, "Usage: accessmatrix <validate|run|demo|version> [options]\n\nvalidate -config FILE\nrun -config FILE [-format table|json] [-output FILE]\ndemo [-vulnerable] [-listen 127.0.0.1:8080]\nversion\n\nExit codes: 0 all checks pass; 1 policy failure; 2 error or inconclusive.")
		return 0
	}
	if args[0] == "demo" {
		return serveDemo(ctx, args[1:], out, errout)
	}
	if args[0] != "run" && args[0] != "validate" {
		return fail("unknown command")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	// Do not echo invalid user-supplied flag values, which may contain credentials.
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "JSON configuration file")
	format := fs.String("format", "table", "table or json")
	output := fs.String("output", "", "new report file; will not overwrite")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(out)
			fs.PrintDefaults()
			return 0
		}
		return fail("invalid options; use -h")
	}
	if fs.NArg() != 0 || *path == "" {
		return fail("a -config file is required; positional arguments are not accepted")
	}
	if *format != "json" && *format != "table" {
		return fail("format must be table or json")
	}
	if args[0] == "validate" && (*output != "" || *format != "table") {
		return fail("validate accepts only -config")
	}
	f, err := os.Open(*path)
	if err != nil {
		return fail("cannot open config file")
	}
	cfg, err := matrix.Load(f)
	closeErr := f.Close()
	if err != nil {
		return fail(err.Error())
	}
	if closeErr != nil {
		return fail("cannot close config file")
	}
	if args[0] == "validate" {
		if _, err = fmt.Fprintln(out, "Configuration valid. No requests sent; credentials not checked."); err != nil {
			return 2
		}
		return 0
	}
	writer := out
	var file *os.File
	keep := false
	if *output != "" {
		file, err = os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return fail("cannot create output file; choose a new path")
		}
		defer func() {
			file.Close()
			if !keep {
				_ = os.Remove(*output)
			}
		}()
		writer = file
	}
	report, err := matrix.Run(ctx, cfg, os.LookupEnv)
	if err != nil {
		return fail(err.Error())
	}
	if *format == "json" {
		enc := json.NewEncoder(writer)
		enc.SetIndent("", "  ")
		err = enc.Encode(report)
	} else {
		err = writeTable(writer, report)
	}
	if err != nil {
		return fail("could not write report")
	}
	if file != nil {
		if err = file.Sync(); err != nil {
			return fail("could not sync report")
		}
		if err = file.Close(); err != nil {
			return fail("could not close report")
		}
		keep = true
	}
	return exitCode(report)
}

func exitCode(report matrix.Report) int {
	if len(report.Results) == 0 {
		return 2
	}
	code := 0
	for _, r := range report.Results {
		switch r.Verdict {
		case "PASS":
		case "FAIL":
			if code == 0 {
				code = 1
			}
		default:
			code = 2
		}
	}
	return code
}

func writeTable(w io.Writer, report matrix.Report) error {
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "TEST\tIDENTITY\tEXPECTED\tRESULT\tHTTP\tREASON"); err != nil {
		return err
	}
	counts := map[string]int{}
	for _, r := range report.Results {
		counts[r.Verdict]++
		if _, err := fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%d\t%s\n", r.Test, r.Identity, r.Expected, r.Verdict, r.Status, r.Reason); err != nil {
			return err
		}
	}
	if err := table.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "\nPASS %d | FAIL %d | INCONCLUSIVE %d | ERROR %d\n", counts["PASS"], counts["FAIL"], counts["INCONCLUSIVE"], counts["ERROR"])
	return err
}

func serveDemo(ctx context.Context, args []string, out, errout io.Writer) int {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	vulnerable := fs.Bool("vulnerable", false, "deliberately omit invoice ownership checks")
	listen := fs.String("listen", "127.0.0.1:8080", "literal loopback address and port")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(out)
			fs.PrintDefaults()
			return 0
		}
		fmt.Fprintln(errout, "invalid demo options")
		return 2
	}
	host, port, err := net.SplitHostPort(*listen)
	n, portErr := strconv.Atoi(port)
	ip := net.ParseIP(host)
	if err != nil || portErr != nil || n < 0 || n > 65535 || ip == nil || !ip.IsLoopback() || fs.NArg() != 0 {
		fmt.Fprintln(errout, "demo requires a literal loopback listen address and valid port")
		return 2
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(errout, "cannot listen on demo address")
		return 2
	}
	server := &http.Server{Handler: demo.Handler(*vulnerable), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()
	mode := "fixed"
	if *vulnerable {
		mode = "vulnerable"
	}
	fmt.Fprintf(out, "Demo API (%s): http://%s\nSynthetic credentials only; Ctrl-C to stop.\n", mode, listener.Addr())
	err = server.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(errout, "demo server failed")
		return 2
	}
	return 0
}
