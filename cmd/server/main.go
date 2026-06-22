package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/app"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/versioning"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// -healthcheck lets the (shell-less, distroless) container probe itself:
	//   HEALTHCHECK CMD ["/app/YOUR_APP_NAME", "-healthcheck"]
	healthcheck := flag.Bool("healthcheck", false, "probe the local /health endpoint and exit 0/1")
	flag.Parse()

	if *healthcheck {
		os.Exit(runHealthcheck())
	}

	build := versioning.BuildInfo{Version: version, Commit: commit, Date: date}

	application, err := app.Build(build)
	if err != nil {
		fatal("startup failed", err)
	}

	if err := application.Start(); err != nil {
		fatal("start failed", err)
	}

	waitForSignal(application)
}

func waitForSignal(a *app.App) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	timeout, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.Stop(timeout); err != nil {
		fatal("shutdown failed", err)
	}
}

// runHealthcheck hits the local /health endpoint and returns a process exit code.
func runHealthcheck() int {
	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/health")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}

func fatal(msg string, err error) {
	fmt.Fprintf(os.Stderr, "fatal: %s: %v\n", msg, err)
	os.Exit(1)
}
