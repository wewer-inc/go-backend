package main

import (
	"context"
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
	build := versioning.BuildInfo{Version: version, Commit: commit, Date: date}

	application, err := app.Build(build)
	if err != nil {
		panic(err)
	}

	if err := application.Start(); err != nil {
		panic(err)
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
		panic(err)
	}
}
