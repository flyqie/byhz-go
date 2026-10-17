// Command byhz runs the 鲍鱼盒子 live web viewer.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"byhz-go/internal/backend"
	"byhz-go/internal/config"
	"byhz-go/internal/playback"
	"byhz-go/internal/server"
)

func main() {
	cfg := config.Load()

	state := backend.New(cfg)
	builder := playback.New(state, cfg.KiwiDebug)
	srv := server.New(cfg, state, builder)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
