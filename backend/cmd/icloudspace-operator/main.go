package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"icloudspace/internal/operatorctl"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(operatorctl.Run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
