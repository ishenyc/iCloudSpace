package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"icloudspace/internal/application"
	"icloudspace/internal/installation"
)

func main() {
	flags := flag.NewFlagSet("icloudspace", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configuration := flags.String("process", "", "absolute path to the explicit installation process document")
	if err := flags.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return
		}
		os.Exit(2)
	}
	if *configuration == "" || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: icloudspace -process /absolute/path/process.json")
		os.Exit(2)
	}
	process, err := installation.LoadProcess(*configuration)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := application.Run(ctx, process); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
