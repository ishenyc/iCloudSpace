package main

import (
	"context"
	"flag"
	"os"

	"icloudspace/internal/healthprobe"
)

func main() {
	address := flag.String("address", "127.0.0.1:8080", "local canonical HTTP listener")
	flag.Parse()
	if flag.NArg() != 0 || !healthprobe.Probe(context.Background(), *address) {
		os.Exit(1)
	}
}
