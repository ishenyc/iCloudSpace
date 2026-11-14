// icloudspace-smtp-egress is an optional host-side Docker Desktop egress helper.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"icloudspace/internal/smtpegress"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:15879", "host listener")
	token := flag.String("token-file", "", "private proxy authentication token file")
	iface := flag.String("interface", "", "physical macOS interface; empty uses the host route")
	dns := flag.String("dns", "", "IPv4 DNS server:53 when binding a physical interface")
	flag.Parse()
	handler, err := smtpegress.New(smtpegress.Config{TokenFile: *token, Interface: *iface, DNS: *dns})
	if err != nil {
		log.Fatal("SMTP egress configuration rejected")
	}
	listener, err := net.Listen("tcp4", *listen)
	if err != nil {
		log.Fatal("SMTP egress listener unavailable")
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 4096}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		server.Close()
	}()
	log.Print("SMTP egress ready; Apple SMTP destination only")
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatal("SMTP egress stopped unexpectedly")
	}
}
