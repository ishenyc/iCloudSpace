// Package installationresources checks the concrete certificate and built web
// resources shared by explicit initialization and canonical startup.
package installationresources

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"icloudspace/internal/httpapi"
	"icloudspace/internal/installation"
)

var ErrResources = errors.New("installationresources: certificate or built web resources rejected")

// Certificate verifies a usable key pair and the declared public hostname.
// Existing locally trusted certificates need no new issuer or replacement.
func Certificate(settings installation.Settings) (tls.Certificate, error) {
	public, err := readPEM(settings.TLSCertificate, false)
	if err != nil {
		return tls.Certificate{}, ErrResources
	}
	private, err := readPEM(settings.TLSPrivateKey, true)
	if err != nil {
		return tls.Certificate{}, ErrResources
	}
	defer clear(private)
	pair, err := tls.X509KeyPair(public, private)
	if err != nil || len(pair.Certificate) == 0 {
		return tls.Certificate{}, ErrResources
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	now := time.Now()
	if err != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || settings.PublicHost == "" || leaf.VerifyHostname(settings.PublicHost) != nil {
		return tls.Certificate{}, ErrResources
	}
	pair.Leaf = leaf
	return pair, nil
}

func readPEM(path string, private bool) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrResources
	}
	defer file.Close()
	info, err := file.Stat()
	const limit = 1 << 20
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit || private && info.Mode().Perm()&0077 != 0 {
		return nil, ErrResources
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(raw) > limit {
		clear(raw)
		return nil, ErrResources
	}
	return raw, nil
}

// ValidateResources performs no database, network, directory-creation or
// listener operation. Web checking uses the same concrete UI loader as serve.
func ValidateResources(process installation.Process, settings installation.Settings) error {
	if _, err := process.Budgets(); err != nil {
		return ErrResources
	}
	if installation.ValidateSettings(settings) != nil || process.InstallationID != settings.ID || process.MaximumSources < 1 || process.MaximumSources > 10000 || settings.SyncConcurrency > 256 {
		return ErrResources
	}
	if _, err := process.ExternalRegistrationKeyHash(); err != nil {
		return ErrResources
	}
	if _, err := Certificate(settings); err != nil {
		return err
	}
	ui, err := httpapi.NewManagementUI(process.WebDirectory, settings.ManagementPath)
	if err != nil {
		return ErrResources
	}
	if ui.Close() != nil {
		return ErrResources
	}
	viewer, err := httpapi.NewPublicViewerUI(process.WebDirectory)
	if err != nil {
		return ErrResources
	}
	if viewer.Close() != nil {
		return ErrResources
	}
	docs, err := httpapi.NewPublicDocumentation(process.WebDirectory)
	if err != nil {
		return ErrResources
	}
	if docs.Close() != nil {
		return ErrResources
	}
	return nil
}
