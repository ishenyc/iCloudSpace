//go:build !darwin

package smtpegress

import "syscall"

func interfaceControl(string) (func(string, string, syscall.RawConn) error, error) {
	return nil, ErrConfiguration
}
