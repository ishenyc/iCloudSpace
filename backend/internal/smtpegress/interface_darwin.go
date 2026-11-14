package smtpegress

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func interfaceControl(name string) (func(string, string, syscall.RawConn) error, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return nil, ErrConfiguration
	}
	return func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		err := raw.Control(func(fd uintptr) {
			socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, iface.Index)
		})
		if err != nil {
			return err
		}
		return socketErr
	}, nil
}
