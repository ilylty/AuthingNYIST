//go:build darwin
// +build darwin

package libauth

import "syscall"

// ipBoundIf is IP_BOUND_IF from netinet/in.h; the syscall package does not
// export it.
const ipBoundIf = 25

// socketControl pins the outbound interface of a socket with IP_BOUND_IF.
func socketControl(ifName string, ifIndex int) func(network, address string, c syscall.RawConn) error {
	if ifIndex <= 0 {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var setErr error
		if err := c.Control(func(fd uintptr) {
			setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIf, ifIndex)
		}); err != nil {
			return err
		}
		return setErr
	}
}

// deviceBindNeedsPrivilege reports that IP_BOUND_IF needs no privilege.
func deviceBindNeedsPrivilege() bool { return false }
