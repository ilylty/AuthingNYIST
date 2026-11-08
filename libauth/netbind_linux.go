//go:build linux
// +build linux

package libauth

import "syscall"

// socketControl binds every socket created by a net.Dialer to ifName through
// SO_BINDTODEVICE. Linux then routes a bound socket through that interface even
// when another table owns the default route, which is what lets a probe observe
// the campus link instead of a TUN stack.
//
// SO_BINDTODEVICE needs CAP_NET_RAW (or root). NewNet verifies the option on a
// local socket first and falls back to source address pinning when it is not
// permitted.
func socketControl(ifName string, ifIndex int) func(network, address string, c syscall.RawConn) error {
	if ifName == "" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var setErr error
		if err := c.Control(func(fd uintptr) {
			setErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifName)
		}); err != nil {
			return err
		}
		return setErr
	}
}

// deviceBindNeedsPrivilege reports that the Linux device option is privileged.
func deviceBindNeedsPrivilege() bool { return true }
