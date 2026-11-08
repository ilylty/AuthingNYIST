//go:build windows
// +build windows

package libauth

import "syscall"

// ipUnicastIf is IP_UNICAST_IF from ws2ipdef.h; the syscall package does not
// export it.
const ipUnicastIf = 31

// socketControl pins the outbound interface of a socket with IP_UNICAST_IF.
// The option takes the interface index in network byte order: a host order
// value fails with WSAEADDRNOTAVAIL and a 16-bit swap fails with WSAEINVAL.
func socketControl(ifName string, ifIndex int) func(network, address string, c syscall.RawConn) error {
	if ifIndex <= 0 {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var setErr error
		if err := c.Control(func(fd uintptr) {
			setErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, ipUnicastIf, int(htonl(uint32(ifIndex))))
		}); err != nil {
			return err
		}
		return setErr
	}
}

// deviceBindNeedsPrivilege reports that IP_UNICAST_IF needs no privilege.
func deviceBindNeedsPrivilege() bool { return false }

func htonl(v uint32) uint32 {
	return v<<24&0xff000000 | v<<8&0x00ff0000 | v>>8&0x0000ff00 | v>>24&0x000000ff
}
