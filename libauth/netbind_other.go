//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

package libauth

import "syscall"

// socketControl has no portable implementation on this platform, so binding is
// limited to the source address set through net.Dialer.LocalAddr.
func socketControl(ifName string, ifIndex int) func(network, address string, c syscall.RawConn) error {
	return nil
}

// deviceBindNeedsPrivilege reports that no privileged device option exists.
func deviceBindNeedsPrivilege() bool { return false }
