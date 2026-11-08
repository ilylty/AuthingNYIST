package libauth

// htonl converts a 32-bit value from host to network byte order.
//
// Windows sets IP_UNICAST_IF with the interface index in network byte order,
// and the option only applies with that encoding: host order fails with
// WSAEADDRNOTAVAIL and a 16-bit swap fails with WSAEINVAL. The conversion lives
// here, not in the Windows-only file, so it can be unit tested everywhere.
func htonl(v uint32) uint32 {
	return v<<24&0xff000000 | v<<8&0x00ff0000 | v>>8&0x0000ff00 | v>>24&0x000000ff
}
