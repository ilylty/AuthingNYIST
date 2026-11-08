package libauth

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// The os and name parameters of the SRun login request are displayed in the
// portal's device list and are not part of the checksum, so they are free-form.
// auth-nyist-cli is the honest default. On April 1st the defaults become an
// April Fools surprise instead, which the portal happily stores.

// aprilFoolsDevices lists the strings used for both os and name on April 1st.
// One list serves both fields so the portal shows a single coherent device
// name instead of a mismatched os/name pair.
var aprilFoolsDevices = []string{
	"Windows 11 Pro 24H2",
	"macOS Sequoia 15.1",
	"Ubuntu 24.04 LTS",
	"Gentoo Linux (stage1, 2004 vintage)",
	"Windows 7 旗舰版 已激活",
	"不想996",
	"已经睡了的服务器",
	"校园网管理员",
	"图书馆馆长",
	"隔壁宿舍的路由器",
	"Solarized TempleOS",
	"Android 15 (Magisk root)",
	"FreeBSD 14.1-RELEASE",
	"NAS (不是网盘)",
	"蹭网的",
	"PRINTER-3000 (共享打印机)",
	"网管不在，勿扰",
	"实验室第 8 台树莓派",
}

// IsAprilFools reports whether t falls on April 1st in its own location. The
// window is the whole local day, so the egg follows the device clock rather
// than UTC.
func IsAprilFools(t time.Time) bool {
	return t.Month() == time.April && t.Day() == 1
}

// AprilFoolsDevice returns the device string used for both os and name on April
// 1st.
func AprilFoolsDevice(seed int64) string {
	r := rand.New(rand.NewSource(seed))
	return aprilFoolsDevices[r.Intn(len(aprilFoolsDevices))]
}

// AprilFoolsIdentity returns the egg identity: one device string for both
// fields, so os and name never disagree.
func AprilFoolsIdentity(seed int64) ClientIdentity {
	device := AprilFoolsDevice(seed)
	return ClientIdentity{OS: device, Name: device}
}

// DefaultIdentity returns the identity to use for a login at t. With egg
// disabled, or outside April 1st, it is the plain default. With egg enabled on
// April 1st both fields become the same random device string.
//
// A non-empty OS or Name in explicit always wins over the egg, because a user
// who typed a value meant it.
func DefaultIdentity(t time.Time, explicit ClientIdentity, egg bool) ClientIdentity {
	resolved := explicit.Resolve()
	if !egg || !IsAprilFools(t) {
		return resolved
	}
	device := AprilFoolsDevice(t.UnixNano())
	// Replace only the fields that would otherwise fall back to the default, so
	// an explicit --os or --device-name is preserved.
	if isDefaultOS(explicit.OS) {
		resolved.OS = device
	}
	if isDefaultName(explicit.Name) {
		resolved.Name = device
	}
	return resolved
}

// isDefaultOS reports whether value would fall back to DefaultOS.
func isDefaultOS(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == "" || strings.EqualFold(trimmed, DefaultOS)
}

// isDefaultName reports whether value would fall back to DefaultDeviceName.
func isDefaultName(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == "" || strings.EqualFold(trimmed, DefaultDeviceName)
}

// Describe renders the identity for logs.
func (c ClientIdentity) String() string {
	resolved := c.Resolve()
	if resolved.OS == resolved.Name {
		return fmt.Sprintf("%q", resolved.OS)
	}
	return fmt.Sprintf("os=%q name=%q", resolved.OS, resolved.Name)
}
