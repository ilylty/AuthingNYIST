package libauth

import (
	"strings"
	"testing"
	"time"
)

func TestClientIdentityResolveDefaults(t *testing.T) {
	got := ClientIdentity{}.Resolve()
	if got.OS != DefaultOS || got.Name != DefaultDeviceName {
		t.Fatalf("zero value should resolve to the defaults, got %+v", got)
	}
	custom := ClientIdentity{OS: "Windows 11", Name: "desk"}.Resolve()
	if custom.OS != "Windows 11" || custom.Name != "desk" {
		t.Fatalf("explicit values must survive Resolve, got %+v", custom)
	}
	// Whitespace-only input falls back, so a stray flag value cannot blank the
	// reported device.
	blank := ClientIdentity{OS: "  ", Name: "\t"}.Resolve()
	if blank.OS != DefaultOS || blank.Name != DefaultDeviceName {
		t.Fatalf("blank values should resolve to defaults, got %+v", blank)
	}
}

// TestBuildLoginParamsSendsIdentity is the regression test for the os/name
// parameters: the portal reads them from the login query string.
func TestBuildLoginParamsSendsIdentity(t *testing.T) {
	params, err := buildLoginParamsWithIdentity("user", "pass", "tok", false, "10.0.0.1", "1",
		ClientIdentity{OS: "不想996", Name: "Windows"})
	if err != nil {
		t.Fatalf("buildLoginParamsWithIdentity: %v", err)
	}
	if got := params.Get("os"); got != "不想996" {
		t.Errorf("os = %q, want %q", got, "不想996")
	}
	if got := params.Get("name"); got != "Windows" {
		t.Errorf("name = %q, want %q", got, "Windows")
	}
}

func TestBuildLoginParamsIdentityDefaults(t *testing.T) {
	params, err := buildLoginParamsWithIdentity("user", "pass", "tok", false, "10.0.0.1", "1", ClientIdentity{})
	if err != nil {
		t.Fatalf("buildLoginParamsWithIdentity: %v", err)
	}
	if got := params.Get("os"); got != DefaultOS {
		t.Errorf("os = %q, want the default %q", got, DefaultOS)
	}
	if got := params.Get("name"); got != DefaultDeviceName {
		t.Errorf("name = %q, want the default %q", got, DefaultDeviceName)
	}
}

// TestIdentityDoesNotAffectChecksum guards the signature: os and name are not
// part of chksum, so adding them must leave the hash untouched.
func TestIdentityDoesNotAffectChecksum(t *testing.T) {
	plain, err := buildLoginParams("user", "pass", "tok", false, "10.0.0.1", "1")
	if err != nil {
		t.Fatalf("buildLoginParams: %v", err)
	}
	decorated, err := buildLoginParamsWithIdentity("user", "pass", "tok", false, "10.0.0.1", "1",
		ClientIdentity{OS: "FreeBSD", Name: "toaster"})
	if err != nil {
		t.Fatalf("buildLoginParamsWithIdentity: %v", err)
	}
	if plain.Get("chksum") != decorated.Get("chksum") {
		t.Fatalf("chksum changed:\n plain    = %s\n decorated= %s", plain.Get("chksum"), decorated.Get("chksum"))
	}
	if plain.Get("info") != decorated.Get("info") {
		t.Fatalf("info changed:\n plain    = %s\n decorated= %s", plain.Get("info"), decorated.Get("info"))
	}
}

func TestIsAprilFools(t *testing.T) {
	cases := []struct {
		when time.Time
		want bool
	}{
		{time.Date(2026, time.April, 1, 0, 0, 0, 0, time.Local), true},
		{time.Date(2026, time.April, 1, 23, 59, 59, 0, time.Local), true},
		{time.Date(2026, time.April, 2, 0, 0, 0, 0, time.Local), false},
		{time.Date(2026, time.March, 31, 23, 59, 59, 0, time.Local), false},
		{time.Date(2026, time.May, 1, 12, 0, 0, 0, time.Local), false},
	}
	for _, c := range cases {
		if got := IsAprilFools(c.when); got != c.want {
			t.Errorf("IsAprilFools(%s) = %v, want %v", c.when.Format(time.RFC3339), got, c.want)
		}
	}
}

func TestDefaultIdentityOutsideAprilFools(t *testing.T) {
	when := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.Local)
	got := DefaultIdentity(when, ClientIdentity{}, true)
	if got.OS != DefaultOS || got.Name != DefaultDeviceName {
		t.Fatalf("outside April 1st the default must stand, got %+v", got)
	}
}

func TestDefaultIdentityOnAprilFools(t *testing.T) {
	when := time.Date(2026, time.April, 1, 9, 0, 0, 0, time.Local)
	got := DefaultIdentity(when, ClientIdentity{}, true)

	if got.OS == DefaultOS && got.Name == DefaultDeviceName {
		t.Fatalf("April 1st with the egg enabled should change the identity, got %+v", got)
	}
	if strings.TrimSpace(got.OS) == "" || strings.TrimSpace(got.Name) == "" {
		t.Fatalf("egg identity must not be empty, got %+v", got)
	}
	// Both fields come from the same draw, so they must be real list entries.
	if !containsString(aprilFoolsOS, got.OS) {
		t.Errorf("os %q is not from the egg list", got.OS)
	}
	if !containsString(aprilFoolsName, got.Name) {
		t.Errorf("name %q is not from the egg list", got.Name)
	}
}

func TestDefaultIdentityEggDisabled(t *testing.T) {
	when := time.Date(2026, time.April, 1, 9, 0, 0, 0, time.Local)
	got := DefaultIdentity(when, ClientIdentity{}, false)
	if got.OS != DefaultOS || got.Name != DefaultDeviceName {
		t.Fatalf("egg disabled must keep the default, got %+v", got)
	}
}

// TestExplicitIdentityBeatsEgg keeps --os/--device-name authoritative even on
// April 1st.
func TestExplicitIdentityBeatsEgg(t *testing.T) {
	when := time.Date(2026, time.April, 1, 9, 0, 0, 0, time.Local)
	got := DefaultIdentity(when, ClientIdentity{OS: "OpenBSD 7.6", Name: "router"}, true)
	if got.OS != "OpenBSD 7.6" || got.Name != "router" {
		t.Fatalf("explicit identity must win over the egg, got %+v", got)
	}
}

func TestAprilFoolsIdentityIsDeterministic(t *testing.T) {
	a := AprilFoolsIdentity(42)
	b := AprilFoolsIdentity(42)
	if a != b {
		t.Fatalf("same seed must produce the same identity: %+v vs %+v", a, b)
	}
}

func TestClientIdentityString(t *testing.T) {
	got := ClientIdentity{OS: "abc", Name: "def"}.String()
	if !strings.Contains(got, `os="abc"`) || !strings.Contains(got, `name="def"`) {
		t.Fatalf("unexpected rendering: %s", got)
	}
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
