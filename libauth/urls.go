package libauth

type UrlProvider struct {
	protocol, host string
	net            *Net
}

func NewUrlProvider(host string, insecure bool) *UrlProvider {
	u := new(UrlProvider)
	u.host = host
	if insecure {
		u.protocol = "http://"
	} else {
		u.protocol = "https://"
	}
	return u
}

// WithNet attaches a network binding. Every request made through this provider
// then leaves through the selected adapter with the selected DNS server, which
// keeps the portal reachable while a TUN client owns the default route.
func (u *UrlProvider) WithNet(n *Net) *UrlProvider {
	u.net = n
	return u
}

// Net returns the attached network binding, possibly nil.
func (u *UrlProvider) Net() *Net { return u.net }

func (u *UrlProvider) LoginUriBase() string {
	return u.protocol + u.host + "/cgi-bin/srun_portal"
}

func (u *UrlProvider) OnlineCheckUriBase() string {
	return u.protocol + u.host + "/srun_portal_pc"
}

func (u *UrlProvider) ChallengeUriBase() string {
	return u.protocol + u.host + "/cgi-bin/get_challenge"
}
