package libauth

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/juju/loggo"
)

var logger = loggo.GetLogger("libauth")

func extractJSONFromJSONP(jsonp, callbackName string) (string, error) {
	l := len(callbackName)
	if len(jsonp) < l+2 {
		return "", errors.New("JSONP string too short")
	}
	if jsonp[:l] != callbackName || jsonp[l] != '(' || jsonp[len(jsonp)-1] != ')' {
		return "", errors.New("Invalid format")
	}
	return jsonp[l+1 : len(jsonp)-1], nil
}

// DefaultOS is the os parameter sent with the login request. The SRun portal
// records it in its online table and accepts any value; auth-nyist-cli matches
// the User-Agent this tool already sends.
const DefaultOS = "auth-nyist-cli"

// DefaultDeviceName is the name parameter, reported to the portal alongside os.
const DefaultDeviceName = "auth-nyist-cli"

// ClientIdentity carries the os and name parameters of the SRun login request.
// The portal shows them in its device list and does not validate them, but some
// deployments inspect them (a campus that expects a real client name).
type ClientIdentity struct {
	// OS is the os parameter. Empty selects DefaultOS.
	OS string
	// Name is the name parameter. Empty selects DefaultDeviceName.
	Name string
}

// Resolve fills the defaults, so callers can pass a zero value confidently.
func (c ClientIdentity) Resolve() ClientIdentity {
	if strings.TrimSpace(c.OS) == "" {
		c.OS = DefaultOS
	}
	if strings.TrimSpace(c.Name) == "" {
		c.Name = DefaultDeviceName
	}
	return c
}

func buildChallengeParams(username string, anotherIP string) url.Values {

	challParams := url.Values{
		"username":     []string{username},
		"ip":           []string{anotherIP},
		"double_stack": []string{"1"},
	}

	return challParams
}

func buildLoginParams(username, password, token string, logout bool, anotherIP string, acID string) (loginParams url.Values, err error) {
	return buildLoginParamsWithIdentity(username, password, token, logout, anotherIP, acID, ClientIdentity{})
}

// buildLoginParamsWithIdentity is buildLoginParams plus the os and name
// parameters. os and name are not part of chksum, so adding them does not
// change the signature.
func buildLoginParamsWithIdentity(username, password, token string, logout bool, anotherIP string, acID string, identity ClientIdentity) (loginParams url.Values, err error) {
	identity = identity.Resolve()
	ip := anotherIP
	hmd5 := fmt.Sprintf("%032x", md5.Sum([]byte(password)))

	action := "login"
	rawInfo := map[string]string{
		"username": username,
		"password": password,
		"ip":       ip,
		"acid":     acID,
		"enc_ver":  "s" + "run" + "_bx1",
	}
	if logout {
		action = "logout"
		delete(rawInfo, "password")
	}
	infoJSON, _ := json.Marshal(rawInfo)

	loginParams = url.Values{
		"action":       []string{action},
		"ac_id":        []string{acID},
		"n":            []string{"200"},
		"type":         []string{"1"},
		"ip":           []string{ip},
		"double_stack": []string{"1"},
		"username":     []string{username},
		"os":           []string{identity.OS},
		"name":         []string{identity.Name},
	}
	if !logout {
		loginParams.Add("password", "{MD5}"+hmd5)
	}
	encoded := XEncode(string(infoJSON), token)
	if encoded == nil {
		err = errors.New("XEncode failed")
		return
	}
	loginParams.Add("info", "{SRBX1}"+QuirkBase64Encode(*encoded))

	if logout {
		loginParams.Add("chksum", sha1sum(token+username+token+acID+token+ip+token+loginParams.Get("n")+token+loginParams.Get("type")+token+loginParams.Get("info")))
	} else {
		loginParams.Add("chksum", sha1sum(token+username+token+hmd5+token+acID+token+ip+token+loginParams.Get("n")+token+loginParams.Get("type")+token+loginParams.Get("info")))
	}

	return
}

// loginTimeout returns the HTTP timeout used for portal requests. A bound net
// keeps its configured dial timeout so a slow campus link does not abort the
// challenge exchange.
func loginTimeout(host *UrlProvider) time.Duration {
	if host != nil && host.net != nil && host.net.Options.Timeout > 0 {
		return host.net.Options.Timeout
	}
	return time.Second * 5
}

func GetJSON(baseUrl string, params url.Values) (string, error) {
	return GetJSONWithNet(nil, baseUrl, params, 0)
}

// GetJSONWithNet performs the JSONP GET through n. A nil n follows the system
// routing, and a zero timeout selects the default.
func GetJSONWithNet(n *Net, baseUrl string, params url.Values, timeout time.Duration) (string, error) {
	const CB = "C_a_l_l_b_a_c_k"
	params.Set("callback", CB)
	if timeout <= 0 {
		timeout = time.Second * 2
	}
	netClient := n.HTTPClientWithRedirect(timeout, nil)
	url := baseUrl + "?" + params.Encode()
	logger.Debugf("GET \"%s\"\n", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "auth-nyist-cli")
	logger.Debugf("User-Agent: auth-nyist-cli\n")

	resp, err := netClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return extractJSONFromJSONP(string(body), CB)
}

func IsOnline(host *UrlProvider, acID string) (online bool, err error, username string) {
	netClient := host.net.HTTPClientWithRedirect(time.Second*2, func(req *http.Request, via []*http.Request) error {
		logger.Debugf("REDIRECT \"%v\"\n", req.URL)
		if strings.Index(req.URL.Path, "succeed_wired.php") != -1 {
			online = true
			regexUsername := regexp.MustCompile(`username=([-a-zA-Z0-9]+)`)
			matches := regexUsername.FindStringSubmatch(req.URL.RawQuery)
			if len(matches) > 0 {
				username = matches[1]
				logger.Debugf("Extracted username: \"%s\"\n", username)
			}

		}
		return nil
	})
	online = false
	params := url.Values{
		"ac_id": []string{acID},
	}
	url := host.OnlineCheckUriBase() + "?" + params.Encode()
	logger.Debugf("GET \"%s\"\n", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "auth-nyist-cli")
	logger.Debugf("User-Agent: auth-nyist-cli\n")

	resp, err := netClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	return
}

func LoginLogout(username, password string, host *UrlProvider, logout bool, anotherIP string, acID string) (err error) {
	return LoginLogoutWithIdentity(username, password, host, logout, anotherIP, acID, ClientIdentity{})
}

// LoginLogoutWithIdentity performs login or logout, reporting identity.OS and
// identity.Name to the portal through the os and name query parameters.
func LoginLogoutWithIdentity(username, password string, host *UrlProvider, logout bool, anotherIP string, acID string, identity ClientIdentity) (err error) {
	logger.Debugf("Getting challenge...\n")
	body, err := GetJSONWithNet(host.net, host.ChallengeUriBase(), buildChallengeParams(username, anotherIP), loginTimeout(host))
	if err != nil {
		return
	}
	logger.Debugf("Challenge response: %v\n", body)

	var challResp map[string]interface{}
	err = json.Unmarshal([]byte(body), &challResp)
	if err != nil {
		return
	}
	res, valid := challResp["res"].(string)
	if !valid || res != "ok" {
		err = errors.New("Failed to get challenge: " + res)
		return
	}
	token, valid := challResp["challenge"].(string)
	if !valid {
		err = errors.New("No challenge field")
		return
	}

	loginParams, err := buildLoginParamsWithIdentity(username, password, token, logout, anotherIP, acID, identity)
	if err != nil {
		return
	}
	logger.Debugf("Sending login request...\n")
	body, err = GetJSONWithNet(host.net, host.LoginUriBase(), loginParams, loginTimeout(host))
	if err != nil {
		return
	}
	logger.Debugf("Login response: %v\n", body)
	var loginResp map[string]interface{}
	err = json.Unmarshal([]byte(body), &loginResp)
	if err != nil {
		return
	}
	res, valid = loginResp["error"].(string)
	if !valid {
		err = errors.New("No error field")
		return
	}

	if res == "ok" {
		err = nil
	} else {
		ecode, _ := loginResp["ecode"].(string)
		if strerr, exist := PortalError[ecode]; exist {
			err = errors.New(strerr)
		} else {
			err = errors.New(res)
		}
	}

	return
}
