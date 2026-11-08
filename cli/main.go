package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/Palvef/AuthingNYIST/libauth"
	"github.com/howeyc/gopass"
	"github.com/juju/loggo"
	"gopkg.in/urfave/cli.v1"
)

type Settings struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Ip       string `json:"ip"`
	Host     string `json:"host"`
	HookSucc string `json:"hook-success"`
	NoCheck  bool   `json:"noCheck"`
	KeepOn   bool   `json:"keepOnline"`
	V6       bool   `json:"useV6"`
	Insecure bool   `json:"insecure"`
	Daemon   bool   `json:"daemonize"`
	Debug    bool   `json:"debug"`
	AcID     string `json:"acId"`

	// Adapter pins every socket (probe, portal requests, DNS) to one network
	// interface. "auto" picks the interface that owns the default route.
	Adapter string `json:"adapter"`
	// SourceIP overrides the address derived from Adapter.
	SourceIP string `json:"sourceIp"`
	// DNS lists campus resolvers used instead of the system resolver, so a
	// fake-ip TUN resolver cannot answer campus names.
	DNS string `json:"dns"`
	// ProbeURL is the connectivity target checked by keepalive.
	ProbeURL string `json:"probeUrl"`
	// ProbeMode is "http" (default) or "tcp".
	ProbeMode string `json:"probeMode"`
	// ProbeExpect lists accepted HTTP status codes for the probe.
	ProbeExpect string `json:"probeExpect"`
	// ProbeLocation requires a substring in the probe redirect Location.
	ProbeLocation string `json:"probeLocation"`
	// Interval is the keepalive probe period in seconds.
	Interval int `json:"interval"`
	// Timeout is the per-probe timeout in seconds.
	Timeout int `json:"timeout"`
	// Retries is how many consecutive probe failures trigger a re-auth.
	Retries int `json:"retries"`
}

var logger = loggo.GetLogger("auth-nyist")
var settings Settings

func parseSettingsFile(path string) error {
	sf, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read config file failed (%s)", err)
	}
	defer sf.Close()
	bv, _ := ioutil.ReadAll(sf)
	err = json.Unmarshal(bv, &settings)
	if err != nil {
		return fmt.Errorf("parse config file \"%s\" failed (%s)", path, err)
	}
	logger.Debugf("Read config file \"%s\" succeeded\n", path)
	return nil
}

func mergeCliSettings(c *cli.Context) {
	var merged Settings
	merged.Username = c.GlobalString("username")
	if len(merged.Username) == 0 {
		merged.Username = settings.Username
	}
	merged.Password = c.GlobalString("password")
	if len(merged.Password) == 0 {
		merged.Password = settings.Password
	}
	merged.Ip = c.String("ip")
	if len(merged.Ip) == 0 {
		merged.Ip = settings.Ip
	}
	merged.Host = c.String("host")
	if len(merged.Host) == 0 {
		merged.Host = settings.Host
	}
	merged.HookSucc = c.GlobalString("hook-success")
	if len(merged.HookSucc) == 0 {
		merged.HookSucc = settings.HookSucc
	}
	merged.NoCheck = settings.NoCheck || c.Bool("no-check")
	merged.V6 = settings.V6 || c.GlobalBool("ipv6")
	merged.KeepOn = settings.KeepOn || c.Bool("keep-online")
	merged.Insecure = settings.Insecure || c.GlobalBool("insecure")
	merged.Daemon = settings.Daemon || c.GlobalBool("daemonize")
	merged.Debug = settings.Debug || c.GlobalBool("debug")
	merged.AcID = c.GlobalString("ac-id")
	if len(merged.AcID) == 0 {
		merged.AcID = settings.AcID
	}
	merged.Adapter = c.GlobalString("interface")
	if len(merged.Adapter) == 0 {
		merged.Adapter = settings.Adapter
	}
	merged.SourceIP = c.GlobalString("source-ip")
	if len(merged.SourceIP) == 0 {
		merged.SourceIP = settings.SourceIP
	}
	merged.DNS = c.GlobalString("dns")
	if len(merged.DNS) == 0 {
		merged.DNS = settings.DNS
	}
	merged.ProbeURL = c.String("probe-url")
	if len(merged.ProbeURL) == 0 {
		merged.ProbeURL = c.String("url")
	}
	if len(merged.ProbeURL) == 0 {
		merged.ProbeURL = settings.ProbeURL
	}
	merged.ProbeMode = c.String("probe-mode")
	if len(merged.ProbeMode) == 0 {
		merged.ProbeMode = settings.ProbeMode
	}
	merged.ProbeExpect = c.String("probe-expect")
	if len(merged.ProbeExpect) == 0 {
		merged.ProbeExpect = settings.ProbeExpect
	}
	merged.ProbeLocation = c.String("probe-location")
	if len(merged.ProbeLocation) == 0 {
		merged.ProbeLocation = settings.ProbeLocation
	}
	merged.Interval = c.Int("interval")
	if merged.Interval == 0 {
		merged.Interval = settings.Interval
	}
	merged.Timeout = c.Int("timeout")
	if merged.Timeout == 0 {
		merged.Timeout = settings.Timeout
	}
	merged.Retries = c.Int("retries")
	if merged.Retries == 0 {
		merged.Retries = settings.Retries
	}
	settings = merged
	logger.Debugf("Settings Username: \"%s\"\n", settings.Username)
	logger.Debugf("Settings Ip: \"%s\"\n", settings.Ip)
	logger.Debugf("Settings Host: \"%s\"\n", settings.Host)
	logger.Debugf("Settings HookSucc: \"%s\"\n", settings.HookSucc)
	logger.Debugf("Settings NoCheck: %t\n", settings.NoCheck)
	logger.Debugf("Settings V6: %t\n", settings.V6)
	logger.Debugf("Settings KeepOn: %t\n", settings.KeepOn)
	logger.Debugf("Settings Insecure: %t\n", settings.Insecure)
	logger.Debugf("Settings Daemon: %t\n", settings.Daemon)
	logger.Debugf("Settings Debug: %t\n", settings.Debug)
	logger.Debugf("Settings AcID: \"%s\"\n", settings.AcID)
	logger.Debugf("Settings Adapter: \"%s\"\n", settings.Adapter)
	logger.Debugf("Settings SourceIP: \"%s\"\n", settings.SourceIP)
	logger.Debugf("Settings DNS: \"%s\"\n", settings.DNS)
	logger.Debugf("Settings ProbeURL: \"%s\"\n", settings.ProbeURL)
	logger.Debugf("Settings ProbeMode: \"%s\"\n", settings.ProbeMode)
	logger.Debugf("Settings ProbeExpect: \"%s\"\n", settings.ProbeExpect)
	logger.Debugf("Settings ProbeLocation: \"%s\"\n", settings.ProbeLocation)
	logger.Debugf("Settings Interval: %d\n", settings.Interval)
	logger.Debugf("Settings Timeout: %d\n", settings.Timeout)
	logger.Debugf("Settings Retries: %d\n", settings.Retries)
}

func requestUser() (err error) {
	if len(settings.Username) == 0 && !settings.Daemon {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Username: ")
		settings.Username, _ = reader.ReadString('\n')
		settings.Username = strings.TrimSpace(settings.Username)
	}
	if len(settings.Username) == 0 {
		err = fmt.Errorf("username can't be empty")
	}
	return
}

func requestPasswd() (err error) {
	if len(settings.Password) == 0 && !settings.Daemon {
		var b []byte
		fmt.Printf("Password: ")
		b, err = gopass.GetPasswdMasked()
		if err != nil {
			err = fmt.Errorf("interrupted")
			return
		}
		settings.Password = string(b)
	}
	if len(settings.Password) == 0 {
		err = fmt.Errorf("password can't be empty")
	}
	return
}

func setLoggerLevel(debug bool, daemon bool) {
	if daemon {
		_ = loggo.ConfigureLoggers("auth-nyist=ERROR;libauth=ERROR")
	} else if debug {
		_ = loggo.ConfigureLoggers("auth-nyist=DEBUG;libauth=DEBUG")
	} else {
		_ = loggo.ConfigureLoggers("auth-nyist=INFO;libauth=INFO")
	}
}

func locateConfigFile(c *cli.Context) (cf string) {
	cf = c.GlobalString("config-file")
	if len(cf) != 0 {
		return
	}

	xdgConfigHome := os.Getenv("XDG_CONFIG_HOME")
	homedir, _ := os.UserHomeDir()
	if len(xdgConfigHome) == 0 {
		xdgConfigHome = path.Join(homedir, ".config")
	}
	cf = path.Join(xdgConfigHome, "auth-nyist")
	_, err := os.Stat(cf)
	if !os.IsNotExist(err) {
		return
	}

	cf = path.Join(homedir, ".auth-nyist")
	_, err = os.Stat(cf)
	if !os.IsNotExist(err) {
		return
	}

	return ""
}

func parseSettings(c *cli.Context) (err error) {
	if c.Bool("help") {
		cli.ShowAppHelpAndExit(c, 0)
	}
	setLoggerLevel(c.GlobalBool("debug"), c.GlobalBool("daemonize"))

	cf := locateConfigFile(c)
	if len(cf) == 0 && c.GlobalBool("daemonize") {
		return fmt.Errorf("cannot find config file (it is necessary in daemon mode)")
	}
	if len(cf) != 0 {
		err = parseSettingsFile(cf)
		if err != nil {
			return err
		}
	}
	mergeCliSettings(c)
	setLoggerLevel(settings.Debug, settings.Daemon)
	return
}

func runHook() {
	if settings.HookSucc != "" {
		logger.Debugf("Run hook \"%s\"\n", settings.HookSucc)
		cmd := exec.Command(settings.HookSucc)
		if err := cmd.Run(); err != nil {
			logger.Errorf("Hook execution failed: %v\n", err)
		}
	}
}
func cmdAuth(c *cli.Context) {
	logout := c.Bool("logout")
	err := authUtil(c, logout)
	if err != nil {
		logger.Errorf("Auth error: %s", err)
		os.Exit(1)
	}
}

func cmdDeauth(c *cli.Context) {
	err := authUtil(c, true)
	if err != nil {
		logger.Errorf("Deauth error: %s\n", err)
		os.Exit(1)
	}
}

const (
	defaultProbeURL      = libauth.DefaultProbeURL
	defaultProbeMode     = string(libauth.ProbeHTTP)
	defaultProbeInterval = 5
	defaultProbeTimeout  = 5
	defaultProbeRetries  = 1
)

// DefaultCampusDNS is the NYIST resolver. It is applied automatically when an
// interface is bound but no resolver is configured, because a TUN client in
// fake-ip mode would otherwise answer campus names with 198.18.x.x addresses
// that are unreachable from the bound campus socket.
const DefaultCampusDNS = "59.69.128.96"

// networkFromSettings builds the socket binding described by the settings.
func networkFromSettings() (*libauth.Net, error) {
	dns := splitList(settings.DNS)
	if len(dns) == 0 && len(strings.TrimSpace(settings.Adapter)) != 0 {
		dns = []string{DefaultCampusDNS}
		logger.Debugf("No DNS configured, using campus resolver %s\n", DefaultCampusDNS)
	}
	opts := &libauth.NetworkOptions{
		Interface: settings.Adapter,
		SourceIP:  settings.SourceIP,
		DNS:       dns,
		Insecure:  settings.Insecure,
		Timeout:   time.Duration(effectiveTimeout()) * time.Second,
	}
	return libauth.NewNet(opts)
}

func splitList(in string) []string {
	if strings.TrimSpace(in) == "" {
		return nil
	}
	return strings.FieldsFunc(in, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	})
}

func effectiveInterval() int {
	if settings.Interval <= 0 {
		return defaultProbeInterval
	}
	return settings.Interval
}

func effectiveTimeout() int {
	if settings.Timeout <= 0 {
		return defaultProbeTimeout
	}
	return settings.Timeout
}

func effectiveRetries() int {
	if settings.Retries <= 0 {
		return defaultProbeRetries
	}
	return settings.Retries
}

func probeOptions() (libauth.ProbeOptions, error) {
	target := settings.ProbeURL
	if len(target) == 0 {
		target = defaultProbeURL
	}
	mode := strings.ToLower(strings.TrimSpace(settings.ProbeMode))
	if len(mode) == 0 {
		mode = defaultProbeMode
	}
	if mode != string(libauth.ProbeHTTP) && mode != string(libauth.ProbeTCP) {
		return libauth.ProbeOptions{}, fmt.Errorf("invalid probe mode %q (want http or tcp)", mode)
	}
	codes, err := libauth.ParseStatusList(settings.ProbeExpect)
	if err != nil {
		return libauth.ProbeOptions{}, err
	}
	return libauth.ProbeOptions{
		URL:            target,
		Kind:           libauth.ProbeKind(mode),
		ExpectStatus:   codes,
		ExpectLocation: settings.ProbeLocation,
		Timeout:        time.Duration(effectiveTimeout()) * time.Second,
	}, nil
}

func cmdProbe(c *cli.Context) {
	err := parseSettings(c)
	if err != nil {
		logger.Errorf("Parse setting error: %s\n", err)
		os.Exit(1)
	}
	n, err := networkFromSettings()
	if err != nil {
		logger.Errorf("Network binding error: %s\n", err)
		os.Exit(1)
	}
	opts, err := probeOptions()
	if err != nil {
		logger.Errorf("Probe option error: %s\n", err)
		os.Exit(1)
	}
	logger.Infof("Probe %s using %s\n", opts.URL, n.Description())
	res := libauth.Probe(n, opts)
	logger.Infof("%s\n", res.String())
	if !res.OK {
		os.Exit(2)
	}
}

func cmdKeepalive(c *cli.Context) {
	err := parseSettings(c)
	if err != nil {
		logger.Errorf("Parse setting error: %s\n", err)
		os.Exit(1)
	}
	err = keepAliveLoop(c)
	if err != nil {
		logger.Errorf("Keepalive error: %s\n", err)
		os.Exit(1)
	}
}
func authUtil(c *cli.Context, logout bool) error {
	err := parseSettings(c)
	if err != nil {
		return err
	}
	acID := "1"
	if len(settings.AcID) != 0 {
		acID = settings.AcID
	}
	domain := settings.Host
	if len(settings.Host) == 0 {
		if settings.V6 {
			domain = "auth.nyist.edu.cn"
		} else {
			domain = "auth.nyist.edu.cn"
		}
	}

	host := libauth.NewUrlProvider(domain, settings.Insecure)
	n, err := networkFromSettings()
	if err != nil {
		return fmt.Errorf("network binding: %w", err)
	}
	host = host.WithNet(n)
	if n.Description() != "system routing" {
		logger.Infof("Network binding: %s\n", n.Description())
	}
	if len(settings.Ip) == 0 && !settings.NoCheck {
		online, _, username := libauth.IsOnline(host, acID)
		if logout && online {
			settings.Username = username
		}
		if online && !logout {
			logger.Infof("Currently online!")
			return nil
		} else if !online && logout {
			logger.Infof("Currently offline!")
			return nil
		}
	}
	err = requestUser()
	if err != nil {
		return err
	}
	if !logout {
		err = requestPasswd()
		if err != nil {
			return err
		}
	}

	err = libauth.LoginLogout(settings.Username, settings.Password, host, logout, settings.Ip, acID)
	action := "Login"
	if logout {
		action = "Logout"
	}
	if err == nil {
		logger.Infof("%s Successfully!\n", action)
		runHook()
		if settings.KeepOn {
			if len(settings.Ip) != 0 {
				logger.Errorf("Cannot keep another IP online\n")
			} else if !keepAliveActive {
				// Only start the loop from the top level. keepAliveLoop calls
				// authUtil on every probe failure, so starting a second loop
				// there would nest one loop per recovery attempt.
				return keepAliveLoop(c)
			}
		}
	} else {
		err = fmt.Errorf("%s Failed: %w", action, err)
	}
	return err
}

// keepAliveActive guards against nesting keepAliveLoop inside itself, which
// happens when keepOnline is set and a probe failure triggers authUtil.
var keepAliveActive bool

// keepAliveLoop probes the campus link and re-authenticates after the session is
// dropped.
//
// The probe deliberately defaults to an HTTP round trip: a TUN based proxy
// client terminates TCP in user space, so a bare connect() only proves that the
// tunnel stack answered the SYN (issue #4). Binding the socket to the campus
// adapter (and resolving names through a campus DNS server when one is
// configured) makes the probe observe the real link again.
func keepAliveLoop(c *cli.Context) (ret error) {
	n, err := networkFromSettings()
	if err != nil {
		return fmt.Errorf("network binding: %w", err)
	}
	opts, err := probeOptions()
	if err != nil {
		return err
	}

	keepAliveActive = true
	defer func() { keepAliveActive = false }()

	interval := time.Duration(effectiveInterval()) * time.Second
	retries := effectiveRetries()

	logger.Infof("Checking connectivity to %s (mode=%s, binding=%s, every %s)\n",
		opts.URL, opts.Kind, n.Description(), interval)

	failures := 0
	for {
		res := libauth.Probe(n, opts)
		if res.OK {
			if failures > 0 {
				logger.Infof("Connectivity restored: %s\n", res.String())
			}
			failures = 0
			logger.Debugf("Probe success: %s\n", res.String())
		} else {
			failures++
			logger.Warningf("Probe failed (%d/%d): %s\n", failures, retries, res.String())
			if failures >= retries {
				failures = 0
				// Authhhhhing!
				if authErr := authUtil(c, false); authErr != nil {
					logger.Errorf("auth error: %v\n", authErr)
				}
			}
		}
		time.Sleep(interval)
	}
}

// probeFlagSet returns a fresh flag set for the probe/keepalive commands.
// Each command needs its own values, so the flags are built per call.
func probeFlagSet() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "url", Usage: "probe target `url` or host:port, default " + defaultProbeURL},
		&cli.StringFlag{Name: "probe-url", Usage: "alias of --url"},
		&cli.StringFlag{Name: "probe-mode", Usage: "probe mode: http (default, one round trip) or tcp (handshake only)"},
		&cli.StringFlag{Name: "probe-expect", Usage: "comma separated accepted HTTP status `codes`, e.g. 200,302"},
		&cli.StringFlag{Name: "probe-location", Usage: "require this substring in the probe redirect Location `header`"},
		&cli.IntFlag{Name: "interval", Usage: "seconds between keepalive probes"},
		&cli.IntFlag{Name: "timeout", Usage: "per-probe `timeout` in seconds"},
		&cli.IntFlag{Name: "retries", Usage: "consecutive probe failures before re-authenticating"},
	}
}

func main() {
	app := &cli.App{
		Name: "auth-nyist",
		UsageText: `auth-nyist [options]
	 auth-nyist [options] auth [auth_options]
	 auth-nyist [options] deauth [auth_options]
	 auth-nyist [options] keepalive [keepalive_options]
	 auth-nyist [options] probe [probe_options]`,
		Usage:    "Authenticating utility for NYIST",
		Version:  "2.0.0",
		HideHelp: true,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "username, u", Usage: "your portal account `name`"},
			&cli.StringFlag{Name: "password, p", Usage: "your portal `password`"},
			&cli.StringFlag{Name: "config-file, c", Usage: "`path` to your config file, default ~/.auth-nyist"},
			&cli.StringFlag{Name: "hook-success", Usage: "command line to be executed in shell after successful login/out"},
			&cli.BoolFlag{Name: "daemonize, D", Usage: "run without reading username/password from standard input; less log"},
			&cli.BoolFlag{Name: "debug", Usage: "print debug messages"},
			&cli.StringFlag{Name: "interface, i", Usage: "bind every socket to this network `name` (e.g. wlan0, WLAN, en0; auto = default-route adapter)"},
			&cli.StringFlag{Name: "source-ip", Usage: "pin this local source `ip` instead of deriving it from --interface"},
			&cli.StringFlag{Name: "dns", Usage: "comma separated resolver `servers`, e.g. 59.69.128.96"},
			&cli.BoolFlag{Name: "insecure", Usage: "skip TLS certificate verification"},
			&cli.BoolFlag{Name: "ipv6", Usage: "use the IPv6 portal address"},
			&cli.StringFlag{Name: "ac-id", Usage: "ac_id to send to the portal"},
			&cli.BoolFlag{Name: "help, h", Usage: "print the help"},
		},
		Commands: []cli.Command{
			{
				Name:  "auth",
				Usage: "(default) Auth via auth.nyist.edu.cn",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "ip", Usage: "authenticating for specified IP address"},
					&cli.BoolFlag{Name: "no-check, n", Usage: "skip online checking, always send login request"},
				},
				Action: cmdAuth,
			},
			{
				Name:   "deauth",
				Usage:  "De-authenticate via auth.nyist.edu.cn",
				Action: cmdDeauth,
			},
			{
				Name:   "keepalive",
				Usage:  "Keep the connection alive by probing a server through the campus adapter",
				Flags:  probeFlagSet(),
				Action: cmdKeepalive,
			},
			{
				Name:   "probe",
				Usage:  "Probe the campus link once and report the result",
				Flags:  probeFlagSet(),
				Action: cmdProbe,
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		logger.Errorf("Run error: %s\n", err)
		os.Exit(1)
	}
}
