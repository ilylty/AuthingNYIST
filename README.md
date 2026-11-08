# AuthingNYIST

[![Build Status](https://github.com/Palvef/AuthingNYIST/actions/workflows/go.yml/badge.svg)](https://github.com/Palvef/AuthingNYIST/actions)
![GPLv3](https://img.shields.io/badge/license-GPLv3-blue.svg)

A command-line NYIST (auth.nyist.edu.cn) authentication tool.

## Download Binary

Download prebuilt binaries from <https://github.com/Palvef/AuthingNYIST/releases>

## Usage

Simply try `./auth-nyist`, then enter your user name and password.

```help
NAME:
   auth-nyist - Authenticating utility for NYIST

USAGE:
   auth-nyist [options]
   auth-nyist [options] auth [auth_options]
   auth-nyist [options] deauth [auth_options]
   auth-nyist [options] keepalive [keepalive_options]
   auth-nyist [options] probe [probe_options]

VERSION:
   2.4.0

COMMANDS:
     auth       (default) Auth via auth.nyist.edu.cn
     deauth     De-authenticate via auth.nyist.edu.cn
     keepalive  Keep the connection alive by probing a server through the campus adapter
     probe      Probe the campus link once and report the result

GLOBAL OPTIONS:
   --username name, -u name          your portal account name
   --password password, -p password  your portal password
   --config-file path, -c path       path to your config file, default ~/.auth-nyist
   --hook-success value              command line to be executed in shell after successful login/out
   --daemonize, -D                   run without reading username/password from standard input; less log
   --debug                           print debug messages
   --interface name, -i name         bind every socket to this network name (e.g. wlan0, WLAN, en0; auto = default-route adapter)
   --source-ip ip                    pin this local source ip instead of deriving it from --interface
   --dns servers                     comma separated resolver servers, e.g. 59.69.128.96
   --insecure                        skip TLS certificate verification
   --strict-interface                fail instead of degrading when --interface is unavailable
   --os os                           os parameter reported to the portal, default auth-nyist-cli
   --device-name name                device name parameter reported to the portal, default auth-nyist-cli
   --no-egg                          disable the April 1st device-name egg
   --help, -h                        print the help
   --version, -v                     print the version
```

The program looks for a config file in `$XDG_CONFIG_HOME/auth-nyist`, `~/.config/auth-nyist`, `~/.auth-nyist` in order.
Write a config file to store your username & password or other options in the following format.

```json
{
  "username": "your-username",
  "password": "your-password",
  "host": "",
  "ip": "166.xxx.xx.xx",
  "debug": false,
  "useV6": false,
  "noCheck": false,
  "insecure": false,
  "daemonize": false,
  "acId": "",

  "adapter": "auto",
  "sourceIp": "",
  "dns": "59.69.128.96",
  "probeUrl": "http://122.207.209.6:8080/",
  "probeMode": "http",
  "probeExpect": "",
  "probeLocation": "",
  "interval": 5,
  "timeout": 5,
  "retries": 1,
  "os": "auth-nyist-cli",
  "name": "auth-nyist-cli",
  "noEgg": false
}
```

Unless you have special need, you can only have `username` and `password` field in your config file. For `host`, the default value defined in code should be sufficient hence there should be no need to fill it. `UseV6` automatically determine the `host` to use. For `ip`, unless you are auth/login the other boxes you have(not the box `auth-nyist` is running on), you can leave it blank. For those boxes unable to get correct acid themselves, we can specify the acid for them by using `acId`. Other options are self-explanatory.

### Network binding (TUN / fake-ip proxy clients)

If a proxy client owns the default route through a TUN interface (Hiddify, Clash Meta, sing-box, Surge …), the campus link is only reachable by name or by a route rule, and a plain `connect()` completes against the tunnel stack instead of the portal. Three settings keep the tool and its keepalive probe on the real link:

| Key | Meaning |
| --- | --- |
| `adapter` | Interface every socket is bound to. `auto` picks the wireless adapter that owns the default route, skipping `tun*`/`utun*`/`Meta` and container bridges. `wlan0`, `WLAN`, `en0` … also work. |
| `sourceIp` | Local source address. Derived from `adapter` when empty; set it only when an adapter holds several addresses. |
| `dns` | Resolvers used instead of the system resolver, e.g. `59.69.128.96`. Applied automatically (with `59.69.128.96`) whenever `adapter` is set and this key is empty, because a proxy in `fake-ip` mode otherwise resolves campus names to `198.18.x.x`, which are unreachable from the bound campus socket. |
| `strictInterface` | Fail instead of degrading when `adapter` is unavailable. Without it the binding degrades and recovers on its own, which is what a service should do. |

Binding behaviour per platform:

- Linux: `SO_BINDTODEVICE` plus the source address. The socket option needs `CAP_NET_RAW`, so run as root or grant the capability; without it the tool warns once and falls back to source address pinning.
- Windows: `IP_UNICAST_IF` with the interface index in network byte order, plus the source address.
- macOS: `IP_BOUND_IF` plus the source address.
- Other platforms: source address pinning only.

### Missing adapter

A named adapter is not guaranteed to exist: a module can start before Wi-Fi associates, and a laptop changes adapters between networks. The binding therefore degrades instead of aborting:

1. the requested adapter, when it exists and holds a global IPv4 address;
2. auto detection, which prefers the wireless adapter owning a default route and skips `tun*`/`utun*`/`Meta` and container bridges;
3. no binding at all (system routing).

`keepalive` rebuilds the binding every round, so it returns to the adapter as soon as it reappears. The log reports the state:

```
WARNING Interface "wlan0" unavailable (route ip+net: no such network interface)
WARNING No usable campus interface (...); falling back to system routing
INFO    Checking connectivity to 122.207.209.6:8080 (mode=tcp, binding=system routing (degraded from wlan0 (not found)), every 5s)
INFO    Binding restored: interface=wlan0 source=10.2.41.236 dns=59.69.128.96:53
```

A binding also degrades when the adapter keeps its name but changes its address, because a pinned source address that no longer exists makes every dial fail. Pass `--strict-interface` (or `"strictInterface": true`) to turn the fallback into a hard error instead, which is what a one-shot script or a CI check wants.

Check the result before trusting a keepalive loop:

```shell
auth-nyist -i auto --dns 59.69.128.96 probe
# INFO Probe http://122.207.209.6:8080/ using interface=wlan0 source=10.2.41.236 dns=59.69.128.96:53
# INFO http://122.207.209.6:8080/ 302 in 32ms
```

`--dns` can be omitted when `--interface` is set: the campus resolver is then selected automatically. Pass `--dns` explicitly only when the deployment uses a different resolver.

A minimal configuration for the TUN case is therefore:

```json
{
  "username": "your-username",
  "password": "your-password",
  "adapter": "auto",
  "keepOnline": true
}
```

### Why the probe is an HTTP round trip

A TUN client terminates TCP in user space: it answers the SYN itself and opens the upstream connection afterwards. A successful `connect()` therefore proves only that the tunnel stack replied, never that the upstream host is reachable (issue #4). The probe defaults to `http` for that reason.

- `probeMode: "http"` (default) requires a complete HTTP response. With `probeExpect`/`probeLocation` you can pin the expected answer, for example `"probeExpect": "302"` with `"probeLocation": "/opac/search/simsearch"` for the NYIST library.
- `probeMode: "tcp"` keeps the old handshake-only check. It is cheap and correct **only when the probe is bound to the campus adapter**, where a completed handshake reflects the real link. Unbound, it is the false-positive described above.
- `interval` is the probe period in seconds, `timeout` the per-probe budget, and `retries` how many consecutive failures trigger a re-authentication.

A bound `tcp` probe is the cheapest correct configuration, since it needs one round trip instead of two:

```shell
auth-nyist -i wlan0 --dns 59.69.128.96 probe --probe-mode tcp --url 122.207.209.6:8080
```

Tuning the probe from the command line:

```shell
auth-nyist probe --url http://127.0.0.1:1/ --timeout 2 ; echo "exit=$?"
auth-nyist keepalive --url http://122.207.209.6:8080/ --interval 10 --retries 2
```

`probe` exits with status 2 when the probe fails, which makes it usable from cron or a health check.

### Reported device name (`os` / `name`)

The SRun login request carries two free-form parameters, `os` and `name`, which the portal stores and shows in its device list. Neither is part of `chksum`, so any value is accepted.

```shell
auth-nyist --os "Windows 11" --device-name "home-pc" auth
```

Defaults to `auth-nyist-cli` for both, matching the User-Agent this tool sends. Configure with `"os"` / `"name"`, override with `--os` / `--device-name`.

**April 1st egg.** On April 1st the defaults are replaced by a random string from a single list (`"Windows 7 旗舰版 已激活"`, `"不想996"`, `"图书馆馆长"`, `"隔壁宿舍的路由器"`, …) used for **both** `os` and `name`, so the portal shows one coherent device instead of a mismatched pair. The egg follows the local date, and an explicitly passed `--os`/`--device-name` always wins over it. Disable it with `--no-egg` or `"noEgg": true`.

## Autostart

It is suggested that one configures and runs it manually first with `debug` flag turned on, which ensures the correctness of one's config, then start it as system service. For `daemonize` flag, it forces the program to only log errors, hence debugging should be done earlier and manually. `daemonize` is automatically turned on for system service (ref to associated systemd unit files).

### Systemd

To configure automatic authentication on systemd-based Linux distro, take a look at `docs/systemd` folder. Just modify the path in configuration files, then copy them to `/etc/systemd` folder.

Note that the program should have access to the configuration file.
For `system/goauthing.service`, since it is run as `nobody`, `/etc/goauthing.json` can not be read by it, hence you can use the following command to enable access:

```shell
setfacl -m u:nobody:r /etc/goauthing.json
```

Or, to be more secure, you can choose `system/goauthing@.service` or `user/goauthing.service` and store the configuration file in the home directory.

### OpenWRT

For OpenWRT users, there are two options available: `goauthing` loading the configuration file, and `goauthing@` interacting with the UCI. The init script should go to the `/etc/init.d/` folder. With the latter, use the following procedure to set up:

```shell
touch /etc/config/goauthing
uci set goauthing.config.username='<YOUR-NYIST-ACCOUNT-NAME>'
uci set goauthing.config.password='<YOUR-NYIST-PASSWORD>'
uci commit goauthing
/etc/init.d/goauthing enable
/etc/init.d/goauthing start
```

## Build

Requires Go 1.11 or above

```shell
export GO111MODULE=on
go build -o auth-nyist github.com/Palvef/AuthingNYIST/cli
```

## Acknowledgments

This project was inspired by the following projects:

- <https://github.com/z4yx/GoAuthing>