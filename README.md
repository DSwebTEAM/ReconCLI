# ReconCLI v3

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ ██████╗██╗     ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██║     ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║     ██║     ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║     ██║     ██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║╚██████╗███████╗██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝
```

**Reconnaissance & Security Audit Toolkit — v3.0.0**  
**DSwebTEAM** | [github.com/DSwebTEAM/ReconCLI](https://github.com/DSwebTEAM/ReconCLI)

> ⚠️ **For authorized use on systems you own or have explicit permission to test.**

---

## What's New in v3

- **Metasploit-style interactive shell** — `use`, `set`, `run`, `back`, `sessions`
- **4 engines, 30 modules** — Recon, Analysis, Security, restructured cleanly
- **Full cross-platform support** — Linux, macOS, Windows, Termux (Android)
- **Typed error handling** — every error has a specific message and fix hint
- **Session logging** — every run saved, exportable as JSON or TXT
- **Lazy imports** — missing packages fail gracefully with install instructions
- **OS-aware** — ping, traceroute, readline, timeouts adapt per platform
- **Tab completion** — module names, options, commands
- **Puppeteer removed** → lives in [DSwebTEAM/Puppetron](https://github.com/DSwebTEAM/Puppetron)

---

## Installation

```bash
git clone https://github.com/DSwebTEAM/ReconCLI.git
cd ReconCLI
```
```
# Linux / macOS
chmod +x install.sh && ./install.sh
```
```
# Termux (Android)
bash install.sh
```
```
# Windows
install.bat
```

**Requirements:** Python 3.8+

---

## Usage

### Interactive Shell (recommended)
```
$ reconcli

recon > help
recon > use recon/subdomain
recon [recon/subdomain] > set TARGET hibiki.app
recon [recon/subdomain] > options
recon [recon/subdomain] > run
recon [recon/subdomain] > back
recon > sessions
recon > findings
recon > export json
recon > exit
```

### Direct Mode (scriptable)
```bash
reconcli recon/subdomain -t hibiki.app
reconcli security/cors -t https://hibiki.app
reconcli security/jwt -t https://hibiki.app --set TOKEN=eyJ...
reconcli recon/portscan -t 192.168.1.1 --set PORTS=1-1024
reconcli --list
```

---

## Modules

### Recon Engine
| Module | Description |
|--------|-------------|
| `recon/portscan` | TCP port scan with banner grab + risk flags |
| `recon/pingsweep` | Discover live hosts in subnet (OS-aware ping) |
| `recon/traceroute` | Map network hops (traceroute / tracert) |
| `recon/dns` | Full DNS record enumeration (A, MX, NS, TXT, SOA, CAA...) |
| `recon/subdomain` | Wordlist-based subdomain discovery |
| `recon/whois` | Domain registration + IP ownership |
| `recon/headers` | HTTP headers grab + quick security check |
| `recon/geoip` | IP/domain geolocation |
| `recon/reverseip` | Find all domains on same IP |
| `recon/asn` | ASN lookup — all IP ranges owned by org |
| `recon/passivedns` | Historical DNS records (no active probing) |
| `recon/wayback` | Historical URLs from Wayback Machine |
| `recon/cloudscan` | Detect cloud provider + open S3 buckets |

### Analysis Engine
| Module | Description |
|--------|-------------|
| `analysis/fingerprint` | Detect tech stack — server, framework, CMS, CDN |
| `analysis/jsrecon` | Extract API endpoints and secrets from JS bundles |
| `analysis/params` | Collect all URL parameters from crawled pages |
| `analysis/tlsintel` | Deep TLS — cert chain, ciphers, HSTS preload |
| `analysis/shield` | Detect WAF, CDN, firewall (Cloudflare, Netlify, Akamai...) |

### Security Engine
| Module | Description |
|--------|-------------|
| `security/cors` | CORS misconfiguration — origin reflection, wildcard+credentials |
| `security/jwt` | JWT decode, alg:none attack, weak secret brute-force |
| `security/fileupload` | File upload bypass — PHP, SVG, path traversal, size |
| `security/secheaders` | Security headers audit with letter grading |
| `security/infodisclosure` | Scan for exposed .env, .git, secrets, stack traces |
| `security/csrf` | CSRF protection validation |
| `security/clickjacking` | Clickjacking detection + PoC generator |
| `security/cookieaudit` | Session cookie flags — HttpOnly, Secure, SameSite |
| `security/dirbust` | Directory + file bruteforce |
| `security/apifuzz` | API endpoint discovery + SQLi/XSS/SSTI probes |
| `security/ssl` | SSL cert validity, expiry, TLS version |
| `security/cve` | Detect outdated libraries with known CVEs |

---

## Shell Commands

| Command | Description |
|---------|-------------|
| `use <engine/module>` | Load a module |
| `set <OPTION> <value>` | Set an option |
| `options` | Show current module options |
| `run` | Execute the loaded module |
| `back` | Unload module |
| `sessions` | List all runs this session |
| `findings` | Show all findings this session |
| `export json\|txt` | Export session report |
| `check` | Verify all dependencies |
| `clear` | Clear screen |
| `help` | Show help |
| `exit` | Exit ReconCLI |

---

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✅ Full | All features |
| macOS | ✅ Full | All features |
| Windows | ✅ Full | Uses `tracert`, `pyreadline3` for tab complete |
| Termux (Android) | ✅ Full | Lower thread counts, `--break-system-packages` pip |

---

## Ecosystem

| Repo | Description |
|------|-------------|
| [ReconCLI](https://github.com/DSwebTEAM/ReconCLI) | This tool — Python security framework |
| [Puppetron](https://github.com/DSwebTEAM/Puppetron) | Node.js headless browser security auditor |

---

## Legal

Built for **defensive security** — find vulnerabilities in systems you own before attackers do.  
Do not use against systems you don't have permission to test.

MIT License — see [LICENSE](LICENSE)

---

*Built by [DSwebTEAM](https://github.com/DSwebTEAM)*
