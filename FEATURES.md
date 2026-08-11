# Feature map

Status of the requested capability set. **Built** = shipping in this repo.
**Partial** = a working subset. **Planned** = on the roadmap; see notes on what
it realistically needs on a driver-free, fail-open design.

## Core firewall
| Feature | Status | Notes |
|---|---|---|
| Inbound filtering / block unauthorized | **Built** | via WFP; all-inbound-block is the machine baseline |
| Stealth mode / hide open ports | **Built** | default-deny inbound = no port responds |
| Port-scan protection | **Built** | alert engine reads firewall drop-log |
| Network zone profiles (Home/Office/Public) | **Built** | reads `NetworkCategory`; header flags Public Wi-Fi |
| Outbound per-app control (allow/deny) | **Built** | block/allow rule scoped to exe path |
| Alert on unknown program connecting | **Built** | new-connection events + suspicious-path alert |
| Rules by IP / port / protocol | **Partial** | IP + program today; port/proto rule UI planned |
| Ask-user on new outbound (interactive prompt) | **Planned** | needs a toast/approval queue; lockdown+allowlist is the current model |
| Editable profile (thresholds, rules, behaviour) | **Built** | `config.json` — dashboard Settings panel + on-disk hot-reload |
| Temporary / time-boxed rules (TTL) | **Built** | auto-block rules carry an expiry and are reaped; block-IP-for-N-min |

## Application control
| Feature | Status | Notes |
|---|---|---|
| Per-executable rules | **Built** | |
| Parent/child process monitoring | **Planned** | needs ETW `Kernel-Process` correlation |
| Digital-signature / trusted-vendor check | **Planned** | `WinVerifyTrust` per image path — cheap to add |
| Cloud reputation lookup | **Planned** | optional, privacy-gated |

## Network security
| Feature | Status | Notes |
|---|---|---|
| Public Wi-Fi auto-hardening | **Built** | per-network profile applied on category change (strictest wins) |
| ARP-spoof detection | **Built** | watches the default-gateway MAC (change / shared-MAC) via `Get-NetNeighbor` |
| IPS / exploit-signature / brute-force | **Partial** | brute-force + scan + **auto-block** built; signature IPS needs a callout driver |

## Privacy / DNS
| Feature | Status | Notes |
|---|---|---|
| Detect plaintext-DNS bypass | **Built** | alerts on TCP :53 to public IPs (guards the DoH chain) |
| DNS-name visibility | **Built** | connections annotated with hostnames from the DNS client cache |
| Secure DNS (DoH/DoT) | **External** | assumed handled by the OS or a separate resolver config |
| Block malicious domains | **Planned** | have DNS names now; needs a blocklist feed to act on them |
| Data-exfiltration detection | **Partial** | upload-surge + host fan-out alerts; per-app byte counts planned |

## Monitoring / visibility
| Feature | Status | Notes |
|---|---|---|
| Real-time dashboard (connections, usage, blocks, profile) | **Built** | |
| Active-connection table w/ process attribution | **Built** | incl. full image path, scope tag |
| Throughput charts + top talkers | **Built** | inline SVG |
| Searchable audit log | **Built** | `logs/events-*.jsonl`, `logs/alerts-*.jsonl` |
| Blocked / allowed / rule-match logging | **Built** | firewall drop-log tail + action log |

## Advanced
| Feature | Status | Notes |
|---|---|---|
| Behavioral anomaly (fan-out, upload surge, odd path) | **Built** | heuristic engine |
| Ransomware / C2 behavioral scoring | **Planned** | extends the anomaly engine |
| Zero-trust default-deny + explicit allow | **Built** | boot lockdown + runtime lockdown toggle |
| Temporary / time-boxed permissions | **Built** | rule TTL + reaper (auto-block + block-for-N-min) |
| Auto-block attackers | **Built** | scanners/brute-forcers blocked automatically for a configurable TTL |
| Geolocation blocking | **Planned** | GeoIP DB + country rules |
| Kill switch (terminate connection) | **Built** | `SetTcpEntry` (TCP/IPv4) |

## Known limits (by design)
- **No kernel callout driver.** Keeps the system driver-free and fail-open;
  the cost is no true per-flow deep inspection and no synchronous
  ask-user-before-connect. Enforcement is WFP rules, monitoring is polling +
  drop-log. A signed WFP callout is the future path if per-flow inspection is
  wanted.
- **Kill is TCP/IPv4 only.** `SetTcpEntry` has no IPv6 or UDP equivalent; to
  cut an IPv6 flow, block the address (a rule) instead.
- **Throughput/connections poll every 2 s.** ETW push is the planned upgrade.
