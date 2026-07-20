# Local Network and Socket Triage

{{#include ../../banners/hacktricks-training.md}}

After getting a shell on a Linux host, the most useful network targets are often not exposed externally. Loopback-only services, veth networks, Unix sockets, temporary listeners, packet captures, and local firewall rules can expose credentials or local-only attack surfaces.

This page focuses on practical local post-exploitation techniques, not general remote network pentesting.

## Loopback and Local Service Enumeration

Start by identifying listening services, their bind addresses, and the owning process when permissions allow it:

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Important patterns:

- `127.0.0.1:<port>` or `[::1]:<port>`: reachable only from the host by default.
- `0.0.0.0:<port>`: reachable on all IPv4 interfaces unless filtered.
- `172.x`, `10.x`, or `192.168.x` on `veth*`, `docker*`, `br-*`, `cni*`: likely container or local lab networks.
- Unix sockets under `/run`, `/var/run`, `/tmp`, or application directories: local IPC surfaces.

Map local ports with lightweight probes:

```bash
for p in 80 443 8000 8080 8081 9000 5000; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```

Use `nmap` locally when available:

```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```

## Hidden veth and Container Subnets

Containerized or lab environments often expose services only on a bridge or veth subnet. Enumerate interfaces and routes before assuming a service is unreachable:

```bash
ip -br addr
ip route
ip neigh
```

Find likely local subnets:

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

Probe a discovered subnet carefully:

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

The technique is useful when a web panel, debug endpoint, or helper service is hidden from external scans but reachable from the compromised host or container network.

## Local Pivot With socat or SSH

If a service is bound to loopback, expose it through an allowed channel instead of changing the service itself.

Forward a local-only HTTP service with SSH:

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Bridge a local port with `socat` when you already have shell access:

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Forward a Unix socket to TCP for local testing:

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

This does not exploit anything by itself. It makes a local-only surface reachable from your tooling so you can interact with it like a normal service.

## Banner Grabbing and Simple Protocols

Not every service is HTTP. Many local services leak enough information through a banner or one-line protocol.

Basic probes:

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

HTTP check without a browser:

```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```

For TLS:

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

The goal is to identify the protocol, authentication scheme, version, and whether the service trusts local clients.

## Capturing Loopback Traffic

Local traffic can expose headers, bearer tokens, Basic Auth credentials, or application-specific secrets. Capture only in authorized environments.

Capture loopback HTTP traffic:

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Capture a specific local service:

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Decode Basic Auth from a captured or logged header:

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Useful strings to look for in text captures:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## TLS Key Logging

If you can control the client process environment in a lab, `SSLKEYLOGFILE` can make TLS sessions decryptable in Wireshark or compatible tooling. This is useful for understanding local HTTPS traffic without attacking TLS itself.

Run a client with key logging enabled:

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Capture the traffic at the same time:

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Then load `/tmp/tls.pcap` and `/tmp/sslkeys.log` into Wireshark. This only works when the client library supports NSS-style key logging and you can set the environment before the connection is made.

## Unix Socket Interaction and Command Injection

Unix sockets are local IPC endpoints. They may expose HTTP APIs, custom protocols, or unsafe command handlers.

Find sockets:

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Interact with HTTP over a Unix socket:

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

Interact with a raw socket:

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

If user-controlled socket input is passed to a shell or privileged helper, it can become command injection. For a focused example, see [Socket Command Injection](socket-command-injection.md).

## nftables Review and Authorized Rule Changes

Local firewall rules may explain why a service is visible locally but blocked remotely, or why a high port appears unreachable from one interface.

Review rules:

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

Look for drops affecting a target port:

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

In an authorized lab, remove a specific blocking rule by handle:

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Prefer deleting the exact handle over flushing full tables. The technique is to identify the precise filter causing the behavior and change only that rule.

## Quick Workflow

```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```

Prioritize services that are local-only, run as a more privileged user, expose admin/debug functions, or trust loopback/container-network clients.
{{#include ../../banners/hacktricks-training.md}}
