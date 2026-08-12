# Local Network and Socket Triage

{{#include ../../banners/hacktricks-training.md}}

After getting a shell on a Linux host, the most useful network targets are often not exposed externally. Loopback-only services, veth networks, Unix sockets, temporary listeners, packet captures, and local firewall rules can expose credentials or local-only attack surfaces.

This page focuses on practical local post-exploitation techniques, not general remote network pentesting.

## Loopback and Local Service Enumeration

Start by identifying listening services, their bind addresses, and the owning process when permissions allow it.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Important patterns:

- `127.0.0.1:<port>` or `[::1]:<port>`: reachable only from the host by default.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: reachable on all IPv4 interfaces unless filtered.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16` on `veth*`, `docker*`, `br-*`, `cni*`: likely container or local lab networks.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix sockets under `/run`, `/var/run`, `/tmp`, or application directories: local IPC surfaces.<sup>[[5]](#references)</sup>

Map local ports with lightweight probes.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
for p in 80 443 8000 8080 8081 9000 5000; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```

Use `nmap` locally when available.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```

## Hidden veth and Container Subnets

Containerized or lab environments often expose services only on a bridge or veth subnet. Enumerate interfaces and routes before assuming a service is unreachable.<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

Find likely local subnets.<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

Probe a discovered subnet carefully.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

The technique is useful when a web panel, debug endpoint, or helper service is hidden from external scans but reachable from the compromised host or container network.

## Local Pivot With socat or SSH

If a service is bound to loopback, expose it through an allowed channel instead of changing the service itself.

Forward a local-only HTTP service with SSH.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Bridge a local port with `socat` when you already have shell access.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Forward a Unix socket to TCP for local testing.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

This does not exploit anything by itself. It makes a local-only surface reachable from your tooling so you can interact with it like a normal service.

## Banner Grabbing and Simple Protocols

Not every service is HTTP. Many local services leak enough information through a banner or one-line protocol.

Basic probes.<sup>[[13]](#references)</sup>

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

HTTP check without a browser.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```

For TLS.<sup>[[14]](#references)[[15]](#references)</sup>

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

The goal is to identify the protocol, authentication scheme, version, and whether the service trusts local clients.

## Capturing Loopback Traffic

Local traffic can expose headers, bearer tokens, Basic Auth credentials, or application-specific secrets.<sup>[[17]](#references)[[25]](#references)</sup> Capture only in authorized environments.

Capture loopback HTTP traffic.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Capture a specific local service.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Decode Basic Auth from a captured or logged header.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Useful strings to look for in text captures:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## TLS Key Logging

If you can control the client process environment in a lab, `SSLKEYLOGFILE` can make TLS sessions decryptable in Wireshark or compatible tooling.<sup>[[19]](#references)[[20]](#references)</sup> This is useful for understanding local HTTPS traffic without attacking TLS itself.

Run a client with key logging enabled.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Capture the traffic at the same time.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Then load `/tmp/tls.pcap` and `/tmp/sslkeys.log` into Wireshark. This only works when the client library supports NSS-style key logging and you can set the environment before the connection is made.<sup>[[20]](#references)[[21]](#references)</sup>

## Unix Socket Interaction and Command Injection

Unix sockets are local IPC endpoints.<sup>[[5]](#references)</sup> They may expose HTTP APIs, custom protocols, or unsafe command handlers.<sup>[[12]](#references)[[14]](#references)</sup>

Find sockets.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Interact with HTTP over a Unix socket.<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

Interact with a raw socket.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

If user-controlled socket input is passed to a shell or privileged helper, it can become command injection.<sup>[[26]](#references)</sup> For a focused example, see [Socket Command Injection](socket-command-injection.md).

## nftables Review and Authorized Rule Changes

Local firewall rules may explain why a service is visible locally but blocked remotely, or why a high port appears unreachable from one interface.<sup>[[22]](#references)</sup>

Review rules.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

Look for drops affecting a target port.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

In an authorized lab, remove a specific blocking rule by handle.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Prefer deleting the exact handle over flushing full tables. The technique is to identify the precise filter causing the behavior and change only that rule.<sup>[[22]](#references)</sup>

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

## References

- [1] [ss(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux manual page](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: IP Version 6 Addressing Architecture](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux manual page](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Redirections (Bash Reference Manual)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout invocation (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Port Scanning Techniques (Nmap Reference Guide)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Host Discovery (Nmap Reference Guide)](https://nmap.org/book/man-host-discovery.html)
- [10] [Port Specification and Scan Order (Nmap Reference Guide)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux manual page](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Linux manual page](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD manual page](https://man.openbsd.org/nc.1)
- [14] [curl command line tool manual](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL Documentation](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux manual page](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: The 'Basic' HTTP Authentication Scheme](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64 invocation (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL Documentation](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark User’s Guide](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables manual](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Address Allocation for Private Internets (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [The OAuth 2.0 Authorization Framework: Bearer Token Usage (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)

{{#include ../../banners/hacktricks-training.md}}
