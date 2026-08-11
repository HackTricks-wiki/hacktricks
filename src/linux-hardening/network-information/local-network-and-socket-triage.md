# Local Network और Socket Triage

{{#include ../../banners/hacktricks-training.md}}

Linux host पर shell प्राप्त करने के बाद, सबसे उपयोगी network targets अक्सर बाहरी रूप से exposed नहीं होते। केवल loopback पर चलने वाली services, veth networks, Unix sockets, temporary listeners, packet captures और local firewall rules credentials या केवल local attack surfaces को expose कर सकते हैं।

यह page सामान्य remote network pentesting पर नहीं, बल्कि practical local post-exploitation techniques पर केंद्रित है।

## Loopback और Local Service Enumeration

Listening services, उनके bind addresses और permissions अनुमति देने पर owning process की पहचान करके शुरुआत करें।<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
महत्वपूर्ण patterns:

- `127.0.0.1:<port>` या `[::1]:<port>`: डिफ़ॉल्ट रूप से केवल host से reachable।<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: फ़िल्टर न किए जाने पर सभी IPv4 interfaces पर reachable।<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12`, या `192.168.0.0/16` को `veth*`, `docker*`, `br-*`, `cni*` पर देखना: संभवतः container या local lab networks।<sup>[[23]](#references)[[24]](#references)</sup>
- `/run`, `/var/run`, `/tmp`, या application directories के अंतर्गत Unix sockets: local IPC surfaces।<sup>[[5]](#references)</sup>

Lightweight probes से local ports को map करें।<sup>[[6]](#references)[[7]](#references)</sup>
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
उपलब्ध होने पर स्थानीय रूप से `nmap` का उपयोग करें।<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Hidden veth और Container Subnets

Containerized या lab environments अक्सर services को केवल bridge या veth subnet पर expose करते हैं। किसी service के unreachable होने का अनुमान लगाने से पहले interfaces और routes की enumeration करें।<sup>[[2]](#references)</sup>
```bash
ip -br addr
ip route
ip neigh
```
संभावित स्थानीय subnets खोजें।<sup>[[2]](#references)</sup>
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
खोजे गए subnet की सावधानीपूर्वक probe करें।<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
यह technique तब उपयोगी होती है जब कोई web panel, debug endpoint या helper service external scans से छिपी हो, लेकिन compromised host या container network से reachable हो।

## Local Pivot With socat or SSH

यदि कोई service loopback से bound हो, तो service को स्वयं बदलने के बजाय उसे किसी allowed channel के माध्यम से expose करें।

SSH के साथ local-only HTTP service को forward करें।<sup>[[11]](#references)</sup>
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
जब आपके पास पहले से `shell access` हो, तो `socat` के साथ एक local port को bridge करें।<sup>[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
स्थानीय testing के लिए Unix socket को TCP पर forward करें।<sup>[[5]](#references)[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
यह अपने आप में किसी चीज़ का exploit नहीं करता। यह केवल local-only surface को आपके tooling से reachable बनाता है, ताकि आप उसके साथ किसी सामान्य service की तरह interact कर सकें।

## Banner Grabbing और Simple Protocols

हर service HTTP नहीं होती। कई local services banner या one-line protocol के माध्यम से पर्याप्त जानकारी leak करती हैं।

Basic probes.<sup>[[13]](#references)</sup>
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
ब्राउज़र के बिना HTTP check.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
TLS के लिए।<sup>[[14]](#references)[[15]](#references)</sup>
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
लक्ष्य protocol, authentication scheme, version और यह पहचानना है कि service local clients पर trust करती है या नहीं।

## Loopback Traffic कैप्चर करना

Local traffic headers, bearer tokens, Basic Auth credentials या application-specific secrets उजागर कर सकता है।<sup>[[17]](#references)[[25]](#references)</sup> केवल authorized environments में ही capture करें।

Loopback HTTP traffic कैप्चर करें।<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
किसी विशिष्ट local service को capture करें।<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
कैप्चर किए गए या लॉग किए गए header से Basic Auth को decode करें।<sup>[[17]](#references)[[18]](#references)</sup>
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
टेक्स्ट captures में खोजने के लिए उपयोगी strings:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

यदि आप lab में client process environment को नियंत्रित कर सकते हैं, तो `SSLKEYLOGFILE` TLS sessions को Wireshark या compatible tooling में decrypt करने योग्य बना सकता है।<sup>[[19]](#references)[[20]](#references)</sup> यह TLS पर स्वयं हमला किए बिना local HTTPS traffic को समझने के लिए उपयोगी है।

Key logging enabled करके client चलाएँ।<sup>[[19]](#references)[[20]](#references)</sup>
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
एक ही समय पर traffic capture करें।<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
फिर `/tmp/tls.pcap` और `/tmp/sslkeys.log` को Wireshark में लोड करें। यह केवल तब काम करता है जब client library NSS-style key logging को support करती हो और connection बनने से पहले environment सेट किया जा सके।<sup>[[20]](#references)[[21]](#references)</sup>

## Unix Socket Interaction और Command Injection

Unix sockets local IPC endpoints होते हैं।<sup>[[5]](#references)</sup> वे HTTP APIs, custom protocols या unsafe command handlers expose कर सकते हैं।<sup>[[12]](#references)[[14]](#references)</sup>

Sockets खोजें।<sup>[[1]](#references)[[5]](#references)</sup>
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Unix socket के माध्यम से HTTP के साथ इंटरैक्ट करें।<sup>[[14]](#references)</sup>
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Raw socket के साथ इंटरैक्ट करें।<sup>[[12]](#references)[[13]](#references)</sup>
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
यदि user-controlled socket input को shell या privileged helper को पास किया जाता है, तो यह command injection में बदल सकता है।<sup>[[26]](#references)</sup> एक केंद्रित उदाहरण के लिए, [Socket Command Injection](socket-command-injection.md) देखें।

## nftables की समीक्षा और अधिकृत Rule Changes

Local firewall rules यह समझा सकते हैं कि कोई service locally visible क्यों है लेकिन remotely blocked है, या कोई high port एक interface से unreachable क्यों दिखाई देता है।<sup>[[22]](#references)</sup>

Rules की समीक्षा करें।<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
target port को प्रभावित करने वाले drops की तलाश करें।<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
एक अधिकृत lab में, handle द्वारा किसी विशिष्ट blocking rule को हटाएँ।<sup>[[22]](#references)</sup>
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
पूरी tables को flush करने के बजाय exact handle को delete करना बेहतर है। Technique यह है कि behavior पैदा करने वाले precise filter की पहचान की जाए और केवल उसी rule को बदला जाए।<sup>[[22]](#references)</sup>

## त्वरित Workflow
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
उन services को प्राथमिकता दें जो केवल local हों, अधिक privileged user के रूप में चलती हों, admin/debug functions expose करती हों, या loopback/container-network clients पर भरोसा करती हों।

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
