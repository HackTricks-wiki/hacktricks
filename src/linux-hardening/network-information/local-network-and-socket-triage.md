# Local Network और Socket Triage

{{#include ../../banners/hacktricks-training.md}}

Linux host पर shell प्राप्त करने के बाद, सबसे उपयोगी network targets अक्सर externally exposed नहीं होते। Loopback-only services, veth networks, Unix sockets, temporary listeners, packet captures और local firewall rules credentials या local-only attack surfaces को expose कर सकते हैं।

यह page general remote network pentesting के बजाय practical local post-exploitation techniques पर केंद्रित है।

## Loopback और Local Service Enumeration

सबसे पहले listening services, उनके bind addresses और permissions अनुमति देने पर owning process की पहचान करें:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
महत्वपूर्ण पैटर्न:

- `127.0.0.1:<port>` या `[::1]:<port>`: डिफ़ॉल्ट रूप से केवल host से पहुंच योग्य।
- `0.0.0.0:<port>`: फ़िल्टर न किए जाने पर सभी IPv4 interfaces पर पहुंच योग्य।
- `172.x`, `10.x`, या `192.168.x` on `veth*`, `docker*`, `br-*`, `cni*`: संभवतः container या local lab networks।
- `/run`, `/var/run`, `/tmp`, या application directories के अंतर्गत Unix sockets: local IPC surfaces।

हल्के probes से local ports को map करें:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
उपलब्ध होने पर स्थानीय रूप से `nmap` का उपयोग करें:
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Hidden veth और Container Subnets

Containerized या lab environments अक्सर services को केवल bridge या veth subnet पर expose करते हैं। किसी service को unreachable मानने से पहले interfaces और routes की enumeration करें:
```bash
ip -br addr
ip route
ip neigh
```
संभावित local subnets खोजें:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
खोजे गए subnet की सावधानीपूर्वक जाँच करें:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
यह technique तब उपयोगी होती है जब कोई web panel, debug endpoint या helper service external scans से hidden हो, लेकिन compromised host या container network से reachable हो।

## socat या SSH के साथ Local Pivot

यदि कोई service loopback से bound है, तो service को स्वयं बदलने के बजाय उसे किसी allowed channel के माध्यम से expose करें।

SSH के साथ किसी local-only HTTP service को forward करें:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
जब आपके पास पहले से shell access हो, तब `socat` के साथ एक local port को bridge करें:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
स्थानीय testing के लिए Unix socket को TCP पर forward करें:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
यह अपने आप किसी चीज़ का exploit नहीं करता। यह केवल local-only surface को आपके tooling से reachable बनाता है, ताकि आप उससे सामान्य service की तरह interact कर सकें।

## Banner Grabbing और Simple Protocols

हर service HTTP नहीं होती। कई local services banner या one-line protocol के माध्यम से पर्याप्त information leak करती हैं।

Basic probes:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
ब्राउज़र के बिना HTTP जाँच:
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
TLS के लिए:
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
लक्ष्य protocol, authentication scheme, version और यह पहचानना है कि service local clients पर trust करती है या नहीं।

## Loopback Traffic कैप्चर करना

Local traffic headers, bearer tokens, Basic Auth credentials या application-specific secrets को उजागर कर सकता है। केवल authorized environments में capture करें।

Loopback HTTP traffic capture करें:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
किसी विशिष्ट स्थानीय service को capture करें:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
captured या logged header से Basic Auth decode करें:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Text captures में खोजने के लिए उपयोगी strings:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

यदि आप किसी lab में client process environment को नियंत्रित कर सकते हैं, तो `SSLKEYLOGFILE` TLS sessions को Wireshark या compatible tooling में decryptable बना सकता है। यह स्वयं TLS पर हमला किए बिना local HTTPS traffic को समझने के लिए उपयोगी है।

Key logging enabled करके client चलाएँ:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
उसी समय traffic capture करें:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
फिर `/tmp/tls.pcap` और `/tmp/sslkeys.log` को Wireshark में लोड करें। यह केवल तब काम करता है, जब client library NSS-style key logging को support करती हो और connection बनने से पहले environment सेट किया जा सके।

## Unix Socket Interaction and Command Injection

Unix sockets स्थानीय IPC endpoints होते हैं। वे HTTP APIs, custom protocols या unsafe command handlers expose कर सकते हैं।

Sockets खोजें:
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Unix socket के माध्यम से HTTP के साथ इंटरैक्ट करें:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Raw socket के साथ interact करें:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
यदि user-controlled socket input को shell या privileged helper को पास किया जाता है, तो यह command injection में बदल सकता है। एक focused example के लिए, [Socket Command Injection](socket-command-injection.md) देखें।

## nftables Review और Authorized Rule Changes

Local firewall rules यह समझा सकते हैं कि कोई service locally visible क्यों है लेकिन remotely blocked क्यों है, या कोई high port एक interface से unreachable क्यों दिखाई देता है।

Rules की review करें:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
target port को प्रभावित करने वाले drops देखें:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
अधिकृत lab में, handle द्वारा किसी विशिष्ट blocking rule को हटाएँ:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
पूर्ण tables को flush करने के बजाय exact handle को delete करना बेहतर है। Technique यह है कि behavior उत्पन्न करने वाले precise filter की पहचान करें और केवल उसी rule को बदलें।

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
उन services को प्राथमिकता दें जो केवल local हों, अधिक privileged user के रूप में चलती हों, admin/debug functions expose करती हों, या loopback/container-network clients पर trust करती हों।
