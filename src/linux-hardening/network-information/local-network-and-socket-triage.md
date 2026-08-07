# Local Network और Socket Triage

{{#include ../../banners/hacktricks-training.md}}

Linux host पर shell प्राप्त करने के बाद, सबसे उपयोगी network targets अक्सर externally exposed नहीं होते। केवल loopback पर उपलब्ध services, veth networks, Unix sockets, temporary listeners, packet captures और local firewall rules credentials या केवल local attack surfaces को उजागर कर सकते हैं।

यह page general remote network pentesting के बजाय practical local post-exploitation techniques पर केंद्रित है।

## Loopback और Local Service Enumeration

Listening services, उनके bind addresses और permissions अनुमति देने पर owning process की पहचान करके शुरुआत करें:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
महत्वपूर्ण patterns:

- `127.0.0.1:<port>` या `[::1]:<port>`: default रूप से केवल host से reachable।
- `0.0.0.0:<port>`: filtered न होने पर सभी IPv4 interfaces पर reachable।
- `veth*`, `docker*`, `br-*`, `cni*` पर `172.x`, `10.x`, या `192.168.x`: संभवतः container या local lab networks।
- `/run`, `/var/run`, `/tmp`, या application directories के अंतर्गत Unix sockets: local IPC surfaces।

lightweight probes से local ports map करें:
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

Containerized या lab environments अक्सर services को केवल bridge या veth subnet पर expose करते हैं। किसी service को unreachable मानने से पहले interfaces और routes enumerate करें:
```bash
ip -br addr
ip route
ip neigh
```
संभावित local subnets खोजें:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
किसी खोजे गए subnet को सावधानीपूर्वक probe करें:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
यह technique तब उपयोगी होती है जब कोई web panel, debug endpoint या helper service external scans से छिपी हो, लेकिन compromised host या container network से reachable हो।

## Local Pivot With socat or SSH

यदि कोई service loopback से bound है, तो service को स्वयं बदलने के बजाय उसे किसी allowed channel के माध्यम से expose करें।

SSH के साथ किसी local-only HTTP service को forward करें:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
जब आपके पास पहले से shell access हो, तब `socat` से एक local port को bridge करें:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
स्थानीय परीक्षण के लिए Unix socket को TCP पर forward करें:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
यह अपने आप किसी चीज़ का exploit नहीं करता। यह केवल local-only surface को आपके tooling से reachable बनाता है, ताकि आप उसके साथ एक सामान्य service की तरह interact कर सकें।

## Banner Grabbing और Simple Protocols

हर service HTTP नहीं होती। कई local services banner या one-line protocol के माध्यम से पर्याप्त information leak करती हैं।

Basic probes:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
ब्राउज़र के बिना HTTP check:
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

Local traffic headers, bearer tokens, Basic Auth credentials या application-specific secrets उजागर कर सकता है। केवल authorized environments में ही capture करें।

Loopback HTTP traffic कैप्चर करें:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
एक विशिष्ट स्थानीय सेवा को कैप्चर करें:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
कैप्चर किए गए या लॉग किए गए header से Basic Auth को decode करें:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
टेक्स्ट captures में खोजने के लिए उपयोगी strings:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

यदि आप किसी lab में client process environment को नियंत्रित कर सकते हैं, तो `SSLKEYLOGFILE` TLS sessions को Wireshark या compatible tooling में decrypt करने योग्य बना सकता है। यह TLS पर सीधे हमला किए बिना local HTTPS traffic को समझने के लिए उपयोगी है।

key logging enabled करके client चलाएँ:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
उसी समय traffic capture करें:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
फिर `/tmp/tls.pcap` और `/tmp/sslkeys.log` को Wireshark में लोड करें। यह केवल तभी काम करता है जब client library NSS-style key logging को support करती हो और connection स्थापित होने से पहले environment सेट किया जा सके।

## Unix Socket Interaction और Command Injection

Unix sockets local IPC endpoints होते हैं। वे HTTP APIs, custom protocols या unsafe command handlers expose कर सकते हैं।

Sockets खोजें:
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Unix socket के माध्यम से HTTP के साथ interact करें:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Raw socket के साथ interact करें:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
यदि user-controlled socket input को shell या privileged helper को pass किया जाता है, तो यह command injection में बदल सकता है। एक focused example के लिए [Socket Command Injection](socket-command-injection.md) देखें।

## nftables Review और Authorized Rule Changes

Local firewall rules यह समझा सकते हैं कि कोई service locally visible लेकिन remotely blocked क्यों है, या कोई high port एक interface से unreachable क्यों दिखाई देता है।

Rules की समीक्षा करें:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
किसी target port को प्रभावित करने वाले drops देखें:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
एक अधिकृत lab में, handle द्वारा एक विशिष्ट blocking rule हटाएँ:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
संपूर्ण tables को flush करने के बजाय exact handle को delete करना बेहतर है। Technique यह है कि behavior उत्पन्न करने वाले precise filter की पहचान की जाए और केवल उसी rule को बदला जाए।

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
केवल-local services, अधिक privileged user के रूप में चलने वाली services, admin/debug functions को expose करने वाली services, या loopback/container-network clients पर trust करने वाली services को प्राथमिकता दें।

{{#include ../../banners/hacktricks-training.md}}
