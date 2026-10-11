# स्थानीय नेटवर्क और सॉकेट ट्रायेज

{{#include ../../banners/hacktricks-training.md}}

Linux host पर shell मिलने के बाद, सबसे उपयोगी नेटवर्क लक्ष्य अक्सर बाहरी रूप से exposed नहीं होते। केवल Loopback पर उपलब्ध services, veth networks, Unix sockets, अस्थायी listeners, packet captures और स्थानीय firewall rules credentials या केवल स्थानीय रूप से उपलब्ध attack surfaces उजागर कर सकते हैं।

यह पेज व्यावहारिक local post-exploitation techniques पर केंद्रित है, सामान्य remote network pentesting पर नहीं।

## Loopback और स्थानीय Service Enumeration

Listening services, उनके bind addresses और, जहाँ permissions इसकी अनुमति दें, उन्हें चलाने वाले process की पहचान करके शुरुआत करें।<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

महत्वपूर्ण पैटर्न:

- `127.0.0.1:<port>` या `[::1]:<port>`: डिफ़ॉल्ट रूप से केवल होस्ट से पहुँच योग्य।<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: फ़िल्टर न होने पर सभी IPv4 इंटरफ़ेस पर पहुँच योग्य।<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12`, या `192.168.0.0/16` on `veth*`, `docker*`, `br-*`, `cni*`: संभवतः container या local lab नेटवर्क।<sup>[[23]](#references)[[24]](#references)</sup>
- `/run`, `/var/run`, `/tmp`, या application directories के अंतर्गत Unix sockets: local IPC सतहें।<sup>[[5]](#references)</sup>

ऐतिहासिक [snapd socket parsing issue, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing) के लिए, चल रहे daemon, उसके local API socket, और installed package या snap revision की जाँच उस distribution के fix से करें। बग snapd द्वारा peer के socket address के validation में था, `snap-confine` में नहीं; set-user-ID `snap-confine` file या केवल upstream version string से exposure साबित नहीं होता। Ubuntu ने release-विशिष्ट package versions में fixes जारी किए थे, और snapd distribution package से स्वतंत्र रूप से snap से refresh हुआ हो सकता है। privileged API boundary का आकलन करने से पहले वास्तविक running build और local socket reachability की पुष्टि करें। Passive enumeration में crafted socket request नहीं भेजनी चाहिए और न ही snap install करना चाहिए।

[`socat` with `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) के ज़रिए शुरू किया गया loopback listener, local client input को किसी अलग program तक पहुँचा सकता है। root-owned custom service को privilege-escalation lead मानने से पहले listener के command, executable path, effective child identity, local reachability और authentication का आपस में मिलान करें। memory-safety flaw या unsafe input-to-command path के लिए विशिष्ट binary और build से सबूत चाहिए; केवल port number, `socat` process या root owner से यह साबित नहीं होता। Passive enumeration में service को input भेजने के बजाय process, socket और file metadata तक ही जाँच सीमित रखें।

कोई local Salt master TCP 4505 और 4506 पर सुन सकता है, जिसमें loopback या container-published host port भी शामिल हैं। [Salt's 3000.2 release notes](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) में unauthenticated method-access flaw, CVE-2020-11651 का वर्णन है, जिसे upstream 2019.2.4 और 3000.2 में ठीक किया गया था। इसे escalation lead मानने से पहले listener का वास्तविक `salt-master` process, reachable interface, installed package और vendor patches, तथा उसकी effective container या host identity से मिलान करें; केवल port या upstream version प्रमाण नहीं है। यदि master किसी container के अंदर चल रहा हो, तो host-root impact एक अलग boundary है: पुष्टि करें कि usable host runtime API socket उस container में mounted है और वहाँ से accessible है। Exposure का आकलन करने के लिए passive enumeration में Salt request server को query न करें और container न बनाएँ। [Salt's port documentation](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) और [runtime API triage](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) देखें।

हल्के probes से local ports का मानचित्र बनाएँ।<sup>[[6]](#references)[[7]](#references)</sup>

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

## छिपे हुए veth और कंटेनर सबनेट

कंटेनराइज़्ड या लैब वातावरण में सेवाएँ अक्सर केवल bridge या veth सबनेट पर उपलब्ध होती हैं। किसी सेवा को पहुँच से बाहर मानने से पहले interfaces और routes की सूची बनाएँ।<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

संभावित स्थानीय सबनेट खोजें.<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

खोजे गए subnet की सावधानीपूर्वक जाँच करें।<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

यह तकनीक तब उपयोगी होती है जब कोई web panel, debug endpoint या helper service बाहरी scans से छिपी हो, लेकिन compromised host या container network से पहुँच योग्य हो।

किसी loopback notebook service में startup token से authentication हो सकता है, जो उसके process output में प्रिंट होता है। यदि यह output किसी ऐसे log में redirect किया गया हो जिसे कोई अन्य local account पढ़ सकता है, तो token user boundary पार कर सकता है और notebook server के account में code execution की अनुमति दे सकता है। किसी log path को privilege escalation का सुराग मानने से पहले listening process के owner, log destination और permissions, मौजूदा token configuration तथा notebook access controls की जाँच करें। Passive enumeration के दौरान log metadata सूचीबद्ध करें; केवल host का वर्गीकरण करने के लिए tokens प्रिंट न करें या service से connect न करें।

## socat या SSH से Local Pivot

यदि कोई service loopback पर bound है, तो service को स्वयं बदलने के बजाय उसे किसी अनुमत channel के ज़रिए expose करें।

SSH से केवल local HTTP service को forward करें।<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

जब आपके पास पहले से shell access हो, तो `socat` के साथ एक local port को bridge करें।<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

स्थानीय परीक्षण के लिए Unix socket को TCP पर फ़ॉरवर्ड करें।<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

यह अपने आप में किसी चीज़ का exploit नहीं करता। यह आपके tooling से केवल लोकल surface को reachable बनाता है, ताकि आप उससे सामान्य service की तरह interact कर सकें।

## Banner Grabbing और Simple Protocols

हर service HTTP नहीं होती। कई लोकल services banner या one-line protocol के ज़रिए पर्याप्त जानकारी leak करती हैं।

Basic probes.<sup>[[13]](#references)</sup>

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

ब्राउज़र के बिना HTTP जाँच।<sup>[[13]](#references)[[14]](#references)</sup>

```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```

TLS के लिए.<sup>[[14]](#references)[[15]](#references)</sup>

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

लक्ष्य है protocol, authentication scheme, version और यह पहचानना कि service स्थानीय clients पर भरोसा करती है या नहीं।

aiohttp listener के लिए, उसके version के साथ-साथ static-route configuration की भी समीक्षा करें। CVE-2024-23334, 3.9.2 से पुराने aiohttp versions को प्रभावित करता है, जब static route में `follow_symlinks=True` सक्षम हो: उस route पर किए गए requests, static root के बाहर की files पढ़ सकते हैं। यदि service root के रूप में चलती है, तो वह root द्वारा पढ़ी जा सकने वाली files उजागर कर सकती है, बशर्ते route तक पहुँचा जा सके। Version banner या loopback bind मात्र से vulnerable configuration या file access की पुष्टि नहीं होती।<sup>[[27]](#references)</sup>

## Loopback Traffic कैप्चर करना

स्थानीय traffic से headers, bearer tokens, Basic Auth credentials या application-specific secrets उजागर हो सकते हैं।<sup>[[17]](#references)[[25]](#references)</sup> केवल अधिकृत environments में ही capture करें।

Loopback HTTP traffic कैप्चर करें।<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

किसी विशिष्ट स्थानीय सेवा को कैप्चर करें.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

कैप्चर किए गए या लॉग किए गए header से Basic Auth को decode करें।<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

टेक्स्ट कैप्चर में खोजने के लिए उपयोगी स्ट्रिंग्स:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## TLS Key Logging

यदि आप किसी lab में client process के environment को नियंत्रित कर सकते हैं, तो `SSLKEYLOGFILE` से TLS sessions को Wireshark या compatible tooling में decrypt किया जा सकता है।<sup>[[19]](#references)[[20]](#references)</sup> यह TLS पर ही हमला किए बिना local HTTPS traffic को समझने के लिए उपयोगी है।

Key logging enabled करके कोई client चलाएँ।<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

उसी समय ट्रैफ़िक कैप्चर करें।<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

फिर `/tmp/tls.pcap` और `/tmp/sslkeys.log` को Wireshark में लोड करें। यह तभी काम करता है जब client library NSS-style key logging को सपोर्ट करती हो और आप connection बनने से पहले environment सेट कर सकें।<sup>[[20]](#references)[[21]](#references)</sup>

## Unix Socket इंटरैक्शन और Command Injection

Unix sockets स्थानीय IPC endpoints होते हैं।<sup>[[5]](#references)</sup> वे HTTP APIs, custom protocols या असुरक्षित command handlers उपलब्ध करा सकते हैं।<sup>[[12]](#references)[[14]](#references)</sup>

Group write permission वाला root-owned socket अपने आप में vulnerability नहीं, बल्कि एक authorization boundary है। जोखिम तय करने से पहले, इसके group और mode की मौजूदा account से तुलना करें, listening process की पहचान करें और जाँचें कि वह process clients से क्या स्वीकार करता है। खास तौर पर, submitted PHP चलाने वाली कोई privileged service दूसरी boundary पार कर सकती है, अगर वह caller द्वारा चुने गए `php.ini` path पर भी भरोसा करती हो या caller को `disable_functions` अथवा `open_basedir` बदलने देती हो; प्रभावी configuration और service validation path की जाँच करें। [PHP configuration guide](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) इन directives के बारे में बताती है। केवल socket metadata से code execution साबित नहीं होता।

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

Raw socket के साथ इंटरैक्ट करें.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

यदि user-controlled socket input को shell या privileged helper को पास किया जाता है, तो इससे command injection हो सकता है।<sup>[[26]](#references)</sup> एक केंद्रित उदाहरण के लिए, [Socket Command Injection](socket-command-injection.md) देखें।

## nftables की समीक्षा और अधिकृत नियम परिवर्तन

स्थानीय firewall नियम यह समझा सकते हैं कि कोई service स्थानीय रूप से क्यों दिखाई देती है, लेकिन दूरस्थ रूप से अवरुद्ध रहती है, या कोई high port एक interface से क्यों पहुँच से बाहर दिखता है।<sup>[[22]](#references)</sup>

नियमों की समीक्षा करें।<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

लक्ष्य पोर्ट को प्रभावित करने वाले drops खोजें।<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

एक अधिकृत लैब में, handle द्वारा किसी विशिष्ट blocking rule को हटाएँ।<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

पूरी tables flush करने के बजाय सटीक handle को delete करना बेहतर है। इस तकनीक में व्यवहार के लिए ज़िम्मेदार सटीक filter की पहचान करके केवल उसी rule को बदलना शामिल है।<sup>[[22]](#references)</sup>

## त्वरित कार्यप्रवाह

```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```

ऐसी services को प्राथमिकता दें जो केवल local हों, अधिक privileged user के रूप में चलती हों, admin/debug functions उजागर करती हों, या loopback/container-network clients पर भरोसा करती हों।

## References

- [1] [ss(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: IP Version 6 Addressing Architecture](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Redirections (Bash Reference Manual)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout invocation (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Port Scanning Techniques (Nmap Reference Guide)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Host Discovery (Nmap Reference Guide)](https://nmap.org/book/man-host-discovery.html)
- [10] [Port Specification and Scan Order (Nmap Reference Guide)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Linux मैनुअल पृष्ठ](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD मैनुअल पृष्ठ](https://man.openbsd.org/nc.1)
- [14] [curl कमांड लाइन टूल मैनुअल](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL दस्तावेज़](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: 'Basic' HTTP Authentication Scheme](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64 invocation (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL दस्तावेज़](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark User’s Guide](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables मैनुअल](https://netfilter.org/projects/nftables/manpage.html)
- [23] [निजी इंटरनेट के लिए पता आवंटन (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [OAuth 2.0 Authorization Framework: Bearer Token Usage (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: OS Command में उपयोग किए गए विशेष तत्वों का अनुचित Neutralization](https://cwe.mitre.org/data/definitions/78.html)
- [27] [aiohttp maintainer advisory: follow_symlinks के साथ static route traversal](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
{{#include ../../banners/hacktricks-training.md}}
