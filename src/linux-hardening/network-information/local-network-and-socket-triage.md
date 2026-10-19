# Local Network और Socket की जाँच

{{#include ../../banners/hacktricks-training.md}}

Linux host पर shell मिलने के बाद, सबसे उपयोगी network targets अक्सर बाहरी रूप से exposed नहीं होते। केवल loopback पर उपलब्ध services, veth networks, Unix sockets, अस्थायी listeners, packet captures और local firewall rules credentials या केवल लोकल स्तर पर उपलब्ध attack surfaces उजागर कर सकते हैं।

यह पेज व्यावहारिक local post-exploitation techniques पर केंद्रित है, सामान्य remote network pentesting पर नहीं।

## Loopback और Local Service की गणना

Listening services, उनके bind addresses और, permissions मिलने पर, उन्हें चलाने वाली process की पहचान से शुरुआत करें।<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

महत्वपूर्ण पैटर्न:

- `127.0.0.1:<port>` या `[::1]:<port>`: डिफ़ॉल्ट रूप से केवल host से पहुंच योग्य।<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: फ़िल्टर न होने पर सभी IPv4 interfaces पर पहुंच योग्य।<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12`, या `192.168.0.0/16` `veth*`, `docker*`, `br-*`, `cni*` पर: संभवतः container या local lab networks।<sup>[[23]](#references)[[24]](#references)</sup>
- `/run`, `/var/run`, `/tmp`, या application directories में Unix sockets: local IPC surfaces।<sup>[[5]](#references)</sup>

ऐतिहासिक [snapd socket parsing issue, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing) के लिए, चल रहे daemon, उसके local API socket, और installed package या snap revision की उस distribution के fix से जांच करें। यह bug snapd में peer के socket address के validation में था, `snap-confine` में नहीं; set-user-ID `snap-confine` file या केवल upstream version string से exposure की पुष्टि नहीं हो सकती। Ubuntu ने release-specific package versions के अंतर्गत fixes जारी किए थे, और snapd distribution package से स्वतंत्र रूप से snap से refresh हुआ हो सकता है। privileged API boundary का आकलन करने से पहले वास्तविक running build और local socket reachability की पुष्टि करें। Passive enumeration में crafted socket request नहीं भेजनी चाहिए और न ही snap install करना चाहिए।

[`socat` के `EXEC` के साथ](https://man7.org/linux/man-pages/man1/socat.1.html) शुरू किया गया loopback listener, local client input को अलग program तक पहुंचा सकता है। root-owned custom service को privilege-escalation lead मानने से पहले listener के command, executable path, effective child identity, local reachability, और authentication का मिलान करें। memory-safety flaw या unsafe input-to-command path के लिए विशिष्ट binary और build से प्रमाण आवश्यक है; केवल port number, `socat` process, या root owner से इसकी पुष्टि नहीं होती। Passive enumeration में service को input भेजने के बजाय process, socket, और file metadata तक ही जांच सीमित रखें।

Local Salt master, TCP 4505 और 4506 पर सुन सकता है, जिसमें loopback या container-published host port भी शामिल हैं। [Salt की 3000.2 release notes](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) में unauthenticated method-access flaw, CVE-2020-11651 का वर्णन है, जिसे upstream 2019.2.4 और 3000.2 में ठीक किया गया था। इसे escalation lead मानने से पहले listener का वास्तविक `salt-master` process, reachable interface, installed package और vendor patches, तथा उसकी effective container या host identity से मिलान करें; केवल port या upstream version प्रमाण नहीं है। अगर master container के अंदर चलता है, तो host-root impact एक अलग boundary है: पुष्टि करें कि usable host runtime API socket उस container में mounted है और वहां से accessible है। Exposure तय करने के लिए passive enumeration में Salt request server से query न करें या container न बनाएं। [Salt की port documentation](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) और [runtime API triage](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) देखें।

हल्के probes से local ports map करें।<sup>[[6]](#references)[[7]](#references)</sup>

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

## छिपे हुए veth और Container Subnets

Containerized या lab environments में services अक्सर केवल bridge या veth subnet पर उपलब्ध होती हैं। किसी service को unreachable मानने से पहले interfaces और routes की enumeration करें।<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

संभावित स्थानीय subnets खोजें।<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

किसी खोजे गए subnet को सावधानीपूर्वक प्रोब करें.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

यह technique तब उपयोगी होती है जब कोई web panel, debug endpoint या helper service external scans से छिपी हो, लेकिन compromised host या container network से पहुँच योग्य हो।

## User boundaries के पार Notebook service tokens

Loopback notebook service, अपने process output में print किए गए startup token से authenticate कर सकती है। अगर उस output को ऐसे log में redirect किया गया हो जिसे कोई दूसरा local account पढ़ सकता है, तो token user boundary पार कर सकता है और notebook server के account में code execution की अनुमति दे सकता है। किसी log path को privilege escalation lead मानने से पहले listening process के owner, log destination और permissions, current token configuration और notebook access controls का मिलान करें। Passive enumeration के दौरान log metadata देखें; केवल host को classify करने के लिए tokens print न करें या service से connect न करें।

Jupyter Lab service अपना token readable systemd `ExecStart` या running command line (`ps auxww`) में भी expose कर सकती है, न कि केवल startup logs में। रिपोर्ट किए गए उदाहरण में, `User=analyst` और `--ServerApp.token` ने credential और `127.0.0.1:8888` listener के पीछे के account—दोनों की पहचान की। Host access के साथ, token और `ssh -L 8888:127.0.0.1:8888 user@host` ने उस service user के रूप में Jupyter Lab के Terminal तक पहुँच की अनुमति दी। Effective unit user, process arguments, listener और token validity को एक साथ जाँचें; केवल loopback binding कोई authorization boundary नहीं है।<sup>[[28]](#references)</sup>

## socat या SSH के साथ Local Pivot

अगर कोई service loopback पर bound है, तो service को खुद बदलने के बजाय उसे किसी allowed channel से expose करें।

SSH से केवल local HTTP service को forward करें।<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

जब आपके पास पहले से shell access हो, तो `socat` के साथ किसी स्थानीय पोर्ट को bridge करें।<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

स्थानीय परीक्षण के लिए Unix socket को TCP पर फ़ॉरवर्ड करें.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

यह अपने आप में किसी चीज़ का exploit नहीं करता। यह केवल स्थानीय surface को आपके tooling से reachable बनाता है, ताकि आप उससे सामान्य service की तरह interact कर सकें।

## Banner Grabbing और सरल Protocols

हर service HTTP नहीं होती। कई स्थानीय services banner या one-line protocol के ज़रिए पर्याप्त जानकारी leak करती हैं।

बुनियादी probes.<sup>[[13]](#references)</sup>

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

ब्राउज़र के बिना HTTP जांच।<sup>[[13]](#references)[[14]](#references)</sup>

```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```

TLS के लिए.<sup>[[14]](#references)[[15]](#references)</sup>

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

लक्ष्य protocol, authentication scheme, version की पहचान करना और यह पता लगाना है कि service local clients पर भरोसा करती है या नहीं।

aiohttp listener के लिए, उसके version के साथ-साथ static-route configuration की भी जाँच करें। CVE-2024-23334, aiohttp के 3.9.2 से पुराने versions को प्रभावित करता है, जब किसी static route में `follow_symlinks=True` सक्षम हो: उस route पर किए गए requests, static root के बाहर की files पढ़ सकते हैं। यदि service root के रूप में चलती है, तो route तक पहुँच संभव होने पर यह root द्वारा पढ़ी जा सकने वाली files को expose कर सकती है। केवल version banner या loopback bind से vulnerable configuration या file access की पुष्टि नहीं होती।<sup>[[27]](#references)</sup>

## Loopback Traffic कैप्चर करना

Local traffic में headers, bearer tokens, Basic Auth credentials या application-specific secrets उजागर हो सकते हैं।<sup>[[17]](#references)[[25]](#references)</sup> केवल authorized environments में ही capture करें।

Loopback HTTP traffic कैप्चर करें।<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

किसी विशिष्ट स्थानीय सेवा को कैप्चर करें।<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

कैप्चर किए गए या लॉग किए गए हेडर से Basic Auth डिकोड करें।<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

टेक्स्ट कैप्चर में देखने के लिए उपयोगी strings:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## TLS Key Logging

यदि आप किसी lab में client process environment को नियंत्रित कर सकते हैं, तो `SSLKEYLOGFILE` TLS sessions को Wireshark या compatible tooling में डिक्रिप्ट करने योग्य बना सकता है।<sup>[[19]](#references)[[20]](#references)</sup> यह TLS पर ही हमला किए बिना स्थानीय HTTPS traffic को समझने के लिए उपयोगी है।

Key logging enabled करके client चलाएँ।<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

उसी समय ट्रैफ़िक कैप्चर करें।<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

फिर `/tmp/tls.pcap` और `/tmp/sslkeys.log` को Wireshark में लोड करें। यह तभी काम करता है जब client library NSS-style key logging का समर्थन करती हो और आप connection बनने से पहले environment सेट कर सकें।<sup>[[20]](#references)[[21]](#references)</sup>

## Unix Socket के साथ इंटरैक्शन और Command Injection

Unix sockets स्थानीय IPC endpoints होते हैं।<sup>[[5]](#references)</sup> वे HTTP APIs, custom protocols या असुरक्षित command handlers उपलब्ध करा सकते हैं।<sup>[[12]](#references)[[14]](#references)</sup>

Group write permission वाला root-owned socket अपने-आप में vulnerability नहीं, बल्कि एक authorization boundary है। जोखिम तय करने से पहले, उसके group और mode की तुलना मौजूदा account से करें, listening process की पहचान करें और जाँचें कि वह process clients से क्या स्वीकार करता है। खास तौर पर, submitted PHP चलाने वाली कोई privileged service दूसरी boundary पार कर सकती है, यदि वह caller द्वारा चुने गए `php.ini` path पर भी भरोसा करती हो या caller को `disable_functions` अथवा `open_basedir` बदलने देती हो; effective configuration और service validation path की जाँच करें। [PHP configuration guide](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) इन directives की व्याख्या करती है। केवल socket metadata से code execution सिद्ध नहीं होता।

Sockets खोजें।<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Unix socket पर HTTP के साथ इंटरैक्ट करें.<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

एक raw socket के साथ इंटरैक्ट करें.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

यदि user-controlled socket input को shell या privileged helper में पास किया जाता है, तो इससे command injection हो सकता है।<sup>[[26]](#references)</sup> एक केंद्रित उदाहरण के लिए, [Socket Command Injection](socket-command-injection.md) देखें।

## nftables Review और अधिकृत Rule Changes

स्थानीय firewall rules यह समझा सकते हैं कि कोई service स्थानीय रूप से क्यों दिखाई देती है, लेकिन दूरस्थ रूप से blocked रहती है, या कोई high port एक interface से पहुँच योग्य क्यों नहीं दिखता।<sup>[[22]](#references)</sup>

Rules की समीक्षा करें।<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

लक्ष्य पोर्ट को प्रभावित करने वाले drops खोजें।<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

अधिकृत लैब में, handle से किसी विशिष्ट blocking rule को हटाएँ।<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

पूरी tables को flush करने के बजाय सटीक handle को हटाना बेहतर है। इस तकनीक में व्यवहार का कारण बनने वाले सटीक filter की पहचान करके केवल उसी rule को बदलना शामिल है।<sup>[[22]](#references)</sup>

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

उन services को प्राथमिकता दें जो केवल स्थानीय स्तर पर उपलब्ध हों, अधिक विशेषाधिकार प्राप्त उपयोगकर्ता के रूप में चलें, admin/debug functions उपलब्ध कराएँ, या loopback/container-network clients पर भरोसा करें।

## References

- [1] [ss(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: IP Version 6 एड्रेसिंग आर्किटेक्चर](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [रीडायरेक्शन (Bash संदर्भ मैनुअल)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout invocation (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Port Scanning Techniques (Nmap संदर्भ गाइड)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Host Discovery (Nmap संदर्भ गाइड)](https://nmap.org/book/man-host-discovery.html)
- [10] [Port Specification and Scan Order (Nmap संदर्भ गाइड)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Linux मैनुअल पृष्ठ](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD मैनुअल पृष्ठ](https://man.openbsd.org/nc.1)
- [14] [curl command line tool मैनुअल](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL दस्तावेज़](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: 'Basic' HTTP प्रमाणीकरण योजना](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64 invocation (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL दस्तावेज़](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark उपयोगकर्ता गाइड](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables मैनुअल](https://netfilter.org/projects/nftables/manpage.html)
- [23] [निजी इंटरनेट के लिए एड्रेस आवंटन (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [OAuth 2.0 प्राधिकरण फ्रेमवर्क: Bearer Token का उपयोग (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: OS Command में उपयोग किए गए विशेष तत्वों का अनुचित निष्प्रभावीकरण](https://cwe.mitre.org/data/definitions/78.html)
- [27] [aiohttp अनुरक्षक की सलाह: follow_symlinks के साथ static route traversal](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
- [28] [HTB: DevHub — systemd और process arguments के ज़रिए उजागर Jupyter token](https://0xdf.gitlab.io/2026/10/10/htb-devhub.html)
{{#include ../../banners/hacktricks-training.md}}
