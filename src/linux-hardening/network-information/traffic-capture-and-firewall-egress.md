# Traffic Capture, Firewall, और Egress Triage

{{#include ../../banners/hacktricks-training.md}}

[स्थानीय listeners और Unix sockets](local-network-and-socket-triage.md) ढूँढ़ने के बाद, जाँचें कि उनका traffic किन interfaces से होकर गुजरता है और कौन-से firewall या proxy rules उनकी पहुँच को प्रभावित करते हैं। केवल loopback पर उपलब्ध service में भी संवेदनशील HTTP headers हो सकते हैं, भले ही वह किसी दूसरे host से पहुँच योग्य न हो।

## Capture permissions जाँचें और interface चुनें

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` में packet-capture की क्षमताएँ हो सकती हैं, भले ही वर्तमान user के पास sudo access न हो। Executable की वास्तविक capabilities और group permissions जाँचें। सबसे उपयोगी interface, duration और filter के साथ न्यूनतम capture करें; capture में credentials या personal data हो सकता है।

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` plaintext TCP streams को reconstruct करता है; `tshark` capture से fields को filter और extract कर सकता है। TLS traffic को decrypt करने के लिए endpoint keys या ऐसा supported client चाहिए जिसे connection से पहले `SSLKEYLOGFILE` के लिए configure किया गया हो। [local network triage page](local-network-and-socket-triage.md#tls-key-logging) पर यह workflow दिखाया गया है। Encrypted capture को पढ़ने योग्य plaintext न मानें।

पहले से संग्रहित incident artifacts से यह आकलन बदल सकता है। [Linux core dump, process memory की एक image है](https://man7.org/linux/man-pages/man5/core.5.html), जिसमें session key बची रह सकती है; यदि readable dump और packet capture एक ही process और session से आए हों, तो analyst उस traffic को decrypt कर सकता है। पहले artifact paths और permissions की सूची बनाएँ, फिर process identity, capture time, protocol और key format को अलग-अलग verify करें। Decrypted traffic या recovered archive, disclosure का संकेत है—किसी दूसरे account की access का प्रमाण नहीं। SSH key का कोई भी आंशिक material अभी भी reconstruct करना होगा, corresponding public key से match करना होगा और उस account की SSH policy से स्वीकार होना होगा। व्यापक enumeration output में core contents या capture payloads dump न करें।

## Firewall layers की पहचान करें

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` और `iptables` को UFW या firewalld जैसे distribution wrappers के ज़रिए भी देखा जा सकता है। सक्रिय rules और wrapper की persisted configuration पढ़ें; एक representation में दिखने वाला rule किसी दूसरे tool ने बनाया हो सकता है। किसी blocked service का कारण किसी खास rule को मानने से पहले interface, direction, source, destination, protocol, port और connection state की जाँच करें। एक केंद्रित उदाहरण के लिए [nftables rule की समीक्षा](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) देखें।

## Egress और proxy व्यवहार का परीक्षण करें

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

DNS failure को TCP, TLS या proxy failure से अलग पहचानें। Assessment के लिए प्रासंगिक विशिष्ट destination और protocol का परीक्षण करें; ICMP reachability का मतलब यह नहीं है कि TCP या UDP की अनुमति है। यदि proxy configured है, तो इच्छित proxied request की तुलना उसी target पर लागू `no_proxy` rules के तहत किए गए अनुरोध से करें। Local port forward किसी loopback service को दूसरी जगह भी उपलब्ध करा सकता है, इसलिए जब firewall view और देखी गई exposure में अंतर हो, तो active listeners और SSH tunnels की समीक्षा करें।
{{#include ../../banners/hacktricks-training.md}}
