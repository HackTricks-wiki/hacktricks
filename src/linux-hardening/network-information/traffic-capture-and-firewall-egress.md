# ट्रैफ़िक कैप्चर, फ़ायरवॉल और egress की प्रारंभिक जाँच

{{#include ../../banners/hacktricks-training.md}}

[स्थानीय listeners और Unix sockets](local-network-and-socket-triage.md) ढूँढ़ने के बाद, जाँचें कि उनका ट्रैफ़िक किन interfaces से गुजरता है और कौन-से फ़ायरवॉल या proxy नियम उनकी पहुँच को प्रभावित करते हैं। loopback-only service में संवेदनशील HTTP headers हो सकते हैं, भले ही वह किसी दूसरे host से पहुँच योग्य न हो।

## कैप्चर की अनुमतियाँ जाँचें और interface चुनें

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` में packet-capture क्षमताएँ हो सकती हैं, भले ही वर्तमान उपयोगकर्ता के पास sudo access न हो। Executable की वास्तविक capabilities और group permissions जाँचें। सबसे छोटा उपयोगी interface, duration और filter चुनकर capture करें; capture में credentials या personal data हो सकता है।

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` plaintext TCP streams को फिर से बनाता है; `tshark` capture से फ़िल्टर कर सकता है और fields निकाल सकता है। TLS traffic के लिए decryption हेतु endpoint keys या ऐसा supported client ज़रूरी है जिसे connection से पहले `SSLKEYLOGFILE` के लिए configure किया गया हो। [local network triage पेज](local-network-and-socket-triage.md#tls-key-logging) में यह workflow दिखाया गया है। Encrypted capture को पढ़ने योग्य plaintext न मानें।

संग्रहीत incident artifacts से यह आकलन बदल सकता है। [Linux core dump, process memory की एक image है](https://man7.org/linux/man-pages/man5/core.5.html), जिसमें session key बची रह सकती है; यदि readable dump और packet capture एक ही process और session से मिले हों, तो analyst उस traffic को decrypt कर सकता है। पहले artifact paths और permissions की सूची बनाएँ, फिर process identity, capture time, protocol और key format को अलग-अलग सत्यापित करें। Decrypted traffic या बरामद archive, disclosure का संकेत है—किसी अन्य account की access का प्रमाण नहीं: SSH key material का कोई भी अधूरा हिस्सा फिर से बनाना होगा, उसे संबंधित public key से मिलाना होगा और उस account की SSH policy से स्वीकार करवाना होगा। व्यापक enumeration output में core contents या capture payloads dump न करें।

## Firewall layers की पहचान करें

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` और `iptables` को UFW या firewalld जैसे distribution wrappers के ज़रिए भी expose किया जा सकता है। सक्रिय rules और wrapper की persisted configuration पढ़ें; एक representation में दिखने वाला rule किसी दूसरे tool ने generate किया हो सकता है। किसी blocked service का कारण किसी खास rule को मानने से पहले interface, direction, source, destination, protocol, port और connection state की जाँच करें। एक केंद्रित उदाहरण के लिए [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) देखें।

## Egress और proxy व्यवहार का परीक्षण

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

DNS विफलता को TCP, TLS या proxy विफलता से अलग पहचानें। आकलन के लिए प्रासंगिक विशिष्ट destination और protocol का परीक्षण करें; ICMP reachability का अर्थ यह नहीं है कि TCP या UDP की अनुमति है। यदि proxy कॉन्फ़िगर है, तो proxy के ज़रिए भेजे जाने वाले अनुरोध की तुलना लागू `no_proxy` नियमों के तहत उसी target से करें। Local port forward किसी loopback service को कहीं और उपलब्ध करा सकता है, इसलिए जब firewall का नज़रिया और देखी गई exposure आपस में मेल न खाएँ, तो active listeners और SSH tunnels की समीक्षा करें।
{{#include ../../banners/hacktricks-training.md}}
