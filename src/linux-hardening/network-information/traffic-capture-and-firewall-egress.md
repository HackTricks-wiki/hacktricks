# ट्रैफ़िक कैप्चर, Firewall और Egress की जाँच

{{#include ../../banners/hacktricks-training.md}}

[लोकल लिसनर और Unix सॉकेट](local-network-and-socket-triage.md) ढूँढ़ने के बाद, जाँचें कि उनका ट्रैफ़िक किन इंटरफ़ेस से गुजरता है और कौन-से firewall या proxy नियम पहुँच को प्रभावित करते हैं। केवल loopback पर चलने वाली सेवा में संवेदनशील HTTP headers हो सकते हैं, भले ही उसे किसी दूसरे होस्ट से एक्सेस न किया जा सके।

## कैप्चर की अनुमतियाँ जाँचें और इंटरफ़ेस चुनें

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` में packet-capture की क्षमताएँ हो सकती हैं, भले ही वर्तमान उपयोगकर्ता के पास sudo access न हो। Executable की वास्तविक capabilities और group permissions जाँचें। सबसे उपयोगी interface, duration और filter के साथ न्यूनतम capture करें; capture में credentials या व्यक्तिगत डेटा हो सकता है।

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` plaintext TCP streams को फिर से बनाता है; `tshark` capture से फ़िल्टर कर सकता है और fields निकाल सकता है। TLS traffic के लिए, decryption हेतु endpoint keys या ऐसा supported client ज़रूरी है जिसे connection से पहले `SSLKEYLOGFILE` के लिए configure किया गया हो। [local network triage page](local-network-and-socket-triage.md#tls-key-logging) में यह workflow दिखाया गया है। Encrypted capture को पढ़ने योग्य plaintext न मानें।

संग्रहीत incident artifacts इस आकलन को बदल सकते हैं। [Linux core dump, process memory की एक image होती है](https://man7.org/linux/man-pages/man5/core.5.html), जिसमें session key बची रह सकती है; अगर पढ़ने योग्य dump और packet capture एक ही process और session से आए हों, तो analyst उस traffic को decrypt कर सकता है। पहले artifact paths और permissions की सूची बनाएँ, फिर process identity, capture time, protocol और key format को अलग-अलग verify करें। Decrypted traffic या recovered archive, disclosure का सुराग है—किसी दूसरे account की पहुँच का प्रमाण नहीं: SSH key का कोई भी आंशिक material अब भी reconstruct करना होगा, उसे संबंधित public key से match करना होगा, और उस account की SSH policy से स्वीकार करवाना होगा। व्यापक enumeration output में core contents या capture payloads dump करने से बचें।

## फ़ायरवॉल लेयर्स की पहचान करें

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` और `iptables` को UFW या firewalld जैसे distribution wrappers के ज़रिए भी एक्सेस किया जा सकता है। सक्रिय नियम और wrapper का सहेजा हुआ configuration पढ़ें; एक representation में दिखने वाला नियम किसी दूसरे tool ने बनाया हो सकता है। किसी blocked service का कारण किसी खास नियम को मानने से पहले interface, direction, source, destination, protocol, port और connection state की जाँच करें। एक केंद्रित उदाहरण के लिए [nftables नियमों की समीक्षा](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) देखें।

## Egress और proxy व्यवहार का परीक्षण करें

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

DNS failure को TCP, TLS या proxy failure से अलग पहचानें। Assessment के लिए प्रासंगिक विशिष्ट destination और protocol का परीक्षण करें; ICMP reachability का अर्थ यह नहीं है कि TCP या UDP की अनुमति है। यदि proxy configured है, तो इच्छित proxied request की तुलना उसी target पर लागू `no_proxy` नियमों के तहत किए गए request से करें। Local port forward किसी loopback service को कहीं और भी उपलब्ध करा सकता है, इसलिए जब firewall view और देखी गई exposure में अंतर हो, तो सक्रिय listeners और SSH tunnels की समीक्षा करें।
{{#include ../../banners/hacktricks-training.md}}
