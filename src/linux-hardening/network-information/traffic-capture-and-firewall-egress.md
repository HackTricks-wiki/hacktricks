# ट्रैफ़िक कैप्चर, फ़ायरवॉल और Egress ट्रायेज

{{#include ../../banners/hacktricks-training.md}}

[लोकल लिसनर और Unix सॉकेट](local-network-and-socket-triage.md) खोजने के बाद, जाँचें कि उनका ट्रैफ़िक किन इंटरफ़ेस से होकर जाता है और कौन-से फ़ायरवॉल या प्रॉक्सी नियम पहुँच को प्रभावित करते हैं। केवल loopback पर चलने वाली सेवा में संवेदनशील HTTP हेडर हो सकते हैं, भले ही वह किसी दूसरे होस्ट से पहुँच योग्य न हो।

## कैप्चर अनुमतियाँ जाँचें और इंटरफ़ेस चुनें

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` में packet-capture की क्षमताएँ हो सकती हैं, भले ही मौजूदा उपयोगकर्ता के पास sudo access न हो। Executable की वास्तविक capabilities और group permissions जाँचें। उपयोगी interface, अवधि और filter के लिए सबसे सीमित मान चुनें; capture में credentials या निजी डेटा हो सकता है।

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` plaintext TCP streams को पुनर्निर्मित करता है; `tshark` किसी capture से fields को filter और extract कर सकता है। TLS traffic को decrypt करने के लिए endpoint keys या ऐसा supported client चाहिए जिसे connection से पहले `SSLKEYLOGFILE` के लिए configure किया गया हो। [local network triage page](local-network-and-socket-triage.md#tls-key-logging) में यह workflow दिखाया गया है। Encrypted capture को पढ़ने योग्य plaintext न मानें।

संग्रहीत incident artifacts इस आकलन को बदल सकते हैं। [Linux core dump, process memory की एक image होती है](https://man7.org/linux/man-pages/man5/core.5.html), जिसमें session key बची रह सकती है; यदि readable dump और packet capture एक ही process और session से आए हों, तो analyst उस traffic को decrypt कर सकता है। पहले artifact paths और permissions की सूची बनाएँ, फिर process identity, capture time, protocol और key format को अलग-अलग verify करें। Decrypted traffic या recovered archive, disclosure का संकेत है—किसी अन्य account की access का प्रमाण नहीं। SSH key material का कोई भी अधूरा हिस्सा अभी भी reconstruct करना होगा, संबंधित public key से match करना होगा, और उस account की SSH policy से स्वीकार होना होगा। व्यापक enumeration output में core contents या capture payloads dump करने से बचें।

## Firewall layers की पहचान करें

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` और `iptables` को UFW या firewalld जैसे distribution wrappers के ज़रिए उपलब्ध कराया जा सकता है। सक्रिय rules और wrapper की persisted configuration पढ़ें; एक representation में दिखने वाला rule किसी अन्य tool ने बनाया हो सकता है। किसी blocked service को किसी खास rule से जोड़ने से पहले interface, direction, source, destination, protocol, port और connection state की जाँच करें। एक केंद्रित उदाहरण के लिए [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) देखें।

## egress और proxy व्यवहार का परीक्षण करें

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

DNS की विफलता को TCP, TLS या proxy की विफलता से अलग पहचानें। आकलन के लिए प्रासंगिक विशिष्ट destination और protocol की जाँच करें; ICMP से पहुँच संभव होने का यह अर्थ नहीं है कि TCP या UDP की अनुमति है। यदि proxy कॉन्फ़िगर है, तो इच्छित proxied request की तुलना लागू `no_proxy` नियमों के तहत उसी target से करें। Local port forward से loopback service कहीं और भी उपलब्ध हो सकती है, इसलिए जब firewall का दृश्य और दिखाई देने वाली exposure में अंतर हो, तो सक्रिय listeners और SSH tunnels की जाँच करें।
{{#include ../../banners/hacktricks-training.md}}
