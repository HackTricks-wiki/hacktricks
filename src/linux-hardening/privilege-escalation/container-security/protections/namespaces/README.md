# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces su kernel feature koji čini da container deluje kao „svoj sopstveni uređaj“ iako je zapravo samo host process tree. Ne kreiraju novi kernel i ne virtualizuju sve, ali dozvoljavaju kernelu da različitim grupama procesa prikaže različite poglede na odabrane resurse. To je suština iluzije container-a: workload vidi filesystem, process table, network stack, hostname, IPC resources i user/group identity model koji deluju lokalno, iako je osnovni sistem deljen.

Zato su namespaces prvi koncept sa kojim se većina ljudi susretne kada uče kako containers funkcionišu. Istovremeno, to je jedan od najčešće pogrešno shvaćenih koncepata jer čitaoci često pretpostave da „has namespaces“ znači „is safely isolated“. U stvarnosti, namespace izoluje samo konkretnu klasu resursa za koju je dizajniran. Proces može imati private PID namespace i ipak biti opasan jer ima writable host bind mount. Može imati private network namespace i opet biti opasan jer zadržava `CAP_SYS_ADMIN` i radi bez seccomp. Namespaces su osnovni sloj, ali su samo jedan sloj u konačnoj granici.

## Namespace Types

Linux containers obično se oslanjaju na više namespace tipova istovremeno. **mount namespace** daje procesu zasebnu mount table i samim tim kontrolisan pogled na filesystem. **PID namespace** menja vidljivost i numerisanje procesa tako da workload vidi sopstveno process tree. **network namespace** izoluje interfaces, routes, sockets i firewall stanje. **IPC namespace** izoluje SysV IPC i POSIX message queues. **UTS namespace** izoluje hostname i NIS domain name. **user namespace** remapuje user i group ID-e tako da root unutar container-a ne znači nužno root na host-u. **cgroup namespace** virtualizuje vidljivu cgroup hijerarhiju, a **time namespace** virtualizuje izabrane clocks u novijim kernel-ima.

Svaki od ovih namespaces rešava drugačiji problem. Zbog toga praktična analiza sigurnosti container-a često se svodi na proveru **which namespaces are isolated** i **which ones have been deliberately shared with the host**.

## Host Namespace Sharing

Mnogi container breakouts ne počinju sa kernel vulnerability. Počinju sa operatorom koji namerno slabi model izolacije. Primeri `--pid=host`, `--network=host`, i `--userns=host` su **Docker/Podman-style CLI flags** korišćeni ovde kao konkretni primeri deljenja host namespace-a. Drugi runtimes isto izražavaju istu ideju drugačije. U Kubernetes ekvivalenti se obično pojavljuju kao Pod settings kao što su `hostPID: true`, `hostNetwork: true`, ili `hostIPC: true`. U nižim runtime stack-ovima kao što su containerd ili CRI-O, isto ponašanje se često postiže kroz generisanu OCI runtime konfiguraciju umesto kroz user-facing flag sa istim imenom. U svim ovim slučajevima, rezultat je sličan: workload više ne dobija podrazumevani izolovani namespace pogled.

Zato pregledi namespaces nikada ne bi trebali da se zaustave na „proces je u nekom namespace-u“. Važno pitanje je da li je namespace privatan za container, deljen sa sibling containers, ili direktno pridružen host-u. U Kubernetes ista ideja se pojavljuje sa flag-ovima kao što su `hostPID`, `hostNetwork`, i `hostIPC`. Imena se menjaju između platformi, ali obrazac rizika je isti: shared host namespace čini preostale privilegije container-a i dostupno host stanje mnogo značajnijim.

## Inspection

Najjednostavniji pregled je:
```bash
ls -l /proc/self/ns
```
Svaki unos je simbolička veza sa identifikatorom sličnim inode-u. Ako dva procesa pokazuju na isti namespace identifikator, oni su u istom namespace-u tog tipa. To čini `/proc` veoma korisnim mestom za upoređivanje tekućeg procesa sa drugim interesantnim procesima na mašini.

Ove brze komande su često dovoljne da se počne:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Odatle, sledeći korak je uporediti proces kontejnera sa procesima na hostu ili susednim procesima i utvrditi da li je namespace zaista privatna ili ne.

### Enumeracija namespace instanci sa hosta

Kada već imate pristup hostu i želite da saznate koliko različitih namespace instanci određenog tipa postoji, `/proc` daje brz pregled:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
Ako želite da pronađete koji procesi pripadaju određenom namespace identifikatoru, pređite sa `readlink` na `ls -l` i koristite grep za ciljni broj namespace-a:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Ove komande su korisne jer vam omogućavaju da utvrdite da li host pokreće jedan izolovan workload, više izolovanih workload-a, ili mešavinu deljenih i privatnih namespace instanci.

### Ulazak u ciljani namespace

Kada pozivalac ima dovoljno privilegija, `nsenter` je standardni način da se pridružite namespace-u drugog procesa:
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
Cilj navođenja ovih oblika zajedno nije da svaka procena zahteva sve njih, već da post-exploitation specifičan za namespace često postane mnogo lakši kada operator zna tačan entry syntax umesto da pamti samo all-namespaces formu.

## Stranice

Sledeće stranice objašnjavaju svaki namespace detaljnije:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

Dok ih čitate, imajte na umu dve ideje. Prvo, svaki namespace izoluje samo jednu vrstu prikaza. Drugo, privatni namespace je koristan samo ako ostatak modela privilegija i dalje čini tu izolaciju smislenom.

## Podrazumevana podešavanja

| Runtime / platform | Podrazumevana namespace postavka | Uobičajeno ručno slabljenje |
| --- | --- | --- |
| Docker Engine | New mount, PID, network, IPC, and UTS namespaces by default; user namespaces are available but not enabled by default in standard rootful setups | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | New namespaces by default; rootless Podman automatically uses a user namespace; cgroup namespace defaults depend on cgroup version | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Usually follow Kubernetes Pod defaults | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

Glavno pravilo prenosivosti je jednostavno: the **concept** of host namespace sharing is common across runtimes, but the **syntax** is runtime-specific.
{{#include ../../../../../banners/hacktricks-training.md}}
