# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces su kernel feature koje čine da se container oseća kao "sopstvena mašina" iako je u stvari samo stabla procesa hosta. One ne kreiraju novi kernel i ne virtualizuju sve, ali dozvoljavaju kernelu da različitim grupama procesa prikaže različite poglede na odabrane resurse. To je suština container iluzije: workload vidi filesystem, procesnu tabelu, network stack, hostname, IPC resurse i model identiteta korisnika/grupe koji deluju lokalno, iako je osnovni sistem deljen.

Zato su namespaces prvo što većina ljudi upozna kada uče kako containers rade. Istovremeno, oni su jedan od najčešće pogrešno shvaćenih koncepata jer čitaoci često pretpostave da "ima namespaces" znači "je bezbedno izolovan". U stvarnosti, namespace izoluje samo specifičnu klasu resursa za koju je dizajniran. Proces može imati privatni PID namespace i i dalje biti opasan jer ima writable host bind mount. Može imati privatni network namespace i i dalje biti opasan jer zadržava `CAP_SYS_ADMIN` i radi bez seccomp. Namespaces su temeljni, ali su samo jedan sloj u konačnoj granici.

## Namespace Types

Linux containers obično se oslanjaju na nekoliko tipova namespaces istovremeno. **mount namespace** daje procesu odvojenu mount tabelu i samim tim kontrolisan pogled na filesystem. **PID namespace** menja vidljivost i numerisanje procesa tako da workload vidi sopstveno stablo procesa. **network namespace** izoluje interfejse, rute, sokete i stanje firewall-a. **IPC namespace** izoluju SysV IPC i POSIX message queues. **UTS namespace** izoluje hostname i NIS domain name. **user namespace** remapuje user i group ID-e tako da root unutar containera ne znači nužno root na hostu. **cgroup namespace** virtualizuje vidljivu cgroup hijerarhiju, a **time namespace** virtualizuje izabrane satove u novijim kernelima.

Svaki od ovih namespaces rešava drugačiji problem. Zato praktična analiza container sigurnosti često se svodi na proveru **koji namespaces su izolovani** i **koji su namerno podeljeni sa hostom**.

## Host Namespace Sharing

Mnogi container breakouts ne počinju sa kernel vulnerabilnošću. Počinju tako što operator namerno oslabi model izolacije. Primeri `--pid=host`, `--network=host`, i `--userns=host` su **Docker/Podman-style CLI flags** korišćeni ovde kao konkretni primeri deljenja host namespaces. Drugi runtimes isto predstave tu ideju drugačije. U Kubernetes ekvivalenti se obično pojavljuju kao Pod podešavanja poput `hostPID: true`, `hostNetwork: true`, ili `hostIPC: true`. U nižim nivoima runtime stack-a kao što su containerd ili CRI-O, isto ponašanje se često postiže kroz generisanu OCI runtime konfiguraciju umesto kroz korisnički flag sa istim imenom. U svim ovim slučajevima, rezultat je sličan: workload više ne dobija podrazumevani izolovani pogled na namespace.

Zato pregledi namespaces nikada ne bi trebali stati na "proces je u nekom namespace-u". Važno pitanje je da li je namespace privatan za container, podeljen s braćom containerima, ili direktno pridružen hostu. U Kubernetes isto ideja se pojavljuje sa flagovima kao što su `hostPID`, `hostNetwork`, i `hostIPC`. Imena se menjaju među platformama, ali obrazac rizika je isti: deljeni host namespace čini preostala privilegija containera i dostupno host stanje mnogo značajnijim.

## Inspection

The simplest overview is:
```bash
ls -l /proc/self/ns
```
Svaki unos je simbolički link sa identifikatorom sličnim inode-u. Ako dva procesa pokazuju na isti namespace identifikator, oni su u istom namespace-u tog tipa. To čini `/proc` veoma korisnim mestom za poređenje trenutnog procesa sa drugim interesantnim procesima na mašini.

Ove brze komande često su dovoljne za početak:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Od toga, sledeći korak je uporediti container process sa host ili susednim procesima i utvrditi da li je namespace zaista privatna ili nije.

### Enumerating Namespace Instances From The Host

Kada već imate host access i želite da razumete koliko različitih namespaces određenog tipa postoji, `/proc` daje brz pregled:
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
Ako želite da pronađete koji procesi pripadaju jednom specifičnom namespace identifikatoru, pređite sa `readlink` na `ls -l` i izvršite grep za ciljni broj namespace-a:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Ove komande su korisne jer vam omogućavaju da utvrdite da li host pokreće jedan izolovani workload, više izolovanih workload-a, ili mešavinu deljenih i privatnih namespace instanci.

### Ulazak u ciljani namespace

Kada pozivalac ima dovoljno privilegija, `nsenter` je standardan način da se pridruži namespace-u drugog procesa:
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
Poenta navođenja ovih oblika zajedno nije u tome da svaka procena treba sve njih, već da namespace-specific post-exploitation često postane mnogo lakše kada operater zna tačnu sintaksu ulaska umesto da pamti samo all-namespaces form.

## Pages

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

Dok ih čitate, imajte na umu dve ideje. Prvo, svaki namespace izoluje samo jednu vrstu pogleda. Drugo, privatni namespace je koristan samo ako ostatak modela privilegija i dalje čini tu izolaciju smislenom.

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | Po defaultu novi mount, PID, network, IPC i UTS namespaces; user namespaces su dostupni ali nisu omogućeni po defaultu u standardnim rootful podešavanjima | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Po defaultu novi namespaces; rootless Podman automatski koristi user namespace; podrazumevana podešavanja cgroup namespace-a zavise od verzije cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pod-ovi **ne** dele host PID, network, ili IPC po defaultu; Pod networking je privatno za Pod, ne za svaki pojedinačni container; user namespaces su opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Obično slede Kubernetes Pod podrazumevane postavke | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

Glavno pravilo prenosivosti je jednostavno: koncept deljenja host namespace-a je zajednički između runtime-a, ali sintaksa je specifična za svaki runtime.
