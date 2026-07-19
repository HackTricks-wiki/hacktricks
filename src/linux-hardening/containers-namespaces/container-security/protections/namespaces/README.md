# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces su funkcionalnost kernela zbog koje kontejner deluje kao „sopstvena mašina“, iako je zapravo samo stablo procesa na hostu. Oni ne kreiraju novi kernel niti virtuelizuju sve, ali omogućavaju kernelu da različitim grupama procesa predstavi različite prikaze odabranih resursa. To je osnova iluzije kontejnera: workload vidi filesystem, tabelu procesa, network stack, hostname, IPC resurse i model identiteta korisnika/grupa koji izgledaju lokalno, iako se osnovni sistem deli.

Zbog toga su namespaces prvi koncept sa kojim se većina ljudi susretne kada uči kako kontejneri rade. Istovremeno, oni su jedan od najčešće pogrešno shvaćenih koncepata, jer čitaoci često pretpostavljaju da „ima namespaces“ znači „bezbedno je izolovan“. U stvarnosti, namespace izoluje samo određenu klasu resursa za koju je dizajniran. Proces može imati privatni PID namespace i dalje biti opasan zato što ima writable host bind mount. Može imati privatni network namespace i dalje biti opasan zato što zadržava `CAP_SYS_ADMIN` i radi bez seccomp-a. Namespaces su osnovni, ali predstavljaju samo jedan sloj konačne granice.

## Tipovi namespaces

Linux kontejneri se obično istovremeno oslanjaju na nekoliko tipova namespaces. **Mount namespace** procesu daje zasebnu mount tabelu i samim tim kontrolisani prikaz filesystema. **PID namespace** menja vidljivost i numeraciju procesa, tako da workload vidi sopstveno stablo procesa. **Network namespace** izoluje interfejse, rute, sockete i stanje firewalla. **IPC namespace** izoluje SysV IPC i POSIX message queue-ove. **UTS namespace** izoluje hostname i NIS domain name. **User namespace** ponovo mapira ID-jeve korisnika i grupa, tako da root unutar kontejnera ne mora nužno biti root na hostu. **Cgroup namespace** virtuelizuje vidljivu cgroup hijerarhiju, a **time namespace** virtuelizuje odabrane satove u novijim kernelima.

Svaki od ovih namespaces rešava drugačiji problem. Zbog toga se praktična analiza container security-ja često svodi na proveru **koji namespaces su izolovani** i **koji su namerno deljeni sa hostom**.

## Deljenje host namespace-a

Mnogi container breakouts ne počinju kernel ranjivošću. Počinju tako što operator namerno oslabi model izolacije. Primeri `--pid=host`, `--network=host` i `--userns=host` su **Docker/Podman-style CLI flags** koji se ovde koriste kao konkretni primeri deljenja host namespace-a. Drugi runtime-i istu ideju izražavaju drugačije. U Kubernetes-u se ekvivalenti obično pojavljuju kao Pod podešavanja, kao što su `hostPID: true`, `hostNetwork: true` ili `hostIPC: true`. U lower-level runtime stack-ovima, kao što su containerd ili CRI-O, isto ponašanje se često postiže kroz generisanu OCI runtime konfiguraciju, a ne kroz user-facing flag sa istim nazivom. U svim ovim slučajevima rezultat je sličan: workload više ne dobija podrazumevani izolovani prikaz namespace-a.

Zbog toga provera namespaces nikada ne bi trebalo da se zaustavi na tvrdnji „proces je u nekom namespace-u“. Važno pitanje je da li je namespace privatan za kontejner, deljen sa sibling kontejnerima ili direktno pridružen hostu. U Kubernetes-u se ista ideja pojavljuje sa flagovima kao što su `hostPID`, `hostNetwork` i `hostIPC`. Nazivi se razlikuju između platformi, ali je obrazac rizika isti: deljeni host namespace čini preostale privilegije kontejnera i dostupno stanje hosta mnogo značajnijim.

## Inspekcija

Najjednostavniji pregled je:
```bash
ls -l /proc/self/ns
```
Svaki unos je simbolička veza sa identifikatorom nalik inode-u. Ako dva procesa pokazuju na isti identifikator namespace-a, nalaze se u istom namespace-u tog tipa. Zbog toga je `/proc` veoma korisno mesto za poređenje trenutnog procesa sa drugim zanimljivim procesima na mašini.

Ove brze komande su često dovoljne za početak:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Od tog trenutka, sledeći korak je upoređivanje procesa iz containera sa procesima na hostu ili u susednim containerima i utvrđivanje da li je namespace zaista privatan ili nije.

### Enumerisanje Instanci Namespace-a Sa Hosta

Kada već imate pristup hostu i želite da utvrdite koliko različitih namespace-ova određenog tipa postoji, `/proc` pruža brz pregled:
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
Ako želite da pronađete koji procesi pripadaju određenom identifikatoru namespace-a, zamenite `readlink` sa `ls -l` i koristite grep za ciljni broj namespace-a:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Ove komande su korisne jer omogućavaju da utvrdite da li host pokreće jedno izolovano workload okruženje, više izolovanih workload okruženja ili kombinaciju deljenih i privatnih Namespace instanci.

### Ulazak u ciljni Namespace

Kada pozivalac ima dovoljne privilegije, `nsenter` je standardni način za pridruživanje Namespace-u drugog procesa:
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
Poenta navođenja ovih formi zajedno nije u tome da svaka procena zahteva sve njih, već da post-exploitation specifičan za namespace često postaje mnogo lakši kada operator zna tačnu ulaznu sintaksu, umesto da pamti samo formu za sve namespaces.

## Stranice

Sledeće stranice detaljnije objašnjavaju svaki namespace:

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

Dok ih čitate, imajte na umu dve ideje. Prvo, svaki namespace izoluje samo jednu vrstu prikaza. Drugo, privatni namespace je koristan samo ako ostatak modela privilegija i dalje čini tu izolaciju značajnom.

## Podrazumevane vrednosti runtime-a

| Runtime / platforma | Podrazumevana postavka namespace-a | Uobičajeno ručno slabljenje |
| --- | --- | --- |
| Docker Engine | Novi mount, PID, network, IPC i UTS namespaces podrazumevano; user namespaces su dostupni, ali nisu podrazumevano omogućeni u standardnim rootful podešavanjima | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Novi namespaces podrazumevano; rootless Podman automatski koristi user namespace; podrazumevane vrednosti cgroup namespace-a zavise od verzije cgroup-a | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pod-ovi podrazumevano **ne dele** host PID, network ili IPC; Pod networking je privatan za Pod, a ne za svaki pojedinačni container; user namespaces se uključuju po izboru preko `spec.hostUsers: false` na podržanim klasterima | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / izostavljanje uključivanja user namespace-a, podešavanja za privileged workload |
| containerd / CRI-O pod Kubernetes-om | Obično prate podrazumevane vrednosti Kubernetes Pod-ova | isto kao u Kubernetes redu; direktne CRI/OCI specifikacije takođe mogu zahtevati pridruživanje host namespace-ovima |

Glavno pravilo prenosivosti je jednostavno: **koncept** deljenja host namespace-a zajednički je različitim runtime-ovima, ali je **sintaksa** specifična za runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
