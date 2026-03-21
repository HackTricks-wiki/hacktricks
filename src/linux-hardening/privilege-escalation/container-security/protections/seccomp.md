# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

**seccomp** je mehanizam koji omogućava kernelu da primeni filter na syscalls koje proces može pozvati. U kontejnerizovanim okruženjima, seccomp se obično koristi u filter modu tako da proces nije jednostavno označen kao "restricted" u nejasnom smislu, već podleže konkretnoj politici za syscalls. Ovo je važno zato što mnogi container breakouts zahtevaju pristup veoma specifičnim kernel interfejsima. Ako proces ne može uspešno da pozove relevantne syscalls, velika klasa napada nestaje pre nego što bilo koja nijansa oko namespaces ili capabilities postane relevantna.

Ključni mentalni model je jednostavan: namespaces odlučuju **šta proces može da vidi**, capabilities odlučuju **koje privilegovane akcije proces nominalno sme da pokuša**, a seccomp odlučuje **da li će kernel uopšte prihvatiti ulaznu tačku za pozvani syscall za pokušanu akciju**. Zato seccomp često sprečava napade koji bi inače delovali mogući zasnovano samo na capabilities.

## Security Impact

Veliki deo opasne površine kernela je dostupan samo kroz relativno mali skup syscalls. Primeri koji se često javljaju pri hardeningu kontejnera uključuju `mount`, `unshare`, `clone` ili `clone3` sa određenim zastavicama, `bpf`, `ptrace`, `keyctl` i `perf_event_open`. Napadač koji može da pristupi tim syscalls može biti u stanju da kreira nove namespaces, manipuliše kernel subsistemima, ili stupi u interakciju sa attack surface-om koji normalnom aplikacionom kontejneru uopšte nije potreban.

Zato su podrazumevani runtime seccomp profili toliko važni. Oni nisu samo "extra defense". U mnogim okruženjima oni predstavljaju razliku između kontejnera koji može da koristi širok deo kernel funkcionalnosti i onog koji je ograničen na syscall površinu bližu onome što aplikaciji zaista treba.

## Modes And Filter Construction

seccomp je istorijski imao strict mode u kojem je samo mali skup syscalls ostajao dostupan, ali mod relevantan za moderne container runtimes je seccomp filter mode, često nazivan **seccomp-bpf**. U ovom modelu kernel evaluira program filtera koji odlučuje da li treba dozvoliti syscall, odbiti sa errno, uhvatiti ga (trapped), zabeležiti (logged) ili ubiti proces. Container runtimes koriste ovaj mehanizam jer je dovoljno izražajan da blokira široke klase opasnih syscalls, a ipak dozvoli normalno ponašanje aplikacija.

Dva niskonivovna primera su korisna jer čine mehanizam konkretnim umesto magičnim. Strict mode demonstrira stari model "samo minimalni skup syscalls opstaje":
```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
int output = open("output.txt", O_WRONLY);
const char *val = "test";
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
write(output, val, strlen(val) + 1);
open("output.txt", O_RDONLY);
}
```
Poslednji `open` uzrokuje da proces bude ubijen jer nije deo minimalnog skupa strict mode-a.

Primer libseccomp filtera jasnije prikazuje moderni model politike:
```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));
seccomp_load(ctx);
seccomp_release(ctx);
printf("pid=%d\n", getpid());
}
```
Ovakav stil politike je ono što većina čitalaca treba da zamisli kada pomisle na runtime seccomp profiles.

## Vežba

Jednostavan način da se potvrdi da je seccomp aktivan u kontejneru je:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Takođe možete pokušati operaciju koju podrazumevani profili obično ograničavaju:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Ako kontejner radi pod normalnim podrazumevanim seccomp profilom, `unshare`-stil operacije su često blokirane. Ovo je koristan primer jer pokazuje da čak i ako userspace alat postoji unutar image-a, kernel putanja koja mu je potrebna može i dalje biti nedostupna.
Ako kontejner radi pod normalnim podrazumevanim seccomp profilom, `unshare`-stil operacije su često blokirane čak i kada userspace alat postoji unutar image-a.

Za opštiji pregled statusa procesa, pokrenite:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Korišćenje u runtime-u

Docker podržava i podrazumevane i prilagođene seccomp profile i omogućava administratorima da ih onemoguće pomoću `--security-opt seccomp=unconfined`. Podman ima sličnu podršku i često kombinuje seccomp sa rootless izvršavanjem u vrlo razumnom podrazumevanom režimu. Kubernetes izlaže seccomp kroz konfiguraciju workload-a, gde je `RuntimeDefault` obično razumna osnovna postavka, a `Unconfined` treba tretirati kao izuzetak koji zahteva opravdanje, a ne kao pogodnosni prekidač.

U okruženjima zasnovanim na containerd i CRI-O, tačan put je slojevitiji, ali princip je isti: engine višeg nivoa ili orchestrator odlučuje šta treba da se desi, a runtime na kraju instalira dobijenu seccomp politiku za proces kontejnera. Ishod i dalje zavisi od krajnje runtime konfiguracije koja dospeva do kernela.

### Primer prilagođene politike

Docker i slični engine-i mogu učitati prilagođeni seccomp profil iz JSON-a. Minimalan primer koji odbija `chmod` dok sve ostalo dozvoljava izgleda ovako:
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
Primenjeno pomoću:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Komanda ne uspeva sa `Operation not permitted`, što pokazuje da ograničenje dolazi iz politike syscall-a, a ne samo iz običnih dozvola fajla. Kod stvarnog hardeninga, liste dozvoljenih su generalno jače od permisivnih podrazumevanih podešavanja sa malom crnom listom.

## Misconfigurations

Najgrublja greška je postaviti seccomp na **unconfined** zato što je aplikacija pala pod podrazumevanom politikom. Ovo je često tokom otklanjanja problema i veoma opasno ako se ostavi kao trajno rešenje. Kada filter nestane, mnogi primitivni za bekstvo zasnovani na syscall-ovima ponovo postaju dostupni, posebno kada su prisutne moćne capabilities ili deljenje host namespace-a.

Još jedan čest problem je korišćenje **prilagođenog permisivnog profila** koji je kopiran sa nekog bloga ili internog zaobilaznog rešenja bez pažljivog pregleda. Timovi ponekad zadrže skoro sve opasne syscalls jednostavno zato što je profil napravljen oko "da aplikacija ne prestane da radi" umesto "dodeli samo ono što aplikacija zapravo treba". Treća zabluda je pretpostavka da je seccomp manje važan za kontejnere koji nisu root. U stvarnosti, veliki deo napadne površine kernela ostaje relevantan čak i kada proces nije UID 0.

## Abuse

Ako seccomp ne postoji ili je ozbiljno oslabljen, napadač bi mogao da pozove namespace-creation syscalls, proširi dostupnu napadnu površinu kernela kroz `bpf` ili `perf_event_open`, zloupotrebi `keyctl`, ili kombinuje te syscall putanje sa opasnim capabilities kao što je `CAP_SYS_ADMIN`. U mnogim stvarnim napadima, seccomp nije jedina kontrola koja nedostaje, ali njegovo odsustvo dramatčno skraćuje put eksploata jer uklanja jednu od retkih odbrana koje mogu zaustaviti rizičan syscall pre nego što ostatak modela privilegija počne da deluje.

Najkorisniji praktični test je pokušati tačno one grupe syscall-a koje podrazumevani profili obično blokiraju. Ako iznenada rade, bezbednosni položaj kontejnera se znatno promenio:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Ako je prisutan `CAP_SYS_ADMIN` ili neka druga snažna capability, proverite da li je seccomp jedina nedostajuća barijera pre mount-based abuse:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Na nekim ciljevima, neposredna vrednost nije potpuni escape već prikupljanje informacija i kernel attack-surface expansion. Ove komande pomažu да се утврди да ли су посебно осетљиви syscall paths доступни:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Ako seccomp nije prisutan i container je na druge načine takođe privilegovan, tada ima smisla preći na specifičnije breakout tehnike koje su već dokumentovane na legacy container-escape stranicama.

### Potpun primer: seccomp je bila jedina stvar koja je onemogućavala `unshare`

Na mnogim targetsima, praktičan efekat uklanjanja seccomp-a je da namespace-creation ili mount syscalls iznenada počnu da rade. Ako container takođe ima `CAP_SYS_ADMIN`, sledeći sled može postati moguć:
```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
mount -t tmpfs tmpfs /tmp/nsroot &&
mkdir -p /tmp/nsroot/proc &&
mount -t proc proc /tmp/nsroot/proc &&
mount | grep /tmp/nsroot
'
```
Samo po sebi ovo još nije host escape, ali pokazuje da je seccomp bila barijera koja je sprečavala mount-related exploitation.

### Potpun primer: seccomp onemogućen + cgroup v1 `release_agent`

Ako je seccomp onemogućen i kontejner može da mount-uje cgroup v1 hijerarhije, tehnika `release_agent` iz cgroups sekcije postaje dostupna:
```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Ovo nije seccomp-only exploit. Poenta je da jednom kada je seccomp unconfined, syscall-heavy breakout chains koje su ranije bile blokirane mogu početi da rade tačno onako kako su napisane.

## Checks

Svrha ovih provera je da se utvrdi da li je seccomp uopšte aktivan, da li ga prati `no_new_privs`, i da li runtime konfiguracija eksplicitno pokazuje da je seccomp onemogućen.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Zanimljivo ovde:

- Nenulti `Seccomp` vrednost znači da je filtriranje aktivno; `0` obično znači da nema seccomp zaštite.
- Ako runtime sigurnosne opcije uključuju `seccomp=unconfined`, workload je izgubio jednu od najsvrsishodnijih odbrana na nivou syscall-a.
- `NoNewPrivs` nije seccomp sam po sebi, ali njihovo zajedničko prisustvo obično ukazuje na pažljiviji hardening nego kada nema nijednog.

Ako container već ima sumnjive mounts, široke capabilities, ili shared host namespaces, i seccomp je takođe unconfined, ta kombinacija treba da se tretira kao ozbiljan signal eskalacije. Container možda i dalje nije trivijalno probiti, ali broj kernel entry points dostupnih napadaču se naglo povećao.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Obično omogućeno podrazumevano | Koristi Docker-ov ugrađeni podrazumevani seccomp profil osim ako nije prepisan | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Obično omogućeno podrazumevano | Primenjuje runtime podrazumevani seccomp profil osim ako nije prepisan | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Nije garantovano podrazumevano** | If `securityContext.seccompProfile` is unset, the default is `Unconfined` unless the kubelet enables `--seccomp-default`; `RuntimeDefault` or `Localhost` must otherwise be set explicitly | `securityContext.seccompProfile.type: Unconfined`, leaving seccomp unset on clusters without `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Sledi Kubernetes node i Pod podešavanja | Runtime profil se koristi kada Kubernetes zahteva `RuntimeDefault` ili kada je kubelet seccomp defaulting omogućen | Isto kao u Kubernetes redu; direktna CRI/OCI konfiguracija takođe može u potpunosti izostaviti seccomp |

The Kubernetes behavior is the one that most often surprises operators. In many clusters, seccomp is still absent unless the Pod requests it or the kubelet is configured to default to `RuntimeDefault`.
