# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

**seccomp** je mehanizam koji omogućava kernelu da primeni filter na syscalls koje proces može da pozove. U containerized okruženjima, seccomp se obično koristi u filter modu, tako da proces nije samo neodređeno označen kao "restricted", već podleže konkretnoj syscall politici. Ovo je važno zato što mnogi container breakouts zahtevaju pristup veoma specifičnim kernel interfejsima. Ako proces ne može uspešno da pozove relevantne syscalls, velika klasa napada nestaje pre nego što nijanse namespace-ova ili capabilities uopšte postanu relevantne.

Ključni mentalni model je jednostavan: namespace-ovi određuju **šta proces može da vidi**, capabilities određuju **koje privilegovane radnje proces nominalno sme da pokuša**, a seccomp određuje **da li će kernel uopšte prihvatiti syscall entry point za pokušanu radnju**. Zbog toga seccomp često sprečava napade koji bi na osnovu samih capabilities inače izgledali mogućim.

## Bezbednosni uticaj

Veliki deo opasne kernel attack surface dostupan je samo kroz relativno mali skup syscalls. Primeri koji su često važni u container hardening-u obuhvataju `mount`, `unshare`, `clone` ili `clone3` sa određenim flagovima, `bpf`, `ptrace`, `keyctl` i `perf_event_open`. Attacker koji može da pristupi tim syscalls može biti u stanju da kreira nove namespace-ove, manipuliše kernel subsystem-ima ili pristupi attack surface-u koji normalnom application container-u uopšte nije potreban.

Zbog toga su default runtime seccomp profili veoma važni. Oni nisu samo "extra defense". U mnogim okruženjima predstavljaju razliku između container-a koji može da koristi širok deo kernel funkcionalnosti i onog koji je ograničen na syscall surface bliži onome što aplikaciji zaista treba.

## Režimi i konstrukcija filtera

seccomp je istorijski imao strict mode, u kojem je bio dostupan samo veoma mali skup syscalls, ali je za moderne container runtime-ove relevantan seccomp filter mode, koji se često naziva **seccomp-bpf**. U ovom modelu, kernel izvršava filter program koji odlučuje da li syscall treba dozvoliti, odbiti uz errno, trap-ovati, evidentirati ili ubiti proces.<sup>[[1]](#references)</sup> Container runtime-ovi koriste ovaj mehanizam zato što je dovoljno izražajan da blokira široke klase opasnih syscalls, a da pritom i dalje omogućava normalno ponašanje aplikacije.

Dva low-level primera su korisna zato što mehanizam čine konkretnim, a ne magičnim. Strict mode prikazuje stari model u kojem "preživljava samo minimalni skup syscalls":
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
Konačni `open` dovodi do prekida procesa jer nije deo minimalnog skupa strict mode-a.

Primer libseccomp filtera jasnije prikazuje moderni model policy-ja:
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
Ovaj stil policy-ja je ono što većina čitalaca treba da zamisli kada pomisli na runtime seccomp profile.

## Laboratorija

Jednostavan način da potvrdite da je seccomp aktivan u container-u je:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Možete takođe pokušati operaciju koju podrazumevani profili obično ograničavaju:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Ako kontejner radi pod uobičajenim podrazumevanim seccomp profilom, operacije u stilu `unshare` često su blokirane. Ovo je korisna demonstracija jer pokazuje da čak i ako userspace alat postoji unutar image-a, putanja kroz kernel koja mu je potrebna i dalje može biti nedostupna.

Ako kontejner radi pod uobičajenim podrazumevanim seccomp profilom, operacije u stilu `unshare` često su blokirane čak i kada userspace alat postoji unutar image-a.

Da biste uopštenije proverili status procesa, pokrenite:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Upotreba tokom izvršavanja

Docker podržava podrazumevane i prilagođene seccomp profile i omogućava administratorima da ih onemoguće pomoću `--security-opt seccomp=unconfined`.<sup>[[2]](#references)</sup> Podman ima sličnu podršku i često kombinuje seccomp sa rootless izvršavanjem, što predstavlja veoma razumnu podrazumevanu postavku. Kubernetes izlaže seccomp kroz konfiguraciju workload-a, gde je `RuntimeDefault` obično razumna osnovna postavka, dok `Unconfined` treba tretirati kao izuzetak koji zahteva obrazloženje, a ne kao praktičan prekidač.<sup>[[3]](#references)</sup>

U okruženjima zasnovanim na containerd-u i CRI-O-u, tačan tok je složeniji, ali princip je isti: engine višeg nivoa ili orchestrator odlučuje šta treba da se desi, a runtime na kraju instalira dobijenu seccomp politiku za proces container-a. Ishod i dalje zavisi od konačne runtime konfiguracije koja stiže do kernel-a.

### Primer prilagođene politike

Docker i slični engine-i mogu učitati prilagođeni seccomp profil iz JSON-a. Minimalni primer koji odbija `chmod`, a dozvoljava sve ostalo, izgleda ovako:
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
Primenjeno uz:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Komanda ne uspeva uz `Operation not permitted`, što pokazuje da ograničenje potiče od syscall politike, a ne samo od uobičajenih dozvola nad datotekama. U stvarnom hardeningu, allowlist-e su uglavnom jače od permissive podrazumevanih podešavanja sa kratkom blacklist-om.

## Misconfigurations

Najgrublja greška je postaviti seccomp na **unconfined** zato što aplikacija nije radila sa podrazumevanom politikom. Ovo je uobičajeno tokom rešavanja problema i veoma je opasno kao trajno rešenje. Kada filter nestane, mnogi syscall-based breakout primitives ponovo postaju dostupni, naročito kada su prisutne moćne capabilities ili deljenje host namespace-ova.

Drugi čest problem je korišćenje **custom permissive profile-a** koji je kopiran sa nekog bloga ili iz internog workaround-a, bez pažljive provere. Timovi ponekad zadržavaju gotovo sve opasne syscall-ove samo zato što je profile napravljen sa ciljem „sprečiti da se aplikacija pokvari“, umesto „dozvoliti samo ono što je aplikaciji zaista potrebno“. Treća zabluda je pretpostavka da je seccomp manje važan za non-root kontejnere. U stvarnosti, veliki deo kernel attack surface-a ostaje relevantan čak i kada proces nije UID 0.

## Abuse

Ako seccomp nedostaje ili je ozbiljno oslabljen, attacker može moći da pozove syscall-ove za kreiranje namespace-ova, proširi dostupan kernel attack surface preko `bpf` ili `perf_event_open`, zloupotrebi `keyctl` ili kombinuje te syscall putanje sa opasnim capabilities kao što je `CAP_SYS_ADMIN`. U mnogim stvarnim napadima seccomp nije jedina kontrola koja nedostaje, ali njegovo odsustvo dramatično skraćuje exploit putanju jer uklanja jednu od malobrojnih odbrana koje mogu zaustaviti rizičan syscall pre nego što ostatak privilege modela uopšte dođe do izražaja.

Najkorisniji praktični test je pokušati sa tačnim syscall family-jima koje podrazumevani profili obično blokiraju. Ako iznenada prorade, bezbednosni položaj kontejnera se značajno promenio:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Ako je prisutan `CAP_SYS_ADMIN` ili druga jaka capability, testirajte da li je seccomp jedina preostala prepreka pre abuse-a zasnovanog na mount-u:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Na nekim metama, neposredna vrednost nije potpuno bekstvo, već prikupljanje informacija i proširivanje attack surface-a kernela. Ove komande pomažu da se utvrdi da li su posebno osetljive syscall putanje dostupne:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Ako seccomp nije prisutan, a container je takođe privileged na druge načine, tada ima smisla preći na specifičnije breakout techniques koje su već dokumentovane na legacy container-escape stranicama.

### Potpuni primer: seccomp je bio jedina stvar koja je blokirala `unshare`

Na mnogim targetima, praktičan efekat uklanjanja seccomp-a jeste da namespace-creation ili mount syscalls iznenada počnu da rade. Ako container takođe ima `CAP_SYS_ADMIN`, sledeći niz koraka može postati moguć:
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
Samo po sebi, ovo još nije `host escape`, ali pokazuje da je seccomp bio prepreka koja je sprečavala exploitation povezan sa mount operacijama.

### Kompletan primer: seccomp Disabled + cgroup v1 `release_agent`

Ako je seccomp disabled i container može da mount-uje cgroup v1 hijerarhije, tehnika `release_agent` iz odeljka o cgroups postaje dostupna:
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
Ovo nije exploit koji se oslanja samo na seccomp. Poenta je da, kada seccomp više nije ograničen, breakout chains koje intenzivno koriste syscall-ove, a koje su ranije bile blokirane, mogu početi da rade upravo onako kako su napisane.

## Provere

Svrha ovih provera jeste da se utvrdi da li je seccomp uopšte aktivan, da li ga prati `no_new_privs` i da li konfiguracija runtime-a eksplicitno pokazuje da je seccomp onemogućen.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Šta je ovde zanimljivo:

- Ne-nulta vrednost `Seccomp` znači da je filtering aktivan; `0` obično znači da nema seccomp zaštite.
- Ako opcije runtime bezbednosti uključuju `seccomp=unconfined`, workload je izgubio jednu od svojih najkorisnijih odbrana na nivou sistemskih poziva.
- `NoNewPrivs` sam po sebi nije seccomp, ali istovremena pojava oba podešavanja obično ukazuje na pažljiviji pristup hardeningu nego kada nema nijednog od njih.

Ako container već ima sumnjive mountove, široke capabilities ili deljene host namespaces, a seccomp je takođe unconfined, tu kombinaciju treba tretirati kao značajan signal eskalacije. Container možda i dalje nije trivijalno kompromitovati, ali se broj kernel entry pointova dostupnih attackeru naglo povećao.

## Podrazumevane Runtime vrednosti

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Obično omogućen podrazumevano | Koristi Docker-ov ugrađeni podrazumevani seccomp profil, osim ako nije zamenjen | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Obično omogućen podrazumevano | Primjenjuje podrazumevani runtime seccomp profil, osim ako nije zamenjen | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Nije garantovano podrazumevano** | Ako je `securityContext.seccompProfile` nepodešen, podrazumevana vrednost je `Unconfined`, osim ako kubelet ne omogući `--seccomp-default`; `RuntimeDefault` ili `Localhost` se u suprotnom moraju eksplicitno postaviti | `securityContext.seccompProfile.type: Unconfined`, ostavljanje seccomp-a nepodešenim na klasterima bez `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Prati Kubernetes node i Pod podešavanja | Runtime profil se koristi kada Kubernetes zahteva `RuntimeDefault` ili kada je kubelet-ov seccomp defaulting omogućen | Isto kao u redu za Kubernetes; direktna CRI/OCI konfiguracija takođe može potpuno izostaviti seccomp |

Kubernetes ponašanje je ono koje najčešće iznenađuje operatore. U mnogim klasterima seccomp je i dalje odsutan, osim ako ga Pod ne zahteva ili kubelet nije konfigurisan da podrazumevano koristi `RuntimeDefault`.<sup>[[3]](#references)</sup>

## Reference

- [1] [Linux kernel documentation: Seccomp BPF (SECure COMPuting with filters)](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [2] [Docker Docs: Seccomp security profiles for Docker](https://docs.docker.com/engine/security/seccomp/)
- [3] [Kubernetes Docs: Restrict a Container's Syscalls with seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)

{{#include ../../../../banners/hacktricks-training.md}}
