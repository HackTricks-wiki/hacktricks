# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

**seccomp** je mehanizam koji omogućava kernelu da primeni filter na syscalls koje proces može da pozove. U kontejnerskim okruženjima, seccomp se obično koristi u režimu filtera, tako da proces nije samo neodređeno označen kao "restricted", već podleže konkretnoj politici syscalls. Ovo je važno zato što mnogi container breakouts zahtevaju pristup vrlo specifičnim kernel interfejsima. Ako proces ne može uspešno da pozove relevantne syscalls, velika klasa napada nestaje pre nego što nijanse u vezi sa namespace ili capabilities uopšte postanu relevantne.

Ključni mentalni model je jednostavan: namespaces određuju **šta proces može da vidi**, capabilities određuju **koje privilegovane radnje je procesu nominalno dozvoljeno da pokuša**, a seccomp određuje **da li će kernel uopšte prihvatiti syscall entry point za pokušanu radnju**. Zbog toga seccomp često sprečava napade koji bi na osnovu samih capabilities inače izgledali mogućim.

## Uticaj na bezbednost

Velikom delu opasne kernel površine može se pristupiti samo putem relativno malog skupa syscalls. Primeri koji su često važni u container hardeningu obuhvataju `mount`, `unshare`, `clone` ili `clone3` sa određenim flags, `bpf`, `ptrace`, `keyctl` i `perf_event_open`. Attacker koji može da pristupi tim syscalls možda može da kreira nove namespaces, manipuliše kernel podsistemima ili stupa u interakciju sa attack surfaceom koji normalnom application containeru uopšte nije potreban.

Zbog toga su podrazumevani seccomp profili runtime-a veoma važni. Oni nisu samo "dodatna odbrana". U mnogim okruženjima predstavljaju razliku između containera koji može da koristi širok deo kernel funkcionalnosti i containera koji je ograničen na syscall surface bliži onome što je aplikaciji zaista potrebno.

## Režimi i konstrukcija filtera

seccomp je istorijski imao strict mode u kojem je ostao dostupan samo veoma mali skup syscalls, ali režim relevantan za moderne container runtimes jeste seccomp filter mode, često nazivan **seccomp-bpf**. U ovom modelu, kernel evaluira filter program koji odlučuje da li syscall treba dozvoliti, odbiti uz errno, trapovati, logovati ili prekinuti proces. Container runtimes koriste ovaj mehanizam zato što je dovoljno izražajan da blokira široke klase opasnih syscalls, a da i dalje omogućava normalno ponašanje aplikacije.

Dva low-level primera su korisna zato što mehanizam čine konkretnim, a ne magičnim. Strict mode prikazuje stari model "preživljava samo minimalni skup syscalls":
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

Primer libseccomp filtera jasnije prikazuje savremeni model policy-ja:
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
Ovaj stil policy-ja je ono što većina čitalaca treba da zamisli kada pomisli na seccomp profile tokom izvršavanja.

## Laboratorija

Jednostavan način da potvrdite da je seccomp aktivan u container-u jeste:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Možete takođe pokušati operaciju koju podrazumevani profili obično ograničavaju:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Ako kontejner radi pod normalnim podrazumevanim seccomp profilom, operacije tipa `unshare` često su blokirane. Ovo je korisna demonstracija jer pokazuje da, čak i ako userspace alat postoji unutar image-a, putanja do kernela koja mu je potrebna i dalje može biti nedostupna.

Ako kontejner radi pod normalnim podrazumevanim seccomp profilom, operacije tipa `unshare` često su blokirane čak i kada userspace alat postoji unutar image-a.

Da biste detaljnije proverili status procesa, pokrenite:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Upotreba tokom izvršavanja

Docker podržava podrazumevane i prilagođene seccomp profile i omogućava administratorima da ih onemoguće pomoću `--security-opt seccomp=unconfined`. Podman ima sličnu podršku i često kombinuje seccomp sa rootless izvršavanjem, što predstavlja veoma razumnu podrazumevanu postavku. Kubernetes izlaže seccomp kroz konfiguraciju workload-a, pri čemu je `RuntimeDefault` obično razumna osnovna postavka, dok `Unconfined` treba tretirati kao izuzetak koji zahteva obrazloženje, a ne kao praktičan prekidač.

U okruženjima zasnovanim na containerd-u i CRI-O-u, tačan put je slojevitiji, ali princip je isti: engine višeg nivoa ili orchestrator odlučuje šta treba da se desi, a runtime na kraju instalira rezultujuću seccomp policy za proces kontejnera. Ishod i dalje zavisi od konačne runtime konfiguracije koja stiže do kernela.

### Primer prilagođene policy

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
Primenjeno sa:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Komanda ne uspeva uz `Operation not permitted`, što pokazuje da ograničenje potiče od syscall policy-ja, a ne samo od uobičajenih dozvola nad fajlovima. U realnom hardening-u, allowliste su generalno jače od permisivnih podrazumevanih podešavanja sa malom blacklistom.

## Pogrešne konfiguracije

Najgrublja greška je postaviti seccomp na **unconfined** zato što aplikacija nije radila pod podrazumevanom policy-jom. Ovo je uobičajeno tokom rešavanja problema i veoma opasno kao trajna ispravka. Kada filter nestane, mnogi syscall-based breakout primitives ponovo postaju dostupni, naročito kada su prisutne moćne capabilities ili deljenje host namespace-a.

Drugi čest problem je korišćenje **custom permissive profile-a** koji je kopiran sa nekog bloga ili iz internog workaround-a, bez pažljive provere. Timovi ponekad zadržavaju gotovo sve opasne syscall-ove samo zato što je profile napravljen sa ciljem „sprečiti da se aplikacija pokvari“, umesto „dozvoliti samo ono što je aplikaciji zaista potrebno“. Treća zabluda je pretpostavka da je seccomp manje važan za non-root containers. U stvarnosti, veliki deo kernel attack surface-a ostaje relevantan čak i kada proces nije UID 0.

## Abuse

Ako seccomp nedostaje ili je ozbiljno oslabljen, attacker može biti u mogućnosti da poziva syscall-ove za kreiranje namespace-a, proširi dostupni kernel attack surface preko `bpf` ili `perf_event_open`, zloupotrebi `keyctl` ili kombinuje te syscall putanje sa opasnim capabilities-ima kao što je `CAP_SYS_ADMIN`. U mnogim realnim attack-ovima seccomp nije jedina kontrola koja nedostaje, ali njegovo odsustvo dramatično skraćuje exploit putanju jer uklanja jednu od retkih odbrana koje mogu zaustaviti rizičan syscall pre nego što ostatak privilege modela uopšte dođe do izražaja.

Najkorisniji praktični test je pokušati sa tačnim syscall familijama koje podrazumevani profili obično blokiraju. Ako one iznenada prorade, bezbednosno stanje container-a se značajno promenilo:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Ako su prisutni `CAP_SYS_ADMIN` ili neka druga snažna capability, testirajte da li je seccomp jedina preostala prepreka za zloupotrebu zasnovanu na mount-u:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Na nekim metama, neposredna korist nije potpuno bekstvo iz kontejnera, već prikupljanje informacija i proširivanje attack surface-a kernela. Ove komande pomažu da se utvrdi da li su naročito osetljive syscall putanje dostupne:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Ako seccomp nije prisutan, a container je takođe privileged na druge načine, tada ima smisla preći na specifičnije breakout tehnike koje su već dokumentovane na legacy container-escape stranicama.

### Potpun primer: seccomp je bio jedina prepreka za `unshare`

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
Samo po sebi, ovo još nije host escape, ali pokazuje da je seccomp bio prepreka koja je sprečavala eksploataciju povezanu sa mount operacijama.

### Potpun primer: seccomp onemogućen + cgroup v1 `release_agent`

Ako je seccomp onemogućen i container može da mount-uje cgroup v1 hijerarhije, `release_agent` tehnika iz odeljka o cgroups postaje dostupna:
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
Ovo nije exploit koji se oslanja isključivo na seccomp. Poenta je da, kada seccomp postane unconfined, syscall-heavy breakout chains koje su ranije bile blokirane mogu početi da rade tačno onako kako su napisane.

## Provere

Svrha ovih provera jeste da se utvrdi da li je seccomp uopšte aktivan, da li ga prati `no_new_privs` i da li runtime konfiguracija eksplicitno pokazuje da je seccomp onemogućen.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Šta je ovde zanimljivo:

- Vrednost `Seccomp` različita od nule znači da je filtering aktivan; `0` obično znači da nema seccomp zaštite.
- Ako opcije runtime security-ja uključuju `seccomp=unconfined`, workload je izgubio jednu od svojih najkorisnijih odbrana na nivou syscall-a.
- `NoNewPrivs` sam po sebi nije seccomp, ali istovremeno prisustvo oba obično ukazuje na pažljiviji pristup hardening-u nego kada nema nijednog.

Ako kontejner već ima sumnjive mount-ove, široke capabilities ili shared host namespace-ove, a seccomp je takođe unconfined, tu kombinaciju treba tretirati kao važan signal eskalacije. Kontejner možda i dalje nije trivijalno breakable, ali broj kernel entry point-a dostupnih attacker-u naglo se povećao.

## Podrazumevane vrednosti u runtime-u

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Obično je podrazumevano omogućen | Koristi Docker-ov ugrađeni podrazumevani seccomp profil, osim ako nije zamenjen | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Obično je podrazumevano omogućen | Primjenjuje podrazumevani seccomp profil runtime-a, osim ako nije zamenjen | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Nije garantovano podrazumevano** | Ako je `securityContext.seccompProfile` nedefinisan, podrazumevana vrednost je `Unconfined`, osim ako kubelet ne omogući `--seccomp-default`; `RuntimeDefault` ili `Localhost` se u suprotnom moraju eksplicitno postaviti | `securityContext.seccompProfile.type: Unconfined`, ostavljanje seccomp-a nedefinisanim na klasterima bez `seccompDefault`, `privileged: true` |
| containerd / CRI-O u okviru Kubernetes-a | Prati podešavanja Kubernetes node-a i Pod-a | Runtime profil se koristi kada Kubernetes zatraži `RuntimeDefault` ili kada je kubelet-ovo podrazumevano podešavanje seccomp-a omogućeno | Isto kao u redu za Kubernetes; direktna CRI/OCI konfiguracija takođe može u potpunosti izostaviti seccomp |

Kubernetes ponašanje je ono koje najčešće iznenađuje operatore. U mnogim klasterima seccomp i dalje nije prisutan, osim ako ga Pod ne zatraži ili ako kubelet nije konfigurisan da podrazumevano koristi `RuntimeDefault`.
{{#include ../../../../banners/hacktricks-training.md}}
