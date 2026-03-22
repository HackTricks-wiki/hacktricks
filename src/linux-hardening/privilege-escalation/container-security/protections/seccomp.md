# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

**seccomp** is die meganisme wat die kernel toelaat om ’n filter toe te pas op die syscalls wat ’n process mag invoke. In containerized omgewings word seccomp gewoonlik in filter mode gebruik sodat die process nie bloot as "restricted" in ’n vae sin gemerk word nie, maar eerder onderwerp is aan ’n konkrete syscall-beleid. Dit maak saak omdat baie container breakouts vereis dat baie spesifieke kernel interfaces bereik word. As die process nie suksesvol die relevante syscalls kan invoke nie, verdwyn ’n groot klas attacks voordat enige namespace of capability nuans selfs relevant raak.

Die sleutel-denkmodel is eenvoudig: namespaces bepaal wat die process kan sien, capabilities bepaal watter privileged actions die process nominaal toegelaat word om te probeer, en seccomp bepaal of die kernel selfs die syscall entry point vir die beoogde aksie sal aanvaar. Dit is waarom seccomp dikwels attacks voorkom wat andersins op grond van capabilities alleen moontlik sou lyk.

## Sekuriteitsimpak

Baie gevaarlike kernel-oppervlakte is slegs deur ’n relatief klein stel syscalls bereikbaar. Voorbeelde wat herhaaldelik saak maak in container hardening sluit in `mount`, `unshare`, `clone` of `clone3` met sekere flags, `bpf`, `ptrace`, `keyctl`, en `perf_event_open`. ’n attacker wat daardie syscalls kan bereik mag in staat wees om nuwe namespaces te skep, kernel subsisteme te manipuleer, of te interact met attack surface wat ’n normale application container glad nie nodig het nie.

Dit is waarom default runtime seccomp profiles so belangrik is. Hulle is nie bloot "extra defense" nie. In baie omgewings is hulle die verskil tussen ’n container wat ’n groot deel van kernel-funksionaliteit kan gebruik en een wat beperk is tot ’n syscall surface nader aan wat die application regtig nodig het.

## Modi En Filterkonstruksie

seccomp het histories ’n strict mode gehad waarin slegs ’n minimale syscall-stel beskikbaar gebly het, maar die mode relevant vir moderne container runtimes is seccomp filter mode, dikwels genaamd **seccomp-bpf**. In hierdie model evalueer die kernel ’n filterprogram wat besluit of ’n syscall toegelaat, geweier met ’n errno, getrap, gelog, of die process gedood moet word. Container runtimes gebruik hierdie meganisme omdat dit uitdruklik genoeg is om breë klasse gevaarlike syscalls te blokkeer terwyl normale application-gedrag steeds toegelaat word.

Twee laevlak-voorbeelde is nuttig omdat hulle die meganisme concreet maak eerder as magies. Strict mode demonstreer die ou "only a minimal syscall set survives" model:
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
Die finale `open` veroorsaak dat die proses gedood word omdat dit nie deel is van strict mode se minimale stel nie.

'n libseccomp-filtervoorbeeld toon die moderne beleidsmodel duideliker:
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
Hierdie soort beleid is wat die meeste lesers voor oë moet hê wanneer hulle aan runtime seccomp profiles dink.

## Laboratorium

'n eenvoudige manier om te bevestig dat seccomp in 'n container aktief is, is:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Jy kan ook 'n operasie probeer wat standaardprofiele gewoonlik beperk:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
As die container onder 'n normale standaard seccomp profile loop, word `unshare`-styl operasies dikwels geblokkeer. Dit is 'n nuttige demonstrasie omdat dit wys dat selfs al bestaan die userspace tool binne die image, die kernel path wat dit benodig steeds onbeskikbaar kan wees.
As die container onder 'n normale standaard seccomp profile loop, word `unshare`-styl operasies dikwels geblokkeer selfs wanneer die userspace tool binne die image bestaan.

Om die prosesstatus meer algemeen te ondersoek, voer uit:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Runtime gebruik

Docker ondersteun beide verstek- en aangepaste seccomp-profiele en laat administrateurs toe om dit te deaktiveer met `--security-opt seccomp=unconfined`. Podman het soortgelyke ondersteuning en koppel seccomp dikwels aan rootless-uitvoering in 'n baie sinvolle verstekhouding. Kubernetes openbaar seccomp deur werkladingkonfigurasie, waar `RuntimeDefault` gewoonlik die sinvolle basislyn is en `Unconfined` as 'n uitsondering behandel moet word wat regverdiging vereis eerder as 'n geriefskakelaar.

In containerd- en CRI-O-gebaseerde omgewings is die presiese pad meer gelaagd, maar die beginsel is dieselfde: die hoërvlak-engine of orkestreerder besluit wat moet gebeur, en die runtime installeer uiteindelik die resulterende seccomp-beleid vir die container-proses. Die uitkoms hang steeds af van die finale runtime-konfigurasie wat die kernel bereik.

### Pasgemaakte beleid-voorbeeld

Docker en soortgelyke engines kan 'n pasgemaakte seccomp-profiel uit JSON laai. 'n Minimale voorbeeld wat `chmod` weier terwyl dit alles anders toelaat, lyk soos volg:
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
Toegepas met:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Die opdrag misluk met `Operation not permitted`, wat aantoon dat die beperking deur die syscall-beleid kom en nie net deur gewone lêertoestemmings nie. In werklike hardening is allowlists oor die algemeen sterker as permissive defaults met 'n klein blacklist.

## Miskonfigurasies

Die grootste fout is om seccomp op **unconfined** te stel omdat 'n toepassing onder die standaardbeleid misluk het. Dit is algemeen tydens troubleshooting en baie gevaarlik as 'n permanente oplossing. Sodra die filter weg is, word baie syscall-based breakout primitives weer bereikbaar, veral wanneer kragtige capabilities of host namespace sharing ook teenwoordig is.

'n Ander gereelde probleem is die gebruik van 'n **custom permissive profile** wat van 'n blog of 'n interne workaround gekopieer is sonder noukeurige hersiening. Spanne bewaar soms byna alle gevaarlike syscalls eenvoudig omdat die profiel gebou is rondom "stop the app from breaking" eerder as "grant only what the app actually needs". 'n Derde misvatting is om aan te neem seccomp is minder belangrik vir non-root containers. In werklikheid bly baie kernel-aanvalsoppervlak relevant selfs wanneer die proses nie UID 0 is nie.

## Misbruik

As seccomp afwesig of ernstig verzwak is, kan 'n aanvaller dalk namespace-creation syscalls aanroep, die bereikbare kernel-aanvalsoppervlak uitbrei deur `bpf` of `perf_event_open`, `keyctl` misbruik, of daardie syscall-paaie kombineer met gevaarlike capabilities soos `CAP_SYS_ADMIN`. In baie werklike aanvalle is seccomp nie die enigste ontbrekende beheer nie, maar sy afwesigheid bekort die exploit path dramaties omdat dit een van die min verdedigings verwyder wat 'n riskante syscall kan stop voordat die res van die privilege model selfs in werking tree.

Die mees nuttige praktiese toets is om presies die syscall-families te probeer wat standaardprofiele gewoonlik blokkeer. As hulle skielik werk, het die container-postuur baie verander:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Indien `CAP_SYS_ADMIN` of 'n ander sterk capability aanwesig is, toets of seccomp die enigste ontbrekende versperring voor mount-based abuse is:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Op sommige teikens is die onmiddellike waarde nie full escape nie, maar inligtingsinsameling en kernel attack-surface expansion. Hierdie opdragte help bepaal of veral sensitiewe syscall paths bereikbaar is:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
As seccomp afwesig is en die container ook op ander maniere bevoorreg is, maak dit sin om te pivot na die meer spesifieke breakout techniques wat reeds in die legacy container-escape pages gedokumenteer is.

### Volledige voorbeeld: seccomp was die enigste ding wat `unshare` geblokkeer het

By baie teikens is die praktiese effek van die verwydering van seccomp dat namespace-creation of mount syscalls skielik begin werk. As die container ook `CAP_SYS_ADMIN` het, kan die volgende volgorde moontlik word:
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
Op sigself is dit nog nie 'n host escape nie, maar dit demonstreer dat seccomp die versperring was wat mount-related exploitation verhoed.

### Volledige Voorbeeld: seccomp Gedeaktiveer + cgroup v1 `release_agent`

As seccomp gedeaktiveer is en die container cgroup v1-hiërargieë kan mount, word die `release_agent` technique uit die cgroups-afdeling bereikbaar:
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
Dit is nie 'n seccomp-only exploit nie. Die punt is dat sodra seccomp nie meer beperk is nie, syscall-heavy breakout chains wat voorheen geblokkeer was, presies soos geskryf kan begin werk.

## Kontroles

Die doel van hierdie kontroles is om vas te stel of seccomp wel aktief is, of `no_new_privs` dit vergesel, en of die runtime-konfigurasie aandui dat seccomp eksplisiet gedeaktiveer is.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Wat hier interessant is:

- 'n Nie-nul `Seccomp`-waarde beteken dat filtering aktief is; `0` beteken gewoonlik geen seccomp-beskerming nie.
- As die runtime beveiligingsopsies `seccomp=unconfined` insluit, het die workload een van sy mees nuttige syscall-vlak verdediging verloor.
- `NoNewPrivs` is nie seccomp self nie, maar om albei saam te sien dui gewoonlik op 'n meer sorgsame verhardingshouding as om geen van beide te sien nie.

As 'n container reeds verdagte mounts, wye capabilities, of gedeelde host namespaces het, en seccomp ook unconfined is, moet daardie kombinasie as 'n groot eskalasievlagsignaal beskou word. Die container mag steeds nie triviaal breekbaar wees nie, maar die aantal kernel-entry points wat aan die aanvaller beskikbaar is, het skerp toegeneem.

## Runtime-standaarde

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Gewoonlik standaard geaktiveer | Gebruik Docker se ingeboude standaard seccomp-profiel tensy dit oorskryf word | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Gewoonlik standaard geaktiveer | Pas die runtime-standaard seccomp-profiel toe, tensy dit oorskryf word | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Nie deur verstek gewaarborg nie** | As `securityContext.seccompProfile` nie gestel is nie, is die verstek `Unconfined` tensy die kubelet `--seccomp-default` inskakel; `RuntimeDefault` of `Localhost` moet andersins uitdruklik gestel word | `securityContext.seccompProfile.type: Unconfined`, seccomp ongespesifiseer op clusters sonder `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Volg Kubernetes node- en Pod-instellings | Runtime-profiel word gebruik wanneer Kubernetes vir `RuntimeDefault` vra of wanneer kubelet seccomp-verstekinstelling geaktiveer is | Dieselfde as die Kubernetes-ry; direkte CRI/OCI-konfigurasie kan seccomp ook heeltemal weglaat |

Die Kubernetes-gedrag is die een wat operateurs die meeste verras. In baie clusters is seccomp steeds afwesig tensy die Pod dit versoek of die kubelet gekonfigureer is om na `RuntimeDefault` te verstek.
{{#include ../../../../banners/hacktricks-training.md}}
