# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

**seccomp** is die meganisme wat die kernel toelaat om ’n filter toe te pas op die syscalls wat ’n proses mag aanroep. In containerized environments word seccomp normaalweg in filter mode gebruik sodat die proses nie bloot in ’n vae sin as "restricted" gemerk word nie, maar eerder aan ’n konkrete syscall-beleid onderhewig is. Dit is belangrik omdat baie container breakouts vereis dat baie spesifieke kernel-interfaces bereik word. As die proses nie die relevante syscalls suksesvol kan aanroep nie, verdwyn ’n groot klas aanvalle voordat enige namespace- of capability-nuanse selfs relevant word.

Die sleutelmentaliteitsmodel is eenvoudig: namespaces bepaal **wat die proses kan sien**, capabilities bepaal **watter privileged actions die proses nominaal mag probeer uitvoer**, en seccomp bepaal **of die kernel selfs die syscall-entry point vir die beoogde aksie sal aanvaar**. Daarom voorkom seccomp dikwels aanvalle wat andersins moontlik sou lyk op grond van capabilities alleen.

## Sekuriteitsimpak

Baie gevaarlike kernel-surface is slegs deur ’n relatief klein stel syscalls bereikbaar. Voorbeelde wat herhaaldelik belangrik is in container hardening, sluit `mount`, `unshare`, `clone` of `clone3` met spesifieke flags, `bpf`, `ptrace`, `keyctl`, en `perf_event_open` in. ’n Attacker wat daardie syscalls kan bereik, kan moontlik nuwe namespaces skep, kernel-subsystems manipuleer, of interaksie hê met attack surface wat ’n normale application container glad nie nodig het nie.

Dit is waarom default runtime seccomp profiles so belangrik is. Hulle is nie bloot "extra defense" nie. In baie omgewings is hulle die verskil tussen ’n container wat ’n breë gedeelte van kernel functionality kan gebruik en een wat beperk is tot ’n syscall-surface wat nader is aan wat die application werklik benodig.

## Modes En Filter-konstruksie

seccomp het histories ’n strict mode gehad waarin slegs ’n baie klein stel syscalls beskikbaar gebly het, maar die mode wat relevant is vir moderne container runtimes is seccomp filter mode, dikwels **seccomp-bpf** genoem. In hierdie model evalueer die kernel ’n filter program wat besluit of ’n syscall toegelaat, met ’n errno geweier, getrap, gelog, of die proses beëindig moet word. Container runtimes gebruik hierdie meganisme omdat dit ekspressief genoeg is om breë klasse gevaarlike syscalls te blokkeer terwyl normale application behavior steeds toegelaat word.

Twee low-level voorbeelde is nuttig omdat hulle die meganisme konkreet eerder as magies maak. Strict mode demonstreer die ou "only a minimal syscall set survives"-model:
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
Die finale `open` veroorsaak dat die proses beëindig word omdat dit nie deel van strict mode se minimale stel is nie.

’n libseccomp-filtervoorbeeld toon die moderne beleidsmodel duideliker:
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
Hierdie styl van beleid is wat die meeste lesers behoort voor te stel wanneer hulle aan runtime seccomp-profiele dink.

## Laboratorium

’n Eenvoudige manier om te bevestig dat seccomp in ’n container aktief is, is:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Jy kan ook ’n bewerking probeer wat verstekprofiele gewoonlik beperk:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
As die container onder ’n normale verstek-`seccomp`-profiel loop, word `unshare`-style-bewerkings dikwels geblokkeer. Dit is ’n nuttige demonstrasie, omdat dit wys dat selfs al bestaan die userspace-hulpmiddel binne die image, die kernel-pad wat dit benodig steeds onbeskikbaar kan wees.

As die container onder ’n normale verstek-`seccomp`-profiel loop, word `unshare`-style-bewerkings dikwels geblokkeer, selfs wanneer die userspace-hulpmiddel binne die image bestaan.

Om die prosesstatus meer algemeen te inspekteer, voer die volgende uit:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Gebruik tydens looptyd

Docker ondersteun beide verstek- en pasgemaakte seccomp-profiele en laat administrateurs toe om dit te deaktiveer met `--security-opt seccomp=unconfined`. Podman het soortgelyke ondersteuning en kombineer seccomp dikwels met rootless-uitvoering in ’n baie sinvolle verstekopstelling. Kubernetes stel seccomp bloot deur workload-konfigurasie, waar `RuntimeDefault` gewoonlik die verstandige basislyn is en `Unconfined` as ’n uitsondering behandel moet word wat regverdiging vereis, eerder as ’n gerieflikheidskakelaar.

In containerd- en CRI-O-gebaseerde omgewings is die presiese roete meer gelaagd, maar die beginsel is dieselfde: die hoërvlak-enjin of orchestrator besluit wat moet gebeur, en die runtime installeer uiteindelik die resulterende seccomp-beleid vir die container-proses. Die uitkoms hang steeds af van die finale runtime-konfigurasie wat die kernel bereik.

### Voorbeeld van ’n pasgemaakte beleid

Docker en soortgelyke enjins kan ’n pasgemaakte seccomp-profiel vanaf JSON laai. ’n Minimale voorbeeld wat `chmod` weier terwyl alles anders toegelaat word, lyk soos volg:
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
Die opdrag misluk met `Operation not permitted`, wat demonstreer dat die beperking van die syscall-beleid afkomstig is, eerder as slegs van gewone lêertoestemmings. In werklike hardening is allowlists oor die algemeen sterker as permissiewe verstekke met 'n klein blacklist.

## Wankonfigurasies

Die mees onbesonne fout is om seccomp op **unconfined** te stel omdat 'n toepassing onder die verstekbeleid misluk het. Dit gebeur dikwels tydens troubleshooting en is baie gevaarlik as 'n permanente oplossing. Sodra die filter verwyder is, word baie syscall-gebaseerde breakout primitives weer bereikbaar, veral wanneer kragtige capabilities of gedeelde host namespaces ook teenwoordig is.

Nog 'n algemene probleem is die gebruik van 'n **custom permissive profile** wat van een of ander blog of interne workaround gekopieer is sonder dat dit noukeurig hersien is. Spanne behou soms byna alle gevaarlike syscalls bloot omdat die profile gebou is rondom "verhoed dat die toepassing breek", eerder as "verleen slegs wat die toepassing werklik nodig het". 'n Derde wanopvatting is om aan te neem dat seccomp minder belangrik is vir nie-root containers. In werklikheid bly baie kernel attack surface relevant, selfs wanneer die proses nie UID 0 is nie.

## Misbruik

As seccomp ontbreek of ernstig verswak is, kan 'n aanvaller moontlik namespace-creation syscalls uitvoer, die bereikbare kernel attack surface uitbrei deur `bpf` of `perf_event_open`, `keyctl` misbruik, of hierdie syscall paths kombineer met gevaarlike capabilities soos `CAP_SYS_ADMIN`. In baie werklike attacks is seccomp nie die enigste ontbrekende beheermaatreël nie, maar die afwesigheid daarvan verkort die exploit path dramaties omdat dit een van die min defenses verwyder wat 'n riskante syscall kan stop voordat die res van die privilege model eers ter sprake kom.

Die nuttigste praktiese toets is om die presiese syscall families te probeer wat default profiles gewoonlik blokkeer. As hulle skielik werk, het die container posture aansienlik verander:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Indien `CAP_SYS_ADMIN` of ’n ander sterk capability teenwoordig is, toets of seccomp die enigste ontbrekende versperring voor mount-gebaseerde misbruik is:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Op sommige teikens is die onmiddellike waarde nie ’n volledige escape nie, maar information gathering en die uitbreiding van die kernel-aanvalsoppervlak. Hierdie opdragte help bepaal of veral sensitiewe syscall-paaie bereikbaar is:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
As seccomp afwesig is en die container ook op ander maniere bevoorreg is, is dit wanneer dit sin maak om na die meer spesifieke breakout-tegnieke in die bestaande container-escape-bladsye te pivot.

### Volledige voorbeeld: seccomp was die enigste ding wat `unshare` geblokkeer het

Op baie targets is die praktiese gevolg van die verwydering van seccomp dat namespace-creation- of mount-syscalls skielik begin werk. As die container ook `CAP_SYS_ADMIN` het, kan die volgende volgorde moontlik word:
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
Op sy eie is dit nog nie ’n host escape nie, maar dit toon dat seccomp die versperring was wat mount-verwante exploitation verhinder het.

### Volledige voorbeeld: seccomp gedeaktiveer + cgroup v1 `release_agent`

As seccomp gedeaktiveer is en die container cgroup v1-hiërargieë kan mount, word die `release_agent`-tegniek uit die cgroups-afdeling bereikbaar:
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
Dit is nie ’n seccomp-only exploit nie. Die punt is dat sodra seccomp unconfined is, syscall-heavy breakout-kettings wat voorheen geblokkeer is, dalk presies soos geskryf kan begin werk.

## Kontroles

Die doel van hierdie kontroles is om vas te stel of seccomp enigsins aktief is, of `no_new_privs` dit vergesel, en of die runtime-konfigurasie wys dat seccomp uitdruklik gedeaktiveer is.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Wat hier interessant is:

- ’n Nie-nul `Seccomp`-waarde beteken dat filtering aktief is; `0` beteken gewoonlik dat geen seccomp-beskerming gebruik word nie.
- As die runtime-sekuriteitsopsies `seccomp=unconfined` insluit, het die workload een van sy nuttigste verdedigingstegnieke op syscall-vlak verloor.
- `NoNewPrivs` is nie self seccomp nie, maar die teenwoordigheid van albei dui gewoonlik op ’n noukeuriger hardening-houding as wanneer nie een van die twee teenwoordig is nie.

As ’n container reeds verdagte mounts, breë capabilities of gedeelde host-namespaces het, en seccomp ook `unconfined` is, moet daardie kombinasie as ’n belangrike escalation-saadteken beskou word. Die container is dalk steeds nie triviaal om te breek nie, maar die aantal kernel-entry points wat vir die aanvaller beskikbaar is, het skerp toegeneem.

## Runtime-verstekwaardes

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Gewoonlik by verstek geaktiveer | Gebruik Docker se ingeboude verstek-seccomp-profiel tensy dit oorskryf word | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Gewoonlik by verstek geaktiveer | Pas die runtime se verstek-seccomp-profiel toe tensy dit oorskryf word | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Nie by verstek gewaarborg nie** | As `securityContext.seccompProfile` nie gestel is nie, is die verstek `Unconfined`, tensy die kubelet `--seccomp-default` aktiveer; `RuntimeDefault` of `Localhost` moet andersins eksplisiet gestel word | `securityContext.seccompProfile.type: Unconfined`, seccomp ongestel laat op clusters sonder `seccompDefault`, `privileged: true` |
| containerd / CRI-O onder Kubernetes | Volg Kubernetes-node- en Pod-instellings | Die runtime-profiel word gebruik wanneer Kubernetes vir `RuntimeDefault` vra, of wanneer kubelet se seccomp-verstektoewysing geaktiveer is | Dieselfde as die Kubernetes-ry; direkte CRI/OCI-konfigurasie kan seccomp ook heeltemal weglaat |

Die Kubernetes-gedrag is die aspek wat operators die meeste verras. In baie clusters is seccomp steeds afwesig tensy die Pod dit aanvra of die kubelet opgestel is om standaard `RuntimeDefault` te gebruik.
{{#include ../../../../banners/hacktricks-training.md}}
