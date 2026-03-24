# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

**seccomp** is die meganisme wat die kernel toelaat om 'n filter toe te pas op die syscalls wat 'n proses mag aanroep. In containerized omgewings word seccomp gewoonlik in filter-modus gebruik sodat die proses nie net vaagweg as "restricted" gemerk word nie, maar onderworpe is aan 'n konkrete syscall-beleid. Dit maak saak omdat baie container breakouts vereis om baie spesifieke kernel interfaces te bereik. As die proses nie daarin slaag om die relevante syscalls aan te roep nie, verdwyn 'n groot klas aanvalle voordat enige namespace of capability nuans selfs relevant word.

Die sleutel-mentale model is eenvoudig: namespaces bepaal **wat die proses kan sien**, capabilities bepaal **watter geprivilegieerde aksies die proses naamlik toegelaat word om te probeer**, en seccomp bepaal **of die kernel selfs die syscall insetpunt vir die poging sal aanvaar**. Dit is hoekom seccomp dikwels aanvalle voorkom wat andersins op grond van capabilities alleen moontlik sou lyk.

## Sekuriteitsimpak

Baie gevaarlike kernel-oppervlak is slegs bereikbaar deur 'n relatief klein stel syscalls. Voorbeelde wat herhaaldelik saak maak in container hardening sluit in `mount`, `unshare`, `clone` of `clone3` met spesifieke vlae, `bpf`, `ptrace`, `keyctl`, en `perf_event_open`. 'n Aanvaller wat daardie syscalls kan bereik, mag in staat wees om nuwe namespaces te skep, kernel-subsisteme te manipuleer, of te interakteer met aanvaloppervlak wat 'n normale application container glad nie nodig het nie.

Hierom is default runtime seccomp profiles so belangrik. Hulle is nie net "extra defense" nie. In baie omgewings is hulle die verskil tussen 'n container wat 'n breë gedeelte van kernel-funksionaliteit kan uit oefen en een wat beperk is tot 'n syscall-oppervlak nader aan wat die toepassing werklik nodig het.

## Modusse en Filterkonstruksie

seccomp het histories 'n strict mode gehad waarin net 'n klein stel syscalls beskikbaar gebly het, maar die modus wat relevant is vir moderne container runtimes is seccomp filter mode, dikwels genoem **seccomp-bpf**. In hierdie model evalueer die kernel 'n filterprogram wat besluit of 'n syscall toegelaat, geweier met 'n errno, getrap, aangeteken, of die proses beëindig moet word. Container runtimes gebruik hierdie meganisme omdat dit uitdrukkend genoeg is om breë klasse gevaarlike syscalls te blokkeer terwyl normale toepassinggedrag steeds toegelaat word.

Twee laevlakvoorbeelde is nuttig omdat hulle die meganisme konkreet maak in plaas van magies. Strict mode demonstreer die ou "only a minimal syscall set survives" model:
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

'n libseccomp filter-voorbeeld wys die moderne beleidsmodel duideliker:
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
Hierdie tipe beleid is wat die meeste lesers sal voorstel wanneer hulle aan runtime seccomp profiles dink.

## Laboratorium

'n eenvoudige manier om te bevestig dat seccomp aktief is in 'n container is:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Jy kan ook 'n operasie probeer wat standaardprofiele gewoonlik beperk:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
As die container onder 'n normale standaard seccomp-profiel loop, word `unshare`-styl operasies dikwels geblokkeer. Dit is 'n nuttige demonstrasie omdat dit wys dat selfs as die userspace tool in die image bestaan, die kernel-pad wat dit benodig steeds onbeskikbaar kan wees.
As die container onder 'n normale standaard seccomp-profiel loop, word `unshare`-styl operasies dikwels geblokkeer selfs wanneer die userspace tool in die image bestaan.

Om die prosesstatus meer algemeen te ondersoek, voer uit:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Runtime gebruik

Docker ondersteun beide standaard- en gekustomiseerde seccomp-profiele en laat administrateurs toe om dit uit te skakel met `--security-opt seccomp=unconfined`. Podman het soortgelyke ondersteuning en kombineer dikwels seccomp met rootless-uitvoering in ’n baie sinvolle standaardhouding. Kubernetes maak seccomp beskikbaar deur werkbelastingkonfigurasie, waar `RuntimeDefault` gewoonlik die redelike basislyn is en `Unconfined` as ’n uitsondering beskou moet word wat regverdiging vereis eerder as ’n geriefskakelaar.

In containerd- en CRI-O-gebaseerde omgewings is die presiese pad meer gelaagd, maar die beginsel is dieselfde: die hoërvlak engine of orkestreerder besluit wat moet gebeur, en die runtime installeer uiteindelik die resulterende seccomp-beleid vir die containerproses. Die uitkoms hang steeds af van die finale runtime-konfigurasie wat die kern bereik.

### Pasgemaakte beleid voorbeeld

Docker en soortgelyke engines kan ’n pasgemaakte seccomp-profiel vanaf JSON laai. ’n Minimale voorbeeld wat `chmod` weier terwyl dit alles anders toelaat, lyk soos volg:
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

## Konfigurasiefoute

Die beslisste fout is om seccomp op **unconfined** te stel omdat 'n toepassing onder die verstekbeleid misluk het. Dit is algemeen tydens troubleshooting en baie gevaarlik as 'n permanente oplossing. Sodra die filter weg is, word baie syscall-gebaseerde breakout primitives weer bereikbaar, veral wanneer kragtige capabilities of host namespace sharing ook teenwoordig is.

Nog 'n algemene probleem is die gebruik van 'n **custom permissive profile** wat van 'n blog of interne workaround gekopieer is sonder noukeurige hersiening. Spanne behou soms byna alle gevaarlike syscalls bloot omdat die profiel rondom "stop the app from breaking" gebou is in plaas van "grant only what the app actually needs". 'n Derde misverstand is om aan te neem dat seccomp minder belangrik is vir non-root containers. In werklikheid bly baie kernel attack surface relevant selfs wanneer die proses nie UID 0 is nie.

## Misbruik

As seccomp afwesig of ernstig verzwak is, kan 'n aanvaller moontlik namespace-creation syscalls aanroep, die bereikbare kernel attack surface uitbrei deur `bpf` of `perf_event_open`, `keyctl` misbruik, of daardie syscall-paaie kombineer met gevaarlike capabilities soos `CAP_SYS_ADMIN`. In baie werklike aanvalle is seccomp nie die enigste ontbrekende beheer nie, maar die afwesigheid daarvan verkort die exploit path dramaties omdat dit een van die min verdedigings verwyder wat 'n riskante syscall kan stop voordat die res van die privilege model selfs in werking tree.

Die mees bruikbare praktiese toets is om presies daardie syscall-families te probeer wat default profiles gewoonlik blokkeer. As hulle skielik werk, het die container-houding baie verander:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
As `CAP_SYS_ADMIN` of `n ander sterk capability` teenwoordig is, toets of seccomp die enigste ontbrekende hindernis is voordat mount-gebaseerde misbruik kan plaasvind:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Op sommige teikens is die onmiddellike doel nie 'n volledige ontsnapping nie, maar eerder inligtingsinsameling en uitbreiding van die kern se aanvalsoppervlak. Hierdie opdragte help bepaal of veral sensitiewe syscall paths toeganklik is:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Indien seccomp afwesig is en die container ook op ander maniere bevoorreg is, is dit wanneer dit sinvol is om na die meer spesifieke breakout techniques oor te skakel wat reeds in die legacy container-escape pages gedokumenteer is.

### Volledige voorbeeld: seccomp was die enigste ding wat `unshare` blokkeer

Op baie teikens is die praktiese uitwerking van die verwydering van seccomp dat namespace-creation of mount syscalls skielik begin werk. As die container ook `CAP_SYS_ADMIN` het, kan die volgende volgorde moontlik word:
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
Op sigself is dit nog nie 'n host escape nie, maar dit demonstreer dat seccomp die versperring was wat mount-related exploitation verhinder het.

### Volledige Voorbeeld: seccomp Disabled + cgroup v1 `release_agent`

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

Die doel van hierdie kontroles is om vas te stel of seccomp wel aktief is, of `no_new_privs` daarmee vergesel word, en of die runtime-konfigurasie toon dat seccomp eksplisiet gedeaktiveer is.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Wat interessant is hier:

- 'n Nie-nul `Seccomp`-waarde beteken filtering is aktief; `0` beteken gewoonlik geen seccomp-beskerming nie.
- As die runtime-sekuriteitsopsies `seccomp=unconfined` insluit, het die workload een van sy nuttigste syscall-vlak verdedigings verloor.
- `NoNewPrivs` is nie seccomp self nie, maar om albei saam te sien dui gewoonlik op 'n meer versigtige hardening-houding as om geen van beide te sien nie.

As 'n container reeds verdagte mounts, broad capabilities, of shared host namespaces het, en seccomp ook unconfined is, moet daardie kombinasie as 'n groot eskalasie-sein beskou word. Die container is dalk nog nie maklik om te breek nie, maar die aantal kernel-toegangspunte beskikbaar vir die aanvaller het skerp toegeneem.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Gewoonlik standaard aangeskakel | Gebruik Docker se ingeboude standaard seccomp-profile tensy dit oorskryf word | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Gewoonlik standaard aangeskakel | Pas die runtime se standaard seccomp-profile toe tensy oorskryf | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Nie deur verstek gewaarborg nie** | As `securityContext.seccompProfile` nie gestel is nie, is die verstek `Unconfined` tensy die kubelet `--seccomp-default` aktiveer; `RuntimeDefault` of `Localhost` moet andersins uitdruklik gestel word | `securityContext.seccompProfile.type: Unconfined`, seccomp ongestel laat op clusters sonder `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Volg Kubernetes node- en Pod-instellings | Runtime-profiel word gebruik wanneer Kubernetes vir `RuntimeDefault` vra of wanneer kubelet seccomp-verstekstelling geaktiveer is | Dieselfde as die Kubernetes-ry; direkte CRI/OCI-konfigurasie kan ook seccomp heeltemal weglaat |

Die Kubernetes-gedrag is die een wat operateurs die meeste verras. In baie clusters is seccomp steeds afwesig, tensy die Pod dit versoek of die kubelet geconfigureer is om na `RuntimeDefault` te verstek.
{{#include ../../../../banners/hacktricks-training.md}}
