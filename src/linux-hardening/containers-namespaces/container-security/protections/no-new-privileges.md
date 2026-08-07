# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` is ’n kernel-hardening-funksie wat keer dat ’n proses meer privileges deur `execve()` verkry. In praktiese terme beteken dit dat, sodra die vlag gestel is, die uitvoer van ’n setuid binary, ’n setgid binary, of ’n lêer met Linux file capabilities nie addisionele privileges gee bo dit waartoe die proses reeds toegang gehad het nie. In containerized environments is dit belangrik omdat baie privilege-escalation chains daarop staatmaak om ’n executable binne die image te vind wat privileges verander wanneer dit launched word.

Vanuit ’n defensive point of view is `no_new_privs` nie ’n plaasvervanger vir namespaces, seccomp, of capability dropping nie. Dit is ’n reinforcement layer. Dit blokkeer ’n spesifieke klas van follow-up escalation nadat code execution reeds verkry is. Dit maak dit besonder waardevol in environments waar images helper binaries, package-manager artifacts, of legacy tools bevat wat andersins gevaarlik sou wees wanneer dit met partial compromise gekombineer word.

## Operation

Die kernel-vlag agter hierdie gedrag is `PR_SET_NO_NEW_PRIVS`. Sodra dit vir ’n proses gestel is, kan latere `execve()`-calls nie privileges verhoog nie. Die belangrike detail is dat die proses steeds binaries kan run; dit kan daardie binaries bloot nie gebruik om ’n privilege boundary oor te steek wat die kernel andersins sou honor nie.<sup>[[1]](#references)</sup>

Die kernel-gedrag word ook **inherited and irreversible**: sodra ’n task `no_new_privs` stel, word die bit oor `fork()`, `clone()`, en `execve()` geërf, en kan dit later nie unset word nie.<sup>[[1]](#references)</sup> Dit is nuttig in assessments omdat ’n enkele `NoNewPrivs: 1` op die container process gewoonlik beteken dat descendants ook in daardie mode behoort te bly, tensy jy na ’n heeltemal ander process tree kyk.

In Kubernetes-georiënteerde environments map `allowPrivilegeEscalation: false` na hierdie gedrag vir die container process.<sup>[[2]](#references)</sup> In Docker- en Podman-style runtimes word die ekwivalent gewoonlik eksplisiet deur middel van ’n security option enabled. Op die OCI-layer verskyn dieselfde konsep as `process.noNewPrivileges`.

## Important Nuances

`no_new_privs` blokkeer **exec-time** privilege gain, nie elke privilege change nie.<sup>[[1]](#references)</sup> In besonder:

- setuid- en setgid-transitions hou op werk oor `execve()`
- file capabilities word nie by die permitted set gevoeg op `execve()` nie
- LSMs soos AppArmor of SELinux relax nie constraints ná `execve()` nie
- reeds-held privilege bly steeds reeds-held privilege

Daardie laaste punt is operasioneel belangrik. As die proses reeds as root run, reeds ’n dangerous capability het, of reeds toegang tot ’n powerful runtime API of writable host mount het, neutraliseer die stel van `no_new_privs` nie daardie exposures nie. Dit verwyder slegs een algemene **next step** in ’n privilege-escalation chain.

Let ook daarop dat die vlag nie privilege changes blokkeer wat nie van `execve()` afhanklik is nie.<sup>[[1]](#references)</sup> Byvoorbeeld, ’n task wat reeds genoeg privileges het, kan steeds `setuid(2)` direk call of ’n privileged file descriptor oor ’n Unix socket ontvang. Daarom moet `no_new_privs` saam met [seccomp](seccomp.md), capability sets, en namespace exposure gelees word, eerder as ’n standalone antwoord.

## Lab

Inspekteer die huidige prosesstatus:
```bash
grep NoNewPrivs /proc/self/status
```
Vergelyk dit met 'n container waarin die runtime die flag aktiveer:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Op ’n hardened workload behoort die resultaat `NoNewPrivs: 1` te wys.

Jy kan ook die werklike effek teen ’n setuid-binary demonstreer:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Die punt van die vergelyking is nie dat `su` universeel uitbuitbaar is nie. Dit is dat dieselfde image baie verskillend kan optree, afhangend daarvan of `execve()` steeds toegelaat word om ’n privilege-grens oor te steek.

## Sekuriteitsimpak

As `no_new_privs` ontbreek, kan ’n foothold binne die container steeds deur setuid helpers of binaries met file capabilities opgegradeer word. As dit teenwoordig is, word daardie post-exec privilege-veranderinge afgesny. Die effek is veral relevant in breë base images wat baie utilities bevat wat die application in die eerste plek nooit nodig gehad het nie.

Daar is ook ’n belangrike seccomp-interaksie. Unprivileged tasks moet gewoonlik `no_new_privs` gestel hê voordat hulle ’n seccomp-filter in filter mode kan installeer.<sup>[[1]](#references)</sup> Dit is een rede waarom hardened containers dikwels beide `Seccomp` en `NoNewPrivs` saam as enabled wys. Vanuit ’n attacker-perspektief beteken die teenwoordigheid van albei gewoonlik dat die omgewing doelbewus eerder as per ongeluk gekonfigureer is.

## Misconfigurations

Die algemeenste probleem is eenvoudig om die control nie te enable in omgewings waar dit versoenbaar sou wees nie. In Kubernetes is dit dikwels die verstek-operasionele fout om `allowPrivilegeEscalation` enabled te laat. In Docker en Podman het die weglating van die relevante security option dieselfde effek. Nog ’n herhalende failure mode is die aanname dat exec-time privilege transitions outomaties irrelevant is omdat ’n container "not privileged" is.

’n Meer subtiele Kubernetes-valstrik is dat `allowPrivilegeEscalation: false` **nie** gehonoreer word soos mense verwag wanneer die container `privileged` is of wanneer dit `CAP_SYS_ADMIN` het nie. Die Kubernetes API dokumenteer dat `allowPrivilegeEscalation` in daardie gevalle effektief altyd true is.<sup>[[2]](#references)</sup> In die praktyk beteken dit dat die field as een signal in die finale posture behandel moet word, nie as ’n waarborg dat die runtime met `NoNewPrivs: 1` geëindig het nie.

## Misbruik

As `no_new_privs` nie gestel is nie, is die eerste vraag of die image binaries bevat wat steeds privilege kan verhoog:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interessante resultate sluit in:

- `NoNewPrivs: 0`
- setuid helpers soos `su`, `mount`, `passwd`, of distribution-specific admin tools
- binaries met file capabilities wat netwerk- of lêerstelselvoorregte verleen

In ’n werklike assessering bewys hierdie bevindings nie op hul eie dat ’n werkende eskalasie moontlik is nie, maar hulle identifiseer presies die binaries wat volgende getoets moet word.

In Kubernetes, verifieer ook dat die YAML-intensie met die kernel-werklikheid ooreenstem:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Interessante kombinasies sluit in:

- `allowPrivilegeEscalation: false` in die Pod-spesifikasie, maar `NoNewPrivs: 0` in die container
- `cap_sys_admin` is teenwoordig, wat die Kubernetes-veld veel minder betroubaar maak
- `Seccomp: 0` en `NoNewPrivs: 0`, wat gewoonlik op 'n wydverspreide verswakte runtime-houding eerder as 'n enkele geïsoleerde fout dui

### Volledige voorbeeld: In-container privilege escalation deur setuid

Hierdie beheer voorkom gewoonlik **in-container privilege escalation** eerder as direkte host escape. As `NoNewPrivs` `0` is en 'n setuid-helper bestaan, toets dit uitdruklik:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
As ’n bekende setuid-binêre lêer teenwoordig en funksioneel is, probeer om dit te begin op ’n manier wat die privilege transition behou:
```bash
/bin/su -c id 2>/dev/null
```
Dit ontsnap nie op sigself uit die container nie, maar dit kan ’n foothold met lae privileges binne die container in container-root omskakel, wat dikwels die voorvereiste word vir latere host-escape deur mounts, runtime sockets of kernel-facing interfaces.

## Kontroles

Die doel van hierdie kontroles is om vas te stel of privilege gain tydens exec geblokkeer word en of die image steeds helpers bevat wat saak sou maak indien dit nie die geval is nie.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Wat is hier interessant:

- `NoNewPrivs: 1` is gewoonlik die veiliger resultaat.
- `NoNewPrivs: 0` beteken dat eskalasiepaaie gebaseer op setuid en file-cap steeds relevant bly.
- `NoNewPrivs: 1` plus `Seccomp: 2` is ’n algemene teken van ’n meer doelbewuste hardening-houding.
- ’n Kubernetes-manifes wat `allowPrivilegeEscalation: false` spesifiseer, is nuttig, maar die kernel-status is die grondwaarheid.
- ’n Minimale image met min of geen setuid/file-cap-binaries gee ’n aanvaller minder post-exploitation-opsies, selfs wanneer `no_new_privs` ontbreek.

## Runtime-verstekinstellings

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Nie by verstek geaktiveer nie | Word eksplisiet geaktiveer met `--security-opt no-new-privileges=true`; ’n daemon-wye verstekinstelling bestaan ook via `dockerd --no-new-privileges` | weglating van die vlag, `--privileged` |
| Podman | Nie by verstek geaktiveer nie | Word eksplisiet geaktiveer met `--security-opt no-new-privileges` of ’n ekwivalente security-konfigurasie | weglating van die opsie, `--privileged` |
| Kubernetes | Word deur workload-beleid beheer | `allowPrivilegeEscalation: false` versoek die effek, maar `privileged: true` en `CAP_SYS_ADMIN` hou dit effektief waar | `allowPrivilegeEscalation: true`, `privileged: true`, byvoeging van `CAP_SYS_ADMIN` |
| containerd / CRI-O onder Kubernetes | Volg Kubernetes-workload-instellings / OCI `process.noNewPrivileges` | Word gewoonlik van die Pod-security-konteks geërf en na die OCI-runtime-konfigurasie vertaal | dieselfde as die Kubernetes-ry |

Hierdie beskerming ontbreek dikwels eenvoudig omdat niemand dit geaktiveer het nie, nie omdat die runtime dit nie ondersteun nie.

## Verwysings

- [1] [Linux-kerneldokumentasie: No New Privileges-vlag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [2] [Kubernetes: Stel ’n security-konteks vir ’n Pod of Container op](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
