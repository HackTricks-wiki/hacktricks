# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` is ’n kernel-hardening-funksie wat verhoed dat ’n proses meer voorregte deur `execve()` verkry. In praktiese terme beteken dit dat, sodra die vlag gestel is, die uitvoering van ’n setuid-binary, ’n setgid-binary of ’n lêer met Linux file capabilities geen bykomende voorregte verleen bo dit waartoe die proses reeds toegang gehad het nie. In containerized environments is dit belangrik omdat baie privilege-escalation chains daarop staatmaak om ’n executable binne die image te vind wat voorregte verander wanneer dit geloods word.

Vanuit ’n defensive point of view is `no_new_privs` nie ’n plaasvervanger vir namespaces, seccomp of capability dropping nie. Dit is ’n versterkingslaag. Dit blokkeer ’n spesifieke klas van opvolgende escalation nadat code execution reeds verkry is. Dit maak dit besonder waardevol in environments waar images helper binaries, package-manager artifacts of legacy tools bevat wat andersins gevaarlik sou wees wanneer dit met partial compromise gekombineer word.

## Werking

Die kernel-vlag agter hierdie gedrag is `PR_SET_NO_NEW_PRIVS`. Sodra dit vir ’n proses gestel is, kan latere `execve()`-calls nie voorregte verhoog nie. Die belangrike detail is dat die proses steeds binaries kan uitvoer; dit kan slegs nie daardie binaries gebruik om ’n privilege boundary oor te steek wat die kernel andersins sou eerbiedig nie.

Die kernel-gedrag word ook **geërf en is onomkeerbaar**: sodra ’n task `no_new_privs` stel, word die bit oor `fork()`, `clone()` en `execve()` geërf, en kan dit later nie afgeskakel word nie. Dit is nuttig in assessments omdat ’n enkele `NoNewPrivs: 1` op die container-proses gewoonlik beteken dat descendants ook in daardie modus behoort te bly, tensy jy na ’n heeltemal ander process tree kyk.

In Kubernetes-georiënteerde environments karteer `allowPrivilegeEscalation: false` na hierdie gedrag vir die container-proses. In Docker- en Podman-styl runtimes word die ekwivalent gewoonlik uitdruklik deur ’n security option geaktiveer. Op die OCI-laag verskyn dieselfde konsep as `process.noNewPrivileges`.

## Belangrike Nuanses

`no_new_privs` blokkeer **voorregverkryging tydens exec**, nie elke voorregverandering nie. Spesifiek:

- setuid- en setgid-oorgange hou op om oor `execve()` te werk
- file capabilities word nie tydens `execve()` by die permitted set gevoeg nie
- LSMs soos AppArmor of SELinux verslap nie constraints ná `execve()` nie
- voorregte wat reeds gehou word, bly steeds reeds-gehoude voorregte

Daardie laaste punt is operasioneel belangrik. As die proses reeds as root loop, reeds ’n gevaarlike capability het, of reeds toegang tot ’n kragtige runtime API of writable host mount het, neutraliseer die instelling van `no_new_privs` nie daardie exposures nie. Dit verwyder slegs een algemene **volgende stap** in ’n privilege-escalation chain.

Let ook daarop dat die vlag nie privilege changes blokkeer wat nie van `execve()` afhanklik is nie. Byvoorbeeld, ’n task wat reeds genoeg voorregte het, kan steeds `setuid(2)` direk call of ’n privileged file descriptor oor ’n Unix-socket ontvang. Daarom moet `no_new_privs` saam met [seccomp](seccomp.md), capability sets en namespace exposure beoordeel word, eerder as as ’n selfstandige antwoord.

## Lab

Inspekteer die huidige process state:
```bash
grep NoNewPrivs /proc/self/status
```
Vergelyk dit met ’n container waar die runtime die flag aktiveer:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Op ’n verhardde workload behoort die resultaat `NoNewPrivs: 1` te wys.

Jy kan ook die werklike effek teenoor ’n setuid binary demonstreer:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Die punt van die vergelyking is nie dat `su` universeel exploitable is nie. Dit is dat dieselfde image baie verskillend kan optree, afhangend daarvan of `execve()` steeds toegelaat word om ’n privilege boundary oor te steek.

## Sekuriteitsimpak

As `no_new_privs` ontbreek, kan ’n foothold binne die container steeds opgegradeer word deur setuid helpers of binaries met file capabilities. As dit teenwoordig is, word daardie post-exec privilege changes afgesny. Die effek is veral relevant in breë base images wat baie utilities insluit wat die application nooit nodig gehad het nie.

Daar is ook ’n belangrike seccomp-interaksie. Unprivileged tasks moet gewoonlik `no_new_privs` gestel hê voordat hulle ’n seccomp filter in filter mode kan installeer. Dit is een rede waarom hardened containers dikwels beide `Seccomp` en `NoNewPrivs` enabled wys. Vanuit ’n attacker-perspektief beteken die teenwoordigheid van albei gewoonlik dat die environment doelbewus eerder as per ongeluk gekonfigureer is.

## Misconfigurations

Die mees algemene probleem is eenvoudig om die control nie te enable in environments waar dit compatible sou wees nie. In Kubernetes is dit dikwels die verstek-operasionele fout om `allowPrivilegeEscalation` enabled te laat. In Docker en Podman het die weglating van die relevante security option dieselfde effek. Nog ’n herhalende failure mode is die aanname dat exec-time privilege transitions outomaties irrelevant is omdat ’n container “not privileged” is.

’n Meer subtiele Kubernetes-pitfall is dat `allowPrivilegeEscalation: false` **nie** op die verwagte manier honored word wanneer die container `privileged` is of wanneer dit `CAP_SYS_ADMIN` het nie. Die Kubernetes API dokumenteer dat `allowPrivilegeEscalation` in daardie gevalle effektief altyd true is. In die praktyk beteken dit dat die field as een signal in die finale posture behandel moet word, nie as ’n guarantee dat die runtime met `NoNewPrivs: 1` geëindig het nie.

## Abuse

As `no_new_privs` nie gestel is nie, is die eerste vraag of die image binaries bevat wat steeds privilege kan verhoog:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interessante resultate sluit in:

- `NoNewPrivs: 0`
- setuid helpers soos `su`, `mount`, `passwd`, of distribution-specific admin tools
- binaries met file capabilities wat network- of filesystem-voorregte verleen

In ’n werklike assessment bewys hierdie bevindings nie op hul eie dat ’n werkende escalation moontlik is nie, maar hulle identifiseer presies die binaries wat volgende getoets moet word.

In Kubernetes, verifieer ook dat die YAML-intensie met die kernel-werklikheid ooreenstem:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Interessante kombinasies sluit in:

- `allowPrivilegeEscalation: false` in die Pod spec maar `NoNewPrivs: 0` in die container
- `cap_sys_admin` teenwoordig, wat die Kubernetes-veld aansienlik minder betroubaar maak
- `Seccomp: 0` en `NoNewPrivs: 0`, wat gewoonlik op ’n wydverspreide verswakte runtime-postuur dui eerder as op ’n enkele geïsoleerde fout

### Volledige Voorbeeld: In-Container Privilege Escalation Deur setuid

Hierdie beheermaatreël voorkom gewoonlik **in-container privilege escalation** eerder as host escape direk. As `NoNewPrivs` `0` is en ’n setuid-helper bestaan, toets dit eksplisiet:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
As ’n bekende setuid-binêre lêer teenwoordig en funksioneel is, probeer om dit te begin op ’n manier wat die voorreg-oorgang behou:
```bash
/bin/su -c id 2>/dev/null
```
Dit ontsnap nie op sigself uit die container nie, maar dit kan ’n foothold met lae privileges binne die container omskep in container-root, wat dikwels ’n voorvereiste word vir ’n latere host-escape deur mounts, runtime-sockets of kernel-facing interfaces.

## Checks

Die doel van hierdie checks is om vas te stel of privilege gain tydens exec geblokkeer word en of die image steeds helpers bevat wat van belang sou wees indien dit nie die geval is nie.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Wat hier interessant is:

- `NoNewPrivs: 1` is gewoonlik die veiliger resultaat.
- `NoNewPrivs: 0` beteken dat setuid- en file-cap-gebaseerde escalation paths steeds relevant bly.
- `NoNewPrivs: 1` plus `Seccomp: 2` is ’n algemene teken van ’n meer doelbewuste hardening posture.
- ’n Kubernetes-manifes wat `allowPrivilegeEscalation: false` bevat, is nuttig, maar die kernel-status is die ground truth.
- ’n Minimale image met min of geen setuid/file-cap binaries gee ’n aanvaller minder post-exploitation-opsies, selfs wanneer `no_new_privs` ontbreek.

## Runtime-standaardwaardes

| Runtime / platform | Standaardtoestand | Standaardgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Nie by verstek geaktiveer nie | Eksplisiet geaktiveer met `--security-opt no-new-privileges=true`; ’n daemon-wye verstek bestaan ook via `dockerd --no-new-privileges` | die vlag weglos, `--privileged` |
| Podman | Nie by verstek geaktiveer nie | Eksplisiet geaktiveer met `--security-opt no-new-privileges` of ekwivalente security configuration | die opsie weglos, `--privileged` |
| Kubernetes | Deur workload policy beheer | `allowPrivilegeEscalation: false` versoek die effek, maar `privileged: true` en `CAP_SYS_ADMIN` hou dit effektief waar | `allowPrivilegeEscalation: true`, `privileged: true`, `CAP_SYS_ADMIN` byvoeg |
| containerd / CRI-O onder Kubernetes | Volg Kubernetes workload settings / OCI `process.noNewPrivileges` | Word gewoonlik van die Pod security context geërf en na OCI runtime configuration vertaal | dieselfde as die Kubernetes-ry |

Hierdie protection ontbreek dikwels bloot omdat niemand dit aangeskakel het nie, nie omdat die runtime nie ondersteuning daarvoor het nie.

## Verwysings

- [Linux-kern-dokumentasie: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
