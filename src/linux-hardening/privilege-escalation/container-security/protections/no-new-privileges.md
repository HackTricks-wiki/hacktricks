# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` is 'n kernel hardening feature wat voorkom dat 'n proses meer privilege oor `execve()` verkry. In praktiese terme, sodra die vlag gestel is, gee die uitvoer van 'n setuid binary, 'n setgid binary, of 'n file met Linux file capabilities nie ekstra privilege buite wat die proses reeds gehad het nie. In containerized environments is dit belangrik omdat baie privilege-escalation chains daarop steun om 'n executable binne die image te vind wat privilege verander wanneer dit geloods word.

Vanuit 'n defensiewe oogpunt is `no_new_privs` nie 'n plaasvervanger vir namespaces, seccomp, of capability dropping nie. Dit is 'n versterkingslaag. Dit blokkeer 'n spesifieke klas van opvolg-escalation nadat code execution reeds verkry is. Dit maak dit veral waardevol in omgewings waar images helper binaries, package-manager artifacts, of legacy tools bevat wat andersins gevaarlik sou wees wanneer dit saam met partial compromise gekombineer word.

## Operation

Die kernel-vlag agter hierdie gedrag is `PR_SET_NO_NEW_PRIVS`. Sodra dit vir 'n proses gestel is, kan latere `execve()` calls nie privilege verhoog nie. Die belangrike detail is dat die proses steeds binaries kan run; dit kan eenvoudig nie daardie binaries gebruik om 'n privilege boundary te kruis wat die kernel andersins sou erken nie.

Die kernel-gedrag is ook **geërf en onomkeerbaar**: sodra 'n task `no_new_privs` stel, word die bit oor `fork()`, `clone()`, en `execve()` geërf, en kan dit later nie uitgeklaar word nie. Dit is nuttig in assessments omdat 'n enkele `NoNewPrivs: 1` op die container-proses gewoonlik beteken dat afstammelinge ook in daardie modus moet bly, tensy jy na 'n heeltemal ander process tree kyk.

In Kubernetes-georiënteerde omgewings map `allowPrivilegeEscalation: false` na hierdie gedrag vir die container-proses. In Docker- en Podman-styl runtimes word die ekwivalent gewoonlik eksplisiet deur 'n security option geaktiveer. Op die OCI-laag verskyn dieselfde konsep as `process.noNewPrivileges`.

## Important Nuances

`no_new_privs` blokkeer **exec-time** privilege gain, nie elke privilege change nie. Veral:

- setuid- en setgid-oorgange hou op werk oor `execve()`
- file capabilities voeg nie by die permitted set op `execve()` nie
- LSMs soos AppArmor of SELinux verslap nie constraints ná `execve()` nie
- reeds-besitte privilege bly steeds reeds-besitte privilege

Daardie laaste punt maak operasioneel saak. As die proses reeds as root loop, reeds 'n gevaarlike capability het, of reeds toegang het tot 'n kragtige runtime API of writable host mount, neutraliseer die stel van `no_new_privs` nie daardie exposures nie. Dit verwyder net een algemene **next step** in 'n privilege-escalation chain.

Let ook daarop dat die vlag nie privilege changes blokkeer wat nie van `execve()` afhang nie. Byvoorbeeld, 'n task wat reeds genoegsaam geprivilegieer is, kan steeds `setuid(2)` direk aanroep of 'n geprivilegieerde file descriptor oor 'n Unix socket ontvang. Daarom moet `no_new_privs` saam met [seccomp](seccomp.md), capability sets, en namespace exposure gelees word eerder as as 'n selfstandige antwoord.

## Lab

Inspect the current process state:
```bash
grep NoNewPrivs /proc/self/status
```
Vergelyk dit met ’n container waar die runtime die vlag aktiveer:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Op ’n geharde workload, moet die resultaat `NoNewPrivs: 1` wys.

Jy kan ook die werklike effek teen ’n setuid binary demonstreer:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Die punt van die vergelyking is nie dat `su` universeel uitbuitbaar is nie. Dit is dat dieselfde image baie anders kan optree, afhangend van of `execve()` nog toegelaat word om ’n privilege boundary oor te steek.

## Security Impact

As `no_new_privs` afwesig is, kan ’n foothold binne die container steeds opgegradeer word deur setuid helpers of binaries met file capabilities. As dit teenwoordig is, word daardie post-exec privilege changes afgesny. Die effek is veral relevant in breë base images wat baie utilities saambring wat die application glad nie van die begin af nodig gehad het nie.

Daar is ook ’n belangrike seccomp-interaksie. Unprivileged tasks moet gewoonlik `no_new_privs` ingestel hê voordat hulle ’n seccomp-filter in filter mode kan installeer. Dit is een rede waarom geharde containers dikwels beide `Seccomp` en `NoNewPrivs` saam geaktiveer toon. Vanuit ’n attacker-perspektief beteken die sien van albei gewoonlik dat die environment doelbewus gekonfigureer is eerder as per ongeluk.

## Misconfigurations

Die mees algemene probleem is eenvoudig om nie die control te aktiveer in environments waar dit versoenbaar sou wees nie. In Kubernetes is dit dikwels die verstek operasionele fout om `allowPrivilegeEscalation` geaktiveer te laat. In Docker en Podman het die weglaat van die relevante security option dieselfde effek. Nog ’n herhalende failure mode is om aan te neem dat, omdat ’n container "not privileged" is, exec-time privilege transitions outomaties irrelevant is.

’n Meer subtiele Kubernetes-pitfall is dat `allowPrivilegeEscalation: false` **nie** toegepas word soos mense verwag wanneer die container `privileged` is of wanneer dit `CAP_SYS_ADMIN` het nie. Die Kubernetes API dokumenteer dat `allowPrivilegeEscalation` in daardie gevalle effektief altyd true is. In die praktyk beteken dit dat die veld as een sein in die finale posture behandel moet word, nie as ’n waarborg dat die runtime uiteindelik `NoNewPrivs: 1` gehad het nie.

## Abuse

As `no_new_privs` nie ingestel is nie, is die eerste vraag of die image binaries bevat wat steeds privilege kan verhoog:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interessante resultate sluit in:

- `NoNewPrivs: 0`
- setuid helpers soos `su`, `mount`, `passwd`, of verspreidingspesifieke admin tools
- binaries met file capabilities wat netwerk- of filesystem-privileges verleen

In `Kubernetes`, verifieer ook dat die YAML-intensie ooreenstem met die kernel-realiteit:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Interessante kombinasies sluit in:

- `allowPrivilegeEscalation: false` in die Pod-spec maar `NoNewPrivs: 0` in die container
- `cap_sys_admin` teenwoordig, wat die Kubernetes-veld baie minder betroubaar maak
- `Seccomp: 0` en `NoNewPrivs: 0`, wat gewoonlik dui op ’n breed verswakte runtime-postuur eerder as ’n enkele geïsoleerde fout

### Full Example: In-Container Privilege Escalation Through setuid

Hierdie control voorkom gewoonlik **in-container privilege escalation** eerder as host escape direk. As `NoNewPrivs` `0` is en ’n setuid-helper bestaan, toets dit eksplisiet:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
As 'n bekende setuid binary teenwoordig en funksioneel is, probeer dit op 'n manier te lanseer wat die privilege transition behou:
```bash
/bin/su -c id 2>/dev/null
```
Dit ontsnap nie op sigself uit die container nie, maar dit kan ’n lae-voorreg-vastrapplek binne die container omskakel na container-root, wat dikwels die voorvereiste word vir latere host escape deur mounts, runtime sockets, of kernel-facing interfaces.

## Checks

Die doel van hierdie checks is om vas te stel of exec-time privilege gain geblokkeer is en of die image steeds helpers bevat wat saak sal maak indien dit nie is nie.
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
- `NoNewPrivs: 0` beteken setuid- en file-cap-verhogingspaaie bly relevant.
- `NoNewPrivs: 1` plus `Seccomp: 2` is ’n algemene teken van ’n meer doelbewuste hardening-posisie.
- ’n Kubernetes manifest wat `allowPrivilegeEscalation: false` sê, is nuttig, maar die kernel-status is die bron van waarheid.
- ’n Minimale image met min of geen setuid/file-cap binaries gee ’n aanvaller minder post-exploitation opsies, selfs wanneer `no_new_privs` ontbreek.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Nie by verstek geaktiveer nie | Eksplisiet geaktiveer met `--security-opt no-new-privileges=true`; daemon-wye verstek bestaan ook via `dockerd --no-new-privileges` | weglating van die vlag, `--privileged` |
| Podman | Nie by verstek geaktiveer nie | Eksplisiet geaktiveer met `--security-opt no-new-privileges` of ekwivalente security configuration | weglating van die opsie, `--privileged` |
| Kubernetes | Beheer deur workload-beleid | `allowPrivilegeEscalation: false` versoek die effek, maar `privileged: true` en `CAP_SYS_ADMIN` hou dit effektief waar | `allowPrivilegeEscalation: true`, `privileged: true`, voeg `CAP_SYS_ADMIN` by |
| containerd / CRI-O under Kubernetes | Volg Kubernetes workload settings / OCI `process.noNewPrivileges` | Gewoonlik geërf van die Pod security context en vertaal na OCI runtime config | dieselfde as Kubernetes-ry |

Hierdie beskerming ontbreek dikwels eenvoudig omdat niemand dit aangeskakel het nie, nie omdat die runtime nie ondersteuning daarvoor het nie.

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
