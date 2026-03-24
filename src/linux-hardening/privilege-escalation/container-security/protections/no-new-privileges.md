# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` is 'n kernel-harding funksie wat verhoed dat 'n proses meer voorregte kry deur `execve()`. In praktiese terme, sodra die vlag gestel is, gee die uitvoering van 'n setuid binary, 'n setgid binary, of 'n file met Linux file capabilities nie ekstra voorregte bo wat die proses reeds gehad het nie. In containerized omgewings is dit belangrik omdat baie privilege-escalation-kettings afhanklik is daarvan om 'n uitvoerbare binne die image te vind wat voorreg verander wanneer dit begin word.

Vanaf 'n verdedigende oogpunt is `no_new_privs` nie 'n plaasvervanger vir namespaces, seccomp, of capability dropping nie. Dit is 'n versterkingslaag. Dit blokkeer 'n spesifieke klas van daaropvolgende eskalasie nadat kode-uitvoering reeds verkry is. Dit maak dit veral waardevol in omgewings waar images helper binaries, package-manager artifacts, of legacy tools bevat wat andersins gevaarlik sou wees wanneer dit met 'n gedeeltelike kompromie gekombineer word.

## Werking

Die kernel-vlag agter hierdie gedrag is `PR_SET_NO_NEW_PRIVS`. Sodra dit vir 'n proses gestel is, kan latere `execve()`-aanroepe nie voorreg verhoog nie. Die belangrike detail is dat die proses steeds binaries kan uitvoer; dit kan net nie daardie binaries gebruik om 'n voorreggrens te oorsteek wat die kernel andersins sou eerbiedig nie.

In Kubernetes-gesentreerde omgewings kom `allowPrivilegeEscalation: false` ooreen met hierdie gedrag vir die container-proses. In Docker- en Podman-styl runtimes word die ekwivalent gewoonlik eksplisiet aangeskakel deur 'n sekuriteitsopsie.

## Laboratorium

Inspekteer die huidige prosesstatus:
```bash
grep NoNewPrivs /proc/self/status
```
Vergelyk dit met 'n container waar die runtime die flag aktiveer:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Op 'n geharde workload moet die resultaat `NoNewPrivs: 1` aandui.

## Sekuriteitsimpak

As `no_new_privs` ontbreek, kan 'n voet aan wal binne die container steeds opgegradeer word via setuid helpers of binaries met file capabilities. As dit teenwoordig is, word daardie post-exec privilege-wijzigings afgesny. Die effek is veral relevant in uitgebreide base images wat baie utilities saamlewer wat die toepassing oorspronklik nooit nodig gehad het nie.

## Miskonfigurasies

Die mees algemene probleem is bloot om die kontrole nie te aktiveer in omgewings waar dit versoenbaar sou wees nie. In Kubernetes is dit dikwels die standaard bedryfsfout om `allowPrivilegeEscalation` aan te laat. In Docker en Podman het die weglating van die relevante sekuriteitsopsie dieselfde uitwerking. 'n Ander herhalende fout is om aan te neem dat omdat 'n container "not privileged" is, exec-time privilege-oorgange outomaties irrelevant is.

## Misbruik

As `no_new_privs` nie gestel is nie, is die eerste vraag of die image binaries bevat wat steeds privileges kan verhoog:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interessante resultate sluit in:

- `NoNewPrivs: 0`
- setuid helpers soos `su`, `mount`, `passwd`, of distribusie-spesifieke admin-instrumente
- binaries met file capabilities wat network- of filesystem privileges verleen

In 'n werklike assessering bewys hierdie bevindinge op hul eie nie 'n werkende escalation nie, maar hulle identifiseer presies die binaries wat volgende die moeite werd is om te toets.

### Volledige voorbeeld: In-Container Privilege Escalation Through setuid

Hierdie beheer voorkom gewoonlik **in-container privilege escalation** eerder as 'n direkte host escape. As `NoNewPrivs` `0` is en 'n setuid helper bestaan, toets dit eksplisiet:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Indien 'n bekende setuid binary teenwoordig en funksioneel is, probeer om dit op 'n wyse te begin wat die privilege transition bewaar:
```bash
/bin/su -c id 2>/dev/null
```
Dit ontsnap nie op sigself uit die container nie, maar dit kan 'n low-privilege foothold binne die container omskakel na container-root, wat dikwels die voorvereiste word vir latere host escape deur mounts, runtime sockets, of kernel-facing interfaces.

## Checks

Die doel van hierdie checks is om vas te stel of exec-time privilege gain geblokkeer is en of die image steeds helpers bevat wat saak sou maak as dit nie is nie.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Wat hier interessant is:

- `NoNewPrivs: 1` is gewoonlik die veiliger resultaat.
- `NoNewPrivs: 0` beteken setuid- en file-cap-gebaseerde eskalasiepaaie bly relevant.
- 'n Minimale image met min of geen setuid/file-cap-binaries gee 'n aanvaller minder post-exploitation-opsies selfs wanneer `no_new_privs` ontbreek.

## Standaardinstellings vir runtime

| Runtime / platform | Standaardtoestand | Standaardgedrag | Algemene manuele verswakking |
| --- | --- | --- | --- |
| Docker Engine | Nie standaard geaktiveer nie | Uitdruklik aangeskakel met `--security-opt no-new-privileges=true` | weglating van die vlag, `--privileged` |
| Podman | Nie standaard geaktiveer nie | Uitdruklik aangeskakel met `--security-opt no-new-privileges` of ekwivalente sekuriteitskonfigurasie | weglating van die opsie, `--privileged` |
| Kubernetes | Beheer deur werkladingbeleid | `allowPrivilegeEscalation: false` skakel die effek in; baie werkladinge laat dit steeds aangeskakel | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Volg Kubernetes werklading-instellings | Gewoonlik geërf van die Pod security context | dieselfde as die Kubernetes-ry |

Hierdie beskerming is dikwels afwesig bloot omdat niemand dit aangeskakel het nie, nie omdat die runtime dit nie ondersteun nie.
{{#include ../../../../banners/hacktricks-training.md}}
