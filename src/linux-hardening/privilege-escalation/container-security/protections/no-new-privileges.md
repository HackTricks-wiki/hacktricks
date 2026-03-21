# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` is 'n kernel-verhardingsfunksie wat verhoed dat 'n proses meer voorregte kry oor `execve()`. Prakties gesproke, sodra die vlag gestel is, gee die uitvoering van 'n setuid binary, 'n setgid binary, of 'n file with Linux file capabilities nie ekstra voorregte bo wat die proses reeds gehad het nie. In containerized environments is dit belangrik omdat baie privilege-escalation chains staatmaak op die vind van 'n executable inside the image wat voorreg verander wanneer dit gelanseer word.

Van 'n verdedigingsoogpunt is `no_new_privs` nie 'n plaasvervanger vir namespaces, seccomp, of capability dropping nie. Dit is 'n versterkingslaag. Dit blokkeer 'n spesifieke klas van follow-up escalation nadat code execution reeds verkry is. Dit maak dit besonder waardevol in omgewings waar images helper binaries, package-manager artifacts, of legacy tools bevat wat andersins gevaarlik sou wees wanneer dit met 'n gedeeltelike kompromie gekombineer word.

## Operation

Die kernel-flag agter hierdie gedrag is `PR_SET_NO_NEW_PRIVS`. Sodra dit vir 'n proses gestel is, kan later `execve()`-oproepe nie privilege verhoog nie. Die belangrike detail is dat die proses steeds binaries kan uitvoer; dit kan net nie daardie binaries gebruik om 'n privilege boundary oor te steek wat die kernel andersins sou eerbiedig nie.

In Kubernetes-oriented omgewings, `allowPrivilegeEscalation: false` map na hierdie gedrag vir die container process. In Docker and Podman style runtimes word die ekwivalent gewoonlik eksplisiet geaktiveer deur 'n security option.

## Lab

Inspekteer die huidige prosesstatus:
```bash
grep NoNewPrivs /proc/self/status
```
Vergelyk dit met 'n container waar die runtime die flag aktiveer:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Op 'n geharde werklas moet die uitslag `NoNewPrivs: 1` aandui.

## Sekuriteitsimplikasie

As `no_new_privs` afwesig is, kan 'n voet in die container steeds opgegradeer word deur setuid-hulpies of binaries met file capabilities. As dit teenwoordig is, word daardie post-exec privilege-wisselings afgesny. Die effek is veral relevant in uitgebreide base images wat baie utilities insluit wat die toepassing oorspronklik nooit nodig gehad het nie.

## Verkeerde konfigurasies

Die algemeenste probleem is eenvoudig om die beheer nie te aktiveer in omgewings waar dit verenigbaar sou wees nie. In Kubernetes is dit dikwels 'n standaard operasionele fout om `allowPrivilegeEscalation` aangeskakel te laat. In Docker en Podman het die weglating van die relevante sekuriteitsopsie dieselfde gevolg. 'n Ander herhalende fout is om aan te neem dat omdat 'n container "not privileged" is, exec-time privilege-oorgange outomaties irrelevant is.

## Misbruik

As `no_new_privs` nie gestel is nie, is die eerste vraag of die image binaries bevat wat steeds privilege kan verhoog:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interessante resultate sluit in:

- `NoNewPrivs: 0`
- setuid-hulpe soos `su`, `mount`, `passwd`, of distribusie-spesifieke administrasie-instrumente
- binaries met file capabilities wat netwerk- of lêerstelsel-privilegies toeken

In 'n werklike assessering bewys hierdie bevindinge op sigself nie 'n werkende eskalasie nie, maar hulle identifiseer presies die binaries wat die moeite werd is om volgende te toets.

### Volledige voorbeeld: In-Container Privilege Escalation Through setuid

Hierdie beheer verhoed gewoonlik **in-container privilege escalation** eerder as om direk 'host escape' te bewerkstellig. As `NoNewPrivs` op `0` staan en 'n setuid-hulp bestaan, toets dit uitdruklik:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
As 'n bekende setuid binary teenwoordig en funksioneel is, probeer dit op 'n wyse te begin wat die privilegie-oorgang behou:
```bash
/bin/su -c id 2>/dev/null
```
Dit ontsnap op sigself nie uit die container nie, maar dit kan 'n lae-privilegie voet-in-die-deur binne die container omskakel na container-root, wat dikwels die voorvereiste word vir latere host escape deur mounts, runtime sockets, of kernel-facing interfaces.

## Checks

Die doel van hierdie kontroles is om vas te stel of exec-time privilege gain geblokkeer is, en of die image nog steeds helpers bevat wat saak sou maak as dit nie geblokkeer is nie.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Wat hier interessant is:

- `NoNewPrivs: 1` is gewoonlik die veiliger resultaat.
- `NoNewPrivs: 0` beteken setuid- en file-cap-gebaseerde eskalasie-paaie bly relevant.
- ’n minimale image met min of geen setuid/file-cap binaries gee 'n attacker minder post-exploitation opsies selfs wanneer `no_new_privs` ontbreek.

## Runtime Standaarde

| Runtime / platform | Standaardstatus | Standaardgedrag | Algemene handmatige verzwakking |
| --- | --- | --- | --- |
| Docker Engine | Nie standaard geaktiveer nie | Uitdruklik geaktiveer met `--security-opt no-new-privileges=true` | weglaat van die vlag, `--privileged` |
| Podman | Nie standaard geaktiveer nie | Uitdruklik geaktiveer met `--security-opt no-new-privileges` of ekwivalente sekuriteitskonfigurasie | weglaat van die opsie, `--privileged` |
| Kubernetes | Beheer deur workload-beleid | `allowPrivilegeEscalation: false` aktiveer die effek; baie workloads laat dit steeds geaktiveer | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Volg Kubernetes workload-instellings | Meestal geërf vanaf die Pod se sekuriteitskonteks | dieselfde as die Kubernetes-ry |

Hierdie beskerming is dikwels afwesig eenvoudig omdat niemand dit aangeskakel het nie, nie omdat die runtime ondersteuning daarvoor ontbreek nie.
