# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` is 'n kernel-hardening-funksie wat voorkom dat 'n proses meer privilege kry via `execve()`. In praktiese terme, sodra die vlag gestel is, gee die uitvoering van 'n setuid binary, 'n setgid binary, of 'n lêer met Linux file capabilities geen ekstra privilege bo wat die proses reeds gehad het nie. In gekontaineriseerde omgewings is dit belangrik omdat baie privilege-escalation kettings staatmaak op die vind van 'n executable binne die image wat privilegies verander wanneer dit gelanseer word.

Van 'n verdedigingsperspektief is `no_new_privs` nie 'n plaasvervanger vir namespaces, seccomp, of capability dropping nie. Dit is 'n versterkingslaag. Dit blokkeer 'n spesifieke klas van follow-up privilege-escalation nadat code-uitvoering reeds verkry is. Dit maak dit veral waardevol in omgewings waar images helper binaries, package-manager artifacts, of legacy tools bevat wat andersins gevaarlik sou wees wanneer dit met gedeeltelike kompromittering gekombineer word.

## Werking

Die kernel-vlag agter hierdie gedrag is `PR_SET_NO_NEW_PRIVS`. Sodra dit vir 'n proses gestel is, kan later `execve()`-oproepe nie privilege verhoog nie. Die belangrike detail is dat die proses steeds binaries kan uitvoer; dit kan net nie daardie binaries gebruik om 'n privilege-grens te oorskry wat die kernel andersins sou eer nie.

In Kubernetes-georiënteerde omgewings stem `allowPrivilegeEscalation: false` ooreen met hierdie gedrag vir die container-proses. In Docker- en Podman-styl runtimes word die ekwivalent gewoonlik eksplisiet geaktiveer deur 'n sekuriteitsopsie.

## Lab

Inspekteer die huidige prosesstaat:
```bash
grep NoNewPrivs /proc/self/status
```
Vergelyk dit met 'n container waarin die runtime die flag inskakel:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Op 'n geharde werklading behoort die resultaat `NoNewPrivs: 1` te wys.

## Sekuriteitsimpak

As `no_new_privs` afwesig is, kan 'n voet aan wal binne die container steeds opgegradeer word deur setuid helpers of binaries met file capabilities. As dit teenwoordig is, word daardie post-exec privilege-wijzigings afgesny. Die effek is veral relevant in breë base images wat baie utilities insluit wat die toepassing oorspronklik nooit benodig het nie.

## Konfigurasiefoute

Die mees algemene probleem is eenvoudig om die kontrole nie te aktiveer in omgewings waar dit versoenbaar sou wees nie. In Kubernetes is dit dikwels 'n standaard operasionele fout om `allowPrivilegeEscalation` aangeskakel te laat. In Docker en Podman het die weglating van die toepaslike sekuriteitsopsie dieselfde gevolg. Nog 'n herhalende faalwyse is om aan te neem dat omdat 'n container "not privileged" is, exec-tydse privilege-oordragte outomaties onbelangrik is.

## Misbruik

As `no_new_privs` nie gestel is nie, is die eerste vraag of die image binaries bevat wat steeds privilege kan verhoog:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interessante resultate sluit in:

- `NoNewPrivs: 0`
- setuid helpers soos `su`, `mount`, `passwd`, of verspreidingspesifieke administrasie-gereedskap
- binaries met file capabilities wat netwerk- of filesystem privileges verleen

In 'n werklike assessering bewys hierdie bevindinge nie op hul eie 'n werkende escalation nie, maar hulle identifiseer presies watter binaries die moeite werd is om volgende te toets.

### Volledige voorbeeld: In-Container Privilege Escalation Through setuid

Hierdie kontrole verhoed gewoonlik **in-container privilege escalation** eerder as direkte host escape. As `NoNewPrivs` is `0` en 'n setuid helper bestaan, toets dit eksplisiet:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
As 'n bekende setuid binary teenwoordig en funksioneel is, probeer dit op 'n wyse te begin wat die privilegie-oorgang behou:
```bash
/bin/su -c id 2>/dev/null
```
Dit ontsnap nie op sigself uit die container nie, maar dit kan 'n lae-privilegie-voetingspunt binne die container in container-root omskakel, wat dikwels die voorvereiste word vir later host escape deur mounts, runtime sockets, of kernel-facing interfaces.

## Kontroles

Die doel van hierdie kontroles is om te bepaal of exec-time privilege gain geblokkeer word en of die image nog helpers bevat wat saak sou maak as dit nie die geval is nie.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Wat hier interessant is:

- `NoNewPrivs: 1` is gewoonlik die veiliger resultaat.
- `NoNewPrivs: 0` beteken setuid- en file-cap-gebaseerde eskalasiepaaie bly relevant.
- 'n Minimale image met min of geen setuid/file-cap binaries gee 'n aanvaller minder post-exploitation opsies selfs wanneer `no_new_privs` ontbreek.

## Runtime-standaarde

| Runtime / platform | Standaardtoestand | Standaardgedrag | Algemene handmatige verzwakking |
| --- | --- | --- | --- |
| Docker Engine | Nie standaard geaktiveer nie | Uitdruklik aangeskakel met `--security-opt no-new-privileges=true` | deur die vlag weg te laat, `--privileged` |
| Podman | Nie standaard geaktiveer nie | Uitdruklik aangeskakel met `--security-opt no-new-privileges` of ekwivalente sekuriteitskonfigurasie | deur die opsie weg te laat, `--privileged` |
| Kubernetes | Beheer deur workload-beleid | `allowPrivilegeEscalation: false` skakel die effek in; baie workloads laat dit steeds aangeskakel | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Volg Kubernetes workload-instellings | Gewoonlik geërf vanaf die Pod-sekuriteitskonteks | dieselfde as die Kubernetes-ry |

Hierdie beskerming is dikwels afwesig eenvoudig omdat niemand dit aangeskakel het nie, nie omdat die runtime ondersteuning daarvoor ontbreek nie.
{{#include ../../../../banners/hacktricks-training.md}}
