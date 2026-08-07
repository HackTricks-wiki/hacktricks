# UTS-naamruimte

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die UTS-naamruimte isoleer die **hostname** en **NIS-domeinnaam** wat deur die proses gesien word. Met die eerste oogopslag mag dit gering lyk in vergelyking met mount-, PID- of user-naamruimtes, maar dit is deel van wat ’n container soos sy eie host laat voorkom. Binne die naamruimte kan die workload ’n hostname sien en soms verander wat plaaslik tot daardie naamruimte is, eerder as globaal tot die masjien.

Op sy eie is dit gewoonlik nie die kern van ’n breakout-scenario nie. Wanneer die host se UTS-naamruimte egter gedeel word, kan ’n voldoende bevoorregte proses moontlik host-identiteitverwante instellings beïnvloed, wat operasioneel belangrik en soms ook sekuriteitsrelevant kan wees.

## Lab

Jy kan ’n UTS-naamruimte met die volgende skep:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Die hostname-verandering bly plaaslik tot daardie namespace en verander nie die host se globale hostname nie. Dit is ’n eenvoudige maar effektiewe demonstrasie van die isolasie-eienskap.

## Runtime-gebruik

Normale containers kry ’n geïsoleerde UTS namespace. Docker en Podman kan by die host se UTS namespace aansluit deur middel van `--uts=host`, en soortgelyke host-sharing-patrone kan in ander runtimes en orchestration-stelsels voorkom. Meestal is private UTS-isolasie egter eenvoudig deel van die normale container-opstelling en vereis dit min operateur-aandag.

## Sekuriteitsimpak

Hoewel die UTS namespace gewoonlik nie die gevaarlikste namespace is om te deel nie, dra dit steeds by tot die integriteit van die container-grens. As die host se UTS namespace blootgestel is en die proses die nodige privileges het, kan dit moontlik host hostname-verwante inligting verander. Dit kan monitoring, logging, operasionele aannames of scripts beïnvloed wat trust-besluite neem gebaseer op host-identiteitsdata.

## Misbruik

As die host se UTS namespace gedeel word, is die praktiese vraag of die proses host-identiteitsinstellings kan wysig eerder as om dit net te lees:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
As die container ook die nodige privilege het, toets of die hostname verander kan word:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Dit is hoofsaaklik ’n integriteits- en operasionele-impakprobleem eerder as ’n volledige escape, maar dit toon steeds dat die container ’n host-globale eienskap direk kan beïnvloed.

Impak:

- peutering aan die host se identiteit
- verwarrende logs, monitering of outomatisering wat die hostname vertrou
- gewoonlik nie op sigself ’n volledige escape nie, tensy dit met ander swakhede gekombineer word

In Docker-style omgewings is ’n nuttige host-side detection pattern:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Containers wat `UTSMode=host` toon, deel die host se UTS-namespace en behoort noukeuriger nagegaan te word indien hulle ook capabilities het waarmee hulle `sethostname()` of `setdomainname()` kan aanroep.

## Kontroles

Hierdie opdragte is voldoende om te sien of die werklading sy eie hostname-aansig het of die host se UTS-namespace deel.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Wat hier interessant is:

- Ooreenstemmende namespace-identifiseerders met ’n host-proses kan op host UTS-sharing dui.
- As die verandering van die hostname meer as net die container beïnvloed, het die workload meer invloed oor host-identiteit as wat dit behoort te hê.
- Dit is gewoonlik ’n laer-prioriteit-bevinding as PID-, mount- of user namespace-kwessies, maar dit bevestig steeds hoe geïsoleerd die proses werklik is.

In die meeste omgewings word die UTS namespace die beste as ’n ondersteunende isolasielaag beskou. Dit is selde die eerste ding wat jy in ’n breakout ondersoek, maar dit vorm steeds deel van die algehele konsekwentheid en veiligheid van die container-aansig.

{{#include ../../../../../banners/hacktricks-training.md}}
