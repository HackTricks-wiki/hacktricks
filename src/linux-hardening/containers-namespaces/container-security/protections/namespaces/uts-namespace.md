# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die UTS namespace isoleer die **hostname** en **NIS domain name** wat deur die proses gesien word. Met die eerste oogopslag mag dit onbenullig lyk in vergelyking met mount-, PID- of user namespaces, maar dit is deel van wat ’n container soos sy eie host laat voorkom. Binne die namespace kan die workload ’n hostname sien en soms verander wat plaaslik tot daardie namespace is eerder as globaal tot die masjien.

Op sy eie is dit gewoonlik nie die kern van ’n breakout-scenario nie. Wanneer die host se UTS namespace egter gedeel word, kan ’n proses met voldoende privileges moontlik host-identiteitverwante instellings beïnvloed, wat operasioneel belangrik en soms ook security-relevant kan wees.

## Lab

Jy kan ’n UTS namespace met die volgende skep:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Die verandering van die hostname bly beperk tot daardie namespace en verander nie die host se globale hostname nie. Dit is ’n eenvoudige maar effektiewe demonstrasie van die isolasie-eienskap.

## Gebruik tydens uitvoering

Normale containers kry ’n geïsoleerde UTS namespace. Docker en Podman kan by die host se UTS namespace aansluit deur middel van `--uts=host`, en soortgelyke host-sharing-patrone kan in ander runtimes en orchestrasiestelsels voorkom. Meeste van die tyd is private UTS-isolasie egter bloot deel van die normale container-opstelling en vereis dit min aandag van die operateur.

## Sekuriteitsimpak

Hoewel die UTS namespace gewoonlik nie die gevaarlikste een is om te deel nie, dra dit steeds by tot die integriteit van die container-grens. As die host se UTS namespace blootgestel is en die proses oor die nodige privileges beskik, kan dit moontlik host hostname-verwante inligting verander. Dit kan monitering, logging, operasionele aannames of scripts beïnvloed wat vertrouensbesluite op grond van host-identiteitsdata neem.

## Misbruik

As die host se UTS namespace gedeel word, is die praktiese vraag of die proses host-identiteitsinstellings kan wysig eerder as om dit net te lees:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Indien die container ook die nodige voorreg het, toets of die hostname verander kan word:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Dit is hoofsaaklik ’n integriteits- en operasionele-impak-kwessie eerder as ’n volledige escape, maar dit wys steeds dat die container ’n host-global eienskap direk kan beïnvloed.

Impak:

- manipulasie van die host se identiteit
- verwarrende logs, monitering of automation wat die hostname vertrou
- gewoonlik nie op sy eie ’n volledige escape nie, tensy dit met ander swakhede gekombineer word

In Docker-style omgewings is ’n nuttige host-side detection-patroon:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Houers wat `UTSMode=host` toon, deel die host se UTS namespace en behoort noukeuriger nagegaan te word indien hulle ook capabilities het wat hulle toelaat om `sethostname()` of `setdomainname()` aan te roep.

## Kontroles

Hierdie commands is voldoende om te sien of die werklading sy eie hostname view het of die host se UTS namespace deel.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Wat is hier interessant:

- Ooreenstemmende namespace-identifiseerders met ’n host-proses kan op host UTS-sharing dui.
- As die verandering van die hostname meer as net die container self beïnvloed, het die workload meer invloed oor host-identiteit as wat dit behoort te hê.
- Dit is gewoonlik ’n laer-prioriteit-bevinding as PID-, mount- of user-namespace-kwessies, maar dit bevestig steeds hoe geïsoleerd die proses werklik is.

In die meeste omgewings word die UTS-namespace die beste beskou as ’n ondersteunende isolasielaag. Dit is selde die eerste ding waarna jy in ’n breakout soek, maar dit vorm steeds deel van die algehele konsekwentheid en veiligheid van die container-aansig.
{{#include ../../../../../banners/hacktricks-training.md}}
