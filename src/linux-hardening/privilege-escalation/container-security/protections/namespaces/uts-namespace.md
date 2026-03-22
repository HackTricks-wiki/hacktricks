# UTS-naamruimte

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die UTS-naamruimte isoleer die **hostname** en **NIS domain name** wat deur die proses gesien word. Op die eerste oogopslag mag dit triviaal lyk vergeleke met mount-, PID- of user-naamruimtes, maar dit is deel van wat 'n container laat voorkom asof dit sy eie host is. Binne die naamruimte kan die workload 'n hostname sien en soms verander wat lokaal is aan daardie naamruimte eerder as globaal op die masjien.

Op sigself is dit gewoonlik nie die kern van 'n breakout story nie. Wanneer die host UTS-naamruimte egter gedeel word, kan 'n proses met voldoende voorregte host-identity-verwante instellings beïnvloed, wat operasioneel en soms ook vanuit sekuriteitsoogpunt van belang kan wees.

## Lab

Jy kan 'n UTS-naamruimte skep met:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Die verandering van die hostname bly plaaslik tot daardie naamruimte en verander nie die gasheer se globale hostname nie. Dit is 'n eenvoudige maar effektiewe demonstrasie van die isolasie-eienskap.

## Runtimegebruik

Normale containers kry 'n geïsoleerde UTS-naamruimte. Docker en Podman kan by die gasheer se UTS-naamruimte aansluit deur `--uts=host`, en soortgelyke gasheer-deelpatrone kan in ander runtimes en orkestrasie-stelsels voorkom. Meestal is private UTS-isolasie egter eenvoudig deel van die normale containeropstelling en vereis dit min aandag van die operateur.

## Sekuriteitsimpak

Alhoewel die UTS-naamruimte gewoonlik nie die gevaarlikste is om te deel nie, dra dit steeds by tot die integriteit van die containergrens. As die gasheer se UTS-naamruimte blootgestel word en die proses die nodige voorregte het, mag dit in staat wees om gasheer-naamverwante inligting te verander. Dit kan monitering, logging, operasionele aannames of skripte wat vertrouensbesluite neem gebaseer op gasheer-identiteitsdata, beïnvloed.

## Misbruik

Indien die gasheer se UTS-naamruimte gedeel word, is die praktiese vraag of die proses die gasheer se identiteitsinstellings kan wysig in plaas van net te lees:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
As die container ook die nodige voorreg het, toets of die hostname verander kan word:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Dit is primêr 'n integriteits- en bedryfs‑impaksaak eerder as 'n volle escape, maar dit toon steeds dat die container direk 'n gasheer‑globale eienskap kan beïnvloed.

Impak:

- vervalsing van gasheeridentiteit
- verwarende logs, monitering of outomatisering wat op die gasheernaam vertrou
- gewoonlik op sigself nie 'n volle escape nie, tensy dit met ander swakhede gekombineer word

In Docker-style omgewings is 'n nuttige gasheer‑kant opsporingspatroon:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Kontainers wat `UTSMode=host` vertoon, deel die gasheer se UTS-naamruimte en moet noukeuriger nagegaan word as hulle ook capabilities het wat hulle toelaat om `sethostname()` of `setdomainname()` aan te roep.

## Kontroles

Hierdie opdragte is genoeg om te sien of die workload sy eie hostname-uitsig het of die gasheer UTS-naamruimte deel.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Wat hier interessant is:

- Ooreenstemmende namespace-identifikatore met 'n host-proses kan aandui dat host UTS sharing plaasvind.
- As die verandering van die hostname meer as die container self beïnvloed, het die workload meer invloed op host identity as wat dit behoort te hê.
- Dit is gewoonlik 'n laer-prioriteitsbevinding as PID-, mount- of user namespace-kwessies, maar dit bevestig steeds hoe geïsoleer die proses werklik is.

In die meeste omgewings word die UTS namespace beskou as 'n ondersteunende isolasielaag. Dit is selde die eerste ding wat jy in 'n breakout jaag, maar dit bly steeds deel van die algehele konsekwentheid en veiligheid van die container-weergave.
{{#include ../../../../../banners/hacktricks-training.md}}
