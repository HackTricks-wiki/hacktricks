# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die UTS-naamruimte isoleer die **hostname** en **NIS domain name** wat deur die proses gesien word. Op die eerste oogopslag mag dit triviaal lyk in vergelyking met mount-, PID- of user namespaces, maar dit is deel van wat 'n container laat voorkom asof dit sy eie host is. Binne die naamruimte kan die workload 'n hostname sien en soms verander wat plaaslik is aan daardie naamruimte eerder as globaal op die masjien.

Op sigself is dit gewoonlik nie die middelpunt van 'n breakout story nie. As die host UTS namespace egter gedeel word, kan 'n voldoende bevoegde proses gasheer-identiteitsverwante instellings beïnvloed, wat operationeel en soms ook sekuriteitsgewys van belang kan wees.

## Lab

Jy kan 'n UTS-naamruimte skep met:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Die hostname-wijziging bly lokaal tot daardie namespace en verander nie die host se globale hostname nie. Dit is 'n eenvoudige maar effektiewe demonstrasie van die isolasie-eienskap.

## Runtime-gebruik

Normale containers kry 'n geïsoleerde UTS namespace. Docker en Podman kan by die host UTS namespace aansluit via `--uts=host`, en soortgelyke host-deelpatrone kan in ander runtimes en orkestreringsisteme voorkom. Die meeste van die tyd is private UTS-isolasie egter eenvoudig deel van die normale container-opstelling en verg min aandag van die operateur.

## Sekuriteitsimpak

Alhoewel die UTS namespace gewoonlik nie die gevaarlikste is om te deel nie, dra dit steeds by tot die integriteit van die container-grens. As die host UTS namespace blootgestel word en die proses die nodige voorregte het, kan dit die host se hostname-verwante inligting verander. Dit kan monitering, logging, operasionele aannames of skripte wat vertrouensbesluite neem op grond van host-identiteitsdata, beïnvloed.

## Misbruik

As die host UTS namespace gedeel word, is die praktiese vraag of die proses host-identiteitsinstellings kan wysig in plaas van net te lees:
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
Dit is hoofsaaklik 'n integriteits- en operasionele-impak kwessie eerder as 'n full escape, maar dit toon steeds dat die container direk 'n host-globale eienskap kan beïnvloed.

Impact:

- manipulasie van host-identiteit
- verwarende logs, monitoring of automatisering wat die hostname vertrou
- gewoonlik nie op sigself 'n full escape nie, tensy dit met ander swakhede gekombineer word

On Docker-style environments, a useful host-side detection pattern is:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Containers wat `UTSMode=host` aandui, deel die gasheer se UTS-naamruimte en moet meer deeglik nagegaan word as hulle ook capabilities dra wat hulle toelaat om `sethostname()` of `setdomainname()` aan te roep.

## Kontroles

Hierdie opdragte is genoeg om te bepaal of die workload sy eie hostname-uitsig het of die gasheer se UTS-naamruimte deel.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
- Die afstem van namespace-identifiseerders met 'n host-proses kan aandui dat die host UTS gedeel word.
- As die verandering van die hostname meer as net die container self beïnvloed, het die workload meer invloed oor host-identiteit as wat dit behoort te hê.
- Dit is gewoonlik 'n laerprioriteitsbevinding as PID-, mount- of user namespace-kwessies, maar dit bevestig steeds hoe geïsoleerd die proses werklik is.

In die meeste omgewings word die UTS namespace die beste beskou as 'n ondersteunende isolasielaag. Dit is selde die eerste ding wat jy in 'n breakout agtervolg, maar dit bly steeds deel van die algehele konsekwentheid en veiligheid van die container-uitsig.
{{#include ../../../../../banners/hacktricks-training.md}}
