# UTS Naamruimte

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die UTS naamruimte isoleer die **hostname** en **NIS domain name** wat deur die proses gesien word. Op die eerste oogopslag mag dit eenvoudig lyk in vergelyking met mount, PID, or user namespaces, maar dit is deel van wat 'n container laat voorkom asof dit sy eie host is. Binne die naamruimte kan die werklas 'n **hostname** sien en soms verander wat plaaslik is tot daardie naamruimte in plaas van globaal vir die masjien.

Op sigself is dit gewoonlik nie die middelpunt van 'n breakout story nie. Maar sodra die host UTS namespace gedeel word, kan 'n voldoende bevoorregte proses host-identity-verwante instellings beïnvloed, wat operasioneel en soms ook sekuriteitsgewys van belang kan wees.

## Lab

Jy kan 'n UTS-naamruimte skep met:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Die verandering van die hostname bly plaaslik tot daardie namespace en verander nie die gasheer se globale hostname nie. Dit is 'n eenvoudige maar doeltreffende demonstrasie van die isolasie-eienskap.

## Runtime Gebruik

Normale kontainers kry 'n geïsoleerde UTS namespace. Docker en Podman kan by die gasheer UTS namespace aansluit deur `--uts=host`, en soortgelyke gasheer-deelpatrone kan in ander runtimes en orkestrasiestelsels voorkom. Die meeste van die tyd is private UTS-isolasie egter net deel van die normale kontaineropstelling en vereis min aandag van die operateur.

## Sekuriteitseffek

Alhoewel die UTS namespace gewoonlik nie die gevaarlikste is om te deel nie, dra dit steeds by tot die integriteit van die kontainergrens. As die gasheer UTS namespace blootgestel word en die proses die nodige voorregte het, mag dit in staat wees om gasheer se hostname-verwante inligting te verander. Dit kan toesig, logboekopname, bedryfsaanname of skripte wat vertrouensbesluite neem gebaseer op gasheeridentiteitsdata, beïnvloed.

## Misbruik

As die gasheer UTS namespace gedeel word, is die praktiese vraag of die proses die gasheeridentiteitsinstellings kan wysig en nie net kan lees nie:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
As die container ook die nodige voorregte het, toets of die hostname verander kan word:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Dit is hoofsaaklik 'n integriteits- en operasionele-impakkwessie eerder as 'n volledige escape, maar dit toon steeds dat die container direk 'n host-global property kan beïnvloed.

Impak:

- host-identiteitsmanipulasie
- verwarrende logs, monitoring, of automation wat die hostname vertrou
- gewoonlik nie 'n volledige escape op sigself nie, tensy dit met ander swakhede gekombineer word

In Docker-style omgewings is 'n nuttige host-side detection pattern:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Kontainers wat `UTSMode=host` vertoon, deel die gasheer se UTS-naamruimte en moet noukeuriger nagegaan word as hulle ook capabilities dra wat hulle toelaat om `sethostname()` of `setdomainname()` aan te roep.

## Kontroles

Hierdie opdragte is genoeg om te sien of die workload sy eie hostname-uitsig het of die gasheer se UTS-naamruimte deel.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Wat hier interessant is:

- Die ooreenstemming van namespace-identifikatore met 'n host-proses kan op host UTS sharing dui.
- As die verandering van die hostname meer raak as net die container self, het die workload meer invloed oor host identity as wat dit behoort te hê.
- Dit is gewoonlik 'n laer-prioriteit bevinding as PID-, mount- of user namespace-kwessies, maar dit bevestig steeds hoe geïsoleerd die proses regtig is.

In die meeste omgewings word die UTS namespace die beste beskou as 'n ondersteunende isolasielaag. Dit is selde die eerste ding wat jy in 'n breakout agterjaag, maar dit bly steeds deel van die algehele konsekwentheid en veiligheid van die container-oorsig.
