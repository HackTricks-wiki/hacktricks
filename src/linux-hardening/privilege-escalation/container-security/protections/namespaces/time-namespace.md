# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die time namespace virtualiseer geselekteerde klokkies, veral **`CLOCK_MONOTONIC`** en **`CLOCK_BOOTTIME`**. Dit is 'n nuwer en meer gespesialiseerde namespace as mount, PID, network, of user namespaces, en dit is selde die eerste ding waaraan 'n operator dink wanneer container hardening bespreek word. Dit is egter deel van die moderne namespace-familie en die moeite werd om konseptueel te verstaan.

Die hoofdoel is om 'n proses toe te laat om beheerde verskuiwings vir sekere klokkies te sien sonder om die host se globale tydsweergawes te verander. Dit is nuttig vir checkpoint/restore workflows, deterministiese toetse, en sommige gevorderde runtime-gedraginge. Dit is gewoonlik nie 'n groot isolasiekontrole op dieselfde manier as mount of user namespaces nie, maar dit dra steeds by om die proses-omgewing meer selfstandig te maak.

## Lab

As die host kernel en userspace dit ondersteun, kan jy die namespace inspekteer met:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Ondersteuning wissel tussen kernel- en gereedskapweergawes, dus gaan hierdie bladsy meer oor die begrip van die meganisme as om te verwag dat dit in elke labomgewing sigbaar sal wees.

### Tydverskuiwings

Linux tyd-naamruimtes virtualiseer verskuiwings vir `CLOCK_MONOTONIC` en `CLOCK_BOOTTIME`. Die huidige per-naamruimte verskuiwings word blootgestel via `/proc/<pid>/timens_offsets`, wat op ondersteunende kernels ook deur 'n proses wat `CAP_SYS_TIME` binne die relevante namespace het, gewysig kan word:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Die lêer bevat nanosekondeverskille. Deur `monotonic` met twee dae aan te pas, verander uptime-agtige waarnemings binne daardie namespace sonder om die host se muurklok te verander.

### `unshare` Hulpvlae

Onlangse `util-linux` weergawes bied geriefvlae wat die offsets outomaties skryf:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Hierdie vlagte is hoofsaaklik 'n bruikbaarheidverbetering, maar dit maak dit ook makliker om die funksie in dokumentasie en toetsing te herken.

## Runtimegebruik

Time namespaces is nuwer en minder wyd gebruik as mount- of PID-namespaces. OCI Runtime Specification v1.1 het eksplisiete ondersteuning vir die `time` namespace en die `linux.timeOffsets` veld bygevoeg, en nuwer `runc` releases implementeer daardie deel van die model. 'n minimale OCI-fragment lyk soos:
```json
{
"linux": {
"namespaces": [
{ "type": "time" }
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Dit maak saak omdat dit time namespacing verander van 'n nismatige kern-primitive in iets wat runtimes draagbaar kan versoek.

## Sekuriteitsimpak

Daar is minder klassieke breakout-verhale wat gefokus is op die time namespace as op ander namespace-tipes. Die risiko hier is gewoonlik nie dat die time namespace direk ontsnapping moontlik maak nie, maar dat lesers dit heeltemal ignoreer en dus mis hoe gevorderde runtimes prosesgedrag kan vorm. In gespesialiseerde omgewings kan veranderde klokuitsigte invloed hê op checkpoint/restore, observability of forensiese aannames.

## Misbruik

Daar is gewoonlik geen direkte breakout-primitive hier nie, maar veranderde klokgedrag kan steeds nuttig wees om die uitvoeringsomgewing te verstaan en gevorderde runtime-funksies te identifiseer:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
As jy twee prosesse vergelyk, kan verskille hier help om vreemde tydsverwante gedrag, checkpoint/restore-artefakte, of omgewing-spesifieke logverskille te verduidelik.

Impak:

- byna altyd verkenning of begrip van die omgewing
- nuttig om logging, uptime, of checkpoint/restore-afwykings te verduidelik
- nie normaalweg op sigself 'n direkte container-escape-meganisme nie

Die belangrike misbruiknuans is dat time namespaces nie `CLOCK_REALTIME` virtualiseer nie, so laat hulle op sigself nie 'n aanvaller toe om die gasheer se stelselklok te vervals of sertifikaatvervalingskontroles stelselwyd direk te breek nie. Hul waarde lê hoofsaaklik daarin om monotoniese-tydgebaseerde logika te verwar, om omgewing-spesifieke foute te reproduseer, of om gevorderde runtime-gedrag te verstaan.

## Kontroles

Hierdie kontroles gaan hoofsaaklik oor die bevestiging of die runtime eintlik 'n private tyd-namespace gebruik.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Wat hier interessant is:

- In baie omgewings sal hierdie waardes nie tot 'n onmiddellike sekuriteitsbevinding lei nie, maar hulle vertel jou wel of 'n gespesialiseerde runtime-funksie in werking is.
- As jy twee prosesse vergelyk, kan verskille hier verwarrende tyd- of checkpoint/restore-gedrag verklaar.

Vir die meeste container breakouts is die time namespace nie die eerste beheer wat jy sal ondersoek nie. Tog behoort 'n volledige container-security-afdeling dit te noem, omdat dit deel is van die moderne kernel model en af en toe saak maak in gevorderde runtime-scenario's.
{{#include ../../../../../banners/hacktricks-training.md}}
