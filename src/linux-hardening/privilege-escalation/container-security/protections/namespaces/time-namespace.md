# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die time namespace virtualiseer gekose kloke, veral **`CLOCK_MONOTONIC`** en **`CLOCK_BOOTTIME`**. Dit is 'n nuwer en meer gespesialiseerde namespace as mount, PID, network, of user namespaces, en dit is selde die eerste ding waaraan 'n operateur dink wanneer hulle container hardening bespreek. Nietemin is dit deel van die moderne namespace-familie en die moeite werd om konseptueel te verstaan.

Die hoofdoel is om 'n proses toe te laat om beheerde verskuiwings ('offsets') vir sekere kloke waar te neem sonder om die host se globale tydsuitkyk te verander. Dit is nuttig vir checkpoint/restore workflows, deterministiese testing, en sommige gevorderde runtime-gedragswyse. Dit is gewoonlik nie 'n vooraanstaande isolasiebeheer op dieselfde manier as mount of user namespaces nie, maar dit dra steeds by tot 'n meer op sigself staande prosesomgewing.

## Lab

As die host kernel en userspace dit ondersteun, kan jy die namespace inspekteer met:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Ondersteuning verskil na gelang van kernel- en gereedskapweergawes, daarom gaan hierdie bladsy meer oor die begrip van die meganisme as om te verwag dat dit in elke labomgewing sigbaar sal wees.

### Time Offsets

Linux time namespaces virtualiseer verskuiwings vir `CLOCK_MONOTONIC` en `CLOCK_BOOTTIME`. Die huidige per-namespace verskuiwings word blootgestel deur `/proc/<pid>/timens_offsets`, wat op kernels wat dit ondersteun ook aangepas kan word deur 'n proses wat `CAP_SYS_TIME` binne die betrokke namespace het:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Die lêer bevat nanosekondeverskille. Deur `monotonic` met twee dae aan te pas, verander uptime-agtige waarnemings binne daardie namespace sonder om die host se wandklok te verander.

### `unshare` Hulppvlagte

Onlangse `util-linux` weergawes bied gerieflike vlagte wat die verskuiwings outomaties wegskryf:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Hierdie vlae is hoofsaaklik 'n bruikbaarheidverbetering, maar dit maak dit ook makliker om die funksie in dokumentasie en toetsing te herken.

## Runtime-gebruik

Tyd-naamruimtes is nuwer en word minder wyd toegepas as mount- of PID-naamruimtes. OCI Runtime Specification v1.1 het eksplisiete ondersteuning vir die `time` namespace en die `linux.timeOffsets` veld bygevoeg, en nuwer `runc`-vrystellings implementeer daardie deel van die model. 'n minimale OCI-fragment lyk soos:
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
Dit is belangrik omdat dit time namespacing verander van 'n nis kernprimitief in iets wat runtimes draagbaar kan versoek.

## Sekuriteitsimpak

Daar is minder klassieke breakout-verhale wat rondom die time namespace draai as by ander namespace-tipes. Die risiko hier is gewoonlik nie dat die time namespace direk ontsnapping moontlik maak nie, maar dat lesers dit heeltemal ignoreer en daarom mis hoe gevorderde runtimes prosesgedrag kan vorm. In gespesialiseerde omgewings kan veranderde klokperspektiewe checkpoint/restore, observability, of forensiese aannames beïnvloed.

## Misbruik

Daar is gewoonlik geen direkte breakout-primitief hier nie, maar veranderde klokgedrag kan steeds nuttig wees om die uitvoeringsomgewing te verstaan en gevorderde runtime-funksies te identifiseer:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
As jy twee prosesse vergelyk, kan verskille hier help om vreemde tydsgedrag, checkpoint/restore-artefakte, of omgewingspesifieke logs wat nie ooreenstem nie, te verduidelik.

Impak:

- byna altyd verkenning of begrip van die omgewing
- bruikbaar om logging, uptime, of checkpoint/restore-afwykings te verduidelik
- normaalweg nie 'n direkte container-escape-meganisme op sigself nie

Die belangrike misbruiknuanse is dat time namespaces nie `CLOCK_REALTIME` virtualiseer nie, so laat hulle op sigself nie 'n aanvaller toe om die host wall clock te vervals of certificate-expiry checks stelselwyd direk te breek nie. Hul waarde lê hoofsaaklik daarin om monotonic-time-based logika te verwar, om omgewingspesifieke bugs te reproduseer, of om gevorderde runtime-gedrag te verstaan.

## Checks

Hierdie kontroles handel meestal oor die bevestiging of die runtime 'n private time namespace gebruik.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Wat hier interessant is:

- In baie omgewings sal hierdie waardes nie tot 'n onmiddellike veiligheidsbevinding lei nie, maar hulle vertel jou of 'n gespesialiseerde runtime-funksie aan die werk is.
- As jy twee prosesse vergelyk, kan verskille hier verwarde timing- of checkpoint/restore-gedrag verklaar.

Vir die meeste container breakouts is die time namespace nie die eerste beheer wat jy sal ondersoek nie. Tog behoort 'n volledige container-security afdeling dit te noem, omdat dit deel is van die moderne kernel-model en soms saak maak in gevorderde runtime-scenario's.
{{#include ../../../../../banners/hacktricks-training.md}}
