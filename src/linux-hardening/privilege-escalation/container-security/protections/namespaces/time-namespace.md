# Tyd-namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die tyd-namespace virtualiseer geselekteerde horlosies, veral **`CLOCK_MONOTONIC`** en **`CLOCK_BOOTTIME`**. Dit is 'n nuwe en meer gespesialiseerde namespace as mount, PID, network, or user namespaces, en dit is selde die eerste ding waaraan 'n operateur dink wanneer container hardening bespreek word. Nietemin is dit deel van die moderne namespace-familie en die moeite werd om konseptueel te verstaan.

Die hoofdoel is om 'n proses toe te laat om beheerde verskuiwings vir sekere horlosies waar te neem sonder om die host se globale tydsbeeld te verander. Dit is nuttig vir checkpoint/restore workflows, deterministiese toetsing, en sommige gevorderde runtime-gedragswyse. Dit is gewoonlik nie 'n prominente isolasiekontrole op dieselfde manier as mount of user namespaces nie, maar dit dra steeds by tot die maak van die proses-omgewing meer selfstandig.

## Lab

As die host kernel en userspace dit ondersteun, kan jy die namespace inspekteer met:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Ondersteuning wissel na gelang van kern- en hulpmiddelweergawes, dus gaan hierdie blad meer oor die begrip van die meganisme as om te verwag dat dit in elke lab-omgewing sigbaar sal wees.

### Tydverskuiwings

Linux tyd-naamruimtes virtualiseer verskuiwings vir `CLOCK_MONOTONIC` en `CLOCK_BOOTTIME`. Die huidige per-naamruimte verskuiwings word blootgestel deur `/proc/<pid>/timens_offsets`, wat op kerne wat dit ondersteun ook gewysig kan word deur `n` proses wat `CAP_SYS_TIME` binne die relevante naamruimte hou:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Die lêer bevat nanosekonde-verskille. Deur `monotonic` met twee dae aan te pas verander uptime-agtige waarnemings binne daardie namespace sonder om die gasheer se stelselklok te verander.

### `unshare` Hulpvlae

Onlangse `util-linux`-weergawes bied geriefvlae wat die offsets outomaties skryf:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Hierdie vlae is hoofsaaklik 'n bruikbaarheidverbetering, maar dit maak dit ook makliker om die funksie in dokumentasie en toetsing te herken.

## Runtydgebruik

Time namespaces is nuwer en minder algemeen gebruik as mount of PID namespaces. OCI Runtime Specification v1.1 het eksplisiete ondersteuning bygevoeg vir die `time` namespace en die `linux.timeOffsets` veld, en nuwer `runc` uitgawes implementeer daardie deel van die model. 'n minimale OCI-fragment lyk soos:
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
Dit is belangrik omdat dit time namespacing verander van 'n nis kernprimitief in iets wat runtimes op 'n draagbare wyse kan versoek.

## Sekuriteitsimpak

Daar is minder klassieke breakout stories wat op die time namespace gefokus is as by ander tipes namespaces. Die risiko hier is gewoonlik nie dat die time namespace direk ontsnapping moontlik maak nie, maar dat lesers dit heeltemal ignoreer en daarom mis hoe gevorderde runtimes prosesgedrag kan vorm. In gespesialiseerde omgewings kan veranderde klokuitsigte checkpoint/restore, observability of forensiese aannames beïnvloed.

## Misbruik

Daar is gewoonlik geen direkte breakout primitive hier nie, maar veranderde klokgedrag kan steeds nuttig wees om die uitvoeringomgewing te verstaan en gevorderde runtime-funksies te identifiseer:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
As jy twee prosesse vergelyk, kan verskille hier help om vreemde tydsgedrag, checkpoint/restore-artefakte, of omgewingspesifieke log-ongelykhede te verduidelik.

Impak:

- almost always reconnaissance or environment understanding
- useful for explaining logging, uptime, or checkpoint/restore anomalies
- not normally a direct container-escape mechanism by itself

Die belangrike misbruiknuans is dat time namespaces nie `CLOCK_REALTIME` virtualiseer nie, sodat hulle op hul eie nie 'n aanvaller toelaat om die gasheer se muurklok te vervals of stelselwyd certificate-expiry-kontroles direk te breek nie. Hul waarde lê hoofsaaklik daarin om monotonic-time-based-logika te verwarr, om omgewingspesifieke foute na te boots, of om gevorderde runtime-gedrag te verstaan.

## Kontroles

Hierdie kontroles gaan hoofsaaklik oor die bevestiging of die runtime 'n private time namespace gebruik.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Wat hier interessant is:

- In baie omgewings sal hierdie waardes nie tot 'n onmiddellike sekuriteitsbevinding lei nie, maar dit vertel jou of 'n gespesialiseerde runtime-funksie in werking is.
- As jy twee prosesse vergelyk, kan verskille hier verwarrende timing of checkpoint/restore-gedrag verduidelik.

Vir die meeste container breakouts is die time namespace nie die eerste control wat jy sal ondersoek nie. Tog behoort 'n volledige container-security afdeling dit te noem, omdat dit deel is van die moderne kernel-model en af en toe saak maak in gevorderde runtime scenarios.
