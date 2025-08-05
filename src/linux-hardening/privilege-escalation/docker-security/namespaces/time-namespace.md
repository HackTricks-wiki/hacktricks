# Tyd Naamruimte

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

Die tyd naamruimte in Linux stel per-naamruimte verskuiwings na die stelsel monotone en opstart-tyd kloks. Dit word algemeen gebruik in Linux houers om die datum/tyd binne 'n houer te verander en kloks aan te pas na herstel vanaf 'n kontrolepunt of snapshot.

## Laboratorium:

### Skep verskillende Naamruimtes

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
Deur 'n nuwe instansie van die `/proc` lêerstelsel te monteer as jy die parameter `--mount-proc` gebruik, verseker jy dat die nuwe monteernaamruimte 'n **akkurate en geïsoleerde siening van die prosesinligting spesifiek vir daardie naamruimte** het.

<details>

<summary>Fout: bash: fork: Kan nie geheue toewys nie</summary>

Wanneer `unshare` sonder die `-f` opsie uitgevoer word, word 'n fout ondervind weens die manier waarop Linux nuwe PID (Proses ID) naamruimtes hanteer. Die sleutelbesonderhede en die oplossing word hieronder uiteengesit:

1. **Probleemverklaring**:

- Die Linux-kern laat 'n proses toe om nuwe naamruimtes te skep met die `unshare` stelselaanroep. Die proses wat die skepping van 'n nuwe PID naamruimte inisieer (genoem die "unshare" proses) gaan egter nie in die nuwe naamruimte in nie; slegs sy kindproses gaan.
- Die uitvoering van `%unshare -p /bin/bash%` begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy kindproses in die oorspronklike PID naamruimte.
- Die eerste kindproses van `/bin/bash` in die nuwe naamruimte word PID 1. Wanneer hierdie proses verlaat, aktiveer dit die opruiming van die naamruimte as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weeskindprosesse aan te neem. Die Linux-kern sal dan PID-toewysing in daardie naamruimte deaktiveer.

2. **Gevolg**:

- Die uitgang van PID 1 in 'n nuwe naamruimte lei tot die opruiming van die `PIDNS_HASH_ADDING` vlag. Dit lei tot die `alloc_pid` funksie wat misluk om 'n nuwe PID toe te wys wanneer 'n nuwe proses geskep word, wat die "Kan nie geheue toewys nie" fout veroorsaak.

3. **Oplossing**:
- Die probleem kan opgelos word deur die `-f` opsie saam met `unshare` te gebruik. Hierdie opsie maak dat `unshare` 'n nuwe proses fork nadat die nuwe PID naamruimte geskep is.
- Die uitvoering van `%unshare -fp /bin/bash%` verseker dat die `unshare` opdrag self PID 1 in die nuwe naamruimte word. `/bin/bash` en sy kindproses is dan veilig binne hierdie nuwe naamruimte, wat die voortydige uitgang van PID 1 voorkom en normale PID-toewysing toelaat.

Deur te verseker dat `unshare` met die `-f` vlag loop, word die nuwe PID naamruimte korrek gehandhaaf, wat toelaat dat `/bin/bash` en sy sub-prosesse kan werk sonder om die geheue toewysing fout te ondervind.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Kontroleer in watter naamruimte jou proses is
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### Vind alle Tyd namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Gaan binne 'n Tyd-namespace in
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
## Manipulasie van Tyd Verskille

Begin met Linux 5.6, kan twee horlosies per tydnaamruimte gevirtualiseer word:

* `CLOCK_MONOTONIC`
* `CLOCK_BOOTTIME`

Hul per-naamruimte deltas word blootgestel (en kan gewysig word) deur die lêer `/proc/<PID>/timens_offsets`:
```
$ sudo unshare -Tr --mount-proc bash   # -T creates a new timens, -r drops capabilities
$ cat /proc/$$/timens_offsets
monotonic 0
boottime  0
```
Die lêer bevat twee lyne – een per klok – met die offset in **nanosekondes**. Prosesse wat **CAP_SYS_TIME** _in die tydnaamruimte_ hou, kan die waarde verander:
```
# advance CLOCK_MONOTONIC by two days (172 800 s)
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
# verify
$ cat /proc/$$/uptime   # first column uses CLOCK_MONOTONIC
172801.37  13.57
```
As jy die muurklok (`CLOCK_REALTIME`) ook wil verander, moet jy steeds op klassieke meganismes staatmaak (`date`, `hwclock`, `chronyd`, …); dit is **nie** naamruimte-gebaseerd nie.


### `unshare(1)` helper vlae (util-linux ≥ 2.38)
```
sudo unshare -T \
--monotonic="+24h"  \
--boottime="+7d"    \
--mount-proc         \
bash
```
Die lang opsies skryf outomaties die gekose deltas na `timens_offsets` reg nadat die naamruimte geskep is, wat 'n handmatige `echo` bespaar.

---

## OCI & Runtime ondersteuning

* Die **OCI Runtime Spesifikasie v1.1** (Nov 2023) het 'n toegewyde `time` naamruimte tipe en die `linux.timeOffsets` veld bygevoeg sodat houer enjinse tydvirtualisering op 'n draagbare manier kan versoek.
* **runc >= 1.2.0** implementeer daardie deel van die spesifikasie. 'n Minimale `config.json` fragment lyk soos volg:
```json
{
"linux": {
"namespaces": [
{"type": "time"}
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Voer dan die houer uit met `runc run <id>`.

>  LET WEL: runc **1.2.6** (Feb 2025) het 'n "exec in houer met private timens" fout reggestel wat tot 'n hang en potensiële DoS kon lei. Maak seker jy is op ≥ 1.2.6 in produksie.

---

## Sekuriteits oorwegings

1. **Vereiste vermoë** – 'n Proses benodig **CAP_SYS_TIME** binne sy gebruiker/tyd naamruimte om die offsets te verander. Om daardie vermoë in die houer te laat val (standaard in Docker & Kubernetes) voorkom manipulasie.
2. **Geen muurklok veranderinge** – Omdat `CLOCK_REALTIME` gedeel word met die gasheer, kan aanvallers nie sertifikaatleeftyds, JWT vervaldatums, ens. via timens alleen naboots nie.
3. **Log / opsporing ontduiking** – Sagteware wat op `CLOCK_MONOTONIC` staatmaak (bv. koersbeperkers gebaseer op uptime) kan verwar word as die naamruimte gebruiker die offset aanpas. Verkies `CLOCK_REALTIME` vir sekuriteitsrelevante tydstempels.
4. **Kernel aanval oppervlak** – Selfs met `CAP_SYS_TIME` verwyder, bly die kernel kode toeganklik; hou die gasheer gepatch. Linux 5.6 → 5.12 het verskeie timens foutregstellings ontvang (NULL-deref, ondertekenheidskwessies).

### Versterking kontrolelys

* Laat `CAP_SYS_TIME` in jou houer runtime standaard profiel val.
* Hou runtimes opgedateer (runc ≥ 1.2.6, crun ≥ 1.12).
* Pin util-linux ≥ 2.38 as jy op die `--monotonic/--boottime` helpers staatmaak.
* Ou dit in-houer sagteware wat **uptime** of **CLOCK_MONOTONIC** lees vir sekuriteitskritiese logika.

## Verwysings

* man7.org – Tyd naamruimtes handleiding bladsy: <https://man7.org/linux/man-pages/man7/time_namespaces.7.html>
* OCI blog – "OCI v1.1: nuwe tyd en RDT naamruimtes" (Nov 15 2023): <https://opencontainers.org/blog/2023/11/15/oci-spec-v1.1>

{{#include ../../../../banners/hacktricks-training.md}}
