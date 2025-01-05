# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

'n UTS (UNIX Time-Sharing System) naamruimte is 'n Linux-kernfunksie wat i**solasie van twee stelselnommers** bied: die **gasheernaam** en die **NIS** (Netwerk Inligtingsdiens) domeinnaam. Hierdie isolasie laat elke UTS naamruimte toe om sy **eie onafhanklike gasheernaam en NIS domeinnaam** te hê, wat veral nuttig is in konteinerisasiescenario's waar elke konteiner as 'n aparte stelsel met sy eie gasheernaam moet verskyn.

### Hoe dit werk:

1. Wanneer 'n nuwe UTS naamruimte geskep word, begin dit met 'n **kopie van die gasheernaam en NIS domeinnaam van sy ouernaamruimte**. Dit beteken dat, by die skepping, die nuwe naamruimte s**elf dieselfde nommers as sy ouer deel**. egter, enige daaropvolgende veranderinge aan die gasheernaam of NIS domeinnaam binne die naamruimte sal nie ander naamruimtes beïnvloed nie.
2. Prosesse binne 'n UTS naamruimte **kan die gasheernaam en NIS domeinnaam verander** deur die `sethostname()` en `setdomainname()` stelselaanroepe, onderskeidelik. Hierdie veranderinge is plaaslik vir die naamruimte en beïnvloed nie ander naamruimtes of die gasheerstelsel nie.
3. Prosesse kan tussen naamruimtes beweeg deur die `setns()` stelselaanroep of nuwe naamruimtes skep deur die `unshare()` of `clone()` stelselaanroepe met die `CLONE_NEWUTS` vlag. Wanneer 'n proses na 'n nuwe naamruimte beweeg of een skep, sal dit begin om die gasheernaam en NIS domeinnaam wat met daardie naamruimte geassosieer word, te gebruik.

## Laboratorium:

### Skep verskillende Naamruimtes

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Deur 'n nuwe instansie van die `/proc` lêerstelsel te monteer as jy die parameter `--mount-proc` gebruik, verseker jy dat die nuwe monteernaamruimte 'n **akkurate en geïsoleerde siening van die prosesinligting spesifiek vir daardie naamruimte** het.

<details>

<summary>Fout: bash: fork: Kan nie geheue toewys nie</summary>

Wanneer `unshare` sonder die `-f` opsie uitgevoer word, word 'n fout ondervind weens die manier waarop Linux nuwe PID (Proses ID) naamruimtes hanteer. Die sleutelbesonderhede en die oplossing word hieronder uiteengesit:

1. **Probleemverklaring**:

- Die Linux-kern laat 'n proses toe om nuwe naamruimtes te skep met die `unshare` stelselaanroep. Die proses wat die skepping van 'n nuwe PID naamruimte inisieer (genoem die "unshare" proses) gaan egter nie in die nuwe naamruimte in nie; slegs sy kindproses gaan.
- Die uitvoering van `%unshare -p /bin/bash%` begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy kindproses in die oorspronklike PID naamruimte.
- Die eerste kindproses van `/bin/bash` in die nuwe naamruimte word PID 1. Wanneer hierdie proses verlaat, aktiveer dit die opruiming van die naamruimte as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weesprosesse aan te neem. Die Linux-kern sal dan PID-toewysing in daardie naamruimte deaktiveer.

2. **Gevolg**:

- Die uitgang van PID 1 in 'n nuwe naamruimte lei tot die opruiming van die `PIDNS_HASH_ADDING` vlag. Dit lei tot die `alloc_pid` funksie wat misluk om 'n nuwe PID toe te wys wanneer 'n nuwe proses geskep word, wat die "Kan nie geheue toewys nie" fout produseer.

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
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Vind alle UTS-namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Gaan binne 'n UTS-namespace in
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
{{#include ../../../../banners/hacktricks-training.md}}
