# CGroup Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

'n cgroup namespace is 'n Linux-kernfunksie wat **isolatie van cgroup hiërargieë vir prosesse wat binne 'n namespace loop** bied. Cgroups, kort vir **kontrole groepe**, is 'n kernfunksie wat toelaat om prosesse in hiërargiese groepe te organiseer om **grense op stelselhulpbronne** soos CPU, geheue en I/O te bestuur en af te dwing.

Terwyl cgroup namespaces nie 'n aparte namespace tipe is soos die ander wat ons vroeër bespreek het nie (PID, mount, netwerk, ens.), is hulle verwant aan die konsep van namespace isolasie. **Cgroup namespaces virtualiseer die siening van die cgroup hiërargie**, sodat prosesse wat binne 'n cgroup namespace loop 'n ander siening van die hiërargie het in vergelyking met prosesse wat in die gasheer of ander namespaces loop.

### Hoe dit werk:

1. Wanneer 'n nuwe cgroup namespace geskep word, **begin dit met 'n siening van die cgroup hiërargie gebaseer op die cgroup van die skepende proses**. Dit beteken dat prosesse wat in die nuwe cgroup namespace loop slegs 'n subset van die hele cgroup hiërargie sal sien, beperk tot die cgroup subboom wat gegrond is op die skepende proses se cgroup.
2. Prosesse binne 'n cgroup namespace sal **hulle eie cgroup as die wortel van die hiërargie sien**. Dit beteken dat, vanuit die perspektief van prosesse binne die namespace, hulle eie cgroup as die wortel verskyn, en hulle kan nie cgroups buite hul eie subboom sien of toegang daartoe kry nie.
3. Cgroup namespaces bied nie direk isolasie van hulpbronne nie; **hulle bied slegs isolasie van die cgroup hiërargie siening**. **Hulpbronbeheer en isolasie word steeds afgedwing deur die cgroup** subsisteme (bv., cpu, geheue, ens.) self.

Vir meer inligting oor CGroups kyk:

{{#ref}}
../cgroups.md
{{#endref}}

## Laboratorium:

### Skep verskillende Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
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
### &#x20;Kontroleer in watter naamruimte jou proses is
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Vind alle CGroup name ruimtes
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Gaan binne 'n CGroup-namespace in
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Ook, jy kan slegs **in 'n ander prosesnaamruimte ingaan as jy root is**. En jy **kan nie** **ingaan** in 'n ander naamruimte **sonder 'n beskrywer** wat daarna verwys nie (soos `/proc/self/ns/cgroup`).

## Verwysings

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
