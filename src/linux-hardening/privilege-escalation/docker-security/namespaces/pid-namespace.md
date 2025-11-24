# PID-naamruimte

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

Die PID (Process IDentifier) naamruimte is 'n funksie in die Linux kernel wat prosesisolasie bied deur 'n groep prosesse toe te laat om hul eie stel unieke PIDs te hê, afsonderlik van die PIDs in ander naamruimtes. Dit is veral nuttig in kontenerisering, waar prosesisolasie noodsaaklik is vir sekuriteit en hulpbronbestuur.

Wanneer 'n nuwe PID-naamruimte geskep word, word die eerste proses in daardie naamruimte PID 1 toegewys. Hierdie proses word die "init" proses van die nuwe naamruimte en is verantwoordelik vir die bestuur van ander prosesse binne die naamruimte. Elke volgende proses wat binne die naamruimte geskep word, sal 'n unieke PID binne daardie naamruimte hê, en hierdie PIDs is onafhanklik van PIDs in ander naamruimtes.

Uit die oogpunt van 'n proses binne 'n PID-naamruimte, kan dit slegs ander prosesse in dieselfde naamruimte sien. Dit is nie bewus van prosesse in ander naamruimtes nie, en dit kan nie met hulle interageer deur tradisionele prosesbestuurhulpmiddele (bv. `kill`, `wait`, ens.) nie. Dit bied 'n vlak van isolasie wat help om te voorkom dat prosesse mekaar ontwrig.

### Hoe dit werk:

1. Wanneer 'n nuwe proses geskep word (bv. deur die gebruik van die `clone()` stelseloproep), kan die proses aan 'n nuwe of bestaande PID-naamruimte toegewys word. **As 'n nuwe naamruimte geskep word, word die proses die "init" proses van daardie naamruimte**.
2. Die **kernel** handhaaf 'n **toewysing tussen die PIDs in die nuwe naamruimte en die ooreenstemmende PIDs** in die ouer-naamruimte (d.w.s. die naamruimte waaruit die nuwe naamruimte geskep is). Hierdie toewysing **laat die kernel toe om PIDs te vertaal wanneer nodig**, byvoorbeeld wanneer seine tussen prosesse in verskillende naamruimtes gestuur word.
3. **Prosesse binne 'n PID-naamruimte kan slegs ander prosesse in dieselfde naamruimte sien en mee interageer**. Hulle is nie bewus van prosesse in ander naamruimtes nie, en hul PIDs is uniek binne hul naamruimte.
4. Wanneer 'n **PID-naamruimte vernietig** word (bv. wanneer die "init" proses van die naamruimte uitlog), **word alle prosesse binne daardie naamruimte beëindig**. Dit verseker dat alle hulpbronne wat met die naamruimte geassosieer is behoorlik opgeskoon word.

## Laboratorium:

### Skep verskillende naamruimtes

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Wanneer `unshare` uitgevoer word sonder die `-f` opsie, word 'n fout teëgekom as gevolg van die manier waarop Linux nuwe PID (Process ID) namespaces hanteer. Die sleutelbesonderhede en die oplossing word hieronder uiteengesit:

1. **Probleembeskrywing**:

- Die Linux kernel laat 'n proses toe om nuwe namespaces te skep deur die `unshare` system call. Die proses wat die skepping van 'n nuwe PID namespace inisieer (verwys as die "unshare" proses) gaan egter nie self in die nuwe namespace in nie; slegs sy subprosesse doen.
- Uitvoeren van %unshare -p /bin/bash% begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy subprosesse in die oorspronklike PID namespace.
- Die eerste subproses van `/bin/bash` in die nuwe namespace word PID 1. Wanneer hierdie proses afsluit, trigger dit die opruiming van die namespace as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weesprosesse te adopteer. Die Linux kernel sal dan PID-toekenning in daardie namespace deaktiveer.

2. **Gevolg**:

- Die uitgang van PID 1 in 'n nuwe namespace lei tot die skoonmaak van die `PIDNS_HASH_ADDING` vlag. Dit lei daartoe dat die `alloc_pid` funksie misluk om 'n nuwe PID toe te ken wanneer 'n nuwe proses geskep word, wat die "Cannot allocate memory" fout produseer.

3. **Oplossing**:
- Die probleem kan opgelos word deur die `-f` opsie met `unshare` te gebruik. Hierdie opsie laat `unshare` 'n nuwe proses fork nadat dit die nuwe PID namespace geskep het.
- Uitvoeren van %unshare -fp /bin/bash% verseker dat die `unshare` opdrag self PID 1 in die nuwe namespace word. `/bin/bash` en sy subprosesse sal dan veilig binne hierdie nuwe namespace gehou word, wat die voortydige afsluiting van PID 1 voorkom en normale PID-toekenning toelaat.

Deur te verseker dat `unshare` met die `-f` vlag loop, word die nuwe PID namespace korrek gehandhaaf, wat toelaat dat `/bin/bash` en sy subprosesse werk sonder om die "Cannot allocate memory" fout te ondervind.

</details>

Deur 'n nuwe instansie van die `/proc` filesystem te mount as jy die parameter `--mount-proc` gebruik, verseker jy dat die nuwe mount namespace 'n **akkurate en geïsoleerde uitsig van die prosesinligting spesifiek vir daardie namespace** het.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Kontroleer in watter namespace jou proses is
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Vind alle PID-naamruimtes
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Neem kennis dat die root user vanuit die aanvanklike (default) PID namespace alle prosesse kan sien, selfs dié in nuwe PID namespaces; daarom kan ons al die PID namespaces sien.

### Gaan binne 'n PID namespace in
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Wanneer jy vanaf die standaard-naamruimte in 'n PID-naamruimte inkom, sal jy steeds alle prosesse kan sien. En die proses in daardie PID-naamruimte sal die nuwe bash in daardie PID-naamruimte kan sien.

Ook kan jy slegs **in 'n ander proses PID-naamruimte inkom as jy root is**. En jy **kan nie** **betree** in 'n ander naamruimte **sonder 'n descriptor** wat daarna wys (soos `/proc/self/ns/pid`) nie.

## Onlangse uitbuitingsnotas

### CVE-2025-31133: abusing `maskedPaths` to reach host PIDs

runc ≤1.2.7 het aanvallers wat container images of `runc exec` workloads beheer toegelaat om die container-kant van `/dev/null` te vervang net voordat die runtime sensitiewe procfs-insette gemasker het. Wanneer die race slaag, kan `/dev/null` in 'n symlink omgeskakel word wat na enige host-pad wys (byvoorbeeld `/proc/sys/kernel/core_pattern`), sodat die nuwe container PID-naamruimte skielik lees-/skryftoegang tot host-globale procfs-instellings erweerf, al het dit nooit sy eie naamruimte verlaat nie. Sodra `core_pattern` of `/proc/sysrq-trigger` skryfbaar is, sal die genereer van 'n coredump of die aktiveer van SysRq kode-uitvoering of ontkenning van diens in die host PID-naamruimte tot gevolg hê.

Praktiese werkvloei:

1. Bou 'n OCI-bundel waarvan die rootfs `/dev/null` vervang met 'n skakel na die gewenste host-pad (`ln -sf /proc/sys/kernel/core_pattern rootfs/dev/null`).
2. Begin die container voordat die regstelling aangebring is, sodat runc die host procfs-doel oor die skakel bind-mount.
3. Binne die container-naamruimte skryf na die nou-blootgestelde procfs-lêer (bv. wys `core_pattern` na 'n reverse shell helper) en laat enige proses crash om die host kernel te dwing jou helper as PID 1-konteks uit te voer.

Jy kan vinnig nagaan of 'n bundel die regte lêers maskeer voordat jy dit begin:
```bash
jq '.linux.maskedPaths' config.json | tr -d '"'
```
As die runtime 'n maskering-invoer wat jy verwag ontbreek (of dit oorslaan omdat `/dev/null` verdwyn het), hanteer die container asof dit potensiële host PID-sigbaarheid het.

### Naamruimteinspuiting met `insject`

NCC Group’s `insject` laai as 'n LD_PRELOAD payload wat 'n laat stadium in die teikenprogram hook (standaard `main`) en voer 'n reeks `setns()`-aanroepe ná `execve()` uit. Dit laat jou toe om vanaf die host (of 'n ander container) in 'n slagoffer se PID-naamruimte aan te koppel *ná* dat sy runtime geïnitialiseer is, en sodoende sy `/proc/<pid>`-uitsig te behou sonder om binaries in die container-lêerstelsel te hoef te kopieer. Omdat `insject` kan uitstel om by die PID-naamruimte aan te sluit totdat dit fork, kan jy een thread in die host-naamruimte hou (met CAP_SYS_PTRACE) terwyl 'n ander thread in die teiken PID-naamruimte uitvoer, wat kragtige debugging- of offensiewe primitives skep.

Example usage:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Belangrike afleidings wanneer jy namespace injection misbruik of daarteen verdedig:

- Gebruik `-S/--strict` om `insject` te dwing om te staak as threads reeds bestaan of namespace joins misluk; anders kan jy deels-gemigreerde threads agterlaat wat oor die host- en container-PID-ruimtes heen strek.
- Moet nooit tools aanheg wat steeds writable host file descriptors hou tensy jy ook die mount namespace join nie — anders kan enige proses binne die PID namespace jou helper ptrace en daardie descriptors hergebruik om met host resources te knoei.

## Verwysings

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [container escape via "masked path" abuse due to mount race conditions (GitHub Security Advisory)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [Tool Release – insject: A Linux Namespace Injector (NCC Group)](https://www.nccgroup.com/us/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../banners/hacktricks-training.md}}
