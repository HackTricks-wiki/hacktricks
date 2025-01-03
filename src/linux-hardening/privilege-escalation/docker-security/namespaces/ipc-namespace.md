# IPC Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

'n IPC (Inter-Process Communication) namespace is 'n Linux-kernfunksie wat **isolasie** van System V IPC-objekte bied, soos boodskapqueues, gedeelde geheue-segmente en semafore. Hierdie isolasie verseker dat prosesse in **verskillende IPC namespaces nie direk toegang kan verkry tot of mekaar se IPC-objekte kan verander nie**, wat 'n addisionele laag van sekuriteit en privaatheid tussen prosesgroepe bied.

### Hoe dit werk:

1. Wanneer 'n nuwe IPC namespace geskep word, begin dit met 'n **heeltemal geïsoleerde stel van System V IPC-objekte**. Dit beteken dat prosesse wat in die nuwe IPC namespace loop nie toegang kan verkry tot of inmeng met die IPC-objekte in ander namespaces of die gasheerstelsel nie, per standaard.
2. IPC-objekte wat binne 'n namespace geskep word, is sigbaar en **slegs toeganklik vir prosesse binne daardie namespace**. Elke IPC-objek word geïdentifiseer deur 'n unieke sleutel binne sy namespace. Alhoewel die sleutel identies mag wees in verskillende namespaces, is die objekte self geïsoleer en kan nie oor namespaces toeganklik wees nie.
3. Prosesse kan tussen namespaces beweeg deur die `setns()` stelselskakel of nuwe namespaces skep deur die `unshare()` of `clone()` stelselskakels met die `CLONE_NEWIPC` vlag. Wanneer 'n proses na 'n nuwe namespace beweeg of een skep, sal dit begin om die IPC-objekte wat met daardie namespace geassosieer is, te gebruik.

## Laboratorium:

### Skep verskillende Namespaces

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
Deur 'n nuwe instansie van die `/proc` lêerstelsel te monteer as jy die parameter `--mount-proc` gebruik, verseker jy dat die nuwe monteernaamruimte 'n **akkurate en geïsoleerde weergawe van die prosesinligting spesifiek vir daardie naamruimte** het.

<details>

<summary>Fout: bash: fork: Kan nie geheue toewys nie</summary>

Wanneer `unshare` sonder die `-f` opsie uitgevoer word, word 'n fout ondervind weens die manier waarop Linux nuwe PID (Proses ID) naamruimtes hanteer. Die sleutelbesonderhede en die oplossing word hieronder uiteengesit:

1. **Probleemverklaring**:

- Die Linux-kern laat 'n proses toe om nuwe naamruimtes te skep met die `unshare` stelselaanroep. Die proses wat die skepping van 'n nuwe PID naamruimte inisieer (genoem die "unshare" proses) gaan egter nie in die nuwe naamruimte in nie; slegs sy kindprosesse doen.
- Om `%unshare -p /bin/bash%` uit te voer, begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy kindprosesse in die oorspronklike PID naamruimte.
- Die eerste kindproses van `/bin/bash` in die nuwe naamruimte word PID 1. Wanneer hierdie proses verlaat, aktiveer dit die opruiming van die naamruimte as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weeskindprosesse aan te neem. Die Linux-kern sal dan PID-toewysing in daardie naamruimte deaktiveer.

2. **Gevolg**:

- Die uitgang van PID 1 in 'n nuwe naamruimte lei tot die opruiming van die `PIDNS_HASH_ADDING` vlag. Dit lei tot die `alloc_pid` funksie wat misluk om 'n nuwe PID toe te wys wanneer 'n nuwe proses geskep word, wat die "Kan nie geheue toewys nie" fout veroorsaak.

3. **Oplossing**:
- Die probleem kan opgelos word deur die `-f` opsie saam met `unshare` te gebruik. Hierdie opsie maak dat `unshare` 'n nuwe proses fork nadat die nuwe PID naamruimte geskep is.
- Om `%unshare -fp /bin/bash%` uit te voer, verseker dat die `unshare` opdrag self PID 1 in die nuwe naamruimte word. `/bin/bash` en sy kindprosesse is dan veilig binne hierdie nuwe naamruimte, wat die voortydige uitgang van PID 1 voorkom en normale PID-toewysing toelaat.

Deur te verseker dat `unshare` met die `-f` vlag loop, word die nuwe PID naamruimte korrek gehandhaaf, wat toelaat dat `/bin/bash` en sy subprosesse funksioneer sonder om die geheue toewysing fout te ondervind.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Kontroleer in watter naamruimte jou proses is
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Vind alle IPC-namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Gaan binne 'n IPC-naamruimte in
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
Ook, jy kan slegs **in 'n ander prosesnaamruimte ingaan as jy root is**. En jy **kan nie** **ingaan** in 'n ander naamruimte **sonder 'n beskrywer** wat daarna verwys nie (soos `/proc/self/ns/net`).

### Skep IPC objek
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## Verwysings

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
