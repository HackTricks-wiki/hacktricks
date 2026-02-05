# UTS Naamruimte

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

'n UTS (UNIX Time-Sharing System) naamruimte is 'n Linux kernel-funksie wat i**skeiding van twee stelselidentiteite** bied: die **hostname** en die **NIS** (Network Information Service) domeinnaam. Hierdie isolasie laat elke UTS naamruimte toe om sy **eie onafhanklike hostname en NIS domeinnaam** te hê, wat veral nuttig is in containerization scenario's waar elke kontener as 'n aparte stelsel met sy eie hostname behoort voor te kom.

### Hoe dit werk:

1. Wanneer 'n nuwe UTS naamruimte geskep word, begin dit met 'n **kopie van die hostname en NIS domeinnaam van sy ouer naamruimte**. Dit beteken dat, by skepping, die nuwe naamruimte s**deel dieselfde identifiseerders as sy ouer**. Enige latere veranderinge aan die hostname of NIS domeinnaam binne die naamruimte sal egter nie ander naamruimtes beïnvloed nie.
2. Prosesse binne 'n UTS naamruimte **kan die hostname en NIS domeinnaam verander** deur die `sethostname()` en `setdomainname()` stelseloproepe onderskeidelik te gebruik. Hierdie veranderinge is lokaal tot die naamruimte en beïnvloed nie ander naamruimtes of die gasheerstelsel nie.
3. Prosesse kan tussen naamruimtes beweeg deur die `setns()` stelseloproep te gebruik of nuwe naamruimtes skep deur die `unshare()` of `clone()` stelseloproepe te gebruik met die `CLONE_NEWUTS` vlag. Wanneer 'n proses na 'n nuwe naamruimte beweeg of een skep, sal dit begin om die hostname en NIS domeinnaam te gebruik wat met daardie naamruimte geassosieer word.

## Lab:

### Skep verskillende Naamruimtes

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **akkurate en geïsoleerde siening van die prosesinligting wat spesifiek is vir daardie namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Wanneer `unshare` uitgevoer word sonder die `-f` opsie, word 'n fout ervaar weens die wyse waarop Linux nuwe PID (Process ID) namespaces hanteer. Die sleutelbesonderhede en die oplossing word hieronder uiteengesit:

1. **Probleembeskrywing**:

- Die Linux-kern laat 'n proses toe om nuwe namespaces te skep deur die `unshare` stelseloproep. Die proses wat die skepping van 'n nuwe PID namespace inisieer (verwys as die "unshare" proses) gaan egter nie in die nuwe namespace in nie; slegs sy child-processes doen dit.
- Die uitvoering van `%unshare -p /bin/bash%` begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy child-processes in die oorspronklike PID namespace.
- Die eerste child-proses van `/bin/bash` in die nuwe namespace word PID 1. Wanneer hierdie proses uitgaan, lei dit tot die skoonmaak van die namespace as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weesprosesse te aanvaar. Die Linux-kern sal dan PID-toewysing in daardie namespace deaktiveer.

2. **Gevolg**:

- Die uittrede van PID 1 in 'n nuwe namespace lei tot die skoonmaak van die `PIDNS_HASH_ADDING` vlag. Dit veroorsaak dat die `alloc_pid` funksie misluk om 'n nuwe PID toe te wys wanneer 'n nuwe proses geskep word, wat die "Cannot allocate memory" fout produseer.

3. **Oplossing**:
- Die probleem kan opgelos word deur die `-f` opsie saam met `unshare` te gebruik. Hierdie opsie laat `unshare` 'n nuwe proses fork nadat dit die nuwe PID namespace geskep het.
- Die uitvoering van `%unshare -fp /bin/bash%` verseker dat die `unshare` opdrag self PID 1 in die nuwe namespace word. `/bin/bash` en sy child-processes word dan veilig binne hierdie nuwe namespace bevat, wat die voortydige uittrede van PID 1 voorkom en normale PID-toewysing toelaat.

Deur te verseker dat `unshare` met die `-f` vlag loop, word die nuwe PID namespace korrek gehandhaaf, wat toelaat dat `/bin/bash` en sy sub-prosesse funksioneer sonder om die geheue-toewysingsfout te ervaar.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Kyk in watter namespace jou proses is
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Vind alle UTS-naamruimtes
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Betree 'n UTS namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Misbruik van gedeelde host UTS

Indien 'n container met `--uts=host` gestart word, sluit dit by die host UTS namespace aan in plaas daarvan om 'n geïsoleerde een te kry. Met capabilities soos `--cap-add SYS_ADMIN` kan kode in die container die host hostname/NIS name verander via `sethostname()`/`setdomainname()`:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Om die hostnaam te verander kan logs/waarskuwings manipuleer, klusterontdekking verwar of TLS/SSH-konfigurasies wat aan die hostnaam vasgemaak is, breek.

### Detecteer containers wat UTS met die gasheer deel
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
