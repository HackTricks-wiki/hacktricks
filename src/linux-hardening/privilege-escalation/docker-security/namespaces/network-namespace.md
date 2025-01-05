# Netwerk Naamruimte

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

'n Netwerk naamruimte is 'n Linux-kernkenmerk wat isolasie van die netwerkstapel bied, wat **elke netwerk naamruimte in staat stel om sy eie onafhanklike netwerkkonfigurasie** te hê, interfaces, IP-adresse, routeringstabelle en firewall-reëls. Hierdie isolasie is nuttig in verskeie scenario's, soos containerisering, waar elke houer sy eie netwerkkonfigurasie moet hê, onafhanklik van ander houers en die gasheerstelsel.

### Hoe dit werk:

1. Wanneer 'n nuwe netwerk naamruimte geskep word, begin dit met 'n **heeltemal geïsoleerde netwerkstapel**, met **geen netwerkinterfaces** behalwe vir die loopback-interface (lo). Dit beteken dat prosesse wat in die nuwe netwerk naamruimte loop nie met prosesse in ander naamruimtes of die gasheerstelsel kan kommunikeer nie, behalwe as 'n spesifieke konfigurasie gemaak word.
2. **Virtuele netwerkinterfaces**, soos veth pare, kan geskep en tussen netwerk naamruimtes beweeg word. Dit maak dit moontlik om netwerkverbinding te vestig tussen naamruimtes of tussen 'n naamruimte en die gasheerstelsel. Byvoorbeeld, een einde van 'n veth paar kan in 'n houer se netwerk naamruimte geplaas word, en die ander einde kan aan 'n **brug** of 'n ander netwerkinterface in die gasheer naamruimte gekoppel word, wat netwerkverbinding aan die houer bied.
3. Netwerkinterfaces binne 'n naamruimte kan hul **eie IP-adresse, routeringstabelle en firewall-reëls** hê, onafhanklik van ander naamruimtes. Dit laat prosesse in verskillende netwerk naamruimtes toe om verskillende netwerk konfigurasies te hê en te werk asof hulle op aparte netwerkstelsels loop.
4. Prosesse kan tussen naamruimtes beweeg deur die `setns()` stelselskakel te gebruik, of nuwe naamruimtes te skep deur die `unshare()` of `clone()` stelselskakels met die `CLONE_NEWNET` vlag. Wanneer 'n proses na 'n nuwe naamruimte beweeg of een skep, sal dit begin om die netwerk konfigurasie en interfaces wat met daardie naamruimte geassosieer word, te gebruik.

## Laboratorium:

### Skep verskillende Naamruimtes

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
Deur 'n nuwe instansie van die `/proc` lêerstelsel te monteer as jy die parameter `--mount-proc` gebruik, verseker jy dat die nuwe monteer-namespas 'n **akkurate en geïsoleerde weergawe van die prosesinligting spesifiek vir daardie namespas** het.

<details>

<summary>Fout: bash: fork: Kan nie geheue toewys nie</summary>

Wanneer `unshare` sonder die `-f` opsie uitgevoer word, word 'n fout ondervind weens die manier waarop Linux nuwe PID (Proses ID) namespase hanteer. Die sleutelbesonderhede en die oplossing word hieronder uiteengesit:

1. **Probleemverklaring**:

- Die Linux-kern laat 'n proses toe om nuwe namespase te skep met behulp van die `unshare` stelselaanroep. Die proses wat die skepping van 'n nuwe PID namespas inisieer (genoem die "unshare" proses) tree egter nie in die nuwe namespas in nie; slegs sy kindproses doen.
- Die uitvoering van `%unshare -p /bin/bash%` begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy kindproses in die oorspronklike PID namespas.
- Die eerste kindproses van `/bin/bash` in die nuwe namespas word PID 1. Wanneer hierdie proses verlaat, veroorsaak dit die opruiming van die namespas as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weesprosesse aan te neem. Die Linux-kern sal dan PID-toewysing in daardie namespas deaktiveer.

2. **Gevolg**:

- Die uitgang van PID 1 in 'n nuwe namespas lei tot die opruiming van die `PIDNS_HASH_ADDING` vlag. Dit lei tot die `alloc_pid` funksie wat misluk om 'n nuwe PID toe te wys wanneer 'n nuwe proses geskep word, wat die "Kan nie geheue toewys nie" fout veroorsaak.

3. **Oplossing**:
- Die probleem kan opgelos word deur die `-f` opsie saam met `unshare` te gebruik. Hierdie opsie maak dat `unshare` 'n nuwe proses fork nadat die nuwe PID namespas geskep is.
- Die uitvoering van `%unshare -fp /bin/bash%` verseker dat die `unshare` opdrag self PID 1 in die nuwe namespas word. `/bin/bash` en sy kindproses is dan veilig binne hierdie nuwe namespas, wat die voortydige uitgang van PID 1 voorkom en normale PID-toewysing toelaat.

Deur te verseker dat `unshare` met die `-f` vlag loop, word die nuwe PID namespas korrek gehandhaaf, wat toelaat dat `/bin/bash` en sy sub-prosesse funksioneer sonder om die geheue toewysing fout te ondervind.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### Kontroleer in watter naamruimte jou proses is
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Vind alle Netwerk-namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Gaan binne 'n Netwerk-namespace in
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Ook, jy kan slegs **in 'n ander prosesnaamruimte ingaan as jy root is**. En jy **kan nie** **ingaan** in 'n ander naamruimte **sonder 'n beskrywer** wat daarna verwys nie (soos `/proc/self/ns/net`).

## Verwysings

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
