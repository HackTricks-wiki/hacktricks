# User Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

'n gebruikersnaamruimte is 'n Linux-kernkenmerk wat **isolasie van gebruikers- en groep ID-kaartings** bied, wat elke gebruikersnaamruimte toelaat om sy **eie stel gebruikers- en groep ID's** te hê. Hierdie isolasie stel prosesse wat in verskillende gebruikersnaamruimtes loop in staat om **verskillende bevoegdhede en eienaarskap** te hê, selfs al deel hulle dieselfde gebruikers- en groep ID's numeries.

Gebruikersnaamruimtes is veral nuttig in houers, waar elke houer sy eie onafhanklike stel gebruikers- en groep ID's moet hê, wat beter sekuriteit en isolasie tussen houers en die gasheerstelsel moontlik maak.

### How it works:

1. Wanneer 'n nuwe gebruikersnaamruimte geskep word, **begin dit met 'n leë stel gebruikers- en groep ID-kaartings**. Dit beteken dat enige proses wat in die nuwe gebruikersnaamruimte loop, **aanvanklik geen bevoegdhede buite die naamruimte sal hê**.
2. ID-kaartings kan gevestig word tussen die gebruikers- en groep ID's in die nuwe naamruimte en dié in die ouer (of gasheer) naamruimte. Dit **laat prosesse in die nuwe naamruimte toe om bevoegdhede en eienaarskap te hê wat ooreenstem met gebruikers- en groep ID's in die ouer naamruimte**. Die ID-kaartings kan egter beperk word tot spesifieke reekse en substelle van ID's, wat fynbeheer oor die bevoegdhede wat aan prosesse in die nuwe naamruimte toegeken word, moontlik maak.
3. Binne 'n gebruikersnaamruimte kan **prosesse volle wortelbevoegdhede (UID 0) hê vir operasies binne die naamruimte**, terwyl hulle steeds beperkte bevoegdhede buite die naamruimte het. Dit laat **houers toe om met wortelagtige vermoëns binne hul eie naamruimte te loop sonder om volle wortelbevoegdhede op die gasheerstelsel te hê**.
4. Prosesse kan tussen naamruimtes beweeg deur die `setns()` stelselskakel of nuwe naamruimtes skep deur die `unshare()` of `clone()` stelselskakels met die `CLONE_NEWUSER` vlag. Wanneer 'n proses na 'n nuwe naamruimte beweeg of een skep, sal dit begin om die gebruikers- en groep ID-kaartings wat met daardie naamruimte geassosieer word, te gebruik.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Deur 'n nuwe instansie van die `/proc` lêerstelsel te monteer as jy die parameter `--mount-proc` gebruik, verseker jy dat die nuwe monteer-namespas 'n **akkurate en geïsoleerde siening van die prosesinligting spesifiek vir daardie namespas** het.

<details>

<summary>Fout: bash: fork: Kan nie geheue toewys nie</summary>

Wanneer `unshare` sonder die `-f` opsie uitgevoer word, word 'n fout ondervind weens die manier waarop Linux nuwe PID (Proses ID) namespase hanteer. Die sleutelbesonderhede en die oplossing word hieronder uiteengesit:

1. **Probleemverklaring**:

- Die Linux-kern laat 'n proses toe om nuwe namespase te skep met behulp van die `unshare` stelselaanroep. Die proses wat die skepping van 'n nuwe PID namespas inisieer (genoem die "unshare" proses) gaan egter nie in die nuwe namespas nie; slegs sy kindproses gaan.
- Die uitvoering van `%unshare -p /bin/bash%` begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy kindproses in die oorspronklike PID namespas.
- Die eerste kindproses van `/bin/bash` in die nuwe namespas word PID 1. Wanneer hierdie proses verlaat, veroorsaak dit die opruiming van die namespas as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weeskindprosesse aan te neem. Die Linux-kern sal dan PID-toewysing in daardie namespas deaktiveer.

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
```
Om die gebruikersnaamruimte te gebruik, moet die Docker-daemon begin word met **`--userns-remap=default`** (In ubuntu 14.04 kan dit gedoen word deur `/etc/default/docker` te wysig en dan `sudo service docker restart` uit te voer)

### &#x20;Kontroleer in watter naamruimte jou proses is
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Dit is moontlik om die gebruikerskaart vanaf die docker-container te kontroleer met:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Of van die gasheer met:
```bash
cat /proc/<pid>/uid_map
```
### Vind alle Gebruiker name ruimtes
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Gaan binne 'n Gebruiker-namespace in
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Ook, jy kan slegs **in 'n ander prosesnaamruimte ingaan as jy root is**. En jy **kan nie** **ingaan** in 'n ander naamruimte **sonder 'n beskrywer** wat daarna verwys nie (soos `/proc/self/ns/user`).

### Skep nuwe Gebruiker naamruimte (met kaartings)
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Herwinning van Vermoëns

In die geval van gebruikersname ruimtes, **wanneer 'n nuwe gebruikersnaam ruimte geskep word, word die proses wat in die naamruimte ingaan 'n volle stel vermoëns binne daardie naamruimte toegeken**. Hierdie vermoëns stel die proses in staat om bevoorregte operasies uit te voer soos **montage** **lêerstelsels**, die skep van toestelle, of die verandering van eienaarskap van lêers, maar **slegs binne die konteks van sy gebruikersnaam ruimte**.

Byvoorbeeld, wanneer jy die `CAP_SYS_ADMIN` vermoë binne 'n gebruikersnaam ruimte het, kan jy operasies uitvoer wat tipies hierdie vermoë vereis, soos die montering van lêerstelsels, maar slegs binne die konteks van jou gebruikersnaam ruimte. Enige operasies wat jy met hierdie vermoë uitvoer, sal nie die gasheerstelsel of ander naamruimtes beïnvloed nie.

> [!WARNING]
> Daarom, selfs al sal die verkryging van 'n nuwe proses binne 'n nuwe gebruikersnaam ruimte **jou al die vermoëns teruggee** (CapEff: 000001ffffffffff), kan jy eintlik **slegs diegene wat met die naamruimte verband hou gebruik** (montage byvoorbeeld) maar nie elkeen nie. So, dit op sigself is nie genoeg om uit 'n Docker houer te ontsnap nie.
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#include ../../../../banners/hacktricks-training.md}}
