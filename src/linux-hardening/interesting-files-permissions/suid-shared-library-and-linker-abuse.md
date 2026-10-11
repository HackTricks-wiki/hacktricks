# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID-binaries word gewoonlik nagegaan vir direkte opdraguitvoering, maar pasgemaakte SUID-programme kan ook kwesbaar wees deur die dynamic linker. Die algemene tema is eenvoudig: ’n bevoorregte uitvoerbare lêer laai kode vanaf ’n pad of konfigurasie wat ’n gebruiker met minder voorregte kan beïnvloed.<sup>[[1]](#references)</sup>

Hierdie bladsy fokus op generiese tegniekpatrone: ontbrekende libraries, skryfbare library-gidse, `RPATH`/`RUNPATH`, `LD_PRELOAD` deur sudo, linker-konfigurasie en verwarring oor SUID-hardlinks.

Sien [ELF basic information](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) vir die ELF-programopskrifte, dynamic section en loader-gedrag agter hierdie kontroles.

## Vinnige enumerasie

Begin deur ongewone SUID-lêers te vind en te kyk of hulle dinamies gekoppel is:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

Gebruik `readelf` vir ’n onbekende uitvoerbare lêer: [`ldd` kan ’n onbetroubare ELF-interpreter uitvoer](https://man7.org/linux/man-pages/man1/ldd.1.html). `readelf` wys direkte afhanklikhede, bevestig dus apart die pad wat die loader werklik kies.<sup>[[1]](#references)[[3]](#references)</sup>

Fokus op nie-standaardliggings, pasgemaakte toepassingspaaie, binaries wat deur root besit word maar buite pakketbestuurde gidse lê, en afhanklikhede wat vanaf skryfbare gidse gelaai word.<sup>[[1]](#references)</sup>

Nuttige skryfbaarheidstoetse:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

Sommige pasgemaakte SUID-binêre lêers probeer ’n shared object laai wat nie bestaan nie. As die ontbrekende pad onder ’n gids is wat deur die aanvaller beheer word, kan die binêre lêer kode laai wat deur die aanvaller verskaf is, as die effektiewe gebruiker.<sup>[[1]](#references)</sup>

Dieselfde grens geld vir ’n **pasgemaakte binêre lêer wat via sudo toegelaat word** wanneer dit `dlopen()` op ’n absolute `.so`-pad onder ’n tuis- of konfigurasiegids skryfbaar deur die aanroeper aanroep. Hierdie laat biblioteeklading kan ontbreek in `ldd`-uitvoer en ELF `NEEDED`-inskrywings. ’n Beperkte hersiening van `strings` of ’n spoor van ’n **onbevoorregte** aanroeping kan die poging tot toegang tot die pad onthul; ’n toepassingswagwoord of kieslyskeuse kan hierdie opsoekaksie beheer. Bevestig die effektiewe sudo-reël, die presiese pad en die toestemmings op die ouergids, en dat die bevoorregte aanroeping daardie opsoekaksie bereik voordat jy dit as eskalasie beskou. Moenie die sudo-teiken bloot aanroep om dit te inventariseer nie.

Vind mislukte biblioteekopsoeke met `strace` se syscall-filter:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

As die binêre lêer ’n skryfbare pad vir `libexample.so` deursoek, kan ’n minimale bewysbiblioteek ’n constructor gebruik. Hou die bewys van impak skadeloos tydens validering:<sup>[[6]](#references)</sup>

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

Die uitbuitbare toestand is nie bloot die ontbrekende library nie. Die aanvaller moet ’n versoenbare shared object kan plaas by ’n pad wat die bevoorregte loader sal aanvaar.<sup>[[1]](#references)</sup>

## Skryfbare Library-gids

Soms bestaan al die dependencies, maar is een van die gidse wat gebruik word om hulle op te spoor skryfbaar. Dit kan dit moontlik maak om ’n gelaaide library te vervang of ’n library met dieselfde naam en hoër prioriteit te plaas.<sup>[[1]](#references)</sup>

Dieselfde ondersoek geld vir ’n pasgemaakte ELF wat **deur sudo toegelaat word**, selfs wanneer die ELF geen SUID-bit het nie en die toegelate RunAs-rekening nie root is nie. Vergelyk sy `DT_NEEDED`-inskrywings met die library-padnaam wat die loader sal gebruik; kyk dan of die gebruiker daardie lêer kan skryf of dit deur ’n skryfbare, deursoekbare ouergids kan vervang. Bevestig die presiese sudo RunAs-reël, simboliese skakels en ACL’s, loader-beleid, en dat die teikenproses die library as die rekening met hoër voorregte laai. ’n Skryfbare `.so` of ’n dependency-naam alleen is net ’n leidraad; ondersoek die metadata sonder om die sudo-opdrag uit te voer.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Ondersoek dependency-paaie:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

As die gids skryfbaar is, valideer dit met ’n kopieveilige benadering in ’n lab. Die vervanging van stelselbiblioteke op ’n aktiewe gasheer kan daartoe lei dat prosesse wat terselfdertyd begin, teenstrydige biblioteekweergawes gebruik.<sup>[[8]](#references)</sup>

### Skryfbare biblioteke binne ’n chroot

’n chroot alleen sluit nie geërfde lêerbeskrywers nie en beperk ook nie alle toegang tot die lêerstelsel nie. As ’n sandbox ’n gidsbeskrywer laat wys na ’n plek buite sy nuwe wortel, en die ingeperkte proses daardie beskrywer kan dereferensieer (byvoorbeeld deur ’n toeganklike `/proc/<pid>/fd/`-inskrywing), kan gasheerpaaie steeds bereikbaar wees. Dit is ’n lêerstelselgrenskwessie; dit verleen op sigself nie root-voorregte nie.<sup>[[11]](#references)[[12]](#references)</sup>

Kontroleer afsonderlik of die ingeperkte gebruiker kan skryf na ’n biblioteekgids wat ’n **gasheer se root-SUID-uitvoerbare lêer** sal gebruik wanneer dit vanuit die jail geloods word. Die loader bepaal afhanklikhede volgens die proses se lêerstelsel-aansig, dus kan ’n aanvaller-beheerde biblioteek daar uitgevoer word met die SUID-program se effektiewe identiteit. Bevestig die presiese uitvoerbare lêer, sy SUID-bis en mount-beleid, die beskrywer se teiken en toegangstoestemmings, die jail se biblioteeksoekpad, en dat die program werklik toegang tot die gasheer se uitvoerbare lêer kan kry. ’n Lêervermoë op die sandbox-launcher, ’n skryfbare jail of ’n gasheer-SUID-binêre lêer alleen is net ’n leidraad; die volledige ketting hang af van die sandbox se implementering.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH and RUNPATH

`RPATH` en `RUNPATH` is inskrywings in die dinamiese afdeling wat die loader vertel waar om na biblioteke te soek. Hulle is gevaarlik in SUID-programme wanneer hulle na gidsse wys waarop aanvallers kan skryf.<sup>[[1]](#references)</sup>

Spoor hulle op:<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

Voorbeeld van riskante uitvoer:

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

As `/opt/app/lib` skryfbaar is en die binêre lêer `libcustom.so` benodig, kan die aanvaller moontlik ’n kwaadwillige `libcustom.so` daar plaas:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` en `RUNPATH` is nie in alle resolusiebesonderhede identies nie, maar vir ’n voorreg-eskalasie-oorsig is die praktiese vraag dieselfde: soek die SUID-binêre lêer in ’n gids wat deur ’n aanvaller geskryf kan word vir ’n biblioteeknaam?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH en SUID

Vir gewone programme kan `LD_PRELOAD` en `LD_LIBRARY_PATH` die laai van gedeelde objeklêers afdwing of beïnvloed. Vir SUID-programme tree die dinamiese laaier gewoonlik in veilige-uitvoeringsmodus en ignoreer gevaarlike omgewingsveranderlikes.<sup>[[1]](#references)</sup>

Dit beteken dat ’n gewone SUID-binêre lêer gewoonlik nie kwesbaar is bloot omdat die gebruiker `LD_PRELOAD` kan stel nie:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

Die algemene uitsondering is ’n sudo-beleid wat ’n omgewingsveranderlike-toekenning op die opdragreël vir die teiken toelaat, soos ’n `SETENV`-merker of toepaslike `setenv`-opsie. As die teiken dinamies geskakel is en sudo `LD_PRELOAD=/path/to/library` aanvaar, kan die teiken kode laai waaroor die oproeper beheer het. Gaan die effektiewe reël en teikenidentiteit na. Om bloot `LD_PRELOAD` by `env_keep` te voeg, is nie voldoende op stelsels waar die dinamiese laaier ’n geërfde `LD_PRELOAD` verwyder voordat die SUID `sudo`-proses begin nie; sudo verwerk ’n toekenning op die opdragreël ná sy eie opstart.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Moenie hierdie gevalle verwar nie; die loader- en sudo-beleëidsreëls hierbo onderskei hulle:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` teen ’n normale SUID-binary: word gewoonlik deur secure execution geblokkeer.
- `LD_PRELOAD` wat as ’n sudo-opdragreëltoewysing vir ’n bevoorregte, dinamies-gekoppelde teiken aanvaar word: moontlik uitbuitbaar.
- Ontbrekende `.so` in ’n skryfbare pad: uitbuitbaar wanneer die SUID-binary daardie pad natuurlik laai.
- `RPATH`/`RUNPATH` na ’n skryfbare gids: uitbuitbaar wanneer ’n vereiste library beheer kan word.
- Skryftoegang tot `/etc/ld.so.preload` of linker-konfigurasie: raak die hele stelsel en het ’n groot impak.

## Linker-konfigurasie

`ld.so` gebruik die linker-cache en `/etc/ld.so.preload`; `ldconfig` bou daardie cache uit `/etc/ld.so.conf` en lêers wat daaruit ingesluit word, gewoonlik uit `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Kontroles met hoë waarde:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Skryfbare linker-konfigurasie is gewoonlik ernstiger as ’n enkele kwesbare SUID-binêre lêer, omdat dit baie dinamies gekoppelde prosesse kan beïnvloed. `/etc/ld.so.preload` is besonder gevaarlik, omdat dit ’n shared object in geprivilegieerde prosesse kan forseer.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID-hardlinkverwarring

Hardlinks kan veroorsaak dat dieselfde SUID-inode onder verskeie name verskyn.<sup>[[9]](#references)</sup> Dit is nuttig om ’n geprivilegieerde helper weg te steek, opruiming te bemoeilik of naïewe padgebaseerde ondersoeke te omseil.

Vind SUID-lêers met meer as een skakel:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Inspekteer alle paaie na dieselfde inode:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

Die misbruik bestaan nie daarin dat ’n hardlink toestemmings verander nie. Dit is padverwarring: ’n bevoorregte inode kan bereikbaar wees via ’n naam wat verdedigers of skripte nie verwag nie.<sup>[[9]](#references)</sup> Vir ’n dieper bespreking van inode- en hardlink-werkvloei, sien [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Verdedigende notas

- Hou SUID-binaries minimaal, geouditeer en, waar moontlik, deur pakkette bestuur.
- Vermy `RPATH`/`RUNPATH`-inskrywings wat na skryfbare of toepassingsbestuurde gidse wys.<sup>[[1]](#references)[[8]](#references)</sup>
- Hou biblioteekgidse in root se besit en maak dit nie skryfbaar vir gewone gebruikers nie.<sup>[[8]](#references)</sup>
- Moenie `LD_PRELOAD`, `LD_LIBRARY_PATH` of soortgelyke loader-veranderlikes via sudo behou nie.<sup>[[1]](#references)[[5]](#references)</sup>
- Monitor `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` en onverwagte SUID-lêers.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Gaan hardlinked SUID-lêers na en ondersoek pasgemaakte SUID-wrappers buite standaardstelselpaaie.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux-handleidingbladsy](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Algemene eienskappe (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dinamiese skakelaar-verharding (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
