# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Konteks

Linux voer programme normaalweg uit uitvoerbare lêers uit wat op skyf of in geheue gestoor is. Dit kan ’n uitvoerbare lêer aan die hand van ’n padnaam of lêerbeskrywer identifiseer, dus is ’n gewone lêerstelselpadnaam nie altyd nodig nie.<sup>[[2]](#references)</sup>

DDexec / EverythingExec gebruik die geheue van ’n **reeds lopende proses**. Die [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md)-bladsy bespreek uitvoering van anonieme lêers en verwante opsporing en forensiese insameling; die [Memory Bypasses overview](index.html#memory-bypasses) skakel ook na MemExec en Memdlopen.<sup>[[1]](#references)</sup>

Met hierdie tegniek kan jy **algemene beskermingstegnieke soos leesalleen, noexec, lêernaam-whitelisting en hash-whitelisting omseil**.<sup>[[1]](#references)</sup>

## Afhanklikhede

Die finale script is afhanklik van die volgende nutsgoed om te werk; hulle moet toeganklik wees op die stelsel wat jy aanval (by verstek sal jy hulle oral kry):

```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```

## Die tegniek

As jy die geheue van ’n proses na willekeur kan wysig, kan jy dit oorneem. Dit kan gebruik word om ’n bestaande proses te kaap en met ’n ander program te vervang. Ons kan dit bereik deur óf die `ptrace()`-syscall te gebruik (waarvoor jy die vermoë moet hê om syscalls uit te voer, of `gdb` moet op die stelsel beskikbaar wees), óf, meer interessant, deur na `/proc/$pid/mem` te skryf.<sup>[[1]](#references)</sup>

Die lêer `/proc/$pid/mem` is ’n een-tot-een-kartering van die hele adresruimte van ’n proses (_bv._ van `0x0000000000000000` tot `0x7ffffffffffff000` in x86-64). Dit beteken dat lees vanaf of skryf na hierdie lêer by ’n offset `x` dieselfde is as lees vanaf of wysiging van die inhoud by die virtuele adres `x`.

Nou het ons vier basiese probleme om te hanteer:

- Oor die algemeen kan net root en die program se lêereienaar dit wysig.
- ASLR.
- As ons probeer om na ’n adres te lees of te skryf wat nie in die program se adresruimte gekarteer is nie, kry ons ’n I/O-fout.

Hierdie probleme het oplossings wat, hoewel dit nie perfek is nie, goed werk:

- Die meeste shell-interpreteerders laat jou toe om lêerbeskrywers te skep wat dan deur kinderprosesse geërf word. Ons kan ’n fd skep wat na die `mem`-lêer van die shell wys, met skryftoestemmings... sodat kinderprosesse wat daardie fd gebruik, die shell se geheue kan wysig.
- ASLR is nie eens ’n probleem nie; ons kan die shell se `maps`-lêer of enige ander lêer vanaf procfs nagaan om inligting oor die proses se adresruimte te bekom.
- Ons moet dus deur die lêer `lseek()`. Dit kan nie vanuit die shell gedoen word nie, tensy ons die berugte `dd` gebruik.

### In meer besonderhede

Die stappe is relatief eenvoudig en vereis geen spesifieke kundigheid om te verstaan nie:<sup>[[1]](#references)</sup>

- Ontleed die binary wat ons wil uitvoer en die loader om uit te vind watter karterings hulle benodig. Stel dan ’n "shell"code saam wat, breedweg gestel, dieselfde stappe uitvoer as wat die kernel met elke oproep na `execve()` uitvoer:
  - Skep die genoemde karterings.
  - Lees die binaries daarin.
  - Stel die toestemmings in.
  - Inisialiseer laastens die stack met die argumente vir die program en plaas die hulpvektor (wat die loader benodig).
  - Spring na die loader en laat dit die res doen (laai die biblioteke wat die program benodig).
- Kry uit die `syscall`-lêer die adres waarheen die proses sal terugkeer nadat die syscall wat dit uitvoer, klaar is.
- Oorskryf daardie plek, wat uitvoerbaar sal wees, met ons shellcode (via `mem` kan ons bladsye wysig waarop nie geskryf kan word nie).
- Gee die program wat ons wil uitvoer aan die stdin van die proses (dit sal deur die genoemde "shell"code gelees word met `read()`).
- Op hierdie punt is dit aan die loader om die nodige biblioteke vir ons program te laai en daarnaartoe te spring.

**Kyk na die nutsding by** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Daar is verskeie alternatiewe vir `dd`. Een daarvan, `tail`, is tans die verstekprogram wat gebruik word om deur die `mem`-lêer te `lseek()` (wat die enigste rede was om `dd` te gebruik). Die alternatiewe is:<sup>[[1]](#references)</sup>

```bash
tail
hexdump
cmp
xxd
```

Deur die `SEEKER`-veranderlike in te stel, kan jy die seeker wat gebruik word verander, _bv._:

```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

As jy nog ’n geldige seeker vind wat nie in die script geïmplementeer is nie, kan jy dit steeds gebruik deur die `SEEKER_ARGS`-veranderlike in te stel:

```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

Blokkeer dit, EDR's.

## References

- [1] [DDexec: ’n Tegniek om binêre lêers lêerloos en ongemerk op Linux uit te voer](https://github.com/arget13/DDexec)
- [2] [execveat(2) — Linux-handleidingbladsy](https://manpages.debian.org/trixie/manpages-dev/execveat.2.en.html)
{{#include ../../../../banners/hacktricks-training.md}}
