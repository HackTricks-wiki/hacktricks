# DDexec / EverythingExec

## Konteks

In Linux moet 'n program as 'n lêer bestaan om dit te kan uitvoer, en dit moet op een of ander manier deur die lêerstelselhiërargie toeganklik wees (dit is bloot hoe `execve()` werk). Hierdie lêer kan op skyf of in ram (tmpfs, memfd) wees, maar jy het 'n lêerpad nodig. Dit het dit baie maklik gemaak om te beheer wat op 'n Linux-stelsel uitgevoer word, en dit maak dit maklik om threats en 'n aanvaller se tools op te spoor, of om te voorkom dat hulle hoegenaamd enigiets van hul eie probeer uitvoer (_bv._ om nie toe te laat dat unprivileged users uitvoerbare lêers enige plek plaas nie).

Maar hierdie technique is hier om dit alles te verander. As jy nie die process wat jy wil hê kan start nie... **dan hijack jy een wat reeds bestaan**.

Hierdie technique laat jou toe om **algemene protection techniques soos read-only, noexec, file-name whitelisting en hash whitelisting te bypass**.<sup>[[1]](#references)</sup>

## Afhanklikhede

Die finale script hang van die volgende tools af om te werk; hulle moet toeganklik wees in die system wat jy aanval (by verstek sal jy almal van hulle oral vind):
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

As jy die geheue van ’n proses arbitrêr kan wysig, kan jy dit oorneem. Dit kan gebruik word om ’n reeds bestaande proses te kaap en dit met ’n ander program te vervang. Ons kan dit bereik deur óf die `ptrace()`-syscall te gebruik (waarvoor jy die vermoë moet hê om syscalls uit te voer, of gdb moet op die stelsel beskikbaar wees), óf, interessanter, deur na `/proc/$pid/mem` te skryf.<sup>[[1]](#references)</sup>

Die lêer `/proc/$pid/mem` is ’n een-tot-een-kartering van die volledige adresruimte van ’n proses (_bv._ van `0x0000000000000000` tot `0x7ffffffffffff000` in x86-64). Dit beteken dat lees vanaf of skryf na hierdie lêer by ’n offset `x` dieselfde is as om die inhoud by die virtuele adres `x` te lees of te wysig.

Ons het nou vier basiese probleme om te hanteer:

- Oor die algemeen mag slegs root en die program-eienaar van die lêer dit wysig.
- ASLR.
- As ons probeer om na ’n adres te lees of te skryf wat nie in die adresruimte van die program gekarteer is nie, sal ons ’n I/O-fout kry.

Hierdie probleme het oplossings wat, hoewel hulle nie perfek is nie, goed werk:

- Die meeste shell-interpreters laat die skepping toe van file descriptors wat dan deur child processes geërf word. Ons kan ’n fd skep wat met skryftoestemmings na die `mem`-lêer van die shell wys... dus sal child processes wat daardie fd gebruik, die shell se geheue kan wysig.
- ASLR is nie eens ’n probleem nie; ons kan die shell se `maps`-lêer of enige ander lêer uit procfs nagaan om inligting oor die proses se adresruimte te bekom.
- Ons moet dus `lseek()` oor die lêer uitvoer. Vanuit die shell kan dit nie gedoen word nie, tensy ons die berugte `dd` gebruik.

### In meer besonderhede

Die stappe is relatief maklik en vereis geen besondere kundigheid om dit te verstaan nie:<sup>[[1]](#references)</sup>

- Parse die binary wat ons wil uitvoer en die loader om uit te vind watter mappings hulle benodig. Skep dan ’n "shell"code wat, breedweg gesproke, dieselfde stappe sal uitvoer as wat die kernel doen tydens elke oproep na `execve()`:
- Skep die genoemde mappings.
- Lees die binaries daarin.
- Stel die toestemmings op.
- Initialiseer laastens die stack met die argumente vir die program en plaas die auxiliary vector daarin (wat deur die loader benodig word).
- Spring na die loader en laat dit die res doen (laai die libraries wat die program benodig).
- Verkry uit die `syscall`-lêer die adres waarheen die proses sal terugkeer nadat die syscall wat dit uitvoer, voltooi is.
- Oorskryf daardie plek, wat uitvoerbaar sal wees, met ons shellcode (deur `mem` kan ons unwritable pages wysig).
- Gee die program wat ons wil uitvoer aan die stdin van die proses (dit sal deur genoemde "shell"code `read()` word).
- Op hierdie punt is dit die loader se taak om die nodige libraries vir ons program te laai en daarnaartoe te spring.

**Kyk na die tool by** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Daar is verskeie alternatiewe vir `dd`, waarvan `tail` een is. Dit is tans die verstekprogram wat gebruik word om deur die `mem`-lêer te `lseek()` (wat die enigste doel was waarvoor `dd` gebruik is). Hierdie alternatiewe is:<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
Deur die veranderlike `SEEKER` te stel, kan jy die seeker wat gebruik word verander, _bv._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Indien jy nog ’n geldige seeker vind wat nie in die script geïmplementeer is nie, kan jy dit steeds gebruik deur die `SEEKER_ARGS`-veranderlike te stel:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blokkeer dit, EDR's.

## References

- [1] [DDexec: 'n Tegniek om binaries sonder lêers en onopvallend op Linux uit te voer](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}
