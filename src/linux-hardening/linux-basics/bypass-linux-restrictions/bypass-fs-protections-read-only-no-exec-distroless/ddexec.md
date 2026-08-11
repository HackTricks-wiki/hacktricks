# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Konteks

In Linux moet ’n program as ’n lêer bestaan om dit uit te voer, en dit moet op een of ander manier deur die lêerstelselhiërargie toeganklik wees (dit is eenvoudig hoe `execve()` werk). Hierdie lêer kan op die skyf of in RAM (tmpfs, memfd) wees, maar jy het ’n lêerpad nodig. Dit het dit baie maklik gemaak om te beheer wat op ’n Linux-stelsel uitgevoer word, en dit maak dit maklik om threats en attacker se tools op te spoor of te voorkom dat hulle hoegenaamd enigiets van hulle probeer uitvoer (_bv._ deur nie toe te laat dat unprivileged users uitvoerbare lêers op enige plek plaas nie).

Maar hierdie technique is hier om dit alles te verander. As jy nie die proses wat jy wil hê kan start nie... **dan hijack jy een wat reeds bestaan**.

Hierdie technique laat jou toe om **common protection techniques soos read-only, noexec, file-name whitelisting en hash whitelisting te bypass**.<sup>[[1]](#references)</sup>

## Dependencies

Die finale script depends op die volgende tools om te werk; hulle moet toeganklik wees in die system wat jy attack (by verstek sal jy hulle oral vind):
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

As jy in staat is om die geheue van ’n proses arbitrêr te wysig, kan jy beheer daaroor oorneem. Dit kan gebruik word om ’n reeds bestaande proses te kaap en dit met ’n ander program te vervang. Ons kan dit óf doen deur die `ptrace()`-syscall te gebruik (wat vereis dat jy die vermoë het om syscalls uit te voer of dat `gdb` op die stelsel beskikbaar is), óf, interessanter, deur na `/proc/$pid/mem` te skryf.<sup>[[1]](#references)</sup>

Die lêer `/proc/$pid/mem` is ’n een-tot-een-kartering van die volledige adresruimte van ’n proses (_bv._ van `0x0000000000000000` tot `0x7ffffffffffff000` in x86-64). Dit beteken dat lees vanaf of skryf na hierdie lêer by ’n offset `x` dieselfde is as om vanaf die virtuele adres `x` te lees of die inhoud daar te wysig.

Nou het ons vier basiese probleme om te hanteer:

- Oor die algemeen mag slegs root en die program se lêereienaar dit wysig.
- ASLR.
- As ons probeer om na ’n adres te lees of te skryf wat nie in die program se adresruimte gekarteer is nie, sal ons ’n I/O-fout kry.

Hierdie probleme het oplossings wat, hoewel hulle nie perfek is nie, goed werk:

- Die meeste shell-interpreters laat die skepping toe van file descriptors wat dan deur child processes geërf word. Ons kan ’n fd skep wat na die `mem`-lêer van die shell wys, met skryftoestemmings... dus sal child processes wat daardie fd gebruik die shell se geheue kan wysig.
- ASLR is nie eens ’n probleem nie; ons kan die shell se `maps`-lêer of enige ander lêer vanaf procfs nagaan om inligting oor die proses se adresruimte te verkry.
- Ons moet dus `lseek()` oor die lêer uitvoer. Vanuit die shell kan dit nie gedoen word nie, tensy die berugte `dd` gebruik word.

### In meer besonderhede

Die stappe is relatief maklik en vereis geen soort kundigheid om dit te verstaan nie:<sup>[[1]](#references)</sup>

- Parse die binary wat ons wil uitvoer en die loader om uit te vind watter mappings hulle benodig. Skep dan ’n "shell"code wat, breedweg gesproke, dieselfde stappe sal uitvoer as die kernel tydens elke oproep na `execve()`:
- Skep die genoemde mappings.
- Lees die binaries daarin.
- Stel die permissions op.
- Inisialiseer laastens die stack met die argumente vir die program en plaas die auxiliary vector daarin (wat deur die loader benodig word).
- Spring na die loader en laat dit die res doen (laai libraries wat deur die program benodig word).
- Verkry uit die `syscall`-lêer die adres waarheen die proses sal terugkeer ná die syscall wat dit uitvoer.
- Oorskryf daardie plek, wat uitvoerbaar sal wees, met ons shellcode (deur `mem` kan ons unwritable pages wysig).
- Gee die program wat ons wil uitvoer aan die stdin van die proses (dit sal deur genoemde "shell"code `read()` word).
- Op hierdie punt is dit die loader se taak om die nodige libraries vir ons program te laai en daarheen te spring.

**Kyk na die tool by** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Daar is verskeie alternatiewe vir `dd`, waarvan `tail` een is en tans die verstekprogram is wat gebruik word om deur die `mem`-lêer te `lseek()` (wat die enigste doel was waarvoor `dd` gebruik is). Hierdie alternatiewe is:<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
Deur die veranderlike `SEEKER` in te stel, kan jy die gebruikte seeker verander, _bv._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Indien jy nog ’n geldige seeker vind wat nie in die script geïmplementeer is nie, kan jy dit steeds gebruik deur die `SEEKER_ARGS`-veranderlike in te stel:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blokkeer dit, EDR's.

## References

- [1] [DDexec: 'n Tegniek om binaries filelessly en stealthily op Linux uit te voer](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}
