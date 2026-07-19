# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Konteks

In Linux moet ’n program as ’n lêer bestaan om dit te kan uitvoer; dit moet op een of ander manier deur die lêerstelselhiërargie toeganklik wees (dit is eenvoudig hoe `execve()` werk). Hierdie lêer kan op skyf of in RAM (tmpfs, memfd) wees, maar jy het ’n lêerpad nodig. Dit het dit baie maklik gemaak om te beheer wat op ’n Linux-stelsel uitgevoer word, dit maak dit maklik om threats en die aanvaller se tools op te spoor, of om te voorkom dat hulle enigsins enigiets van hul eie probeer uitvoer (_bv._ deur nie toe te laat dat unprivileged users uitvoerbare lêers enige plek plaas nie).

Maar hierdie technique is hier om dit alles te verander. As jy nie die process wat jy wil hê kan start nie... **dan hijack jy een wat reeds bestaan**.

Hierdie technique laat jou toe om **algemene protection techniques soos read-only, noexec, file-name whitelisting, hash whitelisting... te bypass**

## Dependencies

Die finale script is afhanklik van die volgende tools om te werk; hulle moet toeganklik wees in die system wat jy aanval (by verstek sal jy hulle oral vind):
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

As jy die geheue van ’n proses arbitrêr kan wysig, kan jy beheer daaroor oorneem. Dit kan gebruik word om ’n reeds bestaande proses te kaap en dit met ’n ander program te vervang. Ons kan dit bereik deur óf die `ptrace()`-syscall te gebruik (wat vereis dat jy die vermoë het om syscalls uit te voer of dat gdb op die stelsel beskikbaar is) óf, meer interessant, deur na `/proc/$pid/mem` te skryf.

Die lêer `/proc/$pid/mem` is ’n een-tot-een-kartering van die volledige adresruimte van ’n proses (_bv._ van `0x0000000000000000` tot `0x7ffffffffffff000` in x86-64). Dit beteken dat die lees van of skryf na hierdie lêer by ’n offset `x` dieselfde is as om die inhoud by die virtuele adres `x` te lees of te wysig.

Nou het ons vier basiese probleme om te hanteer:

- Oor die algemeen mag slegs root en die program-eienaar van die lêer dit wysig.
- ASLR.
- As ons probeer om na ’n adres te lees of te skryf wat nie in die program se adresruimte gekarteer is nie, sal ons ’n I/O-fout kry.

Hierdie probleme het oplossings wat, hoewel hulle nie perfek is nie, goed werk:

- Die meeste shell-interpreters laat die skepping van file descriptors toe wat dan deur child processes geërf word. Ons kan ’n fd skep wat na die `mem`-lêer van die shell wys, met skryftoestemmings... dus sal child processes wat daardie fd gebruik, die shell se geheue kan wysig.
- ASLR is nie eens ’n probleem nie; ons kan die shell se `maps`-lêer of enige ander lêer uit procfs nagaan om inligting oor die proses se adresruimte te verkry.
- Ons moet dus `lseek()` oor die lêer uitvoer. Vanuit die shell kan dit nie gedoen word nie, tensy die berugte `dd` gebruik word.

### In meer besonderhede

Die stappe is relatief maklik en vereis geen spesifieke kundigheid om dit te verstaan nie:

- Ontleed die binary wat ons wil uitvoer en die loader om vas te stel watter mappings hulle benodig. Skep dan ’n "shell"code wat breedweg dieselfde stappe sal uitvoer as wat die kernel tydens elke oproep na `execve()` uitvoer:
- Skep die genoemde mappings.
- Lees die binaries daarin.
- Stel die toestemmings op.
- Inisialiseer laastens die stack met die argumente vir die program en plaas die auxiliary vector daarin (wat deur die loader benodig word).
- Spring na die loader en laat dit die res doen (laai libraries wat deur die program benodig word).
- Verkry uit die `syscall`-lêer die adres waarna die proses sal terugkeer nadat die syscall wat dit uitvoer, voltooi is.
- Oorskryf daardie plek, wat uitvoerbaar sal wees, met ons shellcode (deur `mem` kan ons bladsye wat nie skryfbaar is nie, wysig).
- Gee die program wat ons wil uitvoer aan die stdin van die proses (dit sal deur genoemde "shell"code `read()` word).
- Op hierdie stadium is dit die loader se taak om die nodige libraries vir ons program te laai en daarnaartoe te spring.

**Kyk na die tool by** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Daar is verskeie alternatiewe vir `dd`, waarvan `tail` een is. Dit is tans die verstekprogram wat gebruik word om deur die `mem`-lêer te `lseek()` (wat die enigste doel was waarvoor `dd` gebruik is). Hierdie alternatiewe is:
```bash
tail
hexdump
cmp
xxd
```
Deur die veranderlike `SEEKER` te stel, kan jy die `seeker` wat gebruik word, verander, _byvoorbeeld_:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
As jy nog ’n geldige seeker vind wat nie in die script geïmplementeer is nie, kan jy dit steeds gebruik deur die `SEEKER_ARGS`-veranderlike in te stel:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blokkeer dit, EDRs.

## Verwysings

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}
