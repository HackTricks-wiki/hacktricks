# DDexec / EverythingExec

{{#include ../../../banners/hacktricks-training.md}}

## Konteks

In Linux, om 'n program te laat loop, moet dit as 'n lêer bestaan, dit moet op een of ander manier deur die lêerstelsel hiërargie toeganklik wees (dit is net hoe `execve()` werk). Hierdie lêer kan op skyf of in ram (tmpfs, memfd) wees, maar jy het 'n lêerpad nodig. Dit het dit baie maklik gemaak om te beheer wat op 'n Linux-stelsel gedoen word, dit maak dit maklik om bedreigings en aanvallers se gereedskap te ontdek of om te voorkom dat hulle enige van hul eie pogings om iets uit te voer, kan doen (_e. g._ om nie ongeprivilegieerde gebruikers toe te laat om uitvoerbare lêers enige plek te plaas nie).

Maar hierdie tegniek is hier om al hierdie te verander. As jy nie die proses kan begin wat jy wil nie... **dan neem jy een wat reeds bestaan**.

Hierdie tegniek stel jou in staat om **algemene beskermingstegnieke soos lees-slegs, geen uitvoer, lêernaam witlys, hash witlys... te omseil**.

## Afhanklikhede

Die finale skrip is afhanklik van die volgende gereedskap om te werk, hulle moet toeganklik wees in die stelsel wat jy aanval (per standaard sal jy al hulle oral vind):
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

As jy in staat is om arbitrêr die geheue van 'n proses te verander, kan jy dit oorneem. Dit kan gebruik word om 'n reeds bestaande proses te kap en dit met 'n ander program te vervang. Ons kan dit bereik deur die `ptrace()` syscall te gebruik (wat vereis dat jy die vermoë het om syscalls uit te voer of dat gdb beskikbaar is op die stelsel) of, meer interessant, deur te skryf na `/proc/$pid/mem`.

Die lêer `/proc/$pid/mem` is 'n een-tot-een kaart van die hele adresruimte van 'n proses (_bv._ van `0x0000000000000000` tot `0x7ffffffffffff000` in x86-64). Dit beteken dat om van hierdie lêer te lees of daarin te skryf op 'n offset `x` dieselfde is as om te lees van of die inhoud op die virtuele adres `x` te verander.

Nou het ons vier basiese probleme om te hanteer:

- In die algemeen mag slegs root en die program eienaar van die lêer dit verander.
- ASLR.
- As ons probeer om te lees of te skryf na 'n adres wat nie in die adresruimte van die program gemap is nie, sal ons 'n I/O-fout kry.

Hierdie probleme het oplossings wat, alhoewel hulle nie perfek is nie, goed is:

- Meeste shell interpreters laat die skepping van lêerdescriptors toe wat dan geërf sal word deur kindprosesse. Ons kan 'n fd skep wat na die `mem` lêer van die shell met skryfrechten wys... so kindprosesse wat daardie fd gebruik, sal in staat wees om die geheue van die shell te verander.
- ASLR is glad nie 'n probleem nie, ons kan die shell se `maps` lêer of enige ander van die procfs nagaan om inligting oor die adresruimte van die proses te verkry.
- So ons moet `lseek()` oor die lêer. Van die shell af kan dit nie gedoen word nie tensy ons die berugte `dd` gebruik.

### In meer detail

Die stappe is relatief maklik en vereis geen soort van kundigheid om te verstaan nie:

- Parse die binêre wat ons wil uitvoer en die loader om uit te vind watter mappings hulle benodig. Dan maak 'n "shell"kode wat, in groot mate, dieselfde stappe sal uitvoer wat die kernel doen by elke oproep na `execve()`:
- Skep genoemde mappings.
- Lees die binêre in hulle in.
- Stel toestemmings op.
- Laastens, inisieer die stapel met die argumente vir die program en plaas die bykomende vektor (nodig deur die loader).
- Spring in die loader en laat dit die res doen (laai biblioteke wat deur die program benodig word).
- Verkry van die `syscall` lêer die adres waarheen die proses sal terugkeer na die syscall wat dit uitvoer.
- Oorskryf daardie plek, wat uitvoerbaar sal wees, met ons shellcode (deur `mem` kan ons onskryfbare bladsye verander).
- Gee die program wat ons wil uitvoer aan die stdin van die proses (sal `read()` deur genoemde "shell"kode wees).
- Op hierdie punt is dit aan die loader om die nodige biblioteke vir ons program te laai en daarin te spring.

**Kyk na die hulpmiddel in** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## AllesExec

Daar is verskeie alternatiewe vir `dd`, een daarvan, `tail`, is tans die standaardprogram wat gebruik word om `lseek()` deur die `mem` lêer (wat die enigste doel was om `dd` te gebruik). Genoemde alternatiewe is:
```bash
tail
hexdump
cmp
xxd
```
Deur die veranderlike `SEEKER` in te stel, kan jy die soeker wat gebruik word, verander, _bv._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
As jy 'n ander geldige soeker vind wat nie in die skrif geïmplementeer is nie, kan jy dit steeds gebruik deur die `SEEKER_ARGS` veranderlike in te stel:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blokkeer dit, EDRs.

## Verwysings

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../banners/hacktricks-training.md}}
