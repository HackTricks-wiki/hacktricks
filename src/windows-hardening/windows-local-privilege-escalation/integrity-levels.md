# Integriteitsvlakke

{{#include ../../banners/hacktricks-training.md}}

## Integriteitsvlakke

In Windows Vista en latere weergawes het alle beskermde items 'n **integriteitsvlak**-merker. Hierdie opstelling ken meestal 'n "medium"-integriteitsvlak aan lêers en registersleutels toe, behalwe vir sekere vouers en lêers waarna Internet Explorer 7 op 'n lae integriteitsvlak kan skryf. Die verstekgedrag is dat prosesse wat deur standaardgebruikers begin word, 'n medium-integriteitsvlak het, terwyl dienste tipies op 'n stelsel-integriteitsvlak werk. 'n Hoë-integriteitsmerker beskerm die wortelgids.

'n Belangrike reël is dat objekte nie gewysig kan word deur prosesse met 'n laer integriteitsvlak as die objek se vlak nie. Die integriteitsvlakke is:

- **Untrusted**: Hierdie vlak is vir prosesse met anonieme aanmeldings. Voorbeeld: Chrome
- **Low**: Hoofsaaklik vir internetinteraksies, veral in Internet Explorer se Protected Mode, wat geassosieerde lêers en prosesse, asook sekere vouers soos die **Temporary Internet Folder**, beïnvloed. Low integrity-prosesse ondervind aansienlike beperkings, insluitend geen skryftoegang tot die register nie en beperkte skryftoegang tot die gebruikersprofiel.
- **Medium**: Die verstekvlak vir die meeste aktiwiteite, toegeken aan standaardgebruikers en objekte sonder spesifieke integriteitsvlakke. Selfs lede van die Administrators-groep werk by verstek op hierdie vlak.
- **High**: Gereserveer vir administrateurs, wat hulle toelaat om objekte op laer integriteitsvlakke te wysig, insluitend dié wat self op die hoë vlak is.
- **System**: Die hoogste operasionele vlak vir die Windows-kern en kernservices, buite bereik van selfs administrateurs, wat die beskerming van belangrike stelsel-funksies verseker.
- **Installer**: 'n Unieke vlak wat bo alle ander staan, en objekte op hierdie vlak in staat stel om enige ander objek te deïnstalleer.

Jy kan die integriteitsvlak van 'n proses met **Process Explorer** vanaf **Sysinternals** kry deur die **properties** van die proses te open en die "**Security**"-oortjie te bekyk:

![Integriteitsvlakke - Integriteitsvlakke: Jy kan die integriteitsvlak van 'n proses met Process Explorer vanaf Sysinternals kry deur die properties van die proses te open en die "...](<../../images/image (824).png>)

Jy kan ook jou **huidige integriteitsvlak** met `whoami /groups` kry

![Integriteitsvlakke - Integriteitsvlakke: Jy kan ook jou huidige integriteitsvlak met whoami /groups kry](<../../images/image (325).png>)

### Integriteitsvlakke in die lêerstelsel

'n Objek binne die lêerstelsel mag 'n **minimum-integriteitsvlakvereiste** hê, en as 'n proses nie hierdie integriteitsvlak het nie, sal dit nie daarmee kan interaksie hê nie.\
Byvoorbeeld, kom ons **skep 'n gewone lêer vanaf 'n gewone gebruikerskonsole en kontroleer die toestemmings**:
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Nou ken ons ’n minimum-integriteitsvlak van **Hoog** aan die lêer toe. Dit **moet vanuit ’n console** gedoen word wat as **administrator** loop, aangesien ’n **gewone console** op die Medium-integriteitsvlak sal loop en **nie toegelaat sal word** om ’n Hoë-integriteitsvlak aan ’n objek toe te ken nie:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
Dit is waar dinge interessant raak. Jy kan sien dat die gebruiker `DESKTOP-IDJHTKP\user` **VOLLE privileges** oor die lêer het (inderdaad, dit was die gebruiker wat die lêer geskep het), maar weens die minimum integrity level wat geïmplementeer is, sal hy nie meer die lêer kan wysig nie, tensy hy binne ’n High Integrity Level loop (let daarop dat hy dit sal kan lees):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Wanneer ’n lêer dus ’n minimum-integriteitsvlak het, moet jy ten minste op daardie integriteitsvlak werk om dit te kan wysig.**

### Integriteitsvlakke in Binaries

Ek het ’n kopie van `cmd.exe` in `C:\Windows\System32\cmd-low.exe` gemaak en dit **van ’n administratorkonsole af op ’n lae integriteitsvlak gestel:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Nou, wanneer ek `cmd-low.exe` uitvoer, sal dit **onder ’n lae-integriteitsvlak** loop in plaas van ’n medium een:

![Integriteitsvlakke in lêerstelsel - Integriteitsvlakke in binaries: Nou, wanneer ek cmd-low.exe uitvoer, sal dit onder ’n lae-integriteitsvlak loop in plaas van ’n medium een](<../../images/image (313).png>)

Vir nuuskierige mense: as jy ’n hoë-integriteitsvlak aan ’n binary toewys (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), sal dit nie outomaties met ’n hoë-integriteitsvlak loop nie (as jy dit vanuit ’n medium-integriteitsvlak aanroep --by verstek-- sal dit onder ’n medium-integriteitsvlak loop).

### Integriteitsvlakke in prosesse

Nie alle lêers en vouers het ’n minimum-integriteitsvlak nie, **maar alle prosesse loop onder ’n integriteitsvlak**. En soortgelyk aan wat met die lêerstelsel gebeur het, **moet ’n proses ten minste dieselfde integriteitsvlak hê as dit binne ’n ander proses wil skryf**. Dit beteken dat ’n proses met ’n lae-integriteitsvlak nie ’n handle met volle toegang tot ’n proses met ’n medium-integriteitsvlak kan oopmaak nie.

Weens die beperkings wat in hierdie en die vorige afdeling bespreek is, word dit vanuit ’n sekuriteitsoogpunt altyd **aanbeveel om ’n proses op die laagste moontlike integriteitsvlak te laat loop**.

{{#include ../../banners/hacktricks-training.md}}
