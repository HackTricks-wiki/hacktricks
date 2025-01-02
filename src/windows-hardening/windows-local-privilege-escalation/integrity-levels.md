# Integriteitsvlakke

{{#include ../../banners/hacktricks-training.md}}

## Integriteitsvlakke

In Windows Vista en later weergawes, kom alle beskermde items met 'n **integriteitsvlak** etiket. Hierdie opstelling ken meestal 'n "medium" integriteitsvlak toe aan lêers en registriesleutels, behalwe vir sekere vouers en lêers waartoe Internet Explorer 7 kan skryf op 'n lae integriteitsvlak. Die standaardgedrag is dat prosesse wat deur standaardgebruikers geïnisieer word, 'n medium integriteitsvlak het, terwyl dienste tipies op 'n stelselintegriteitsvlak werk. 'n Hoë-integriteitsetiket beskerm die wortelgids.

'n Sleutelreël is dat voorwerpe nie gewysig kan word deur prosesse met 'n laer integriteitsvlak as die voorwerp se vlak nie. Die integriteitsvlakke is:

- **Onbetroubaar**: Hierdie vlak is vir prosesse met anonieme aanmeldings. %%%Voorbeeld: Chrome%%%
- **Laag**: Hoofsaaklik vir internetinteraksies, veral in Internet Explorer se Beskermde Modus, wat geassosieerde lêers en prosesse beïnvloed, en sekere vouers soos die **Tydelike Internet-gids**. Lae integriteitsprosesse ondervind beduidende beperkings, insluitend geen registrieskryftoegang en beperkte gebruikersprofielskryftoegang nie.
- **Medium**: Die standaardvlak vir die meeste aktiwiteite, toegeken aan standaardgebruikers en voorwerpe sonder spesifieke integriteitsvlakke. Selfs lede van die Administrators-groep werk standaard op hierdie vlak.
- **Hoog**: Gereserveer vir administrateurs, wat hulle toelaat om voorwerpe op laer integriteitsvlakke te wysig, insluitend dié op die hoë vlak self.
- **Stelsel**: Die hoogste operasionele vlak vir die Windows-kern en kern dienste, buite bereik selfs vir administrateurs, wat beskerming van noodsaaklike stelselfunksies verseker.
- **Installeerder**: 'n Unieke vlak wat bo alle ander staan, wat voorwerpe op hierdie vlak in staat stel om enige ander voorwerp te deïnstalleer.

Jy kan die integriteitsvlak van 'n proses verkry met **Process Explorer** van **Sysinternals**, deur toegang te verkry tot die **eienskappe** van die proses en die "**Sekuriteit**" oortjie te besigtig:

![](<../../images/image (824).png>)

Jy kan ook jou **huidige integriteitsvlak** verkry met `whoami /groups`

![](<../../images/image (325).png>)

### Integriteitsvlakke in die lêerstelsel

'n Voorwerp binne die lêerstelsel mag 'n **minimum integriteitsvlak vereiste** benodig en as 'n proses nie hierdie integriteitsvlak het nie, sal dit nie in staat wees om daarmee te kommunikeer.\
Byvoorbeeld, kom ons **skep 'n gewone lêer vanaf 'n gewone gebruikerskonsol en kyk na die toestemmings**:
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
Nou, laat ons 'n minimum integriteitsvlak van **Hoog** aan die lêer toewys. Dit **moet gedoen word vanaf 'n konsole** wat as **administrateur** loop, aangesien 'n **gewone konsole** in Medium Integriteitsvlak sal loop en **nie toegelaat sal word** om 'n Hoog Integriteitsvlak aan 'n objek toe te wys:
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
Hierdie is waar dinge interessant raak. Jy kan sien dat die gebruiker `DESKTOP-IDJHTKP\user` **VOLLEDIGE regte** oor die lêer het (in werklikheid was dit die gebruiker wat die lêer geskep het), egter, as gevolg van die minimum integriteitsvlak wat geïmplementeer is, sal hy nie in staat wees om die lêer weer te wysig nie, tensy hy binne 'n Hoë Integriteitsvlak loop (let op dat hy dit sal kan lees):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!NOTE]
> **Daarom, wanneer 'n lêer 'n minimum integriteitsvlak het, moet jy ten minste op daardie integriteitsvlak loop om dit te kan wysig.**

### Integriteitsvlakke in Binaries

Ek het 'n kopie van `cmd.exe` gemaak in `C:\Windows\System32\cmd-low.exe` en dit 'n **integriteitsvlak van laag vanaf 'n administrateurkonsol gestel:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Nou, wanneer ek `cmd-low.exe` uitvoer, sal dit **onder 'n lae-integriteitsvlak** loop in plaas van 'n medium een:

![](<../../images/image (313).png>)

Vir nuuskierige mense, as jy 'n hoë integriteitsvlak aan 'n binêre toewys (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), sal dit nie outomaties met 'n hoë integriteitsvlak loop nie (as jy dit van 'n medium integriteitsvlak aanroep --per standaard-- sal dit onder 'n medium integriteitsvlak loop).

### Integriteitsvlakke in Prosesse

Nie alle lêers en vouers het 'n minimum integriteitsvlak nie, **maar alle prosesse loop onder 'n integriteitsvlak**. En soortgelyk aan wat met die lêerstelsel gebeur het, **as 'n proses binne 'n ander proses wil skryf, moet dit ten minste dieselfde integriteitsvlak hê**. Dit beteken dat 'n proses met 'n lae integriteitsvlak nie 'n handvatsel met volle toegang tot 'n proses met 'n medium integriteitsvlak kan oopmaak nie.

As gevolg van die beperkings wat in hierdie en die vorige afdeling bespreek is, is dit altyd **aanbeveel om 'n proses in die laagste moontlike integriteitsvlak te laat loop**.

{{#include ../../banners/hacktricks-training.md}}
