# Integriteitsvlakke

{{#include ../../banners/hacktricks-training.md}}

## Integriteitsvlakke

In Windows Vista en latere weergawes kan beveiligbare objekte ’n **integriteitsvlak**-etiket dra. Die meeste objekte word as medium-integriteit behandel, terwyl spesifieke liggings wat vir lae-integriteit-toepassings bedoel is, as laag gemerk kan word. Prosesse wat deur standaardgebruikers begin word, loop normaalweg met medium-integriteit, verhoogde toepassings loop met hoë-integriteit, en baie dienste loop met stelsel-integriteit.<sup>[[1]](#references)</sup>

’n Belangrike reël is dat objekte nie deur prosesse met ’n laer integriteitsvlak as die vlak van die objek gewysig kan word nie. Windows pas hierdie Mandatory Integrity Control (MIC)-kontrole toe voordat die objek se discretionary access control list (DACL) geëvalueer word. Die vlakke wat algemeen teëgekom word, is:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: Die laagste vlak, verteenwoordig deur `SECURITY_MANDATORY_UNTRUSTED_RID`.
- **Low**: Hoofsaaklik vir internetinteraksies, veral in Internet Explorer se Protected Mode, wat geassosieerde lêers en prosesse beïnvloed, asook sekere vouers soos die **Temporary Internet Folder**. Low-integrity-prosesse het beduidende beperkings, insluitend geen skryftoegang tot die register nie en beperkte skryftoegang tot die gebruikerprofiel.
- **Medium**: Die verstekvlak vir die meeste aktiwiteite, toegeken aan standaardgebruikers en objekte sonder spesifieke integriteitsvlakke. Selfs lede van die Administrators-groep werk by verstek op hierdie vlak.
- **High**: Gereserveer vir administrateurs, wat hulle toelaat om objekte op laer integriteitsvlakke te wysig, insluitend dié op die hoë vlak self.
- **System**: Die hoogste operasionele vlak vir die Windows-kern en kern dienste, buite die bereik van selfs administrateurs, wat beskerming van belangrike stelselfunksies verseker.

Windows definieer ook ’n protected-process-integriteitswaarde bo System. **TrustedInstaller** is egter ’n Windows-diensidentiteit eerder as ’n afsonderlike MIC-vlak; die vermoë daarvan om beskermde bedryfstelselhulpbronne te wysig, kom van die toestemmings wat aan daardie identiteit toegeken is.

Jy kan die integriteitsvlak van ’n proses met **Process Explorer** van **Sysinternals** verkry deur die proses-eienskappe oop te maak en die **Security**-oortjie te bekyk:<sup>[[3]](#references)</sup>

![Integriteitsvlakke - Integriteitsvlakke: Jy kan die integriteitsvlak van ’n proses verkry deur Process Explorer van Sysinternals te gebruik, die eienskappe van die proses oop te maak en die "...](<../../images/image (824).png>)

Jy kan ook jou **huidige integriteitsvlak** met `whoami /groups` verkry:

![Integriteitsvlakke - Integriteitsvlakke: Jy kan ook jou huidige integriteitsvlak met whoami /groups verkry](<../../images/image (325).png>)

### Integriteitsvlakke in die lêerstelsel

’n Objek in die lêerstelsel kan ’n **minimumvereiste vir die integriteitsvlak** hê. ’n Proses onder daardie vlak is onderworpe aan die objek se verpligte beleid, selfs wanneer die DACL andersins toegang sou verleen. Skep byvoorbeeld ’n gewone lêer vanuit ’n standaardgebruikerskonsole en inspekteer sy toestemmings:<sup>[[1]](#references)[[4]](#references)</sup>
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
Ken nou ’n minimumintegriteitsvlak van **Hoog** aan die lêer toe. Dit **moet vanuit ’n konsole** gedoen word wat as **administrateur** loop, omdat ’n gewone konsole op Medium-integriteit loop en **nie toegelaat sal word om Hoë-integriteit aan ’n objek toe te ken nie**:
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
Die gebruiker `DESKTOP-IDJHTKP\user` het **VOLLEDIGE voorregte** oor die lêer omdat daardie gebruiker dit geskep het. Die verpligte etiket verhoed egter dat die gebruiker die lêer wysig, tensy die proses met High integrity loop. Die gebruiker kan dit steeds lees omdat die vertoonde verpligte beleid `(NW)`, of no-write-up, is:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Daarom, wanneer 'n lêer 'n minimum-integriteitsvlak het, moet jy ten minste op daardie integriteitsvlak loop om dit te kan wysig.**

### Integriteitsvlakke in Binaries

Die volgende voorbeeld gebruik 'n kopie van `cmd.exe` by `C:\Windows\System32\cmd-low.exe` en ken dit 'n **Lae integriteitsvlak toe vanuit 'n administrateurkonsole**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Nou, wanneer ek `cmd-low.exe` uitvoer, sal dit **onder 'n lae integriteitsvlak loop** in plaas van 'n medium een:

![Integriteitsvlakke in die lêerstelsel - Integriteitsvlakke in binaries: Nou, wanneer ek cmd-low.exe uitvoer, sal dit onder 'n lae integriteitsvlak loop in plaas van 'n medium een](<../../images/image (313).png>)

Die toekenning van 'n hoë-integriteitsetiket aan 'n binary (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) laat dit nie outomaties met hoë integriteit loop nie. As dit vanuit 'n medium-integriteitsproses aangeroep word, loop dit met medium integriteit, omdat 'n nuwe proses die laagste van die uitvoerbare lêer se en die oproeper se integriteitsvlakke ontvang.<sup>[[1]](#references)</sup>

### Integriteitsvlakke in prosesse

Nie alle lêers en vouers het 'n eksplisiete minimum-integriteitsetiket nie, **maar elke proses loop op 'n integriteitsvlak**. Soos met lêerstelselobjekte, **moet 'n proses wat skryftoegang tot 'n ander proses wil hê, ten minste dieselfde integriteitsvlak hê**. Daarom kan 'n lae-integriteitsproses nie 'n medium-integriteitsproses met volledige toegang oopmaak nie.<sup>[[1]](#references)</sup>

As gevolg van hierdie beperkings is die veiligste benadering om **elke proses op die laagste integriteitsvlak te laat loop wat dit steeds toelaat om sy beoogde werk uit te voer**.

## References

- [1] [Microsoft Learn – Verpligte integriteitsbeheer](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL-enumerasie](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
{{#include ../../banners/hacktricks-training.md}}
