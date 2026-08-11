# Integriteitsvlakke

{{#include ../../banners/hacktricks-training.md}}

## Integriteitsvlakke

In Windows Vista en latere weergawes kan beveiligbare objects 'n **integriteitsvlak**-etiket bevat. Die meeste objects word as medium integriteit behandel, terwyl spesifieke liggings wat vir lae-integriteitstoepassings bedoel is, as laag gemerk kan word. Prosesse wat deur standaardgebruikers begin word, loop normaalweg met medium integriteit, verhoogde toepassings loop met hoë integriteit, en baie dienste loop met stelselintegriteit.<sup>[[1]](#references)</sup>

'n Belangrike reël is dat objects nie gewysig kan word deur prosesse met 'n laer integriteitsvlak as die vlak van die object nie. Windows pas hierdie Mandatory Integrity Control (MIC)-kontrole toe voordat die object se discretionary access control list (DACL) geëvalueer word. Die vlakke wat algemeen teëgekom word, is:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: Die laagste vlak, voorgestel deur `SECURITY_MANDATORY_UNTRUSTED_RID` (`S-1-16-0`). Moenie hierdie integriteitsetiket met die **Anonymous Logon**-identiteit (`S-1-5-7`) verwar nie; verifikasie-identiteite en MIC-etikette is afsonderlike SID-naamruimtes. As 'n werklike voorbeeld ken Chromium se Windows-sandbox aanvanklik Low-integriteit aan sandboxed teikens toe en verlaag dit daarna renderer-teikens na Untrusted-integriteit nadat die opstart voltooi is.<sup>[[5]](#references)[[6]](#references)</sup>
- **Low**: Hoofsaaklik vir internetinteraksies, veral in Internet Explorer se Protected Mode, wat geassosieerde lêers en prosesse beïnvloed, asook sekere vouers soos die **Temporary Internet Folder**. Low-integriteitprosesse ondervind beduidende beperkings, insluitend geen skryftoegang tot die register nie en beperkte skryftoegang tot die gebruikerprofiel.
- **Medium**: Die verstekvlak vir die meeste aktiwiteite, toegeken aan standaardgebruikers en objects sonder spesifieke integriteitsvlakke. Selfs lede van die Administrators-groep werk by verstek op hierdie vlak.
- **High**: Gereserveer vir administrateurs, wat hulle toelaat om objects op laer integriteitsvlakke te wysig, insluitend dié wat self op die hoë vlak is.
- **System**: Die hoogste operasionele vlak vir die Windows-kern en kerndienste, buite bereik van selfs administrateurs, wat beskerming van noodsaaklike stelselfunksies verseker.

Windows definieer ook 'n protected-process-integriteitswaarde bo System. **TrustedInstaller** is egter 'n Windows-diensidentiteit eerder as 'n afsonderlike MIC-vlak; sy vermoë om beskermde bedryfstelselbronne te wysig, spruit uit die toestemmings wat aan daardie identiteit toegeken is.

Moenie aanvaar dat 'n ligging soos die wortel van 'n stelselaandrywer altyd 'n vaste High-integriteitsetiket het nie. Inspekteer die effektiewe DACL en enige eksplisiete mandatory label met `icacls`; 'n object sonder 'n etiket word vir MIC as Medium behandel, terwyl sy DACL en eienaarskap steeds onafhanklik toegang kan beperk.<sup>[[1]](#references)[[4]](#references)</sup>

Jy kan die integriteitsvlak van 'n proses met **Process Explorer** van **Sysinternals** verkry deur die proses-eienskappe oop te maak en die **Security**-oortjie te bekyk:<sup>[[3]](#references)</sup>

![Integriteitsvlakke - Integriteitsvlakke: Jy kan die integriteitsvlak van 'n proses verkry deur Process Explorer van Sysinternals te gebruik, die eienskappe van die proses oop te maak en die "...](<../../images/image (824).png>)

Jy kan ook jou **huidige integriteitsvlak** met `whoami /groups` verkry:

![Integriteitsvlakke - Integriteitsvlakke: Jy kan ook jou huidige integriteitsvlak met whoami /groups verkry](<../../images/image (325).png>)

### Integriteitsvlakke in die lêerstelsel

'n Object in die lêerstelsel kan 'n **minimum-integriteitsvlakvereiste** hê. 'n Proses onder daardie vlak is onderhewig aan die object se mandatory policy, selfs wanneer sy DACL andersins toegang sou toestaan. Skep byvoorbeeld 'n gewone lêer vanaf 'n standaardgebruikerkonsole en inspekteer sy toestemmings:<sup>[[1]](#references)[[4]](#references)</sup>
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
Ken nou ’n minimum-integriteitsvlak van **High** aan die file toe. Dit **moet vanaf ’n console** gedoen word wat as **administrator** loop, omdat ’n gewone console op Medium-integriteit loop en **nie toegelaat sal word** om High-integriteit aan ’n object toe te ken nie:
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
Die gebruiker `DESKTOP-IDJHTKP\user` het **VOLLE voorregte** oor die lêer omdat daardie gebruiker dit geskep het. Die verpligte etiket verhoed egter dat die gebruiker die lêer wysig tensy die proses op High integrity loop. Die gebruiker kan dit steeds lees omdat die vertoonde verpligte beleid `(NW)`, of no-write-up, is:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Daarom, wanneer ’n lêer ’n minimum-integriteitsvlak het, moet jy ten minste op daardie integriteitsvlak loop om dit te kan wysig.**

### Integriteitsvlakke in Binaries

Die volgende voorbeeld gebruik ’n kopie van `cmd.exe` by `C:\Windows\System32\cmd-low.exe` en ken dit ’n **Lae integriteitsvlak toe vanaf ’n administrateurkonsole**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Nou, wanneer ek `cmd-low.exe` uitvoer, sal dit **onder ’n lae-integriteitsvlak loop** in plaas van ’n medium een:

![Integriteitsvlakke in lêerstelsel - Integriteitsvlakke in binaries: Nou, wanneer ek cmd-low.exe uitvoer, sal dit onder ’n lae-integriteitsvlak loop in plaas van ’n medium een](<../../images/image (313).png>)

Om ’n High-integriteitsetiket aan ’n binary toe te ken (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) laat dit nie outomaties by High-integriteit loop nie. As dit vanuit ’n Medium-integriteitsproses aangeroep word, loop dit by Medium-integriteit omdat ’n nuwe proses die laagste van die uitvoerbare lêer se en die aanroeper se integriteitsvlakke ontvang.<sup>[[1]](#references)</sup>

### Integriteitsvlakke in prosesse

Nie alle lêers en vouers het ’n eksplisiete minimum-integriteitsetiket nie, **maar elke proses loop by ’n integriteitsvlak**. Soos met lêerstelselobjekte, **moet ’n proses wat skryftoegang tot ’n ander proses wil hê, minstens dieselfde integriteitsvlak hê**. Daarom kan ’n Low-integriteitsproses nie ’n Medium-integriteitsproses met volle toegang oopmaak nie.<sup>[[1]](#references)</sup>

Weens hierdie beperkings is die veiligste benadering om **elke proses by die laagste integriteitsvlak te laat loop wat dit steeds toelaat om sy beoogde werk uit te voer**.

## References

- [1] [Microsoft Learn – Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL-enumerasie](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Chromium-bronkode – Verstek Windows-sandbox-integriteitsbeleid](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
- [6] [Microsoft Learn – Welbekende SIDs](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
{{#include ../../banners/hacktricks-training.md}}
