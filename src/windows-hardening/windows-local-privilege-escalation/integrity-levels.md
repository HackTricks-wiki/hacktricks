# Nivoi integriteta

{{#include ../../banners/hacktricks-training.md}}

## Nivoi integriteta

U sistemima Windows Vista i novijim verzijama, objekti koji mogu biti zaštićeni mogu imati oznaku **nivoa integriteta**. Većina objekata se tretira kao objekat srednjeg nivoa integriteta, dok određene lokacije namenjene aplikacijama niskog nivoa integriteta mogu biti označene kao objekti niskog nivoa. Procesi koje pokreću standardni korisnici obično rade na srednjem nivou integriteta, aplikacije pokrenute sa povišenim privilegijama rade na visokom nivou integriteta, a mnogi servisi rade na nivou sistemskog integriteta.<sup>[[1]](#references)</sup>

Ključno pravilo je da procese sa nižim nivoom integriteta nije moguće koristiti za izmenu objekata čiji je nivo integriteta viši. Windows primenjuje ovu proveru Mandatory Integrity Control (MIC) pre procene discretionary access control liste (DACL) objekta. Najčešći nivoi su:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: Najniži nivo, predstavljen vrednošću `SECURITY_MANDATORY_UNTRUSTED_RID` (`S-1-16-0`). Ovu oznaku integriteta ne treba mešati sa identitetom **Anonymous Logon** (`S-1-5-7`); identiteti autentikacije i MIC oznake pripadaju odvojenim SID prostorima imena. Kao primer iz prakse, Chromium-ov Windows sandbox prvobitno dodeljuje sandboxovanim ciljevima nivo Low, a zatim nakon pokretanja spušta renderer ciljeve na nivo Untrusted.<sup>[[5]](#references)[[6]](#references)</sup>
- **Low**: Uglavnom se koristi za interakcije sa internetom, naročito u Protected Mode-u Internet Explorer-a, što utiče na povezane datoteke i procese, kao i na određene fascikle poput **Temporary Internet Folder**. Procesi sa niskim nivoom integriteta suočavaju se sa značajnim ograničenjima, uključujući zabranu upisivanja u registry i ograničen pristup upisivanju u korisnički profil.
- **Medium**: Podrazumevani nivo za većinu aktivnosti, dodeljen standardnim korisnicima i objektima bez posebno navedenog nivoa integriteta. Čak i članovi grupe Administrators podrazumevano rade na ovom nivou.
- **High**: Rezervisan za administratore i omogućava im izmenu objekata sa nižim nivoima integriteta, uključujući i one na samom visokom nivou.
- **System**: Najviši operativni nivo za Windows kernel i osnovne servise, nedostupan čak i administratorima, čime se obezbeđuje zaštita ključnih sistemskih funkcija.

Windows takođe definiše vrednost integriteta za protected-process iznad nivoa System. Međutim, **TrustedInstaller** je identitet Windows servisa, a ne zaseban MIC nivo; njegova mogućnost izmene zaštićenih resursa operativnog sistema potiče od dozvola dodeljenih tom identitetu.

Ne treba pretpostaviti da lokacija kao što je koren sistemskog diska uvek ima fiksnu oznaku visokog nivoa integriteta. Proverite efektivni DACL i svaku eksplicitnu mandatory label oznaku pomoću komande `icacls`; objekat bez oznake tretira se kao objekat srednjeg nivoa za MIC, dok njegov DACL i vlasništvo i dalje mogu nezavisno ograničavati pristup.<sup>[[1]](#references)[[4]](#references)</sup>

Nivo integriteta procesa možete dobiti pomoću alata **Process Explorer** iz paketa **Sysinternals**, tako što otvorite svojstva procesa i prikažete karticu **Security**:<sup>[[3]](#references)</sup>

![Nivoi integriteta - Nivoi integriteta: Nivo integriteta procesa možete dobiti pomoću alata Process Explorer iz paketa Sysinternals, tako što pristupite svojstvima procesa i prikažete "...](<../../images/image (824).png>)

Svoj **trenutni nivo integriteta** možete dobiti i pomoću komande `whoami /groups`:

![Nivoi integriteta - Nivoi integriteta: Svoj trenutni nivo integriteta možete dobiti i pomoću komande whoami /groups](<../../images/image (325).png>)

### Nivoi integriteta u sistemu datoteka

Objekat u sistemu datoteka može imati **zahtev za minimalnim nivoom integriteta**. Proces čiji je nivo ispod tog nivoa podvrgava se mandatory policy pravilima objekta čak i kada bi njegov DACL inače odobrio pristup. Na primer, napravite običnu datoteku iz konzole standardnog korisnika i proverite njene dozvole:<sup>[[1]](#references)[[4]](#references)</sup>
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
Sada dodelite minimalni nivo integriteta **High** datoteci. Ovo **mora biti urađeno iz konzole** pokrenute kao **administrator**, jer se obična konzola pokreće sa nivoom integriteta Medium i **neće imati dozvolu** da objektu dodeli nivo integriteta High:
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
Korisnik `DESKTOP-IDJHTKP\user` ima **PUNE privilegije** nad datotekom zato što ju je taj korisnik kreirao. Međutim, obavezna oznaka sprečava korisnika da menja datoteku osim ako proces ne radi sa visokim nivoom integriteta. Korisnik i dalje može da je čita zato što je prikazana obavezna politika `(NW)`, odnosno no-write-up:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Dakle, kada datoteka ima minimalni nivo integriteta, da biste je izmenili morate raditi najmanje na tom nivou integriteta.**

### Nivoi integriteta u binarnim datotekama

Sledeći primer koristi kopiju datoteke `cmd.exe` na lokaciji `C:\Windows\System32\cmd-low.exe` i dodeljuje joj **nizak nivo integriteta iz administratorske konzole**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Sada, kada pokrenem `cmd-low.exe`, on će se **pokrenuti na niskom nivou integriteta** umesto na srednjem:

![Nivoi integriteta u sistemu datoteka - Nivoi integriteta u binarnim datotekama: Sada, kada pokrenem cmd-low.exe, on će se pokrenuti na niskom nivou integriteta umesto na srednjem](<../../images/image (313).png>)

Dodeljivanje oznake visokog integriteta binarnoj datoteci (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) ne znači da će se ona automatski pokrenuti sa visokim integritetom. Ako se pozove iz procesa sa srednjim integritetom, pokreće se sa srednjim integritetom, jer novi proces dobija niži od nivoa integriteta izvršne datoteke i procesa koji ga poziva.<sup>[[1]](#references)</sup>

### Nivoi integriteta u procesima

Nemaju sve datoteke i fascikle eksplicitnu minimalnu oznaku integriteta, **ali svaki proces radi na određenom nivou integriteta**. Kao i kod objekata sistema datoteka, **proces koji želi pristup za pisanje drugom procesu mora imati najmanje isti nivo integriteta**. Zbog toga proces sa niskim integritetom ne može da otvori proces sa srednjim integritetom sa potpunim pristupom.<sup>[[1]](#references)</sup>

Zbog ovih ograničenja, najbezbedniji pristup je da se **svaki proces pokreće na najnižem nivou integriteta koji mu i dalje omogućava da obavlja predviđeni posao**.

## References

- [1] [Microsoft Learn – Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL enumeration](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Chromium source – Default Windows sandbox integrity policy](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
- [6] [Microsoft Learn – Well-known SIDs](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
{{#include ../../banners/hacktricks-training.md}}
