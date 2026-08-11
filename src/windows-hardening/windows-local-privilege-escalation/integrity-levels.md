# Nivoi integriteta

{{#include ../../banners/hacktricks-training.md}}

## Nivoi integriteta

U operativnom sistemu Windows Vista i novijim verzijama, objekti koji podržavaju bezbednost mogu imati oznaku **nivoa integriteta**. Većina objekata tretira se kao objekat srednjeg nivoa integriteta, dok određene lokacije namenjene aplikacijama sa niskim nivoom integriteta mogu biti označene kao objekti niskog nivoa. Procesi koje pokreću standardni korisnici obično rade sa srednjim nivoom integriteta, aplikacije pokrenute sa povišenim privilegijama rade sa visokim nivoom integriteta, a mnogi servisi rade sa sistemskim nivoom integriteta.<sup>[[1]](#references)</sup>

Ključno pravilo je da procese sa nižim nivoom integriteta nije moguće koristiti za izmenu objekata čiji je nivo integriteta viši. Windows primenjuje ovu proveru Mandatory Integrity Control (MIC) pre procene object's discretionary access control liste (DACL). Najčešći nivoi su:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: Najniži nivo, predstavljen vrednošću `SECURITY_MANDATORY_UNTRUSTED_RID`.
- **Low**: Uglavnom se koristi za interakcije sa internetom, naročito u Protected Mode-u programa Internet Explorer, što utiče na povezane datoteke i procese, kao i na određene fascikle poput **Temporary Internet Folder**. Procesi sa niskim nivoom integriteta suočavaju se sa značajnim ograničenjima, uključujući zabranu upisivanja u registry i ograničen pristup upisivanju u korisnički profil.
- **Medium**: Podrazumevani nivo za većinu aktivnosti, dodeljen standardnim korisnicima i objektima bez posebno definisanih nivoa integriteta. Čak i članovi grupe Administrators podrazumevano rade na ovom nivou.
- **High**: Rezervisan za administratore, omogućavajući im da menjaju objekte sa nižim nivoima integriteta, uključujući i one koji imaju visoki nivo.
- **System**: Najviši operativni nivo za Windows kernel i osnovne servise, nedostupan čak i administratorima, čime se obezbeđuje zaštita ključnih sistemskih funkcija.

Windows takođe definiše vrednost integriteta protected-process iznad nivoa System. **TrustedInstaller**, međutim, predstavlja identitet Windows servisa, a ne zaseban MIC nivo; njegova mogućnost izmene zaštićenih resursa operativnog sistema potiče od dozvola dodeljenih tom identitetu.

Nivo integriteta procesa možete dobiti pomoću alata **Process Explorer** iz paketa **Sysinternals**, tako što otvorite svojstva procesa i prikažete karticu **Security**:<sup>[[3]](#references)</sup>

![Nivoi integriteta - Nivoi integriteta: Nivo integriteta procesa možete dobiti pomoću alata Process Explorer iz paketa Sysinternals, tako što otvorite svojstva procesa i prikažete karticu "...](<../../images/image (824).png>)

Svoj **trenutni nivo integriteta** možete dobiti i pomoću komande `whoami /groups`:

![Nivoi integriteta - Nivoi integriteta: Svoj trenutni nivo integriteta možete dobiti i pomoću komande whoami /groups](<../../images/image (325).png>)

### Nivoi integriteta u sistemu datoteka

Objekat u sistemu datoteka može imati **minimalni zahtevani nivo integriteta**. Proces čiji je nivo ispod tog nivoa podleže obaveznoj politici objekta čak i kada bi mu DACL inače dozvolio pristup. Na primer, napravite običnu datoteku iz konzole standardnog korisnika i proverite njene dozvole:<sup>[[1]](#references)[[4]](#references)</sup>
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
Sada dodelite minimalni nivo integriteta **High** datoteci. Ovo **mora da se uradi iz konzole** pokrenute kao **administrator**, jer se obična konzola pokreće sa nivoom integriteta Medium i **neće imati dozvolu** da objektu dodeli nivo integriteta High:
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
Korisnik `DESKTOP-IDJHTKP\user` ima **FULL privileges** nad datotekom jer ju je taj korisnik kreirao. Međutim, mandatory label sprečava korisnika da menja datoteku osim ako proces ne radi na nivou High integrity. Korisnik i dalje može da je čita jer je prikazana mandatory policy `(NW)`, odnosno no-write-up:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Stoga, kada datoteka ima minimalni nivo integriteta, da biste je izmenili morate raditi najmanje na tom nivou integriteta.**

### Nivoi integriteta u binarnim datotekama

Sledeći primer koristi kopiju datoteke `cmd.exe` na putanji `C:\Windows\System32\cmd-low.exe` i dodeljuje joj **Low nivo integriteta iz administratorske konzole**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Sada, kada pokrenem `cmd-low.exe`, on će se **pokrenuti sa nivoom niskog integriteta** umesto sa srednjim:

![Nivoi integriteta u sistemu datoteka - Nivoi integriteta u binarnim datotekama: Sada, kada pokrenem cmd-low.exe, on će se pokrenuti sa nivoom niskog integriteta umesto sa srednjim](<../../images/image (313).png>)

Dodeljivanje oznake visokog integriteta binarnoj datoteci (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) ne znači da će se ona automatski pokrenuti sa visokim integritetom. Ako se pozove iz procesa sa srednjim integritetom, pokreće se sa srednjim integritetom, jer novi proces dobija niži od nivoa integriteta izvršne datoteke i procesa koji ga poziva.<sup>[[1]](#references)</sup>

### Nivoi integriteta u procesima

Nemaju sve datoteke i fascikle eksplicitnu minimalnu oznaku integriteta, **ali svaki proces radi na određenom nivou integriteta**. Kao i kod objekata sistema datoteka, **proces koji želi pristup za upis drugom procesu mora imati najmanje isti nivo integriteta**. Zbog toga proces sa niskim integritetom ne može da otvori proces sa srednjim integritetom sa potpunim pristupom.<sup>[[1]](#references)</sup>

Zbog ovih ograničenja, najbezbedniji pristup je da se **svaki proces pokreće na najnižem nivou integriteta koji mu i dalje omogućava da obavlja predviđeni posao**.

## References

- [1] [Microsoft Learn – Obavezna kontrola integriteta](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – Nabrajanje MANDATORY_LEVEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
{{#include ../../banners/hacktricks-training.md}}
