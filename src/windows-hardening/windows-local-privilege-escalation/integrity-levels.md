# Nivoi integriteta

{{#include ../../banners/hacktricks-training.md}}

## Nivoi integriteta

U Windows Vista i novijim verzijama, sve zaštićene stavke imaju oznaku **nivoa integriteta**. Ova postavka uglavnom dodeljuje "srednji" nivo integriteta datotekama i ključevima registra, osim određenim fasciklama i datotekama u koje Internet Explorer 7 može da upisuje na niskom nivou integriteta. Podrazumevano ponašanje je da procesi koje pokreću standardni korisnici imaju srednji nivo integriteta, dok servisi obično rade na sistemskom nivou integriteta. Oznaka visokog integriteta štiti korenski direktorijum.

Važno pravilo je da procese sa nižim nivoom integriteta nije moguće koristiti za izmenu objekata čiji je nivo viši. Nivoi integriteta su:

- **Untrusted**: Ovaj nivo je namenjen procesima sa anonimnim prijavljivanjem. Primer: Chrome
- **Low**: Uglavnom se koristi za internet interakcije, naročito u Protected Mode-u programa Internet Explorer, što utiče na povezane datoteke i procese, kao i na određene fascikle poput **Temporary Internet Folder**. Procesi sa niskim nivoom integriteta suočavaju se sa značajnim ograničenjima, uključujući zabranu upisivanja u registar i ograničen upis u korisnički profil.
- **Medium**: Podrazumevani nivo za većinu aktivnosti, dodeljuje se standardnim korisnicima i objektima bez posebno definisanih nivoa integriteta. Čak i članovi grupe Administrators podrazumevano rade na ovom nivou.
- **High**: Rezervisan je za administratore i omogućava im da menjaju objekte sa nižim nivoima integriteta, uključujući i one na samom visokom nivou.
- **System**: Najviši operativni nivo za Windows kernel i osnovne servise, nedostupan čak i administratorima, čime se obezbeđuje zaštita ključnih sistemskih funkcija.
- **Installer**: Jedinstveni nivo koji je iznad svih ostalih i omogućava objektima na ovom nivou da deinstaliraju bilo koji drugi objekat.

Nivo integriteta procesa možete dobiti pomoću alata **Process Explorer** iz paketa **Sysinternals**, tako što otvorite **properties** procesa i pogledate karticu "**Security**":

![Nivoi integriteta - Nivoi integriteta: Nivo integriteta procesa možete dobiti pomoću alata Process Explorer iz paketa Sysinternals, tako što otvorite properties procesa i pogledate karticu "...](<../../images/image (824).png>)

Svoj **trenutni nivo integriteta** možete dobiti i pomoću komande `whoami /groups`

![Nivoi integriteta - Nivoi integriteta: Svoj trenutni nivo integriteta možete dobiti i pomoću komande whoami /groups](<../../images/image (325).png>)

### Nivoi integriteta u sistemu datoteka

Objekat unutar sistema datoteka može zahtevati **minimalni nivo integriteta**, a ako proces nema taj nivo integriteta, neće moći da komunicira sa njim.\
Na primer, **napravimo običnu datoteku iz konzole standardnog korisnika i proverimo dozvole**:
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
Sada dodelimo minimalni nivo integriteta **High** datoteci. Ovo **mora da se uradi iz konzole** pokrenute kao **administrator**, jer će **regularna konzola** raditi na nivou Medium Integrity i **neće moći** da dodeli nivo High Integrity objektu:
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
Ovde stvari postaju zanimljive. Možete videti da korisnik `DESKTOP-IDJHTKP\user` ima **FULL privileges** nad datotekom (zapravo, to je korisnik koji je kreirao datoteku), međutim, zbog implementiranog minimalnog nivoa integriteta više neće moći da izmeni datoteku, osim ako radi unutar visokog nivoa integriteta (imajte na umu da će moći da je čita):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Prema tome, kada datoteka ima minimalni nivo integriteta, da biste je izmenili, morate raditi najmanje na tom nivou integriteta.**

### Nivoi integriteta u binarnim datotekama

Napravio sam kopiju datoteke `cmd.exe` u `C:\Windows\System32\cmd-low.exe` i podesio joj **nizak nivo integriteta iz administratorske konzole:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Sada, kada pokrenem `cmd-low.exe`, on će se **pokrenuti pod nivoom niskog integriteta** umesto srednjeg:

![Nivoi integriteta u sistemu datoteka - Nivoi integriteta u binarnim datotekama: Sada, kada pokrenem cmd-low.exe, on će se pokrenuti pod nivoom niskog integriteta umesto srednjeg](<../../images/image (313).png>)

Za radoznale, ako binarnoj datoteci dodelite visok nivo integriteta (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), ona se neće automatski pokrenuti sa visokim nivoom integriteta (ako je pozovete iz procesa sa srednjim nivoom integriteta --podrazumevano-- pokrenuće se pod srednjim nivoom integriteta).

### Nivoi integriteta u procesima

Nemaju sve datoteke i fascikle minimalni nivo integriteta, **ali svi procesi rade pod određenim nivoom integriteta**. Slično kao u sistemu datoteka, **ako proces želi da piše unutar drugog procesa, mora imati najmanje isti nivo integriteta**. To znači da proces sa niskim nivoom integriteta ne može da otvori handle sa potpunim pristupom procesu sa srednjim nivoom integriteta.

Zbog ograničenja navedenih u ovom i prethodnom odeljku, sa stanovišta bezbednosti uvek se **preporučuje pokretanje procesa na najnižem mogućem nivou integriteta**.

{{#include ../../banners/hacktricks-training.md}}
