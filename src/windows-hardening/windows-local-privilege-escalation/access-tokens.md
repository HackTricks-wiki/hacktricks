# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Svaki **korisnik prijavljen** na sistem **poseduje access token sa bezbednosnim informacijama** za tu sesiju prijavljivanja. Sistem kreira access token kada se korisnik prijavi. **Svaki proces izvršen** u ime korisnika **poseduje kopiju access tokena**. Token identifikuje korisnika, korisničke grupe i korisničke privilegije. Token takođe sadrži logon SID (Security Identifier) koji identifikuje trenutnu sesiju prijavljivanja.

Ove informacije možete videti izvršavanjem komande `whoami /all`
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
ili korišćenjem _Process Explorer_ alata iz Sysinternals-a (izaberite proces i otvorite karticu "Security"):

![Access Tokens - Access Tokens: ili korišćenjem Process Explorer alata iz Sysinternals-a (izaberite proces i otvorite karticu "Security")](<../../images/image (772).png>)

### Lokalni administrator

Kada se lokalni administrator prijavi, **kreiraju se dva access tokena**: jedan sa administratorskim pravima, a drugi sa normalnim pravima. **Podrazumevano**, kada ovaj korisnik izvrši proces, koristi se token sa **standardnim** (neadministratorskim) **pravima**. Kada ovaj korisnik pokuša da nešto **izvrši** **kao administrator** (na primer, "Run as Administrator"), koristiće se **UAC** za traženje dozvole.\
Ako želite da [**saznate više o UAC-u, pročitajte ovu stranicu**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

U praksi, to znači da **ne-elevated administratorski shell obično radi sa filtriranim tokenom**. Zato `whoami /groups` često prikazuje **`BUILTIN\Administrators` kao `Deny only`** sve dok se proces ne elevira. Interno, Windows održava **povezani elevated token** (`TokenLinkedToken`) i prati stanje pomoću polja kao što je `TokenElevationType`.

### Impersonation korisnika pomoću credentials-a

Ako imate **važeće credentials-e bilo kog drugog korisnika**, možete **kreirati** **novu logon sesiju** pomoću tih credentials-a:
```
runas /user:domain\username cmd.exe
```
The **access token** takođe sadrži **referencu** na sesije prijavljivanja unutar **LSASS**-a, što je korisno ako proces treba da pristupi nekim mrežnim objektima.\
Proces koji **koristi različite akreditive za pristup mrežnim servisima** možeš pokrenuti pomoću:
```
runas /user:domain\username /netonly cmd.exe
```
Ovo je korisno ako imate korisne kredencijale za pristup objektima u mreži, ali ti kredencijali nisu važeći unutar trenutnog hosta, jer će se koristiti samo u mreži (na trenutnom hostu biće korišćene privilegije trenutnog korisnika).

#### Detalji za `runas /netonly`

`runas /netonly` (i C2 helpers kao što je `make_token`) kreira **`LOGON32_LOGON_NEW_CREDENTIALS`** token. Ovo je veoma korisno za razumevanje tokom lateral movement-a, jer:<sup>[[3]](#references)</sup>

- **Lokalno**, novi proces zadržava **isti lokalni identitet**, grupe, nivo integriteta i većinu istih odluka o pristupu kao trenutni token.
- **Udaljeno**, odlazna autentikacija može koristiti **navedene kredencijale** za SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Zato `whoami` i dalje može prikazivati **originalnog lokalnog korisnika**, dok se mrežnom pristupu pristupa kao **alternativni nalog**.

Ovo je odlična opcija kada su kredencijali važeći u domenu ili na drugom hostu, ali korisnik **ne može ili ne treba da se lokalno prijavi** na trenutnu mašinu.

### Tipovi tokena

Dostupna su dva tipa tokena:

- **Primary Token**: Predstavlja bezbednosne kredencijale procesa. Kreiranje i povezivanje primary tokena sa procesima zahteva povišene privilegije, naglašavajući princip razdvajanja privilegija. Obično je authentication service odgovoran za kreiranje tokena, dok je logon service zadužen za njegovo povezivanje sa korisničkim shell-om operativnog sistema. Važno je napomenuti da procesi prilikom kreiranja nasleđuju primary token svog parent procesa.
- **Impersonation Token**: Omogućava server aplikaciji da privremeno preuzme identitet klijenta radi pristupa zaštićenim objektima. Ovaj mehanizam je podeljen na četiri nivoa rada:
- **Anonymous**: Omogućava serveru pristup sličan pristupu neidentifikovanog korisnika.
- **Identification**: Omogućava serveru da proveri identitet klijenta, ali bez njegovog korišćenja za pristup objektima.
- **Impersonation**: Omogućava serveru da radi pod identitetom klijenta.
- **Delegation**: Slično kao Impersonation, ali uključuje mogućnost proširenja ovog preuzetog identiteta na udaljene sisteme sa kojima server komunicira, uz očuvanje kredencijala.

#### Impersonate Tokens

Korišćenjem _**incognito**_ modula metasploita, ako imate dovoljno privilegija, možete jednostavno da **izlistate** i **impersonate** druge **tokene**. Ovo može biti korisno za izvršavanje **akcija kao da ste drugi korisnik**. Ovom tehnikom možete i **eskalirati privilegije**.

Neke praktične napomene koje se lako zaboravljaju tokom rada:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** zahteva **`SeImpersonatePrivilege`** kod pozivaoca, a novi proces će raditi u **sesiji pozivaoca**.
- **`CreateProcessAsUserW`** je uobičajeni fallback kada `CreateProcessWithTokenW` ne uspe sa greškom `1314`, ili kada je potrebno pokretanje u **sesiji na koju token upućuje**.
- Ako token potiče od **`LogonUser(LOGON32_LOGON_NETWORK)`**, on je obično **impersonation token**, pa je potrebno **`DuplicateTokenEx(..., TokenPrimary, ...)`** pre pokušaja pokretanja procesa pomoću njega.
- Nisu svi impersonation tokeni podjednako korisni: **`SecurityIdentification`** omogućava pregled korisnika, ali **ne i delovanje u njegovo ime**. Ako coercion primitive ili pipe/RPC client obezbedi samo token na identification nivou, proverite **`TokenImpersonationLevel`** i pređite na primitive koji daje **`SecurityImpersonation`** ili viši nivo.

#### Krađa tokena bez dodirivanja LSASS-a

Ako već imate **service** ili **SYSTEM** context, a **privileged user je prijavljen**, krađa ili dupliciranje tokena tog korisnika često je tiše od dumpovanja **LSASS-a**. U mnogim stvarnim upadima ovo je dovoljno za:<sup>[[2]](#references)</sup>

- izvršavanje lokalnih akcija kao taj korisnik
- pristup udaljenim resursima kao taj korisnik
- izvršavanje AD operacija bez prethodnog izvlačenja kredencijala koji se mogu ponovo koristiti

Za primere **session/user token hijacking-a** iz privilegovanog context-a pogledajte [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Imajte na umu da su API-ji kao što je **`WTSQueryUserToken`** namenjeni **visoko pouzdanim servisima** i obično zahtevaju **`LocalSystem` + `SeTcbPrivilege`**, pa su prvenstveno korisni kada već kontrolišete context na nivou servisa. Za načine dobijanja **SYSTEM** privilegija specifične za privilegije, prvo pogledajte stranice u nastavku.

### Token Privileges

Saznajte koje **token privileges mogu biti zloupotrebljene za eskalaciju privilegija:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Pogledajte [**sve moguće token privileges i neke definicije na ovoj eksternoj stranici**](https://github.com/gtworek/Priv2Admin).

## Reference

- [1] [Razumevanje i zloupotreba access tokena — II deo](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Zloupotreba Windows tokena za kompromitovanje Active Directory-ja bez dodirivanja LSASS-a](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Razjašnjavanje Cobalt Strike komande "make_token"](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
