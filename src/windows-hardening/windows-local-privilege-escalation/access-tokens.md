# Tokeni pristupa

{{#include ../../banners/hacktricks-training.md}}

## Tokeni pristupa

Svaki proces ima **primarni token pristupa** koji definiše njegov bezbednosni kontekst. Nit obično koristi taj token, ali privremeno može imati i **token za impersonaciju**. Tokeni sadrže SID korisnika, SID-ove grupa, privilegije, informacije o integritetu i SID prijavljivanja za sesiju prijavljivanja. Procesi uglavnom nasleđuju referencu na primarni token roditeljskog procesa; ne dobijaju nezavisnu kopiju njegovog sadržaja.<sup>[[4]](#references)</sup>

Ove informacije možete da vidite pomoću komande `whoami /all`

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

ili pomoću _Process Explorer_ kompanije Sysinternals (izaberite proces i otvorite karticu „Security“):

![Access Tokens - Access Tokens: ili pomoću Process Explorer-a kompanije Sysinternals (izaberite proces i otvorite karticu „Security“)](<../../images/image (772).png>)

### Lokalni administrator

Kada se **UAC Admin Approval Mode** primenjuje na administratora, interaktivno prijavljivanje kreira potpuni administratorski token i filtrirani token. Explorer i uobičajeni podređeni procesi podrazumevano koriste filtrirani token. Zahtev za povišenje privilegija, kao što je **Run as administrator**, traži od UAC-a da pokrene program sa potpunim tokenom. Tačno ponašanje se razlikuje za ugrađeni nalog Administrator i kada je Admin Approval Mode onemogućen.<sup>[[5]](#references)</sup>

Pogledajte posebnu [**UAC stranicu**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) za tehnike zaobilaženja i detalje o pravilima.

U praksi, to znači da se **administratorska ljuska bez povišenih privilegija obično pokreće sa filtriranim tokenom**. Zato `whoami /groups` često prikazuje **`BUILTIN\Administrators` kao `Deny only`** dok se procesu ne podignu privilegije. Interno, Windows čuva **povezani token sa povišenim privilegijama** (`TokenLinkedToken`) i prati stanje pomoću polja kao što je `TokenElevationType`.

### Impersonacija korisnika pomoću kredencijala

Ako imate **važeće kredencijale bilo kog drugog korisnika**, možete **kreirati** **novu sesiju prijavljivanja** pomoću tih kredencijala:

```
runas /user:domain\username cmd.exe
```

The **access token** takođe sadrži **referencu** na logon sesije unutar **LSASS-a**; ovo je korisno ako proces treba da pristupi nekim objektima na mreži.\
Možete pokrenuti proces koji **koristi različite akreditive za pristup mrežnim servisima** pomoću:

```
runas /user:domain\username /netonly cmd.exe
```

Ovo je korisno ako imate kredencijale koji omogućavaju pristup objektima na mreži, ali oni ne važe na trenutnom hostu, jer će se koristiti samo na mreži (na trenutnom hostu koristiće se privilegije vašeg trenutnog korisnika).

#### Detalji o `runas /netonly`

`runas /netonly` (i C2 pomoćni alati kao što je `make_token`) kreira token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Ovo je veoma korisno za razumevanje tokom lateral movement-a, jer:<sup>[[3]](#references)</sup>

- **Lokalno**, novi proces zadržava **isti lokalni identitet**, grupe, nivo integriteta i većinu istih odluka o pristupu kao trenutni token.
- **Udaljeno**, za odlaznu autentifikaciju mogu se koristiti **dostavljeni kredencijali** za SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Zato `whoami` i dalje može da prikaže **originalnog lokalnog korisnika**, dok se mrežnom pristupu pristupa kao **alternativni nalog**.

Ovo je odlična opcija kada kredencijali važe na domenu ili drugom hostu, ali korisnik **ne može ili ne bi trebalo da se lokalno prijavi** na trenutnu mašinu.

### Tipovi tokena

Postoje dva tipa tokena:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primarni token**: Predstavlja bezbednosni kontekst procesa. Podređeni proces obično nasleđuje primarni token roditeljskog procesa, dok API-ji za kreiranje procesa sa eksplicitnim tokenom imaju sopstvene zahteve za pristup tokenu i privilegije pozivaoca.
- **Token za impersonaciju**: Omogućava niti servera da privremeno koristi bezbednosni kontekst klijenta za provere pristupa. Postoje četiri nivoa:
  - **Anonymous**: Daje serveru pristup sličan pristupu neidentifikovanog korisnika.
  - **Identification**: Omogućava serveru da proveri identitet klijenta, ali ne i da ga koristi za pristup objektima.
  - **Impersonation**: Omogućava serveru da radi pod identitetom klijenta.
  - **Delegation**: Omogućava serveru da se predstavlja kao klijent na udaljenim sistemima kada mehanizam autentifikacije i konfiguracija naloga podržavaju delegiranje.

#### Proverite prikupljeni token pre upotrebe

Ne birajte token samo na osnovu korisničkog imena. Isti nalog može imati više tokena sa različitim sesijama prijavljivanja, service SID-ovima, privilegijama, nivoima integriteta, ograničenjima i mrežnim kredencijalima.<sup>[[9]](#references)</sup> Pomoću `GetTokenInformation` proverite najmanje **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** i **`TokenStatistics.AuthenticationId`**.<sup>[[7]](#references)</sup>

Ograničeni token može sadržati SID-ove koji služe samo za zabranu, uklonjene privilegije i ograničavajuće SID-ove. Kada postoje ograničavajući SID-ovi, Windows obavlja jednu proveru pristupa sa omogućenim SID-ovima, a drugu sa ograničavajućim SID-ovima; **obe provere moraju dozvoliti pristup**. Zato privlačan korisnički SID ili omogućena grupa u izlazu sami po sebi ne dokazuju da token može da pristupi ciljnom objektu.<sup>[[8]](#references)</sup>

Pratite ovaj tok odlučivanja u skladu sa dokumentovanim zahtevima za tokene i kreiranje procesa:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Za **primarni token** potreban je handle sa pravima `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` pre nego što se prosledi funkciji `CreateProcessWithTokenW` ili `CreateProcessAsUserW`.
2. Konvertujte **token za impersonaciju** pomoću `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Tokeni nivoa Identification mogu otkriti podatke o identitetu, ali ne mogu obavljati provere pristupa kao taj klijent.
3. `CreateProcessWithTokenW` zahteva `SeImpersonatePrivilege` i pokreće podređeni proces u sesiji pozivaoca. `CreateProcessAsUserW` koristi sesiju tokena, ali obično zahteva `SeIncreaseQuotaPrivilege`, a može zahtevati i `SeAssignPrimaryTokenPrivilege`. Ako su kredencijali dostupni, a ove privilegije nedostaju, dokumentovana alternativa je `CreateProcessWithLogonW`.

#### Pronađite handle-ove tokena, ne samo vlasnike procesa

Otvaranje primarnog tokena svakog procesa može da propusti **tokene za impersonaciju sačuvane kao obični handle-ovi** u servisima i brokerskim procesima. Ponovljiv tok rada za enumeraciju tabele handle-ova jeste da nabrojite sistemske handle-ove, filtrirate objekte tokena, otvorite svakog vlasnika pomoću `PROCESS_DUP_HANDLE`, duplirate kandidatski handle u trenutni proces, a zatim proverite gorenavedena polja. Proverite da duplirani handle uključuje `TOKEN_QUERY` i `TOKEN_DUPLICATE`; prisustvo handle-a tokena ne znači da se on može duplirati u upotrebljiv primarni token. Zaštićeni procesi i DACL-ovi procesa i dalje mogu blokirati handle ka procesu vlasniku.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` automatizuje enumeraciju primarnih tokena procesa i sačuvanih handle-ova tokena. `list_token` zadržava po jednog preferiranog kandidata za svako korisničko ime, dok `list_all_token` prikazuje sve kandidate. PID ograničava enumeraciju na jedan proces vlasnika.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Za ručni pregled i proveru pristupa, **TokenUniverse** može da otvara tokene procesa/niti, pretražuje postojeće rukovaoce tokenima, pregleda ograničenja i sesije prijavljivanja, duplira tokene i testira nekoliko metoda kreiranja procesa.<sup>[[13]](#references)</sup> Više informacija o osnovnom primitivu za rukovanje između procesa potražite ovde:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Impersonacija tokena

Ako imate dovoljno privilegija, pomoću _**incognito**_ modula u Metasploit-u možete lako da **izlistate** i **impersonirate** druge **tokene**. Ovo može biti korisno za izvršavanje **radnji kao da ste drugi korisnik**. Ovom tehnikom možete i da **eskalirate privilegije**.

Nekoliko praktičnih napomena koje je lako zaboraviti tokom rada:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** zahteva **`SeImpersonatePrivilege`** u procesu pozivaoca, a novi proces će se pokrenuti u **sesiji pozivaoca**.
- **`CreateProcessAsUserW`** može da posluži kao zamena kada `CreateProcessWithTokenW` ne uspe sa greškom `1314`, ali samo ako pozivalac ispunjava zahteve za privilegije. To je ujedno i pravi izbor kada podređeni proces treba da se pokrene u **sesiji na koju se token odnosi**.<sup>[[9]](#references)[[10]](#references)</sup>
- Ako token potiče od **`LogonUser(LOGON32_LOGON_NETWORK)`**, obično je reč o **impersonation token-u**, pa je potrebno da pozovete **`DuplicateTokenEx(..., TokenPrimary, ...)`** pre pokušaja pokretanja procesa pomoću njega.
- Nisu svi impersonation token-i podjednako korisni: **`SecurityIdentification`** vam omogućava da pregledate korisnika, ali **ne i da postupate kao on**. Ako vam coercion primitive ili pipe/RPC klijent pruži samo token na nivou identifikacije, proverite **`TokenImpersonationLevel`** i pređite na primitive koji obezbeđuje **`SecurityImpersonation`** ili viši nivo.

#### Krađa tokena bez pristupa LSASS-u

Ako već imate kontekst **usluge** ili **SYSTEM**-a, a **privilegovani korisnik je prijavljen**, krađa ili dupliranje njegovog tokena često je tiše od pravljenja dump-a **LSASS**-a. U mnogim stvarnim upadima ovo je dovoljno da:<sup>[[2]](#references)</sup>

- izvršavate lokalne radnje kao taj korisnik
- pristupate udaljenim resursima kao taj korisnik
- izvršavate AD operacije bez prethodnog izdvajanja ponovo upotrebljivih akreditiva

Primeri **otmice tokena sesije/korisnika** iz privilegovanog konteksta nalaze se na stranici [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Imajte na umu da su API-ji kao što je **`WTSQueryUserToken`** namenjeni **visokopouzdanim uslugama** i obično zahtevaju **`LocalSystem` + `SeTcbPrivilege`**, pa su prvenstveno korisni kada već kontrolišete kontekst na nivou usluge. Za načine dobijanja **SYSTEM** privilegija, pogledajte stranice u nastavku.

### Privilegije tokena

Saznajte koje **privilegije tokena mogu da se zloupotrebe za eskalaciju privilegija:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Pogledajte [**sve moguće privilegije tokena i neke definicije na ovoj spoljašnjoj stranici**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Razumevanje i zloupotreba Access Tokens — II deo](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Zloupotreba Windows tokena za kompromitovanje Active Directory-ja bez pristupa LSASS-u](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Razjašnjavanje Cobalt Strike komande „make_token“](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Access Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Kako funkcioniše User Account Control - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Nivoi impersonation-a - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Enumeracija TOKEN_INFORMATION_CLASS - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Ograničeni tokeni - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Funkcija CreateProcessWithTokenW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Funkcija CreateProcessAsUserW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Funkcija DuplicateHandle - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
