# Tokeni za pristup

{{#include ../../banners/hacktricks-training.md}}

## Tokeni za pristup

Svaki proces ima **primarni token za pristup** koji definiše njegov bezbednosni kontekst. Nit obično koristi taj token, ali može privremeno da ima i **token za impersonaciju**. Tokeni sadrže SID korisnika, SID-ove grupa, privilegije, informacije o integritetu i SID prijave za sesiju prijave. Procesi uglavnom nasleđuju referencu na primarni token roditeljskog procesa; ne dobijaju nezavisnu kopiju njegovog sadržaja.<sup>[[4]](#references)</sup>

Ove informacije možete da vidite izvršavanjem komande `whoami /all`

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

ili pomoću _Process Explorer_ iz Sysinternals (izaberite proces i otvorite karticu „Bezbednost“):

![Tokeni za pristup - Tokeni za pristup: ili pomoću Process Explorer iz Sysinternals (izaberite proces i otvorite karticu „Bezbednost“)](<../../images/image (772).png>)

### Lokalni administrator

Kada se **UAC Admin Approval Mode** primenjuje na administratora, interaktivna prijava kreira pun administratorski token i filtrirani token. Explorer i uobičajeni podređeni procesi podrazumevano koriste filtrirani token. Zahtev za povišenje privilegija, kao što je **Pokreni kao administrator**, traži od UAC-a da pokrene program s punim tokenom. Tačno ponašanje se razlikuje za ugrađeni nalog Administrator i kada je Admin Approval Mode onemogućen.<sup>[[5]](#references)</sup>

Pročitajte posebnu [**UAC stranicu**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) za tehnike zaobilaženja i detalje o smernicama.

U praksi to znači da **nepovišena administratorska ljuska obično radi s filtriranim tokenom**. Zato `whoami /groups` često prikazuje **`BUILTIN\Administrators` kao `Deny only`** sve dok se privilegije procesa ne povise. Windows interno čuva **povezani povišeni token** (`TokenLinkedToken`) i prati stanje pomoću polja kao što je `TokenElevationType`.

### Impersonacija korisnika pomoću akreditiva

Ako imate **važeće akreditive bilo kog drugog korisnika**, možete **kreirati** **novu sesiju prijave** pomoću tih akreditiva:

```
runas /user:domain\username cmd.exe
```

**Token za pristup** takođe sadrži **referencu** na sesije prijavljivanja unutar **LSASS-a**; to je korisno ako proces treba da pristupa nekim mrežnim objektima.\
Možeš pokrenuti proces koji **koristi različite akreditive za pristup mrežnim servisima** pomoću:

```
runas /user:domain\username /netonly cmd.exe
```

Ovo je korisno ako imate akreditive koji omogućavaju pristup objektima na mreži, ali ti akreditivi ne važe na trenutnom hostu, jer će se koristiti samo na mreži (na trenutnom hostu koristiće se privilegije vašeg trenutnog korisnika).

#### Detalji za `runas /netonly`

`runas /netonly` (i C2 pomoćni alati kao što je `make_token`) kreira token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Ovo je veoma korisno za razumevanje tokom lateral movement-a, jer:<sup>[[3]](#references)</sup>

- **Lokalno**, novi proces zadržava **isti lokalni identitet**, grupe, nivo integriteta i većinu istih odluka o pristupu kao trenutni token.
- **Udaljeno**, za odlaznu autentifikaciju mogu se koristiti **dostavljeni akreditivi** za SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Zato `whoami` i dalje može da prikazuje **originalnog lokalnog korisnika**, dok se pristup mreži ostvaruje kao **alternativni nalog**.

Ovo je odlična opcija kada akreditivi važe u domenu ili na drugom hostu, ali korisnik **ne može ili ne bi trebalo lokalno da se prijavi** na trenutnu mašinu.

### Tipovi tokena

Dostupna su dva tipa tokena:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primarni token**: Predstavlja bezbednosni kontekst procesa. Podređeni proces obično nasleđuje primarni token roditeljskog procesa, dok API-ji za eksplicitno kreiranje procesa pomoću tokena imaju sopstvene zahteve za pristup tokenu i privilegije pozivaoca.
- **Token za impersonaciju**: Omogućava niti servera da privremeno koristi bezbednosni kontekst klijenta za provere pristupa. Ima četiri nivoa:
  - **Anonimni**: Daje serveru pristup sličan pristupu neidentifikovanog korisnika.
  - **Identifikacioni**: Omogućava serveru da proveri identitet klijenta, ali ne i da ga koristi za pristup objektima.
  - **Impersonacija**: Omogućava serveru da radi pod identitetom klijenta.
  - **Delegiranje**: Omogućava serveru da impersonira klijenta na udaljenim sistemima ako mehanizam autentifikacije i konfiguracija naloga podržavaju delegiranje.

#### Proverite uhvaćeni token pre upotrebe

Nemojte birati token samo na osnovu korisničkog imena. Isti nalog može imati više tokena sa različitim sesijama prijavljivanja, SID-ovima servisa, privilegijama, nivoima integriteta, ograničenjima i mrežnim akreditivima.<sup>[[9]](#references)</sup> Pomoću `GetTokenInformation` proverite najmanje **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** i **`TokenStatistics.AuthenticationId`**.<sup>[[7]](#references)</sup>

Ograničeni token može sadržati SID-ove koji se koriste samo za zabranu, uklonjene privilegije i ograničavajuće SID-ove. Kada postoje ograničavajući SID-ovi, Windows obavlja jednu proveru pristupa pomoću omogućenih SID-ova, a drugu pomoću ograničavajućih SID-ova; **obe provere moraju dozvoliti pristup**. Zato privlačan korisnički SID ili omogućena grupa u izlazu sami po sebi ne dokazuju da token može da pristupi ciljnom objektu.<sup>[[8]](#references)</sup>

Pratite ovaj tok odlučivanja za dokumentovane zahteve za token i kreiranje procesa:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Za **primarni token** potreban je handle sa pravima `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` pre nego što može da se prosledi funkciji `CreateProcessWithTokenW` ili `CreateProcessAsUserW`.
2. Pretvorite **token za impersonaciju** pomoću `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Tokeni nivoa Identification mogu da otkriju podatke o identitetu, ali ne mogu da obavljaju provere pristupa kao taj klijent.
3. Za `CreateProcessWithTokenW` potrebna je privilegija `SeImpersonatePrivilege`, a podređeni proces se pokreće u sesiji pozivaoca. `CreateProcessAsUserW` umesto toga koristi sesiju tokena, ali mu je obično potrebna privilegija `SeIncreaseQuotaPrivilege`, a može biti potrebna i privilegija `SeAssignPrimaryTokenPrivilege`. Ako su akreditivi dostupni, a ove privilegije nedostaju, dokumentovana alternativa je `CreateProcessWithLogonW`.

#### Tražite handle-ove tokena, ne samo vlasnike procesa

Otvaranjem primarnog tokena svakog procesa možete propustiti **tokene za impersonaciju sačuvane kao obični handle-ovi** u servisima i brokerskim procesima. Ponovljiv postupak rada sa tabelom handle-ova jeste da nabrojite sistemske handle-ove, filtrirate objekte tokena, otvorite svaki vlasnički proces pomoću `PROCESS_DUP_HANDLE`, duplirate kandidatni handle u trenutni proces, pa zatim proverite gore navedena polja. Proverite da duplirani handle sadrži `TOKEN_QUERY` i `TOKEN_DUPLICATE`; to što vidite handle tokena ne znači da može da se duplira u upotrebljiv primarni token. Zaštićeni procesi i DACL-ovi procesa i dalje mogu da blokiraju handle vlasničkog procesa.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` automatizuje nabrajanje primarnih tokena procesa i sačuvanih handle-ova tokena. `list_token` zadržava po jednog poželjnog kandidata za svako korisničko ime, dok `list_all_token` ispisuje sve kandidate. PID ograničava nabrajanje na jedan vlasnički proces.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Za ručni pregled i proveru pristupa, **TokenUniverse** može da otvara tokene procesa/niti, pretražuje postojeće ručice tokena, pregleda ograničenja i logon sesije, duplira tokene i testira nekoliko metoda za kreiranje procesa.<sup>[[13]](#references)</sup> Za osnovni primitiv za ručice između procesa pogledajte:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Impersoniranje tokena

Ako imate dovoljno privilegija, pomoću _**incognito**_ modula za metasploit možete lako da **izlistate** i **impersonirate** druge **tokene**. Ovo može biti korisno za obavljanje **radnji kao da ste drugi korisnik**. Ovom tehnikom možete i da **eskalirate privilegije**.

Neke praktične napomene koje je lako zaboraviti tokom rada:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** zahteva **`SeImpersonatePrivilege`** od pozivaoca, a novi proces će se pokrenuti u **sesiji pozivaoca**.
- **`CreateProcessAsUserW`** je moguća rezervna opcija kada `CreateProcessWithTokenW` ne uspe uz grešku `1314`, ali samo ako pozivalac ispunjava zahteve za privilegije. To je i ispravan izbor kada se podređeni proces mora pokrenuti u **sesiji na koju token upućuje**.<sup>[[9]](#references)[[10]](#references)</sup>
- Ako token potiče od **`LogonUser(LOGON32_LOGON_NETWORK)`**, obično je to **token impersoniranja**, pa pre pokušaja pokretanja procesa s njim treba da pozovete **`DuplicateTokenEx(..., TokenPrimary, ...)`**.
- Nisu svi tokeni impersoniranja podjednako korisni: **`SecurityIdentification`** vam omogućava da pregledate korisnika, ali **ne i da delujete u njegovo ime**. Ako vam coercion primitiv ili pipe/RPC klijent obezbedi samo token nivoa identifikacije, proverite **`TokenImpersonationLevel`** i pređite na primitiv koji daje **`SecurityImpersonation`** ili viši nivo.

#### Krađa tokena bez pristupa LSASS-u

Ako već imate kontekst **usluge** ili **SYSTEM** i **prijavljen je privilegovani korisnik**, krađa ili dupliranje tokena tog korisnika često je tiše od dumpovanja **LSASS-a**. U mnogim stvarnim upadima ovo je dovoljno da:<sup>[[2]](#references)</sup>

- obavljate lokalne radnje kao taj korisnik
- pristupate udaljenim resursima kao taj korisnik
- obavljate AD operacije bez prethodnog izvlačenja ponovo upotrebljivih akreditiva

Za primere **otimanja tokena sesije/korisnika** iz privilegovanog konteksta pogledajte [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Imajte na umu da su API-ji kao što je **`WTSQueryUserToken`** namenjeni **visokopouzdanim uslugama** i da obično zahtevaju **`LocalSystem` + `SeTcbPrivilege`**, pa su uglavnom korisni tek kada već kontrolišete kontekst na nivou usluge. Za načine dobijanja privilegije **SYSTEM** korišćenjem određenih privilegija, prvo pogledajte stranice u nastavku.

### Privilegije tokena

Saznajte koje **privilegije tokena mogu da se zloupotrebe za eskalaciju privilegija:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Pogledajte [**sve moguće privilegije tokena i neke definicije na ovoj spoljnoj stranici**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Razumevanje i zloupotreba tokena pristupa — II deo](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Zloupotreba Windows tokena za kompromitovanje Active Directory-ja bez pristupa LSASS-u](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Razjašnjavanje Cobalt Strike komande "make_token"](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Tokeni pristupa - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Kako funkcioniše kontrola korisničkog naloga - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Nivoi impersoniranja - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Enumeracija TOKEN_INFORMATION_CLASS - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Ograničeni tokeni - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Funkcija CreateProcessWithTokenW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Funkcija CreateProcessAsUserW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Funkcija DuplicateHandle - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
