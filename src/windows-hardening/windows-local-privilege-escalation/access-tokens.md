# Tokeni za pristup

{{#include ../../banners/hacktricks-training.md}}

## Tokeni za pristup

Svaki proces ima **primarni token za pristup** koji definiše njegov bezbednosni kontekst. Nit obično koristi taj token, ali privremeno može imati i **token za impersonaciju**. Tokeni sadrže SID korisnika, SID-ove grupa, privilegije, informacije o integritetu i SID prijavljivanja za sesiju prijavljivanja. Procesi uglavnom nasleđuju referencu na primarni token roditeljskog procesa; ne dobijaju nezavisnu kopiju njegovog sadržaja.<sup>[[4]](#references)</sup>

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

ili pomoću _Process Explorer_ iz Sysinternals-a (izaberite proces i otvorite karticu "Security"):

![Access Tokens - Access Tokens: ili pomoću Process Explorer-a iz Sysinternals-a (izaberite proces i otvorite karticu "Security")](<../../images/image (772).png>)

### Lokalni administrator

Kada se na administratora primenjuje **UAC Admin Approval Mode**, interaktivno prijavljivanje kreira potpuni administratorski token i filtrirani token. Explorer i obični podređeni procesi podrazumevano koriste filtrirani token. Zahtev za elevaciju, kao što je **Run as administrator**, traži od UAC-a da pokrene program sa potpunim tokenom. Tačno ponašanje se razlikuje za ugrađeni Administrator nalog i kada je Admin Approval Mode onemogućen.<sup>[[5]](#references)</sup>

Pročitajte posvećenu [**UAC stranicu**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) za tehnike zaobilaženja i detalje o pravilima.

U praksi to znači da **ne-elevirana administratorska ljuska obično radi sa filtriranim tokenom**. Zato `whoami /groups` često prikazuje **`BUILTIN\Administrators` kao `Deny only`** sve dok se proces ne podigne sa višim privilegijama. Interno, Windows čuva **povezani token sa višim privilegijama** (`TokenLinkedToken`) i prati stanje pomoću polja kao što je `TokenElevationType`.

### Impersonacija korisnika pomoću akreditiva

Ako imate **važeće akreditive bilo kog drugog korisnika**, možete da **kreirate** **novu sesiju prijavljivanja** pomoću tih akreditiva :

```
runas /user:domain\username cmd.exe
```

**access token** takođe sadrži **referencu** na sesije prijavljivanja unutar **LSASS-a**. To je korisno ako proces treba da pristupi nekim mrežnim objektima.\
Možete pokrenuti proces koji **koristi različite akreditive za pristup mrežnim servisima** pomoću:

```
runas /user:domain\username /netonly cmd.exe
```

Ovo je korisno ako imate upotrebljive credentials za pristup objektima na mreži, ali ti credentials nisu važeći na trenutnom hostu, jer će se koristiti samo na mreži (na trenutnom hostu koristiće se privilegije vašeg trenutnog korisnika).

#### Detalji za `runas /netonly`

`runas /netonly` (i C2 pomoćni alati kao što je `make_token`) kreira token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Ovo je veoma korisno razumeti tokom lateral movement-a, jer:<sup>[[3]](#references)</sup>

- **Lokalno**, novi proces zadržava **isti lokalni identitet**, grupe, nivo integriteta i uglavnom iste odluke o pristupu kao trenutni token.
- **Udaljeno**, za izlaznu autentifikaciju mogu se koristiti **dostavljeni credentials** za SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Zato `whoami` i dalje može da prikazuje **originalnog lokalnog korisnika**, dok se pristup mreži ostvaruje kao **alternativni nalog**.

Ovo je odlična opcija kada su credentials važeći u domenu ili na drugom hostu, ali korisnik **ne može ili ne treba lokalno da se prijavi** na trenutnu mašinu.

### Vrste tokena

Dostupne su dve vrste tokena:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primarni token**: Predstavlja bezbednosni kontekst procesa. Podređeni proces obično nasleđuje primarni token roditeljskog procesa, dok API-jevi za kreiranje procesa sa eksplicitnim tokenom nameću sopstvene zahteve za pristup tokenu i privilegije pozivaoca.
- **Token za impersonaciju**: Omogućava serverskoj niti da privremeno koristi bezbednosni kontekst klijenta za provere pristupa. Ima četiri nivoa:
  - **Anonymous**: Daje serveru pristup sličan pristupu neidentifikovanog korisnika.
  - **Identification**: Omogućava serveru da proveri identitet klijenta, ali ne i da ga koristi za pristup objektima.
  - **Impersonation**: Omogućava serveru da radi pod identitetom klijenta.
  - **Delegation**: Omogućava serveru da impersonira klijenta na udaljenim sistemima kada mehanizam autentifikacije i konfiguracija naloga podržavaju delegiranje.

#### Proverite pre upotrebe preuzeti token

Nemojte birati token samo na osnovu korisničkog imena. Isti nalog može imati više tokena sa različitim logon sesijama, service SID-ovima, privilegijama, nivoima integriteta, ograničenjima i network credentials.<sup>[[9]](#references)</sup> Pomoću `GetTokenInformation` proverite bar **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** i **`TokenStatistics.AuthenticationId`**.<sup>[[7]](#references)</sup>

Ograničeni token može da sadrži SID-ove sa oznakom deny-only, uklonjene privilegije i ograničavajuće SID-ove. Kada postoje ograničavajući SID-ovi, Windows obavlja jednu proveru pristupa sa omogućenim SID-ovima, a drugu sa ograničavajućim SID-ovima; **obe provere moraju odobriti pristup**. Zato privlačan korisnički SID ili omogućena grupa u izlazu sami po sebi ne dokazuju da token može da pristupi ciljnom objektu.<sup>[[8]](#references)</sup>

Pratite ovaj tok odlučivanja za dokumentovane zahteve za tokene i kreiranje procesa:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Za **primarni token** potreban je handle sa `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` pre nego što se može proslediti funkciji `CreateProcessWithTokenW` ili `CreateProcessAsUserW`.
2. Konvertujte **token za impersonaciju** pomoću `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Tokeni nivoa Identification mogu da otkriju podatke o identitetu, ali ne mogu da obavljaju provere pristupa kao taj klijent.
3. `CreateProcessWithTokenW` zahteva `SeImpersonatePrivilege` i pokreće podređeni proces u sesiji pozivaoca. `CreateProcessAsUserW` umesto toga koristi sesiju tokena, ali obično zahteva `SeIncreaseQuotaPrivilege`, a može zahtevati i `SeAssignPrimaryTokenPrivilege`. Ako su credentials dostupni, a ove privilegije nedostaju, dokumentovana alternativa je `CreateProcessWithLogonW`.

#### Tražite handles tokena, ne samo vlasnike procesa

Otvaranjem primarnog tokena svakog procesa mogu se propustiti **tokeni za impersonaciju zadržani kao obični handles** unutar servisa i broker procesa. Postupak za ponovnu upotrebu tabele handles obuhvata nabrajanje sistemskih handles, filtriranje objekata tokena, otvaranje svakog vlasnika pomoću `PROCESS_DUP_HANDLE`, dupliranje kandidatskog handle-a u trenutni proces, a zatim proveru gore navedenih polja. Potvrdite da duplirani handle sadrži `TOKEN_QUERY` i `TOKEN_DUPLICATE`; to što vidite handle tokena ne znači da se on može duplirati u upotrebljiv primarni token. Zaštićeni procesi i DACL-ovi procesa i dalje mogu da blokiraju handle ka vlasničkom procesu.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` automatizuje nabrajanje primarnih tokena procesa i zadržanih handles tokena. `list_token` zadržava po jednog poželjnog kandidata za svako korisničko ime, dok `list_all_token` prikazuje svakog kandidata. PID ograničava nabrajanje na jedan vlasnički proces.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Za ručni pregled i proveru pristupa, **TokenUniverse** može da otvara tokene procesa/niti, pretražuje postojeće ručke tokena, pregleda ograničenja i sesije prijavljivanja, duplicira tokene i testira nekoliko metoda kreiranja procesa.<sup>[[13]](#references)</sup> Za primitivu ručke između procesa na kojoj se ovo zasniva, pogledajte:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

### Pronalaženje aktivnih tokena za impersonaciju niti

Nit servisa može privremeno da impersonira klijenta čak i kada **primarni token procesa** pripada nalogu servisa, pa skeniranje vlasnika procesa može da ne otkrije kontekst klijenta.<sup>[[4]](#references)</sup> TokenUniverse može da prikaže dostupne tokene procesa/niti; u System Informer-u pregledajte karticu **Threads** procesa i kolonu **Impersonation** da biste pronašli potencijalne niti.<sup>[[13]](#references)[[14]](#references)</sup>

Za ciljanu proveru preko API-ja, napravite snimak `TH32CS_SNAPTHREAD`, filtrirajte `THREADENTRY32.th32OwnerProcessID` prema PID-u servisa, a zatim za svaku dostupnu nit pozovite `OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid)` i `OpenThreadToken(thread, TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &token)`.<sup>[[15]](#references)[[16]](#references)</sup> `TRUE` znači da provera pristupa pri otvaranju tokena koristi **kontekst procesa** pozivaoca, što je važno ako sam skener impersonira na nivou identifikacije.<sup>[[17]](#references)</sup> Pre nego što pokušate tok dupliranja/kreiranja procesa opisan iznad, proverite korisnika, tip, nivo impersonacije i ID sesije prijavljivanja tokena.<sup>[[7]](#references)</sup> Nit može da prestane sa impersonacijom između enumeracije i otvaranja; token može da ne postoji, a anonimni tokeni, zaštićene niti, DACL-ovi niti i DACL-ovi tokena mogu da spreče prikupljanje.<sup>[[16]](#references)[[17]](#references)</sup> Za razliku od skeniranja zadržanih ručki tokena servisa, ovim se proverava **trenutno dodeljeni token niti**.

Za putanju napada u kojoj se token niti dobija tako što se privilegovani klijent navede da se poveže na vašu cev, umesto da se skeniraju postojeće niti, pogledajte [impersonaciju klijenta named pipe-a](named-pipe-client-impersonation.md).

#### Impersonacija tokena

Ako imate dovoljno privilegija, pomoću _**incognito**_ modula metasploit-a možete lako da **izlistate** i **impersonirate** druge **tokene**. Ovo može biti korisno za **izvršavanje radnji kao da ste drugi korisnik**. Ovom tehnikom možete i da **eskalirate privilegije**.

Neke praktične napomene koje je lako zaboraviti tokom rada:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** zahteva **`SeImpersonatePrivilege`** od pozivaoca, a novi proces će se pokrenuti u **sesiji pozivaoca**.
- **`CreateProcessAsUserW`** je moguća rezervna opcija kada `CreateProcessWithTokenW` ne uspe sa greškom `1314`, ali samo ako pozivalac ispunjava njene zahteve za privilegije. To je i ispravan izbor kada podređeni proces mora da se pokrene u **sesiji na koju token upućuje**.<sup>[[9]](#references)[[10]](#references)</sup>
- **`LogonUser(LOGON32_LOGON_NETWORK)`** vraća **token za impersonaciju**. Pre kreiranja procesa, konvertujte ga pomoću **`DuplicateTokenEx(..., TokenPrimary, ...)`**. Čak ni nakon konverzije, dobijeni proces ne može da koristi tu prijavu preko mreže za pristup udaljenim deljenim resursima ili štampačima koji zahtevaju autentifikaciju: ovaj tip prijave ne kešira akreditive. Ako imate akreditive i potreban vam je dalji mrežni pristup, koristite interaktivnu prijavu ili prijavu sa akreditivima u čistom tekstu; nemojte ovo mešati sa `LOGON32_LOGON_NEW_CREDENTIALS` (`runas /netonly`), koji zadržava lokalni identitet, a koristi dostavljene akreditive za odlazne veze.<sup>[[18]](#references)</sup>
- Nisu svi tokeni za impersonaciju podjednako korisni: **`SecurityIdentification`** omogućava pregled korisnika, ali **ne i postupanje u njegovo ime**. Ako vam coercion primitiva ili klijent pipe/RPC-a obezbedi samo token nivoa identifikacije, proverite **`TokenImpersonationLevel`** i pređite na primitivu koja daje **`SecurityImpersonation`** ili viši nivo.

#### Krađa tokena bez pristupa LSASS-u

Ako već imate kontekst **servisa** ili **SYSTEM-a**, a **privilegovani korisnik je prijavljen**, krađa ili dupliranje tokena tog korisnika često je tiše od dumpovanja **LSASS-a**. U mnogim stvarnim upadima ovo je dovoljno da se:<sup>[[2]](#references)</sup>

- izvršavaju lokalne radnje kao taj korisnik
- pristupa udaljenim resursima kao taj korisnik
- obavljaju AD operacije bez prethodnog izdvajanja akreditiva za ponovnu upotrebu

Primeri **otimanja tokena sesije/korisnika** iz privilegovanog konteksta nalaze se u [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Imajte na umu da su API-ji kao što je **`WTSQueryUserToken`** namenjeni **visokopouzdanim servisima** i da obično zahtevaju **`LocalSystem` + `SeTcbPrivilege`**, pa su prvenstveno korisni kada već kontrolišete kontekst na nivou servisa. Za načine dobijanja **SYSTEM** privilegija koji zavise od konkretnih privilegija, pogledajte stranice u nastavku.

### Privilegije tokena

Saznajte koje **privilegije tokena mogu da se zloupotrebe za eskalaciju privilegija:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Pogledajte [**sve moguće privilegije tokena i neka objašnjenja na ovoj eksternoj stranici**](https://github.com/gtworek/Priv2Admin).



## References

- [1] [Razumevanje i zloupotreba tokena za pristup — II deo](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Zloupotreba Windows tokena za kompromitovanje Active Directory-ja bez pristupa LSASS-u](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Razjašnjenje Cobalt Strike komande „make_token“](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Tokeni za pristup - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Kako funkcioniše kontrola korisničkog naloga - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Nivoi impersonacije - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Enumeracija TOKEN_INFORMATION_CLASS - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Ograničeni tokeni - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Funkcija CreateProcessWithTokenW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Funkcija CreateProcessAsUserW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Funkcija DuplicateHandle - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
- [14] [Zahtev za dodavanje funkcije pregleda tokena niti u System Informer-u](https://github.com/winsiderss/systeminformer/issues/1275)
- [15] [Prolazak kroz listu niti - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list)
- [16] [NtOpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenthreadtoken)
- [17] [OpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [18] [LogonUserA - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera)
{{#include ../../banners/hacktricks-training.md}}
