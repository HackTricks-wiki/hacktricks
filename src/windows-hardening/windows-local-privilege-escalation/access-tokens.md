# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Svaki **prijavljeni korisnik** na sistem **poseduje access token sa bezbednosnim informacijama** za tu logon sesiju. Sistem kreira access token kada se korisnik prijavi. **Svaki proces koji se izvršava** u ime korisnika **ima kopiju access token-a**. Token identifikuje korisnika, grupe korisnika i privilegije korisnika. Token takođe sadrži logon SID (Security Identifier) koji identifikuje trenutnu logon sesiju.

Ove informacije možete videti izvršavanjem `whoami /all`
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
or using _Process Explorer_ from Sysinternals (select process and access"Security" tab):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Lokalni administrator

Kada se lokalni administrator prijavi, **kreiraju se dva access tokena**: jedan sa admin pravima i drugi sa normalnim pravima. **Podrazumevano**, kada ovaj korisnik izvršava proces, koristi se onaj sa **regular** (non-administrator) **pravima**. Kada ovaj korisnik pokuša da **izvrši** bilo šta **kao administrator** (na primer "Run as Administrator"), **UAC** će biti korišćen da zatraži dozvolu.\
Ako želite da [**saznate više o UAC pročitajte ovu stranicu**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

U praksi, to znači da **non-elevated admin shell** obično radi sa filtered tokenom. Zato `whoami /groups` često prikazuje **`BUILTIN\Administrators` kao `Deny only`** dok proces nije elevated. Interno, Windows čuva **linked elevated token** (`TokenLinkedToken`) i prati stanje pomoću polja kao što je `TokenElevationType`.

### Impersonacija korisnika pomoću credentials

Ako imate **valid credentials bilo kog drugog korisnika**, možete **kreirati** **novu logon session** sa tim credentials :
```
runas /user:domain\username cmd.exe
```
**access token** takođe ima **reference** na logon sesije unutar **LSASS**, što je korisno ako proces treba da pristupi nekim objektima na mreži.\
Možete pokrenuti proces koji **koristi različite kredencijale za pristup mrežnim servisima** koristeći:
```
runas /user:domain\username /netonly cmd.exe
```
Ovo je korisno ako imate korisne kredencijale za pristup objektima u mreži, ali ti kredencijali nisu validni unutar trenutnog hosta jer će se koristiti samo u mreži (na trenutnom hostu biće korišćene privilegije vašeg trenutnog korisnika).

#### `runas /netonly` detalji

`runas /netonly` (i C2 helpers kao što je `make_token`) kreira **`LOGON32_LOGON_NEW_CREDENTIALS`** token. Ovo je veoma korisno za razumevanje tokom lateral movement jer:

- **Lokalno**, novi proces zadržava **isti lokalni identitet**, grupe, integrity level i većinu istih odluka o pristupu kao trenutni token.
- **Udaljeno**, outbound autentikacija može koristiti **prosleđene kredencijale** za SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Zato `whoami` može i dalje prikazivati **originalnog lokalnog korisnika** dok se mrežni pristup obavlja kao **alternativni nalog**.

Ovo je odlična opcija kada su kredencijali validni u domenu ili na drugom hostu, ali korisnik **ne može ili ne bi trebalo da se lokalno prijavi** na trenutnu mašinu.

### Tipovi tokena

Postoje dva tipa tokena:

- **Primary Token**: Predstavlja security credentials procesa. Kreiranje i povezivanje primary tokena sa procesima su radnje koje zahtevaju povišene privilegije, što naglašava princip separation of privilege. Tipično, authentication service je odgovoran za kreiranje tokena, dok logon service rukuje njegovim povezivanjem sa shell-om korisnika u operativnom sistemu. Vredi napomenuti da procesi nasleđuju primary token svog roditeljskog procesa pri kreiranju.
- **Impersonation Token**: Omogućava serverskoj aplikaciji da privremeno preuzme identitet klijenta radi pristupa secure objektima. Ovaj mehanizam je podeljen na četiri nivoa rada:
- **Anonymous**: Daje server access nalik onom neidentifikovanog korisnika.
- **Identification**: Omogućava serveru da proveri identitet klijenta bez korišćenja tog identiteta za access objektima.
- **Impersonation**: Omogućava serveru da radi pod identitetom klijenta.
- **Delegation**: Slično kao Impersonation, ali uključuje mogućnost da se ovo preuzimanje identiteta proširi na remote systems sa kojima server komunicira, uz očuvanje kredencijala.

#### Impersonate Tokens

Korišćenjem _**incognito**_ modula u metasploit-u, ako imate dovoljno privilegija, možete lako **izlistati** i **impersonate** druge **tokene**. Ovo može biti korisno za izvođenje **radnji kao da ste drugi korisnik**. Takođe možete **escalate privileges** ovom tehnikom.

Neke praktične napomene koje je lako zaboraviti tokom rada:

- **`CreateProcessWithTokenW`** zahteva **`SeImpersonatePrivilege`** kod pozivaoca i novi proces će raditi u **sesiji pozivaoca**.
- **`CreateProcessAsUserW`** je uobičajeni fallback kada **`CreateProcessWithTokenW`** zakaže sa `1314`, ili kada treba da pokrenete proces u **sesiji na koju token pokazuje**.
- Ako token dolazi iz **`LogonUser(LOGON32_LOGON_NETWORK)`**, on je obično **impersonation token**, pa morate koristiti **`DuplicateTokenEx(..., TokenPrimary, ...)`** pre nego što pokušate da pokrenete proces sa njim.
- Nije svaki impersonation token jednako koristan: **`SecurityIdentification`** omogućava da pregledate korisnika, ali **ne i da delujete kao on**. Ako coercion primitive ili pipe/RPC klijent daje samo token nivoa identification, proverite **`TokenImpersonationLevel`** i prebacite se na primitive koji daje **`SecurityImpersonation`** ili bolje.

#### Krađa tokena bez diranja LSASS

Ako već imate **service** ili **SYSTEM** kontekst i **privilegovani korisnik je prijavljen**, krađa ili dupliranje tokena tog korisnika često je tiše nego dumpovanje **LSASS**. U mnogim realnim upadima ovo je dovoljno da:

- pokrećete lokalne radnje kao taj korisnik
- pristupate remote resursima kao taj korisnik
- obavljate AD operacije bez prethodnog izvlačenja reusable credentials

Za primere **session/user token hijacking** iz privilegovanog konteksta, pogledajte [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Zapamtite da su API-jevi kao što je **`WTSQueryUserToken`** namenjeni za **visoko poverljive servise** i obično zahtevaju **`LocalSystem` + `SeTcbPrivilege`**, pa su prvenstveno korisni tek kada već kontrolišete service-level kontekst. Za privilegije-specifične načine da prvo dobijete **SYSTEM**, pogledajte stranice ispod.

### Token Privileges

Saznajte koji se **token privileges mogu zloupotrebiti za escalate privileges:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Pogledajte [**sve moguće token privileges i neke definicije na ovoj eksternoj stranici**](https://github.com/gtworek/Priv2Admin).

## References

- [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)
- [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
