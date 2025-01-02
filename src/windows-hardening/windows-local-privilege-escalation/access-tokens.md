# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Svaki **korisnik prijavljen** na sistem **ima pristupni token sa bezbednosnim informacijama** za tu sesiju prijavljivanja. Sistem kreira pristupni token kada se korisnik prijavi. **Svaki proces izvršen** u ime korisnika **ima kopiju pristupnog tokena**. Token identifikuje korisnika, korisnikove grupe i korisnikove privilegije. Token takođe sadrži logon SID (Identifikator bezbednosti) koji identifikuje trenutnu sesiju prijavljivanja.

Možete videti ove informacije izvršavanjem `whoami /all`
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
ili korišćenjem _Process Explorer_ iz Sysinternals (izaberite proces i pristupite "Security" tabu):

![](<../../images/image (772).png>)

### Lokalni administrator

Kada se lokalni administrator prijavi, **kreiraju se dva pristupna tokena**: jedan sa administratorskim pravima i drugi sa normalnim pravima. **Podrazumevano**, kada ovaj korisnik izvrši proces, koristi se onaj sa **redovnim** (ne-administratorskim) **pravima**. Kada ovaj korisnik pokuša da **izvrši** bilo šta **kao administrator** ("Run as Administrator" na primer), koristiće se **UAC** da zatraži dozvolu.\
Ako želite da [**saznate više o UAC, pročitajte ovu stranicu**](../authentication-credentials-uac-and-efs/#uac)**.**

### Impersonacija korisničkih kredencijala

Ako imate **važeće kredencijale bilo kog drugog korisnika**, možete **kreirati** **novu sesiju prijavljivanja** sa tim kredencijalima:
```
runas /user:domain\username cmd.exe
```
**Access token** takođe ima **referencu** na sesije prijavljivanja unutar **LSASS**, što je korisno ako proces treba da pristupi nekim objektima mreže.\
Možete pokrenuti proces koji **koristi različite akreditive za pristup mrežnim uslugama** koristeći:
```
runas /user:domain\username /netonly cmd.exe
```
Ovo je korisno ako imate korisne akreditive za pristup objektima u mreži, ali ti akreditivi nisu validni unutar trenutnog hosta jer će se koristiti samo u mreži (u trenutnom hostu koristiće se privilegije vašeg trenutnog korisnika).

### Tipovi tokena

Postoje dva tipa tokena dostupna:

- **Primarni token**: Služi kao reprezentacija bezbednosnih akreditiva procesa. Kreiranje i povezivanje primarnih tokena sa procesima su radnje koje zahtevaju povišene privilegije, naglašavajući princip odvajanja privilegija. Obično, usluga autentifikacije je odgovorna za kreiranje tokena, dok usluga prijavljivanja upravlja njegovim povezivanjem sa operativnim sistemom korisnika. Vredno je napomenuti da procesi nasleđuju primarni token svog roditeljskog procesa prilikom kreiranja.
- **Token impersonacije**: Omogućava serverskoj aplikaciji da privremeno usvoji identitet klijenta za pristup sigurnim objektima. Ovaj mehanizam je stratifikovan u četiri nivoa operacije:
- **Anonimno**: Daje serveru pristup sličan onom neidentifikovanog korisnika.
- **Identifikacija**: Omogućava serveru da verifikuje identitet klijenta bez korišćenja za pristup objektima.
- **Impersonacija**: Omogućava serveru da funkcioniše pod identitetom klijenta.
- **Delegacija**: Slično impersonaciji, ali uključuje sposobnost da se ovo usvajanje identiteta proširi na udaljene sisteme sa kojima server komunicira, osiguravajući očuvanje akreditiva.

#### Impersonate tokeni

Korišćenjem _**incognito**_ modula metasploit-a, ako imate dovoljno privilegija, možete lako **navesti** i **impersonirati** druge **tokene**. Ovo može biti korisno za izvršavanje **akcija kao da ste drugi korisnik**. Takođe možete **povišiti privilegije** ovom tehnikom.

### Privilegije tokena

Saznajte koje **privilegije tokena mogu biti zloupotrebljene za povišenje privilegija:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Pogledajte [**sve moguće privilegije tokena i neka objašnjenja na ovoj eksternoj stranici**](https://github.com/gtworek/Priv2Admin).

## Reference

Saznajte više o tokenima u ovim tutorijalima: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) i [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

{{#include ../../banners/hacktricks-training.md}}
