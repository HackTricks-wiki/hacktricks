# Zloupotreba Tokena

{{#include ../../banners/hacktricks-training.md}}

## Tokeni

Ako **ne znate šta su Windows Access Tokens**, pročitajte ovu stranicu pre nego što nastavite:

{{#ref}}
access-tokens.md
{{#endref}}

**Možda biste mogli da eskalirate privilegije zloupotrebom tokena koje već imate**

### SeImpersonatePrivilege

Ovo je privilegija koju ima svaki proces koji omogućava impersonaciju (ali ne i kreiranje) bilo kog tokena, pod uslovom da se može dobiti rukohvat za njega. Privilegovan token može se dobiti iz Windows servisa (DCOM) izazivanjem da izvrši NTLM autentifikaciju protiv exploita, čime se omogućava izvršenje procesa sa SYSTEM privilegijama. Ova ranjivost može se iskoristiti korišćenjem raznih alata, kao što su [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (koji zahteva da winrm bude onemogućen), [SweetPotato](https://github.com/CCob/SweetPotato) i [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Veoma je slična **SeImpersonatePrivilege**, koristiće **istu metodu** za dobijanje privilegovanog tokena.\
Zatim, ova privilegija omogućava **dodeljivanje primarnog tokena** novom/obustavljenom procesu. Sa privilegovanim impersonacionim tokenom možete derivirati primarni token (DuplicateTokenEx).\
Sa tokenom, možete kreirati **novi proces** koristeći 'CreateProcessAsUser' ili kreirati proces u obustavljenom stanju i **postaviti token** (generalno, ne možete modifikovati primarni token pokrenutog procesa).

### SeTcbPrivilege

Ako ste omogućili ovaj token, možete koristiti **KERB_S4U_LOGON** da dobijete **impersonacioni token** za bilo kog drugog korisnika bez poznavanja kredencijala, **dodati proizvoljnu grupu** (administratore) u token, postaviti **nivo integriteta** tokena na "**medium**", i dodeliti ovaj token **trenutnoj niti** (SetThreadToken).

### SeBackupPrivilege

Sistem se uzrokuje da **dodeli sve pristupne** kontrole za čitanje bilo kog fajla (ograničeno na operacije čitanja) ovom privilegijom. Koristi se za **čitanje hešova lozinki lokalnih Administrator** naloga iz registra, nakon čega se alati kao što su "**psexec**" ili "**wmiexec**" mogu koristiti sa hešom (Pass-the-Hash tehnika). Međutim, ova tehnika ne uspeva pod dva uslova: kada je lokalni Administrator nalog onemogućen, ili kada je politika na snazi koja uklanja administrativna prava lokalnim administratorima koji se povezuju na daljinu.\
Možete **zloupotrebiti ovu privilegiju** sa:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- prateći **IppSec** na [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ili kako je objašnjeno u sekciji **eskalacija privilegija sa Backup Operatorima** u:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Ova privilegija omogućava **pristup za pisanje** bilo kojem sistemskom fajlu, bez obzira na Access Control List (ACL) fajla. Otvara brojne mogućnosti za eskalaciju, uključujući mogućnost **modifikacije servisa**, izvođenje DLL Hijacking-a i postavljanje **debuggera** putem Image File Execution Options među raznim drugim tehnikama.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege je moćna dozvola, posebno korisna kada korisnik ima sposobnost da impersonira tokene, ali i u odsustvu SeImpersonatePrivilege. Ova sposobnost zavisi od mogućnosti da se impersonira token koji predstavlja istog korisnika i čiji nivo integriteta ne prelazi nivo trenutnog procesa.

**Ključne tačke:**

- **Impersonacija bez SeImpersonatePrivilege:** Moguće je iskoristiti SeCreateTokenPrivilege za EoP impersonacijom tokena pod specifičnim uslovima.
- **Uslovi za impersonaciju tokena:** Uspešna impersonacija zahteva da ciljni token pripada istom korisniku i da ima nivo integriteta koji je manji ili jednak nivou integriteta procesa koji pokušava impersonaciju.
- **Kreiranje i modifikacija impersonacionih tokena:** Korisnici mogu kreirati impersonacioni token i poboljšati ga dodavanjem SID-a privilegovane grupe (Security Identifier).

### SeLoadDriverPrivilege

Ova privilegija omogućava **učitavanje i uklanjanje drajvera** uz kreiranje unosa u registru sa specifičnim vrednostima za `ImagePath` i `Type`. Pošto je direktan pristup za pisanje na `HKLM` (HKEY_LOCAL_MACHINE) ograničen, umesto toga mora se koristiti `HKCU` (HKEY_CURRENT_USER). Međutim, da bi `HKCU` bio prepoznat od strane jezgra za konfiguraciju drajvera, mora se pratiti specifičan put.

Ovaj put je `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gde je `<RID>` Relativni Identifikator trenutnog korisnika. Unutar `HKCU`, ovaj ceo put mora biti kreiran, i dve vrednosti treba postaviti:

- `ImagePath`, što je putanja do binarnog fajla koji treba izvršiti
- `Type`, sa vrednošću `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Koraci koje treba pratiti:**

1. Pristupite `HKCU` umesto `HKLM` zbog ograničenog pristupa za pisanje.
2. Kreirajte put `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` unutar `HKCU`, gde `<RID>` predstavlja Relativni Identifikator trenutnog korisnika.
3. Postavite `ImagePath` na putanju izvršenja binarnog fajla.
4. Dodelite `Type` kao `SERVICE_KERNEL_DRIVER` (`0x00000001`).
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Više načina za zloupotrebu ovog privilegija u [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Ovo je slično **SeRestorePrivilege**. Njegova primarna funkcija omogućava procesu da **preuzme vlasništvo nad objektom**, zaobilazeći zahtev za eksplicitnim diskrecionim pristupom kroz obezbeđivanje WRITE_OWNER prava pristupa. Proces uključuje prvo obezbeđivanje vlasništva nad nameravanom registracionom ključem u svrhu pisanja, a zatim menjanje DACL-a kako bi se omogućile operacije pisanja.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Ova privilegija omogućava **debugovanje drugih procesa**, uključujući čitanje i pisanje u memoriju. Različite strategije za injekciju memorije, sposobne da izbegnu većinu antivirusnih i rešenja za prevenciju upada, mogu se koristiti sa ovom privilegijom.

#### Dump memorije

Možete koristiti [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) iz [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) da **zabeležite memoriju procesa**. Konkretno, ovo se može primeniti na **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** proces, koji je odgovoran za čuvanje korisničkih kredencijala nakon što se korisnik uspešno prijavi na sistem.

Zatim možete učitati ovaj dump u mimikatz da dobijete lozinke:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Ako želite da dobijete `NT SYSTEM` shell, možete koristiti:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Proverite privilegije
```
whoami /priv
```
**Tokeni koji se pojavljuju kao Onemogućeni** mogu se omogućiti, zapravo možete zloupotrebiti _Omogućene_ i _Onemogućene_ tokene.

### Omogućite sve tokene

Ako imate tokene koji su onemogućeni, možete koristiti skriptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) da omogućite sve tokene:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ili **skripta** ugrađena u ovu [**objavu**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Potpuni cheat sheet za privilegije tokena na [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), sažetak u nastavku će navesti samo direktne načine za iskorišćavanje privilegije za dobijanje admin sesije ili čitanje osetljivih fajlova.

| Privilegija                | Uticaj      | Alat                    | Putanja izvršenja                                                                                                                                                                                                                                                                                                                                     | Napomene                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | alat treće strane       | _"Omogućava korisniku da imituje tokene i privesc do nt sistema koristeći alate kao što su potato.exe, rottenpotato.exe i juicypotato.exe"_                                                                                                                                                                                                      | Hvala [Aurélien Chalot](https://twitter.com/Defte_) na ažuriranju. Pokušaću da to preformulišem u nešto više nalik receptu uskoro.                                                                                                                                                                                         |
| **`SeBackup`**             | **Pretnja** | _**Ugrađene komande**_ | Čitajte osetljive fajlove sa `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Može biti zanimljivije ako možete da pročitate %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (i robocopy) nisu od pomoći kada su u pitanju otvoreni fajlovi.<br><br>- Robocopy zahteva i SeBackup i SeRestore da bi radio sa /b parametrom.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | alat treće strane       | Kreirajte proizvoljni token uključujući lokalna admin prava sa `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplirajte `lsass.exe` token.                                                                                                                                                                                                                                                                                                                   | Skripta se može naći na [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | alat treće strane       | <p>1. Učitajte greškom kernel drajver kao što je <code>szkg64.sys</code><br>2. Iskoristite ranjivost drajvera<br><br>Alternativno, privilegija se može koristiti za uklanjanje drajvera vezanih za bezbednost sa <code>ftlMC</code> ugrađenom komandom. tj.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Ranjivost <code>szkg64</code> je navedena kao <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">kod za eksploataciju</a> je kreirao <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Pokrenite PowerShell/ISE sa prisutnom SeRestore privilegijom.<br>2. Omogućite privilegiju sa <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Preimenujte utilman.exe u utilman.old<br>4. Preimenujte cmd.exe u utilman.exe<br>5. Zaključajte konzolu i pritisnite Win+U</p> | <p>Napad može biti otkriven od strane nekog AV softvera.</p><p>Alternativna metoda se oslanja na zamenu servisnih binarnih fajlova smeštenih u "Program Files" koristeći istu privilegiju</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Ugrađene komande**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Preimenujte cmd.exe u utilman.exe<br>4. Zaključajte konzolu i pritisnite Win+U</p>                                                                                                                                       | <p>Napad može biti otkriven od strane nekog AV softvera.</p><p>Alternativna metoda se oslanja na zamenu servisnih binarnih fajlova smeštenih u "Program Files" koristeći istu privilegiju.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | alat treće strane       | <p>Manipulišite tokenima da uključite lokalna admin prava. Može zahtevati SeImpersonate.</p><p>Treba potvrditi.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Referenca

- Pogledajte ovu tabelu koja definiše Windows tokene: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Pogledajte [**ovaj rad**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) o privesc-u sa tokenima.

{{#include ../../banners/hacktricks-training.md}}
