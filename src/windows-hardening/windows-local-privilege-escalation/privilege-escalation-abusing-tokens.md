# Zloupotreba tokena

{{#include ../../banners/hacktricks-training.md}}

## Tokeni

Ako **ne znate šta su Windows Access Tokens** pročitajte ovu stranicu pre nego što nastavite:


{{#ref}}
access-tokens.md
{{#endref}}

**Možda možete eskalirati privilegije zloupotrebom tokena koje već posedujete**

### SeImpersonatePrivilege

Ovo je privilegija koju poseduje proces i koja omogućava impersonaciju (ali ne i kreiranje) bilo kog tokena, pod uslovom da se dobije handle na njega. Privilegovan token može se pribaviti iz Windows servisa (DCOM) tako što se natera da izvrši NTLM autentikaciju prema exploit-u, čime se omogućava izvršavanje procesa sa SYSTEM privilegijama. Ova ranjivost se može iskoristiti korišćenjem različitih alata, kao što su [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (zahteva da winrm bude onemogućen), [SweetPotato](https://github.com/CCob/SweetPotato) i [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Veoma je slična **SeImpersonatePrivilege**, koristiće **isti metod** da dobije privilegovan token.\
Zatim, ova privilegija omogućava **dodelu primary tokena** novom/suspendovanom procesu. Sa privilegovanim impersonation tokenom možete izvesti derivaciju primary tokena (DuplicateTokenEx).\
Sa tokenom možete kreirati **novi proces** pomoću 'CreateProcessAsUser' ili kreirati proces u suspendovanom stanju i **postaviti token** (općenito, ne možete menjati primary token već pokrenutog procesa).

### SeTcbPrivilege

Ako imate omogućenu ovu privilegiju možete koristiti **KERB_S4U_LOGON** da dobijete **impersonation token** za bilo kog drugog korisnika bez poznavanja kredencijala, **dodati proizvoljnu grupu** (admins) u token, postaviti **integrity level** tokena na "**medium**", i dodeliti taj token **trenutnoj niti** (SetThreadToken).

### SeBackupPrivilege

Ova privilegija uzrokuje da sistem **dodeli sva prava za čitanje** za bilo koji fajl (ograničeno na operacije čitanja). Koristi se za **čitavanje password hash-eva lokalnih Administrator** naloga iz registra, nakon čega se alati poput "**psexec**" ili "**wmiexec**" mogu koristiti sa hash-om (Pass-the-Hash tehnika). Međutim, ova tehnika ne uspeva u dva slučaja: kada je Local Administrator nalog onemogućen, ili kada postoji politika koja uklanja administrativna prava od Local Administrators koji se povezuju na daljinu.\
Ovu privilegiju možete **zloupotrebiti** sa:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- prateći **IppSec** u [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ili kao što je objašnjeno u sekciji **escalating privileges with Backup Operators** od:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Ova privilegija daje dozvolu za **write access** bilo kojem sistemskom fajlu, bez obzira na Access Control List (ACL) fajla. Otvara mnoge mogućnosti za eskalaciju, uključujući mogućnost **izmenе servisa**, izvođenje DLL Hijacking-a i postavljanje **debuggera** preko Image File Execution Options, među raznim drugim tehnikama.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege je moćna dozvola, naročito korisna kada korisnik ima mogućnost impersonacije tokena, ali i u odsustvu SeImpersonatePrivilege. Ova mogućnost zavisi od sposobnosti da se impersonira token koji predstavlja istog korisnika i čiji integrity level nije viši od integrity level-a trenutnog procesa.

**Ključne tačke:**

- **Impersonacija bez SeImpersonatePrivilege:** Moguće je iskoristiti SeCreateTokenPrivilege za EoP impersonirajući tokene pod određenim uslovima.
- **Uslovi za impersonaciju tokena:** Uspešna impersonacija zahteva da cilj token pripada istom korisniku i da ima integrity level manji ili jednak integrity level-u procesa koji pokušava impersonaciju.
- **Kreiranje i modifikacija impersonation tokena:** Korisnici mogu kreirati impersonation token i poboljšati ga dodavanjem SID-a privilegovane grupe (Security Identifier).

### SeLoadDriverPrivilege

Ova privilegija omogućava **učitavanje i izbacivanje device driver-a** kreiranjem unosa u registru sa specifičnim vrednostima za `ImagePath` i `Type`. Pošto je direktan write pristup `HKLM` (HKEY_LOCAL_MACHINE) ograničen, mora se koristiti `HKCU` (HKEY_CURRENT_USER). Međutim, da bi kernel prepoznao `HKCU` za konfiguraciju drajvera, mora se slediti specifičan put.

Taj put je `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gde je `<RID>` Relative Identifier trenutnog korisnika. Unutar `HKCU` mora se kreirati ceo ovaj put i postaviti dve vrednosti:

- `ImagePath`, koji je putanja do binarnog fajla koji će se izvršiti
- `Type`, sa vrednošću `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Koraci koje treba slediti:**

1. Pristupite `HKCU` umesto `HKLM` zbog ograničenog write pristupa.
2. Kreirajte put `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` unutar `HKCU`, gde `<RID>` predstavlja Relative Identifier trenutnog korisnika.
3. Postavite `ImagePath` na putanju izvršnog binarnog fajla.
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
Više načina za zloupotrebu ove privilegije u [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Ovo je slično **SeRestorePrivilege**. Njegova primarna funkcija omogućava procesu da **preuzme vlasništvo nad objektom**, zaobilaženjem zahteva za eksplicitnim diskrecionim pristupom putem dodeljivanja WRITE_OWNER prava pristupa. Postupak podrazumeva prvo obezbeđivanje vlasništva nad ciljnim registarskim ključem radi upisa, a zatim izmenu DACL-a kako bi se omogućile operacije upisa.
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

Ova privilegija omogućava **debug other processes**, uključujući čitanje i pisanje u memoriju. Razne strategije za **memory injection**, koje mogu zaobići većinu antivirus i host intrusion prevention rešenja, mogu se koristiti sa ovom privilegijom.

#### Dump memory

Možete koristiti [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) iz [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) da **capture the memory of a process**. Konkretno, ovo se može primeniti na proces **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, koji je odgovoran za čuvanje korisničkih kredencijala nakon što se korisnik uspešno prijavi na sistem.

Zatim možete učitati ovaj dump u mimikatz da biste dobili lozinke:
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
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Ovo pravo (Perform volume maintenance tasks) omogućava otvaranje raw volume device handles (npr. \\.\C:) za direktan disk I/O koji zaobilazi NTFS ACLs. Pomoću njega možete kopirati bajtove bilo koje datoteke na volumenu čitajući osnovne blokove, što omogućava proizvoljno čitanje datoteka osetljivog sadržaja (npr. privatni ključevi mašine u %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS). Posebno je uticajan na CA serverima gde exfiltrating CA private key omogućava falsifikovanje Golden Certificate za impersonaciju bilo kog principal-a.

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Provera privilegija
```
whoami /priv
```
**tokens koji se pojavljuju kao Disabled** mogu biti omogućeni; zapravo možete zloupotrebiti _Enabled_ i _Disabled_ tokens.

### Omogući sve tokens

Ako imate tokens koji su Disabled, možete koristiti skriptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) da omogućite sve tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ili **skripta** ugrađena u ovaj [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Kompletan cheatsheet privilegija tokena na [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), sažetak ispod će navesti samo direktne načine za iskorišćavanje privilegije da se dobije administratorska sesija ili čitanje osetljivih fajlova.

| Privilege                  | Uticaj      | Alat                    | Put izvršavanja                                                                                                                                                                                                                                                                                                                                     | Napomene                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Omogućava korisniku da imitira tokene i izvrši privesc na NT System koristeći alate kao što su potato.exe, rottenpotato.exe i juicypotato.exe"_                                                                                                                                                                                                      | Hvala [Aurélien Chalot](https://twitter.com/Defte_) za ažuriranje. Pokušaću uskoro da to preformulišem u nešto više receptnog stila.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Pročitajte osetljive fajlove pomoću `robocopy /b`                                                                                                                                                                                                                                                                                                  | <p>- Može biti interesantnije ako možete pročitati %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (i robocopy) nije od pomoći kada su u pitanju otvoreni fajlovi.<br><br>- Robocopy zahteva i SeBackup i SeRestore da bi radio sa /b parametrom.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Napravite proizvoljan token uključujući lokalna admin prava pomoću `NtCreateToken`.                                                                                                                                                                                                                                                                 |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplirajte token `lsass.exe`.                                                                                                                                                                                                                                                                                                                      | Skripta se može naći na [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Učitajte problematični kernel driver kao što je <code>szkg64.sys</code><br>2. Iskoristite ranjivost drajvera<br><br>Alternativno, privilegija se može koristiti za uklanjanje security-related drajvera pomoću builtin komande <code>ftlMC</code>, npr.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Ranljivost <code>szkg64</code> je navedena kao <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> je kreirao <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Pokrenite PowerShell/ISE sa prisutnom SeRestore privilegijom.<br>2. Omogućite privilegiju pomoću <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Preimenujte utilman.exe u utilman.old<br>4. Preimenujte cmd.exe u utilman.exe<br>5. Zaključajte konzolu i pritisnite Win+U</p> | <p>Napad može biti detektovan od strane nekog AV softvera.</p><p>Alternativna metoda se oslanja na zamenu binarnih fajlova servisa koji su smešteni u "Program Files" koristeći istu privilegiju</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Preimenujte cmd.exe u utilman.exe<br>4. Zaključajte konzolu i pritisnite Win+U</p>                                                                                                                                       | <p>Napad može biti detektovan od strane nekog AV softvera.</p><p>Alternativna metoda se oslanja na zamenu binarnih fajlova servisa koji su smešteni u "Program Files" koristeći istu privilegiju.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulišite tokenima da uključe lokalna admin prava. Možda zahteva SeImpersonate.</p><p>Treba potvrditi.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Referenca

- Pogledajte ovu tabelu koja definiše Windows tokene: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Pogledajte [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) o privesc koristeći tokene.
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
