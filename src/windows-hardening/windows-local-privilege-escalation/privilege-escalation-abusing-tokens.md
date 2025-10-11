# Zloupotreba tokena

{{#include ../../banners/hacktricks-training.md}}

## Tokeni

Ako **ne znate šta su Windows Access Tokens** pročitajte ovu stranicu pre nastavka:


{{#ref}}
access-tokens.md
{{#endref}}

**Možda ćete moći eskalirati privilegije zloupotrebom tokena koje već imate**

### SeImpersonatePrivilege

Ovo je privilegija koju poseduje bilo koji proces i koja omogućava impersonaciju (ali ne i kreiranje) bilo kog tokena, pod uslovom da se može dobiti handle za njega. Privilegovani token može se pribaviti iz Windows servisa (DCOM) navođenjem servisa da izvrši NTLM autentikaciju prema exploit-u, što potom omogućava izvršenje procesa sa SYSTEM privilegijama. Ova ranjivost se može iskoristiti korišćenjem različitih alata, kao što su [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (koji zahteva da winrm bude onemogućen), [SweetPotato](https://github.com/CCob/SweetPotato), i [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Veoma je slična **SeImpersonatePrivilege** i koristiće **istu metodu** da dobije privilegovani token.\
Zatim, ova privilegija omogućava **dodeljivanje primarnog tokena** novom/suspendovanom procesu. Sa privilegovanim impersonation tokenom možete izvesti primarni token (DuplicateTokenEx).\
Sa tim tokenom možete kreirati **novi proces** pomoću 'CreateProcessAsUser' ili kreirati proces u suspendovanom stanju i **postaviti token** (uopšteno, ne možete menjati primarni token već pokrenutog procesa).

### SeTcbPrivilege

Ako je ova privilegija omogućena možete koristiti **KERB_S4U_LOGON** da dobijete **impersonation token** za bilo kog drugog korisnika bez poznavanja kredencijala, **dodate proizvoljnu grupu** (admins) tokenu, podesite **integrity level** tokena na "**medium**", i dodelite taj token **current thread**-u (SetThreadToken).

### SeBackupPrivilege

Ova privilegija uzrokuje da sistem dodeli **puni pristup za čitanje** bilo kojoj datoteci (ograničeno na operacije čitanja). Koristi se za **čitanje hash-eva lozinki lokalnih Administrator** naloga iz registra, nakon čega se mogu koristiti alati poput "**psexec**" ili "**wmiexec**" sa hash-om (Pass-the-Hash tehnika). Međutim, ova tehnika ne prolazi u dva slučaja: kada je Local Administrator nalog onemogućen, ili kada postoji politika koja uklanja administratorska prava Local Administrators prilikom udaljenog povezivanja.\
Možete **zloupotrebiti ovu privilegiju** sa:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- prateći **IppSec** u [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ili kao što je objašnjeno u odeljku **escalating privileges with Backup Operators** od:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Ova privilegija omogućava **pristup za pisanje** bilo kojoj sistemskoj datoteci, bez obzira na Access Control List (ACL) te datoteke. Otvara brojne mogućnosti za eskalaciju, uključujući mogućnost **modifikacije servisa**, izvođenje DLL Hijacking-a, i postavljanje **debugger-a** preko Image File Execution Options, između ostalih tehnika.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege je moćna dozvola, posebno korisna kada korisnik ima mogućnost impersonacije tokena, ali i u odsustvu SeImpersonatePrivilege. Ova mogućnost zasniva se na sposobnosti da se impersonira token koji predstavlja istog korisnika i čiji integrity level ne prelazi nivo procesa koji pokušava impersonaciju.

**Ključne tačke:**

- **Impersonation without SeImpersonatePrivilege:** Moguće je iskoristiti SeCreateTokenPrivilege za EoP impersonirajući tokene pod određenim uslovima.
- **Conditions for Token Impersonation:** Uspešna impersonacija zahteva da ciljni token pripada istom korisniku i da ima integrity level koji je manji ili jednak integrity level-u procesa koji pokušava impersonaciju.
- **Creation and Modification of Impersonation Tokens:** Korisnici mogu kreirati impersonation token i unaprediti ga dodavanjem SID-a privilegovane grupe (Security Identifier).

### SeLoadDriverPrivilege

Ova privilegija omogućava **učitavanje i uklanjanje device driver-a** kreiranjem registry unosa sa specifičnim vrednostima za `ImagePath` i `Type`. Pošto je direktan upis u `HKLM` (HKEY_LOCAL_MACHINE) ograničen, mora se koristiti `HKCU` (HKEY_CURRENT_USER). Međutim, da bi kernel prepoznao `HKCU` za konfiguraciju drajvera, mora se pratiti specifičan put.

Ovaj put je `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gde je `<RID>` Relative Identifier trenutnog korisnika. Unutar `HKCU` mora se kreirati čitav ovaj put i postaviti dve vrednosti:

- `ImagePath`, koji je putanja do binarnog fajla koji će biti izvršen
- `Type`, sa vrednošću `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Koraci koje treba slediti:**

1. Pristupite `HKCU` umesto `HKLM` zbog ograničenog pristupa za pisanje.
2. Kreirajte put `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` unutar `HKCU`, gde `<RID>` predstavlja Relative Identifier trenutnog korisnika.
3. Postavite `ImagePath` na putanju izvršenja binarnog fajla.
4. Dodelite `Type` vrednost `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Više načina za zloupotrebu ovog privilegija na [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Ovo je slično **SeRestorePrivilege**. Njegova primarna funkcija omogućava procesu da **preuzme vlasništvo nad objektom**, zaobilazeći potrebu za eksplicitnim diskrecionim pristupom kroz dodeljivanje WRITE_OWNER prava pristupa. Proces podrazumeva prvo osiguravanje vlasništva nad ciljnim registry key-jem radi pisanja, a zatim izmenu DACL-a kako bi se omogućile operacije pisanja.
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

Ova privilegija omogućava **debug drugih procesa**, uključujući čitanje i pisanje u memoriji. Razne strategije za injekciju u memoriju, koje mogu zaobići većinu antivirusnih i host intrusion prevention rešenja, mogu se koristiti uz ovu privilegiju.

#### Dump memory

Možete koristiti [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) iz [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) da **snimite memoriju procesa**. Konkretno, ovo se može primeniti na proces **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, koji je odgovoran za čuvanje korisničkih kredencijala nakon što se korisnik uspešno prijavi na sistem.

Nakon toga možete učitati ovaj dump u mimikatz da biste dobili lozinke:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Ako želite да добијете `NT SYSTEM` shell, можете користити:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Ovo pravo (Perform volume maintenance tasks) omogućava otvaranje raw volume device handles (npr. \\.\C:) za direktan disk I/O koji zaobilazi NTFS ACLs. Sa njim možete kopirati bajtove bilo kog fajla na volumenu čitajući osnovne blokove, što omogućava proizvoljno čitanje fajlova osetljivog sadržaja (npr. machine private keys u %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS putem VSS). Posebno je opasno na CA serverima gde eksfiltracija privatnog ključa CA omogućava falsifikovanje Golden Certificate i impersonaciju bilo kog principal-a.

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Provera privilegija
```
whoami /priv
```
Tokeni koji se pojavljuju kao **Disabled** mogu biti omogućeni; zapravo možete zloupotrebiti i _Enabled_ i _Disabled_ tokene.

### Omogućavanje svih tokena

Ako imate onemogućene tokene, možete koristiti skriptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) da omogućite sve tokene:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ili the **script** ugrađen u ovom [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), sažetak u nastavku će navesti samo direktne načine za iskorišćavanje privilegije radi dobijanja admin sesije ili čitanja osetljivih fajlova.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Hvala [Aurélien Chalot](https://twitter.com/Defte_) na ažuriranju. Pokušaću to uskoro da preformulišem tako da bude više u obliku recepta.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Read sensitve files with `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Može biti interesantnije ako možete pročitati %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (and robocopy) nije od pomoći kada su u pitanju otvoreni fajlovi.<br><br>- Robocopy zahteva i SeBackup i SeRestore da bi radio sa /b parametrom.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Create arbitrary token including local admin rights with `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicate the `lsass.exe` token.                                                                                                                                                                                                                                                                                                                   | Skript se može naći na [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Učitajte ranjiv kernel driver kao što je <code>szkg64.sys</code><br>2. Iskoristite ranjivost drajvera<br><br>Alternativno, privilegija se može koristiti za učitavanje/odučitavanje sigurnosno-povezanih drajvera pomoću builtin komande <code>ftlMC</code>, npr.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Ranjivost <code>szkg64</code> je navedena kao <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> je napravio <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Pokrenite PowerShell/ISE sa prisutnim SeRestore privilegijem.<br>2. Omogućite privilegiju pomoću <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.<br>3. Preimenujte utilman.exe u utilman.old<br>4. Preimenujte cmd.exe u utilman.exe<br>5. Zaključajte konzolu i pritisnite Win+U</p> | <p>Napad može biti otkriven od strane nekog AV softvera.</p><p>Alternativna metoda se oslanja na zamenu binarnih fajlova servisa koji se nalaze u "Program Files" koristeći isti privilegij</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Preimenujte cmd.exe u utilman.exe<br>4. Zaključajte konzolu i pritisnite Win+U</p>                                                                                                                                       | <p>Napad može biti otkriven od strane nekog AV softvera.</p><p>Alternativna metoda se oslanja na zamenu binarnih fajlova servisa koji se nalaze u "Program Files" koristeći isti privilegij.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulišite tokenima da uključe lokalna admin prava. Može zahtevati SeImpersonate.</p><p>Potrebno je verifikovati.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Reference

- Pogledajte ovu tabelu koja definiše Windows token-e: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Pogledajte [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) o privesc sa tokenima.
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
