# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

If you **nie wiesz, czym są Windows Access Tokens**, przeczytaj tę stronę przed kontynuowaniem:

{{#ref}}
access-tokens.md
{{#endref}}

**Możesz być w stanie podnieść uprawnienia, nadużywając tokenów, które już posiadasz**

### SeImpersonatePrivilege

To uprawnienie, które posiada każdy proces, pozwala na impersonację (ale nie tworzenie) dowolnego tokena, pod warunkiem, że można uzyskać do niego uchwyt. Uprawniony token można uzyskać z usługi Windows (DCOM) poprzez skłonienie jej do przeprowadzenia uwierzytelnienia NTLM przeciwko exploitowi, co następnie umożliwia wykonanie procesu z uprawnieniami SYSTEM. Ta luka może być wykorzystana za pomocą różnych narzędzi, takich jak [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (które wymaga wyłączenia winrm), [SweetPotato](https://github.com/CCob/SweetPotato) i [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Jest bardzo podobne do **SeImpersonatePrivilege**, użyje **tej samej metody** do uzyskania uprawnionego tokena.\
Następnie to uprawnienie pozwala **przypisać token główny** do nowego/zawieszonego procesu. Z uprawnionym tokenem impersonacyjnym możesz uzyskać token główny (DuplicateTokenEx).\
Z tokenem możesz stworzyć **nowy proces** za pomocą 'CreateProcessAsUser' lub stworzyć proces zawieszony i **ustawić token** (ogólnie rzecz biorąc, nie możesz modyfikować głównego tokena działającego procesu).

### SeTcbPrivilege

Jeśli masz włączony ten token, możesz użyć **KERB_S4U_LOGON**, aby uzyskać **token impersonacyjny** dla dowolnego innego użytkownika bez znajomości poświadczeń, **dodać dowolną grupę** (administratorów) do tokena, ustawić **poziom integralności** tokena na "**medium**" i przypisać ten token do **bieżącego wątku** (SetThreadToken).

### SeBackupPrivilege

System jest zmuszony do **przyznania pełnego dostępu do odczytu** do dowolnego pliku (ograniczonego do operacji odczytu) przez to uprawnienie. Jest wykorzystywane do **odczytywania hashy haseł lokalnych kont Administratora** z rejestru, po czym narzędzia takie jak "**psexec**" lub "**wmiexec**" mogą być używane z hashem (technika Pass-the-Hash). Jednak ta technika zawodzi w dwóch warunkach: gdy konto lokalnego administratora jest wyłączone lub gdy obowiązuje polityka, która odbiera prawa administracyjne lokalnym administratorom łączącym się zdalnie.\
Możesz **nadużyć tego uprawnienia** za pomocą:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- śledząc **IppSec** w [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Lub jak wyjaśniono w sekcji **podnoszenia uprawnień z Backup Operators** w:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Uprawnienie do **dostępu do zapisu** do dowolnego pliku systemowego, niezależnie od listy kontroli dostępu (ACL) pliku, jest zapewniane przez to uprawnienie. Otwiera to liczne możliwości eskalacji, w tym możliwość **modyfikacji usług**, przeprowadzania DLL Hijacking oraz ustawiania **debuggerów** za pomocą opcji wykonania pliku obrazu, wśród różnych innych technik.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege to potężne uprawnienie, szczególnie przydatne, gdy użytkownik ma możliwość impersonacji tokenów, ale także w przypadku braku SeImpersonatePrivilege. Ta zdolność opiera się na możliwości impersonacji tokena, który reprezentuje tego samego użytkownika i którego poziom integralności nie przekracza poziomu bieżącego procesu.

**Kluczowe punkty:**

- **Impersonacja bez SeImpersonatePrivilege:** Możliwe jest wykorzystanie SeCreateTokenPrivilege do EoP poprzez impersonację tokenów w określonych warunkach.
- **Warunki dla impersonacji tokenów:** Udana impersonacja wymaga, aby docelowy token należał do tego samego użytkownika i miał poziom integralności mniejszy lub równy poziomowi integralności procesu próbującego impersonacji.
- **Tworzenie i modyfikacja tokenów impersonacyjnych:** Użytkownicy mogą tworzyć token impersonacyjny i wzbogacać go, dodając SID grupy z uprawnieniami (Security Identifier).

### SeLoadDriverPrivilege

To uprawnienie pozwala na **ładowanie i odładowywanie sterowników urządzeń** poprzez utworzenie wpisu w rejestrze z określonymi wartościami dla `ImagePath` i `Type`. Ponieważ bezpośredni dostęp do zapisu do `HKLM` (HKEY_LOCAL_MACHINE) jest ograniczony, należy zamiast tego wykorzystać `HKCU` (HKEY_CURRENT_USER). Jednak aby `HKCU` było rozpoznawane przez jądro do konfiguracji sterowników, należy przestrzegać określonej ścieżki.

Ta ścieżka to `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gdzie `<RID>` to identyfikator względny bieżącego użytkownika. Wewnątrz `HKCU` należy utworzyć całą tę ścieżkę i ustawić dwie wartości:

- `ImagePath`, która jest ścieżką do wykonywanego pliku binarnego
- `Type`, z wartością `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Kroki do wykonania:**

1. Uzyskaj dostęp do `HKCU` zamiast `HKLM` z powodu ograniczonego dostępu do zapisu.
2. Utwórz ścieżkę `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` w `HKCU`, gdzie `<RID>` reprezentuje identyfikator względny bieżącego użytkownika.
3. Ustaw `ImagePath` na ścieżkę wykonywania pliku binarnego.
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
Więcej sposobów na nadużycie tego przywileju w [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Jest to podobne do **SeRestorePrivilege**. Jego główną funkcją jest umożliwienie procesowi **przyjęcia własności obiektu**, omijając wymóg wyraźnego dostępu dyskrecjonalnego poprzez przyznanie praw dostępu WRITE_OWNER. Proces polega najpierw na zabezpieczeniu własności zamierzonego klucza rejestru w celu pisania, a następnie na zmianie DACL, aby umożliwić operacje zapisu.
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

Ten przywilej pozwala na **debugowanie innych procesów**, w tym na odczyt i zapis w pamięci. Różne strategie wstrzykiwania pamięci, zdolne do omijania większości rozwiązań antywirusowych i zapobiegających włamaniom, mogą być stosowane z tym przywilejem.

#### Zrzut pamięci

Możesz użyć [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) z [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), aby **złapać pamięć procesu**. W szczególności może to dotyczyć procesu **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, który jest odpowiedzialny za przechowywanie poświadczeń użytkowników po pomyślnym zalogowaniu się użytkownika do systemu.

Następnie możesz załadować ten zrzut w mimikatz, aby uzyskać hasła:
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
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Sprawdź uprawnienia
```
whoami /priv
```
**Tokeny, które pojawiają się jako Wyłączone**, mogą być włączone, możesz faktycznie wykorzystać _Włączone_ i _Wyłączone_ tokeny.

### Włącz wszystkie tokeny

Jeśli masz tokeny wyłączone, możesz użyć skryptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), aby włączyć wszystkie tokeny:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Lub **skrypt** osadzony w tym [**poście**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Pełna ściągawka uprawnień tokenów znajduje się na [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), podsumowanie poniżej wymieni tylko bezpośrednie sposoby na wykorzystanie uprawnienia do uzyskania sesji administratora lub odczytu wrażliwych plików.

| Uprawnienie                | Wpływ      | Narzędzie               | Ścieżka wykonania                                                                                                                                                                                                                                                                                                                                     | Uwagi                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | narzędzie firm trzecich | _"Pozwoliłoby to użytkownikowi na naśladowanie tokenów i privesc do systemu nt przy użyciu narzędzi takich jak potato.exe, rottenpotato.exe i juicypotato.exe"_                                                                                                                                                                                                      | Dziękuję [Aurélien Chalot](https://twitter.com/Defte_) za aktualizację. Postaram się wkrótce przeformułować to na coś bardziej przypominającego przepis.                                                                                                                                                                                         |
| **`SeBackup`**             | **Zagrożenie**  | _**Wbudowane polecenia**_ | Odczytaj wrażliwe pliki za pomocą `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Może być bardziej interesujące, jeśli możesz odczytać %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (i robocopy) nie są pomocne w przypadku otwartych plików.<br><br>- Robocopy wymaga zarówno SeBackup, jak i SeRestore, aby działać z parametrem /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | narzędzie firm trzecich | Utwórz dowolny token, w tym prawa lokalnego administratora za pomocą `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplikuj token `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Skrypt do znalezienia na [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | narzędzie firm trzecich | <p>1. Załaduj wadliwy sterownik jądra, taki jak <code>szkg64.sys</code><br>2. Wykorzystaj lukę w sterowniku<br><br>Alternatywnie, uprawnienie może być użyte do odłączenia sterowników związanych z bezpieczeństwem za pomocą wbudowanego polecenia <code>ftlMC</code>. tzn.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Luka w <code>szkg64</code> jest wymieniona jako <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">kod exploita</a> został stworzony przez <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Uruchom PowerShell/ISE z obecnym uprawnieniem SeRestore.<br>2. Włącz uprawnienie za pomocą <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.<br>3. Zmień nazwę utilman.exe na utilman.old<br>4. Zmień nazwę cmd.exe na utilman.exe<br>5. Zablokuj konsolę i naciśnij Win+U</p> | <p>Atak może być wykryty przez niektóre oprogramowanie antywirusowe.</p><p>Alternatywna metoda polega na zastąpieniu binariów usług przechowywanych w "Program Files" przy użyciu tych samych uprawnień</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Wbudowane polecenia**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Zmień nazwę cmd.exe na utilman.exe<br>4. Zablokuj konsolę i naciśnij Win+U</p>                                                                                                                                       | <p>Atak może być wykryty przez niektóre oprogramowanie antywirusowe.</p><p>Alternatywna metoda polega na zastąpieniu binariów usług przechowywanych w "Program Files" przy użyciu tych samych uprawnień.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | narzędzie firm trzecich | <p>Manipuluj tokenami, aby mieć włączone prawa lokalnego administratora. Może wymagać SeImpersonate.</p><p>Do weryfikacji.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Odniesienie

- Zobacz tę tabelę definiującą tokeny Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Zobacz [**ten dokument**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) dotyczący privesc z tokenami.

{{#include ../../banners/hacktricks-training.md}}
