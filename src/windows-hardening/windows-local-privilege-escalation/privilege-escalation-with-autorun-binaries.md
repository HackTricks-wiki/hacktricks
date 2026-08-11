# Eskalacja uprawnień za pomocą Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** może być używany do uruchamiania programów podczas **startup**. Sprawdź, które pliki binarne są zaprogramowane do uruchamiania podczas **startup**, za pomocą:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Zaplanowane zadania

**Zadania** można zaplanować tak, aby były uruchamiane z **określoną częstotliwością**. Użyj następujących poleceń, aby sprawdzić, które pliki binarne są zaplanowane do uruchomienia:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Foldery

Wszystkie pliki binarne znajdujące się w **folderach startowych zostaną uruchomione podczas startu systemu**. Typowe foldery startowe to te wymienione poniżej, ale folder startowy jest wskazany w rejestrze. [Przeczytaj tutaj, aby dowiedzieć się gdzie.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Podatności typu *path traversal* podczas rozpakowywania archiwów (takie jak ta wykorzystywana w WinRAR przed wersją 7.13 – CVE-2025-8088) mogą zostać wykorzystane do **umieszczenia payloadów bezpośrednio w tych folderach Startup podczas dekompresji**, co skutkuje wykonaniem kodu przy następnym logowaniu użytkownika. Szczegółowy opis tej techniki znajduje się tutaj:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Rejestr

> [!TIP]
> [Notatka od tutaj](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Wpis rejestru **Wow6432Node** wskazuje, że używasz 64-bitowej wersji Windows. System operacyjny używa tego klucza do wyświetlania oddzielnego widoku HKEY_LOCAL_MACHINE\SOFTWARE dla aplikacji 32-bitowych uruchamianych w 64-bitowych wersjach Windows.

### Runs

**Powszechnie znane** AutoRun w rejestrze:

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

Klucze rejestru znane jako **Run** i **RunOnce** służą do automatycznego uruchamiania programów za każdym razem, gdy użytkownik loguje się do systemu. Wiersz poleceń przypisany jako wartość danych klucza jest ograniczony do maksymalnie 260 znaków.<sup>[[2]](#references)</sup>

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

W systemie Windows Vista i nowszych wersjach klucze rejestru **Run** i **RunOnce** nie są generowane automatycznie. Wpisy w tych kluczach mogą bezpośrednio uruchamiać programy lub określać je jako zależności. Na przykład, aby załadować plik DLL podczas logowania, można użyć klucza rejestru **RunOnceEx** wraz z kluczem „Depend”. Pokazuje to dodanie wpisu rejestru w celu wykonania pliku „C:\temp\evil.dll” podczas uruchamiania systemu:<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Jeśli możesz zapisywać w dowolnym z wymienionych kluczy rejestru w **HKLM**, możesz eskalować uprawnienia, gdy zaloguje się inny użytkownik.

> [!TIP]
> **Exploit 2**: Jeśli możesz nadpisać dowolny z plików binarnych wskazanych w którymkolwiek z kluczy rejestru w **HKLM**, możesz zmodyfikować ten plik binarny, dodając backdoor, gdy zaloguje się inny użytkownik, i eskalować uprawnienia.
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
### Ścieżka uruchamiania

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Skróty umieszczone w folderze **Startup** automatycznie spowodują uruchomienie usług lub aplikacji podczas logowania użytkownika albo ponownego uruchomienia systemu. Lokalizacja folderu **Startup** jest określona w rejestrze zarówno dla zakresu **Local Machine**, jak i **Current User**. Oznacza to, że każdy skrót dodany do określonych lokalizacji **Startup** zapewni uruchomienie powiązanej usługi lub programu po zakończeniu procesu logowania lub ponownego uruchomienia, co stanowi prostą metodę planowania automatycznego uruchamiania programów.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Jeśli możesz nadpisać dowolny [User] Shell Folder w ramach **HKLM**, będziesz w stanie wskazać folder kontrolowany przez siebie i umieścić w nim backdoor, który będzie wykonywany za każdym razem, gdy użytkownik zaloguje się do systemu, prowadząc do eskalacji uprawnień.
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

Ta wartość rejestru przypisana do użytkownika może wskazywać skrypt lub command wykonywany podczas logowania tego użytkownika. Jest to głównie mechanizm **persistence**, ponieważ działa wyłącznie w kontekście użytkownika, którego dotyczy, ale nadal warto ją sprawdzać podczas post-exploitation i przeglądów autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Jeśli możesz zapisywać tę wartość dla bieżącego użytkownika, możesz ponownie wywołać jej wykonanie przy następnym interaktywnym logowaniu bez uprawnień administratora. Jeśli możesz zapisywać ją w hive innego użytkownika, możesz uzyskać code execution, gdy ten użytkownik się zaloguje.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Uwagi:

- Preferowane są pełne ścieżki do plików `.bat`, `.cmd`, `.ps1` lub innych plików uruchamiających, które są już dostępne do odczytu dla użytkownika docelowego.
- Działa to do momentu usunięcia wartości, również po wylogowaniu lub ponownym uruchomieniu systemu.
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

### Zmiana wiersza polecenia w trybie awaryjnym

W Rejestrze Windows, w `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, znajduje się wartość **`AlternateShell`**, która domyślnie jest ustawiona na `cmd.exe`. Oznacza to, że po wybraniu podczas uruchamiania opcji „Tryb awaryjny z wierszem polecenia” (przez naciśnięcie klawisza F8) używany jest `cmd.exe`. Możliwe jest jednak skonfigurowanie komputera tak, aby automatycznie uruchamiał się w tym trybie bez konieczności naciskania klawisza F8 i ręcznego wybierania tej opcji.

Kroki tworzenia opcji rozruchu umożliwiającej automatyczne uruchamianie w „Trybie awaryjnym z wierszem polecenia”:<sup>[[5]](#references)</sup>

1. Zmień atrybuty pliku `boot.ini`, aby usunąć flagi tylko do odczytu, systemową i ukrytą: `attrib c:\boot.ini -r -s -h`
2. Otwórz plik `boot.ini` do edycji.
3. Wstaw wiersz taki jak: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Zapisz zmiany w pliku `boot.ini`.
5. Przywróć oryginalne atrybuty pliku: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Zmiana klucza rejestru **AlternateShell** umożliwia skonfigurowanie niestandardowej powłoki poleceń, co może zostać wykorzystane do uzyskania nieautoryzowanego dostępu.
- **Exploit 2 (uprawnienia zapisu do PATH):** Posiadanie uprawnień zapisu do dowolnej części zmiennej systemowej **PATH**, zwłaszcza znajdującej się przed `C:\Windows\system32`, umożliwia uruchomienie niestandardowego `cmd.exe`, który może pełnić funkcję backdoora, jeśli system zostanie uruchomiony w trybie awaryjnym.
- **Exploit 3 (uprawnienia zapisu do PATH i boot.ini):** Uprawnienia zapisu do pliku `boot.ini` umożliwiają automatyczne uruchomienie trybu awaryjnego, ułatwiając uzyskanie nieautoryzowanego dostępu przy następnym ponownym uruchomieniu.

Aby sprawdzić bieżące ustawienie **AlternateShell**, użyj następujących poleceń:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Zainstalowany komponent

Active Setup to funkcja systemu Windows, która **uruchamia się przed pełnym załadowaniem środowiska pulpitu**. Nadaje priorytet wykonywaniu określonych poleceń, które muszą zostać zakończone przed kontynuowaniem logowania użytkownika. Proces ten zachodzi nawet przed uruchomieniem innych wpisów startowych, takich jak te w sekcjach rejestru Run lub RunOnce.

Active Setup jest zarządzany za pomocą następujących kluczy rejestru:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

W tych kluczach znajduje się wiele podkluczy, z których każdy odpowiada konkretnemu komponentowi. Szczególnie interesujące wartości kluczy obejmują:

- **IsInstalled:**
- `0` oznacza, że polecenie komponentu nie zostanie wykonane.
- `1` oznacza, że polecenie zostanie wykonane raz dla każdego użytkownika. Jest to domyślne zachowanie, jeśli brakuje wartości `IsInstalled`.
- **StubPath:** Definiuje polecenie, które ma zostać wykonane przez Active Setup. Może to być dowolny prawidłowy wiersz poleceń, na przykład uruchomienie `notepad`.

**Spostrzeżenia dotyczące bezpieczeństwa:**

- Modyfikowanie klucza lub zapisywanie do niego, gdy **`IsInstalled`** ma wartość `"1"` i określony **`StubPath`**, może prowadzić do nieautoryzowanego wykonania poleceń, potencjalnie umożliwiając privilege escalation.
- Zmiana pliku binarnego wskazywanego przez dowolną wartość **`StubPath`** również może umożliwić privilege escalation, jeśli dostępne są wystarczające uprawnienia.

Do sprawdzenia konfiguracji **`StubPath`** w komponentach Active Setup można użyć następujących poleceń:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Przegląd Browser Helper Objects (BHO)

Browser Helper Objects (BHO) to moduły DLL, które dodają dodatkowe funkcje do przeglądarki Internet Explorer firmy Microsoft. Są ładowane do Internet Explorer i Windows Explorer przy każdym uruchomieniu. Ich wykonywanie można jednak zablokować, ustawiając klucz **NoExplorer** na wartość 1, co uniemożliwia ich ładowanie wraz z instancjami Windows Explorer.<sup>[[1]](#references)</sup>

BHO są kompatybilne z Windows 10 za pośrednictwem Internet Explorer 11, ale nie są obsługiwane w Microsoft Edge, domyślnej przeglądarce w nowszych wersjach Windows.

Aby sprawdzić BHO zarejestrowane w systemie, możesz przeanalizować następujące klucze rejestru:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Każdy BHO jest reprezentowany w rejestrze przez swój **CLSID**, który służy jako unikatowy identyfikator. Szczegółowe informacje o każdym CLSID można znaleźć w `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

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
### Polecenie Open

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Image File Execution Options
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Należy pamiętać, że wszystkie lokalizacje, w których można znaleźć autoruns, są **już przeszukiwane przez**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Jednak aby uzyskać **bardziej kompleksową listę automatycznie uruchamianych** plików, można użyć narzędzia [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)firmy systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Więcej

**Więcej elementów Autoruns, takich jak rejestry, znajdziesz w** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Typowe mechanizmy persistence malware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Kategorie autostartu (Rozwiązywanie problemów za pomocą narzędzi Windows Sysinternals, wydanie 2.)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Jak dodać opcję rozruchu, która uruchamia alternatywną powłokę?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Podsumowanie Metasploit 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
