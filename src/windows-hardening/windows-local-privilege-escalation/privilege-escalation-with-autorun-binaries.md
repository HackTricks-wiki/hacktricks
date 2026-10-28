# Eskalacja uprawnień za pomocą Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** można używać do uruchamiania programów podczas **uruchamiania systemu**. Sprawdź, które pliki binarne są skonfigurowane do uruchamiania podczas startu systemu:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Zaplanowane zadania

**Zadania** można zaplanować tak, aby uruchamiały się z **określoną częstotliwością**. Użyj następujących poleceń, aby sprawdzić, które pliki binarne są zaplanowane do uruchomienia:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Requires an elevated caller to register a task as SYSTEM
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

Zadanie utworzone za pomocą `/sc ONLOGON /rl HIGHEST` żąda najwyższego poziomu uruchomienia **dostępnego dla zarejestrowanego podmiotu zabezpieczeń**; sam przełącznik nie zmienia tego podmiotu ani nie omija UAC. Proces o niskich uprawnieniach nie może zarejestrować zadania z najwyższym poziomem uruchomienia ani wybrać SYSTEM jako tożsamości zadania. Traktuj powyższy przykład jako działanie dostępne już podwyższonemu procesowi wywołującemu, a nie sposób na uzyskanie uprawnień SYSTEM ze standardowego konta użytkownika.<sup>[[8]](#references)</sup>

Włączone zadanie uruchamiane jako SYSTEM wymaga sprawdzenia, nawet jeśli jego definicja i plik akcji są chronione. [Task Scheduler wymaga uprawnienia do wykonywania zadania, aby uruchomić je na żądanie](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Jeśli użytkownik o niskich uprawnieniach ma to uprawnienie, sprawdź dokładną akcję, zwłaszcza skrypty PowerShell modyfikujące ACL Active Directory lub resetujące ustawienia ochrony kont. Sprawdź ustawienie `AllowDemandStart` zadania oraz zweryfikuj dane wejściowe i działanie skryptu; samo uprawnienie do uruchomienia określonego zadania nie oznacza możliwości wykonania dowolnego kodu.

## Foldery

Wszystkie pliki binarne znajdujące się w **folderach Autostart zostaną uruchomione podczas uruchamiania systemu**. Typowe foldery Autostart wymieniono poniżej, ale folder Autostart jest wskazany w rejestrze. [Przeczytaj, aby dowiedzieć się, gdzie.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Wyższy poziom uprawnień użytkownika może uruchamiać przy logowaniu chroniony skrypt, który wielokrotnie otwiera pliki z katalogu, do którego inny użytkownik ma prawo zapisu. Zanim uznasz ten katalog za ścieżkę eskalacji uprawnień, sprawdź **rzeczywistą tożsamość logowania**, katalog wejściowy skryptu i jego ACL oraz dokładne działanie skryptu. W szczególności [`hh.exe` otwiera skompilowane pliki HTML Help (`.chm`)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program); skrypt przekazujący mu pliki dostarczone przez wywołującego przekracza granicę zaufania treści, nawet jeśli sprawdza nazwę pliku lub jego pierwsze bajty. [Zasady HTML Help mogą ograniczać wykonywanie skrótów](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands), dlatego sprawdź zainstalowane zasady i zachowanie dostępnej zawartości. Samo rozszerzenie `.chm` lub sygnatura bajtowa nie dowodzą wykonania kodu z wyższymi uprawnieniami. Podczas inwentaryzacji sprawdź autorun, wiersz poleceń procesu i uprawnienia do ścieżki, nie otwierając niezaufanego pliku.

Ta sama granica zaufania treści istnieje, gdy osoba z wyższymi uprawnieniami **ręcznie otwiera** plik `.chm` z folderu dokumentacji, który może modyfikować inny użytkownik. Sprawdź dokładny plik i uprawnienia zapisu do katalogu nadrzędnego, tożsamość użytkownika uruchamiającego przeglądarkę oraz zdarzenie otwarcia, a także efektywne zasady HTML Help. Możliwość zapisu do folderu ani prośba o sprawdzenie dokumentacji nie dowodzą, że użytkownik o wyższych uprawnieniach otworzył zawartość kontrolowaną przez atakującego.

> **FYI**: Luki *path traversal* podczas wypakowywania archiwów (takie jak ta wykorzystywana w WinRAR przed wersją 7.13 – CVE-2025-8088) mogą posłużyć do **umieszczenia payloadów bezpośrednio w tych folderach Startup podczas wypakowywania**, co skutkuje wykonaniem kodu przy następnym logowaniu użytkownika.  Szczegółowe omówienie tej techniki znajdziesz tutaj:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Rejestr

> [!TIP]
> [Uwaga stąd](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): wpis rejestru **Wow6432Node** wskazuje, że używasz 64-bitowej wersji Windows. System operacyjny używa tego klucza do prezentowania oddzielnego widoku HKEY_LOCAL_MACHINE\SOFTWARE dla aplikacji 32-bitowych działających w 64-bitowych wersjach Windows.

### Uruchamianie

**Powszechnie znane** klucze rejestru AutoRun:

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

Klucze rejestru znane jako **Run** i **RunOnce** służą do automatycznego uruchamiania programów za każdym razem, gdy użytkownik loguje się do systemu. Wiersz poleceń przypisany jako wartość danych klucza może mieć maksymalnie 260 znaków.<sup>[[2]](#references)</sup>

**Uruchamianie usług** (można kontrolować automatyczne uruchamianie usług podczas rozruchu):

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

W systemie Windows Vista i nowszych wersjach klucze rejestru **Run** i **RunOnce** nie są generowane automatycznie. Wpisy w tych kluczach mogą bezpośrednio uruchamiać programy lub określać je jako zależności. Na przykład, aby załadować plik DLL podczas logowania, można użyć klucza rejestru **RunOnceEx** wraz z kluczem „Depend”. Pokazano to na przykładzie dodania wpisu rejestru, który uruchamia plik „C:\temp\evil.dll” podczas uruchamiania systemu:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: Jeśli możesz zapisywać do dowolnego z wymienionych kluczy rejestru w **HKLM**, możesz eskalować uprawnienia, gdy zaloguje się inny użytkownik.

> [!TIP]
> **Exploit 2**: Jeśli możesz nadpisać dowolny plik binarny wskazany w jednym z kluczy rejestru w **HKLM**, możesz zmodyfikować go, dodając backdoor, który umożliwi eskalację uprawnień, gdy zaloguje się inny użytkownik.

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

Skróty umieszczone w folderze **Startup** automatycznie uruchamiają usługi lub aplikacje podczas logowania użytkownika albo ponownego uruchamiania systemu. Lokalizacja folderu **Startup** jest określona w rejestrze zarówno dla zakresu **Local Machine**, jak i **Current User**. Oznacza to, że każdy skrót dodany do tych określonych lokalizacji **Startup** spowoduje uruchomienie powiązanej usługi lub programu po zalogowaniu lub ponownym uruchomieniu systemu. To prosty sposób na zaplanowanie automatycznego uruchamiania programów.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Jeśli możesz nadpisać dowolny folder [User] Shell w **HKLM**, będziesz w stanie wskazać folder, nad którym masz kontrolę, i umieścić w nim backdoor uruchamiany za każdym razem, gdy użytkownik zaloguje się do systemu, co pozwoli na eskalację uprawnień.

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

Ta wartość rejestru specyficzna dla użytkownika może wskazywać skrypt lub polecenie uruchamiane podczas logowania tego użytkownika. Jest głównie mechanizmem **persistence**, ponieważ działa tylko w kontekście danego użytkownika, ale warto ją sprawdzić podczas przeglądu po post-exploitation i analizy autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Jeśli możesz zapisywać tę wartość dla bieżącego użytkownika, możesz ponownie wywołać jej wykonanie przy następnym logowaniu interaktywnym bez uprawnień administratora. Jeśli możesz zapisywać ją w gałęzi rejestru innego użytkownika, możesz uzyskać wykonanie kodu, gdy ten użytkownik się zaloguje.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Notatki:

- Preferuj pełne ścieżki do plików `.bat`, `.cmd`, `.ps1` lub innych plików uruchamiających, które są już czytelne dla użytkownika docelowego.
- Utrzymuje się to po wylogowaniu/ponownym uruchomieniu, dopóki wartość nie zostanie usunięta.
- W przeciwieństwie do `HKLM\...\Run`, samo w sobie **nie** nadaje uprawnień do podniesienia poziomu; jest to mechanizm utrwalania w zakresie użytkownika.

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

W rejestrze systemu Windows, w kluczu `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, znajduje się wartość **`AlternateShell`**, która domyślnie jest ustawiona na `cmd.exe`. Oznacza to, że po wybraniu podczas uruchamiania opcji „Tryb awaryjny z wierszem polecenia” (przez naciśnięcie F8) używany jest `cmd.exe`. Można jednak skonfigurować komputer tak, aby uruchamiał się automatycznie w tym trybie, bez konieczności naciskania F8 i ręcznego wybierania tej opcji.

Kroki tworzenia opcji rozruchu, która automatycznie uruchamia komputer w „Trybie awaryjnym z wierszem polecenia”:<sup>[[5]](#references)</sup>

1. Zmień atrybuty pliku `boot.ini`, usuwając flagi tylko do odczytu, systemową i ukrytą: `attrib c:\boot.ini -r -s -h`
2. Otwórz plik `boot.ini` do edycji.
3. Wstaw wiersz podobny do tego: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Zapisz zmiany w pliku `boot.ini`.
5. Przywróć oryginalne atrybuty pliku: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Zmiana klucza rejestru **AlternateShell** umożliwia skonfigurowanie niestandardowej powłoki poleceń, co może posłużyć do uzyskania nieautoryzowanego dostępu.
- **Exploit 2 (uprawnienia do zapisu w PATH):** Uprawnienia do zapisu w dowolnej części zmiennej systemowej **PATH**, zwłaszcza przed `C:\Windows\system32`, pozwalają uruchomić niestandardowy plik `cmd.exe`, który może pełnić funkcję backdoora, jeśli system zostanie uruchomiony w trybie awaryjnym.
- **Exploit 3 (uprawnienia do zapisu w PATH i boot.ini):** Uprawnienia do zapisu w pliku `boot.ini` umożliwiają automatyczne uruchamianie systemu w trybie awaryjnym, ułatwiając uzyskanie nieautoryzowanego dostępu przy następnym ponownym uruchomieniu.

Aby sprawdzić bieżące ustawienie **AlternateShell**, użyj następujących poleceń:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Zainstalowany składnik

Active Setup to funkcja systemu Windows, która **uruchamia się, zanim środowisko pulpitu zostanie w pełni załadowane**. Nadaje priorytet wykonaniu określonych poleceń, które muszą zakończyć się przed kontynuowaniem logowania użytkownika. Proces ten zachodzi nawet przed uruchomieniem innych wpisów startowych, takich jak wpisy w sekcjach rejestru Run lub RunOnce.

Active Setup jest zarządzany za pomocą następujących kluczy rejestru:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

W tych kluczach znajdują się różne podklucze, z których każdy odpowiada określonemu składnikowi. Wartości kluczy, na które warto zwrócić uwagę, to:

- **IsInstalled:**
  - `0` oznacza, że polecenie składnika nie zostanie wykonane.
  - `1` oznacza, że polecenie zostanie wykonane raz dla każdego użytkownika; jest to domyślne zachowanie, jeśli brakuje wartości `IsInstalled`.
- **StubPath:** Określa polecenie wykonywane przez Active Setup. Może to być dowolny prawidłowy wiersz poleceń, na przykład uruchomienie `notepad`.

**Informacje dotyczące bezpieczeństwa:**

- Modyfikacja klucza lub zapis do niego, gdy **`IsInstalled`** ma wartość `"1"` i ustawiono określony **`StubPath`**, może prowadzić do nieautoryzowanego wykonania poleceń, a potencjalnie także do eskalacji uprawnień.
- Zmiana pliku binarnego wskazanego w dowolnej wartości **`StubPath`** również może umożliwić eskalację uprawnień, jeśli dostępne są wystarczające uprawnienia.

Do sprawdzenia konfiguracji **`StubPath`** we wszystkich składnikach Active Setup można użyć następujących poleceń:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Obiekty pomocnicze przeglądarki

### Omówienie obiektów pomocniczych przeglądarki (BHO)

Obiekty pomocnicze przeglądarki (BHO) to moduły DLL dodające dodatkowe funkcje do Microsoft Internet Explorer. Są ładowane do Internet Explorer i Windows Explorer przy każdym uruchomieniu. Można jednak zablokować ich wykonywanie, ustawiając klucz **NoExplorer** na wartość 1, co uniemożliwia ich ładowanie w instancjach Windows Explorer.<sup>[[1]](#references)</sup>

BHO są zgodne z Windows 10 za pośrednictwem Internet Explorer 11, ale nie są obsługiwane w Microsoft Edge, domyślnej przeglądarce w nowszych wersjach Windows.

Aby sprawdzić BHO zarejestrowane w systemie, można przejrzeć następujące klucze rejestru:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Każdy BHO jest reprezentowany w rejestrze przez **CLSID**, który pełni funkcję unikatowego identyfikatora. Szczegółowe informacje o każdym CLSID można znaleźć w `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Do wyszukiwania BHO w rejestrze można użyć następujących poleceń:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Rozszerzenia Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Pamiętaj, że rejestr będzie zawierał po 1 nowym wpisie dla każdej biblioteki dll, reprezentowanym przez **CLSID**. Informacje o CLSID znajdziesz w `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

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

### Obsługiwacze COM menu kontekstowego

Obsługiwacze menu kontekstowego Eksploratora to rozszerzenia powłoki zarejestrowane pod kluczami takimi jak `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` i `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`. Wartość domyślna obsługiwacza, a czasem nazwa jego klucza, to CLSID. Przejdź do `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`; jego wartość domyślna wskazuje nazwę biblioteki DLL ładowanej po wywołaniu obsługiwacza.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Sprawdź widoki rejestru 32- i 64-bitowy. `HKCR` scala rejestracje klas użytkownika i całego komputera, dlatego sprawdź, który klucz bazowy zostanie użyty przez dany proces. Tożsamość o niskich uprawnieniach, która może zmienić wartość `InprocServer32` obowiązującą na całym komputerze, może przekierować proces o wyższych uprawnieniach do innej biblioteki DLL, ale eskalacja wymaga, aby ten proces wywołał procedurę obsługi. Zapisywalna ścieżka do biblioteki DLL może stwarzać podobne ryzyko, nawet jeśli sama wartość rejestru jest chroniona.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Zwróć uwagę, że wszystkie lokalizacje, w których można znaleźć autoruns, są **już sprawdzane przez**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Jeśli jednak potrzebujesz **pełniejszej listy plików uruchamianych automatycznie**, możesz użyć [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)z systinternals:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Więcej

**Znajdź więcej lokalizacji Autoruns, takich jak rejestry, w** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Typowe mechanizmy utrzymywania trwałości złośliwego oprogramowania](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Automatyczne uruchamianie podczas rozruchu lub logowania: klucze rejestru Run / folder Autostart](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Skrypty inicjalizacyjne podczas rozruchu lub logowania: skrypt logowania (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – kategorie autostartu (Rozwiązywanie problemów za pomocą narzędzi Windows Sysinternals, wydanie 2)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Jak dodać opcję rozruchu, która uruchamia alternatywną powłokę?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Podsumowanie Metasploit z 04.03.2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
- [8] [Microsoft Learn – konteksty zabezpieczeń dla zadań](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
{{#include ../../banners/hacktricks-training.md}}
