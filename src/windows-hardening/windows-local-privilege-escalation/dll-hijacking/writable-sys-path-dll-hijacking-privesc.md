# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

Jeśli odkryłeś, że możesz **zapisywać w folderze System Path** (zauważ, że to nie zadziała, jeśli możesz zapisywać w folderze User Path), możliwe, że możesz **eskalować uprawnienia** w systemie.

Aby to zrobić, możesz wykorzystać **Dll Hijacking**, gdzie będziesz **przechwytywać ładowaną bibliotekę** przez usługę lub proces z **większymi uprawnieniami** niż twoje, a ponieważ ta usługa ładuje Dll, które prawdopodobnie nawet nie istnieje w całym systemie, spróbuje załadować je z System Path, gdzie możesz zapisywać.

Więcej informacji o **what is Dll Hijackig** znajdziesz tutaj:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a missing Dll

Pierwszą rzeczą, której potrzebujesz, jest **zidentyfikowanie procesu** uruchomionego z **większymi uprawnieniami** niż twoje, który próbuje **załadować Dll z System Path**, do którego masz dostęp do zapisu.

Pamiętaj, że ta technika zależy od wpisu **Machine/System PATH**, a nie tylko od twojego **User PATH**. Dlatego, zanim poświęcisz czas na Procmon, warto wyliczyć wpisy **Machine PATH** i sprawdzić, które z nich są zapisywalne:
```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
$path = $_.Trim()
if ($path) {
Write-Host "`n[*] $path"
icacls $path 2>$null
}
}
```
Problem w tych przypadkach polega na tym, że prawdopodobnie te procesy już działają. Aby znaleźć, których Dll brakuje usługom, musisz uruchomić procmon tak szybko, jak to możliwe (zanim procesy zostaną załadowane). Więc, aby znaleźć brakujące .dll, zrób:

- **Create** folder `C:\privesc_hijacking` i dodaj ścieżkę `C:\privesc_hijacking` do **System Path env variable**. Możesz to zrobić **ręcznie** albo za pomocą **PS**:
```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- Uruchom **`procmon`** i przejdź do **`Options`** --> **`Enable boot logging`** i naciśnij **`OK`** w oknie dialogowym.
- Następnie **zrestartuj** komputer. Po ponownym uruchomieniu **`procmon`** zacznie jak najszybciej **rejestrować** zdarzenia.
- Gdy **Windows** się **uruchomi, uruchom ponownie `procmon`**, powie Ci, że działał w tle i **zapyta, czy chcesz zapisać** zdarzenia do pliku. Odpowiedz **yes** i **zapisz zdarzenia do pliku**.
- **Po** wygenerowaniu **pliku**, **zamknij** otwarte okno **`procmon`** i **otwórz plik zdarzeń**.
- Dodaj te **filtry**, a znajdziesz wszystkie Dll-e, które jakiś **proces próbował załadować** z zapisywalnego folderu System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** jest wymagane tylko dla usług, które uruchamiają się zbyt wcześnie, aby można je było inaczej zaobserwować. Jeśli możesz **uruchomić docelową usługę/program na żądanie** (na przykład poprzez interakcję z interfejsem COM, restart usługi albo ponowne uruchomienie zaplanowanego zadania), zwykle szybciej jest użyć zwykłego przechwytywania Procmon z filtrami takimi jak **`Path contains .dll`**, **`Result is NAME NOT FOUND`** oraz **`Path begins with <writable_machine_path>`**.

### Missed Dlls

Uruchamiając to na darmowej **wirtualnej maszynie (vmware) Windows 11** dostałem takie wyniki:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

W tym przypadku pliki .exe są bezużyteczne, więc je zignoruj; brakujące DLL-e pochodziły z:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Po znalezieniu tego natrafiłem na ten ciekawy wpis na blogu, który również wyjaśnia, jak [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). To właśnie zamierzamy **teraz zrobić**.

### Other candidates worth triaging

`WptsExtensions.dll` to dobry przykład, ale nie jest to jedyna powtarzająca się **phantom DLL**, która pojawia się w uprzywilejowanych usługach. Nowoczesne reguły huntingu i publiczne katalogi hijacków nadal śledzą nazwy takie jak:

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Klasyczny kandydat **SYSTEM** na systemach klienckich. Dobre, gdy zapisywalny katalog znajduje się w **Machine PATH** i usługa sprawdza DLL podczas startu. |
| NetMan na Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interesujące na **wersjach serwerowych**, ponieważ usługa działa jako **SYSTEM** i w niektórych buildach może być **uruchamiana na żądanie przez zwykłego użytkownika**, co jest lepsze niż przypadki wymagające tylko restartu. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Zwykle najpierw daje **`NT AUTHORITY\LOCAL SERVICE`**. Często nadal wystarcza, ponieważ token ma **`SeImpersonatePrivilege`**, więc możesz połączyć to z [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Traktuj te nazwy jako **wskazówki do triage**, a nie gwarantowane sukcesy: zależą od **SKU/build**, a Microsoft może zmienić zachowanie między wydaniami. Najważniejszy wniosek to szukać **brakujących DLL-i w uprzywilejowanych usługach, które przechodzą przez Machine PATH**, szczególnie jeśli usługę można **ponownie uruchomić bez restartu**.

### Exploitation

Tak więc, aby **podnieść uprawnienia**, przejmiemy bibliotekę **WptsExtensions.dll**. Mając **ścieżkę** i **nazwę**, musimy tylko **wygenerować złośliwy dll**.

Możesz [**spróbować użyć dowolnego z tych przykładów**](#creating-and-compiling-dlls). Możesz uruchomić payloady takie jak: rev shell, dodanie użytkownika, uruchomienie beacona...

> [!WARNING]
> Zwróć uwagę, że **nie wszystkie usługi są uruchamiane** z **`NT AUTHORITY\SYSTEM`**, niektóre działają również jako **`NT AUTHORITY\LOCAL SERVICE`**, który ma **mniej uprawnień** i **nie będziesz w stanie utworzyć nowego użytkownika** wykorzystując jego uprawnienia.\
> Jednak ten użytkownik ma uprawnienie **`seImpersonate`**, więc możesz użyć [**potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). W tym przypadku rev shell jest więc lepszą opcją niż próba utworzenia użytkownika.

W momencie pisania tego tekstu usługa **Task Scheduler** działa jako **Nt AUTHORITY\SYSTEM**.

Po **wygenerowaniu złośliwego Dll-a** (_w moim przypadku użyłem x64 rev shell i dostałem shell z powrotem, ale defender go zabił, bo pochodził z msfvenom_), zapisz go w zapisywalnym System Path pod nazwą **WptsExtensions.dll** i **zrestartuj** komputer (albo zrestartuj usługę, albo zrób cokolwiek, co jest potrzebne, aby ponownie uruchomić podatną usługę/program).

Gdy usługa zostanie ponownie uruchomiona, **dll powinien zostać załadowany i wykonany** (możesz **ponownie użyć** sztuczki z **procmon**, aby sprawdzić, czy **biblioteka została załadowana zgodnie z oczekiwaniami**).

## References

- [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)

{{#include ../../../banners/hacktricks-training.md}}
