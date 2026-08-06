# Writable Sys Path + Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

Jeśli odkryłeś, że możesz **zapisywać w folderze System Path** (pamiętaj, że nie zadziała to, jeśli możesz zapisywać w folderze User Path), możliwe, że będziesz w stanie **eskalować uprawnienia** w systemie.

Aby to zrobić, możesz wykorzystać **Dll Hijacking**, przejmując **library being loaded** przez usługę lub proces z **większymi uprawnieniami** niż Twoje. Ponieważ ta usługa ładuje Dll, która prawdopodobnie nie istnieje nawet w całym systemie, spróbuje załadować ją z System Path, do którego możesz zapisywać.

Więcej informacji na temat **what is Dll Hijackig** znajdziesz tutaj:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Znajdowanie brakującej Dll

Pierwszą rzeczą, której potrzebujesz, jest **zidentyfikowanie procesu** działającego z **większymi uprawnieniami** niż Twoje, który próbuje **załadować Dll z folderu System Path**, do którego możesz zapisywać.

Pamiętaj, że ta technika zależy od wpisu **Machine/System PATH**, a nie tylko od **User PATH**. Dlatego przed poświęceniem czasu na Procmon warto wyliczyć wpisy **Machine PATH** i sprawdzić, które z nich można zapisywać:<sup>[[1]](#references)</sup>
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
Problem w tych przypadkach polega na tym, że te procesy prawdopodobnie już działają. Aby znaleźć, których bibliotek DLL brakuje usługom, musisz uruchomić procmon tak szybko, jak to możliwe (zanim procesy zostaną załadowane). Aby znaleźć brakujące pliki `.dll`, wykonaj następujące czynności:

- **Utwórz** folder `C:\privesc_hijacking` i dodaj ścieżkę `C:\privesc_hijacking` do **zmiennej środowiskowej System Path**. Możesz zrobić to **ręcznie** lub za pomocą **PS**:
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
- Uruchom **`procmon`** i przejdź do **`Options`** --> **`Enable boot logging`**, a następnie naciśnij **`OK`** w monicie.
- Następnie wykonaj **reboot**. Po ponownym uruchomieniu komputera **`procmon`** zacznie jak najszybciej **rejestrować** zdarzenia.
- Po **uruchomieniu Windows uruchom ponownie `procmon`**. Poinformuje Cię, że działał w tle, i **zapyta, czy chcesz zapisać** zdarzenia w pliku. Odpowiedz **tak** i **zapisz zdarzenia w pliku**.
- **Po** wygenerowaniu **pliku** zamknij otwarte okno **`procmon`** i **otwórz plik ze zdarzeniami**.
- Dodaj te **filtry**, a znajdziesz wszystkie biblioteki DLL, które jakaś **proccess próbowała załadować** z zapisywalnego folderu System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging jest wymagane tylko w przypadku usług uruchamianych zbyt wcześnie**, aby można było je obserwować w inny sposób. Jeśli możesz **wywołać docelową usługę/program na żądanie** (na przykład przez interakcję z jego interfejsem COM, ponowne uruchomienie usługi lub ponowne uruchomienie scheduled task), zwykle szybciej jest pozostawić normalny capture w Procmonie z filtrami takimi jak **`Path contains .dll`**, **`Result is NAME NOT FOUND`** oraz **`Path begins with <writable_machine_path>`**.

### Pominięte biblioteki DLL

Uruchamiając to na darmowej **wirtualnej maszynie (vmware) z Windows 11**, uzyskałem następujące wyniki:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

W tym przypadku pliki .exe są bezużyteczne, więc je zignoruj. Pominięte biblioteki DLL pochodziły z:

| Usługa                         | DLL                | Linia CMD                                                           |
| ------------------------------ | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)      | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                            | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Po znalezieniu tego natrafiłem na interesujący wpis na blogu, który również wyjaśnia, jak [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Właśnie tym **zajmiemy się teraz**.<sup>[[3]](#references)</sup>

### Inne warte sprawdzenia kandydatury

`WptsExtensions.dll` jest dobrym przykładem, ale nie jest jedyną powtarzającą się **phantom DLL**, która pojawia się w uprzywilejowanych usługach. Współczesne reguły huntingu i publiczne katalogi hijacków nadal śledzą takie nazwy jak:<sup>[[2]](#references)</sup>

| Usługa / scenariusz | Brakująca DLL | Uwagi |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Klasyczny kandydat do uzyskania **SYSTEM** w systemach klienckich. Dobry wybór, gdy zapisywalny katalog znajduje się w **Machine PATH**, a usługa sprawdza obecność DLL podczas uruchamiania. |
| NetMan w Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interesujące w przypadku **server editions**, ponieważ usługa działa jako **SYSTEM** i w niektórych buildach może być **wywołana na żądanie przez zwykłego użytkownika**, co czyni ten przypadek lepszym niż scenariusze wymagające wyłącznie rebootu. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Zwykle najpierw uzyskuje się **`NT AUTHORITY\LOCAL SERVICE`**. Często nadal wystarcza to do dalszego działania, ponieważ token ma **`SeImpersonatePrivilege`**, więc można połączyć go z [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Traktuj te nazwy jako **wskazówki do triage**, a nie gwarantowany sukces: zależą one od **SKU/builda**, a Microsoft może zmieniać zachowanie między kolejnymi wydaniami. Najważniejszy wniosek jest taki, aby szukać **brakujących DLL w uprzywilejowanych usługach, które przechodzą przez Machine PATH**, szczególnie jeśli usługę można **ponownie wywołać bez rebootu**.

### Exploitation

Aby więc **escalate privileges**, dokonamy hijacku biblioteki **WptsExtensions.dll**. Mając **ścieżkę** i **nazwę**, musimy tylko **wygenerować malicious DLL**.

Możesz [**spróbować użyć dowolnego z tych przykładów**](#creating-and-compiling-dlls). Możesz uruchomić payloady takie jak: uzyskać rev shell, dodać użytkownika, wykonać beacon...

> [!WARNING]
> Pamiętaj, że **nie wszystkie usługi są uruchamiane** z uprawnieniami **`NT AUTHORITY\SYSTEM`**. Niektóre działają również jako **`NT AUTHORITY\LOCAL SERVICE`**, które ma **mniej uprawnień**, dlatego **nie będziesz w stanie utworzyć nowego użytkownika ani abuse jego uprawnień**.\
> Jednak ten użytkownik ma uprawnienie **`seImpersonate`**, więc możesz użyć[ **potato suite do escalate privileges**](../roguepotato-and-printspoofer.md). W takim przypadku rev shell jest lepszą opcją niż próba utworzenia użytkownika.

W chwili pisania tego tekstu usługa **Task Scheduler** działa jako **Nt AUTHORITY\SYSTEM**.

Po **wygenerowaniu malicious DLL** (_w moim przypadku użyłem x64 rev shell i uzyskałem shell, ale defender go zabił, ponieważ pochodził z msfvenom_) zapisz ją w zapisywalnym System Path pod nazwą **WptsExtensions.dll** i wykonaj **restart** komputera (albo zrestartuj usługę lub zrób cokolwiek, co spowoduje ponowne uruchomienie danej usługi/programu).

Po ponownym uruchomieniu usługi **DLL powinna zostać załadowana i wykonana** (możesz ponownie wykorzystać trik z **procmon**, aby sprawdzić, czy biblioteka została załadowana zgodnie z oczekiwaniami).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)

{{#include ../../../banners/hacktricks-training.md}}
