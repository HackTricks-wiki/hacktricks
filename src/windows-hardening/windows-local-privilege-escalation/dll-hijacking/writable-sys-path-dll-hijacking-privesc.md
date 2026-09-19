# Zapisywalna ścieżka systemowa + DLL Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

Jeśli możesz **zapisywać do katalogu w systemowym `PATH`** (a nie tylko w swoim użytkownika `PATH`), możesz być w stanie **eskalować uprawnienia** w systemie.

Można to wykorzystać poprzez **DLL hijacking**, gdy usługa lub proces działający z większymi uprawnieniami próbuje załadować bibliotekę DLL, która nie istnieje we wcześniejszych lokalizacjach wyszukiwania, a następnie ostatecznie przeszukuje zapisywalny katalog systemowego `PATH`.

Więcej informacji o **DLL hijacking** znajdziesz tutaj:


{{#ref}}
./
{{#endref}}

## Privesc z DLL Hijacking

### Znajdowanie brakującej biblioteki DLL

Najpierw **zidentyfikuj proces** działający z **większymi uprawnieniami**, który próbuje **załadować bibliotekę DLL z zapisywalnego katalogu systemowego `PATH`**.

Pamiętaj, że ta technika zależy od wpisu **Machine/System PATH**, a nie tylko od **User PATH**. Dlatego przed poświęceniem czasu na Procmon warto wyliczyć wpisy **Machine PATH** i sprawdzić, które z nich są zapisywalne:<sup>[[1]](#references)</sup>
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
Problem w tych przypadkach polega na tym, że te procesy prawdopodobnie już działają. Aby zidentyfikować biblioteki DLL, które usługi próbują załadować, ale nie mogą tego zrobić, uruchom Procmon tak wcześnie, jak to możliwe (przed uruchomieniem procesów), a następnie:

- **Utwórz** folder `C:\privesc_hijacking` i dodaj ścieżkę `C:\privesc_hijacking` do **systemowej zmiennej środowiskowej Path**. Możesz zrobić to **ręcznie** lub za pomocą **PS**:
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
- Następnie wykonaj **reboot**. Po ponownym uruchomieniu komputera **`procmon`** rozpocznie **rejestrowanie** zdarzeń tak szybko, jak to możliwe.
- Po **uruchomieniu systemu Windows uruchom ponownie `procmon`**. Poinformuje Cię, że działał w tle, i **zapyta, czy chcesz zapisać** zdarzenia w pliku. Odpowiedz **tak** i **zapisz zdarzenia w pliku**.
- **Po** wygenerowaniu **pliku** zamknij otwarte okno **`procmon`** i **otwórz plik ze zdarzeniami**.
- Dodaj następujące **filtry**, aby znaleźć wszystkie biblioteki DLL, które **proces próbował załadować** z zapisywalnego folderu System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** jest wymagane tylko w przypadku usług, które uruchamiają się **zbyt wcześnie**, aby można było je obserwować w inny sposób. Jeśli możesz **wywołać docelową usługę/program na żądanie** (na przykład poprzez interakcję z jego interfejsem COM, ponowne uruchomienie usługi lub ponowne uruchomienie zaplanowanego zadania), zwykle szybciej jest użyć normalnego przechwytywania w Procmon z filtrami takimi jak **`Path contains .dll`**, **`Result is NAME NOT FOUND`** oraz **`Path begins with <writable_machine_path>`**.

### Pominięte biblioteki DLL

Uruchamiając to na darmowej **wirtualnej maszynie (vmware) z systemem Windows 11**, uzyskałem następujące wyniki:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

W tym przypadku zignoruj wyniki `.exe`. Próby załadowania brakujących bibliotek DLL pochodziły z:

| Usługa                         | Dll                | Wiersz polecenia                                                     |
| ------------------------------ | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Poniższy przykład wykorzystuje technikę opisaną w tym artykule dotyczącym [**wykorzystania `WptsExtensions.dll` do eskalacji uprawnień**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Inne warte przeanalizowania możliwości

`WptsExtensions.dll` jest dobrym przykładem, ale nie jest jedyną powtarzającą się **phantom DLL**, która pojawia się w uprzywilejowanych usługach. Współczesne reguły wyszukiwania i publiczne katalogi hijackingu nadal śledzą takie nazwy jak:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Klasyczny kandydat **SYSTEM** w systemach klienckich. Dobry wybór, gdy zapisywalny katalog znajduje się w **Machine PATH**, a usługa wyszukuje bibliotekę DLL podczas uruchamiania. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interesująca opcja w **edycjach serwerowych**, ponieważ usługa działa jako **SYSTEM** i w niektórych buildach może być **wywołana na żądanie przez zwykłego użytkownika**, co czyni ją lepszą niż przypadki wymagające wyłącznie restartu. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Zwykle najpierw uzyskuje się **`NT AUTHORITY\LOCAL SERVICE`**. Często jest to nadal wystarczające, ponieważ token ma **`SeImpersonatePrivilege`**, więc można połączyć tę technikę z [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Traktuj te nazwy jako **wskazówki do analizy**, a nie gwarantowane możliwości: zależą one od **SKU/build**, a Microsoft może zmieniać to zachowanie między wydaniami. Najważniejszy wniosek jest taki, aby szukać **brakujących bibliotek DLL w uprzywilejowanych usługach, które przeszukują Machine PATH**, szczególnie jeśli usługę można **ponownie wywołać bez restartowania systemu**.

### Eksploatacja

Aby **eskalować uprawnienia**, przejmij **`WptsExtensions.dll`**. Gdy znana jest **ścieżka** i **nazwa**, wygeneruj złośliwą bibliotekę DLL.

Możesz [**spróbować użyć dowolnego z tych przykładów**](#creating-and-compiling-dlls). Możesz uruchamiać payloady takie jak: uzyskanie rev shell, dodanie użytkownika, wykonanie beacon...

> [!WARNING]
> Pamiętaj, że **nie wszystkie usługi działają** jako **`NT AUTHORITY\SYSTEM`**. Niektóre działają jako **`NT AUTHORITY\LOCAL SERVICE`**, który ma **mniej uprawnień**, więc wykorzystanie jednej z tych usług może nie pozwolić na utworzenie nowego użytkownika.\
> To konto ma jednak prawo użytkownika **`SeImpersonatePrivilege`**, więc możesz użyć [**Potato suite do eskalacji uprawnień**](../roguepotato-and-printspoofer.md). W takim przypadku reverse shell jest lepszą opcją niż próba utworzenia użytkownika.

W chwili pisania tego tekstu usługa **Task Scheduler** działa z uprawnieniami **Nt AUTHORITY\SYSTEM**.

Po **wygenerowaniu złośliwej biblioteki DLL** (_w moim przypadku użyłem x64 rev shell i uzyskałem shell, ale defender go zablokował, ponieważ pochodził z msfvenom_) zapisz ją w zapisywalnym System Path pod nazwą **WptsExtensions.dll**, a następnie **uruchom ponownie** komputer (albo uruchom ponownie usługę lub wykonaj dowolną czynność konieczną do ponownego uruchomienia zaatakowanej usługi/programu).

Po ponownym uruchomieniu usługi **biblioteka DLL powinna zostać załadowana i wykonana** (możesz **ponownie wykorzystać** sztuczkę z **procmon**, aby sprawdzić, czy **biblioteka została załadowana zgodnie z oczekiwaniami**).

## References

- [1] [Wyjaśnienie Windows DLL Hijacking (miejmy nadzieję)](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Podejrzana biblioteka DLL załadowana w celu utrzymania dostępu lub eskalacji uprawnień](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – eskalacja uprawnień w systemie Windows](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
