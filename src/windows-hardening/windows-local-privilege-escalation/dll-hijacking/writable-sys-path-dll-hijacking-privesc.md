# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Jeśli możesz **zapisywać do katalogu w systemowym `PATH`** (a nie tylko w swoim `PATH` użytkownika), możesz być w stanie **eskalować uprawnienia** w systemie.

Można to wykorzystać za pomocą **DLL hijacking**, gdy usługa lub proces z większymi uprawnieniami próbuje załadować bibliotekę DLL, która nie istnieje we wcześniejszych lokalizacjach wyszukiwania, a następnie ostatecznie przeszukuje zapisywalny katalog systemowego `PATH`.

Więcej informacji o **DLL hijacking** znajdziesz tutaj:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a Missing DLL

Najpierw **zidentyfikuj proces** działający z **większymi uprawnieniami**, który próbuje **załadować bibliotekę DLL z zapisywalnego katalogu systemowego `PATH`**.

Pamiętaj, że ta technika zależy od wpisu **Machine/System PATH**, a nie tylko od **User PATH**. Dlatego przed poświęceniem czasu na Procmon warto wylistować wpisy **Machine PATH** i sprawdzić, które z nich są zapisywalne:<sup>[[1]](#references)</sup>
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
Problem w tych przypadkach polega na tym, że te procesy prawdopodobnie już działają. Aby zidentyfikować biblioteki DLL, których usiłują użyć usługi, ale których nie mogą załadować, uruchom Procmon możliwie wcześnie (zanim procesy zostaną uruchomione), a następnie:

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
- Uruchom **`procmon`**, przejdź do **`Options`** --> **`Enable boot logging`** i naciśnij **`OK`** w wyświetlonym monicie.
- Następnie wykonaj **restart**. Po ponownym uruchomieniu komputera **`procmon`** zacznie jak najszybciej **rejestrować** zdarzenia.
- Po **uruchomieniu systemu Windows uruchom ponownie `procmon`**. Program poinformuje Cię, że działał w tle, i **zapyta, czy chcesz zapisać** zdarzenia w pliku. Odpowiedz **tak** i **zapisz zdarzenia w pliku**.
- **Po** wygenerowaniu **pliku** zamknij otwarte okno **`procmon`** i **otwórz plik ze zdarzeniami**.
- Dodaj poniższe **filtry**, aby znaleźć wszystkie biblioteki DLL, które **proces próbował załadować** z zapisywalnego folderu System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** jest wymagane tylko w przypadku usług, które uruchamiają się **zbyt wcześnie**, aby można było je obserwować w inny sposób. Jeśli możesz **wywołać docelową usługę/program na żądanie** (na przykład poprzez interakcję z jego interfejsem COM, ponowne uruchomienie usługi lub ponowne uruchomienie zaplanowanego zadania), zwykle szybciej jest przeprowadzić standardowe przechwytywanie za pomocą Procmon z filtrami takimi jak **`Path contains .dll`**, **`Result is NAME NOT FOUND`** oraz **`Path begins with <writable_machine_path>`**.

### Pominięte biblioteki DLL

Uruchamiając to na darmowej **wirtualnej maszynie (vmware) z systemem Windows 11**, uzyskałem następujące wyniki:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

W tym przypadku zignoruj wyniki dotyczące plików `.exe`. Próby załadowania brakujących bibliotek DLL pochodziły z:

| Usługa                         | Biblioteka DLL     | Wiersz CMD                                                          |
| ------------------------------ | ------------------ | -------------------------------------------------------------------- |
| Harmonogram zadań (Schedule)   | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Usługa zasad diagnostycznych (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                            | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Poniższy przykład wykorzystuje technikę opisaną w tym artykule dotyczącą [**abusing `WptsExtensions.dll` for privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Inne kandydatury warte sprawdzenia

`WptsExtensions.dll` jest dobrym przykładem, ale nie jest jedyną powtarzającą się **phantom DLL**, która pojawia się w uprzywilejowanych usługach. Współczesne reguły huntingu i publiczne katalogi hijack nadal śledzą nazwy takie jak:<sup>[[2]](#references)</sup>

| Usługa / scenariusz | Brakująca biblioteka DLL | Uwagi |
| --- | --- | --- |
| Harmonogram zadań (`Schedule`) | `WptsExtensions.dll` | Klasyczny kandydat do uzyskania uprawnień **SYSTEM** w systemach klienckich. Dobry wybór, gdy zapisywalny katalog znajduje się w **Machine PATH**, a usługa sprawdza obecność biblioteki DLL podczas uruchamiania. |
| NetMan w systemie Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interesujący przypadek w **edycjach serwerowych**, ponieważ usługa działa jako **SYSTEM** i w niektórych kompilacjach może być **wywołana na żądanie przez zwykłego użytkownika**, co czyni ją lepszą od przypadków wymagających wyłącznie restartu. |
| Usługa Connected Devices Platform (`CDPSvc`) | `cdpsgshims.dll` | Zwykle najpierw uzyskuje się **`NT AUTHORITY\LOCAL SERVICE`**. Często nadal jest to wystarczające, ponieważ token ma **`SeImpersonatePrivilege`**, więc można połączyć tę technikę z [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Traktuj te nazwy jako **wskazówki do wstępnego sprawdzenia**, a nie gwarantowane sukcesy: zależą one od **SKU/kompilacji**, a firma Microsoft może zmieniać zachowanie między kolejnymi wydaniami. Najważniejszym wnioskiem jest wyszukiwanie **brakujących bibliotek DLL w uprzywilejowanych usługach, które przechodzą przez Machine PATH**, szczególnie jeśli usługę można **ponownie wywołać bez restartu systemu**.

### Exploitation

Aby **eskalować uprawnienia**, przeprowadź hijacking **`WptsExtensions.dll`**. Po ustaleniu **ścieżki** i **nazwy** wygeneruj złośliwą bibliotekę DLL.

Możesz [**spróbować użyć dowolnego z tych przykładów**](#creating-and-compiling-dlls). Możesz uruchomić payloady takie jak: uzyskać rev shell, dodać użytkownika, uruchomić beacon...

> [!WARNING]
> Pamiętaj, że **nie wszystkie usługi działają** jako **`NT AUTHORITY\SYSTEM`**. Niektóre działają jako **`NT AUTHORITY\LOCAL SERVICE`**, które ma **mniej uprawnień**, więc abuse jednej z tych usług może nie pozwolić na utworzenie nowego użytkownika.\
> To konto ma jednak prawo użytkownika **`SeImpersonatePrivilege`**, więc możesz użyć [**Potato suite do eskalacji uprawnień**](../roguepotato-and-printspoofer.md). W takim przypadku reverse shell jest lepszą opcją niż próba utworzenia użytkownika.

W chwili pisania tego tekstu usługa **Task Scheduler** działa z uprawnieniami **Nt AUTHORITY\SYSTEM**.

Po **wygenerowaniu złośliwej biblioteki DLL** (_w moim przypadku użyłem x64 rev shell i uzyskałem shell, ale defender go zablokował, ponieważ pochodził z msfvenom_) zapisz ją w zapisywalnym System Path pod nazwą **WptsExtensions.dll** i wykonaj **restart** komputera (albo zrestartuj usługę lub zrób cokolwiek, co spowoduje ponowne uruchomienie podatnej usługi/programu).

Po ponownym uruchomieniu usługi **biblioteka DLL powinna zostać załadowana i wykonana** (możesz **ponownie użyć** sztuczki z **procmon**, aby sprawdzić, czy **biblioteka została załadowana zgodnie z oczekiwaniami**).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Podejrzana biblioteka DLL załadowana w celu utrzymania dostępu lub eskalacji uprawnień](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – eskalacja uprawnień w systemie Windows](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
