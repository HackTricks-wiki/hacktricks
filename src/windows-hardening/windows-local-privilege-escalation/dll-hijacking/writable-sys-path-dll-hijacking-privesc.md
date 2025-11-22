# Zapisalna ścieżka systemowa +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

Jeśli odkryjesz, że możesz **zapisywać w folderze System Path** (uwaga: nie zadziała to, jeśli możesz zapisywać tylko w folderze User Path), możliwe, że będziesz mógł **escalate privileges** w systemie.

Aby to zrobić, możesz wykorzystać **Dll Hijacking**, polegający na **przechwyceniu biblioteki ładowanej** przez usługę lub proces o **wyższych uprawnieniach** niż Twoje. Ponieważ ta usługa ładuje Dll, która prawdopodobnie nie istnieje w całym systemie, spróbuje załadować ją ze ścieżki systemowej, do której możesz zapisywać.

Więcej informacji o tym, **czym jest Dll Hijackig**, znajdziesz tutaj:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Znajdowanie brakującej Dll

Pierwszą rzeczą, której potrzebujesz, jest **zidentyfikowanie procesu** działającego z **wyższymi uprawnieniami** niż Twoje, który próbuje **załadować Dll ze ścieżki systemowej**, do której możesz zapisywać.

Problem w takich przypadkach jest taki, że te procesy prawdopodobnie już działają. Aby znaleźć, których .dll brakuje usługom, musisz uruchomić procmon jak najszybciej (zanim procesy zostaną załadowane). Więc, aby znaleźć brakujące .dll, wykonaj:

- **Utwórz** folder `C:\privesc_hijacking` i dodaj ścieżkę `C:\privesc_hijacking` do **zmiennej środowiskowej Path systemu**. Możesz to zrobić **ręcznie** lub przy użyciu **PS**:
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
- Uruchom **`procmon`** i przejdź do **`Options`** --> **`Enable boot logging`** i naciśnij **`OK`** w wyświetlonym oknie.
- Następnie, **reboot**. Po ponownym uruchomieniu komputera **`procmon`** zacznie jak najszybciej **rejestrować** zdarzenia.
- Gdy **Windows** wystartuje, ponownie uruchom **`procmon`** — poinformuje Cię, że działał podczas startu i **zapowie**, czy chcesz zapisać zdarzenia do pliku. Wybierz **yes** i **zapisz zdarzenia do pliku**.
- **Po** wygenerowaniu **pliku**, zamknij otwarte okno **`procmon`** i otwórz plik ze zdarzeniami.
- Dodaj poniższe **filtry** i znajdziesz wszystkie Dll, które jakiś **proces próbował załadować** z zapisywalnego folderu System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Brakujące Dlls

Uruchamiając to na darmowej **virtual (vmware) Windows 11 machine** otrzymałem następujące wyniki:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

W tym przypadku pliki .exe są bezużyteczne, więc je zignoruj — brakujące DLL pochodziły z:

| Usługa                          | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Po znalezieniu tego, natrafiłem na ciekawy wpis na blogu, który także wyjaśnia, jak [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). To właśnie **zamierzamy teraz zrobić**.

### Eksploatacja

Zatem, aby **escalate privileges** przechwycimy bibliotekę **WptsExtensions.dll**. Mając **ścieżkę** i **nazwę**, musimy jedynie **wygenerować złośliwą dll**.

Możesz [**try to use any of these examples**](#creating-and-compiling-dlls). Możesz uruchomić payloady takie jak: get a rev shell, add a user, execute a beacon...

> [!WARNING]
> Zauważ, że **not all the service are run** z **`NT AUTHORITY\SYSTEM`** — niektóre są też uruchamiane jako **`NT AUTHORITY\LOCAL SERVICE`**, które ma **mniejsze uprawnienia** i **nie będziesz w stanie utworzyć nowego użytkownika** wykorzystując jego uprawnień.\
> Jednak ten użytkownik ma przywilej **`seImpersonate`**, więc możesz użyć [ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). W takim przypadku rev shell jest lepszą opcją niż próba tworzenia użytkownika.

W momencie pisania usługa **Task Scheduler** jest uruchamiana z **Nt AUTHORITY\SYSTEM**.

Po **wygenerowaniu złośliwej Dll** (_w moim przypadku użyłem x64 rev shell i otrzymałem shell, ale Defender go zabił, ponieważ pochodził z msfvenom_), zapisz ją w zapisywalnym System Path pod nazwą **WptsExtensions.dll** i **restart** komputera (lub zrestartuj usługę albo zrób cokolwiek, co spowoduje ponowne uruchomienie dotkniętej usługi/programu).

Gdy usługa zostanie ponownie uruchomiona, **dll powinna zostać załadowana i wykonana** (możesz **ponownie użyć** triku **procmon**, aby sprawdzić, czy **biblioteka została załadowana zgodnie z oczekiwaniami**).

{{#include ../../../banners/hacktricks-training.md}}
