# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

Jeśli odkryłeś, że możesz **zapisywać w folderze System Path** (zauważ, że to nie zadziała, jeśli możesz zapisywać w folderze User Path), istnieje możliwość, że możesz **eskalować uprawnienia** w systemie.

Aby to zrobić, możesz wykorzystać **Dll Hijacking**, gdzie zamierzasz **przechwycić bibliotekę ładowaną** przez usługę lub proces z **większymi uprawnieniami** niż twoje, a ponieważ ta usługa ładuje Dll, która prawdopodobnie nie istnieje w całym systemie, spróbuje załadować ją z System Path, w którym możesz pisać.

Aby uzyskać więcej informacji na temat **czym jest Dll Hijacking**, sprawdź:

{{#ref}}
./
{{#endref}}

## Eskalacja uprawnień z Dll Hijacking

### Znalezienie brakującej Dll

Pierwszą rzeczą, którą musisz zrobić, jest **zidentyfikowanie procesu** działającego z **większymi uprawnieniami** niż ty, który próbuje **załadować Dll z System Path**, w którym możesz pisać.

Problem w tych przypadkach polega na tym, że prawdopodobnie te procesy już działają. Aby znaleźć, które Dll brakuje usługom, musisz uruchomić procmon tak szybko, jak to możliwe (zanim procesy zostaną załadowane). Aby znaleźć brakujące .dll, wykonaj:

- **Utwórz** folder `C:\privesc_hijacking` i dodaj ścieżkę `C:\privesc_hijacking` do **zmiennej środowiskowej System Path**. Możesz to zrobić **ręcznie** lub za pomocą **PS**:
```powershell
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
- Następnie **zrestartuj** komputer. Gdy komputer się uruchomi, **`procmon`** zacznie **rejestrować** zdarzenia jak najszybciej.
- Po **uruchomieniu Windows** uruchom ponownie **`procmon`**, powie ci, że działał i **zapyta, czy chcesz zapisać** zdarzenia w pliku. Powiedz **tak** i **zapisz zdarzenia w pliku**.
- **Po** **wygenerowaniu pliku**, **zamknij** otwarte okno **`procmon`** i **otwórz plik ze zdarzeniami**.
- Dodaj te **filtry**, a znajdziesz wszystkie Dll, które niektóre **procesy próbowały załadować** z folderu zapisywalnego System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Brakujące Dll

Uruchamiając to na darmowej **wirtualnej maszynie (vmware) Windows 11** uzyskałem te wyniki:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

W tym przypadku .exe są bezużyteczne, więc je zignoruj, brakujące DLL pochodziły z:

| Usługa                          | Dll                | Linia CMD                                                           |
| ------------------------------- | ------------------ | ------------------------------------------------------------------- |
| Harmonogram zadań (Schedule)   | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`         |
| Usługa polityki diagnostycznej (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`               |

Po znalezieniu tego, znalazłem ten interesujący post na blogu, który również wyjaśnia, jak [**nadużyć WptsExtensions.dll do eskalacji uprawnień**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Co zamierzamy teraz zrobić.

### Eksploatacja

Aby **eskalować uprawnienia**, zamierzamy przejąć bibliotekę **WptsExtensions.dll**. Mając **ścieżkę** i **nazwę**, musimy tylko **wygenerować złośliwy dll**.

Możesz [**spróbować użyć któregokolwiek z tych przykładów**](./#creating-and-compiling-dlls). Możesz uruchomić payloady takie jak: uzyskać powłokę rev, dodać użytkownika, wykonać beacon...

> [!WARNING]
> Zauważ, że **nie wszystkie usługi są uruchamiane** z **`NT AUTHORITY\SYSTEM`**, niektóre są również uruchamiane z **`NT AUTHORITY\LOCAL SERVICE`**, które mają **mniejsze uprawnienia** i **nie będziesz mógł stworzyć nowego użytkownika** nadużyć jego uprawnień.\
> Jednak ten użytkownik ma uprawnienie **`seImpersonate`**, więc możesz użyć [**potato suite do eskalacji uprawnień**](../roguepotato-and-printspoofer.md). Tak więc w tym przypadku powłoka rev jest lepszą opcją niż próba stworzenia użytkownika.

W momencie pisania usługa **Harmonogram zadań** jest uruchamiana z **Nt AUTHORITY\SYSTEM**.

Mając **wygenerowany złośliwy Dll** (_w moim przypadku użyłem x64 rev shell i otrzymałem powłokę, ale defender ją zabił, ponieważ pochodziła z msfvenom_), zapisz go w zapisywalnym System Path pod nazwą **WptsExtensions.dll** i **zrestartuj** komputer (lub zrestartuj usługę lub zrób cokolwiek, aby ponownie uruchomić dotkniętą usługę/program).

Gdy usługa zostanie ponownie uruchomiona, **dll powinien zostać załadowany i wykonany** (możesz **ponownie użyć** sztuczki **procmon**, aby sprawdzić, czy **biblioteka została załadowana zgodnie z oczekiwaniami**).

{{#include ../../../banners/hacktricks-training.md}}
