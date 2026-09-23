# Writable System PATH + DLL Hijacking Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

Jeśli możesz **zapisywać w katalogu znajdującym się w systemowym `PATH`** (nie tylko w `PATH` użytkownika), możesz być w stanie **eskalować uprawnienia** w systemie.

Można to wykorzystać poprzez **DLL hijacking**, gdy usługa lub proces działający z większymi uprawnieniami próbuje załadować bibliotekę DLL, która nie istnieje we wcześniejszych lokalizacjach wyszukiwania, a następnie przeszukuje zapisywalny katalog systemowego `PATH`.

Zapisywalny wpis Machine `PATH` jest tylko **prymitywem**, a nie dowodem wykonania kodu. W przypadku aplikacji niespakietowanej korzystającej ze standardowej kolejności wyszukiwania `PATH` jest sprawdzany dopiero po przekierowaniu, API sets, SxS, liście załadowanych modułów, KnownDLLs, katalogach aplikacji i Windows oraz katalogu bieżącym. Pełna ścieżka lub polityka `LOAD_LIBRARY_SEARCH_*` / `SetDefaultDllDirectories` może całkowicie wykluczyć `PATH`.<sup>[[4]](#references)</sup>

Więcej informacji o **DLL hijacking** znajdziesz tutaj:

{{#ref}}
./
{{#endref}}

## Privesc z DLL Hijacking

### Znajdowanie brakującej biblioteki DLL

Najpierw **zidentyfikuj proces** działający z **większymi uprawnieniami**, który próbuje **załadować bibliotekę DLL z zapisywalnego katalogu systemowego `PATH`**.

Pamiętaj, że ta technika zależy od wpisu Machine/System PATH, a nie tylko od **PATH użytkownika**. Dlatego przed poświęceniem czasu na Procmon warto wyliczyć wpisy **Machine PATH** i sprawdzić, które z nich są zapisywalne:<sup>[[1]](#references)</sup>
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
Tekst ACL może wprowadzać w błąd, ponieważ na wynik wpływają członkostwo w grupach, wpisy ACE typu deny oraz dziedziczone uprawnienia. W autoryzowanym teście sonda create/delete sprawdza **efektywny dostęp bieżącego tokenu** (jest inwazyjna i może generować alerty):<sup>[[1]](#references)</sup>
```powershell
$dirs = [Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } |
Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $dirs) {
if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
$probe = Join-Path $dir ('.ht-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force; "[WRITABLE] $dir" }
catch { }
}
```
### Potwierdź efektywną wartość `PATH` celu

Machine `PATH` odczytany z rejestru to dane konfiguracyjne; loader używa bloku środowiska **procesu docelowego**. Każdy proces posiada własny blok środowiska, a proces potomny zwykle dziedziczy kopię bloku środowiska procesu nadrzędnego. W rezultacie długo działająca usługa może zachować starszą wartość, a usługa uruchomiona z niestandardowym środowiskiem może różnić się od wartości widocznej w Twojej powłoce. Traktuj zaobserwowane w Procmon zapytanie dotyczące dokładnego katalogu przez docelowy PID jako źródło prawdy; po zmianie `PATH` w labie uruchom ponownie odpowiednie drzewo procesów lub wykonaj reboot, zanim stwierdzisz, że lookup nie występuje.<sup>[[5]](#references)</sup>

Problem w tych przypadkach polega na tym, że te procesy prawdopodobnie już działają. Aby zidentyfikować DLL, które usługi próbują załadować, ale nie potrafią tego zrobić, uruchom Procmon tak wcześnie, jak to możliwe (przed uruchomieniem procesów), a następnie:

> [!WARNING]
> Dodanie katalogu zapisywalnego przez użytkownika do Machine `PATH` **tworzy podatny warunek**. Wykonuj to wyłącznie w izolowanej research VM, aby sprawdzić, które uprzywilejowane procesy odwołują się do `PATH`; na testowanym hoście monitoruj istniejący zapisywalny wpis bez zmieniania konfiguracji systemu.<sup>[[1]](#references)</sup>

- **Utwórz** folder `C:\privesc_hijacking` i dodaj ścieżkę `C:\privesc_hijacking` do **System Path env variable**. Możesz zrobić to **ręcznie** lub za pomocą **PS**:
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
- Następnie wykonaj **restart**. Po ponownym uruchomieniu komputera **`procmon`** zacznie jak najszybciej **rejestrować** zdarzenia.
- Po **uruchomieniu systemu Windows uruchom ponownie `procmon`**. Program poinformuje, że działał w tle, i **zapyta, czy chcesz zapisać** zdarzenia w pliku. Wybierz **tak** i **zapisz zdarzenia w pliku**.
- **Po** wygenerowaniu **pliku** zamknij otwarte okno **`procmon`** i **otwórz plik zdarzeń**.
- Dodaj te **filtry**, aby znaleźć wszystkie biblioteki DLL, które **proces próbował załadować** z zapisywalnego folderu System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging jest wymagane tylko w przypadku usług, które uruchamiają się zbyt wcześnie**, aby można było je obserwować w inny sposób. Jeśli możesz **wywołać docelową usługę/program na żądanie** (na przykład przez interakcję z jego interfejsem COM, ponowne uruchomienie usługi lub ponowne uruchomienie zaplanowanego zadania), zwykle szybciej jest użyć normalnego przechwytywania w Procmon z filtrami takimi jak **`Path contains .dll`**, **`Result is NAME NOT FOUND`** oraz **`Path begins with <writable_machine_path>`**.

### Pominięte biblioteki DLL

Uruchamiając to na darmowej **wirtualnej maszynie (vmware) z systemem Windows 11**, uzyskałem następujące wyniki:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

W tym przypadku zignoruj wyniki `.exe`. Zapytania dotyczące brakujących bibliotek DLL pochodziły z:

| Usługa                         | Dll                | Wiersz CMD                                                           |
| ------------------------------ | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)      | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL      | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                            | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Poniższy przykład wykorzystuje technikę opisaną w tym artykule na temat [**nadużywania `WptsExtensions.dll` w celu eskalacji uprawnień**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Inne warte analizy kandydatury

`WptsExtensions.dll` jest dobrym przykładem, ale nie jest jedyną powtarzającą się **phantom DLL**, która pojawia się w uprzywilejowanych usługach. Współczesne reguły huntingu i publiczne katalogi hijack nadal śledzą nazwy takie jak:<sup>[[2]](#references)</sup>

| Usługa / scenariusz | Brakująca biblioteka DLL | Uwagi |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Klasyczna kandydatura **SYSTEM** w systemach klienckich. Dobre rozwiązanie, gdy zapisywalny katalog znajduje się w **Machine PATH**, a usługa sprawdza obecność biblioteki DLL podczas uruchamiania. |
| NetMan w Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interesujące w **edycjach serwerowych**, ponieważ usługa działa jako **SYSTEM** i w niektórych buildach może być **wywołana na żądanie przez zwykłego użytkownika**, co czyni ją lepszą od przypadków wymagających ponownego uruchomienia systemu. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Zwykle najpierw zapewnia **`NT AUTHORITY\LOCAL SERVICE`**. Często jest to wystarczające, ponieważ token ma **`SeImpersonatePrivilege`**, więc można połączyć tę technikę z [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Traktuj te nazwy jako **wskazówki do analizy**, a nie gwarantowane możliwości: zależą one od **SKU/builda**, a Microsoft może zmieniać ich działanie między wydaniami. Najważniejszy wniosek jest taki, aby szukać **brakujących bibliotek DLL w uprzywilejowanych usługach, które przeszukują Machine PATH**, szczególnie jeśli usługę można **ponownie wywołać bez restartu systemu**.

### Zweryfikuj kandydaturę przed jej wykorzystaniem

Samo zdarzenie `NAME NOT FOUND` nie wystarcza. Przed umieszczeniem payloadu zweryfikuj cały łańcuch:<sup>[[1]](#references)[[4]](#references)</sup>

1. Zdarzenie należy do oczekiwanego **PID, wiersza poleceń, konta usługi i poziomu integralności**, a brakująca ścieżka jest dokładnie zapisywalnym katalogiem Machine `PATH`.
2. Dla tej samej nazwy bazowej DLL żaden wcześniejszy katalog nie zwraca `SUCCESS`, a moduł nie jest dostępny na liście załadowanych modułów, w KnownDLLs, poprzez redirection ani przez manifest SxS.
3. Zapytanie powtarza się, gdy użytkownik o niskich uprawnieniach wywołuje zamierzony trigger. Wyszukiwanie wykonywane wyłącznie podczas uruchamiania systemu jest możliwe do wykorzystania, ale operacyjnie znacznie gorsze od wyszukiwania wywoływanego na żądanie.
4. Architektura payloadu odpowiada procesowi. Jeśli aplikacja później rozwiązuje eksporty, użyj proxy dla legalnej biblioteki DLL lub wyeksportuj oczekiwane symbole; zobacz [Tworzenie i kompilowanie bibliotek DLL](README.md#creating-and-compiling-dlls).
5. Najpierw użyj nieszkodliwej canary DLL, która zapisuje PID, tożsamość i znacznik czasu. W Procmon wymagaj pomyślnego zdarzenia **`Load Image`** z podłożonej ścieżki, zamiast zakładać, że wcześniejsze sprawdzenie pliku spowodowało wykonanie.

### Exploitation

Aby **eskalować uprawnienia**, przejmij **`WptsExtensions.dll`**. Gdy znana jest **ścieżka** i **nazwa**, wygeneruj złośliwą bibliotekę DLL.

Możesz [**spróbować użyć dowolnego z tych przykładów**](README.md#creating-and-compiling-dlls). Możesz uruchomić payloady takie jak: uzyskać rev shell, dodać użytkownika, wykonać beacon...

> [!WARNING]
> Pamiętaj, że **nie wszystkie usługi działają** jako **`NT AUTHORITY\SYSTEM`**. Niektóre działają jako **`NT AUTHORITY\LOCAL SERVICE`**, które ma **mniej uprawnień**, więc nadużycie jednej z tych usług może nie pozwolić na utworzenie nowego użytkownika.\
> To konto ma jednak prawo użytkownika **`SeImpersonatePrivilege`**, dlatego możesz użyć [**Potato suite do eskalacji uprawnień**](../roguepotato-and-printspoofer.md). W takim przypadku reverse shell jest lepszym rozwiązaniem niż próba utworzenia użytkownika.

Usługa **Task Scheduler** zwykle działa jako **`NT AUTHORITY\SYSTEM`**, ale zweryfikuj rzeczywiste wdrożenie i nie wyciągaj wniosków o tożsamości wykonawczej wyłącznie na podstawie nazwy usługi:<sup>[[3]](#references)</sup>
```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```
Po **wygenerowaniu złośliwej biblioteki DLL** (_w moim przypadku użyłem x64 rev shell i otrzymałem shell, ale defender go zablokował, ponieważ pochodził z msfvenom_), zapisz ją w zapisywalnej ścieżce System Path pod nazwą **WptsExtensions.dll** i **uruchom ponownie** komputer (albo uruchom ponownie usługę lub wykonaj dowolną czynność wymaganą do ponownego uruchomienia zaatakowanej usługi/programu).

Po ponownym uruchomieniu usługi **DLL powinna zostać załadowana i wykonana** (możesz **ponownie użyć** sztuczki z **Procmon**, aby sprawdzić, czy **biblioteka została załadowana zgodnie z oczekiwaniami**).

> [!NOTE]
> Zaplanuj czyszczenie przed uruchomieniem payloadu. Usługa może utrzymywać mapowanie DLL i blokować plik do momentu zatrzymania; w przypadku `WptsExtensions.dll` zatrzymanie Task Scheduler wymaga podwyższonych uprawnień. Po uzyskaniu docelowego kontekstu bezpiecznie zatrzymaj cel, usuń payload i przywróć wszelkie zmiany `PATH` używane wyłącznie w laboratorium.<sup>[[1]](#references)</sup>

### Remediacja / wykrywanie

Usuń słabe uprawnienia zapisu ze wszystkich katalogów Machine `PATH` i usuń nieaktualne wpisy. Deweloperzy powinni ładować zaufane biblioteki przy użyciu pełnej ścieżki albo ograniczyć rozwiązywanie ścieżek za pomocą `SetDefaultDllDirectories` / flag wyszukiwania `LoadLibraryEx`. Obrońcy mogą korelować zmiany w Machine `PATH` z uprzywilejowanymi procesami ładującymi DLL z niesystemowych katalogów zapisywalnych przez użytkowników.<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [Przejmowanie DLL w Windows — miejmy nadzieję, że wyjaśnione](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Podejrzana DLL załadowana w celu utrzymania dostępu lub eskalacji uprawnień](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – eskalacja uprawnień w Windows](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Kolejność wyszukiwania biblioteki dynamicznego linkowania](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Zmienne środowiskowe](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
