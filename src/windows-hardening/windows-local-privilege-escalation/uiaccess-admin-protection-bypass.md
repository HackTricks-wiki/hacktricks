# Ominięcia Admin Protection za pomocą UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Przegląd
- Windows AppInfo udostępnia `RAiLaunchAdminProcess` do uruchamiania procesów UIAccess (przeznaczonych do ułatwień dostępu). UIAccess omija większość filtrowania komunikatów User Interface Privilege Isolation (UIPI), dzięki czemu oprogramowanie ułatwień dostępu może sterować interfejsem użytkownika o wyższym poziomie integralności.
- Bezpośrednie włączenie UIAccess wymaga `NtSetInformationToken(TokenUIAccess)` z **SeTcbPrivilege**, dlatego procesy o niskich uprawnieniach korzystają z usługi. Usługa wykonuje trzy kontrole pliku binarnego przed ustawieniem UIAccess:
- Osadzony manifest zawiera `uiAccess="true"`.
- Plik jest podpisany dowolnym certyfikatem zaufanym przez magazyn główny Local Machine (bez wymogu EKU/Microsoft).
- Plik znajduje się w ścieżce dostępnej wyłącznie administratorom na dysku systemowym (np. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), z wyłączeniem określonych podścieżek z możliwością zapisu.
- `RAiLaunchAdminProcess` nie wyświetla monitu o zgodę podczas uruchamiania UIAccess (w przeciwnym razie narzędzia ułatwień dostępu nie mogłyby sterować monitem).<sup>[[1]](#references)</sup>

## Kształtowanie tokena i poziomy integralności
- Jeśli kontrole zakończą się powodzeniem, AppInfo **kopiuje token procesu wywołującego**, włącza UIAccess i podnosi poziom integralności (IL):
- Ograniczony użytkownik administratora (użytkownik należy do grupy Administrators, ale działa z filtrowanym tokenem) ➜ **High IL**.
- Użytkownik niebędący administratorem ➜ IL zwiększony o **+16 poziomów**, maksymalnie do poziomu **High** (System IL nigdy nie jest przypisywany).
- Jeśli token procesu wywołującego ma już UIAccess, IL pozostaje bez zmian.
- Sztuczka „ratchet”: proces UIAccess może wyłączyć UIAccess dla samego siebie, uruchomić się ponownie za pomocą `RAiLaunchAdminProcess` i uzyskać kolejne zwiększenie IL o +16 poziomów. Przejście z Medium➜High wymaga 255 ponownych uruchomień (jest głośne, ale działa).<sup>[[1]](#references)</sup>

## Dlaczego UIAccess umożliwia obejście Admin Protection
- UIAccess pozwala procesowi o niższym IL wysyłać komunikaty okien do okien o wyższym IL, omijając filtry UIPI. Przy **równym IL** klasyczne mechanizmy UI, takie jak `SetWindowsHookEx`, **pozwalają na wstrzykiwanie kodu/ładowanie DLL** do dowolnego procesu posiadającego okno (w tym do **okien tylko komunikatowych**, używanych przez COM).
- Admin Protection uruchamia proces UIAccess w kontekście tożsamości **ograniczonego użytkownika**, ale z **High IL**, bez wyświetlania monitu. Gdy w tym procesie UIAccess o wysokim IL zostanie uruchomiony dowolny kod, atakujący może wstrzykiwać kod do innych procesów o wysokim IL na pulpicie (nawet należących do innych użytkowników), łamiąc zamierzoną separację.<sup>[[1]](#references)</sup>

## Prymityw uchwytu procesu na podstawie HWND (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- W Windows 10 1803+ API przeniesiono do Win32k (`NtUserGetWindowProcessHandle`), a następnie umożliwiono otwieranie uchwytu procesu przy użyciu dostarczonego przez wywołującego `DesiredAccess`. Ścieżka jądra korzysta z `ObOpenObjectByPointer(..., KernelMode, ...)`, co omija standardowe kontrole dostępu w trybie użytkownika.<sup>[[2]](#references)</sup>
- Wymagania w praktyce: okno docelowe musi znajdować się na tym samym pulpicie, a kontrole UIPI muszą zakończyć się powodzeniem. Historycznie proces z UIAccess mógł ominąć niepowodzenie UIPI i nadal uzyskać uchwyt w trybie jądra (naprawiono w CVE-2023-41772).
- Skutek: uchwyt okna staje się **zdolnością** do uzyskania potężnego uchwytu procesu (zwykle `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`), którego wywołujący normalnie nie mógłby otworzyć. Umożliwia to dostęp między sandboxami i może przełamać granice Protected Process / PPL, jeśli proces docelowy udostępnia dowolne okno (w tym okna tylko komunikatowe).
- Praktyczny przebieg nadużycia: wylicz lub znajdź HWND-y (np. za pomocą `EnumWindows`/`FindWindowEx`), ustal PID właściciela (`GetWindowThreadProcessId`), wywołaj `GetProcessHandleFromHwnd`, a następnie użyj zwróconego uchwytu do odczytu/zapisu pamięci lub zastosowania prymitywów przejęcia wykonania kodu.
- Zachowanie po poprawce: UIAccess nie zapewnia już otwierania w trybie jądra w przypadku niepowodzenia UIPI, a dozwolone prawa dostępu ograniczono do starszego zestawu hooków; Windows 11 24H2 dodaje kontrole ochrony procesów oraz bezpieczniejsze ścieżki sterowane flagami funkcji. Wyłączenie UIPI w całym systemie (`EnforceUIPI=0`) osłabia te zabezpieczenia.<sup>[[2]](#references)</sup>

## Słabości walidacji bezpiecznych katalogów (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo rozwiązuje dostarczoną ścieżkę za pomocą `GetFinalPathNameByHandle`, a następnie stosuje **sprawdzanie ciągów znaków pod kątem dozwolonych i zablokowanych wartości** względem hardcoded roots/exclusions. Z tego uproszczonego mechanizmu walidacji wynika kilka klas obejść:
- **Nazwane strumienie katalogów**: Wykluczone katalogi z możliwością zapisu (np. `C:\Windows\tracing`) można obejść za pomocą nazwanego strumienia samego katalogu, np. `C:\Windows\tracing:file.exe`. Sprawdzanie ciągów widzi `C:\Windows\` i pomija wykluczoną podścieżkę.
- **Plik/katalog z możliwością zapisu wewnątrz dozwolonego katalogu głównego**: `CreateProcessAsUser` **nie wymaga rozszerzenia `.exe`**. Nadpisanie dowolnego pliku z możliwością zapisu znajdującego się w dozwolonym katalogu głównym za pomocą payloadu wykonywalnego działa; podobnie skopiowanie podpisanego pliku EXE z `uiAccess="true"` do dowolnego podkatalogu z możliwością zapisu (np. pozostałości po aktualizacji, takie jak `Tasks_Migrated`, jeśli występują) pozwala przejść kontrolę bezpiecznej ścieżki.
- **MSIX w `C:\Program Files\WindowsApps` (naprawione)**: Użytkownicy niebędący administratorami mogli instalować podpisane pakiety MSIX, które trafiały do `WindowsApps`, a ścieżka ta nie była wykluczona. Umieszczenie pliku binarnego UIAccess w pakiecie MSIX, a następnie uruchomienie go za pomocą `RAiLaunchAdminProcess`, skutkowało uruchomieniem **procesu UIAccess o wysokim IL bez monitu**. Microsoft ograniczył ten problem, wykluczając tę ścieżkę; sama ograniczona funkcja MSIX `uiAccess` już wymaga instalacji przez administratora.<sup>[[1]](#references)</sup>

## Przebieg ataku (High IL bez monitu)
1. Uzyskaj/zbuduj **podpisany plik binarny UIAccess** (manifest `uiAccess="true"`).
2. Umieść go w miejscu akceptowanym przez allowlistę AppInfo (lub wykorzystaj opisany powyżej przypadek brzegowy walidacji ścieżki/artefakt z możliwością zapisu).
3. Wywołaj `RAiLaunchAdminProcess`, aby **bezgłośnie** uruchomić plik z UIAccess i podwyższonym IL.
4. Z uzyskanego dostępu na poziomie High IL zaatakuj inny proces o wysokim IL na pulpicie, używając **hooków okien/wstrzykiwania DLL** lub innych prymitywów dostępnych przy równym IL, aby w pełni przejąć kontekst administratora.<sup>[[1]](#references)</sup>

## Wyliczanie potencjalnych ścieżek z możliwością zapisu
Uruchom helper PowerShell, aby znaleźć obiekty z możliwością zapisu/nadpisania wewnątrz nominalnie bezpiecznych katalogów głównych z perspektywy wybranego tokena:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Uruchom jako Administrator, aby uzyskać szerszy wgląd; ustaw `-ProcessId` na proces o niskich uprawnieniach, aby odwzorować dostęp tego tokena.
- Ręcznie odfiltruj znane niedozwolone podkatalogi przed użyciem kandydatów z `RAiLaunchAdminProcess`.

## Powiązane

LPE poprzez propagację rejestru dostępności Secure Desktop (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Odnośniki

- [1] [Obejście ochrony Administratora poprzez nadużycie UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [Dogłębna analiza GetProcessHandleFromHwnd (GPHFH)](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
