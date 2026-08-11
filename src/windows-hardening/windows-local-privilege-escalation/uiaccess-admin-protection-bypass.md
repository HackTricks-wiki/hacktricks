# Bypasses ochrony administratora przez UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Overview
- Windows AppInfo udostępnia wewnętrzną ścieżkę `RAiLaunchAdminProcess`, używaną do uruchamiania aplikacji UIAccess dla ułatwień dostępu. UIAccess umożliwia wybranym aplikacjom interakcję poprzez granice User Interface Privilege Isolation (UIPI); nie jest to ogólny bypass każdej granicy bezpieczeństwa procesów.<sup>[[1]](#references)[[3]](#references)</sup>
- Bezpośrednie włączenie UIAccess wymaga `NtSetInformationToken(TokenUIAccess)` z **SeTcbPrivilege**, dlatego low-priv callers korzystają z usługi. Usługa wykonuje trzy kontrole docelowego pliku binarnego przed ustawieniem UIAccess:
- Osadzony manifest zawiera `uiAccess="true"`.
- Plik jest podpisany dowolnym certyfikatem zaufanym przez magazyn główny Local Machine (bez wymogu EKU/Microsoft).
- Plik znajduje się w ścieżce dostępnej wyłącznie dla administratorów na dysku systemowym (np. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), z wyłączeniem określonych podścieżek z możliwością zapisu.
- `RAiLaunchAdminProcess` nie wyświetla promptu zgody dla uruchomień UIAccess (w przeciwnym razie narzędzia ułatwień dostępu nie mogłyby obsługiwać tego promptu).<sup>[[1]](#references)</sup>

## Kształtowanie tokenu i poziomy integralności
- Jeśli kontrole zakończą się powodzeniem, AppInfo **kopiuje token wywołującego**, włącza UIAccess i podnosi Integrity Level (IL):
- Ograniczony użytkownik administratora (użytkownik należy do grupy Administrators, ale działa z filtrowanym tokenem) ➜ **High IL**.
- Użytkownik niebędący administratorem ➜ IL zwiększony o **+16 poziomów**, maksymalnie do poziomu **High** (System IL nigdy nie jest nadawany).
- Jeśli token wywołującego ma już UIAccess, IL pozostaje bez zmian.
- Trick „ratchet”: proces UIAccess może wyłączyć UIAccess dla samego siebie, uruchomić się ponownie przez `RAiLaunchAdminProcess` i uzyskać kolejne zwiększenie IL o +16. Przejście z Medium➜High wymaga 255 ponownych uruchomień (jest głośne, ale działa).<sup>[[1]](#references)</sup>

## Dlaczego UIAccess umożliwia obejście Admin Protection
- UIAccess pozwala procesowi o niższym IL wysyłać komunikaty okien do okien o wyższym IL (z pominięciem filtrów UIPI). Przy **równym IL** klasyczne mechanizmy UI, takie jak `SetWindowsHookEx`, **umożliwiają code injection/ładowanie DLL** do dowolnego procesu posiadającego okno (w tym **message-only windows** używanych przez COM).
- Admin Protection uruchamia proces UIAccess z tożsamością **ograniczonego użytkownika**, ale z **High IL**, bez promptu. Gdy dowolny kod wykona się wewnątrz tego procesu UIAccess z High IL, attacker może wykonać injection do innych procesów z High IL na pulpicie (nawet należących do innych użytkowników), łamiąc zamierzoną separację.<sup>[[1]](#references)</sup>

## Prymityw uzyskiwania uchwytu procesu na podstawie HWND (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- W Windows 10 1803+ API przeniesiono do Win32k (`NtUserGetWindowProcessHandle`) i może ono otwierać uchwyt procesu przy użyciu `DesiredAccess` podanego przez wywołującego. Ścieżka jądra używa `ObOpenObjectByPointer(..., KernelMode, ...)`, co omija standardowe user-mode access checks.<sup>[[2]](#references)</sup>
- Wymagania wstępne w praktyce: docelowe okno musi znajdować się na tym samym pulpicie, a kontrole UIPI muszą zakończyć się powodzeniem. Historycznie caller z UIAccess mógł ominąć błąd UIPI i nadal uzyskać uchwyt w trybie jądra (naprawiono w CVE-2023-41772).
- Historyczny wpływ: uchwyt okna stawał się **capability** umożliwiającym dostęp do procesu, taki jak `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE` lub `PROCESS_VM_OPERATION`, którego caller normalnie nie mógł uzyskać. Przed udokumentowanymi poprawkami umożliwiało to przekraczanie granic sandboxa i protected-process, gdy cel udostępniał okno, w tym message-only window.<sup>[[2]](#references)</sup>
- Praktyczny flow abuse: wylicz lub znajdź HWND (np. `EnumWindows`/`FindWindowEx`), ustal PID właściciela (`GetWindowThreadProcessId`), wywołaj `GetProcessHandleFromHwnd`, a następnie użyj zwróconego uchwytu do odczytu/zapisu pamięci lub prymitywów przejęcia wykonania kodu.
- Zachowanie po poprawkach: UIAccess nie zapewnia już otwierania w trybie jądra po nieudanej kontroli UIPI, a dozwolone prawa dostępu są ograniczone do legacy hook set; Windows 11 24H2 dodaje kontrole ochrony procesów oraz bezpieczniejsze ścieżki sterowane feature flagami. Wyłączenie UIPI w całym systemie (`EnforceUIPI=0`) osłabia te zabezpieczenia.<sup>[[2]](#references)</sup>

## Słabości walidacji secure-directory (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo rozwiązuje podaną ścieżkę za pomocą `GetFinalPathNameByHandle`, a następnie stosuje **stringowe kontrole allow/deny** względem hardcoded roots/exclusions. Z tego uproszczonego mechanizmu walidacji wynika kilka klas bypassów:
- **Nazwane strumienie katalogów**: wykluczone katalogi z możliwością zapisu (np. `C:\Windows\tracing`) można ominąć za pomocą named stream na samym katalogu, np. `C:\Windows\tracing:file.exe`. Kontrole stringów widzą `C:\Windows\` i pomijają wykluczoną podścieżkę.
- **Zapisywalny plik/katalog wewnątrz dozwolonego root**: `CreateProcessAsUser` **nie wymaga rozszerzenia `.exe`**. Nadpisanie dowolnego zapisywalnego pliku w dozwolonym root za pomocą executable payload zadziała; podobnie skopiowanie podpisanego EXE z `uiAccess="true"` do dowolnego zapisywalnego podkatalogu (np. pozostałości po aktualizacjach, takie jak `Tasks_Migrated`, gdy są obecne) pozwala przejść secure-path check.
- **MSIX w `C:\Program Files\WindowsApps` (naprawione)**: non-admins mogli instalować podpisane pakiety MSIX, które trafiały do `WindowsApps`, a ścieżka ta nie była wykluczona. Umieszczenie pliku binarnego UIAccess w MSIX, a następnie uruchomienie go przez `RAiLaunchAdminProcess` dawało **proces UIAccess z High IL uruchomiony bez promptu**. Microsoft ograniczył ten problem, wykluczając tę ścieżkę; sama ograniczona capability MSIX `uiAccess` już wymaga instalacji przez administratora.<sup>[[1]](#references)</sup>

## Workflow ataku (High IL bez promptu)
1. Uzyskaj/zbuduj **podpisany plik binarny UIAccess** (manifest `uiAccess="true"`). W realistycznym assessment używaj materiału zaufania i ścieżek jawnie autoryzowanych dla labu; nie dodawaj certyfikatu attackera do magazynu głównego Local Machine na produkcyjnej maszynie.
2. Umieść go w miejscu akceptowanym przez allowlist AppInfo (lub wykorzystaj edge case walidacji ścieżki / zapisywalny artefakt opisany powyżej).
3. Wywołaj `RAiLaunchAdminProcess`, aby **bez promptu** uruchomić proces z UIAccess i podwyższonym IL.
4. Z uzyskanego footholda z High IL zaatakuj inny proces z High IL na pulpicie, używając **window hooks/DLL injection** lub innych prymitywów przy równym IL, aby w pełni przejąć kontekst administratora.<sup>[[1]](#references)</sup>

## Wyliczanie potencjalnych zapisywalnych ścieżek
Uruchom helper PowerShell, aby znaleźć zapisywalne/nadpisywalne obiekty wewnątrz nominalnie bezpiecznych rootów z perspektywy wybranego tokenu:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Uruchom jako Administrator, aby uzyskać szerszy wgląd; ustaw `-ProcessId` na proces o niskich uprawnieniach, aby odwzorować dostęp tego tokenu.
- Ręcznie odfiltruj znane niedozwolone podkatalogi przed użyciem kandydatów z `RAiLaunchAdminProcess`.

## Powiązane

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## References

- [1] [Omijanie Administrator Protection przez nadużycie UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [Dogłębna analiza GetProcessHandleFromHwnd (GPHFH)](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [3] [Microsoft Learn — aplikacje UIAccess](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works#uiaccess-applications)
{{#include ../../banners/hacktricks-training.md}}
