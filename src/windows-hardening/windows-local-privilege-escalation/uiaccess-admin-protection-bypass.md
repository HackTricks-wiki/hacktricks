# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Przegląd
- Windows AppInfo udostępnia `RAiLaunchAdminProcess` do uruchamiania procesów UIAccess (przeznaczone dla accessibility). UIAccess omija większość filtrowania komunikatów User Interface Privilege Isolation (UIPI), dzięki czemu oprogramowanie dostępności może sterować UI o wyższym IL.
- Włączenie UIAccess bezpośrednio wymaga `NtSetInformationToken(TokenUIAccess)` z **SeTcbPrivilege**, więc wywołujący o niskich uprawnieniach polegają na serwisie. Serwis wykonuje trzy sprawdzenia docelowego binarium przed ustawieniem UIAccess:
- Osadzony manifest zawiera `uiAccess="true"`.
- Podpisany przez dowolny certyfikat zaufany przez Local Machine root store (bez wymogu EKU/Microsoft).
- Znajduje się w ścieżce dostępnej tylko dla administratorów na dysku systemowym (np. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, z wyłączeniem konkretnych zapisywalnych podścieżek).
- `RAiLaunchAdminProcess` nie wyświetla monitów zgody dla uruchomień UIAccess (w przeciwnym razie narzędzia dostępności nie mogłyby obsłużyć monitu).

## Token shaping and integrity levels
- Jeśli sprawdzenia zakończą się powodzeniem, AppInfo **kopiuje token wywołującego**, włącza UIAccess i zwiększa Integrity Level (IL):
- Limited admin user (user is in Administrators but running filtered) ➜ **High IL**.
- Non-admin user ➜ IL zwiększane o **+16 poziomów** aż do limitu **High** (System IL nigdy nie jest przypisywany).
- Jeśli token wywołującego już posiada UIAccess, IL pozostaje bez zmian.
- Sztuczka „Ratchet”: proces UIAccess może wyłączyć UIAccess dla siebie, ponownie uruchomić się przez `RAiLaunchAdminProcess` i uzyskać kolejny przyrost o +16 IL. Medium➜High wymaga 255 ponownych uruchomień (głośne, ale działa).

## Dlaczego UIAccess umożliwia obejście Admin Protection
- UIAccess pozwala procesowi o niższym IL wysyłać komunikaty okien do okien o wyższym IL (omijając filtry UIPI). Przy **równym IL** klasyczne mechanizmy UI, takie jak `SetWindowsHookEx`, **pozwalają na wstrzykiwanie kodu/ładowanie DLL** do dowolnego procesu posiadającego okno (włączając w to **message-only windows** używane przez COM).
- Admin Protection uruchamia proces UIAccess pod tożsamością **ograniczonego użytkownika**, ale na **High IL**, cicho. Gdy dowolny kod zostanie wykonany w takim procesie High-IL UIAccess, atakujący może wstrzykiwać do innych procesów High-IL na pulpicie (nawet należących do innych użytkowników), łamiąc zamierzoną separację.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Na Windows 10 1803+ API zostało przeniesione do Win32k (`NtUserGetWindowProcessHandle`) i może otworzyć handle procesu używając `DesiredAccess` dostarczonego przez wywołującego. Ścieżka jądra używa `ObOpenObjectByPointer(..., KernelMode, ...)`, co omija normalne sprawdzenia dostępu w trybie użytkownika.
- Warunki w praktyce: docelowe okno musi być na tym samym pulpicie, a sprawdzenia UIPI muszą przejść. Historycznie wywołujący z UIAccess mógł ominąć błąd UIPI i mimo to uzyskać handle w trybie jądra (naprawione jako CVE-2023-41772).
- Skutki: uchwyt okna staje się **capability** do uzyskania potężnego handle procesu (zwykle `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`), którego wywołujący normalnie nie mógłby otworzyć. Umożliwia to dostęp między sandboxami i może złamać granice Protected Process / PPL jeśli cel udostępnia jakiekolwiek okno (włączając message-only windows).
- Praktyczny schemat nadużycia: enumeruj lub zlokalizuj HWND (np. `EnumWindows`/`FindWindowEx`), rozwiąż PID właściciela (`GetWindowThreadProcessId`), wywołaj `GetProcessHandleFromHwnd`, a następnie użyj zwróconego handle do odczytu/zapisu pamięci lub prymitywów przejęcia kodu.
- Po poprawce: UIAccess nie daje już otwarć w trybie jądra przy porażce UIPI, a dozwolone prawa dostępu ograniczono do zestawu legacy hook; Windows 11 24H2 dodaje sprawdzenia ochrony procesu i bezpieczniejsze ścieżki w feature-flagach. Wyłączenie UIPI globalnie (`EnforceUIPI=0`) osłabia te zabezpieczenia.

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo rozwiązuje podaną ścieżkę przez `GetFinalPathNameByHandle`, a następnie stosuje **porównania łańcuchowe allow/deny** względem zakodowanych korzeni/wykluczeń. Wiele klas obejść wynika z tej uproszczonej walidacji:
- **Directory named streams**: Wykluczone zapisywalne katalogi (np. `C:\Windows\tracing`) można obejść używając strumienia nazwanego na samym katalogu, np. `C:\Windows\tracing:file.exe`. Sprawdzenia łańcuchowe widzą `C:\Windows\` i pomijają wykluczoną podścieżkę.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` **nie wymaga rozszerzenia `.exe`**. Nadpisanie dowolnego zapisywalnego pliku w dozwolonym korzeniu z payloadem wykonywalnym działa, lub skopiowanie podpisanego EXE z `uiAccess="true"` do dowolnego zapisywalnego podkatalogu (np. pozostałości po aktualizacji takie jak `Tasks_Migrated`, gdy istnieją) pozwala mu przejść check secure-path.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins mogli instalować podpisane pakiety MSIX, które trafiały do `WindowsApps`, który nie był wykluczony. Zapakowanie binarki UIAccess w MSIX i uruchomienie jej przez `RAiLaunchAdminProcess` dawało **cichy proces UIAccess z High-IL**. Microsoft złagodził problem przez wyłączenie tej ścieżki; ograniczona capability `uiAccess` dla MSIX i tak wymagała instalacji przez admina.

## Attack workflow (High IL without a prompt)
1. Uzyskaj/zbuduj **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Umieść go tam, gdzie lista dozwolonych AppInfo go akceptuje (lub wykorzystaj edge case walidacji ścieżki/zapisywalny artefakt jak wyżej).
3. Wywołaj `RAiLaunchAdminProcess`, by uruchomić go **cicho** z UIAccess + podwyższonym IL.
4. Z tego High-IL punktu zaczepienia zaatakuj inny proces High-IL na pulpicie używając **window hooks/DLL injection** lub innych prymitywów tego samego IL, aby w pełni przejąć kontekst administratora.

## Enumerating candidate writable paths
Uruchom pomocnika PowerShell, aby odkryć zapisywalne/nadpisywalne obiekty wewnątrz nominalnie bezpiecznych korzeni z perspektywy wybranego tokena:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Uruchom jako Administrator dla szerszej widoczności; ustaw `-ProcessId` na low-priv process, aby odwzorować dostęp tego tokena.
- Filtruj ręcznie, aby wykluczyć znane niedozwolone podkatalogi przed użyciem kandydatów z `RAiLaunchAdminProcess`.

## References
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
