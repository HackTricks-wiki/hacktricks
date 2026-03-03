# Omijanie Admin Protection przez UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Przegląd
- Windows AppInfo udostępnia `RAiLaunchAdminProcess` do uruchamiania procesów UIAccess (przeznaczone dla accessibility). UIAccess omija większość filtrowania komunikatów User Interface Privilege Isolation (UIPI), aby software accessibility mógł sterować UI o wyższym IL.
- Włączenie UIAccess bezpośrednio wymaga `NtSetInformationToken(TokenUIAccess)` z **SeTcbPrivilege**, więc wywołujący o niskich uprawnieniach polegają na serwisie. Serwis wykonuje trzy sprawdzenia względem docelowego binarium przed ustawieniem UIAccess:
- Osadzony manifest zawiera `uiAccess="true"`.
- Podpisany przez certyfikat zaufany przez Local Machine root store (bez wymogu EKU/Microsoft).
- Znajduje się w ścieżce dostępnej tylko dla administratora na dysku systemowym (np. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, z wyłączeniem konkretnych zapisywalnych podścieżek).
- `RAiLaunchAdminProcess` nie wyświetla consent prompt dla uruchomień UIAccess (w przeciwnym razie narzędzia accessibility nie mogłyby sterować monitami).

## Kształtowanie tokena i poziomy integralności
- Jeśli sprawdzenia zakończą się pomyślnie, AppInfo **kopiuje token wywołującego**, włącza UIAccess i podnosi Integrity Level (IL):
- Limited admin user (użytkownik jest w Administrators, ale uruchomiony jest w filtrze) ➜ **High IL**.
- Non-admin user ➜ IL zwiększony o **+16 poziomów** do maksymalnego ograniczenia **High** (System IL nigdy nie jest przypisywany).
- Jeśli token wywołującego już ma UIAccess, IL pozostaje niezmieniony.
- „Ratchet” trick: proces UIAccess może wyłączyć UIAccess u siebie, ponownie uruchomić się przez `RAiLaunchAdminProcess` i uzyskać kolejne zwiększenie IL o +16. Medium➜High wymaga 255 ponownych uruchomień (głośne, ale działa).

## Dlaczego UIAccess umożliwia ucieczkę z Admin Protection
- UIAccess pozwala procesowi o niższym IL wysyłać komunikaty okien do okien o wyższym IL (omijając filtry UIPI). Przy **równym IL**, klasyczne mechanizmy UI jak `SetWindowsHookEx` **pozwalają na wstrzykiwanie kodu/ładowanie DLL** do dowolnego procesu posiadającego okno (włączając **message-only windows** używane przez COM).
- Admin Protection uruchamia proces UIAccess pod tożsamością **limited user**, ale na **High IL**, bez widocznego powiadomienia. Gdy w tym High-IL procesie UIAccess zacznie działać dowolny kod, atakujący może wstrzyknąć do innych High-IL procesów na pulpicie (nawet należących do innych użytkowników), łamiąc zamierzony podział.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Na Windows 10 1803+ API przeniesiono do Win32k (`NtUserGetWindowProcessHandle`) i może otworzyć handle procesu przy użyciu `DesiredAccess` podanego przez wywołującego. Ścieżka jądra używa `ObOpenObjectByPointer(..., KernelMode, ...)`, co omija normalne sprawdzenia dostępu w trybie użytkownika.
- Warunki w praktyce: docelowe okno musi być na tym samym desktopie, a kontrole UIPI muszą przejść. Historycznie wywołujący z UIAccess mógł obejść błąd UIPI i nadal dostać kernel-mode handle (naprawione jako CVE-2023-41772).
- Skutki: handle okna staje się **capability** do uzyskania potężnego handle’a procesu (zwykle `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`), którego wywołujący normalnie nie mógłby otworzyć. To umożliwia dostęp między sandboxami i może złamać granice Protected Process / PPL, jeśli cel wystawia jakiekolwiek okno (włączając message-only windows).
- Praktyczny przebieg nadużycia: enumeruj lub zlokalizuj HWNDy (np. `EnumWindows`/`FindWindowEx`), rozwiąż PID właściciela (`GetWindowThreadProcessId`), wywołaj `GetProcessHandleFromHwnd`, a następnie użyj zwróconego handle’a do odczytu/zapisu pamięci lub prymitywów przejęcia kodu.
- Po poprawce: UIAccess nie daje już otwarć w kernel-mode przy niepowodzeniu UIPI, a dozwolone prawa dostępu są ograniczone do zestawu legacy hook; Windows 11 24H2 dodaje sprawdzenia ochrony procesu i feature-flagowane bezpieczniejsze ścieżki. Wyłączenie UIPI system-wide (`EnforceUIPI=0`) osłabia te zabezpieczenia.

## Słabości walidacji bezpiecznego katalogu (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo rozwiązuje podaną ścieżkę przez `GetFinalPathNameByHandle`, a następnie stosuje **sprawdzenia ciągów allow/deny** względem hardcodowanych korzeni/wyłączeń. Kilka klas obejść wynika z tej uproszczonej walidacji:
- **Directory named streams**: Wyłączone zapisywalne katalogi (np. `C:\Windows\tracing`) można obejść używając named stream na samym katalogu, np. `C:\Windows\tracing:file.exe`. Sprawdzenia ciągów widzą `C:\Windows\` i nie dostrzegają wyłączonej podścieżki.
- **Zapisowalny plik/katalog wewnątrz dozwolonego roota**: `CreateProcessAsUser` **nie wymaga rozszerzenia `.exe`**. Nadpisanie dowolnego zapisywalnego pliku pod dozwolonym rootem payloadem wykonywalnym działa, lub skopiowanie podpisanego EXE z `uiAccess="true"` do dowolnego zapisywalnego podkatalogu (np. pozostałości po aktualizacji jak `Tasks_Migrated` jeśli występują) pozwala mu przejść walidację bezpiecznej ścieżki.
- **MSIX do `C:\Program Files\WindowsApps` (naprawione)**: Non-admini mogli instalować podpisane pakiety MSIX trafiające do `WindowsApps`, które nie było wyłączone. Zapakowanie binarki UIAccess w MSIX i uruchomienie jej przez `RAiLaunchAdminProcess` skutkowało **bezmonitowym procesem UIAccess na High-IL**. Microsoft złagodził to, wyłączając tę ścieżkę; sama ograniczona capability `uiAccess` w MSIX już wymaga admin install.

## Przebieg ataku (High IL bez promptu)
1. Uzyskaj/zbuduj **podpisane binarium UIAccess** (manifest `uiAccess="true"`).
2. Umieść je tam, gdzie allowlista AppInfo je akceptuje (lub wykorzystaj błąd walidacji ścieżki/zapisowalny artefakt jak wyżej).
3. Wywołaj `RAiLaunchAdminProcess`, aby uruchomić je **cicho** z UIAccess + podwyższonym IL.
4. Z tej High-IL pozycji ataku, celuj w inny High-IL proces na pulpicie używając **window hooks/DLL injection** lub innych prymitywów same-IL, aby w pełni przejąć kontekst administratora.

## Enumeracja kandydatów na zapisywalne ścieżki
Uruchom PowerShell helper, aby odkryć zapisywalne/nadpisywalne obiekty wewnątrz nominalnie bezpiecznych rootów z perspektywy wybranego tokena:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Uruchom jako Administrator, aby uzyskać szerszą widoczność; ustaw `-ProcessId` na low-priv process, aby odzwierciedlić dostęp tego tokena.
- Filtruj ręcznie, aby wykluczyć znane niedozwolone podkatalogi przed użyciem kandydatów z `RAiLaunchAdminProcess`.

## Źródła
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
