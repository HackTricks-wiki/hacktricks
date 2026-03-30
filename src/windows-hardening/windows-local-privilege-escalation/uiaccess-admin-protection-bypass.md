# Omijanie Admin Protection za pomocą UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Przegląd
- Windows AppInfo udostępnia `RAiLaunchAdminProcess` do uruchamiania procesów UIAccess (przeznaczone dla oprogramowania ułatwień dostępu). UIAccess omija większość filtrowania wiadomości User Interface Privilege Isolation (UIPI), dzięki czemu oprogramowanie ułatwień dostępu może sterować UI o wyższym IL.
- Bezpośrednie włączenie UIAccess wymaga `NtSetInformationToken(TokenUIAccess)` z **SeTcbPrivilege**, więc niskoprzywilejowe wywołania polegają na serwisie. Serwis wykonuje trzy sprawdzenia na docelowym binarium przed ustawieniem UIAccess:
- Osadzony manifest zawiera `uiAccess="true"`.
- Podpisane jest przez dowolny certyfikat zaufany przez Local Machine root store (brak wymogu EKU/Microsoft).
- Zlokalizowane w ścieżce dostępnej tylko dla administratora na dysku systemowym (np. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, z wyłączeniem konkretnych podścieżek zapisywalnych).
- `RAiLaunchAdminProcess` nie wyświetla promptu zgody dla uruchomień UIAccess (w przeciwnym razie narzędzia ułatwień dostępu nie mogłyby sterować promptem).

## Kształtowanie tokenów i poziomy integralności
- Jeśli sprawdzenia zakończą się sukcesem, AppInfo **kopiuje token wywołującego**, włącza UIAccess i podwyższa Integrity Level (IL):
- Limited admin user (user jest w Administrators, ale działa filtrowany) ➜ **High IL**.
- Non-admin user ➜ IL zwiększane o **+16 poziomów** do maksymalnego pułapu **High** (System IL nigdy nie jest przypisywany).
- Jeśli token wywołującego już ma UIAccess, IL pozostaje bez zmian.
- Sztuczka „ratchet”: proces UIAccess może wyłączyć UIAccess na sobie, ponownie się uruchomić przez `RAiLaunchAdminProcess` i uzyskać kolejne +16 IL. Medium➜High wymaga 255 ponownych uruchomień (głośne, ale działa).

## Dlaczego UIAccess umożliwia obejście Admin Protection
- UIAccess pozwala procesowi o niższym IL wysyłać wiadomości okien do okien o wyższym IL (omijając filtry UIPI). Przy **równym IL**, klasyczne mechanizmy UI jak `SetWindowsHookEx` **pozwalają na wstrzyknięcie kodu/ładowanie DLL** do dowolnego procesu posiadającego okno (w tym **message-only windows** używanych przez COM).
- Admin Protection uruchamia proces UIAccess pod **tożsamością ograniczonego użytkownika**, ale na **High IL**, bez widocznego okna dialogowego. Gdy dowolny kod wykona się w tym procesie High-IL UIAccess, atakujący może wstrzykiwać do innych procesów High-IL na pulpicie (nawet należących do innych użytkowników), łamiąc zamierzoną separację.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Na Windows 10 1803+ API przeniesiono do Win32k (`NtUserGetWindowProcessHandle`) i może otworzyć handle procesu używając `DesiredAccess` podanego przez wywołującego. Ścieżka jądra używa `ObOpenObjectByPointer(..., KernelMode, ...)`, co omija normalne kontrole dostępu w trybie użytkownika.
- Warunki w praktyce: docelowe okno musi znajdować się na tym samym pulpicie, a sprawdzenia UIPI muszą przejść. Historycznie wywołujący z UIAccess mógł ominąć niepowodzenie UIPI i wciąż uzyskać handle w trybie jądra (załatane jako CVE-2023-41772).
- Skutek: uchwyt okna staje się **uprawnieniem** do uzyskania potężnego handle procesu (często `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`), którego wywołujący normalnie nie mógłby otworzyć. To umożliwia dostęp między sandboxami i może złamać granice Protected Process / PPL jeśli cel wystawia jakiekolwiek okno (wliczając message-only windows).
- Praktyczny przebieg nadużycia: enumeruj lub znajdź HWNDy (np. `EnumWindows`/`FindWindowEx`), rozwiąż PID właściciela (`GetWindowThreadProcessId`), wywołaj `GetProcessHandleFromHwnd`, a następnie użyj zwróconego handle do odczytu/zapisu pamięci lub do technik przejęcia kodu.
- Po naprawie: UIAccess nie daje już otwarć w trybie jądra przy niepowodzeniu UIPI, a dozwolone prawa dostępu są ograniczone do zestawu zgodnego z legacy hook; Windows 11 24H2 dodaje sprawdzenia ochrony procesu i feature-flagowane bezpieczniejsze ścieżki. Wyłączenie UIPI system-wide (`EnforceUIPI=0`) osłabia te zabezpieczenia.

## Słabości walidacji bezpiecznego katalogu (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo rozwiązuje dostarczoną ścieżkę przez `GetFinalPathNameByHandle`, a następnie stosuje **porównania ciągów allow/deny** względem hardcodowanych rootów/wykluczeń. Kilka klas obejść wynika z tej uproszczonej walidacji:
- **Directory named streams**: Wykluczone katalogi zapisywalne (np. `C:\Windows\tracing`) można obejść strumieniem nazwanym na samym katalogu, np. `C:\Windows\tracing:file.exe`. Porównania ciągów widzą `C:\Windows\` i nie wykrywają wykluczonej podścieżki.
- **Zapisalny plik/katalog wewnątrz dozwolonego roota**: `CreateProcessAsUser` **nie wymaga rozszerzenia `.exe`**. Nadpisanie dowolnego zapisywalnego pliku pod dozwolonym rootem payloadem wykonywalnym działa, lub skopiowanie podpisanego `uiAccess="true"` EXE do dowolnego zapisywalnego podkatalogu (np. pozostałości aktualizacji takie jak `Tasks_Migrated` gdy obecne) pozwala przejść check ścieżki bezpiecznej.
- **MSIX do `C:\Program Files\WindowsApps` (załatane)**: Nie-admini mogli instalować podpisane pakiety MSIX umieszczone w `WindowsApps`, które nie były wykluczone. Zapakowanie binarium UIAccess w MSIX i uruchomienie go przez `RAiLaunchAdminProcess` dawało **bezpromptowy proces UIAccess z High-IL**. Microsoft złagodził problem przez wyłączenie tej ścieżki; capability ograniczające `uiAccess` w MSIX wymagała już instalacji jako admin.

## Scenariusz ataku (High IL bez promptu)
1. Uzyskaj/zbuduj **podpisane binarium UIAccess** (manifest `uiAccess="true"`).
2. Umieść je tam, gdzie lista dozwolonych AppInfo je akceptuje (lub wykorzystaj edge case walidacji ścieżki/ zapisowalny artefakt jak wyżej).
3. Wywołaj `RAiLaunchAdminProcess`, aby uruchomić je **cicho** z UIAccess + podwyższonym IL.
4. Z tego footholda High-IL, zaatakuj inny proces High-IL na pulpicie używając **window hooks/DLL injection** lub innych prymitywów działających przy tym samym IL, aby w pełni przejąć kontekst administratora.

## Enumeracja kandydatów zapisywalnych ścieżek
Uruchom pomocnika PowerShell, aby odkryć zapisywalne/ nadpisywalne obiekty wewnątrz nominalnie bezpiecznych rootów z perspektywy wybranego tokenu:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Uruchom jako Administrator, aby mieć szerszą widoczność; ustaw `-ProcessId` na proces o niskich uprawnieniach, aby odwzorować dostęp tego tokena.
- Ręcznie przefiltruj, aby wykluczyć znane niedozwolone podkatalogi przed użyciem kandydatów z `RAiLaunchAdminProcess`.

## Powiązane

Propagacja rejestru dostępności Secure Desktop — LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Źródła
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
