# Omijanie Admin Protection przez UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Przegląd
- Windows AppInfo udostępnia `RAiLaunchAdminProcess` do uruchamiania procesów UIAccess (przeznaczonych dla ułatwień dostępu). UIAccess omija większość filtrowania komunikatów User Interface Privilege Isolation (UIPI), dzięki czemu oprogramowanie ułatwień dostępu może sterować interfejsem o wyższym IL.
- Włączenie UIAccess bezpośrednio wymaga wywołania `NtSetInformationToken(TokenUIAccess)` z **SeTcbPrivilege**, więc wywołujący o niskich uprawnieniach polegają na tym serwisie. Serwis wykonuje trzy kontrole docelowego binarium przed ustawieniem UIAccess:
- Wbudowany manifest zawiera `uiAccess="true"`.
- Podpisany przez dowolny certyfikat zaufany przez magazyn root Local Machine (bez wymogu EKU/Microsoft).
- Zlokalizowany w ścieżce dostępnej tylko dla administratorów na dysku systemowym (np. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, z wyłączeniem określonych zapisywalnych podścieżek).
- `RAiLaunchAdminProcess` nie wyświetla monitów o zgodę przy uruchomieniach UIAccess (w przeciwnym razie narzędzia ułatwień dostępu nie mogłyby sterować monitami).

## Kształtowanie tokena i poziomy integralności
- Jeśli kontrole zakończą się pomyślnie, AppInfo **kopiuje token wywołującego**, włącza UIAccess i podnosi poziom integralności (IL):
- Ograniczony administrator (użytkownik należy do Administrators, ale działa w filtrze) ➜ **High IL**.
- Użytkownik niebędący administratorem ➜ IL zwiększany o **+16 poziomów** do maksymalnego poziomu **High** (System IL nigdy nie jest przydzielany).
- Jeśli token wywołującego już ma UIAccess, IL pozostaje niezmieniony.
- Sztuczka „Ratchet”: proces UIAccess może wyłączyć UIAccess dla siebie, ponownie uruchomić się przez `RAiLaunchAdminProcess` i uzyskać kolejne +16 IL. Przejście z Medium➜High wymaga 255 ponownych uruchomień (głośne, ale działa).

## Dlaczego UIAccess umożliwia obejście Admin Protection
- UIAccess pozwala procesowi o niższym IL wysyłać komunikaty okien do okien o wyższym IL (omijając filtry UIPI). Przy **równym IL** klasyczne mechanizmy UI jak `SetWindowsHookEx` **umożliwiają wstrzykiwanie kodu/ładowanie DLL** do dowolnego procesu, który posiada okno (włącznie z **message-only windows** używanymi przez COM).
- Admin Protection uruchamia proces UIAccess pod tożsamością **ograniczonego użytkownika**, ale na poziomie **High IL**, bez powiadomień. Gdy dowolny kod zostanie uruchomiony w takim procesie High-IL UIAccess, atakujący może wstrzykiwać do innych procesów o High-IL na pulpicie (nawet należących do innych użytkowników), łamiąc zamierzoną separację.

## Słabości walidacji bezpiecznych katalogów (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo rozwiązuje podaną ścieżkę za pomocą `GetFinalPathNameByHandle`, a następnie stosuje **kontrole łańcucha dozwól/zabroń** w stosunku do zakodowanych korzeni/wyłączeń. Z tej prostej walidacji wynikają różne klasy obejść:
- **Directory named streams**: Wykluczone zapisywalne katalogi (np. `C:\Windows\tracing`) można obejść za pomocą strumienia nazwanego na samym katalogu, np. `C:\Windows\tracing:file.exe`. Kontrole łańcuchów widzą `C:\Windows\` i pomijają wykluczoną podścieżkę.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` **nie wymaga rozszerzenia `.exe`**. Nadpisanie dowolnego pliku zapisywalnego pod dozwolonym korzeniem payloadem wykonywalnym działa, albo skopiowanie podpisanego EXE z `uiAccess="true"` do dowolnego zapisywalnego podkatalogu (np. pozostałości update takie jak `Tasks_Migrated`, jeśli istnieją) pozwala przejść kontrolę bezpiecznej ścieżki.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Użytkownicy niebędący adminami mogli instalować podpisane pakiety MSIX, które trafiały do `WindowsApps`, które nie było wyłączone. Zapakowanie binarium UIAccess wewnątrz MSIX, a następnie uruchomienie go przez `RAiLaunchAdminProcess` skutkowało **procesem UIAccess o High-IL bez monitów**. Microsoft złagodził problem, wykluczając tę ścieżkę; sama zdolność MSIX ograniczona przez `uiAccess` już wymaga instalacji przez administratora.

## Przebieg ataku (High IL bez monitu)
1. Uzyskać/zbudować **podpisane binarium UIAccess** (manifest `uiAccess="true"`).
2. Umieścić je tam, gdzie allowlist AppInfo je akceptuje (lub wykorzystać opisany powyżej przypadek brzegowy walidacji ścieżki/artfakt zapisywalny).
3. Wywołać `RAiLaunchAdminProcess`, aby uruchomić je **bez powiadomień** z UIAccess i podniesionym IL.
4. Z tego punktu zaczepienia o High-IL zaatakować inny proces o High-IL na pulpicie używając **window hooks/DLL injection** lub innych prymitywów działających przy tym samym IL, aby w pełni przejąć kontekst administratora.

## Enumeracja kandydatów na zapisywalne ścieżki
Uruchom pomocnika PowerShell, aby odnaleźć obiekty zapisywalne/nadpisywalne wewnątrz nominalnie bezpiecznych korzeni z perspektywy wybranego tokena:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Uruchom jako Administrator, aby uzyskać szerszą widoczność; ustaw `-ProcessId` na proces o niskich uprawnieniach, aby odzwierciedlić dostęp tego tokena.
- Ręcznie odfiltruj, aby wykluczyć znane niedozwolone podkatalogi przed użyciem kandydatów z `RAiLaunchAdminProcess`.

## Referencje
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
