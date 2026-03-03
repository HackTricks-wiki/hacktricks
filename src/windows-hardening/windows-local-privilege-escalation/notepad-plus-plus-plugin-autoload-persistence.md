# Notepad++ Plugin Autoload — utrwalenie i wykonanie

{{#include ../../banners/hacktricks-training.md}}

Notepad++ podczas uruchamiania **automatycznie załaduje każdą bibliotekę DLL pluginu znalezioną w podfolderach `plugins`**. Wrzucenie złośliwego pluginu do dowolnej **zapisywalnej instalacji Notepad++** umożliwia wykonanie kodu w procesie `notepad++.exe` przy każdym starcie edytora — można to wykorzystać do **persistence**, ukrytego **initial execution**, lub jako **in-process loader**, jeśli edytor jest uruchomiony z podwyższonymi uprawnieniami.

## Writable plugin locations
- Instalacja standardowa: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (zwykle wymaga uprawnień admina do zapisu).
- Opcje zapisu dla operatorów o niskich uprawnieniach:
- Użyj **portable Notepad++ build** w katalogu zapisywalnym przez użytkownika.
- Skopiuj `C:\Program Files\Notepad++` do ścieżki kontrolowanej przez użytkownika (np. `%LOCALAPPDATA%\npp\`) i uruchom stamtąd `notepad++.exe`.
- Każdy plugin ma własny podfolder w `plugins` i jest ładowany automatycznie przy starcie; pozycje w menu pojawiają się pod **Plugins**.

## Plugin load points (execution primitives)
Notepad++ oczekuje określonych **exported functions**. Wszystkie są wywoływane podczas inicjalizacji, dając wiele punktów wykonania:
- **`DllMain`** — uruchamia się natychmiast po załadowaniu DLL (pierwszy punkt wykonania).
- **`setInfo(NppData)`** — wywoływane raz przy ładowaniu, przekazuje uchwyty Notepad++; typowe miejsce do rejestracji pozycji menu.
- **`getName()`** — zwraca nazwę pluginu wyświetlaną w menu.
- **`getFuncsArray(int *nbF)`** — zwraca komendy menu; nawet jeśli pusta, jest wywoływana podczas startu.
- **`beNotified(SCNotification*)`** — otrzymuje zdarzenia edytora (otwarcie/zmiana pliku, zdarzenia UI) do wywołań na bieżąco.
- **`messageProc(UINT, WPARAM, LPARAM)`** — handler wiadomości, przydatny do większych wymian danych.
- **`isUnicode()`** — flaga kompatybilności sprawdzana przy ładowaniu.

Większość eksportów można zaimplementować jako **stubs**; wykonanie może nastąpić z `DllMain` lub z dowolnego callbacku powyżej podczas autoload.

## Minimal malicious plugin skeleton
Compile a DLL with the expected exports and place it in `plugins\\MyNewPlugin\\MyNewPlugin.dll` under a writable Notepad++ folder:
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
2. Utwórz podfolder plugin pod `plugins` i umieść w nim DLL.
3. Uruchom ponownie Notepad++; DLL jest ładowany automatycznie, wykonując `DllMain` i kolejne callbacki.

## Reflective loader plugin pattern
A weaponized plugin can turn Notepad++ into a **reflective DLL loader**:
- Present a minimal UI/menu entry (e.g., "LoadDLL").
- Accept a **file path** or **URL** to fetch a payload DLL.
- Reflectively map the DLL into the current process and invoke an exported entry point (e.g., a loader function inside the fetched DLL).
- Benefit: reuse a benign-looking GUI process instead of spawning a new loader; payload inherits the integrity of `notepad++.exe` (including elevated contexts).
- Trade-offs: dropping an **unsigned plugin DLL** to disk is noisy; consider piggybacking on existing trusted plugins if present.

## Detection and hardening notes
- Block or monitor **writes to Notepad++ plugin directories** (including portable copies in user profiles); enable controlled folder access or application allowlisting.
- Alert on **new unsigned DLLs** under `plugins` and unusual **child processes/network activity** from `notepad++.exe`.
- Enforce plugin installation via **Plugins Admin** only, and restrict execution of portable copies from untrusted paths.

## References
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
