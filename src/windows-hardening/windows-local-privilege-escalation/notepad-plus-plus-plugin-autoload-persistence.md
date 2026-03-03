# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ będzie **autoload every plugin DLL found under its `plugins` subfolders** przy uruchomieniu. Upuszczenie złośliwego pluginu do dowolnej **writable Notepad++ installation** daje wykonanie kodu wewnątrz `notepad++.exe` za każdym razem przy starcie edytora, co można wykorzystać do **persistence**, ukrytego **initial execution**, lub jako **in-process loader**, jeśli edytor zostanie uruchomiony z podwyższonymi uprawnieniami.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (zwykle wymaga uprawnień admina do zapisu).
- Writable options for low-privileged operators:
- Use the **portable Notepad++ build** in a user-writable folder.
- Copy `C:\Program Files\Notepad++` to a user-controlled path (e.g., `%LOCALAPPDATA%\npp\`) and run `notepad++.exe` from there.
- Each plugin gets its own subfolder under `plugins` and is loaded automatically at startup; menu entries appear under **Plugins**.

## Plugin load points (execution primitives)
Notepad++ oczekuje konkretnych **exported functions**. Wszystkie są wywoływane podczas inicjalizacji, dając wielokrotne powierzchnie wykonawcze:
- **`DllMain`** — uruchamia się natychmiast po załadowaniu DLL (pierwszy punkt wykonania).
- **`setInfo(NppData)`** — wywoływana raz przy ładowaniu w celu dostarczenia uchwytów Notepad++; typowe miejsce do rejestracji pozycji menu.
- **`getName()`** — zwraca nazwę pluginu wyświetlaną w menu.
- **`getFuncsArray(int *nbF)`** — zwraca polecenia menu; nawet jeśli pusta, jest wywoływana podczas uruchamiania.
- **`beNotified(SCNotification*)`** — odbiera zdarzenia edytora (otwarcie/zmiana pliku, zdarzenia UI) jako triggery dla dalszych działań.
- **`messageProc(UINT, WPARAM, LPARAM)`** — handler wiadomości, przydatny do wymiany większych danych.
- **`isUnicode()`** — flaga kompatybilności sprawdzana przy ładowaniu.

Większość eksportów może być zaimplementowana jako **stubs**; wykonanie może nastąpić z `DllMain` lub z dowolnego powyższego callbacku podczas autoload.

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
1. Skompiluj DLL (Visual Studio/MinGW).
2. Utwórz podfolder pluginu w `plugins` i umieść w nim DLL.
3. Zrestartuj Notepad++; DLL jest ładowany automatycznie, wykonując `DllMain` i kolejne wywołania zwrotne.

## Reflective loader plugin pattern
A weaponized plugin can turn Notepad++ into a **reflective DLL loader**:
- Udostępnij minimalny interfejs/menu (np. "LoadDLL").
- Akceptuj **ścieżkę pliku** lub **URL** do pobrania payload DLL.
- Reflectively map the DLL into the current process and invoke an exported entry point (e.g., a loader function inside the fetched DLL).
- Korzyść: ponowne użycie pozornie nieszkodliwego procesu GUI zamiast uruchamiania nowego loadera; payload dziedziczy poziom integralności `notepad++.exe` (w tym konteksty z podwyższonymi uprawnieniami).
- Kompromisy: zapisanie na dysku **unsigned plugin DLL** jest głośne; rozważ piggybacking na istniejących zaufanych pluginach, jeśli są dostępne.

## Detection and hardening notes
- Blokuj lub monitoruj **writes to Notepad++ plugin directories** (w tym przenośne kopie w profilach użytkowników); włącz Controlled Folder Access lub application allowlisting.
- Generuj alerty dla **new unsigned DLLs** w `plugins` oraz nietypowej **child processes/network activity** pochodzącej z `notepad++.exe`.
- Wymuszaj instalację pluginów wyłącznie przez **Plugins Admin**, oraz ogranicz uruchamianie przenośnych kopii z nieznanych ścieżek.

## References
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
