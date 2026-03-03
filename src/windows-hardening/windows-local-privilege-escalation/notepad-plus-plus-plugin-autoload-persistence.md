# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ sal by opstart **elke plugin DLL wat onder sy `plugins`-subvouers gevind word outomaties laai**. Deur 'n kwaadwillige plugin in enige **skryfbare Notepad++ installasie** te plaas, kry jy code execution binne `notepad++.exe` elke keer as die redigeerder begin, wat misbruik kan word vir **persistensie**, sluipende **aanvangsuitvoering**, of as 'n **in-proses loader** indien die redigeerder verhoogde regte het.

## Writable plugin locations
- Standaard installasie: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (gewoonlik vereis admin om te skryf).
- Skryfbare opsies vir laag-geprivilegieerde gebruikers:
- Gebruik die **portable Notepad++ build** in 'n gebruiker-skryfbare vouer.
- Kopieer `C:\Program Files\Notepad++` na 'n gebruiker-beheerde pad (bv. `%LOCALAPPDATA%\npp\`) en hardloop `notepad++.exe` daarvandaan.
- Elke plugin kry sy eie submap onder `plugins` en word outomaties by opstart gelaai; menupunte verskyn onder **Plugins**.

## Plugin load points (execution primitives)
Notepad++ verwag spesifieke **exported functions**. Hierdie word almal tydens inisialisering aangeroep, wat verskeie uitvoeringsoppervlakke bied:
- **`DllMain`** — hardloop onmiddellik by DLL-laai (eerste uitvoeringspunt).
- **`setInfo(NppData)`** — een keer aangeroep by laai om Notepad++ handvatsels te verskaf; tipiese plek om menupunte te registreer.
- **`getName()`** — keer die plugin-naam terug wat in die menu gewys word.
- **`getFuncsArray(int *nbF)`** — gee menubevels terug; selfs al leeg, word dit tydens opstart aangeroep.
- **`beNotified(SCNotification*)`** — ontvang redigeerdergebeurtenisse (lêer open/wysig, UI-gebeurtenisse) vir voortdurende triggers.
- **`messageProc(UINT, WPARAM, LPARAM)`** — boodskaphandelaar, nuttig vir groter data-uitruilings.
- **`isUnicode()`** — verenigbaarheidsvlag wat by laai nagegaan word.

Die meeste exports kan as **stubs** geïmplementeer word; uitvoering kan plaasvind vanuit `DllMain` of enige terugroeppunt hierbo tydens die outomatiese laai.

## Minimal malicious plugin skeleton
Kompileer 'n DLL met die verwagte exports en plaas dit in `plugins\\MyNewPlugin\\MyNewPlugin.dll` onder 'n skryfbare Notepad++ gids:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Bou die DLL (Visual Studio/MinGW).
2. Skep die plugin-submap onder `plugins` en plaas die DLL daarin.
3. Herbegin Notepad++; die DLL word outomaties gelaai en voer `DllMain` en daaropvolgende callbacks uit.

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
