# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ **hupakia kiotomatiki kila plugin DLL inayopatikana chini ya subfolders zake za `plugins`** inapowashwa. Kuweka plugin hasidi ndani ya **usakinishaji wowote wa Notepad++ unaoweza kuandikwa** hutoa code execution ndani ya `notepad++.exe` kila mara editor inapoanza, jambo linaloweza kutumiwa kwa **persistence**, **initial execution** isiyoonekana kwa urahisi, au kama **in-process loader** ikiwa editor imeanzishwa kwa viwango vya juu vya ruhusa.<sup>[[1]](#references)</sup>

Tangu **Notepad++ 7.6+**, mpangilio unaotarajiwa wa usakinishaji wa manually ni **subfolder moja kwa kila plugin** (`plugins\<PluginName>\<PluginName>.dll`). Katika **portable mode** (uwepo wa `doLocalConf.xml` karibu na `notepad++.exe`), mti mzima wa application hubaki ndani ya directory hiyo, jambo ambalo mara nyingi hugeuza bundles za tools zilizokopiwa/admin kuwa execution surface rahisi inayoweza kuandikwa na mtumiaji.<sup>[[2]](#references)</sup>

## Maeneo ya plugin yanayoweza kuandikwa

- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (kwa kawaida huhitaji admin ili kuandika).<sup>[[1]](#references)</sup>
- Chaguo zinazoweza kuandikwa na waendeshaji wenye low privilege:<sup>[[1]](#references)</sup>
- Tumia **portable Notepad++ build** ndani ya folder inayoweza kuandikwa na mtumiaji.
- Copy `C:\Program Files\Notepad++` hadi path inayodhibitiwa na mtumiaji (kwa mfano `%LOCALAPPDATA%\npp\`) na endesha `notepad++.exe` kutoka hapo.
- Tafuta **admin tool bundles**, nakala za zip zilizotolewa, au toolkits za help-desk ambazo tayari zina `doLocalConf.xml` na ziko nje ya `Program Files`.
- Kila plugin hupata subfolder yake chini ya `plugins` na hupakiwa kiotomatiki wakati wa startup; menu entries huonekana chini ya **Plugins**.<sup>[[2]](#references)</sup>

Triage ya haraka:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Sehemu za upakiaji wa Plugin (execution primitives)
Notepad++ hutegemea **exported functions** maalum. Zote huitwa wakati wa initialization, na kutoa sehemu nyingi za execution:<sup>[[1]](#references)</sup>
- **`DllMain`** — huendeshwa mara moja DLL inapopakiwa (sehemu ya kwanza ya execution).
- **`setInfo(NppData)`** — huitwa mara moja wakati wa upakiaji ili kutoa handles za Notepad++; kwa kawaida hapa ndipo menu items husajiliwa.
- **`getName()`** — hurejesha jina la plugin linaloonyeshwa kwenye menu.
- **`getFuncsArray(int *nbF)`** — hurejesha menu commands; hata ikiwa ni tupu, huitwa wakati wa startup.
- **`beNotified(SCNotification*)`** — hupokea matukio ya Notepad++ / Scintilla (yanafaa kuahirisha payloads hadi user action au editor event itokee).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, inayofaa kwa data exchanges kubwa.
- **`isUnicode()`** — compatibility flag inayokaguliwa wakati wa upakiaji.

Exports nyingi zinaweza kutekelezwa kama **stubs**; execution inaweza kutokea kutoka `DllMain` au callback yoyote hapo juu wakati wa autoload.

## Minimal malicious plugin skeleton
Compile DLL yenye exports zinazotarajiwa na uiweke katika `plugins\\MyNewPlugin\\MyNewPlugin.dll` chini ya writable Notepad++ folder:<sup>[[1]](#references)</sup>
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Tengeneza DLL (Visual Studio/MinGW).
2. Unda subfolder ya plugin chini ya `plugins` na uweke DLL ndani.
3. Anzisha upya Notepad++; DLL inapakiwa kiotomatiki, ikiendesha `DllMain` na callbacks zinazofuata.

## Pattern ya trigger yenye kelele ndogo kupitia `beNotified`
Kwa OPSEC, payload nyingi hazipaswi kuanzishwa kutoka `DllMain`. Pattern tulivu zaidi ni kuruhusu plugin ipakie kwa usahihi, kisha ianze kutekelezwa baada tu ya tukio halisi la editor kama vile **startup complete**, **buffer activation**, au **first typed character**.
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
Hii inalingana vizuri zaidi na utafiti wa umma wa offensive kuliko `DllMain` beacon yenye kelele: DLL bado inapakiwa kiotomatiki wakati wa startup, lakini kitendo hasidi hucheleweshwa hadi Notepad++ ionekane inatumika kweli.

## Kutumia plugin config directory kama secondary storage
Notepad++ hutoa `NPPM_GETPLUGINSCONFIGDIR`, ambayo hurudisha **plugin configuration directory ya mtumiaji wa sasa**.<sup>[[3]](#references)</sup> Plugin hasidi inaweza kutumia hii kuweka DLL iliyo kwenye disk ikiwa ndogo huku ikihifadhi config iliyosimbwa, payloads zilizowekwa hatua kwa hatua, au tasking files katika path inayofanana na hali ya kawaida ya plugin.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Kivitendo hii ni muhimu unapotaka:
- bootstrap DLL ndogo inayopakiwa kiotomatiki;
- tasking ya kila mtumiaji bila kugusa tena binary kuu ya plugin;
- kutenganisha **autoload trigger** na second stage nzito zaidi.

## Pattern ya Reflective loader plugin
Plugin yenye silaha inaweza kugeuza Notepad++ kuwa **reflective DLL loader**:<sup>[[1]](#references)</sup>
- Kutoa UI/menu entry ndogo (kwa mfano, "LoadDLL").
- Kukubali **file path** au **URL** ya kuchukua payload DLL.
- Kumap DLL kwa reflective method ndani ya process ya sasa na kuita entry point iliyiexport (kwa mfano, loader function ndani ya DLL iliyochukuliwa).
- Faida: kutumia tena process ya GUI inayoonekana kuwa halali badala ya kuanzisha loader mpya; payload hurithi integrity ya `notepad++.exe` (ikiwemo elevated contexts).
- Hasara: kuweka **unsigned plugin DLL** kwenye disk kunaonekana kwa urahisi; variation ya kivitendo ni kutumia plugin inayopakiwa kiotomatiki kama stub pekee na kuhifadhi implant halisi ikiwa encrypted/staged mahali pengine.

## Maelezo ya detection na hardening
- Zuia au fuatilia **writes to Notepad++ plugin directories** (ikiwemo portable copies zilizo kwenye user profiles); wezesha controlled folder access au application allowlisting.
- Toa alert kuhusu **new unsigned DLLs** zilizo chini ya `plugins`, mabadiliko kwenye portable Notepad++ trees, na **child processes/network activity** zisizo za kawaida kutoka kwa `notepad++.exe`.
- Tengeneza baseline ya plugins halali na chunguza DLL yoyote mpya inayotoa normal Notepad++ plugin interface lakini pia inaanzisha shells, PowerShell, au network beacons.
- Lazimisha usakinishaji wa plugin kupitia **Plugins Admin** pekee, na zuia execution ya portable copies kutoka untrusted paths.

## Marejeleo

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
