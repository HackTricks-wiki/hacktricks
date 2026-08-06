# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ sal **elke plugin DLL outolaai wat onder sy `plugins`-subvouers gevind word** wanneer dit begin. Deur 'n kwaadwillige plugin in enige **skryfbare Notepad++-installasie** te plaas, kry jy kode-uitvoering binne `notepad++.exe` elke keer wanneer die editor begin, wat misbruik kan word vir **persistence**, onopvallende **initial execution**, of as 'n **in-process loader** indien die editor met verhoogde regte begin word.<sup>[[1]](#references)</sup>

Sedert **Notepad++ 7.6+** is die verwagte handmatige installasie-uitleg **een subvouer per plugin** (`plugins\<PluginName>\<PluginName>.dll`). In **portable mode** (die teenwoordigheid van `doLocalConf.xml` langs `notepad++.exe`) bly die hele toepassingsboom plaaslik tot daardie gids, wat gekopieerde/admin tool bundles dikwels in 'n maklik skryfbare execution surface vir gebruikers omskep.<sup>[[2]](#references)</sup>

## Skryfbare plugin-liggings

- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (vereis gewoonlik admin om te skryf).<sup>[[1]](#references)</sup>
- Skryfbare opsies vir low-privileged operators:<sup>[[1]](#references)</sup>
- Gebruik die **portable Notepad++ build** in 'n gebruikerskryfbare vouer.
- Kopieer `C:\Program Files\Notepad++` na 'n gebruikerbeheerde pad (byvoorbeeld `%LOCALAPPDATA%\npp\`) en run `notepad++.exe` vanaf daar.
- Soek na **admin tool bundles**, onttrekte zip-kopieë, of help-desk toolkits wat reeds `doLocalConf.xml` bevat en buite `Program Files` geleë is.
- Elke plugin kry sy eie subvouer onder `plugins` en word outomaties tydens startup gelaai; menu-inskrywings verskyn onder **Plugins**.<sup>[[2]](#references)</sup>

Vinnige triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin-laaipunte (execution primitives)
Notepad++ verwag spesifieke **exported functions**. Hulle word almal tydens initialisering geroep, wat verskeie execution surfaces bied:<sup>[[1]](#references)</sup>
- **`DllMain`** — loop onmiddellik wanneer die DLL gelaai word (eerste execution point).
- **`setInfo(NppData)`** — word een keer tydens load geroep om Notepad++-handles te verskaf; ’n tipiese plek om menu-items te registreer.
- **`getName()`** — gee die plugin-naam terug wat in die menu vertoon word.
- **`getFuncsArray(int *nbF)`** — gee menu-opdragte terug; selfs al is dit leeg, word dit tydens startup geroep.
- **`beNotified(SCNotification*)`** — ontvang Notepad++ / Scintilla-events (nuttig om payloads uit te stel totdat ’n gebruikeraksie of editor-event plaasvind).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, nuttig vir groter data-uitruilings.
- **`isUnicode()`** — compatibility flag wat tydens load nagegaan word.

Die meeste exports kan as **stubs** geïmplementeer word; execution kan vanaf `DllMain` of enige callback hierbo tydens autoload plaasvind.

## Minimale malicious plugin-skeleton
Compileer ’n DLL met die verwagte exports en plaas dit in `plugins\\MyNewPlugin\\MyNewPlugin.dll` onder ’n skryfbare Notepad++-folder:<sup>[[1]](#references)</sup>
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
2. Skep die plugin-subgids onder `plugins` en plaas die DLL daarin.
3. Herbegin Notepad++; die DLL word outomaties gelaai, wat `DllMain` en daaropvolgende callbacks uitvoer.

## Lae-geraas-snellerpatroon via `beNotified`
Vir OPSEC behoort baie payloads **nie vanaf `DllMain` geaktiveer te word nie**. ’n Stilller patroon is om die plugin skoon te laat laai en dit dan eers uit te voer ná ’n realistiese editor-gebeurtenis, soos **startup voltooi**, **buffer-aktivering** of die **eerste getikte karakter**.
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
Dit pas beter by publieke offensive research as 'n raserige `DllMain` beacon: die DLL word steeds by opstart outomaties gelaai, maar die kwaadwillige aksie word uitgestel totdat Notepad++ werklik in gebruik is.

## Die gebruik van die plugin-konfigurasiegids as sekondêre storage
Notepad++ stel `NPPM_GETPLUGINSCONFIGDIR` bloot, wat die **huidige gebruiker se plugin-konfigurasiegids** terugstuur.<sup>[[3]](#references)</sup> 'n Kwaadwillige plugin kan dit gebruik om die DLL op die skyf minimaal te hou, terwyl dit geënkripteerde konfigurasie, staged payloads of tasking files stoor in 'n pad wat met normale plugin-state saamsmelt.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operasioneel is dit nuttig wanneer jy die volgende wil hê:
- ’n klein autoloaded bootstrap DLL;
- per-user tasking sonder om weer aan die hoofplugin-binêre lêer te raak;
- om die **autoload trigger** van die swaarder second stage te skei.

## Reflective loader plugin pattern
’n Weaponized plugin kan Notepad++ in ’n **reflective DLL loader** omskep:<sup>[[1]](#references)</sup>
- Bied ’n minimale UI/menu-inskrywing aan (bv. "LoadDLL").
- Aanvaar ’n **file path** of **URL** om ’n payload DLL te fetch.
- Map die DLL reflectively in die huidige proses en roep ’n exported entry point aan (bv. ’n loader-funksie binne die fetched DLL).
- Voordeel: hergebruik ’n GUI-proses wat benigne lyk in plaas daarvan om ’n nuwe loader te spawn; die payload erf die integriteit van `notepad++.exe` (insluitend elevated contexts).
- Nadele: om ’n **unsigned plugin DLL** na skyf te drop, is opvallend; ’n praktiese variasie is om die autoloaded plugin slegs as ’n stub te gebruik en die werklike implant elders geënkripteer/staged te hou.

## Detection and hardening notes
- Blokkeer of monitor **writes to Notepad++ plugin directories** (insluitend portable copies in user profiles); enable controlled folder access of application allowlisting.
- Alert op **new unsigned DLLs** onder `plugins`, changes to portable Notepad++ trees, en unusual **child processes/network activity** vanaf `notepad++.exe`.
- Baseline legitimate plugins en ondersoek enige nuwe DLL wat die normale Notepad++ plugin-interface export, maar ook shells, PowerShell of network beacons spawn.
- Enforce plugin installation via **Plugins Admin** only, en restrict execution of portable copies from untrusted paths.

## Verwysings

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
