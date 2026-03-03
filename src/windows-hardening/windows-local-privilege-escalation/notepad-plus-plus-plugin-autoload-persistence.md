# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ itapakia moja kwa moja kila plugin DLL inayopatikana katika folda zake ndogo za `plugins` wakati wa kuanzisha. Kudondoa plugin yenye madhara ndani ya chochote cha **writable Notepad++ installation** kunatoa utekelezaji wa code ndani ya `notepad++.exe` kila wakati mhariri anapoanza, jambo ambalo linaweza kutumiwa kwa **persistence**, kwa siri kwa **initial execution**, au kama **in-process loader** ikiwa mhariri ataendeshwa elevated.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (kwa kawaida inahitaji admin kuandika).
- Writable options for low-privileged operators:
- Tumia the **portable Notepad++ build** katika folda ambayo mtumiaji anaweza kuandika.
- Nakili `C:\Program Files\Notepad++` hadi njia inayodhibitiwa na mtumiaji (km, `%LOCALAPPDATA%\npp\`) kisha endesha `notepad++.exe` kutoka huko.
- Kila plugin inapokea subfolder yake chini ya `plugins` na inapakiwa kiotomatiki wakati wa kuanzisha; vitu vya menyu vinaonekana chini ya **Plugins**.

## Plugin load points (execution primitives)
Notepad++ inatarajia **exported functions** maalum. Hizi zote zinaitwa wakati wa uanzishaji, zikitoa nyuso mbalimbali za utekelezaji:
- **`DllMain`** — inaendesha mara moja kwenye DLL load (pointi ya kwanza ya utekelezaji).
- **`setInfo(NppData)`** — inaitwa mara moja wakati wa load kutoa Notepad++ handles; sehemu ya kawaida ya kusajili vitu vya menyu.
- **`getName()`** — inarudisha jina la plugin linaloonyeshwa kwenye menyu.
- **`getFuncsArray(int *nbF)`** — inarudisha amri za menyu; hata kama tupu, inaitwa wakati wa startup.
- **`beNotified(SCNotification*)`** — inapokea matukio ya editor (file open/change, matukio ya UI) kwa vichocheo vinavyoendelea.
- **`messageProc(UINT, WPARAM, LPARAM)`** — mshughulikiaji wa message, muhimu kwa kubadilishana data kubwa.
- **`isUnicode()`** — bendera ya compatibility inayokaguliwa wakati wa load.

Wengi wa exports yanaweza kutekelezwa kama **stubs**; utekelezaji unaweza kutokea kutoka `DllMain` au callback yoyote hapo juu wakati wa autoload.

## Minimal malicious plugin skeleton
Kusanya (compile) DLL yenye exports zinazotarajiwa na uiweke katika `plugins\\MyNewPlugin\\MyNewPlugin.dll` chini ya folda ya Notepad++ inayoweza kuandikwa:
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
2. Unda saraka ndogo ya plugin chini ya `plugins` na uweke DLL ndani.
3. Restart Notepad++; DLL inapakiwa kiotomatiki, ikiendesha `DllMain` na callbacks zifuatazo.

## Reflective loader plugin pattern
Plugin iliyoharibika inaweza kugeuza Notepad++ kuwa **reflective DLL loader**:
- Onyesha UI/menu ndogo (mfano, "LoadDLL").
- Kubali **njia ya faili** au **URL** ili kupata payload DLL.
- Reflectively map DLL ndani ya mchakato wa sasa na uitumie exported entry point (mfano, loader function ndani ya DLL iliyopakuliwa).
- Faida: tumia tena mchakato la GUI linaloonekana kuwa salama badala ya kuanzisha loader mpya; payload inachukua uadilifu wa `notepad++.exe` (ikijumuisha muktadha wa ruhusa za juu).
- Madhara: kuacha **unsigned plugin DLL** kwenye diski ni noisy; fikiria piggybacking kwenye plugins za kuaminika zilizopo ikiwa zipo.

## Vidokezo vya utambuzi na kuimarisha usalama
- Zuia au fuatilia **writes to Notepad++ plugin directories** (ikiwa ni pamoja na portable copies katika user profiles); wezesha controlled folder access au application allowlisting.
- Toa tahadhari kuhusu **new unsigned DLLs** chini ya `plugins` na isiyo ya kawaida **child processes/network activity** kutoka `notepad++.exe`.
- Lazimisha ufungaji wa plugin kupitia **Plugins Admin** tu, na zuilia utekelezaji wa portable copies kutoka njia zisizoaminika.

## Marejeleo
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
