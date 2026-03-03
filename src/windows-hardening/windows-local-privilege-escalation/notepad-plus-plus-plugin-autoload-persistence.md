# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ itaingia kwa otomatiki kila DLL ya plugin inayopatikana ndani ya subfolders zake za `plugins` wakati wa kuanzisha. Kuweka plugin hatari katika **Notepad++ installation yoyote inayoweza kuandikwa** kunatoa code execution ndani ya `notepad++.exe` kila wakati mhariri anapoanzishwa, jambo ambalo linaweza kutumiwa kwa **persistence**, stealthy **initial execution**, au kama **in-process loader** ikiwa mhariri ataanzishwa elevated.

## Mahali pa plugin zinazoweza kuandikwa
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (kwa kawaida inahitaji admin kuandika).
- Chaguzi zinazoweza kuandikwa kwa watumiaji wenye ruhusa ndogo:
- Tumia the **portable Notepad++ build** katika folda inayoweza kuandikwa na mtumiaji.
- Nakili `C:\Program Files\Notepad++` hadi njia inayodhibitiwa na mtumiaji (kwa mfano, `%LOCALAPPDATA%\npp\`) na endesha `notepad++.exe` kutoka huko.
- Kila plugin inapata saraka yake ndogo chini ya `plugins` na inapakiwa moja kwa moja wakati wa startup; machaguo ya menyu yanaonekana chini ya **Plugins**.

## Plugin load points (execution primitives)
Notepad++ inatarajia kazi maalum zilizotangazwa (**exported functions**). Hizi zote huitwa wakati wa initialization, zikitoa substrate nyingi za utekelezaji:
- **`DllMain`** — inaendeshwa mara moja baada ya DLL kupakiwa (sehemu ya kwanza ya utekelezaji).
- **`setInfo(NppData)`** — huitwa mara moja kwenye load kutoa handles za Notepad++; nafasi ya kawaida ya kusajili vitu vya menyu.
- **`getName()`** — inarudisha jina la plugin linaloonyeshwa kwenye menyu.
- **`getFuncsArray(int *nbF)`** — inarudisha amri za menyu; hata ikiwa ni tupu, huitwa wakati wa startup.
- **`beNotified(SCNotification*)`** — hupokea matukio ya mhariri (ufunguzi/mabadiliko ya faili, matukio ya UI) kwa kuzusha triggers za kuendelea.
- **`messageProc(UINT, WPARAM, LPARAM)`** — handler ya ujumbe, inayofaa kwa kubadilishana data kubwa.
- **`isUnicode()`** — flag ya compatibility inayokaguliwa wakati wa load.

Marejeo mengi yanaweza kutekelezwa kama **stubs**; utekelezaji unaweza kutokea kutoka `DllMain` au callback yoyote iliyo hapo juu wakati wa autoload.

## Minimal malicious plugin skeleton
Compile DLL yenye exports zinazotarajiwa na uiweke katika `plugins\\MyNewPlugin\\MyNewPlugin.dll` chini ya folda ya Notepad++ inayoweza kuandikwa:
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
2. Unda saraka ndogo ya plugin chini ya `plugins` na uweke DLL ndani.
3. Anzisha tena Notepad++; DLL itapakiwa kiotomatiki, ikitekeleza `DllMain` na subsequent callbacks.

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
