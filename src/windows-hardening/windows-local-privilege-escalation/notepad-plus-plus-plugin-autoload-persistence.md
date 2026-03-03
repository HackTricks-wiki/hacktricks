# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ लॉन्च पर अपने `plugins` उपफ़ोल्डरों के अंतर्गत मिलने वाली हर plugin DLL को **autoload** करेगा। किसी भी **writable Notepad++ installation** में एक malicious plugin डालने से एडिटर हर बार शुरू होने पर `notepad++.exe` के अंदर code execution मिलती है, जिसे **persistence**, stealthy **initial execution**, या यदि एडिटर elevated लॉन्च किया गया हो तो एक **in-process loader** के रूप में दुरुपयोग किया जा सकता है।

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (आमतौर पर लिखने के लिए admin की आवश्यकता होती है).
- Writable options for low-privileged operators:
- उपयोगकर्ता-लिखने योग्य फ़ोल्डर में **portable Notepad++ build** का उपयोग करें।
- `C:\Program Files\Notepad++` को user-controlled path (उदा., `%LOCALAPPDATA%\npp\`) में कॉपी करें और वहां से `notepad++.exe` चलाएँ।
- प्रत्येक plugin को `plugins` के अंतर्गत अपना सबफ़ोल्डर मिलता है और यह स्टार्टअप पर स्वतः लोड हो जाता है; मेनू एंट्रीज़ **Plugins** के तहत दिखाई देती हैं।

## Plugin load points (execution primitives)
Notepad++ विशिष्ट **exported functions** की उम्मीद करता है। ये सभी initialization के दौरान कॉल होती हैं, जिससे कई execution surfaces मिलते हैं:
- **`DllMain`** — DLL load पर तुरंत चलती है (first execution point).
- **`setInfo(NppData)`** — load पर एक बार कॉल की जाती है ताकि Notepad++ handles प्रदान किए जा सकें; आमतौर पर मेनू आइटम रजिस्टर करने की जगह।
- **`getName()`** — मेनू में दिखने वाला plugin नाम लौटाता है।
- **`getFuncsArray(int *nbF)`** — मेनू कमांड लौटाता है; खाली होने पर भी यह startup के दौरान कॉल होती है।
- **`beNotified(SCNotification*)`** — ongoing triggers के लिए editor events (file open/change, UI events) प्राप्त करता है।
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, बड़े डेटा एक्सचेंज के लिए उपयोगी।
- **`isUnicode()`** — compatibility flag जो load पर चेक की जाती है।

Most exports को **stubs** के रूप में लागू किया जा सकता है; execution `DllMain` या ऊपर दिए किसी भी callback से autoload के दौरान हो सकती है।

## Minimal malicious plugin skeleton
एक DLL कंपाइल करें जिसमें अपेक्षित exports हों और उसे writable Notepad++ फ़ोल्डर के अंतर्गत `plugins\\MyNewPlugin\\MyNewPlugin.dll` में रखें:
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
2. `plugins` के अंदर plugin सबफ़ोल्डर बनाएं और DLL को उसमें डालें।
3. Notepad++ को रीस्टार्ट करें; DLL स्वचालित रूप से लोड हो जाएगा, `DllMain` और उसके बाद वाले callbacks को निष्पादित करेगा।

## Reflective loader plugin pattern
A weaponized plugin Notepad++ को एक **reflective DLL loader** में बदल सकता है:
- एक न्यूनतम UI/menu entry प्रस्तुत करें (उदा., "LoadDLL")।
- payload DLL को फेच करने के लिए **file path** या **URL** स्वीकार करें।
- DLL को वर्तमान process में reflectively map करें और किसी exported entry point को invoke करें (उदा., fetched DLL के अंदर एक loader function)।
- लाभ: नया loader spawn करने के बजाय एक benign-looking GUI process को reuse करें; payload `notepad++.exe` की integrity inherit कर लेता है (including elevated contexts)।
- नुकसान: डिस्क पर एक **unsigned plugin DLL** डालना noisy होता है; यदि मौजूद हों तो existing trusted plugins पर piggybacking करने पर विचार करें।

## डिटेक्शन और हार्डनिंग नोट्स
- Block या monitor करें **writes to Notepad++ plugin directories** (user profiles में portable copies सहित); controlled folder access या application allowlisting सक्षम करें।
- Alert करें जब `plugins` के नीचे **new unsigned DLLs** हो और `notepad++.exe` से असामान्य **child processes/network activity** दिखाई दे।
- Plugin installation को केवल **Plugins Admin** के माध्यम से लागू करें, और untrusted paths से portable copies के execution को प्रतिबंधित करें।

## References
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
