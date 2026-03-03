# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ लॉन्च पर अपने `plugins` सबफ़ोल्डर्स के तहत पाए जाने वाली हर plugin DLL को **autoload** करेगा. किसी भी **writable Notepad++ installation** में एक malicious plugin डालने से हर बार editor शुरू होने पर `notepad++.exe` के अंदर code execution मिलती है, जिसे **persistence**, stealthy **initial execution**, या यदि editor elevated रूप में लॉन्च हुआ हो तो **in-process loader** के रूप में दुरुपयोग किया जा सकता है।

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (usually requires admin to write).
- Writable options for low-privileged operators:
- Use the **portable Notepad++ build** in a user-writable folder.
- Copy `C:\Program Files\Notepad++` to a user-controlled path (e.g., `%LOCALAPPDATA%\npp\`) and run `notepad++.exe` from there.
- Each plugin gets its own subfolder under `plugins` and is loaded automatically at startup; menu entries appear under **Plugins**.

## Plugin load points (execution primitives)
Notepad++ विशिष्ट **exported functions** की अपेक्षा करता है। ये सभी initialization के दौरान कॉल होते हैं, जिससे कई execution surfaces मिलते हैं:
- **`DllMain`** — DLL load होते ही तुरंत चलता है (पहला execution point).
- **`setInfo(NppData)`** — load पर एक बार कॉल होता है और Notepad++ handles देता है; आमतौर पर menu items रजिस्टर करने की जगह।
- **`getName()`** — menu में दिखने वाला plugin नाम रिटर्न करता है।
- **`getFuncsArray(int *nbF)`** — menu commands रिटर्न करता है; खाली होने पर भी startup के दौरान इसे कॉल किया जाता है।
- **`beNotified(SCNotification*)`** — editor events (file open/change, UI events) प्राप्त करता है, जो ongoing triggers के लिए उपयोगी है।
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, बड़े डेटा आदान-प्रदान के लिए उपयोगी।
- **`isUnicode()`** — compatibility flag जिसे load पर चेक किया जाता है।

अधिकांश exports को **stubs** के रूप में लागू किया जा सकता है; autoload के दौरान execution `DllMain` या उपरोक्त किसी callback से हो सकता है।

## Minimal malicious plugin skeleton
DLL को अपेक्षित exports के साथ compile करें और इसे writable Notepad++ फ़ोल्डर के अंतर्गत `plugins\\MyNewPlugin\\MyNewPlugin.dll` में रखें:
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
2. `plugins` के अंतर्गत plugin सबफ़ोल्डर बनाएं और DLL को इसमें डालें।
3. Notepad++ को रीस्टार्ट करें; DLL स्वचालित रूप से लोड हो जाता है, `DllMain` और बाद के callbacks को execute करते हुए।

## Reflective loader plugin pattern
A weaponized plugin can turn Notepad++ into a **reflective DLL loader**:
- एक न्यूनतम UI/menu एंट्री प्रस्तुत करें (उदा., "LoadDLL").
- payload DLL प्राप्त करने के लिए **file path** या **URL** स्वीकार करें।
- DLL को वर्तमान process में reflectively map करें और एक exported entry point को invoke करें (उदा., fetched DLL के अंदर का loader function)।
- लाभ: एक सामान्य दिखने वाले GUI process का पुन: उपयोग करें बजाय नए loader को spawn करने के; payload `notepad++.exe` की integrity inherit करता है (including elevated contexts)।
- Trade-offs: डिस्क पर एक **unsigned plugin DLL** छोड़ना noisy होता है; यदि मौजूद हों तो मौजूदा trusted plugins पर piggyback करने पर विचार करें।

## Detection और hardening नोट्स
- Notepad++ plugin directories पर होने वाली **writes** को ब्लॉक या मॉनिटर करें (user profiles में portable copies सहित); controlled folder access या application allowlisting सक्षम करें।
- `plugins` के तहत आने वाले **new unsigned DLLs** और `notepad++.exe` से होने वाली असामान्य **child processes/network activity** पर अलर्ट करें।
- plugin installation को केवल **Plugins Admin** के माध्यम से लागू करें, और untrusted paths से portable copies के execution को प्रतिबंधित करें।

## References
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
