# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic क्या है?

Mythic एक open-source, modular, collaborative command and control (C2) framework है, जिसे red teaming के लिए बनाया गया है। यह operators को Windows, Linux और macOS सहित अलग-अलग operating systems पर agents (payloads) को manage और deploy करने की सुविधा देता है। Mythic, multi-operator tasking, file handling, SOCKS/rpfwd management और payload generation के लिए browser UI उपलब्ध कराता है।

Monolithic frameworks के विपरीत, Mythic repository में स्वयं **payload types या C2 profiles शामिल नहीं होते**। Agents, wrappers और C2 profiles आमतौर पर external components के रूप में install किए जाते हैं और Mythic core से स्वतंत्र रूप से update किए जा सकते हैं।

### Installation

Mythic install करने के लिए, आधिकारिक **[Mythic repo](https://github.com/its-a-feature/Mythic)** में दिए गए निर्देशों का पालन करें। Mythic directory से एक आम bootstrap यह है:

```bash
sudo make
sudo ./mythic-cli start
```

यदि Mythic पहले से चल रहा है, तो आप आमतौर पर `./mythic-cli install github ...` से नया agent या profile जोड़ सकते हैं और फिर Mythic को restart कर सकते हैं या सीधे नया component शुरू कर सकते हैं।

### Agents

Mythic कई agents को support करता है, जो **compromised systems पर tasks करने वाले payloads** होते हैं। प्रत्येक agent को विशिष्ट ज़रूरतों के अनुसार तैयार किया जा सकता है और यह अलग-अलग operating systems पर चल सकता है।

डिफ़ॉल्ट रूप से Mythic में कोई agent इंस्टॉल नहीं होता। Open-source community agents [**https://github.com/MythicAgents**](https://github.com/MythicAgents) पर उपलब्ध हैं, और supported operating systems, payload formats, wrappers तथा C2 profiles को तुरंत जाँचने के लिए [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) उपयोगी है।<sup>[[1]](#references)</sup>

उस org से agent इंस्टॉल करने के लिए आप यह चला सकते हैं:

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

`sudo -E` वाला तरीका तब उपयोगी होता है, जब आप non-root environment से install कर रहे हों। Mythic पहले से चल रहा हो, तब भी आप पिछले command से नए agents जोड़ सकते हैं।

### C2 Profiles

Mythic में C2 profiles यह तय करते हैं कि **agents, Mythic server से कैसे communicate करते हैं**। ये communication protocol, encryption methods और अन्य settings निर्दिष्ट करते हैं। आप Mythic web interface के ज़रिए C2 profiles बना और manage कर सकते हैं।

डिफ़ॉल्ट रूप से Mythic बिना किसी profile के install होता है। हालाँकि, repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) से कुछ profiles download करना संभव है। इसके लिए यह command चलाएँ:

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

ध्यान में रखने योग्य operator-संबंधित मौजूदा profiles:

- [`http`](https://github.com/MythicC2Profiles/http): बुनियादी asynchronous GET/POST traffic।
- [`httpx`](https://github.com/MythicC2Profiles/httpx): अधिक flexible HTTP traffic, जिसमें कई callback domains, fail-over/round-robin rotation, custom headers/query parameters, और message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) शामिल हैं। इन्हें cookies, headers, query parameters या body में रखा जा सकता है।
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): जब static `http` profile बहुत आसानी से पहचाना जा सके, तब JSON/TOML-आधारित HTTP message shaping।

### मौजूदा platform नोट्स

- अब कई public agents और profiles पहले से बने remote container images के साथ install होते हैं।
  अगर आप किसी component को fork करते हैं या उसे locally patch करते हैं और Mythic फिर भी पुराना behavior इस्तेमाल करता है, तो `*_REMOTE_IMAGE`,
  `*_USE_BUILD_CONTEXT`, और `*_USE_VOLUME` वाली generated `.env` entries देखें; आमतौर पर
  `*_USE_BUILD_CONTEXT="true"` enable करने से Mythic remote image को चुपचाप दोबारा इस्तेमाल करने के बजाय आपके local Docker context से rebuild करता है।
- Browser scripts, operators के लिए Mythic की सबसे उपयोगी quality-of-life सुविधाओं में से एक हैं: ये raw command output को tables, screenshot viewers, download links, search links, और ऐसे buttons में बदल सकते हैं जो सीधे UI से आगे की tasking शुरू करते हैं। मौजूदा Mythic builds में हर operator अपने scripts रख सकता है, उन्हें globally या प्रति-task toggle कर सकता है, और agents के plaintext के बजाय structured JSON लौटाने पर सबसे अच्छे परिणाम मिलते हैं। यह बार-बार किए जाने वाले `ls`, `ps`, triage और file-browser workflows के लिए विशेष रूप से उपयोगी है।<sup>[[4]](#references)[[6]](#references)</sup>
- नए Mythic builds interactive tasking और Push C2 patterns को भी support करते हैं, जिससे PTY/SOCKS/rpfwd-भारी operations के दौरान `sleep 0` polling की ज़रूरत घटती है। जब कोई agent/profile इसे support करता है, तो interactive channel को चालू रखने के लिए लगातार check-ins भेजने की तुलना में यह आमतौर पर कम overhead वाला तरीका है।<sup>[[3]](#references)</sup>
- मौजूदा 3.4-era Mythic builders, पुराने लेखों के बताए तरीकों की तुलना में context को बेहतर समझते हैं: build parameters को चुने गए OS या अन्य build options के आधार पर समूहित या छिपाया जा सकता है, payload types यह घोषित कर सकते हैं कि वे एक build में कई C2 profiles या एक ही C2 के कई instances support करते हैं या नहीं, और C2 parameter deviations किसी agent को ऐसे fields छिपाने देते हैं जिन्हें वह वास्तव में implement नहीं करता। `http`, `httpx`, `smb`, `tcp`, और `websocket` के बीच बदलते समय यह महत्वपूर्ण है, क्योंकि सुरक्षित/मान्य build विकल्प अब एक सपाट static form तक सीमित नहीं हैं।<sup>[[5]](#references)</sup>
- अगर आप custom agent/profile pair बना रहे हैं और wire पर Mythic का JSON message format या default crypto इस्तेमाल नहीं करना चाहते, तो `translation_container` इस्तेमाल करें: Mythic UUID हटा देता है, encrypted blob और key material को gRPC के ज़रिए translator को देता है, और बदले में agent-native bytes की अपेक्षा करता है। पूरे server को दोबारा लिखे बिना binary protocols, custom framing या agent-side encryption support करने का यह साफ़ तरीका है।
- याद रखें कि linked/P2P callbacks सिर्फ tasking आगे नहीं पहुँचाते। Mythic का `get_tasking` flow responses के साथ-साथ `delegates`, `socks`,
  `rpfwd`, और `interactive` data भी ले जा सकता है। व्यवहार में, एक egress callback एक ही polling loop में inner callbacks और pivot channels को संभाल सकता है; अगर child agents अपने periodic check-ins खुद करते हैं, तो `get_delegate_tasks=false` parent को inner callback की queued jobs गलती से लेने से रोकता है।

### Wrapper payloads

Wrapper payloads आपको वही agent logic बनाए रखते हुए delivered या persisted payload का on-disk representation बदलने देते हैं।

- `service_wrapper`: दूसरे payload को Windows service executable में बदलता है, जो तब उपयोगी है जब execution path के लिए एक valid service binary ज़रूरी हो।
- `scarecrow_wrapper`: compatible shellcode को ScareCrow loader से wrap करके loader-backed outputs, जैसे EXE/DLL/CPL, बनाता है।

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo एक Windows agent है, जिसे C# में 4.0 .NET Framework का उपयोग करके लिखा गया है और SpecterOps के training offerings में इस्तेमाल के लिए बनाया गया है।<sup>[[2]](#references)</sup>

इसे install करने के लिए:

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### मौजूदा build/profile नोट्स

- Apollo फिलहाल `WinExe`, `Shellcode`, `Service`, और `Source` payloads बना सकता है।
- Apollo के आम तौर पर इस्तेमाल होने वाले profiles हैं: `http`, `httpx`, `smb`, `tcp`, और `websocket`।
- जब आपको domain rotation, proxy support, custom message placement, और message transforms चाहिए हों, तो पुराने static `http` profile के बजाय `httpx` आमतौर पर ज़्यादा flexible विकल्प होता है।
- Apollo अधिक feature-complete community agents में से एक है और फिलहाल Mythic-side integrations उपलब्ध कराता है, जैसे browser scripts, file/process browser views, screenshots, keylogging, SOCKS, rpfwd, Push C2, और P2P routing।
- Apollo `service_wrapper` और `scarecrow_wrapper` जैसे wrapper payloads को support करता है।
- Apollo dynamic command loading को support करता है। इससे आप शुरुआती payload को lean रख सकते हैं और हर post-ex capability को पहली build में compile करने के बजाय बाद में अतिरिक्त commands या Forge modules load कर सकते हैं।
- Shellcode output बनाते समय, Apollo का मौजूदा builder Donut format के विकल्प भी देता है (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) और Donut bypass behavior (`None`, `Abort on fail`, `Continue on fail`) भी। यह उपयोगी है, अगर अंतिम लक्ष्य shellcode को `service_wrapper`, `scarecrow_wrapper`, या किसी custom loader से दोबारा wrap करना हो।
- `register_file` और `register_assembly`, `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, और `powerpick` के लिए staging primitives हैं। Apollo की मौजूदा builds में, ये staged artifacts client-side पर DPAPI-protected AES256 blobs के रूप में cache किए जाते हैं।
- `ls` और `ps` के results, Mythic के browser scripts और file/process browser के साथ खास तौर पर अच्छी तरह integrate होते हैं, जिससे collaborative operations में operator triage काफ़ी तेज़ हो जाता है।
- Apollo के fork-and-run jobs, sacrificial process settings `spawnto_x86` / `spawnto_x64` से लेते हैं, parent selection `ppid` से लेते हैं, और फिर मौजूदा चुने हुए injection primitive का इस्तेमाल करते हैं। व्यवहार में, इसका मतलब है कि एक command के लिए आपकी OPSEC tuning अक्सर `execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe`, और `spawn` को एक साथ प्रभावित करती है।
- Apollo के मौजूदा documented injection backends में `CreateRemoteThread`, `QueueUserAPC` (early-bird style), और syscalls के ज़रिए `NtCreateThreadEx` शामिल हैं। Noisy post-exploitation से पहले `get_injection_techniques` का इस्तेमाल करें, और अगर आपको ऐसे primitive से हटना हो जो target या चलाए जाने वाले command से मेल नहीं खाता, तो `set_injection_technique` का इस्तेमाल करें।
- `blockdlls` केवल post-exploitation jobs के लिए बनाए गए sacrificial processes को प्रभावित करता है। इसे default bare `rundll32.exe` से कम suspicious `spawnto_x64` target के साथ इस्तेमाल करना, assembly/PowerShell-heavy tasking चलाने से पहले Apollo-side पर किए जा सकने वाले सबसे आसान बदलावों में से एक है।

### Detection-aware .NET agent build pipeline

Detection-aware Apollo fork को **पूरे build-system की समस्या** मानना चाहिए, न कि आख़िर में चलाए जाने वाले `obfuscate.exe` step के रूप में। यह case study सामान्य [AV evasion methodology](av-bypass.md) और [.NET inspection tools](../reversing/reversing-tools-basic-methods/README.md) की पूरक है: wire identifiers, IL metadata, dependency packaging, reflection, और dynamically compiled tasks में बदलाव एक ही compatibility boundary बनाते हैं।<sup>[[8]](#references)</sup>

#### YARA-aware protocol mutation

Code बदलने से पहले public file/memory rules की जाँच करें। उदाहरण के लिए, Elastic का `Multi_Trojan_Mythic_4beb7e17` तब match करता है, जब Mythic JSON/action strings में से कोई भी **7 of 11** मौजूद हों; इनमें `task_id`, `post_response`, `c2_profile`, `get_tasking`, और `get_delegate_tasks` शामिल हैं। पर्याप्त fields का नाम बदलने से यह threshold चकमा खा सकता है, लेकिन ये protocol values हैं, cosmetic symbols नहीं: agent और संबंधित server/profile implementation को साथ में बदलना होगा।<sup>[[7]](#references)[[8]](#references)</sup>

इससे केवल एक static feature set हटता है। Check-in cadence, message shape, task/response flow, और runtime string reconstruction फिर भी behavioral या memory indicators बने रह सकते हैं; इसलिए, clean string scan को सफलता मानने के बजाय built artifact और चलाए गए callback—दोनों को validate करें।<sup>[[8]](#references)</sup>

#### Global transforms लागू करने से पहले merge करें

Costura जैसे tools से resource embedding करने पर companion assemblies compressed resources के रूप में रहती हैं। इसलिए, केवल outer module को देखने वाला obfuscator उनके type names और metadata को छोड़ देता है; इसके बजाय, हर DLL को अलग-अलग obfuscate करने से cross-assembly contracts के लिए असंगत names तय हो सकते हैं। पहले build outputs को IL level पर merge करें (उदाहरण के लिए [ILRepack](https://github.com/gluck/il-repack) से), फिर परिणामी module पर एक ही rename map लागू करें।<sup>[[8]](#references)</sup>

```text
agent.exe + dependency DLLs
          -> ILRepack -> merged.exe
          -> dnlib IL/metadata transforms
          -> AsmResolver PE/resource patching
          -> final payload
```

एक custom pass, managed IL/metadata transforms के लिए [dnlib](https://github.com/0xd4d/dnlib) और write के बाद PE/resource patching के लिए [AsmResolver](https://github.com/Washi1337/AsmResolver) का उपयोग कर सकता है। इस case study में, पात्र `ldstr` instructions को एक नई 16-byte rolling-XOR key से संचालित integer-token/decryptor calls में बदला गया, जबकि symbols और namespaces को छोटे क्रमिक identifiers के बजाय विश्वसनीय enterprise-शैली के नाम दिए गए। अन्य passes ने चुने हुए compiler/debugger attributes हटाए, merger/embedding references साफ़ किए, resources के नाम बदले और version information patch की। हर स्वतंत्र build के लिए नामों, dead code और encryption material को फिर से seed करें: ciphertext बदलने से स्थिर bytes हट जाते हैं, लेकिन स्थिर decryptor या पहचानने योग्य transformation pattern खुद एक signature होता है।<sup>[[8]](#references)</sup>

#### Dynamic tasks को payload के साथ synchronized रखें

Apollo server-side पर task source compile कर सकता है, DLL bytes भेज सकता है और उन्हें `Assembly.Load()` से load कर सकता है। Base agent के public types के नाम बदल जाने के बाद, original API के साथ compile किए गए बाद के tasks resolve नहीं होते। Exported rename map को payload-specific ABI artifact मानें:<sup>[[8]](#references)</sup>

1. Map और type context को सटीक payload/build identifier से जोड़ें।
2. हर task build के लिए वह map प्राप्त करें और temporary source tree को rewrite करें।
3. केवल resolved namespace, type, nested/generic type, field और property references rewrite करें, फिर obfuscated merged assembly के विरुद्ध compile करें।
4. Task भेजने से पहले missing या mismatched maps को अस्वीकार करें और compilation के बाद initialization test चलाएँ।

Blind global replacement असुरक्षित है, क्योंकि कोई identifier किसी string, local declaration, member access, framework type या असंबंधित namespace में भी मौजूद हो सकता है। यदि text/regex rewriter का उपयोग जारी रखते हैं, तो उन contexts को स्पष्ट रूप से सुरक्षित रखें और map schema या rename pass में बदलाव होने पर हर बार regression-test करें।<sup>[[8]](#references)</sup>

#### Reflection contracts को namespace से स्वतंत्र बनाएँ

` t.FullName.StartsWith("Tasks.")` जाँचने वाला discovery code namespace को load-bearing बनाता है और namespace remapping के बाद विफल हो जाता है। इसके बजाय स्थिर type relationship के आधार पर discover करें और command class names को बरकरार रखें, यदि dispatch अब भी `t.Name` का उपयोग करता है:<sup>[[8]](#references)</sup>

```csharp
foreach (Type t in _tasksAsm.GetExportedTypes())
{
    if (t.IsSubclassOf(typeof(Tasking)) && !t.IsAbstract)
        _loadedTaskTypes[t.Name] = t;
}
```

Reflection-visible names, serializer fields, entry points और cross-assembly APIs की एक स्पष्ट allowlist बनाए रखें, जिनका नाम नहीं बदलना चाहिए। अंत में, नतीजे को ILSpy/dnSpy से decompile करें, file और memory—दोनों representations को scan करें, और EDR lab में हर command/loader path को चलाकर जाँचें; सफलतापूर्वक शुरू होने वाले build में भी ऐसे tasks हो सकते हैं जो renaming से टूट गए हों या जिनका behavior केवल execution के बाद detect हो।<sup>[[8]](#references)</sup>

इस agent में कई commands हैं, जो इसे Cobalt Strike के Beacon से काफी मिलता-जुलता बनाती हैं, साथ ही इसमें कुछ अतिरिक्त सुविधाएँ भी हैं। इनमें यह शामिल हैं:

### Common actions

- `cat`: किसी file का content प्रिंट करें
- `cd`: मौजूदा working directory बदलें
- `cp`: किसी file को एक जगह से दूसरी जगह copy करें
- `ls`: मौजूदा directory या बताए गए path में files और directories की सूची दिखाएँ
- `ifconfig`: Network adapters और interfaces की जानकारी प्राप्त करें
- `netstat`: TCP और UDP connections की जानकारी प्राप्त करें
- `pwd`: मौजूदा working directory प्रिंट करें
- `ps`: Target system पर चल रही processes की सूची दिखाएँ (अतिरिक्त जानकारी के साथ)
- `jobs`: Long-running tasking से जुड़े सभी running jobs की सूची दिखाएँ
- `download`: Target system से local machine पर file download करें
- `upload`: Local machine से target system पर file upload करें
- `reg_query`: Target system पर registry keys और values की जाँच करें
- `reg_write_value`: निर्दिष्ट registry key में नई value लिखें
- `sleep`: Agent का sleep interval बदलें, जिससे तय होता है कि वह Mythic server से कितनी बार संपर्क करता है
- और भी कई commands हैं; उपलब्ध commands की पूरी सूची देखने के लिए `help` का उपयोग करें।

### Privilege escalation

- `getprivs`: मौजूदा thread token पर जितने संभव हों उतने privileges enable करें
- `getsystem`: winlogon का handle खोलें और token duplicate करें, जिससे privileges प्रभावी रूप से SYSTEM स्तर तक बढ़ जाते हैं
- `make_token`: नया logon session बनाएँ और उसे agent पर लागू करें, जिससे किसी अन्य user का impersonation संभव होता है
- `steal_token`: किसी दूसरी process से primary token चुराएँ, जिससे agent उस process के user का impersonation कर सकता है
- `pth`: Pass-the-Hash attack, जिससे agent plaintext password की आवश्यकता के बिना user के NTLM hash का उपयोग करके authenticate कर सकता है
- `mimikatz`: Memory या SAM database से credentials, hashes और अन्य संवेदनशील जानकारी निकालने के लिए Mimikatz commands चलाएँ
- `rev2self`: Agent के token को उसके primary token पर वापस लाएँ, जिससे privileges प्रभावी रूप से मूल स्तर पर लौट जाते हैं
- `ppid`: नया parent process ID निर्दिष्ट करके post-exploitation jobs के लिए parent process बदलें, जिससे job execution context पर बेहतर नियंत्रण मिलता है
- `printspoofer`: Print spooler के security measures को bypass करने के लिए PrintSpoofer commands चलाएँ, जिससे privilege escalation या code execution संभव होता है
- `dcsync`: User की Kerberos keys को local machine पर sync करें, जिससे offline password cracking या आगे के attacks संभव होते हैं
- `ticket_cache_add`: मौजूदा या निर्दिष्ट logon session में Kerberos ticket जोड़ें, जिससे ticket reuse या impersonation संभव होता है

### Process execution

- `assembly_inject`: Remote process में .NET assembly loader inject करें
- `blockdlls`: Post-exploitation jobs में non-Microsoft signed DLLs को load होने से रोकें
- `execute_assembly`: Agent के context में .NET assembly चलाएँ
- `execute_coff`: COFF file को memory में चलाएँ, जिससे compiled code का in-memory execution संभव होता है
- `execute_pe`: Unmanaged executable (PE) चलाएँ
- `keylog_inject`: दूसरे process में keylogger inject करें और keystrokes को Mythic के keylog view में stream करें
- `screenshot` / `screenshot_inject`: मौजूदा desktop का screenshot लें, सीधे या target process/session में screenshot assembly inject करके
- `get_injection_techniques`: उपलब्ध injection techniques और वर्तमान में चुनी गई technique दिखाएँ
- `inline_assembly`: Disposable AppDomain में .NET assembly चलाएँ, जिससे agent की main process को प्रभावित किए बिना code को अस्थायी रूप से चलाया जा सके
- `register_assembly`: बाद में execution के लिए .NET assembly register करें
- `register_file`: बाद में `execute_*` या PowerShell tasking के लिए agent cache में file register करें
- `run`: System के PATH का उपयोग करके target system पर binary चलाएँ और executable खोजें
- `set_injection_technique`: Post-exploitation jobs द्वारा उपयोग किए जाने वाले injection primitive को बदलें
- `shinject`: Remote process में shellcode inject करें, जिससे arbitrary code का in-memory execution संभव होता है
- `inject`: Remote process में agent shellcode inject करें, जिससे agent के code का in-memory execution संभव होता है
- `spawn`: निर्दिष्ट executable में नया agent session शुरू करें, जिससे नए process में shellcode का execution संभव होता है
- `spawnto_x64` और `spawnto_x86`: Post-exploitation jobs में उपयोग होने वाले default binary को निर्दिष्ट path से बदलें। इससे बिना params वाले `rundll32.exe` का उपयोग नहीं करना पड़ता, जो बहुत noisy है।

### Mythic Forge

इससे Mythic Forge से **COFF/BOF** files load की जा सकती हैं। Mythic Forge pre-compiled payloads और tools का repository है, जिन्हें target system पर चलाया जा सकता है। Load की जा सकने वाली सभी commands के साथ, उन्हें BOFs के रूप में मौजूदा agent process में चलाकर सामान्य actions करना संभव होगा (आमतौर पर अलग process शुरू करने की तुलना में बेहतर OPSEC के साथ)।

इन्हें install करना शुरू करें:

```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```

फिर, Mythic Forge से COFF/BOF modules दिखाने के लिए `forge_collections` का उपयोग करें, ताकि आप उन्हें चुनकर execution के लिए agent की memory में load कर सकें। डिफ़ॉल्ट रूप से, Apollo में ये 2 collections जोड़े जाते हैं:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

कोई module load होने के बाद, वह सूची में एक और command के रूप में दिखाई देगा, जैसे `forge_bof_sa-whoami` या `forge_bof_sa-netuser`।

BOFs के लिए, ध्यान रखें कि Forge सिर्फ़ एक flat argument string को Apollo तक नहीं भेजता। यह BOF parameters को Mythic के typed-array format में map करता है और फिर उन्हें Apollo के `execute_coff` flow में forward करता है। अगर Forge से load किया गया BOF अजीब व्यवहार करे, तो सिर्फ़ आपके टाइप किए गए command line को नहीं, बल्कि अपेक्षित BOF argument types / entrypoint को जाँचें। यह भी ध्यान दें कि Apollo के नए BOF loader ने पुराने 2.3.1-era builds की तुलना में argument handling बदल दी है, इसलिए पुराने BOFs या collections सिर्फ़ इसलिए fail हो सकते हैं क्योंकि marshaling की अपेक्षाएँ बदल गई हैं।

### PowerShell और scripting execution

- `powershell_import`: बाद में execution के लिए agent cache में नई PowerShell script (.ps1) import करता है
- `powershell`: agent के context में PowerShell command execute करता है, जिससे advanced scripting और automation संभव होती है
- `powerpick`: PowerShell loader assembly को sacrificial process में inject करता है और PowerShell command execute करता है (powershell logging के बिना)।
- `psinject`: किसी निर्दिष्ट process में PowerShell execute करता है, जिससे दूसरे process के context में scripts को लक्षित रूप से execute किया जा सकता है
- `shell`: agent के context में shell command execute करता है, यह cmd.exe में command चलाने जैसा है

### Lateral Movement

- `jump_psexec`: पहले Apollo agent executable (apollo.exe) को कॉपी करके execute करने के लिए PsExec technique का उपयोग करके नए host पर lateral movement करता है।
- `jump_wmi`: पहले Apollo agent executable (apollo.exe) को कॉपी करके execute करने के लिए WMI technique का उपयोग करके नए host पर lateral movement करता है।
- `link` और `unlink`: callbacks के बीच P2P links (उदाहरण के लिए SMB/TCP पर) बनाते और बंद करते हैं।
- `wmiexecute`: impersonation के लिए वैकल्पिक credentials के साथ, WMI का उपयोग करके local या निर्दिष्ट remote system पर command execute करता है।
- `net_dclist`: निर्दिष्ट domain के domain controllers की सूची प्राप्त करता है, जो lateral movement के संभावित targets की पहचान करने में उपयोगी है।
- `net_localgroup`: निर्दिष्ट computer पर local groups की सूची देता है। यदि कोई computer निर्दिष्ट न हो, तो localhost को default मानता है।
- `net_localgroup_member`: local या remote computer पर किसी निर्दिष्ट group की membership प्राप्त करता है, जिससे विशिष्ट groups के users की enumeration की जा सकती है।
- `net_shares`: निर्दिष्ट computer पर remote shares और उनकी accessibility की सूची देता है, जो lateral movement के संभावित targets की पहचान करने में उपयोगी है।
- `socks`: target network पर SOCKS 5 compliant proxy सक्षम करता है, जिससे compromised host के माध्यम से traffic tunnel किया जा सकता है। proxychains जैसे tools के साथ compatible है।
- `rpfwd`: target host पर निर्दिष्ट port पर listening शुरू करता है और Mythic के माध्यम से traffic को remote IP और port तक forward करता है, जिससे target network की services को remote access मिलता है।
- `listpipes`: local system पर सभी named pipes की सूची देता है, जो IPC mechanisms के साथ interact करके lateral movement या privilege escalation के लिए उपयोगी हो सकते हैं।

`jump_wmi` या `wmiexecute` के नीचे इस्तेमाल होने वाले low-level WMI execution primitives के लिए [WmiExec](lateral-movement/wmiexec.md) देखें। व्यापक pivoting patterns के लिए [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md) देखें।

### Miscellaneous Commands
- `help`: विशिष्ट commands के बारे में विस्तृत जानकारी या agent में उपलब्ध सभी commands के बारे में सामान्य जानकारी दिखाता है।
- `clear`: tasks को 'cleared' के रूप में चिह्नित करता है, ताकि agents उन्हें pick up न कर सकें। सभी tasks clear करने के लिए `all` या किसी विशिष्ट task को clear करने के लिए `task Num` निर्दिष्ट कर सकते हैं।  


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon एक Golang agent है, जो **Linux और macOS** executables में compile होता है।

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### वर्तमान build/profile नोट्स

- वर्तमान Poseidon builds `x86_64` और `arm64` दोनों पर Linux और macOS को target करते हैं।
- समर्थित output formats में native executables और `dylib` तथा `so` जैसे shared-library style outputs शामिल हैं।
- Poseidon `http`, `websocket`, `tcp`, और `dynamichttp` को support करता है, और वर्तमान builders में `egress_order` तथा failover thresholds जैसी multi-egress settings उपलब्ध हैं।
- Poseidon का वर्तमान capability metadata browser scripts, file/process browser integration, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd, और P2P को भी advertise करता है। इसलिए यह केवल एक साधारण remote shell नहीं, बल्कि Linux/macOS pivot node के रूप में काम कर सकता है।
- जब आपको बेहतर network behavior या Go binary की अतिरिक्त obfuscation चाहिए, तो `proxy_bypass` और `garble` जैसे build-time options देखना उपयोगी है।
- Linux/macOS operations के लिए `pty` सबसे उपयोगी नए quality-of-life commands में से एक है, क्योंकि यह interactive PTY खोलता है और पुराने `sleep 0` + SOCKS workaround का सहारा लिए बिना, बेहतर terminal interaction के लिए Mythic-side port उपलब्ध करा सकता है।
- macOS-केंद्रित tradecraft के लिए Poseidon के वर्तमान docs खास तौर पर दिलचस्प हैं: `jxa` JavaScript for Automation को in-memory execute करता है, `screencapture` logged-in desktop का capture लेता है, `clipboard_monitor` pasteboard में होने वाले बदलाव stream करता है, `execute_library` local dylib load करके उसका function call करता है, और `libinject` किसी remote process को disk पर मौजूद dylib load करने के लिए बाध्य करता है।
- लंबे समय तक चलने वाले jobs के लिए ध्यान रखें कि Poseidon post-exploitation work को goroutines/threads में चलाता है, जिन्हें cooperative तरीके से रोका जाता है, hard-kill नहीं किया जा सकता। Docs यह भी स्पष्ट रूप से बताते हैं कि फिलहाल built-in agent obfuscation नहीं है, इसलिए build/profile-स्तर का tradecraft, heavily obfuscated commercial implants की तुलना में अधिक मायने रखता है।

Mythic-backed operations, JAMF abuse, या MDM-as-C2 के विचारों से जुड़े macOS-specific tradecraft के लिए [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md) देखें।

Linux या macOS पर इस्तेमाल किए जाने पर इसमें कुछ दिलचस्प commands हैं:

### आम कार्रवाइयाँ

- `cat`: किसी file की सामग्री print करें
- `cd`: वर्तमान working directory बदलें
- `chmod`: किसी file की permissions बदलें
- `config`: वर्तमान config और host की जानकारी देखें
- `cp`: किसी file को एक जगह से दूसरी जगह copy करें
- `curl`: वैकल्पिक headers और method के साथ एक web request execute करें
- `upload`: target पर file upload करें
- `download`: target system से local machine पर file download करें
- और भी बहुत कुछ

### संवेदनशील जानकारी खोजें

- `triagedirectory`: किसी host की directory में दिलचस्प files खोजें, जैसे sensitive files या credentials।
- `getenv`: सभी वर्तमान environment variables प्राप्त करें।

### macOS-specific tradecraft

- `jxa`: `OSAScript` के ज़रिए JavaScript for Automation को in-memory execute करें। यह अलग script files छोड़े बिना native macOS post-exploitation के लिए उपयोगी है।
- `clipboard_monitor`: pasteboard को poll करें और बदलावों की रिपोर्ट Mythic को भेजें। यह copy/paste पर निर्भर credential/token theft workflows के लिए उपयोगी है।
- `screencapture`: macOS पर user के desktop का capture लें।
- `execute_library`: disk से dylib load करें और किसी विशिष्ट exported function को call करें।
- `libinject`: ऐसा shellcode stub inject करें जो किसी दूसरे macOS process को disk से dylib load करने के लिए बाध्य करे।
- `persist_launchd`: agent से सीधे LaunchAgent / LaunchDaemon persistence बनाएँ।

### Lateral movement करें

- `ssh`: निर्धारित credentials का उपयोग करके host से SSH करें और ssh spawn किए बिना PTY खोलें।
- `sshauth`: निर्धारित credentials का उपयोग करके निर्दिष्ट host(s) से SSH करें। इसका उपयोग SSH के ज़रिए remote hosts पर कोई विशिष्ट command execute करने या files को SCP करने के लिए भी किया जा सकता है।
- `link_tcp`: TCP पर किसी दूसरे agent से link करें, जिससे agents के बीच सीधा communication संभव हो।
- `link_webshell`: webshell P2P profile का उपयोग करके किसी agent से link करें, जिससे agent के web interface तक remote access मिले।
- `rpfwd`: Reverse Port Forward शुरू या बंद करें, जिससे target network की services तक remote access मिल सके।
- `socks`: target network पर SOCKS5 proxy शुरू या बंद करें, जिससे compromised host के ज़रिए traffic tunnel किया जा सके। proxychains जैसे tools के साथ compatible है।
- `portscan`: खुले ports के लिए host(s) scan करें। यह lateral movement या आगे के attacks के संभावित targets की पहचान करने में उपयोगी है।

### Process execution

- `shell`: `/bin/sh` के ज़रिए एक shell command execute करें, जिससे target system पर commands सीधे execute की जा सकें।
- `run`: arguments के साथ disk से कोई command execute करें, जिससे target system पर binaries या scripts execute की जा सकें।
- `pty`: interactive PTY खोलें, जिससे target system पर shell के साथ सीधे interaction किया जा सके।

## References

- [1] [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 की मुख्य बातें: Interactive Tasking, Push C2, और Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Mythic के छिपे हुए उपयोगी फीचर्स से Red Team Ops में बदलाव: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
- [7] [Elastic protections-artifacts: Multi_Trojan_Mythic YARA rules](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Mythic.yar)
- [8] [Fork से Framework तक: Apollo में बदलाव करने से Agent Invasion के बारे में हमने क्या सीखा](https://bishopfox.com/blog/from-fork-to-framework-what-modifying-apollo-taught-us-about-agent-invasion)
{{#include ../banners/hacktricks-training.md}}
