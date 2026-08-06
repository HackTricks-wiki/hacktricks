# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic क्या है?

Mythic एक open-source, modular, collaborative command and control (C2) framework है, जिसे red teaming के लिए बनाया गया है। यह operators को Windows, Linux और macOS सहित विभिन्न operating systems पर agents (payloads) को manage और deploy करने की सुविधा देता है। Mythic multi-operator tasking, file handling, SOCKS/rpfwd management और payload generation के लिए browser UI प्रदान करता है।

Monolithic frameworks के विपरीत, Mythic repository में स्वयं payload types या C2 profiles शामिल नहीं होते। Agents, wrappers और C2 profiles आमतौर पर external components के रूप में install किए जाते हैं और Mythic core से स्वतंत्र रूप से update किए जा सकते हैं।

### Installation

Mythic को install करने के लिए official **[Mythic repo](https://github.com/its-a-feature/Mythic)** में दिए गए instructions का पालन करें। Mythic directory से किया जाने वाला एक सामान्य bootstrap है:
```bash
sudo make
sudo ./mythic-cli start
```
यदि Mythic पहले से चल रहा है, तो आप सामान्यतः `./mythic-cli install github ...` के साथ नया agent या profile जोड़ सकते हैं और फिर Mythic को restart कर सकते हैं या केवल नए component को सीधे start कर सकते हैं।

### Agents

Mythic कई agents को support करता है, जो **compromised systems पर tasks perform करने वाले payloads** होते हैं। प्रत्येक agent को विशिष्ट आवश्यकताओं के अनुसार तैयार किया जा सकता है और यह अलग-अलग operating systems पर चल सकता है।

डिफ़ॉल्ट रूप से Mythic में कोई agent installed नहीं होता। Open-source community agents [**https://github.com/MythicAgents**](https://github.com/MythicAgents) पर उपलब्ध हैं, और [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) supported operating systems, payload formats, wrappers और C2 profiles को जल्दी check करने के लिए उपयोगी है।<sup>[[1]](#references)</sup>

उस org से agent install करने के लिए आप चला सकते हैं:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
`sudo -E` form तब उपयोगी होता है जब आप non-root environment से install कर रहे हों। Mythic पहले से running होने पर भी आप पिछली command से नए agents जोड़ सकते हैं।

### C2 Profiles

Mythic में C2 profiles यह परिभाषित करते हैं कि **agents, Mythic server के साथ कैसे communicate करते हैं**। इनमें communication protocol, encryption methods और अन्य settings निर्दिष्ट की जाती हैं। आप Mythic web interface के माध्यम से C2 profiles create और manage कर सकते हैं।

By default Mythic बिना किसी profiles के install होता है, हालांकि repo से कुछ profiles download करना संभव है। इसके लिए चलाएँ:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
वर्तमान operator-relevant profiles को ध्यान में रखें:

- [`http`](https://github.com/MythicC2Profiles/http): basic asynchronous GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): अधिक flexible HTTP traffic, जिसमें multiple callback domains, fail-over/round-robin rotation, custom headers/query parameters और message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) शामिल हैं, जिन्हें cookies, headers, query parameters या body में रखा जा सकता है।
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): जब static `http` profile बहुत आसानी से पहचाना जा सके, तब JSON/TOML-driven HTTP message shaping।

### वर्तमान platform notes

- कई public agents और profiles अब pre-built remote container images के साथ install होते हैं।
यदि आप किसी component को fork करते हैं या उसे locally patch करते हैं और Mythic पुराने
behavior का उपयोग करता रहता है, तो generated `.env` entries में `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT` और `*_USE_VOLUME` देखें; `*_USE_BUILD_CONTEXT="true"` enable करना
आमतौर पर Mythic को आपके local Docker context से rebuild करने के लिए पर्याप्त होता है,
जिससे वह चुपचाप remote image का पुनः उपयोग नहीं करता।
- Browser scripts operators के लिए Mythic के सबसे अधिक उपयोगी quality-of-life features में से एक हैं:
वे raw command output को tables, screenshot viewers, download links, search links और ऐसे buttons में बदल सकते हैं
जो UI से सीधे follow-on tasking जारी करते हैं। वर्तमान Mythic builds प्रत्येक operator को अपने
scripts रखने, उन्हें globally या per-task toggle करने की सुविधा देते हैं, और agents के plaintext के बजाय
structured JSON लौटाने पर सर्वोत्तम परिणाम मिलते हैं। यह repetitive `ls`, `ps`, triage और
file-browser workflows के लिए विशेष रूप से उपयोगी है।<sup>[[4]](#references)[[6]](#references)</sup>
- नए Mythic builds interactive tasking और Push C2 patterns को भी support करते हैं,
जो PTY/SOCKS/rpfwd-heavy operations के दौरान `sleep 0` polling की आवश्यकता कम करते हैं।
जब कोई agent/profile इसे support करता है, तो interactive channel को usable बनाए रखने के लिए
constant check-ins से server पर बार-बार load डालने की तुलना में यह आमतौर पर कम overhead वाला तरीका है।<sup>[[3]](#references)</sup>
- वर्तमान 3.4-era Mythic builders पुराने writeups के संकेत से अधिक context-aware हैं:
अब build parameters को selected OS या अन्य build options के आधार पर group या hide किया जा सकता है,
payload types यह declare कर सकते हैं कि वे multiple C2 profiles या एक ही C2 की multiple instances
को एक build में support करते हैं या नहीं, और C2 parameter deviations किसी agent द्वारा वास्तव में
implement न किए गए fields को hide करने देते हैं। यह तब महत्वपूर्ण होता है जब आप `http`, `httpx`, `smb`,
`tcp` और `websocket` के बीच switch करते हैं, क्योंकि safe/valid build surface अब flat static form नहीं रहा है।<sup>[[5]](#references)</sup>
- यदि आप कोई custom agent/profile pair बना रहे हैं और wire पर Mythic का JSON message format या
default crypto नहीं चाहते, तो `translation_container` का उपयोग करें: Mythic UUID को strip करता है,
encrypted blob और key material को gRPC के माध्यम से translator को देता है, और agent-native bytes वापस
अपेक्षित करता है। Binary protocols, custom framing या agent-side encryption support करने के लिए,
पूरे server को rewrite किए बिना, यह सबसे साफ तरीका है।
- याद रखें कि linked/P2P callbacks केवल tasking को shuttle नहीं करते। Mythic का
`get_tasking` flow responses के साथ-साथ `delegates`, `socks`, `rpfwd` और `interactive` data भी
carry कर सकता है। व्यवहार में, एक egress callback inner callbacks और pivot channels को उसी polling
loop में service कर सकता है; यदि child agents अपने periodic check-ins स्वयं perform करते हैं,
तो `get_delegate_tasks=false` parent को inner callback की queued jobs को गलती से consume करने से रोकता है।

### Wrapper payloads

Wrapper payloads आपको delivered या persisted on-disk representation बदलते हुए भी वही agent logic बनाए रखने देते हैं।

- `service_wrapper`: किसी अन्य payload को Windows service executable में बदलता है, जो तब उपयोगी है जब execution path को valid service binary की आवश्यकता हो।
- `scarecrow_wrapper`: compatible shellcode को ScareCrow loader से wrap करके loader-backed outputs जैसे EXE/DLL/CPL generate करता है।

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo एक Windows agent है, जिसे C# में 4.0 .NET Framework का उपयोग करके लिखा गया है और SpecterOps training offerings में उपयोग के लिए design किया गया है।<sup>[[2]](#references)</sup>

इसे इस command से install करें:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Apollo वर्तमान में `WinExe`, `Shellcode`, `Service`, और `Source` payloads emit कर सकता है।
- आमतौर पर उपयोग किए जाने वाले Apollo profiles `http`, `httpx`, `smb`, `tcp`, और `websocket` हैं।
- जब आपको domain rotation, proxy support, custom message placement, और message transforms की आवश्यकता हो, तो पुराने static `http` profile के बजाय `httpx` आमतौर पर अधिक flexible विकल्प होता है।
- Apollo अधिक feature-complete community agents में से एक है और वर्तमान में Mythic-side integrations जैसे browser scripts, file/process browser views, screenshots, keylogging, SOCKS, rpfwd, Push C2, और P2P routing उपलब्ध कराता है।
- Apollo `service_wrapper` और `scarecrow_wrapper` जैसे wrapper payloads को support करता है।
- Apollo dynamic command loading को support करता है, इसलिए initial payload को lean रखा जा सकता है और हर post-ex capability को पहले build में compile करने के बजाय बाद में extra commands या Forge modules load किए जा सकते हैं।
- Shellcode output generate करते समय Apollo का current builder Donut format choices (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) और Donut bypass behavior (`None`, `Abort on fail`, `Continue on fail`) भी उपलब्ध कराता है। यह उपयोगी है यदि अंतिम उद्देश्य shellcode को `service_wrapper`, `scarecrow_wrapper`, या किसी custom loader से दोबारा wrap करना हो।
- `register_file` और `register_assembly`, `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, और `powerpick` के लिए staging primitives हैं। Current Apollo builds में, ये staged artifacts client-side पर DPAPI-protected AES256 blobs के रूप में cached रहते हैं।
- `ls` और `ps` के results Mythic के browser scripts तथा file/process browser के साथ विशेष रूप से अच्छी तरह integrate होते हैं, जिससे collaborative operations में operator triage काफी तेज हो जाता है।
- Apollo के fork-and-run jobs अपनी sacrificial process settings
`spawnto_x86` / `spawnto_x64` से inherit करते हैं, parent selection `ppid` से inherit करते हैं, और
फिर वर्तमान में selected injection primitive का उपयोग करते हैं। व्यवहार में, इसका अर्थ है कि
एक command के लिए आपका OPSEC tuning अक्सर `execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe`, और `spawn` को
एक साथ प्रभावित करता है।
- वर्तमान documented Apollo injection backends में `CreateRemoteThread`,
`QueueUserAPC` (early-bird style), और syscalls के माध्यम से `NtCreateThreadEx` शामिल हैं।
शोरपूर्ण post-exploitation से पहले `get_injection_techniques` का उपयोग करें और
यदि आपको किसी ऐसे primitive से बदलना हो जो target या आपके चलाए जाने वाले command से
टकराता है, तो `set_injection_technique` का उपयोग करें।
- `blockdlls` केवल post-exploitation jobs के लिए बनाए गए sacrificial processes को प्रभावित करता है।
Default bare `rundll32.exe` की तुलना में कम suspicious `spawnto_x64` target के साथ combine करने पर,
assembly/PowerShell-heavy tasking चलाने से पहले यह Apollo-side पर किए जाने वाले सबसे आसान बदलावों में से एक है।

इस agent में बहुत सारे commands हैं, जो इसे कुछ अतिरिक्त सुविधाओं के साथ Cobalt Strike के Beacon के समान बनाते हैं। इनमें यह support करता है:

### Common actions

- `cat`: किसी file के contents print करें
- `cd`: current working directory बदलें
- `cp`: एक location से दूसरी location पर file copy करें
- `ls`: current directory या specified path में files और directories की list दिखाएं
- `ifconfig`: network adapters और interfaces प्राप्त करें
- `netstat`: TCP और UDP connection information प्राप्त करें
- `pwd`: current working directory print करें
- `ps`: target system पर चल रही processes की list दिखाएं (अतिरिक्त info के साथ)
- `jobs`: long-running tasking से संबंधित सभी running jobs की list दिखाएं
- `download`: target system से local machine पर file download करें
- `upload`: local machine से target system पर file upload करें
- `reg_query`: target system पर registry keys और values query करें
- `reg_write_value`: specified registry key में नया value लिखें
- `sleep`: agent का sleep interval बदलें, जो निर्धारित करता है कि वह Mythic server से कितनी बार check in करता है
- और भी कई commands हैं; उपलब्ध commands की पूरी list देखने के लिए `help` का उपयोग करें।

### Privilege escalation

- `getprivs`: current thread token पर जितने संभव हों उतने privileges enable करें
- `getsystem`: winlogon का handle खोलें और token duplicate करें, जिससे privileges प्रभावी रूप से SYSTEM level तक escalate हो जाते हैं
- `make_token`: नया logon session create करें और उसे agent पर apply करें, जिससे किसी अन्य user का impersonation संभव होता है
- `steal_token`: किसी अन्य process से primary token चुराएं, जिससे agent उस process के user का impersonate कर सकता है
- `pth`: Pass-the-Hash attack, जिससे agent plaintext password की आवश्यकता के बिना user के NTLM hash का उपयोग करके authenticate कर सकता है
- `mimikatz`: memory या SAM database से credentials, hashes और अन्य sensitive information extract करने के लिए Mimikatz commands चलाएं
- `rev2self`: agent के token को उसके primary token पर revert करें, जिससे privileges प्रभावी रूप से original level पर वापस आ जाते हैं
- `ppid`: नया parent process ID specify करके post-exploitation jobs के parent process को बदलें, जिससे job execution context पर बेहतर control मिलता है
- `printspoofer`: print spooler security measures को bypass करने के लिए PrintSpoofer commands execute करें, जिससे privilege escalation या code execution संभव होता है
- `dcsync`: किसी user की Kerberos keys को local machine पर sync करें, जिससे offline password cracking या आगे के attacks संभव होते हैं
- `ticket_cache_add`: current logon session या specified session में Kerberos ticket add करें, जिससे ticket reuse या impersonation संभव होता है

### Process execution

- `assembly_inject`: remote process में .NET assembly loader inject करने की अनुमति देता है
- `blockdlls`: post-exploitation jobs में non-Microsoft signed DLLs को load होने से block करें
- `execute_assembly`: agent के context में .NET assembly execute करता है
- `execute_coff`: COFF file को memory में execute करता है, जिससे compiled code का in-memory execution संभव होता है
- `execute_pe`: unmanaged executable (PE) execute करता है
- `keylog_inject`: किसी अन्य process में keylogger inject करता है और keystrokes को Mythic के keylog view में stream करता है
- `screenshot` / `screenshot_inject`: current desktop capture करता है या
target process/session में screenshot assembly inject करके capture करता है
- `get_injection_techniques`: available injection techniques और वर्तमान में selected technique दिखाता है
- `inline_assembly`: disposable AppDomain में .NET assembly execute करता है, जिससे agent की main process को प्रभावित किए बिना code का temporary execution संभव होता है
- `register_assembly`: बाद में execution के लिए .NET assembly register करता है
- `register_file`: बाद में `execute_*` या PowerShell tasking के लिए agent cache में file register करता है
- `run`: system के PATH का उपयोग करके executable खोजता है और target system पर binary execute करता है
- `set_injection_technique`: post-exploitation jobs द्वारा उपयोग किए जाने वाले injection primitive को बदलता है
- `shinject`: remote process में shellcode inject करता है, जिससे arbitrary code का in-memory execution संभव होता है
- `inject`: remote process में agent shellcode inject करता है, जिससे agent code का in-memory execution संभव होता है
- `spawn`: specified executable में नया agent session spawn करता है, जिससे नए process में shellcode का execution संभव होता है
- `spawnto_x64` और `spawnto_x86`: post-exploitation jobs में उपयोग होने वाले default binary को specified path पर बदलें, बजाय इसके कि बिना params वाले `rundll32.exe` का उपयोग किया जाए, जो बहुत noisy होता है।

### Mythic Forge

यह Mythic Forge से **COFF/BOF** files को **load** करने की अनुमति देता है। Mythic Forge pre-compiled payloads और tools का repository है, जिन्हें target system पर execute किया जा सकता है। Load किए जा सकने वाले सभी commands के साथ, current agent process में उन्हें BOFs के रूप में execute करके common actions करना संभव होगा (आमतौर पर separate process spawn करने की तुलना में बेहतर OPSEC के साथ)।

इन्हें install करना शुरू करें:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
फिर, Mythic Forge से COFF/BOF modules दिखाने के लिए `forge_collections` का उपयोग करें, ताकि उन्हें select करके execution के लिए agent की memory में load किया जा सके। डिफ़ॉल्ट रूप से, Apollo में निम्नलिखित 2 collections जोड़े जाते हैं:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

एक module load होने के बाद, यह list में किसी अन्य command की तरह दिखाई देगा, जैसे `forge_bof_sa-whoami` या `forge_bof_sa-netuser`।

BOFs के लिए याद रखें कि Forge Apollo को केवल एक flat argument string पास **नहीं** करता। यह BOF parameters को Mythic के typed-array format में map करता है और फिर उन्हें Apollo के `execute_coff` flow में forward करता है। यदि Forge-loaded BOF असामान्य व्यवहार करे, तो केवल आपके द्वारा typed command line की जांच करने के बजाय अपेक्षित BOF argument types / entrypoint की जांच करें। यह भी ध्यान दें कि Apollo के नए BOF loader ने बहुत पुराने 2.3.1-era builds की तुलना में argument handling बदल दी है, इसलिए केवल marshaling expectations बदलने के कारण stale BOFs या old collections fail हो सकते हैं।

### PowerShell & scripting execution

- `powershell_import`: बाद में execution के लिए agent cache में एक नई PowerShell script (.ps1) import करता है
- `powershell`: agent के context में एक PowerShell command execute करता है, जिससे advanced scripting और automation संभव होता है
- `powerpick`: एक sacrificial process में PowerShell loader assembly inject करता है और PowerShell command execute करता है (powershell logging के बिना)।
- `psinject`: एक specified process में PowerShell execute करता है, जिससे किसी अन्य process के context में scripts का targeted execution संभव होता है
- `shell`: agent के context में shell command execute करता है, जो cmd.exe में command चलाने के समान है

### Lateral Movement

- `jump_psexec`: पहले Apollo agent executable (apollo.exe) को copy करके और execute करके, PsExec technique का उपयोग कर नए host पर lateral movement करता है।
- `jump_wmi`: पहले Apollo agent executable (apollo.exe) को copy करके और execute करके, WMI technique का उपयोग कर नए host पर lateral movement करता है।
- `link` और `unlink`: callbacks के बीच P2P links (उदाहरण के लिए SMB/TCP पर) create और tear down करते हैं।
- `wmiexecute`: impersonation के लिए optional credentials का उपयोग करते हुए, WMI के माध्यम से local या specified remote system पर command execute करता है।
- `net_dclist`: specified domain के domain controllers की list retrieve करता है, जो lateral movement के लिए potential targets की पहचान करने में उपयोगी है।
- `net_localgroup`: specified computer पर local groups की list देता है; यदि कोई computer specified न हो, तो localhost को default मानता है।
- `net_localgroup_member`: local या remote computer पर specified group की local group membership retrieve करता है, जिससे specific groups में users की enumeration संभव होती है।
- `net_shares`: specified computer पर remote shares और उनकी accessibility की list देता है, जो lateral movement के लिए potential targets की पहचान करने में उपयोगी है।
- `socks`: target network पर SOCKS 5 compliant proxy enable करता है, जिससे compromised host के माध्यम से traffic tunneling संभव होती है। यह proxychains जैसे tools के साथ compatible है।
- `rpfwd`: target host पर specified port पर listening शुरू करता है और Mythic के माध्यम से traffic को remote IP और port पर forward करता है, जिससे target network पर services का remote access संभव होता है।
- `listpipes`: local system पर सभी named pipes की list देता है, जो IPC mechanisms के साथ interact करके lateral movement या privilege escalation के लिए उपयोगी हो सकती है।

`jump_wmi` या `wmiexecute` के underlying lower-level WMI execution primitives के लिए [WmiExec](lateral-movement/wmiexec.md) देखें। व्यापक pivoting patterns के लिए [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md) देखें।

### Miscellaneous Commands
- `help`: specific commands या agent में उपलब्ध सभी commands के बारे में detailed information display करता है।
- `clear`: tasks को 'cleared' के रूप में mark करता है, ताकि agents उन्हें pick up न कर सकें। सभी tasks clear करने के लिए `all` या किसी specific task को clear करने के लिए `task Num` specify कर सकते हैं।


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon एक Golang agent है जो **Linux और macOS** executables में compile होता है।
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Current build/profile notes

- वर्तमान Poseidon builds Linux और macOS को `x86_64` और `arm64` दोनों पर target करते हैं।
- Supported output formats में native executables के साथ-साथ `dylib` और `so` जैसे shared-library style outputs भी शामिल हैं।
- Poseidon `http`, `websocket`, `tcp`, और `dynamichttp` को support करता है, और वर्तमान builders `egress_order` तथा failover thresholds जैसी multi-egress settings expose करते हैं।
- Poseidon का वर्तमान capability metadata browser scripts, file/process browser integration, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd, और P2P को भी advertise करता है, इसलिए यह केवल simple remote shell के बजाय एक वास्तविक Linux/macOS pivot node के रूप में काम कर सकता है।
- जब आपको cleaner network behavior या अतिरिक्त Go binary obfuscation की आवश्यकता हो, तो `proxy_bypass` और `garble` जैसे build-time options जांचने योग्य हैं।
- Linux/macOS operations के लिए `pty` सबसे उपयोगी नए quality-of-life commands में से एक है, क्योंकि यह interactive PTY खोलता है और पुराने `sleep 0` + SOCKS workaround का सहारा लिए बिना अधिक पूर्ण terminal interaction के लिए Mythic-side port expose कर सकता है।
- Mythic-backed operations के लिए Poseidon के वर्तमान docs macOS-heavy tradecraft के संदर्भ में विशेष रूप से दिलचस्प हैं: `jxa`, `OSAScript` के माध्यम से JavaScript for Automation को in-memory execute करता है; `screencapture`, logged-in desktop को capture करता है; `clipboard_monitor`, pasteboard changes को stream करता है; `execute_library`, local dylib को load करके उसका कोई function call करता है; और `libinject`, किसी remote process को on-disk dylib load करने के लिए force करता है।
- लंबे समय तक चलने वाले jobs के लिए याद रखें कि Poseidon post-exploitation work को goroutines/threads में execute करता है, जिन्हें cooperative तरीके से terminate किया जाता है और hard-kill नहीं किया जा सकता। Docs यह भी स्पष्ट रूप से बताते हैं कि वर्तमान में built-in agent obfuscation उपलब्ध नहीं है, इसलिए heavily obfuscated commercial implants की तुलना में build/profile-level tradecraft अधिक महत्वपूर्ण है।

Mythic-backed operations, JAMF abuse, या MDM-as-C2 ideas के संदर्भ में macOS-specific tradecraft के लिए [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md) देखें।

Linux या macOS पर उपयोग किए जाने पर इसमें कुछ दिलचस्प commands हैं:

### Common actions

- `cat`: किसी file के contents print करता है
- `cd`: current working directory बदलता है
- `chmod`: किसी file की permissions बदलता है
- `config`: वर्तमान config और host information दिखाता है
- `cp`: किसी file को एक location से दूसरी location पर copy करता है
- `curl`: optional headers और method के साथ एक single web request execute करता है
- `upload`: target पर कोई file upload करता है
- `download`: target system से local machine पर कोई file download करता है
- और भी बहुत कुछ

### Search Sensitive Information

- `triagedirectory`: किसी host पर directory के भीतर interesting files खोजता है, जैसे sensitive files या credentials।
- `getenv`: वर्तमान सभी environment variables प्राप्त करता है।

### macOS-specific tradecraft

- `jxa`: `OSAScript` के माध्यम से JavaScript for Automation को in-memory execute करता है, जो अलग script files drop किए बिना native macOS post-exploitation के लिए उपयोगी है।
- `clipboard_monitor`: pasteboard को poll करता है और changes को Mythic में report करता है, जो copy/paste पर निर्भर credential/token theft workflows के लिए उपयोगी है।
- `screencapture`: macOS पर user के desktop को capture करता है।
- `execute_library`: disk से dylib load करता है और किसी specific exported function को call करता है।
- `libinject`: ऐसा shellcode stub inject करता है जो किसी अन्य macOS process को disk से dylib load करने के लिए force करता है।
- `persist_launchd`: सीधे agent से LaunchAgent / LaunchDaemon persistence create करता है।

### Move laterally

- `ssh`: designated credentials का उपयोग करके host पर SSH करता है और ssh spawn किए बिना PTY खोलता है।
- `sshauth`: designated credentials का उपयोग करके specified host(s) पर SSH करता है। इसका उपयोग remote hosts पर SSH के माध्यम से कोई specific command execute करने या files को SCP करने के लिए भी किया जा सकता है।
- `link_tcp`: TCP पर किसी अन्य agent से link करता है, जिससे agents के बीच direct communication संभव होता है।
- `link_webshell`: webshell P2P profile का उपयोग करके किसी agent से link करता है, जिससे agent के web interface तक remote access मिलता है।
- `rpfwd`: Reverse Port Forward को start या stop करता है, जिससे target network पर services तक remote access संभव होता है।
- `socks`: target network पर SOCKS5 proxy को start या stop करता है, जिससे compromised host के माध्यम से traffic tunnel किया जा सकता है। यह proxychains जैसे tools के साथ compatible है।
- `portscan`: open ports के लिए host(s) को scan करता है, जो lateral movement या आगे के attacks के लिए potential targets पहचानने में उपयोगी है।

### Process execution

- `shell`: `/bin/sh` के माध्यम से single shell command execute करता है, जिससे target system पर commands का direct execution संभव होता है।
- `run`: arguments के साथ disk से कोई command execute करता है, जिससे target system पर binaries या scripts execute की जा सकती हैं।
- `pty`: interactive PTY खोलता है, जिससे target system पर shell के साथ direct interaction संभव होता है।

## References

- [1] [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transforming Red Team Ops with Mythic's Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)

{{#include ../banners/hacktricks-training.md}}
