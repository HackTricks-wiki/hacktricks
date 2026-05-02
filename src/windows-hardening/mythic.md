# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic क्या है?

Mythic एक open-source, modular, collaborative command and control (C2) framework है, जिसे red teaming के लिए डिज़ाइन किया गया है। यह operators को अलग-अलग operating systems, including Windows, Linux, and macOS, पर agents (payloads) को manage और deploy करने की सुविधा देता है। Mythic multi-operator tasking, file handling, SOCKS/rpfwd management, और payload generation के लिए browser UI प्रदान करता है।

Monolithic frameworks के विपरीत, Mythic repository स्वयं **does not** payload types या C2 profiles ship नहीं करता। Agents, wrappers, और C2 profiles आमतौर पर external components के रूप में install किए जाते हैं और Mythic core से independently update किए जा सकते हैं।

### Installation

Mythic install करने के लिए, official **[Mythic repo](https://github.com/its-a-feature/Mythic)** पर दिए गए instructions का पालन करें। Mythic directory से एक common bootstrap यह है:
```bash
sudo make
sudo ./mythic-cli start
```
अगर Mythic पहले से चल रहा है, तो आप आम तौर पर `./mythic-cli install github ...` के साथ एक नया agent या profile जोड़ सकते हैं और फिर या तो Mythic को restart करें या सीधे नए component को शुरू करें।

### Agents

Mythic कई agents को support करता है, जो **payloads हैं जो compromised systems पर tasks perform करते हैं**। हर agent को specific needs के अनुसार tailor किया जा सकता है और वह अलग-अलग operating systems पर चल सकता है।

By default Mythic में कोई agents installed नहीं होते। open-source community agents [**https://github.com/MythicAgents**](https://github.com/MythicAgents) में मिलते हैं, और [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) supported operating systems, payload formats, wrappers, और C2 profiles को जल्दी check करने के लिए useful है।

उस org से एक agent install करने के लिए आप चला सकते हैं:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
`sudo -E` form तब उपयोगी है जब आप non-root environment से install कर रहे हों। आप पिछले command से नए agents जोड़ सकते हैं, भले ही Mythic पहले से चल रहा हो।

### C2 Profiles

Mythic में C2 profiles यह define करते हैं कि **agents Mythic server के साथ कैसे communicate करते हैं**। वे communication protocol, encryption methods, और अन्य settings specify करते हैं। आप Mythic web interface के जरिए C2 profiles create और manage कर सकते हैं।

By default Mythic बिना किसी profiles के install होता है, हालांकि repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) से कुछ profiles download करना possible है, running:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): basic asynchronous GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): multiple callback domains, fail-over/round-robin rotation, custom headers/query parameters, और message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) के साथ अधिक flexible HTTP traffic, जिन्हें cookies, headers, query parameters, या body में रखा जा सकता है।
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-driven HTTP message shaping जब static `http` profile बहुत recognizable हो।

### Wrapper payloads

Wrapper payloads आपको वही agent logic बनाए रखते हुए on-disk representation बदलने देते हैं, जो delivered या persisted होती है।

- `service_wrapper`: दूसरे payload को Windows service executable में बदल देता है, जो तब उपयोगी है जब execution path को valid service binary चाहिए।
- `scarecrow_wrapper`: compatible shellcode को ScareCrow loader के साथ wrap करता है ताकि EXE/DLL/CPL जैसे loader-backed outputs बनाए जा सकें।

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo एक Windows agent है, जो C# में लिखा गया है और 4.0 .NET Framework का उपयोग करता है, तथा SpecterOps training offerings में उपयोग के लिए बनाया गया है।

इसे इस तरह install करें:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Apollo अभी `WinExe`, `Shellcode`, `Service`, और `Source` payloads emit कर सकता है।
- आम तौर पर इस्तेमाल होने वाले Apollo profiles हैं `http`, `httpx`, `smb`, `tcp`, और `websocket`।
- जब domain rotation, proxy support, custom message placement, और message transforms की जरूरत हो, तो पुराना static `http` profile की बजाय `httpx` आम तौर पर ज्यादा flexible option होता है।
- Apollo `service_wrapper` और `scarecrow_wrapper` जैसे wrapper payloads support करता है।
- `register_file` और `register_assembly` `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, और `powerpick` के लिए staging primitives हैं। Current Apollo builds में, ये staged artifacts client-side DPAPI-protected AES256 blobs के रूप में cache होते हैं।
- `ls` और `ps` results, Mythic के browser scripts और file/process browser के साथ खास तौर पर अच्छी तरह integrate होते हैं, जिससे collaborative operations में operator triage noticeably faster हो जाता है।

इस agent में बहुत सारे commands हैं, जो इसे कुछ extras के साथ Cobalt Strike के Beacon के काफी समान बनाते हैं। इनमें यह support करता है:

### Common actions

- `cat`: किसी file की contents print करें
- `cd`: current working directory बदलें
- `cp`: एक file को एक location से दूसरी location पर copy करें
- `ls`: current directory या specified path में files और directories list करें
- `ifconfig`: network adapters और interfaces देखें
- `netstat`: TCP और UDP connection information देखें
- `pwd`: current working directory print करें
- `ps`: target system पर running processes list करें (extra info के साथ)
- `jobs`: long-running tasking से जुड़े सभी running jobs list करें
- `download`: target system से local machine पर file download करें
- `upload`: local machine से target system पर file upload करें
- `reg_query`: target system पर registry keys और values query करें
- `reg_write_value`: specified registry key में नया value write करें
- `sleep`: agent का sleep interval बदलें, जो तय करता है कि वह कितनी बार Mythic server से check in करेगा
- और बहुत कुछ, full list of available commands देखने के लिए `help` use करें।

### Privilege escalation

- `getprivs`: current thread token पर जितनी संभव हों उतनी privileges enable करें
- `getsystem`: winlogon पर handle खोलें और token duplicate करें, जिससे privileges effectively SYSTEM level तक escalate हो जाती हैं
- `make_token`: नया logon session बनाएं और उसे agent पर apply करें, जिससे दूसरे user की impersonation संभव हो
- `steal_token`: किसी दूसरे process से primary token चुराएं, जिससे agent उस process के user की impersonation कर सके
- `pth`: Pass-the-Hash attack, जिससे plaintext password की जरूरत के बिना agent किसी user की NTLM hash से authenticate कर सके
- `mimikatz`: credentials, hashes, और memory या SAM database से अन्य sensitive information निकालने के लिए Mimikatz commands चलाएं
- `rev2self`: agent के token को उसके primary token पर revert करें, जिससे privileges वापस original level पर आ जाती हैं
- `ppid`: नया parent process ID specify करके post-exploitation jobs के लिए parent process बदलें, जिससे job execution context पर बेहतर control मिले
- `printspoofer`: print spooler security measures bypass करने के लिए PrintSpoofer commands चलाएं, जिससे privilege escalation या code execution संभव हो
- `dcsync`: किसी user की Kerberos keys को local machine पर sync करें, जिससे offline password cracking या आगे के attacks संभव हों
- `ticket_cache_add`: current logon session या specified session में Kerberos ticket जोड़ें, जिससे ticket reuse या impersonation संभव हो

### Process execution

- `assembly_inject`: remote process में .NET assembly loader inject करने की अनुमति देता है
- `blockdlls`: post-exploitation jobs में non-Microsoft signed DLLs के loading को block करें
- `execute_assembly`: agent के context में एक .NET assembly execute करता है
- `execute_coff`: memory में COFF file execute करता है, जिससे compiled code का in-memory execution संभव होता है
- `execute_pe`: एक unmanaged executable (PE) execute करता है
- `get_injection_techniques`: उपलब्ध injection techniques और currently selected one दिखाएं
- `inline_assembly`: disposable AppDomain में एक .NET assembly execute करता है, जिससे agent के main process को प्रभावित किए बिना code का temporary execution संभव होता है
- `register_assembly`: बाद में execution के लिए एक .NET assembly register करें
- `register_file`: बाद में `execute_*` या PowerShell tasking के लिए agent cache में एक file register करें
- `run`: system के PATH का उपयोग करके executable ढूंढते हुए target system पर binary execute करता है
- `set_injection_technique`: post-exploitation jobs द्वारा उपयोग की जाने वाली injection primitive बदलें
- `shinject`: remote process में shellcode inject करता है, जिससे arbitrary code का in-memory execution संभव होता है
- `inject`: remote process में agent shellcode inject करता है, जिससे agent के code का in-memory execution संभव होता है
- `spawn`: specified executable में एक नया agent session spawn करता है, जिससे नए process में shellcode execute किया जा सके
- `spawnto_x64` और `spawnto_x86`: `rundll32.exe` without params का उपयोग करने की बजाय post-exploitation jobs में उपयोग होने वाले default binary को specified path पर बदलें, जो बहुत noisy है।

### Mythic Forge

यह आपको Mythic Forge से **load COFF/BOF** files करने देता है, जो pre-compiled payloads और tools का एक repository है जिन्हें target system पर execute किया जा सकता है। जितने भी commands load किए जा सकते हैं, उनके साथ current agent process में उन्हें BOFs के रूप में execute करके common actions perform करना संभव होगा (आम तौर पर separate process spawn करने की तुलना में बेहतर OPSEC के साथ)।

इन्हें install करना शुरू करें:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, `forge_collections` का उपयोग करके Mythic Forge से COFF/BOF modules दिखाएँ ताकि उन्हें चुनकर execution के लिए agent की memory में load किया जा सके। Default रूप से, Apollo में निम्न 2 collections जोड़ी जाती हैं:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

एक module load होने के बाद, वह list में `forge_bof_sa-whoami` या `forge_bof_sa-netuser` जैसी एक और command के रूप में दिखाई देगा।

### PowerShell & scripting execution

- `powershell_import`: बाद में execution के लिए agent cache में एक नया PowerShell script (.ps1) import करता है
- `powershell`: agent के context में एक PowerShell command execute करता है, जिससे advanced scripting और automation संभव होती है
- `powerpick`: एक PowerShell loader assembly को sacrificial process में inject करता है और एक PowerShell command execute करता है (बिना powershell logging के)
- `psinject`: निर्दिष्ट process में PowerShell execute करता है, जिससे दूसरे process के context में scripts को targeted execution के लिए चलाया जा सकता है
- `shell`: agent के context में एक shell command execute करता है, जो cmd.exe में command चलाने जैसा है

### Lateral Movement

- `jump_psexec`: PsExec technique का उपयोग करके एक नए host पर laterally move करता है, पहले Apollo agent executable (apollo.exe) को copy करके और फिर उसे execute करके
- `jump_wmi`: WMI technique का उपयोग करके एक नए host पर laterally move करता है, पहले Apollo agent executable (apollo.exe) को copy करके और फिर उसे execute करके
- `link` और `unlink`: callbacks के बीच P2P links बनाता और हटाता है (उदाहरण के लिए SMB/TCP के माध्यम से)
- `wmiexecute`: WMI का उपयोग करके local या निर्दिष्ट remote system पर command execute करता है, impersonation के लिए optional credentials के साथ
- `net_dclist`: निर्दिष्ट domain के लिए domain controllers की सूची प्राप्त करता है, जो lateral movement के संभावित targets की पहचान के लिए उपयोगी है
- `net_localgroup`: निर्दिष्ट computer पर local groups की सूची देता है, और यदि कोई computer निर्दिष्ट नहीं है तो localhost default होता है
- `net_localgroup_member`: निर्दिष्ट group के लिए local group membership को local या remote computer पर प्राप्त करता है, जिससे specific groups में users की enumeration की जा सकती है
- `net_shares`: निर्दिष्ट computer पर remote shares और उनकी accessibility की सूची देता है, जो lateral movement के संभावित targets की पहचान के लिए उपयोगी है
- `socks`: target network पर SOCKS 5 compliant proxy सक्षम करता है, जिससे compromised host के through traffic tunneling संभव होता है। proxychains जैसे tools के साथ compatible है
- `rpfwd`: target host पर निर्दिष्ट port पर listening शुरू करता है और traffic को Mythic के through remote IP और port तक forward करता है, जिससे target network पर services तक remote access संभव होता है
- `listpipes`: local system पर सभी named pipes की सूची देता है, जो IPC mechanisms के साथ interact करके lateral movement या privilege escalation के लिए उपयोगी हो सकता है

नीचे वाले WMI execution primitives के लिए जो `jump_wmi` या `wmiexecute` के अंदर उपयोग होते हैं, [WmiExec](lateral-movement/wmiexec.md) देखें। broader pivoting patterns के लिए, [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md) देखें।

### Miscellaneous Commands
- `help`: specific commands या agent में उपलब्ध सभी commands के बारे में विस्तृत जानकारी दिखाता है
- `clear`: tasks को 'cleared' के रूप में mark करता है ताकि agents उन्हें pick up न कर सकें। आप सभी tasks clear करने के लिए `all` या किसी specific task को clear करने के लिए `task Num` specify कर सकते हैं


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon एक Golang agent है जो **Linux and macOS** executables में compile होता है।
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### वर्तमान build/profile नोट्स

- Current Poseidon builds Linux और macOS दोनों पर `x86_64` और `arm64` को target करते हैं।
- Supported output formats में native executables के साथ-साथ `dylib` और `so` जैसे shared-library style outputs शामिल हैं।
- Poseidon `http`, `websocket`, `tcp`, और `dynamichttp` को support करता है, और current builders `egress_order` और failover thresholds जैसे multi-egress settings expose करते हैं।
- `proxy_bypass` और `garble` जैसे build-time options देखने लायक हैं जब आपको cleaner network behavior या extra Go binary obfuscation चाहिए।

For macOS-specific tradecraft around Mythic-backed operations, JAMF abuse, or MDM-as-C2 ideas, check [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

जब इसे Linux या macOS पर उपयोग किया जाता है, तो इसमें कुछ दिलचस्प commands हैं:

### Common actions

- `cat`: किसी file की contents print करें
- `cd`: current working directory बदलें
- `chmod`: किसी file की permissions बदलें
- `config`: current config और host information देखें
- `cp`: किसी file को एक location से दूसरी location पर copy करें
- `curl`: optional headers और method के साथ एक single web request execute करें
- `upload`: target पर एक file upload करें
- `download`: target system से local machine पर एक file download करें
- और भी बहुत कुछ

### Search Sensitive Information

- `triagedirectory`: host पर किसी directory के भीतर interesting files ढूँढें, जैसे sensitive files या credentials।
- `getenv`: current environment variables सभी प्राप्त करें।

### Move laterally

- `ssh`: designated credentials का उपयोग करके host पर SSH करें और ssh spawn किए बिना एक PTY open करें।
- `sshauth`: designated credentials का उपयोग करके specified host(s) पर SSH करें। आप इसे remote hosts पर SSH के जरिए कोई specific command execute करने के लिए भी use कर सकते हैं या files SCP करने के लिए भी।
- `link_tcp`: TCP over दूसरे agent से link करें, जिससे agents के बीच direct communication संभव हो।
- `link_webshell`: webshell P2P profile का उपयोग करके agent से link करें, जिससे agent के web interface तक remote access मिल सके।
- `rpfwd`: Reverse Port Forward शुरू या stop करें, जिससे target network पर services तक remote access मिल सके।
- `socks`: target network पर SOCKS5 proxy शुरू या stop करें, जिससे compromised host के through traffic tunneling हो सके। proxychains जैसे tools के साथ compatible।
- `portscan`: host(s) पर खुले ports scan करें, lateral movement या आगे के attacks के लिए potential targets identify करने में उपयोगी।

### Process execution

- `shell`: /bin/sh के जरिए एक single shell command execute करें, जिससे target system पर commands सीधे execute की जा सकें।
- `run`: arguments के साथ disk से एक command execute करें, जिससे target system पर binaries या scripts execute की जा सकें।
- `pty`: एक interactive PTY खोलें, जिससे target system पर shell के साथ direct interaction हो सके।




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
{{#include ../banners/hacktricks-training.md}}
