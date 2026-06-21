# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic क्या है?

Mythic एक open-source, modular, collaborative command and control (C2) framework है, जिसे red teaming के लिए डिज़ाइन किया गया है। यह operators को अलग-अलग operating systems, जैसे Windows, Linux, और macOS, पर agents (payloads) को manage और deploy करने की सुविधा देता है। Mythic multi-operator tasking, file handling, SOCKS/rpfwd management, और payload generation के लिए browser UI प्रदान करता है।

Monolithic frameworks के विपरीत, Mythic repository स्वयं **payload types** या C2 profiles ship नहीं करता। Agents, wrappers, और C2 profiles आमतौर पर external components के रूप में install किए जाते हैं और Mythic core से independently update किए जा सकते हैं।

### Installation

Mythic install करने के लिए, official **[Mythic repo](https://github.com/its-a-feature/Mythic)** पर दिए गए instructions follow करें। Mythic directory से एक common bootstrap है:
```bash
sudo make
sudo ./mythic-cli start
```
अगर Mythic पहले से चल रहा है, तो आप आमतौर पर `./mythic-cli install github ...` के साथ एक नया agent या profile जोड़ सकते हैं, और फिर या तो Mythic को restart करें या सीधे नए component को start करें।

### Agents

Mythic multiple agents को support करता है, जो **payloads हैं जो compromised systems पर tasks perform करते हैं**. हर agent को specific needs के हिसाब से tailor किया जा सकता है और यह अलग-अलग operating systems पर run कर सकता है।

By default Mythic में कोई agents installed नहीं होते। open-source community agents [**https://github.com/MythicAgents**](https://github.com/MythicAgents) में available हैं, और [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) supported operating systems, payload formats, wrappers, और C2 profiles को जल्दी check करने के लिए useful है।

उस org से एक agent install करने के लिए आप चला सकते हैं:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
`sudo -E` फॉर्म non-root environment से install करते समय उपयोगी है। आप previous command से नए agents जोड़ सकते हैं, भले ही Mythic पहले से running हो।

### C2 Profiles

Mythic में C2 profiles यह define करती हैं कि **agents Mythic server के साथ कैसे communicate करते हैं**। ये communication protocol, encryption methods, और अन्य settings specify करती हैं। आप Mythic web interface के through C2 profiles create और manage कर सकते हैं।

By default Mythic बिना किसी profiles के install होता है, हालांकि repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) से कुछ profiles download करना possible है, running:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): basic asynchronous GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): more flexible HTTP traffic with multiple callback domains, fail-over/round-robin rotation, custom headers/query parameters, and message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) placed in cookies, headers, query parameters, or body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-driven HTTP message shaping when the static `http` profile is too recognizable.

### Current platform notes

- कई public agents and profiles now install with pre-built remote container images.
If you fork a component or patch it locally and Mythic keeps using the old
behavior, inspect the generated `.env` entries for `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT`, and `*_USE_VOLUME`; enabling
`*_USE_BUILD_CONTEXT="true"` is usually what makes Mythic rebuild from your
local Docker context instead of silently reusing the remote image.
- Browser scripts are one of Mythic's highest-value quality-of-life features
for operators: they can turn raw command output into tables, screenshot
viewers, download links, and buttons that issue follow-on tasking directly
from the UI. This is especially useful for repetitive `ls`, `ps`, triage,
and file-browser workflows.
- Newer Mythic builds also support interactive tasking and Push C2 patterns
that reduce the need for `sleep 0` polling during PTY/SOCKS/rpfwd-heavy
operations. When an agent/profile supports it, this is usually lower-overhead
than hammering the server with constant check-ins just to keep an interactive
channel usable.

### Wrapper payloads

Wrapper payloads let you keep the same agent logic while changing the on-disk representation that gets delivered or persisted.

- `service_wrapper`: turns another payload into a Windows service executable, which is useful when the execution path requires a valid service binary.
- `scarecrow_wrapper`: wraps compatible shellcode with the ScareCrow loader to generate loader-backed outputs such as EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo is a Windows agent written in C# using the 4.0 .NET Framework designed to be used in SpecterOps training offerings.

Install it with:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Apollo अभी `WinExe`, `Shellcode`, `Service`, और `Source` payloads emit कर सकता है।
- आमतौर पर इस्तेमाल होने वाले Apollo profiles हैं `http`, `httpx`, `smb`, `tcp`, और `websocket`।
- `httpx` आमतौर पर ज़्यादा flexible option होता है जब आपको domain rotation, proxy support, custom message placement, और message transforms चाहिए, पुराने static `http` profile की बजाय।
- Apollo `service_wrapper` और `scarecrow_wrapper` जैसे wrapper payloads support करता है।
- `register_file` और `register_assembly` `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, और `powerpick` के लिए staging primitives हैं। Current Apollo builds में, वे staged artifacts client-side DPAPI-protected AES256 blobs के रूप में cache होते हैं।
- `ls` और `ps` results खास तौर पर Mythic के browser scripts और file/process browser के साथ अच्छी तरह integrate होते हैं, जिससे collaborative operations में operator triage noticeably तेज़ हो जाता है।
- Apollo के fork-and-run jobs अपने sacrificial process settings `spawnto_x86` / `spawnto_x64` से inherit करते हैं, parent selection `ppid` से inherit करते हैं, और फिर currently selected injection primitive का उपयोग करते हैं। Practical तौर पर, इसका मतलब है कि एक command के लिए आपकी OPSEC tuning अक्सर `execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe`, और `spawn` को एक साथ प्रभावित करती है।
- Current documented Apollo injection backends में `CreateRemoteThread`, `QueueUserAPC` (early-bird style), और syscalls के ज़रिए `NtCreateThreadEx` शामिल हैं। Noisy post-exploitation से पहले `get_injection_techniques` का उपयोग करें, और अगर आपको ऐसे primitive से हटना हो जो target या उस command से clash करता हो जिसे आप run करना चाहते हैं, तो `set_injection_technique` का उपयोग करें।
- `blockdlls` केवल post-exploitation jobs के लिए बनाए गए sacrificial processes को affect करता है। Default bare `rundll32.exe` की तुलना में कम suspicious `spawnto_x64` target के साथ मिलाकर, Assembly/PowerShell-heavy tasking चलाने से पहले Apollo-side पर यह सबसे आसान changes में से एक है।

This agent के पास बहुत सारे commands हैं, जो इसे कुछ extras के साथ Cobalt Strike's Beacon जैसा बनाते हैं। इनमें यह support करता है:

### Common actions

- `cat`: एक file की contents print करता है
- `cd`: current working directory बदलता है
- `cp`: एक file को एक location से दूसरी location पर copy करता है
- `ls`: current directory या specified path में files और directories list करता है
- `ifconfig`: network adapters और interfaces प्राप्त करता है
- `netstat`: TCP और UDP connection information प्राप्त करता है
- `pwd`: current working directory print करता है
- `ps`: target system पर running processes list करता है (extra info के साथ)
- `jobs`: long-running tasking से जुड़े सभी running jobs list करता है
- `download`: target system से local machine पर एक file download करता है
- `upload`: local machine से target system पर एक file upload करता है
- `reg_query`: target system पर registry keys और values query करता है
- `reg_write_value`: specified registry key में नया value लिखता है
- `sleep`: agent का sleep interval बदलता है, जो तय करता है कि वह Mythic server को कितनी बार check in करता है
- और भी बहुत कुछ, available commands की पूरी list देखने के लिए `help` use करें।

### Privilege escalation

- `getprivs`: current thread token पर जितनी हो सकें उतनी privileges enable करता है
- `getsystem`: winlogon पर handle खोलता है और token duplicate करता है, effectively privileges को SYSTEM level तक escalate करता है
- `make_token`: नया logon session बनाता है और उसे agent पर apply करता है, जिससे दूसरे user की impersonation संभव होती है
- `steal_token`: दूसरे process से primary token चुराता है, जिससे agent उस process के user की impersonation कर सकता है
- `pth`: Pass-the-Hash attack, जिससे agent plaintext password की जरूरत के बिना user के NTLM hash का उपयोग करके authenticate कर सकता है
- `mimikatz`: Mimikatz commands run करता है ताकि memory या SAM database से credentials, hashes, और अन्य sensitive information निकाली जा सके
- `rev2self`: agent के token को उसके primary token पर revert करता है, effectively privileges को मूल level पर वापस drop करता है
- `ppid`: नया parent process ID specify करके post-exploitation jobs के लिए parent process बदलता है, जिससे job execution context पर बेहतर control मिलता है
- `printspoofer`: print spooler security measures bypass करने के लिए PrintSpoofer commands execute करता है, जिससे privilege escalation या code execution संभव होती है
- `dcsync`: user की Kerberos keys को local machine पर sync करता है, जिससे offline password cracking या आगे के attacks संभव होते हैं
- `ticket_cache_add`: current logon session या किसी specified session में Kerberos ticket add करता है, जिससे ticket reuse या impersonation संभव होती है

### Process execution

- `assembly_inject`: remote process में एक .NET assembly loader inject करने की अनुमति देता है
- `blockdlls`: post-exploitation jobs में गैर-Microsoft signed DLLs को load होने से रोकता है
- `execute_assembly`: agent के context में एक .NET assembly execute करता है
- `execute_coff`: memory में एक COFF file execute करता है, जिससे compiled code का in-memory execution संभव होता है
- `execute_pe`: एक unmanaged executable (PE) execute करता है
- `keylog_inject`: दूसरे process में keylogger inject करता है और keystrokes को वापस Mythic के keylog view में stream करता है
- `screenshot` / `screenshot_inject`: current desktop सीधे capture करता है या target process/session में screenshot assembly inject करके
- `get_injection_techniques`: available injection techniques और currently selected one दिखाता है
- `inline_assembly`: एक disposable AppDomain में .NET assembly execute करता है, जिससे agent के main process को प्रभावित किए बिना temporary code execution संभव होती है
- `register_assembly`: बाद में execution के लिए एक .NET assembly register करता है
- `register_file`: बाद में `execute_*` या PowerShell tasking के लिए agent cache में एक file register करता है
- `run`: executable को खोजने के लिए system के PATH का उपयोग करके target system पर एक binary execute करता है
- `set_injection_technique`: post-exploitation jobs द्वारा उपयोग किए जाने वाले injection primitive को बदलता है
- `shinject`: remote process में shellcode inject करता है, जिससे arbitrary code का in-memory execution संभव होता है
- `inject`: remote process में agent shellcode inject करता है, जिससे agent के code का in-memory execution संभव होता है
- `spawn`: specified executable में एक नया agent session spawn करता है, जिससे नए process में shellcode execution संभव होती है
- `spawnto_x64` और `spawnto_x86`: post-exploitation jobs में used default binary को `rundll32.exe` बिना params इस्तेमाल करने की बजाय specified path पर बदलते हैं, जो बहुत noisy होता है।

### Mythic Forge

यह Mythic Forge से **COFF/BOF** files load करने की अनुमति देता है, जो pre-compiled payloads और tools का repository है जिन्हें target system पर execute किया जा सकता है। जितने commands load किए जा सकते हैं, उनके साथ उन्हें current agent process में BOFs के रूप में execute करके common actions करना संभव होगा (आम तौर पर अलग process spawn करने की तुलना में बेहतर OPSEC के साथ)।

इन्हें install करना शुरू करें:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, `forge_collections` का उपयोग करके Mythic Forge से COFF/BOF modules दिखाएँ ताकि उन्हें चुनकर execution के लिए agent की memory में load किया जा सके। By default, Apollo में निम्न 2 collections जोड़े जाते हैं:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

एक बार कोई module load हो जाने पर, वह list में `forge_bof_sa-whoami` या `forge_bof_sa-netuser` जैसी दूसरी command के रूप में दिखेगा।

BOFs के लिए, याद रखें कि Forge **सिर्फ** Apollo को एक flat argument string पास नहीं करता। यह BOF parameters को Mythic के typed-array format में map करता है और फिर उन्हें Apollo के `execute_coff` flow में forward करता है। अगर कोई Forge-loaded BOF अजीब तरह से behave करे, तो केवल command line पर ध्यान देने के बजाय expected BOF argument types / entrypoint check करें।

### PowerShell & scripting execution

- `powershell_import`: बाद में execution के लिए agent cache में एक नया PowerShell script (.ps1) import करता है
- `powershell`: agent के context में PowerShell command execute करता है, जिससे advanced scripting और automation संभव होती है
- `powerpick`: एक PowerShell loader assembly को sacrificial process में inject करता है और PowerShell command execute करता है (without powershell logging).
- `psinject`: निर्दिष्ट process में PowerShell execute करता है, जिससे दूसरे process के context में scripts का targeted execution संभव होता है
- `shell`: agent के context में shell command execute करता है, cmd.exe में command चलाने जैसा

### Lateral Movement

- `jump_psexec`: पहले Apollo agent executable (apollo.exe) को copy करके और उसे execute करके PsExec technique का उपयोग करते हुए नए host पर laterally move करता है
- `jump_wmi`: पहले Apollo agent executable (apollo.exe) को copy करके और उसे execute करके WMI technique का उपयोग करते हुए नए host पर laterally move करता है
- `link` and `unlink`: callbacks के बीच P2P links बनाता और हटाता है (उदाहरण के लिए SMB/TCP पर)
- `wmiexecute`: optional credentials for impersonation के साथ WMI का उपयोग करके local या specified remote system पर command execute करता है
- `net_dclist`: निर्दिष्ट domain के लिए domain controllers की list प्राप्त करता है, lateral movement के लिए संभावित targets पहचानने में उपयोगी
- `net_localgroup`: निर्दिष्ट computer पर local groups list करता है, अगर कोई computer specified न हो तो defaulting to localhost
- `net_localgroup_member`: specified group के लिए local group membership प्राप्त करता है, local या remote computer पर, specific groups में users की enumeration की अनुमति देता है
- `net_shares`: specified computer पर remote shares और उनकी accessibility list करता है, lateral movement के लिए संभावित targets पहचानने में उपयोगी
- `socks`: target network पर SOCKS 5 compliant proxy सक्षम करता है, compromised host के through traffic tunneling की अनुमति देता है। proxychains जैसे tools के साथ compatible
- `rpfwd`: target host पर specified port पर listening शुरू करता है और Mythic के through traffic को remote IP और port पर forward करता है, जिससे target network पर services तक remote access संभव होता है
- `listpipes`: local system पर सभी named pipes list करता है, जो IPC mechanisms के साथ interact करके lateral movement या privilege escalation के लिए उपयोगी हो सकता है

नीचे उपयोग किए गए lower-level WMI execution primitives के लिए, `jump_wmi` या `wmiexecute` के नीचे, [WmiExec](lateral-movement/wmiexec.md) देखें। broader pivoting patterns के लिए, [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md) देखें।

### Miscellaneous Commands
- `help`: agent में सभी available commands के बारे में या किसी specific command के बारे में detailed information दिखाता है
- `clear`: tasks को 'cleared' के रूप में mark करता है ताकि agents उन्हें pick up न कर सकें। आप सभी tasks clear करने के लिए `all` या किसी specific task को clear करने के लिए `task Num` specify कर सकते हैं


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon एक Golang agent है जो **Linux और macOS** executables में compile होता है।
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Current build/profile notes

- Current Poseidon builds target Linux and macOS on both `x86_64` and `arm64`.
- Supported output formats include native executables plus shared-library style outputs such as `dylib` and `so`.
- Poseidon supports `http`, `websocket`, `tcp`, and `dynamichttp`, and current builders expose multi-egress settings such as `egress_order` and failover thresholds.
- Build-time options such as `proxy_bypass` and `garble` are worth checking when you need either cleaner network behavior or extra Go binary obfuscation.
- `pty` is one of the most useful newer-quality-of-life commands for Linux/macOS
operations because it opens an interactive PTY and can expose a Mythic-side
port for fuller terminal interaction without resorting to the older `sleep 0`
+ SOCKS workaround.
- Poseidon's current docs are especially interesting for macOS-heavy
tradecraft: `jxa` executes JavaScript for Automation in-memory,
`screencapture` grabs the logged-in desktop, `clipboard_monitor` streams
pasteboard changes, `execute_library` loads a local dylib and calls a
function from it, and `libinject` forces a remote process to load an on-disk
dylib.
- For long-running jobs, remember that Poseidon executes post-exploitation work
in goroutines/threads that are cooperative rather than hard-killable. The
docs also explicitly note that there is currently no built-in agent
obfuscation, so build/profile-level tradecraft matters more than with heavily
obfuscated commercial implants.

For macOS-specific tradecraft around Mythic-backed operations, JAMF abuse, or MDM-as-C2 ideas, check [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

When used on Linux or macOS it has some interesting commands:

### Common actions

- `cat`: किसी फ़ाइल की सामग्री प्रिंट करें
- `cd`: वर्तमान working directory बदलें
- `chmod`: किसी फ़ाइल की permissions बदलें
- `config`: current config और host information देखें
- `cp`: किसी फ़ाइल को एक location से दूसरी location पर copy करें
- `curl`: optional headers और method के साथ single web request execute करें
- `upload`: target पर एक फ़ाइल upload करें
- `download`: target system से local machine पर एक फ़ाइल download करें
- और कई अन्य

### Search Sensitive Information

- `triagedirectory`: host पर किसी directory के भीतर दिलचस्प फ़ाइलें ढूँढें, जैसे sensitive files या credentials.
- `getenv`: सभी current environment variables प्राप्त करें.

### macOS-specific tradecraft

- `jxa`: `OSAScript` के जरिए in-memory JavaScript for Automation execute करें, जो
native macOS post-exploitation के लिए useful है बिना अलग script
files drop किए.
- `clipboard_monitor`: pasteboard को poll करें और changes वापस Mythic को report करें,
जो copy/paste पर निर्भर credential/token theft workflows के लिए handy है.
- `screencapture`: macOS पर user का desktop capture करें.
- `execute_library`: disk से एक dylib load करें और उसमें से एक specific exported function call करें.
- `libinject`: एक shellcode stub inject करें जो किसी दूसरी macOS process को disk से एक dylib load करने के लिए मजबूर करे.
- `persist_launchd`: agent से सीधे LaunchAgent / LaunchDaemon persistence बनाएं.

### Move laterally

- `ssh`: designated credentials का उपयोग करके host पर SSH करें और ssh spawn किए बिना एक PTY खोलें.
- `sshauth`: designated credentials का उपयोग करके specified host(s) पर SSH करें. आप इसका उपयोग remote hosts पर SSH के जरिए specific command execute करने के लिए भी कर सकते हैं या files SCP करने के लिए भी.
- `link_tcp`: TCP के जरिए दूसरे agent से link करें, जिससे agents के बीच direct communication संभव हो.
- `link_webshell`: webshell P2P profile का उपयोग करके किसी agent से link करें, जिससे agent के web interface तक remote access मिल सके.
- `rpfwd`: Reverse Port Forward शुरू या बंद करें, जिससे target network पर services तक remote access मिल सके.
- `socks`: target network पर SOCKS5 proxy शुरू या बंद करें, जिससे compromised host के through traffic tunneling संभव हो. proxychains जैसे tools के साथ compatible.
- `portscan`: host(s) पर open ports scan करें, lateral movement या आगे के attacks के लिए potential targets पहचानने में useful.

### Process execution

- `shell`: `/bin/sh` के जरिए एक single shell command execute करें, जिससे target system पर commands directly run की जा सकें.
- `run`: arguments के साथ disk से एक command execute करें, जिससे target system पर binaries या scripts execute किए जा सकें.
- `pty`: एक interactive PTY खोलें, जिससे target system पर shell के साथ direct interaction किया जा सके.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
{{#include ../banners/hacktricks-training.md}}
