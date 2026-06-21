# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic ni nini?

Mythic ni framework ya open-source, modular, shirikishi ya command and control (C2) iliyoundwa kwa ajili ya red teaming. Inaruhusu operators kudhibiti na kusambaza agents (payloads) katika mifumo tofauti ya uendeshaji, ikiwemo Windows, Linux, na macOS. Mythic hutoa browser UI kwa multi-operator tasking, file handling, usimamizi wa SOCKS/rpfwd, na uundaji wa payload.

Tofauti na frameworks za monolithic, repository ya Mythic yenyewe **haileti** payload types au C2 profiles. Agents, wrappers, na C2 profiles kwa kawaida husakinishwa kama vipengele vya nje na vinaweza kusasishwa kwa kujitegemea kutoka kwa Mythic core.

### Installation

Ili kusakinisha Mythic, fuata maagizo kwenye official **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Bootstrap ya kawaida kutoka kwenye saraka ya Mythic ni:
```bash
sudo make
sudo ./mythic-cli start
```
Kama Mythic tayari inaendesha, kwa kawaida unaweza kuongeza agent au profile mpya kwa `./mythic-cli install github ...` kisha ama uanze upya Mythic au tuanzishe component mpya moja kwa moja.

### Agents

Mythic inaunga mkono agents wengi, ambao ni **payloads zinazofanya tasks kwenye systems zilizoathiriwa**. Kila agent inaweza kubinafsishwa kulingana na mahitaji maalum na inaweza kuendesha kwenye operating systems tofauti.

Kwa default Mythic haina agents zozote zilizosakinishwa. Agents za open-source community zipo katika [**https://github.com/MythicAgents**](https://github.com/MythicAgents), na [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) ni muhimu ili kuangalia haraka operating systems zinazoungwa mkono, payload formats, wrappers, na C2 profiles.

Ili kusakinisha agent kutoka org hiyo unaweza kuendesha:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Fomu ya `sudo -E` ni muhimu unapokuwa unasakinisha kutoka kwenye mazingira yasiyo ya root. Unaweza kuongeza agents mpya kwa amri ya awali hata ikiwa Mythic tayari inaendeshwa.

### C2 Profiles

C2 profiles katika Mythic hufafanua **jinsi agents wanavyowasiliana na Mythic server**. Hubainisha itifaki ya mawasiliano, mbinu za usimbaji fiche, na mipangilio mingine. Unaweza kuunda na kusimamia C2 profiles kupitia Mythic web interface.

Kwa chaguo-msingi Mythic husakinishwa bila profiles, hata hivyo, inawezekana kupakua baadhi ya profiles kutoka kwenye repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) inayoendeshwa:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): basic asynchronous GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): more flexible HTTP traffic with multiple callback domains, fail-over/round-robin rotation, custom headers/query parameters, and message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) placed in cookies, headers, query parameters, or body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-driven HTTP message shaping when the static `http` profile is too recognizable.

### Current platform notes

- Many public agents and profiles now install with pre-built remote container images.
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

- Apollo kwa sasa inaweza kutoa payloads za `WinExe`, `Shellcode`, `Service`, na `Source`.
- Profiles za Apollo zinazotumiwa sana ni `http`, `httpx`, `smb`, `tcp`, na `websocket`.
- `httpx` kwa kawaida ni chaguo lenye unyumbufu zaidi unapohitaji domain rotation, proxy support, custom message placement, na message transforms badala ya profile ya zamani tuli ya `http`.
- Apollo inaunga mkono wrapper payloads kama `service_wrapper` na `scarecrow_wrapper`.
- `register_file` na `register_assembly` ni staging primitives za `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, na `powerpick`. Katika current Apollo builds, artifacts hizo staged huhifadhiwa client-side kama DPAPI-protected AES256 blobs.
- Matokeo ya `ls` na `ps` yanaunganishwa hasa vizuri na Mythic browser scripts na file/process browser, jambo linalofanya operator triage iwe ya haraka zaidi kwa kiasi kinachoonekana katika collaborative operations.
- Apollo's fork-and-run jobs hurithi sacrificial process settings zao kutoka
`spawnto_x86` / `spawnto_x64`, hurithi parent selection kutoka `ppid`, na
kisha hutumia currently selected injection primitive. Kiutendaji, hii inamaanisha
OPSEC tuning yako kwa command moja mara nyingi huathiri `execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe`, na `spawn` kwa
wakati huohuo.
- Current documented Apollo injection backends ni pamoja na `CreateRemoteThread`,
`QueueUserAPC` (early-bird style), na `NtCreateThreadEx` kupitia syscalls. Tumia
`get_injection_techniques` kabla ya noisy post-exploitation na
`set_injection_technique` ikiwa unahitaji kubadilisha kutoka kwenye primitive
inayogongana na target au command unayotaka kuendesha.
- `blockdlls` huathiri tu sacrificial processes zilizoundwa kwa post-exploitation
jobs. Zikijumuishwa na `spawnto_x64` lengwa lisilo la kutiliwa shaka kuliko default
bare `rundll32.exe`, hii ni moja ya mabadiliko rahisi zaidi ya upande wa Apollo
kufanya kabla ya kuendesha assembly/PowerShell-heavy tasking.

This agent has a lot of commands that makes it very similar to Cobalt Strike's Beacon with some extras. Among them, it supports:

### Common actions

- `cat`: Chapisha contents za file
- `cd`: Badilisha current working directory
- `cp`: Nakili file kutoka location moja kwenda nyingine
- `ls`: Orodhesha files na directories kwenye current directory au specified path
- `ifconfig`: Pata network adapters na interfaces
- `netstat`: Pata TCP na UDP connection information
- `pwd`: Chapisha current working directory
- `ps`: Orodhesha running processes kwenye target system (na info ya ziada)
- `jobs`: Orodhesha all running jobs zinazohusiana na long-running tasking
- `download`: Pakua file kutoka target system kwenda local machine
- `upload`: Pakia file kutoka local machine kwenda target system
- `reg_query`: Uliza registry keys na values kwenye target system
- `reg_write_value`: Andika value mpya kwenye specified registry key
- `sleep`: Badilisha agent's sleep interval, ambayo huamua ni mara ngapi hujipigia check-in kwa Mythic server
- Na nyingine nyingi, tumia `help` kuona full list ya available commands.

### Privilege escalation

- `getprivs`: Washa privileges nyingi iwezekanavyo kwenye current thread token
- `getsystem`: Fungua handle kwa winlogon na duplicate token, kivitendo ukipandisha privileges hadi SYSTEM level
- `make_token`: Tengeneza new logon session na uitumie kwa agent, ikiruhusu impersonation ya user mwingine
- `steal_token`: Chukua primary token kutoka process nyingine, ikiruhusu agent kumwiga user wa process hiyo
- `pth`: Pass-the-Hash attack, ikiruhusu agent kuthibitisha kama user kwa kutumia NTLM hash yao bila kuhitaji plaintext password
- `mimikatz`: Endesha Mimikatz commands kutoa credentials, hashes, na taarifa nyingine nyeti kutoka memory au SAM database
- `rev2self`: Rudisha token ya agent kwenda primary token yake, kivitendo ikiondoa privileges kurudi kwenye kiwango cha asili
- `ppid`: Badilisha parent process kwa post-exploitation jobs kwa kubainisha new parent process ID, ikiruhusu udhibiti bora wa job execution context
- `printspoofer`: Endesha PrintSpoofer commands kupita security measures za print spooler, ikiruhusu privilege escalation au code execution
- `dcsync`: Sync Kerberos keys za user kwenda local machine, ikiruhusu offline password cracking au further attacks
- `ticket_cache_add`: Ongeza Kerberos ticket kwenye current logon session au iliyobainishwa, ikiruhusu ticket reuse au impersonation

### Process execution

- `assembly_inject`: Inaruhusu ku-inject .NET assembly loader ndani ya remote process
- `blockdlls`: Zuia non-Microsoft signed DLLs zisipakie ndani ya post-exploitation jobs
- `execute_assembly`: Hutekeleza .NET assembly katika context ya agent
- `execute_coff`: Hutekeleza COFF file in memory, ikiruhusu in-memory execution ya compiled code
- `execute_pe`: Hutekeleza unmanaged executable (PE)
- `keylog_inject`: Hu-inject keylogger ndani ya process nyingine na kutiririsha keystrokes kurudi kwenye Mythic's keylog view
- `screenshot` / `screenshot_inject`: Nasa current desktop moja kwa moja au
kwa ku-inject screenshot assembly ndani ya target process/session
- `get_injection_techniques`: Onyesha available injection techniques na iliyochaguliwa kwa sasa
- `inline_assembly`: Hutekeleza .NET assembly ndani ya disposable AppDomain, ikiruhusu execution ya muda ya code bila kuathiri main process ya agent
- `register_assembly`: Sajili .NET assembly kwa ajili ya execution ya baadaye
- `register_file`: Sajili file kwenye agent cache kwa ajili ya baadaye `execute_*` au PowerShell tasking
- `run`: Hutekeleza binary kwenye target system, ikitumia system's PATH kupata executable
- `set_injection_technique`: Badilisha injection primitive inayotumiwa na post-exploitation jobs
- `shinject`: Hu-inject shellcode ndani ya remote process, ikiruhusu in-memory execution ya arbitrary code
- `inject`: Hu-inject agent shellcode ndani ya remote process, ikiruhusu in-memory execution ya code ya agent
- `spawn`: Huzalisha new agent session kwenye specified executable, ikiruhusu execution ya shellcode kwenye new process
- `spawnto_x64` and `spawnto_x86`: Badilisha default binary inayotumiwa kwenye post-exploitation jobs iwe path iliyobainishwa badala ya kutumia `rundll32.exe` bila params ambayo ni very noisy.

### Mythic Forge

Hii inaruhusu **kupakia COFF/BOF** files kutoka Mythic Forge, ambayo ni repository ya pre-compiled payloads na tools zinazoweza kutekelezwa kwenye target system. Pamoja na commands zote zinazoweza kupakiwa itawezekana kufanya common actions kwa kuzitekeleza kwenye current agent process kama BOFs (kawaida zikiwa na better OPSEC kuliko kuanzisha process tofauti).

Anza kuziinstall kwa:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, tumia `forge_collections` kuonyesha COFF/BOF modules kutoka Mythic Forge ili uweze kuzichagua na kuzipakia kwenye memory ya agent kwa ajili ya execution. Kwa default, makusanyo 2 yafuatayo huongezwa katika Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Baada ya module moja kupakiwa, itaonekana kwenye list kama command nyingine kama `forge_bof_sa-whoami` au `forge_bof_sa-netuser`.

Kwa BOFs, kumbuka kuwa Forge haipitishi tu flat argument string moja
kwa Apollo. Inapanga BOF parameters kwenye Mythic's typed-array format na kisha
inazipitisha ndani ya Apollo's `execute_coff` flow. Ikiwa BOF iliyopakiwa kutoka Forge ina tabia
isiyo ya kawaida, kagua expected BOF argument types / entrypoint badala ya kuangalia tu
command line uliyoandika.

### PowerShell & scripting execution

- `powershell_import`: Hu-import script mpya ya PowerShell (.ps1) kwenye agent cache kwa ajili ya execution ya baadaye
- `powershell`: Hutekeleza PowerShell command katika context ya agent, ikiruhusu advanced scripting na automation
- `powerpick`: Huingiza PowerShell loader assembly kwenye sacrificial process na hutekeleza PowerShell command (bila powershell logging).
- `psinject`: Hutekeleza PowerShell katika process maalum, ikiruhusu targeted execution ya scripts katika context ya process nyingine
- `shell`: Hutekeleza shell command katika context ya agent, sawa na kuendesha command katika cmd.exe

### Lateral Movement

- `jump_psexec`: Hutumia technique ya PsExec kusonga laterally kwenda host mpya kwa kuanza kwa kunakili Apollo agent executable (apollo.exe) na kuiendesha.
- `jump_wmi`: Hutumia technique ya WMI kusonga laterally kwenda host mpya kwa kuanza kwa kunakili Apollo agent executable (apollo.exe) na kuiendesha.
- `link` and `unlink`: Huunda na kuvunja P2P links (kwa mfano kupitia SMB/TCP) kati ya callbacks.
- `wmiexecute`: Hutekeleza command kwenye local au specified remote system kwa kutumia WMI, na optional credentials za impersonation.
- `net_dclist`: Hupata list ya domain controllers kwa domain iliyobainishwa, muhimu kwa kutambua potential targets za lateral movement.
- `net_localgroup`: Huorodhesha local groups kwenye computer iliyobainishwa, kwa default localhost ikiwa hakuna computer iliyoainishwa.
- `net_localgroup_member`: Hupata local group membership kwa group iliyobainishwa kwenye local au remote computer, ikiruhusu enumeration ya users katika groups maalum.
- `net_shares`: Huorodhesha remote shares na accessibility yake kwenye computer iliyobainishwa, muhimu kwa kutambua potential targets za lateral movement.
- `socks`: Huwasha SOCKS 5 compliant proxy kwenye target network, ikiruhusu tunneling ya traffic kupitia compromised host. Inaoana na tools kama proxychains.
- `rpfwd`: Huanza kusikiliza kwenye port iliyobainishwa kwenye target host na kuelekeza traffic kupitia Mythic kwenda remote IP na port, ikiruhusu remote access kwa services kwenye target network.
- `listpipes`: Huorodhesha named pipes zote kwenye local system, ambazo zinaweza kuwa muhimu kwa lateral movement au privilege escalation kwa kuingiliana na IPC mechanisms.

Kwa lower-level WMI execution primitives zinazotumika chini ya `jump_wmi` au `wmiexecute`, angalia [WmiExec](lateral-movement/wmiexec.md). Kwa broader pivoting patterns, angalia [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Huonyesha taarifa za kina kuhusu commands maalum au taarifa za jumla kuhusu commands zote zinazopatikana katika agent.
- `clear`: Huweka tasks kuwa 'cleared' ili zisichukuliwe na agents. Unaweza kubainisha `all` ili kufuta tasks zote au `task Num` ili kufuta task maalum.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon ni Golang agent inayocompile kuwa **Linux and macOS** executables.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Maelezo ya sasa ya build/profile

- Current Poseidon builds zinalenga Linux na macOS kwenye `x86_64` na `arm64`.
- Miundo ya output inayoungwa mkono inajumuisha native executables pamoja na outputs za aina ya shared-library kama `dylib` na `so`.
- Poseidon inaunga mkono `http`, `websocket`, `tcp`, na `dynamichttp`, na current builders huonyesha mipangilio ya multi-egress kama `egress_order` na failover thresholds.
- Chaguzi za build-time kama `proxy_bypass` na `garble` zinafaa kuangalia unapohitaji tabia safi zaidi ya mtandao au Go binary obfuscation ya ziada.
- `pty` ni mojawapo ya commands mpya zenye manufaa zaidi kwa Linux/macOS
operations kwa sababu hufungua interactive PTY na inaweza kufichua port ya upande wa Mythic kwa ajili ya terminal interaction iliyo kamili zaidi bila kutumia njia ya zamani ya `sleep 0`
+ SOCKS workaround.
- Current docs za Poseidon zinavutia hasa kwa macOS-heavy
tradecraft: `jxa` hutekeleza JavaScript for Automation ndani ya memory,
`screencapture` hunasa desktop ya logged-in, `clipboard_monitor` hutiririsha mabadiliko ya pasteboard, `execute_library` hupakia local dylib na kuita
function kutoka humo, na `libinject` hulazimisha remote process kupakia on-disk
dylib.
- Kwa jobs za muda mrefu, kumbuka kuwa Poseidon hutekeleza post-exploitation work
kwa goroutines/threads ambazo ni cooperative badala ya hard-killable. Docs pia zinaonyesha wazi kwamba kwa sasa hakuna built-in agent
obfuscation, hivyo build/profile-level tradecraft ni muhimu zaidi kuliko ilivyo kwa heavily
obfuscated commercial implants.

Kwa macOS-specific tradecraft kuhusu Mythic-backed operations, JAMF abuse, au MDM-as-C2 ideas, angalia [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Inapotumiwa kwenye Linux au macOS ina commands za kuvutia:

### Common actions

- `cat`: Chapisha maudhui ya file
- `cd`: Badilisha current working directory
- `chmod`: Badilisha permissions za file
- `config`: Tazama current config na host information
- `cp`: Nakili file kutoka eneo moja kwenda jingine
- `curl`: Tekeleza web request moja yenye headers na method za hiari
- `upload`: Pakia file kwenda kwenye target
- `download`: Pakua file kutoka target system kwenda local machine
- Na mengine mengi

### Search Sensitive Information

- `triagedirectory`: Tafuta files za kuvutia ndani ya directory kwenye host, kama files nyeti au credentials.
- `getenv`: Pata current environment variables zote.

### macOS-specific tradecraft

- `jxa`: Tekeleza JavaScript for Automation ndani ya memory kupitia `OSAScript`, ambayo ni
muhimu kwa native macOS post-exploitation bila kuacha separate script
files.
- `clipboard_monitor`: Fuatilia pasteboard na ripoti mabadiliko kurudi kwa Mythic,
ambayo ni msaada kwa credential/token theft workflows zinazotegemea copy/paste.
- `screencapture`: Nasa desktop ya user kwenye macOS.
- `execute_library`: Pakia dylib kutoka disk na ita function maalum iliyo exported.
- `libinject`: Dunga shellcode stub inayolazimisha process nyingine ya macOS kupakia dylib kutoka disk.
- `persist_launchd`: Unda LaunchAgent / LaunchDaemon persistence moja kwa moja kutoka kwa agent.

### Move laterally

- `ssh`: Fanya SSH kwenda host kwa kutumia designated credentials na fungua PTY bila kuzalisha ssh.
- `sshauth`: Fanya SSH kwenda host(s) maalum kwa kutumia designated credentials. Unaweza pia kutumia hii kutekeleza command maalum kwenye remote hosts kupitia SSH au kuitumia ku SCP files.
- `link_tcp`: Unganisha na agent mwingine kupitia TCP, kuruhusu direct communication kati ya agents.
- `link_webshell`: Unganisha na agent kwa kutumia webshell P2P profile, kuruhusu remote access kwenye web interface ya agent.
- `rpfwd`: Anzisha au simamisha Reverse Port Forward, kuruhusu remote access kwenda services kwenye target network.
- `socks`: Anzisha au simamisha SOCKS5 proxy kwenye target network, kuruhusu tunneling ya traffic kupitia compromised host. Inaoana na tools kama proxychains.
- `portscan`: Skani host(s) kwa open ports, muhimu kwa kutambua potential targets za lateral movement au mashambulizi zaidi.

### Process execution

- `shell`: Tekeleza single shell command kupitia /bin/sh, kuruhusu direct execution ya commands kwenye target system.
- `run`: Tekeleza command kutoka disk pamoja na arguments, kuruhusu execution ya binaries au scripts kwenye target system.
- `pty`: Fungua interactive PTY, kuruhusu interaction ya moja kwa moja na shell kwenye target system.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
{{#include ../banners/hacktricks-training.md}}
