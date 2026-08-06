# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic ni nini?

Mythic ni framework ya open-source, modular, na shirikishi ya command and control (C2) iliyoundwa kwa ajili ya red teaming. Inawawezesha operators kusimamia na ku-deploy agents (payloads) kwenye operating systems tofauti, zikiwemo Windows, Linux, na macOS. Mythic hutoa browser UI kwa ajili ya tasking ya wa-operator wengi, ushughulikiaji wa files, usimamizi wa SOCKS/rpfwd, na utengenezaji wa payloads.

Tofauti na frameworks za monolithic, repository ya Mythic yenyewe **haisafirishi payload types au C2 profiles**. Agents, wrappers, na C2 profiles kwa kawaida husakinishwa kama components za nje na zinaweza kusasishwa bila kutegemea Mythic core.

### Usakinishaji

Ili kusakinisha Mythic, fuata maelekezo kwenye **[Mythic repo](https://github.com/its-a-feature/Mythic)** rasmi. Bootstrap ya kawaida kutoka kwenye directory ya Mythic ni:
```bash
sudo make
sudo ./mythic-cli start
```
Ikiwa Mythic tayari inaendeshwa, kwa kawaida unaweza kuongeza agent au profile mpya kwa kutumia `./mythic-cli install github ...`, kisha uanze upya Mythic au uanzishe tu component mpya moja kwa moja.

### Agents

Mythic inasaidia agents nyingi, ambazo ni **payloads zinazotekeleza kazi kwenye mifumo iliyoathiriwa**. Kila agent inaweza kubadilishwa kulingana na mahitaji maalum na inaweza kuendeshwa kwenye operating systems tofauti.

Kwa chaguo-msingi, Mythic haina agents zozote zilizosakinishwa. Agents za community ya open-source zinapatikana kwenye [**https://github.com/MythicAgents**](https://github.com/MythicAgents), na [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) ni muhimu kwa kuangalia kwa haraka operating systems zinazotumika, payload formats, wrappers, na C2 profiles.<sup>[[1]](#references)</sup>

Ili kusakinisha agent kutoka kwenye org hiyo, unaweza kuendesha:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Fomu ya `sudo -E` ni muhimu unaposakinisha kutoka katika mazingira yasiyo ya root. Unaweza kuongeza agents wapya kwa kutumia amri iliyotangulia hata kama Mythic tayari inaendeshwa.

### C2 Profiles

C2 profiles katika Mythic hufafanua **jinsi agents wanavyowasiliana na server ya Mythic**. Hubainisha protocol ya mawasiliano, mbinu za encryption, na mipangilio mingine. Unaweza kuunda na kudhibiti C2 profiles kupitia kiolesura cha wavuti cha Mythic.

Kwa chaguo-msingi, Mythic husakinishwa bila profiles, hata hivyo, inawezekana kupakua baadhi ya profiles kutoka kwenye repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) kwa kuendesha:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Wasifu muhimu kwa operator kwa sasa wa kuzingatia:

- [`http`](https://github.com/MythicC2Profiles/http): traffic ya msingi ya asynchronous GET/POST.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): traffic ya HTTP yenye unyumbufu zaidi, ikiwa na callback domains nyingi, fail-over/round-robin rotation, custom headers/query parameters, na message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) zinazowekwa kwenye cookies, headers, query parameters, au body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): uundaji wa HTTP messages unaoendeshwa na JSON/TOML wakati static `http` profile inapotambulika kwa urahisi.

### Maelezo ya sasa kuhusu platforms

- Public agents na profiles nyingi sasa hu-install kwa kutumia pre-built remote container images.
Ikiwa uta-fork component au kuifanyia patch locally na Mythic ikaendelea kutumia
behavior ya zamani, kagua entries za `.env` zilizotengenezwa kwa ajili ya
`*_REMOTE_IMAGE`, `*_USE_BUILD_CONTEXT`, na `*_USE_VOLUME`; kuwezesha
`*_USE_BUILD_CONTEXT="true"` kwa kawaida ndicho kinachofanya Mythic ijenge upya kutoka kwenye
local Docker context yako badala ya kutumia remote image kimya kimya.
- Browser scripts ni miongoni mwa features zenye thamani kubwa zaidi za Mythic za kurahisisha kazi
kwa operators: zinaweza kubadilisha command output ghafi kuwa tables, screenshot
viewers, download links, search links, na buttons zinazotuma follow-on
tasking moja kwa moja kutoka kwenye UI. Builds za sasa za Mythic zinamruhusu kila operator
kuhifadhi scripts zake mwenyewe, kuziwasha au kuzizima globally au per-task, na kupata matokeo bora
wakati agents zinaporejesha structured JSON badala ya plaintext. Hii ni muhimu hasa kwa workflows
zinazorudiwa za `ls`, `ps`, triage, na file-browser.<sup>[[4]](#references)[[6]](#references)</sup>
- Builds mpya za Mythic pia zinaunga mkono interactive tasking na Push C2 patterns
zinazopunguza hitaji la polling ya `sleep 0` wakati wa operations zenye PTY/SOCKS/rpfwd nyingi. Agent/profile
inapoiunga mkono, hii kwa kawaida huwa na overhead ndogo kuliko kuipiga server kwa
check-ins za mara kwa mara ili tu kuweka interactive channel ikiwa usable.<sup>[[3]](#references)</sup>
- Mythic builders za sasa za enzi ya 3.4 zina ufahamu mkubwa zaidi wa context kuliko writeups za zamani
zinavyodokeza: build parameters sasa zinaweza kugroupiwa au kufichwa kulingana na OS
iliyochaguliwa au build options nyingine, payload types zinaweza kutangaza kama zinaunga mkono
multiple C2 profiles au multiple instances za C2 hiyo hiyo katika build moja, na
C2 parameter deviations zinamruhusu agent kuficha fields ambazo haimplementi
hasa. Hili ni muhimu unapobadilishana kati ya `http`, `httpx`, `smb`,
`tcp`, na `websocket`, kwa sababu safe/valid build surface si form tuli ya flat tena.<sup>[[5]](#references)</sup>
- Ikiwa unaunda custom agent/profile pair na hutaki Mythic's
JSON message format au default crypto itumike kwenye wire, tumia
`translation_container`: Mythic huondoa UUID, kisha kumpa translator encrypted blob na key
material kupitia gRPC, na hutegemea irejeshe agent-native bytes. Hii ndiyo njia safi ya kusaidia
binary protocols, custom framing, au agent-side encryption bila kuandika upya server nzima.
- Kumbuka kuwa linked/P2P callbacks hazipitishi tasking pekee. Mythic's
`get_tasking` flow inaweza pia kubeba responses pamoja na `delegates`, `socks`,
`rpfwd`, na `interactive` data. Kwa vitendo, egress callback moja inaweza kuhudumia inner
callbacks na pivot channels katika polling loop hiyo hiyo; ikiwa child
agents zinafanya check-ins zao za mara kwa mara, `get_delegate_tasks=false` humzuia
parent kutumia kwa bahati mbaya queued jobs za inner callback.

### Wrapper payloads

Wrapper payloads zinakuruhusu kuweka agent logic ileile huku ukibadilisha on-disk representation inayowasilishwa au kuhifadhiwa.

- `service_wrapper`: hubadilisha payload nyingine kuwa Windows service executable, jambo linalofaa wakati execution path inahitaji service binary halali.
- `scarecrow_wrapper`: hufunga shellcode inayooana pamoja na ScareCrow loader ili kutengeneza outputs zinazotegemea loader kama vile EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo ni Windows agent iliyoandikwa kwa C# ikitumia 4.0 .NET Framework, iliyoundwa kutumiwa katika SpecterOps training offerings.<sup>[[2]](#references)</sup>

I-install kwa:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Maelezo ya sasa ya build/profile

- Apollo kwa sasa inaweza kutoa payload za `WinExe`, `Shellcode`, `Service`, na `Source`.
- Apollo profiles zinazotumiwa mara nyingi ni `http`, `httpx`, `smb`, `tcp`, na `websocket`.
- `httpx` kwa kawaida ndiyo chaguo linalonyumbulika zaidi unapohitaji domain rotation, proxy support, custom message placement, na message transforms badala ya `http` profile ya zamani na tuli.
- Apollo ni miongoni mwa community agents zilizo na vipengele vingi zaidi, na kwa sasa inatoa Mythic-side integrations kama browser scripts, file/process browser views, screenshots, keylogging, SOCKS, rpfwd, Push C2, na P2P routing.
- Apollo inasaidia wrapper payloads kama `service_wrapper` na `scarecrow_wrapper`.
- Apollo inasaidia dynamic command loading, hivyo unaweza kuweka payload ya mwanzo ikiwa ndogo na kupakia commands au Forge modules za ziada baadaye badala ya ku-compile kila post-ex capability ndani ya build ya kwanza.
- Unapotengeneza shellcode output, builder ya sasa ya Apollo pia inatoa Donut format choices (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) na Donut bypass behavior (`None`, `Abort on fail`, `Continue on fail`). Hii ni muhimu ikiwa lengo la mwisho ni ku-wrap tena shellcode kwa `service_wrapper`, `scarecrow_wrapper`, au custom loader.
- `register_file` na `register_assembly` ni staging primitives za `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, na `powerpick`. Katika Apollo builds za sasa, staged artifacts hizo huwekwa kwenye client-side cache kama AES256 blobs zilizolindwa na DPAPI.
- Matokeo ya `ls` na `ps` yanaunganishwa vizuri hasa na Mythic's browser scripts na file/process browser, jambo linalofanya operator triage iwe ya haraka zaidi katika collaborative operations.
- Apollo's fork-and-run jobs hurithi sacrificial process settings kutoka
`spawnto_x86` / `spawnto_x64`, hurithi parent selection kutoka `ppid`, na
kisha hutumia injection primitive iliyochaguliwa kwa sasa. Kwa vitendo, hii
inamaanisha OPSEC tuning yako kwa command moja mara nyingi huathiri
`execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe`, na `spawn` kwa
wakati mmoja.
- Apollo injection backends zilizoandikwa kwa sasa zinajumuisha `CreateRemoteThread`,
`QueueUserAPC` (early-bird style), na `NtCreateThreadEx` kupitia syscalls. Tumia
`get_injection_techniques` kabla ya noisy post-exploitation na
`set_injection_technique` ikiwa unahitaji kubadilisha kutoka primitive ambayo
haipatani na target au command unayotaka kuendesha.
- `blockdlls` huathiri tu sacrificial processes zilizoundwa kwa ajili ya post-exploitation
jobs. Ikiunganishwa na `spawnto_x64` target isiyo na mashaka mengi kuliko
`rundll32.exe` tupu ya default, hii ni mojawapo ya mabadiliko rahisi zaidi ya Apollo-side
ya kufanya kabla ya kuendesha assembly/PowerShell-heavy tasking.

Agent huyu ana commands nyingi zinazomfanya afanane sana na Cobalt Strike's Beacon pamoja na baadhi ya ziada. Miongoni mwa hizo, inasaidia:

### Vitendo vya kawaida

- `cat`: Chapisha yaliyomo kwenye file
- `cd`: Badilisha current working directory
- `cp`: Nakili file kutoka eneo moja hadi jingine
- `ls`: Orodhesha files na directories katika directory ya sasa au path iliyobainishwa
- `ifconfig`: Pata taarifa za network adapters na interfaces
- `netstat`: Pata taarifa za TCP na UDP connections
- `pwd`: Chapisha current working directory
- `ps`: Orodhesha processes zinazoendelea kwenye target system (pamoja na taarifa za ziada)
- `jobs`: Orodhesha jobs zote zinazoendelea zinazohusishwa na long-running tasking
- `download`: Pakua file kutoka target system hadi local machine
- `upload`: Pakia file kutoka local machine hadi target system
- `reg_query`: Uliza registry keys na values kwenye target system
- `reg_write_value`: Andika value mpya kwenye registry key iliyobainishwa
- `sleep`: Badilisha sleep interval ya agent, inayobainisha mara ngapi agent huwasiliana na Mythic server
- Na nyingine nyingi, tumia `help` kuona orodha kamili ya commands zinazopatikana.

### Privilege escalation

- `getprivs`: Wezesha privileges nyingi iwezekanavyo kwenye current thread token
- `getsystem`: Fungua handle kwa winlogon na duplicate token, hivyo kuongeza privileges hadi kiwango cha SYSTEM
- `make_token`: Unda logon session mpya na uitumie kwa agent, ikiruhusu impersonation ya user mwingine
- `steal_token`: Steal primary token kutoka process nyingine, ikiruhusu agent ku-impersonate user wa process hiyo
- `pth`: Pass-the-Hash attack, ikiruhusu agent ku-authenticate kama user kwa kutumia NTLM hash yake bila kuhitaji plaintext password
- `mimikatz`: Endesha Mimikatz commands ili kutoa credentials, hashes, na taarifa nyingine nyeti kutoka memory au SAM database
- `rev2self`: Rejesha token ya agent kwenye primary token yake, hivyo kuondoa privileges na kurudi kwenye kiwango cha awali
- `ppid`: Badilisha parent process kwa post-exploitation jobs kwa kubainisha parent process ID mpya, ikiruhusu udhibiti bora wa job execution context
- `printspoofer`: Endesha PrintSpoofer commands ili kupita print spooler security measures, ikiruhusu privilege escalation au code execution
- `dcsync`: Sync Kerberos keys za user kwenye local machine, ikiruhusu offline password cracking au attacks zaidi
- `ticket_cache_add`: Ongeza Kerberos ticket kwenye current logon session au session iliyobainishwa, ikiruhusu ticket reuse au impersonation

### Process execution

- `assembly_inject`: Huruhusu ku-inject .NET assembly loader kwenye remote process
- `blockdlls`: Zuia DLLs ambazo hazijasainiwa na Microsoft kupakiwa kwenye post-exploitation jobs
- `execute_assembly`: Endesha .NET assembly katika context ya agent
- `execute_coff`: Endesha COFF file kwenye memory, ikiruhusu in-memory execution ya compiled code
- `execute_pe`: Endesha unmanaged executable (PE)
- `keylog_inject`: Inject keylogger kwenye process nyingine na kutuma keystrokes kwa Mythic's keylog view
- `screenshot` / `screenshot_inject`: Nasa desktop ya sasa moja kwa moja au
kwa ku-inject screenshot assembly kwenye target process/session
- `get_injection_techniques`: Onyesha injection techniques zinazopatikana na iliyochaguliwa kwa sasa
- `inline_assembly`: Endesha .NET assembly kwenye disposable AppDomain, ikiruhusu code execution ya muda bila kuathiri main process ya agent
- `register_assembly`: Register .NET assembly kwa ajili ya execution baadaye
- `register_file`: Register file kwenye agent cache kwa ajili ya `execute_*` au PowerShell tasking baadaye
- `run`: Endesha binary kwenye target system, ukitumia system's PATH kutafuta executable
- `set_injection_technique`: Badilisha injection primitive inayotumiwa na post-exploitation jobs
- `shinject`: Inject shellcode kwenye remote process, ikiruhusu in-memory execution ya arbitrary code
- `inject`: Inject agent shellcode kwenye remote process, ikiruhusu in-memory execution ya agent's code
- `spawn`: Spawn new agent session kwenye executable iliyobainishwa, ikiruhusu execution ya shellcode kwenye process mpya
- `spawnto_x64` na `spawnto_x86`: Badilisha binary ya default inayotumiwa kwenye post-exploitation jobs iwe path iliyobainishwa badala ya kutumia `rundll32.exe` bila params, ambayo inaonekana sana.

### Mythic Forge

Hii inaruhusu **load COFF/BOF** files kutoka Mythic Forge, ambayo ni repository ya pre-compiled payloads na tools zinazoweza kutekelezwa kwenye target system. Kwa commands zote zinazoweza kupakiwa, itawezekana kufanya vitendo vya kawaida kwa kuzitekeleza kwenye current agent process kama BOFs (kwa kawaida zikiwa na OPSEC bora kuliko ku-spawn process tofauti).

Anza ku-install kwa:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Kisha, tumia `forge_collections` kuonyesha modules za COFF/BOF kutoka Mythic Forge ili uweze kuzichagua na kuzipakia kwenye memory ya agent kwa ajili ya execution. Kwa default, collections 2 zifuatazo huongezwa kwenye Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Baada ya module moja kupakiwa, itaonekana kwenye list kama command nyingine kama `forge_bof_sa-whoami` au `forge_bof_sa-netuser`.

Kwa BOFs, kumbuka kwamba Forge **haipitishi tu string moja bapa ya argument**
kwenye Apollo. Inabadilisha BOF parameters kuwa format ya typed-array ya Mythic na kisha
kuzipitisha kwenye flow ya `execute_coff` ya Apollo. Ikiwa BOF iliyopakiwa na Forge inafanya
mambo yasiyo ya kawaida, kagua BOF argument types / entrypoint inayotarajiwa badala ya kuangalia
tu command line uliyoandika. Pia kumbuka kwamba BOF loader mpya zaidi ya Apollo ilibadilisha
ushughulikiaji wa arguments ikilinganishwa na builds za zamani sana za enzi ya 2.3.1, hivyo BOFs
zilizopitwa na wakati au collections za zamani zinaweza kushindwa kwa sababu tu matarajio ya marshaling
yalibadilika.

### PowerShell & scripting execution

- `powershell_import`: Hu-import script mpya ya PowerShell (.ps1) kwenye agent cache kwa ajili ya execution baadaye
- `powershell`: Hu-execute PowerShell command katika context ya agent, ikiruhusu scripting na automation ya hali ya juu
- `powerpick`: Hu-inject assembly ya PowerShell loader kwenye sacrificial process na ku-execute PowerShell command (bila powershell logging).
- `psinject`: Hu-execute PowerShell kwenye process iliyobainishwa, ikiruhusu execution iliyolengwa ya scripts katika context ya process nyingine
- `shell`: Hu-execute shell command katika context ya agent, sawa na ku-run command kwenye cmd.exe

### Lateral Movement

- `jump_psexec`: Hutumia technique ya PsExec kusonga laterally hadi host mpya kwa kwanza kunakili executable ya Apollo agent (apollo.exe) na kuifanya i-execute.
- `jump_wmi`: Hutumia technique ya WMI kusonga laterally hadi host mpya kwa kwanza kunakili executable ya Apollo agent (apollo.exe) na kuifanya i-execute.
- `link` na `unlink`: Huunda na kuvunja P2P links (kwa mfano kupitia SMB/TCP) kati ya callbacks.
- `wmiexecute`: Hu-execute command kwenye mfumo wa local au remote uliobainishwa kwa kutumia WMI, ikiwa na credentials za hiari kwa impersonation.
- `net_dclist`: Huretrieve list ya domain controllers za domain iliyobainishwa, ambayo ni muhimu kwa kutambua targets zinazowezekana za lateral movement.
- `net_localgroup`: Huorodhesha local groups kwenye computer iliyobainishwa, na default ikiwa localhost ikiwa hakuna computer iliyobainishwa.
- `net_localgroup_member`: Huretrieve members wa local group iliyobainishwa kwenye computer ya local au remote, ikiruhusu enumeration ya users walio kwenye groups maalum.
- `net_shares`: Huorodhesha remote shares na accessibility yake kwenye computer iliyobainishwa, ambayo ni muhimu kwa kutambua targets zinazowezekana za lateral movement.
- `socks`: Hu-enable proxy inayofuata SOCKS 5 kwenye target network, ikiruhusu tunneling ya traffic kupitia compromised host. Inaendana na tools kama proxychains.
- `rpfwd`: Huanzisha listening kwenye port iliyobainishwa kwenye target host na ku-forward traffic kupitia Mythic hadi remote IP na port, ikiruhusu remote access kwa services zilizo kwenye target network.
- `listpipes`: Huorodhesha named pipes zote kwenye local system, ambazo zinaweza kuwa muhimu kwa lateral movement au privilege escalation kwa ku-interact na IPC mechanisms.

Kwa low-level WMI execution primitives zinazotumiwa chini ya `jump_wmi` au `wmiexecute`, angalia [WmiExec](lateral-movement/wmiexec.md). Kwa patterns pana za pivoting, angalia [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Huonyesha maelezo ya kina kuhusu commands maalum au maelezo ya jumla kuhusu commands zote zinazopatikana kwenye agent.
- `clear`: Hu-mark tasks kama 'cleared' ili agents zisiweze kuzipick up. Unaweza kubainisha `all` ili ku-clear tasks zote au `task Num` ili ku-clear task maalum.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon ni agent ya Golang inayocompile kuwa executables za **Linux na macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Maelezo ya sasa ya build/profile

- Builds za sasa za Poseidon zinalenga Linux na macOS kwenye `x86_64` na `arm64`.
- Miundo ya output inayotumika inajumuisha executables za native pamoja na miundo ya shared-library kama `dylib` na `so`.
- Poseidon inatumia `http`, `websocket`, `tcp`, na `dynamichttp`, na builders za sasa zinaonyesha mipangilio ya multi-egress kama `egress_order` na viwango vya failover.
- Metadata ya sasa ya capabilities za Poseidon pia inatangaza browser scripts, file/process browser integration, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd, na P2P, hivyo inaweza kufanya kazi kama pivot node halisi ya Linux/macOS badala ya remote shell rahisi tu.
- Chaguo za build-time kama `proxy_bypass` na `garble` zinafaa kuchunguzwa unapohitaji network behavior safi zaidi au Go binary obfuscation ya ziada.
- `pty` ni mojawapo ya commands mpya zenye manufaa zaidi kwa shughuli za Linux/macOS, kwa sababu hufungua PTY ya maingiliano na inaweza kufichua port ya upande wa Mythic kwa terminal interaction kamili zaidi bila kutumia workaround ya zamani ya `sleep 0` + SOCKS.
- Docs za Poseidon za sasa zinavutia hasa kwa macOS-heavy tradecraft: `jxa` hutekeleza JavaScript for Automation in-memory, `screencapture` hunasa desktop ya mtumiaji aliyeingia, `clipboard_monitor` hutuma mabadiliko ya pasteboard, `execute_library` hupakia dylib ya ndani na kuita function kutoka humo, na `libinject` hulazimisha remote process kupakia dylib iliyo kwenye disk.
- Kwa jobs zinazoendelea kwa muda mrefu, kumbuka kwamba Poseidon hutekeleza kazi za post-exploitation katika goroutines/threads zinazoshirikiana badala ya kuweza hard-kill. Docs pia zinaeleza wazi kwamba kwa sasa hakuna built-in agent obfuscation, hivyo tradecraft ya build/profile ni muhimu zaidi kuliko ilivyo kwa commercial implants zenye obfuscation kubwa.

Kwa macOS-specific tradecraft inayohusu operations zinazotegemea Mythic, matumizi mabaya ya JAMF, au mawazo ya MDM-as-C2, angalia [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Inapotumika kwenye Linux au macOS, ina commands kadhaa za kuvutia:

### Common actions

- `cat`: Chapisha yaliyomo kwenye file
- `cd`: Badilisha current working directory
- `chmod`: Badilisha permissions za file
- `config`: Tazama config ya sasa na taarifa za host
- `cp`: Nakili file kutoka eneo moja hadi jingine
- `curl`: Tekeleza web request moja yenye headers na method za hiari
- `upload`: Upload file kwenda kwenye target
- `download`: Download file kutoka kwenye target system kwenda kwenye local machine
- Na nyingine nyingi

### Search Sensitive Information

- `triagedirectory`: Tafuta files za kuvutia ndani ya directory kwenye host, kama files nyeti au credentials.
- `getenv`: Pata environment variables zote za sasa.

### macOS-specific tradecraft

- `jxa`: Tekeleza JavaScript for Automation in-memory kupitia `OSAScript`, ambayo ni muhimu kwa native macOS post-exploitation bila kuweka script files tofauti.
- `clipboard_monitor`: Poll pasteboard na kuripoti mabadiliko kwa Mythic, jambo linalofaa kwa credential/token theft workflows zinazotegemea copy/paste.
- `screencapture`: Capture desktop ya mtumiaji kwenye macOS.
- `execute_library`: Pakia dylib kutoka disk na kuita exported function maalum.
- `libinject`: Inject shellcode stub inayolazimisha macOS process nyingine kupakia dylib kutoka disk.
- `persist_launchd`: Unda persistence ya LaunchAgent / LaunchDaemon moja kwa moja kutoka kwa agent.

### Move laterally

- `ssh`: SSH kwenda kwenye host kwa kutumia credentials zilizoteuliwa na ufungue PTY bila ku-spawn ssh.
- `sshauth`: SSH kwenda kwenye host(s) maalum kwa kutumia credentials zilizoteuliwa. Unaweza pia kutumia hii kutekeleza command maalum kwenye remote hosts kupitia SSH au kuitumia SCP files.
- `link_tcp`: Link kwenda kwenye agent nyingine kupitia TCP, ikiruhusu direct communication kati ya agents.
- `link_webshell`: Link kwenda kwenye agent kwa kutumia webshell P2P profile, ikiruhusu remote access kwenye web interface ya agent.
- `rpfwd`: Anzisha au simamisha Reverse Port Forward, ikiruhusu remote access kwenye services za target network.
- `socks`: Anzisha au simamisha SOCKS5 proxy kwenye target network, ikiruhusu tunneling ya traffic kupitia compromised host. Inaoana na tools kama proxychains.
- `portscan`: Scan host(s) kwa ports zilizo wazi, ikiwa na manufaa katika kutambua potential targets kwa lateral movement au attacks zaidi.

### Process execution

- `shell`: Tekeleza shell command moja kupitia /bin/sh, ikiruhusu direct execution ya commands kwenye target system.
- `run`: Tekeleza command kutoka disk ikiwa na arguments, ikiruhusu execution ya binaries au scripts kwenye target system.
- `pty`: Fungua PTY ya maingiliano, ikiruhusu direct interaction na shell kwenye target system.

## References

- [1] [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transforming Red Team Ops with Mythic's Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)

{{#include ../banners/hacktricks-training.md}}
