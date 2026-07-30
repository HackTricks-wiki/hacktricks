# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic ni nini?

Mythic ni mfumo wa command and control (C2) wa open-source, modular na shirikishi ulioundwa kwa ajili ya red teaming. Unawawezesha operators kusimamia na ku-deploy agents (payloads) kwenye operating systems mbalimbali, zikiwemo Windows, Linux na macOS. Mythic hutoa browser UI kwa ajili ya multi-operator tasking, kushughulikia files, usimamizi wa SOCKS/rpfwd na kutengeneza payloads.

Tofauti na frameworks za monolithic, Mythic repository yenyewe **haisafirishi payload types au C2 profiles**. Agents, wrappers na C2 profiles kwa kawaida huwekwa kama external components na zinaweza kusasishwa bila kutegemea Mythic core.

### Installation

Ili kusakinisha Mythic, fuata maelekezo kwenye **[Mythic repo](https://github.com/its-a-feature/Mythic)** rasmi. Bootstrap ya kawaida kutoka kwenye Mythic directory ni:
```bash
sudo make
sudo ./mythic-cli start
```
Ikiwa Mythic tayari inaendesha, kwa kawaida unaweza kuongeza agent au profile mpya kwa `./mythic-cli install github ...`, kisha uanze upya Mythic au uanzishe moja kwa moja component mpya.

### Agents

Mythic inasaidia agents wengi, ambao ni **payloads zinazotekeleza tasks kwenye systems zilizoathiriwa**. Kila agent inaweza kubinafsishwa kulingana na mahitaji mahususi na inaweza kuendeshwa kwenye operating systems tofauti.

Kwa chaguo-msingi, Mythic haina agents zilizosakinishwa. Agents za open-source kutoka community zinapatikana kwenye [**https://github.com/MythicAgents**](https://github.com/MythicAgents), na [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) ni muhimu kwa kuangalia kwa haraka operating systems, payload formats, wrappers, na C2 profiles zinazotumika.

Ili kusakinisha agent kutoka kwenye org hiyo, unaweza kuendesha:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Aina ya `sudo -E` ni muhimu unaposakinisha kutoka kwenye mazingira yasiyo ya root. Unaweza kuongeza agents wapya kwa kutumia amri ya awali hata kama Mythic tayari inaendeshwa.

### C2 Profiles

C2 profiles katika Mythic hufafanua **jinsi agents wanavyowasiliana na seva ya Mythic**. Zinabainisha itifaki ya mawasiliano, mbinu za usimbaji fiche na mipangilio mingine. Unaweza kuunda na kudhibiti C2 profiles kupitia kiolesura cha wavuti cha Mythic.

Kwa chaguo-msingi, Mythic husakinishwa bila profiles, hata hivyo, inawezekana kupakua baadhi ya profiles kutoka kwenye repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) kwa kuendesha:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Wasifu muhimu kwa operator wa sasa wa kuzingatia:

- [`http`](https://github.com/MythicC2Profiles/http): traffic ya msingi ya asynchronous GET/POST.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): traffic ya HTTP yenye unyumbufu zaidi, ikiwa na callback domains nyingi, fail-over/round-robin rotation, custom headers/query parameters, na message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) zinazowekwa kwenye cookies, headers, query parameters, au body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): uundaji wa HTTP messages unaoendeshwa na JSON/TOML wakati static `http` profile inapotambulika kwa urahisi sana.

### Maelezo ya sasa kuhusu platforms

- Public agents na profiles nyingi sasa husakinishwa kwa kutumia pre-built remote container images.
Ikiwa unafanya fork ya component au kuifanyia patch locally na Mythic inaendelea kutumia
tabia ya zamani, kagua entries za `.env` zilizozalishwa za `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT`, na `*_USE_VOLUME`; kuwasha
`*_USE_BUILD_CONTEXT="true"` kwa kawaida ndiko kunakofanya Mythic ijenge upya kutoka kwenye
Docker context yako ya local badala ya kutumia kimya kimya remote image ya zamani.
- Browser scripts ni miongoni mwa features zenye thamani kubwa zaidi za Mythic za kuboresha matumizi
kwa operators: zinaweza kubadilisha command output ghafi kuwa tables, screenshot
viewers, download links, search links, na buttons zinazotuma follow-on
tasking moja kwa moja kutoka kwenye UI. Builds za sasa za Mythic humruhusu kila operator kuhifadhi
scripts zake, kuziwasha au kuzizima globally au kwa kila task, na kupata matokeo bora zaidi
wakati agents zinaporudisha structured JSON badala ya plaintext. Hii ni muhimu hasa kwa workflows
zinazorudiwa za `ls`, `ps`, triage, na file-browser.
- Builds mpya za Mythic pia zinaunga mkono interactive tasking na Push C2 patterns
zinazopunguza hitaji la polling ya `sleep 0` wakati wa operations zinazotumia PTY/SOCKS/rpfwd kwa wingi. Wakati agent/profile inaiunga mkono, hii kwa kawaida hutumia overhead ndogo
kuliko kuipiga server mara kwa mara kwa check-ins za kudumu ili tu kuweka interactive
channel ikiwa inatumika.
- Mythic builders za sasa za enzi ya 3.4 zina uelewa zaidi wa context kuliko writeups za zamani
zinavyodokeza: build parameters sasa zinaweza kupangwa katika groups au kufichwa kulingana na OS
iliyochaguliwa au build options nyingine, payload types zinaweza kutangaza kama zinaunga mkono
C2 profiles nyingi au instances nyingi za C2 ileile katika build moja, na
C2 parameter deviations huruhusu agent kuficha fields ambazo kwa kweli haizitekelezi. Hili ni muhimu
unapobadilishana kati ya `http`, `httpx`, `smb`,
`tcp`, na `websocket`, kwa sababu safe/valid build surface si
flat static form tena.
- Ikiwa unaunda custom agent/profile pair na hutaki Mythic's
JSON message format au default crypto ionekane kwenye wire, tumia
`translation_container`: Mythic huondoa UUID, hukabidhi encrypted blob na key
material kwa translator kupitia gRPC, na hutegemea agent-native bytes
zirudishwe. Hii ndiyo njia safi ya kuunga mkono binary protocols, custom framing,
au agent-side encryption bila kuandika upya server yote.
- Kumbuka kwamba linked/P2P callbacks hazipitishi tasking pekee. Mythic's
`get_tasking` flow inaweza pia kubeba responses pamoja na `delegates`,
`socks`, `rpfwd`, na `interactive` data. Kwa vitendo, egress callback moja inaweza kuhudumia
inner callbacks na pivot channels katika polling loop ileile; ikiwa child
agents zinafanya check-ins zao za mara kwa mara, `get_delegate_tasks=false` huizuia
parent kutumia kimakosa jobs zilizowekwa kwenye queue ya inner callback.

### Wrapper payloads

Wrapper payloads hukuruhusu kuhifadhi agent logic ileile huku ukibadilisha representation iliyo kwenye disk ambayo inatumwa au kuhifadhiwa.

- `service_wrapper`: hubadilisha payload nyingine kuwa Windows service executable, jambo ambalo ni muhimu wakati execution path inahitaji service binary halali.
- `scarecrow_wrapper`: hufunga shellcode inayooana pamoja na ScareCrow loader ili kutengeneza outputs zinazotegemea loader kama EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo ni agent ya Windows iliyoandikwa kwa C# ikitumia 4.0 .NET Framework, iliyoundwa kutumiwa katika offerings za mafunzo za SpecterOps.

Isakinishe kwa kutumia:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Maelezo ya sasa ya build/profile

- Apollo kwa sasa inaweza kutoa payload za `WinExe`, `Shellcode`, `Service`, na `Source`.
- Apollo profiles zinazotumika kwa kawaida ni `http`, `httpx`, `smb`, `tcp`, na `websocket`.
- `httpx` kwa kawaida ndiyo chaguo linalobadilika zaidi unapohitaji domain rotation, proxy support, custom message placement, na message transforms badala ya `http profile` ya zamani isiyobadilika.
- Apollo ni mojawapo ya community agents zilizo na vipengele vingi zaidi, na kwa sasa hutoa Mythic-side integrations kama browser scripts, file/process browser views, screenshots, keylogging, SOCKS, rpfwd, Push C2, na P2P routing.
- Apollo inasaidia wrapper payloads kama `service_wrapper` na `scarecrow_wrapper`.
- Apollo inasaidia dynamic command loading, hivyo unaweza kuweka initial payload ikiwa ndogo na kupakia commands au Forge modules za ziada baadaye badala ya ku-compile kila post-ex capability ndani ya build ya kwanza.
- Unapotengeneza shellcode output, builder ya sasa ya Apollo pia hutoa Donut format choices (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) na Donut bypass behavior (`None`, `Abort on fail`, `Continue on fail`). Hii ni muhimu ikiwa lengo la mwisho ni kuifunga tena shellcode kwa `service_wrapper`, `scarecrow_wrapper`, au custom loader.
- `register_file` na `register_assembly` ni staging primitives za `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, na `powerpick`. Katika Apollo builds za sasa, staged artifacts hizo huhifadhiwa client-side kama DPAPI-protected AES256 blobs.
- Matokeo ya `ls` na `ps` yanaunganishwa vizuri sana na browser scripts na file/process browser ya Mythic, jambo linalofanya operator triage iwe ya haraka zaidi katika collaborative operations.
- Apollo's fork-and-run jobs hurithi sacrificial process settings kutoka
`spawnto_x86` / `spawnto_x64`, hurithi parent selection kutoka `ppid`, na
kisha hutumia injection primitive iliyochaguliwa kwa sasa. Kwa vitendo, hii inamaanisha
OPSEC tuning yako kwa command moja mara nyingi huathiri `execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe`, na `spawn` kwa
wakati mmoja.
- Apollo injection backends zilizorekodiwa kwa sasa zinajumuisha `CreateRemoteThread`,
`QueueUserAPC` (early-bird style), na `NtCreateThreadEx` kupitia syscalls. Tumia
`get_injection_techniques` kabla ya noisy post-exploitation na
`set_injection_technique` ikiwa unahitaji kubadilisha kutoka primitive ambayo
haipatani na target au command unayotaka kuendesha.
- `blockdlls` huathiri tu sacrificial processes zinazoundwa kwa post-exploitation
jobs. Ikiunganishwa na `spawnto_x64` target isiyo na mashaka mengi kuliko default
bare `rundll32.exe`, hii ni mojawapo ya mabadiliko rahisi zaidi ya Apollo-side
ya kufanya kabla ya kuendesha assembly/PowerShell-heavy tasking.

Agent hii ina commands nyingi zinazoifanya ifanane sana na Cobalt Strike's Beacon ikiwa na ziada kadhaa. Miongoni mwa hizo, inasaidia:

### Common actions

- `cat`: Chapisha yaliyomo kwenye file
- `cd`: Badilisha current working directory
- `cp`: Nakili file kutoka location moja hadi nyingine
- `ls`: Orodhesha files na directories katika directory ya sasa au path iliyobainishwa
- `ifconfig`: Pata network adapters na interfaces
- `netstat`: Pata taarifa za TCP na UDP connections
- `pwd`: Chapisha current working directory
- `ps`: Orodhesha processes zinazoendelea kwenye target system (ikiwa na taarifa za ziada)
- `jobs`: Orodhesha jobs zote zinazoendelea zinazohusiana na long-running tasking
- `download`: Pakua file kutoka target system hadi local machine
- `upload`: Pakia file kutoka local machine hadi target system
- `reg_query`: Query registry keys na values kwenye target system
- `reg_write_value`: Andika value mpya kwenye registry key iliyobainishwa
- `sleep`: Badilisha sleep interval ya agent, inayoamua mara ngapi inafanya check-in na Mythic server
- Na nyingine nyingi, tumia `help` kuona list kamili ya commands zinazopatikana.

### Privilege escalation

- `getprivs`: Wezesha privileges nyingi iwezekanavyo kwenye current thread token
- `getsystem`: Fungua handle kwa winlogon na duplicate token, jambo linaloongeza privileges hadi kiwango cha SYSTEM
- `make_token`: Tengeneza logon session mpya na uitumie kwa agent, ikiruhusu impersonation ya user mwingine
- `steal_token`: Iba primary token kutoka process nyingine, ikiruhusu agent ku-impersonate user wa process hiyo
- `pth`: Pass-the-Hash attack, inayoruhusu agent ku-authenticate kama user kwa kutumia NTLM hash yake bila kuhitaji plaintext password
- `mimikatz`: Endesha Mimikatz commands za kutoa credentials, hashes, na taarifa nyingine nyeti kutoka memory au SAM database
- `rev2self`: Rejesha token ya agent kwenye primary token yake, jambo linaloondoa privileges na kuirudisha kwenye kiwango cha awali
- `ppid`: Badilisha parent process ya post-exploitation jobs kwa kubainisha parent process ID mpya, ikiruhusu udhibiti bora wa job execution context
- `printspoofer`: Endesha PrintSpoofer commands za kupita print spooler security measures, ikiruhusu privilege escalation au code execution
- `dcsync`: Sync Kerberos keys za user kwenye local machine, ikiruhusu offline password cracking au attacks zaidi
- `ticket_cache_add`: Ongeza Kerberos ticket kwenye current logon session au session iliyobainishwa, ikiruhusu ticket reuse au impersonation

### Process execution

- `assembly_inject`: Huruhusu ku-inject .NET assembly loader kwenye remote process
- `blockdlls`: Zuia DLLs ambazo hazijasainiwa na Microsoft kupakiwa kwenye post-exploitation jobs
- `execute_assembly`: Tekeleza .NET assembly katika context ya agent
- `execute_coff`: Tekeleza COFF file kwenye memory, ikiruhusu in-memory execution ya compiled code
- `execute_pe`: Tekeleza unmanaged executable (PE)
- `keylog_inject`: Inject keylogger kwenye process nyingine na kutuma keystrokes kwenye Mythic's keylog view
- `screenshot` / `screenshot_inject`: Piga picha ya desktop ya sasa moja kwa moja au
kwa ku-inject screenshot assembly kwenye target process/session
- `get_injection_techniques`: Onyesha injection techniques zinazopatikana na iliyochaguliwa kwa sasa
- `inline_assembly`: Tekeleza .NET assembly kwenye disposable AppDomain, ikiruhusu temporary execution ya code bila kuathiri main process ya agent
- `register_assembly`: Register .NET assembly kwa ajili ya execution baadaye
- `register_file`: Register file kwenye agent cache kwa ajili ya `execute_*` au PowerShell tasking baadaye
- `run`: Tekeleza binary kwenye target system, ukitumia system's PATH kutafuta executable
- `set_injection_technique`: Badilisha injection primitive inayotumiwa na post-exploitation jobs
- `shinject`: Inject shellcode kwenye remote process, ikiruhusu in-memory execution ya arbitrary code
- `inject`: Inject agent shellcode kwenye remote process, ikiruhusu in-memory execution ya agent's code
- `spawn`: Spawn new agent session kwenye executable iliyobainishwa, ikiruhusu execution ya shellcode katika process mpya
- `spawnto_x64` na `spawnto_x86`: Badilisha default binary inayotumiwa katika post-exploitation jobs iwe path iliyobainishwa badala ya kutumia `rundll32.exe` bila params, hali ambayo ina noise nyingi.

### Mythic Forge

Hii inaruhusu **load COFF/BOF** files kutoka Mythic Forge, ambayo ni repository ya pre-compiled payloads na tools zinazoweza kutekelezwa kwenye target system. Kwa commands zote zinazoweza kupakiwa, itawezekana kufanya common actions kwa kuzitekeleza katika current agent process kama BOFs (kwa kawaida ikiwa na OPSEC bora kuliko ku-spawn process tofauti).

Anza ku-install kwa:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Kisha, tumia `forge_collections` kuonyesha modules za COFF/BOF kutoka Mythic Forge ili uweze kuzichagua na kuzipakia kwenye memory ya agent kwa ajili ya execution. Kwa chaguo-msingi, collections 2 zifuatazo huongezwa kwenye Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Baada ya module moja kupakiwa, itaonekana kwenye orodha kama command nyingine, kama `forge_bof_sa-whoami` au `forge_bof_sa-netuser`.

Kwa BOFs, kumbuka kwamba Forge **haipitishi** string moja tambarare ya arguments kwenda Apollo. Hu-map BOF parameters kuwa katika format ya typed-array ya Mythic, kisha huzipitisha kwenye flow ya Apollo ya `execute_coff`. Ikiwa BOF iliyopakiwa na Forge inafanya kazi kwa njia isiyo ya kawaida, kagua BOF argument types / entrypoint zinazotarajiwa badala ya kuangalia tu command line uliyoandika. Pia kumbuka kwamba BOF loader mpya zaidi ya Apollo ilibadilisha ushughulikiaji wa arguments ikilinganishwa na builds za zamani sana za enzi ya 2.3.1, hivyo BOFs zilizopitwa na wakati au collections za zamani zinaweza kushindwa kwa sababu tu matarajio ya marshaling yalibadilika.

### PowerShell & scripting execution

- `powershell_import`: Hu-import PowerShell script mpya (.ps1) kwenye agent cache kwa ajili ya execution ya baadaye
- `powershell`: Hu-execute PowerShell command katika context ya agent, ikiruhusu scripting na automation ya hali ya juu
- `powerpick`: Hu-inject PowerShell loader assembly kwenye sacrificial process na ku-execute PowerShell command (bila powershell logging).
- `psinject`: Hu-execute PowerShell kwenye process maalum, ikiruhusu execution inayolengwa ya scripts katika context ya process nyingine
- `shell`: Hu-execute shell command katika context ya agent, sawa na ku-run command kwenye cmd.exe

### Lateral Movement

- `jump_psexec`: Hutumia technique ya PsExec kufanya lateral movement kwenda host mpya kwa kunakili kwanza Apollo agent executable (apollo.exe) na kuiexecute.
- `jump_wmi`: Hutumia technique ya WMI kufanya lateral movement kwenda host mpya kwa kunakili kwanza Apollo agent executable (apollo.exe) na kuiexecute.
- `link` na `unlink`: Huunda na kuvunja P2P links (kwa mfano kupitia SMB/TCP) kati ya callbacks.
- `wmiexecute`: Hu-execute command kwenye local system au remote system iliyobainishwa kwa kutumia WMI, ikiwa na credentials za hiari kwa ajili ya impersonation.
- `net_dclist`: Huretrieve orodha ya domain controllers za domain iliyobainishwa, ikiwa na manufaa kwa kutambua targets zinazowezekana za lateral movement.
- `net_localgroup`: Huorodhesha local groups kwenye computer iliyobainishwa, na kwa chaguo-msingi hutumia localhost ikiwa hakuna computer iliyobainishwa.
- `net_localgroup_member`: Huretrieve uanachama wa local group maalum kwenye computer ya local au remote, hivyo kuruhusu enumeration ya users walio kwenye groups maalum.
- `net_shares`: Huorodhesha remote shares na accessibility yake kwenye computer iliyobainishwa, ikiwa na manufaa kwa kutambua targets zinazowezekana za lateral movement.
- `socks`: Hu-enable proxy inayotii SOCKS 5 kwenye target network, ikiruhusu tunneling ya traffic kupitia host iliyo-compromise. Inaendana na tools kama proxychains.
- `rpfwd`: Huanzisha kusikiliza kwenye port iliyobainishwa kwenye target host na ku-forward traffic kupitia Mythic kwenda remote IP na port, hivyo kuruhusu remote access kwa services kwenye target network.
- `listpipes`: Huorodhesha named pipes zote kwenye local system, ambazo zinaweza kuwa na manufaa kwa lateral movement au privilege escalation kupitia interaction na IPC mechanisms.

Kwa primitives za kiwango cha chini za WMI execution zinazotumika chini ya `jump_wmi` au `wmiexecute`, angalia [WmiExec](lateral-movement/wmiexec.md). Kwa patterns pana za pivoting, angalia [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Huonyesha maelezo ya kina kuhusu commands maalum au maelezo ya jumla kuhusu commands zote zinazopatikana kwenye agent.
- `clear`: Hu-mark tasks kama 'cleared' ili agents zisiweze kuzichukua. Unaweza kubainisha `all` ili ku-clear tasks zote au `task Num` ili ku-clear task maalum.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon ni agent ya Golang inayocompile kuwa executables za **Linux na macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Maelezo ya sasa ya build/profile

- Builds za sasa za Poseidon zinalenga Linux na macOS kwenye `x86_64` na `arm64`.
- Miundo ya output inayotumika inajumuisha executables za native pamoja na miundo ya shared-library kama `dylib` na `so`.
- Poseidon inasaidia `http`, `websocket`, `tcp`, na `dynamichttp`, na builders za sasa zinaonyesha mipangilio ya multi-egress kama `egress_order` na failover thresholds.
- Metadata ya sasa ya uwezo wa Poseidon pia inatangaza browser scripts, file/process browser integration, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd, na P2P, hivyo inaweza kufanya kazi kama pivot node halisi ya Linux/macOS badala ya kuwa remote shell rahisi tu.
- Chaguo za wakati wa build kama `proxy_bypass` na `garble` zinafaa kuchunguzwa unapohitaji network behavior iliyo safi zaidi au Go binary obfuscation ya ziada.
- `pty` ni mojawapo ya commands mpya zenye manufaa zaidi za kuboresha matumizi kwenye Linux/macOS
operations kwa sababu hufungua PTY shirikishi na inaweza kuweka port ya upande wa Mythic
kwa ajili ya terminal interaction pana zaidi bila kutumia workaround ya zamani ya `sleep 0`
+ SOCKS.
- Docs za Poseidon za sasa zinavutia hasa kwa tradecraft inayolenga macOS:
  `jxa` hutekeleza JavaScript for Automation ndani ya memory,
  `screencapture` huchukua picha ya desktop iliyo logged-in,
  `clipboard_monitor` hutuma mabadiliko ya pasteboard,
  `execute_library` hupakia dylib ya local na kuita
  function kutoka humo, na `libinject` hulazimisha process ya mbali
  kupakia dylib iliyo kwenye disk.
- Kwa jobs zinazoendelea kwa muda mrefu, kumbuka kwamba Poseidon hutekeleza kazi za post-exploitation
  kwenye goroutines/threads zinazoshirikiana badala ya kukatizwa kwa nguvu. Docs
  pia zinaeleza wazi kwamba kwa sasa hakuna agent
  obfuscation iliyojengwa ndani, hivyo tradecraft ya kiwango cha build/profile ni muhimu zaidi
  kuliko ilivyo kwa implants za kibiashara zilizo na obfuscation kubwa.

Kwa tradecraft maalum ya macOS inayohusu operations zinazoendeshwa na Mythic, matumizi mabaya ya JAMF, au mawazo ya MDM-as-C2, angalia [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Inapotumika kwenye Linux au macOS ina commands zinazovutia:

### Vitendo vya kawaida

- `cat`: Chapisha yaliyomo kwenye file
- `cd`: Badilisha working directory ya sasa
- `chmod`: Badilisha permissions za file
- `config`: Angalia config ya sasa na taarifa za host
- `cp`: Nakili file kutoka location moja hadi nyingine
- `curl`: Tekeleza web request moja kwa headers na method za hiari
- `upload`: Upload file kwenda kwenye target
- `download`: Download file kutoka kwenye target system kwenda kwenye local machine
- Na nyingine nyingi

### Kutafuta Taarifa Nyeti

- `triagedirectory`: Tafuta files zinazovutia ndani ya directory kwenye host, kama vile files nyeti au credentials.
- `getenv`: Pata environment variables zote za sasa.

### Tradecraft maalum ya macOS

- `jxa`: Tekeleza JavaScript for Automation ndani ya memory kupitia `OSAScript`, ambayo ni
muhimu kwa native macOS post-exploitation bila kuacha files tofauti za script.
- `clipboard_monitor`: Poll pasteboard na kuripoti mabadiliko kwa Mythic,
ambayo ni muhimu kwa workflows za credential/token theft zinazotegemea copy/paste.
- `screencapture`: Capture desktop ya mtumiaji kwenye macOS.
- `execute_library`: Pakia dylib kutoka kwenye disk na uite function maalum iliyotangazwa.
- `libinject`: Inject shellcode stub inayolazimisha process nyingine ya macOS kupakia dylib kutoka kwenye disk.
- `persist_launchd`: Unda persistence ya LaunchAgent / LaunchDaemon moja kwa moja kutoka kwa agent.

### Kusogea laterally

- `ssh`: Tumia SSH kwenda kwenye host kwa credentials zilizoteuliwa na ufungue PTY bila kuanzisha ssh.
- `sshauth`: Tumia SSH kwenda kwenye host(s) maalum kwa credentials zilizoteuliwa. Unaweza pia kutumia hii kutekeleza command maalum kwenye remote hosts kupitia SSH au kuitumia kwa SCP files.
- `link_tcp`: Unganisha na agent nyingine kupitia TCP, ukiruhusu mawasiliano ya moja kwa moja kati ya agents.
- `link_webshell`: Unganisha na agent kwa kutumia webshell P2P profile, ukiruhusu remote access kwenye web interface ya agent.
- `rpfwd`: Anzisha au simamisha Reverse Port Forward, ukiruhusu remote access kwenye services zilizo kwenye target network.
- `socks`: Anzisha au simamisha SOCKS5 proxy kwenye target network, ukiruhusu tunneling ya traffic kupitia compromised host. Inaoana na tools kama proxychains.
- `portscan`: Scan host(s) kwa ports zilizo wazi, ikiwa muhimu kwa kutambua potential targets za lateral movement au attacks zaidi.

### Utekelezaji wa process

- `shell`: Tekeleza shell command moja kupitia /bin/sh, ukiruhusu utekelezaji wa moja kwa moja wa commands kwenye target system.
- `run`: Tekeleza command kutoka kwenye disk ikiwa na arguments, ukiruhusu utekelezaji wa binaries au scripts kwenye target system.
- `pty`: Fungua PTY shirikishi, ukiruhusu interaction ya moja kwa moja na shell kwenye target system.






## Marejeo

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [Transforming Red Team Ops with Mythic’s Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
{{#include ../banners/hacktricks-training.md}}
