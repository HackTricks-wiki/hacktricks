# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic ni nini?

Mythic ni framework ya open-source, modular, collaborative command and control (C2) iliyoundwa kwa ajili ya red teaming. Inawaruhusu operators kusimamia na deploy agents (payloads) kwenye operating systems tofauti, ikiwemo Windows, Linux, na macOS. Mythic inatoa browser UI kwa multi-operator tasking, file handling, usimamizi wa SOCKS/rpfwd, na generation ya payload.

Tofauti na frameworks za monolithic, repository ya Mythic yenyewe **hai**kuja na aina za payload au C2 profiles. Agents, wrappers, na C2 profiles kwa kawaida husakinishwa kama external components na zinaweza kusasishwa kwa kujitegemea kutoka kwa core ya Mythic.

### Installation

Ili kusakinisha Mythic, fuata maelekezo kwenye official **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Bootstrap ya kawaida kutoka kwenye directory ya Mythic ni:
```bash
sudo make
sudo ./mythic-cli start
```
Kama Mythic tayari inafanya kazi, kwa kawaida unaweza kuongeza agent au profile mpya kwa `./mythic-cli install github ...` kisha ama uanze upya Mythic au tu anzisha component mpya moja kwa moja.

### Agents

Mythic inasaidia agents nyingi, ambazo ni **payloads zinazotekeleza tasks kwenye systems zilizoathiriwa**. Kila agent inaweza kubinafsishwa kulingana na mahitaji mahususi na inaweza kuendeshwa kwenye operating systems tofauti.

Kwa default Mythic haina agents zozote zilizosakinishwa. Open-source community agents zipo kwenye [**https://github.com/MythicAgents**](https://github.com/MythicAgents), na [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) ni muhimu kwa kuangalia haraka supported operating systems, payload formats, wrappers, na C2 profiles.

Ili kusakinisha agent kutoka kwa hiyo org unaweza kuendesha:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Fomu ya `sudo -E` ni muhimu unapokuwa unasakinisha kutoka kwenye mazingira yasiyo ya root. Unaweza kuongeza agents wapya kwa kutumia amri iliyotangulia hata ikiwa Mythic tayari inaendeshwa.

### C2 Profiles

C2 profiles katika Mythic hufafanua **jinsi agents zinavyowasiliana na Mythic server**. Zinaonyesha communication protocol, encryption methods, na settings nyingine. Unaweza kuunda na kudhibiti C2 profiles kupitia Mythic web interface.

Kwa chaguo-msingi Mythic husakinishwa bila profiles, hata hivyo, inawezekana kupakua baadhi ya profiles kutoka kwenye repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) kwa kuendesha:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Profaili za operator zinazofaa kuzingatia kwa sasa:

- [`http`](https://github.com/MythicC2Profiles/http): trafiki ya msingi ya asynchronous GET/POST.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): trafiki ya HTTP yenye kubadilika zaidi na callback domains nyingi, fail-over/round-robin rotation, custom headers/query parameters, na message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) zilizowekwa kwenye cookies, headers, query parameters, au body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): uundaji wa ujumbe wa HTTP unaoendeshwa na JSON/TOML wakati profile ya tuli `http` inatambulika sana.

### Wrapper payloads

Wrapper payloads hukuwezesha kuweka logic ileile ya agent huku ukibadilisha on-disk representation inayotolewa au kuendelea kuwepo.

- `service_wrapper`: hugeuza payload nyingine kuwa Windows service executable, ambayo ni muhimu wakati execution path inahitaji valid service binary.
- `scarecrow_wrapper`: hufunga compatible shellcode kwa kutumia ScareCrow loader ili kutoa outputs zenye loader kama vile EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo ni Windows agent iliyoandikwa kwa C# kwa kutumia 4.0 .NET Framework iliyoundwa kutumika katika offerings za mafunzo za SpecterOps.

Isakinishe kwa:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Maelezo ya sasa ya build/profile

- Apollo kwa sasa inaweza kutoa payloads za `WinExe`, `Shellcode`, `Service`, na `Source`.
- Profiles za Apollo zinazotumika sana ni `http`, `httpx`, `smb`, `tcp`, na `websocket`.
- `httpx` kawaida ni chaguo lenye unyumbufu zaidi unapohitaji domain rotation, msaada wa proxy, custom message placement, na message transforms badala ya profile ya zamani ya `http` tuli.
- Apollo inasaidia wrapper payloads kama `service_wrapper` na `scarecrow_wrapper`.
- `register_file` na `register_assembly` ni staging primitives za `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, na `powerpick`. Katika builds za sasa za Apollo, hizo staged artifacts huhifadhiwa kwenye upande wa client kama DPAPI-protected AES256 blobs.
- Matokeo ya `ls` na `ps` yanaunganishwa vizuri sana na browser scripts za Mythic na file/process browser, jambo linalofanya triage ya operator iwe haraka zaidi katika shughuli za pamoja.

Huyu agent ana commands nyingi zinazomfanya afanane sana na Beacon ya Cobalt Strike pamoja na extras kadhaa. Miongoni mwao, inasaidia:

### Vitendo vya kawaida

- `cat`: Chapisha yaliyomo ya faili
- `cd`: Badilisha directory ya sasa ya kazi
- `cp`: Nakili faili kutoka eneo moja hadi jingine
- `ls`: Orodhesha faili na directories katika directory ya sasa au path iliyobainishwa
- `ifconfig`: Pata network adapters na interfaces
- `netstat`: Pata taarifa za TCP na UDP connection
- `pwd`: Chapisha directory ya sasa ya kazi
- `ps`: Orodhesha processes zinazoendeshwa kwenye mfumo lengwa (pamoja na info iliyoongezwa)
- `jobs`: Orodhesha jobs zote zinazoendeshwa zinazohusishwa na long-running tasking
- `download`: Pakua faili kutoka mfumo lengwa kwenda kwenye machine ya ndani
- `upload`: Pakia faili kutoka kwenye machine ya ndani kwenda kwenye mfumo lengwa
- `reg_query`: Chunguza registry keys na values kwenye mfumo lengwa
- `reg_write_value`: Andika value mpya kwenye registry key iliyoainishwa
- `sleep`: Badilisha sleep interval ya agent, ambayo huamua mara ngapi huwasiliana na Mythic server
- Na nyingine nyingi zaidi, tumia `help` kuona orodha kamili ya commands zinazopatikana.

### Privilege escalation

- `getprivs`: Washa privileges nyingi iwezekanavyo kwenye current thread token
- `getsystem`: Fungua handle kwenda winlogon na duplicate token, kwa ufanisi ukiongeza privileges hadi kiwango cha SYSTEM
- `make_token`: Unda logon session mpya na uitumie kwa agent, kuruhusu impersonation ya user mwingine
- `steal_token`: Chukua primary token kutoka process nyingine, kuruhusu agent kuigiza user wa process hiyo
- `pth`: Pass-the-Hash attack, kuruhusu agent kuauthenticate kama user kwa kutumia NTLM hash yao bila kuhitaji plaintext password
- `mimikatz`: Endesha commands za Mimikatz kutoa credentials, hashes, na taarifa nyingine nyeti kutoka memory au SAM database
- `rev2self`: Rudisha token ya agent kwenye primary token yake, kwa ufanisi ukishusha privileges kurudi kiwango cha awali
- `ppid`: Badilisha parent process kwa post-exploitation jobs kwa kubainisha new parent process ID, kuruhusu udhibiti bora wa job execution context
- `printspoofer`: Endesha commands za PrintSpoofer ili kupita hatua za usalama za print spooler, kuruhusu privilege escalation au code execution
- `dcsync`: Sakanisha Kerberos keys za user kwenda kwenye machine ya ndani, kuruhusu offline password cracking au mashambulizi ya ziada
- `ticket_cache_add`: Ongeza Kerberos ticket kwenye current logon session au iliyoainishwa, kuruhusu ticket reuse au impersonation

### Utekelezaji wa process

- `assembly_inject`: Huaruhusu kuingiza .NET assembly loader kwenye remote process
- `blockdlls`: Zuia DLLs zisizosainiwa na Microsoft kupakiwa ndani ya post-exploitation jobs
- `execute_assembly`: Hutekeleza .NET assembly katika muktadha wa agent
- `execute_coff`: Hutekeleza faili ya COFF kwenye memory, kuruhusu in-memory execution ya compiled code
- `execute_pe`: Hutekeleza executable isiyosimamiwa (PE)
- `get_injection_techniques`: Onyesha injection techniques zinazopatikana na ile iliyochaguliwa sasa
- `inline_assembly`: Hutekeleza .NET assembly ndani ya AppDomain inayotupwa, kuruhusu utekelezaji wa muda wa code bila kuathiri process kuu ya agent
- `register_assembly`: Sajili .NET assembly kwa utekelezaji wa baadaye
- `register_file`: Sajili faili kwenye agent cache kwa baadaye `execute_*` au PowerShell tasking
- `run`: Hutekeleza binary kwenye mfumo lengwa, ikitumia PATH ya mfumo kutafuta executable
- `set_injection_technique`: Badilisha injection primitive inayotumiwa na post-exploitation jobs
- `shinject`: Hu-inject shellcode kwenye remote process, kuruhusu in-memory execution ya code yoyote
- `inject`: Hu-inject agent shellcode kwenye remote process, kuruhusu in-memory execution ya code ya agent
- `spawn`: Huanzisha session mpya ya agent katika executable iliyoainishwa, kuruhusu utekelezaji wa shellcode katika process mpya
- `spawnto_x64` na `spawnto_x86`: Badilisha binary ya kawaida inayotumiwa katika post-exploitation jobs kwenda path iliyoainishwa badala ya kutumia `rundll32.exe` bila params ambayo inaonekana sana.

### Mythic Forge

Hii inaruhusu **load COFF/BOF** files kutoka Mythic Forge, ambayo ni repository ya pre-compiled payloads na tools zinazoweza kutekelezwa kwenye mfumo lengwa. Pamoja na commands zote zinazoweza kupakiwa itawezekana kufanya vitendo vya kawaida kwa kuzitekeleza katika current agent process kama BOFs (kawaida ikiwa na OPSEC bora kuliko kuanzisha process tofauti).

Anza kuziinstall kwa:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, tumia `forge_collections` kuonyesha moduli za COFF/BOF kutoka Mythic Forge ili uweze kuzichagua na kuziload kwenye memory ya agent kwa ajili ya execution. Kwa default, makusanyo 2 yafuatayo huongezwa katika Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Baada ya module moja ku-loadiwa, itaonekana kwenye list kama command nyingine kama `forge_bof_sa-whoami` au `forge_bof_sa-netuser`.

### PowerShell & scripting execution

- `powershell_import`: Hu-import script mpya ya PowerShell (.ps1) kwenye agent cache kwa ajili ya execution ya baadaye
- `powershell`: Hu-execute command ya PowerShell katika context ya agent, ikiruhusu scripting ya hali ya juu na automation
- `powerpick`: Hu-inject PowerShell loader assembly kwenye sacrificial process na hu-execute command ya PowerShell (bila powershell logging).
- `psinject`: Hu-execute PowerShell kwenye process maalum, ikiruhusu execution iliyolengwa ya scripts katika context ya process nyingine
- `shell`: Hu-execute command ya shell katika context ya agent, sawa na kuendesha command kwenye cmd.exe

### Lateral Movement

- `jump_psexec`: Hutumia technique ya PsExec kusonga laterally kwenda host mpya kwa kwanza kunakili Apollo agent executable (apollo.exe) na kuiexecute.
- `jump_wmi`: Hutumia technique ya WMI kusonga laterally kwenda host mpya kwa kwanza kunakili Apollo agent executable (apollo.exe) na kui-execute.
- `link` and `unlink`: Huunda na kuvunja P2P links (kwa mfano juu ya SMB/TCP) kati ya callbacks.
- `wmiexecute`: Hu-execute command kwenye local au specified remote system kwa kutumia WMI, na optional credentials kwa impersonation.
- `net_dclist`: Huretrieve list ya domain controllers kwa domain iliyoainishwa, muhimu kwa kutambua potential targets za lateral movement.
- `net_localgroup`: Hualista local groups kwenye computer iliyoainishwa, na default kuwa localhost ikiwa hakuna computer iliyoainishwa.
- `net_localgroup_member`: Huretrieve local group membership kwa group iliyoainishwa kwenye local au remote computer, ikiruhusu enumeration ya users katika groups maalum.
- `net_shares`: Hualista remote shares na accessibility yake kwenye computer iliyoainishwa, muhimu kwa kutambua potential targets za lateral movement.
- `socks`: Hu-enable SOCKS 5 compliant proxy kwenye target network, ikiruhusu tunneling ya traffic kupitia compromised host. Inaoana na tools kama proxychains.
- `rpfwd`: Huanza kusikiliza kwenye port iliyoainishwa kwenye target host na ku-forward traffic kupitia Mythic kwenda remote IP na port, ikiruhusu remote access kwa services kwenye target network.
- `listpipes`: Hualista named pipes zote kwenye local system, ambazo zinaweza kuwa muhimu kwa lateral movement au privilege escalation kwa kuingiliana na IPC mechanisms.

Kwa lower-level WMI execution primitives zinazotumika chini ya `jump_wmi` au `wmiexecute`, angalia [WmiExec](lateral-movement/wmiexec.md). Kwa broader pivoting patterns, angalia [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Huonyesha maelezo ya kina kuhusu commands maalum au maelezo ya jumla kuhusu commands zote zinazopatikana kwenye agent.
- `clear`: Hu-mark tasks kama 'cleared' ili zisiweze kuchukuliwa na agents. Unaweza kubainisha `all` ili kufuta tasks zote au `task Num` ili kufuta task maalum.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon ni Golang agent inayocompile kuwa executables za **Linux and macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Maelezo ya sasa ya build/profile

- Current Poseidon builds zinalenga Linux na macOS kwenye `x86_64` na `arm64` zote mbili.
- Muundo wa output unaotumika unajumuisha native executables pamoja na outputs za aina ya shared-library kama `dylib` na `so`.
- Poseidon inasaidia `http`, `websocket`, `tcp`, na `dynamichttp`, na builders wa sasa wanaonyesha mipangilio ya multi-egress kama `egress_order` na failover thresholds.
- Chaguo za wakati wa build kama `proxy_bypass` na `garble` zinafaa kuangaliwa unapohitaji tabia safi zaidi ya mtandao au extra Go binary obfuscation.

Kwa tradecraft maalum ya macOS kuhusu operesheni zinazotegemea Mythic, JAMF abuse, au mawazo ya MDM-as-C2, angalia [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Inapotumika kwenye Linux au macOS ina baadhi ya commands za kuvutia:

### Vitendo vya kawaida

- `cat`: Chapisha maudhui ya faili
- `cd`: Badilisha current working directory
- `chmod`: Badilisha permissions za faili
- `config`: Tazama current config na host information
- `cp`: Nakili faili kutoka eneo moja kwenda jingine
- `curl`: Tekeleza web request moja yenye optional headers na method
- `upload`: Pakia faili kwenye target
- `download`: Pakua faili kutoka mfumo wa target kwenda kwenye machine ya ndani
- Na vingine vingi

### Tafuta Taarifa Nyeti

- `triagedirectory`: Tafuta files za kuvutia ndani ya directory kwenye host, kama vile sensitive files au credentials.
- `getenv`: Pata current environment variables zote.

### Sogeza laterally

- `ssh`: SSH hadi host ukitumia designated credentials na kufungua PTY bila kuanzisha ssh.
- `sshauth`: SSH hadi specified host(s) ukitumia designated credentials. Unaweza pia kutumia hii kutekeleza command maalum kwenye remote hosts kupitia SSH au kuitumia kus SCP files.
- `link_tcp`: Unganisha kwa agent mwingine kupitia TCP, kuruhusu direct communication kati ya agents.
- `link_webshell`: Unganisha kwa agent kwa kutumia webshell P2P profile, kuruhusu remote access kwenye web interface ya agent.
- `rpfwd`: Anzisha au simamisha Reverse Port Forward, kuruhusu remote access kwa services kwenye target network.
- `socks`: Anzisha au simamisha SOCKS5 proxy kwenye target network, kuruhusu traffic tunneling kupitia host iliyoathiriwa. Inaoana na tools kama proxychains.
- `portscan`: Changanua host(s) kwa open ports, muhimu kwa kutambua potential targets za lateral movement au mashambulizi zaidi.

### Utekelezaji wa process

- `shell`: Tekeleza single shell command kupitia /bin/sh, kuruhusu direct execution ya commands kwenye target system.
- `run`: Tekeleza command kutoka disk pamoja na arguments, kuruhusu utekelezaji wa binaries au scripts kwenye target system.
- `pty`: Fungua interactive PTY, kuruhusu mwingiliano wa moja kwa moja na shell kwenye target system.




## Marejeo

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
{{#include ../banners/hacktricks-training.md}}
