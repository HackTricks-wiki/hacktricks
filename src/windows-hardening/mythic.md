# Mythic

{{#include ../banners/hacktricks-training.md}}

## Wat is Mythic?

Mythic is 'n oopbron, modulêre, samewerkende command and control (C2)-raamwerk wat vir red teaming ontwerp is. Dit laat operators toe om agents (payloads) oor verskillende bedryfstelsels te bestuur en te ontplooi, insluitend Windows, Linux, en macOS. Mythic bied 'n browser UI vir multi-operator tasking, lêerhantering, SOCKS/rpfwd-bestuur, en payload-generering.

Anders as monolitiese raamwerke, stuur die Mythic-repo self **nie** payload-tipes of C2-profiele saam nie. Agents, wrappers, en C2-profiele word tipies as eksterne komponente geïnstalleer en kan onafhanklik van Mythic core opgedateer word.

### Installation

Om Mythic te installeer, volg die instruksies op die amptelike **[Mythic repo](https://github.com/its-a-feature/Mythic)**. 'n Algemene bootstrap vanaf die Mythic-gids is:
```bash
sudo make
sudo ./mythic-cli start
```
As Mythic reeds loop, kan jy normaalweg ’n nuwe agent of profile byvoeg met `./mythic-cli install github ...` en dan óf Mythic herbegin óf net die nuwe komponent direk begin.

### Agents

Mythic ondersteun verskeie agents, wat die **payloads is wat take op die gekompromitteerde stelsels uitvoer**. Elke agent kan vir spesifieke behoeftes aangepas word en kan op verskillende bedryfstelsels loop.

By verstek het Mythic geen agents geïnstalleer nie. Die open-source community agents is beskikbaar by [**https://github.com/MythicAgents**](https://github.com/MythicAgents), en die [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) is nuttig om vinnig ondersteunede bedryfstelsels, payload-formate, wrappers, en C2 profiles na te gaan.

Om ’n agent van daardie org te installeer kan jy hardloop:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Die `sudo -E` vorm is nuttig wanneer jy vanaf ’n nie-root-omgewing installeer. Jy kan nuwe agents met die vorige opdrag byvoeg selfs al loop Mythic reeds.

### C2 Profiles

C2 profiles in Mythic definieer **hoe agents met die Mythic server kommunikeer**. Hulle spesifiseer die kommunikasieprotokol, enkripsiemetodes, en ander instellings. Jy kan C2 profiles skep en bestuur deur die Mythic web interface.

By verstek word Mythic geïnstalleer met geen profiles nie, maar dit is moontlik om sommige profiles van die repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) af te laai deur:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): basiese asinchroniese GET/POST-verkeer.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): meer buigsame HTTP-verkeer met veelvuldige callback domains, fail-over/round-robin rotasie, custom headers/query parameters, en message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) wat in cookies, headers, query parameters, of body geplaas word.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-gedrewe HTTP message shaping wanneer die statiese `http` profile te herkenbaar is.

### Current platform notes

- Baie publieke agents en profiles installeer nou met voorafgeboude remote container images.
As jy ’n component fork of plaaslik patch en Mythic hou aan om die ou gedrag te gebruik, inspekteer die gegenereerde `.env` entries vir `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT`, en `*_USE_VOLUME`; om
`*_USE_BUILD_CONTEXT="true"` te aktiveer is gewoonlik wat Mythic laat herbuild vanuit jou
plaaslike Docker context in plaas daarvan om stilweg die remote image te hergebruik.
- Browser scripts is een van Mythic se hoogste-waarde quality-of-life features
vir operators: hulle kan raw command output omskakel na tables, screenshot
viewers, download links, en buttons wat follow-on tasking direk
vanuit die UI uitstuur. Dit is veral nuttig vir herhalende `ls`, `ps`, triage,
en file-browser workflows.
- Nuwe Mythic builds ondersteun ook interactive tasking en Push C2 patterns
wat die behoefte aan `sleep 0` polling tydens PTY/SOCKS/rpfwd-swaar
operasies verminder. Wanneer ’n agent/profile dit ondersteun, is dit gewoonlik laer-overhead
as om die server voortdurend te hammer met konstante check-ins net om ’n interactive
channel bruikbaar te hou.

### Wrapper payloads

Wrapper payloads laat jou toe om dieselfde agent logic te behou terwyl jy die on-disk representation verander wat afgelewer of gepersist word.

- `service_wrapper`: verander ’n ander payload in ’n Windows service executable, wat nuttig is wanneer die execution path ’n geldige service binary vereis.
- `scarecrow_wrapper`: wrap kompatibele shellcode met die ScareCrow loader om loader-backed outputs soos EXE/DLL/CPL te genereer.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo is ’n Windows agent geskryf in C# wat die 4.0 .NET Framework gebruik en ontwerp is om in SpecterOps training offerings gebruik te word.

Installeer dit met:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Apollo kan tans `WinExe`, `Shellcode`, `Service`, en `Source` payloads uitstuur.
- Die algemeen gebruikte Apollo profiles is `http`, `httpx`, `smb`, `tcp`, en `websocket`.
- `httpx` is gewoonlik die meer buigsame opsie wanneer jy domain rotation, proxy support, custom message placement, en message transforms nodig het in plaas van die ouer statiese `http` profile.
- Apollo ondersteun wrapper payloads soos `service_wrapper` en `scarecrow_wrapper`.
- `register_file` en `register_assembly` is die staging primitives vir `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, en `powerpick`. In huidige Apollo builds word daardie staged artifacts client-side as DPAPI-beskermde AES256 blobs gecache.
- `ls` en `ps` resultate integreer veral goed met Mythic se browser scripts en file/process browser, wat operator triage merkbaar vinniger maak in collaborative operations.
- Apollo se fork-and-run jobs erf hul sacrificial process settings van
`spawnto_x86` / `spawnto_x64`, erf parent selection van `ppid`, en
gebruik dan die tans gekose injection primitive. In die praktyk beteken dit
dat jou OPSEC tuning vir een command dikwels `execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe`, en `spawn` op dieselfde
tyd beïnvloed.
- Huidig gedokumenteerde Apollo injection backends sluit `CreateRemoteThread`,
`QueueUserAPC` (early-bird style), en `NtCreateThreadEx` via syscalls in. Gebruik
`get_injection_techniques` voor lawaaierige post-exploitation en
`set_injection_technique` as jy weg moet skuif van `n primitive wat
bots met die target of die command wat jy wil run.
- `blockdlls` beïnvloed net sacrificial processes wat vir post-exploitation
jobs geskep word. Gekombineer met `n minder verdagte `spawnto_x64` target as die standaard
kaal `rundll32.exe`, is dit een van die maklikste Apollo-side veranderinge om te maak
voor jy assembly/PowerShell-heavy tasking run.

This agent het baie commands wat dit baie soortgelyk aan Cobalt Strike se Beacon maak met 'n paar extras. Onder andere ondersteun dit:

### Common actions

- `cat`: Print die contents van `n file
- `cd`: Verander die huidige working directory
- `cp`: Copy `n file van een location na `n ander
- `ls`: Lys files en directories in die huidige directory of gespesifiseerde path
- `ifconfig`: Kry network adapters en interfaces
- `netstat`: Kry TCP en UDP connection information
- `pwd`: Print die huidige working directory
- `ps`: Lys lopende processes op die target system (met bygevoegde info)
- `jobs`: Lys alle lopende jobs wat met long-running tasking geassosieer word
- `download`: Download `n file van die target system na die local machine
- `upload`: Upload `n file van die local machine na die target system
- `reg_query`: Query registry keys en values op die target system
- `reg_write_value`: Skryf `n nuwe value na `n gespesifiseerde registry key
- `sleep`: Verander die agent se sleep interval, wat bepaal hoe gereeld dit incheck by die Mythic server
- En baie ander, gebruik `help` om die volle lys van beskikbare commands te sien.

### Privilege escalation

- `getprivs`: Enable soveel privileges as moontlik op die current thread token
- `getsystem`: Open `n handle na winlogon en duplicate die token, wat effektief privileges na SYSTEM level escalate
- `make_token`: Skep `n nuwe logon session en pas dit toe op die agent, wat impersonation van `n ander user toelaat
- `steal_token`: Steel `n primary token van `n ander process, wat die agent toelaat om daardie process se user te impersonate
- `pth`: Pass-the-Hash attack, wat die agent toelaat om as `n user te authenticate deur hul NTLM hash te gebruik sonder om die plaintext password nodig te hê
- `mimikatz`: Run Mimikatz commands om credentials, hashes, en ander sensitive information uit memory of die SAM database te extract
- `rev2self`: Revert die agent se token na sy primary token, wat effektief privileges terug laat val na die oorspronklike level
- `ppid`: Verander die parent process vir post-exploitation jobs deur `n nuwe parent process ID te spesifiseer, wat beter control oor job execution context toelaat
- `printspoofer`: Execute PrintSpoofer commands om print spooler security measures te bypass, wat privilege escalation of code execution toelaat
- `dcsync`: Sync `n user se Kerberos keys na die local machine, wat offline password cracking of further attacks toelaat
- `ticket_cache_add`: Voeg `n Kerberos ticket by die current logon session of `n gespesifiseerde een, wat ticket reuse of impersonation toelaat

### Process execution

- `assembly_inject`: Laat toe om `n .NET assembly loader in `n remote process in te inject
- `blockdlls`: Block nie-Microsoft signed DLLs om te load in post-exploitation jobs
- `execute_assembly`: Execute `n .NET assembly in die context van die agent
- `execute_coff`: Execute `n COFF file in memory, wat in-memory execution van compiled code toelaat
- `execute_pe`: Execute `n unmanaged executable (PE)
- `keylog_inject`: Inject `n keylogger in `n ander process en stroom keystrokes terug na Mythic se keylog view
- `screenshot` / `screenshot_inject`: Capture die huidige desktop direk of
deur `n screenshot assembly in te inject in `n target process/session
- `get_injection_techniques`: Wys beskikbare injection techniques en die tans gekose een
- `inline_assembly`: Execute `n .NET assembly in `n disposable AppDomain, wat tydelike execution van code toelaat sonder om die agent se main process te beïnvloed
- `register_assembly`: Registreer `n .NET assembly vir latere execution
- `register_file`: Registreer `n file in die agent cache vir latere `execute_*` of PowerShell tasking
- `run`: Execute `n binary op die target system, deur die system se PATH te gebruik om die executable te vind
- `set_injection_technique`: Verander die injection primitive wat deur post-exploitation jobs gebruik word
- `shinject`: Inject shellcode in `n remote process, wat in-memory execution van arbitrary code toelaat
- `inject`: Inject agent shellcode in `n remote process, wat in-memory execution van die agent se code toelaat
- `spawn`: Spawn `n nuwe agent session in die gespesifiseerde executable, wat execution van shellcode in `n nuwe process toelaat
- `spawnto_x64` en `spawnto_x86`: Verander die default binary wat in post-exploitation jobs gebruik word na `n gespesifiseerde path in plaas van om `rundll32.exe` sonder params te gebruik, wat baie noisy is.

### Mythic Forge

Dit laat toe om **load COFF/BOF** files vanaf die Mythic Forge, wat `n repository is van pre-compiled payloads en tools wat op die target system executed kan word. Met al die commands wat gelaai kan word sal dit moontlik wees om common actions uit te voer deur hulle in die current agent process as BOFs te execute (gewoonlik met beter OPSEC as om `n aparte process te spawn).

Begin om hulle te installeer met:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, use `forge_collections` om die COFF/BOF modules van die Mythic Forge te wys sodat jy hulle kan kies en laai in die agent se geheue vir uitvoering. By verstek word die volgende 2 collections in Apollo bygevoeg:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Nadat een module gelaai is, sal dit in die lys verskyn as nog ’n command soos `forge_bof_sa-whoami` of `forge_bof_sa-netuser`.

Vir BOFs, onthou dat Forge **nie** net een plat argument string
na Apollo deurgee nie. Dit map BOF parameters na Mythic se typed-array formaat en stuur
dit dan aan na Apollo se `execute_coff` flow. As ’n Forge-gelaaide BOF vreemd optree, kyk na die verwagte BOF argument types / entrypoint eerder as net die command line wat jy getik het.

### PowerShell & scripting execution

- `powershell_import`: Importeer ’n nuwe PowerShell script (.ps1) in die agent cache vir latere uitvoering
- `powershell`: Voer ’n PowerShell command uit in die konteks van die agent, wat gevorderde scripting en automation toelaat
- `powerpick`: Injecteer ’n PowerShell loader assembly in ’n sacrificial process en voer ’n PowerShell command uit (sonder powershell logging).
- `psinject`: Voer PowerShell uit in ’n gespesifiseerde process, wat geteikende uitvoering van scripts in die konteks van ’n ander process moontlik maak
- `shell`: Voer ’n shell command uit in die konteks van die agent, soortgelyk aan die uitvoer van ’n command in cmd.exe

### Lateral Movement

- `jump_psexec`: Gebruik die PsExec technique om lateraal na ’n nuwe host te beweeg deur eers die Apollo agent executable (apollo.exe) te kopieer en dit uit te voer.
- `jump_wmi`: Gebruik die WMI technique om lateraal na ’n nuwe host te beweeg deur eers die Apollo agent executable (apollo.exe) te kopieer en dit uit te voer.
- `link` and `unlink`: Skep en breek P2P links (byvoorbeeld oor SMB/TCP) tussen callbacks af.
- `wmiexecute`: Voer ’n command uit op die plaaslike of gespesifiseerde remote system met behulp van WMI, met opsionele credentials vir impersonation.
- `net_dclist`: Herwin ’n lys van domain controllers vir die gespesifiseerde domain, nuttig om potensiële targets vir lateral movement te identifiseer.
- `net_localgroup`: Lys local groups op die gespesifiseerde computer, met localhost as die verstek as geen computer gespesifiseer is nie.
- `net_localgroup_member`: Herwin local group membership vir ’n gespesifiseerde group op die plaaslike of remote computer, wat enumerasie van users in spesifieke groups moontlik maak.
- `net_shares`: Lys remote shares en hul toeganklikheid op die gespesifiseerde computer, nuttig om potensiële targets vir lateral movement te identifiseer.
- `socks`: Aktiveer ’n SOCKS 5-kompatibele proxy op die target network, wat tunneling van traffic deur die gecompromitteerde host moontlik maak. Compatible met tools soos proxychains.
- `rpfwd`: Begin luister op ’n gespesifiseerde port op die target host en stuur traffic deur Mythic na ’n remote IP en port, wat remote access tot services op die target network moontlik maak.
- `listpipes`: Lys alle named pipes op die plaaslike system, wat nuttig kan wees vir lateral movement of privilege escalation deur met IPC mechanisms te interaksie.

Vir die laer-vlak WMI execution primitives wat onder `jump_wmi` of `wmiexecute` gebruik word, kyk [WmiExec](lateral-movement/wmiexec.md). Vir breër pivoting patterns, kyk [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Wys gedetailleerde inligting oor spesifieke commands of algemene inligting oor al die beskikbare commands in die agent.
- `clear`: Merk tasks as 'cleared' sodat agents hulle nie kan optel nie. Jy kan `all` spesifiseer om al die tasks skoon te maak of `task Num` om ’n spesifieke task skoon te maak.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon is ’n Golang agent wat kompileer na **Linux en macOS** executables.
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

- `cat`: Druk die inhoud van 'n lêer
- `cd`: Verander die huidige werkgids
- `chmod`: Verander die toestemmings van 'n lêer
- `config`: Bekyk huidige config en gasheerinligting
- `cp`: Kopieer 'n lêer van een ligging na 'n ander
- `curl`: Voer 'n enkele webversoek uit met opsionele headers en metode
- `upload`: Laai 'n lêer na die teiken op
- `download`: Laai 'n lêer van die teikenstelsel na die plaaslike masjien af
- En nog baie meer

### Search Sensitive Information

- `triagedirectory`: Vind interessante lêers binne 'n gids op 'n gasheer, soos sensitiewe lêers of geloofsbriewe.
- `getenv`: Kry al die huidige omgewingsveranderlikes.

### macOS-specific tradecraft

- `jxa`: Voer JavaScript for Automation in-memory uit via `OSAScript`, wat
nuttig is vir inheemse macOS post-exploitation sonder om afsonderlike skriplêers
te laat val.
- `clipboard_monitor`: Poll die pasteboard en rapporteer veranderinge terug na Mythic,
wat handig is vir geloofsbrief-/token-diefstal-werkvloeie wat op copy/paste staatmaak.
- `screencapture`: Neem die gebruiker se lessenaar op macOS vas.
- `execute_library`: Laai 'n dylib van skyf en roep 'n spesifieke geëksponeerde funksie daarop aan.
- `libinject`: Inject 'n shellcode-stomp wat 'n ander macOS-proses dwing om 'n dylib van skyf te laai.
- `persist_launchd`: Skep LaunchAgent / LaunchDaemon persistence direk vanaf die agent.

### Move laterally

- `ssh`: SSH na 'n gasheer met die aangewese geloofsbriewe en open 'n PTY sonder om ssh te spawn.
- `sshauth`: SSH na gespesifiseerde gasheer(s) met die aangewese geloofsbriewe. Jy kan dit ook gebruik om 'n spesifieke opdrag op die afgeleë gashere via SSH uit te voer of om dit te gebruik om lêers via SCP te kopieer.
- `link_tcp`: Koppel aan 'n ander agent oor TCP, wat direkte kommunikasie tussen agente toelaat.
- `link_webshell`: Koppel aan 'n agent deur die webshell P2P-profiel te gebruik, wat afgeleë toegang tot die agent se webkoppelvlak toelaat.
- `rpfwd`: Begin of Stop 'n Reverse Port Forward, wat afgeleë toegang tot dienste op die teikennetwerk toelaat.
- `socks`: Begin of Stop 'n SOCKS5-proxy op die teikennetwerk, wat tunneling van verkeer deur die gekompromitteerde gasheer toelaat. Versoenbaar met gereedskap soos proxychains.
- `portscan`: Skandeer gasheer(s) vir oop poorte, nuttig vir die identifisering van potensiële teikens vir laterale beweging of verdere aanvalle.

### Process execution

- `shell`: Voer 'n enkele shell-opdrag uit via /bin/sh, wat direkte uitvoering van opdragte op die teikestelsel moontlik maak.
- `run`: Voer 'n opdrag van skyf uit met argumente, wat die uitvoering van binaries of skripte op die teikestelsel moontlik maak.
- `pty`: Open 'n interaktiewe PTY, wat direkte interaksie met die shell op die teikestelsel moontlik maak.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
{{#include ../banners/hacktricks-training.md}}
