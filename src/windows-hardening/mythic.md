# Mythic

{{#include ../banners/hacktricks-training.md}}

## Wat is Mythic?

Mythic is 'n oopbron, modulêre, samewerkende command and control (C2)-raamwerk wat vir red teaming ontwerp is. Dit stel operators in staat om agents (payloads) oor verskillende bedryfstelsels, insluitend Windows, Linux en macOS, te bestuur en te ontplooi. Mythic bied 'n blaaier-UI vir multi-operator-tasking, lêerhantering, SOCKS/rpfwd-bestuur en payload-generering.

Anders as monolitiese raamwerke, bevat die Mythic-repository self **nie payload-tipes of C2-profiele nie**. Agents, wrappers en C2-profiele word gewoonlik as eksterne komponente geïnstalleer en kan onafhanklik van Mythic core opgedateer word.

### Installasie

Om Mythic te installeer, volg die instruksies op die amptelike **[Mythic repo](https://github.com/its-a-feature/Mythic)**. 'n Algemene bootstrap vanuit die Mythic-gids is:
```bash
sudo make
sudo ./mythic-cli start
```
As Mythic reeds loop, kan jy normaalweg ’n nuwe agent of profile byvoeg met `./mythic-cli install github ...` en dan Mythic herbegin of net die nuwe component direk begin.

### Agents

Mythic ondersteun verskeie agents, wat die **payloads is wat take op die gekompromitteerde stelsels uitvoer**. Elke agent kan volgens spesifieke behoeftes aangepas word en op verskillende bedryfstelsels loop.

By verstek het Mythic geen agents geïnstalleer nie. Die open-source community agents is beskikbaar by [**https://github.com/MythicAgents**](https://github.com/MythicAgents), en die [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) is nuttig om vinnig die ondersteunde bedryfstelsels, payload-formate, wrappers en C2-profiele na te gaan.

Om ’n agent vanaf daardie organisasie te installeer, kan jy uitvoer:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Die `sudo -E`-vorm is nuttig wanneer jy vanuit ’n nie-root-omgewing installeer. Jy kan nuwe agents met die vorige opdrag byvoeg, selfs al loop Mythic reeds.

### C2 Profiles

C2 profiles in Mythic definieer **hoe agents met die Mythic server kommunikeer**. Hulle spesifiseer die communication protocol, encryption methods en ander instellings. Jy kan C2 profiles deur die Mythic-webkoppelvlak skep en bestuur.

By verstek word Mythic sonder profiles geïnstalleer, maar dit is moontlik om sommige profiles vanaf die repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) af te laai deur die volgende uit te voer:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Huidige operator-relevante profiele om in gedagte te hou:

- [`http`](https://github.com/MythicC2Profiles/http): basiese asynchronous GET/POST-verkeer.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): meer buigsame HTTP-verkeer met veelvuldige callback-domains, fail-over/round-robin-rotasie, pasgemaakte headers/query parameters, en message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) wat in cookies, headers, query parameters of die body geplaas word.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-gedrewe HTTP message shaping wanneer die statiese `http`-profiel te herkenbaar is.

### Huidige platformnotas

- Baie publieke agents en profiele installeer nou met voorafgeboude remote container images.
As jy ’n komponent fork of dit plaaslik patch en Mythic steeds die ou
gedrag gebruik, inspekteer die gegenereerde `.env`-inskrywings vir `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT`, en `*_USE_VOLUME`; om
`*_USE_BUILD_CONTEXT="true"` te aktiveer, is gewoonlik wat Mythic laat herbou
vanaf jou plaaslike Docker context in plaas daarvan om stilweg die remote image te hergebruik.
- Browser scripts is een van Mythic se waardevolste quality-of-life features
vir operators: hulle kan rou command output in tabelle, screenshot viewers,
download links, search links, en knoppies omskep wat follow-on
tasking direk vanuit die UI uitvoer. Huidige Mythic builds laat elke operator toe om
hul eie scripts te behou, dit globaal of per task te aktiveer, en die beste resultate te kry
wanneer agents gestruktureerde JSON eerder as plaintext terugstuur. Dit is veral
nuttig vir herhalende `ls`, `ps`, triage, en file-browser workflows.
- Nuwer Mythic builds ondersteun ook interactive tasking en Push C2-patrone
wat die behoefte aan `sleep 0` polling tydens PTY/SOCKS/rpfwd-swaar
operasies verminder. Wanneer ’n agent/profile dit ondersteun, is dit gewoonlik laer
oorhoofse koste as om die server voortdurend met check-ins te oorlaai net om ’n interactive
channel bruikbaar te hou.
- Huidige 3.4-era Mythic builders is meer context-aware as wat ouer writeups
impliseer: build parameters kan nou gegroepeer of versteek word gebaseer op die geselekteerde OS
of ander build options, payload types kan verklaar of hulle
multiple C2 profiles of multiple instances van dieselfde C2 in een build ondersteun,
en C2 parameter deviations laat ’n agent toe om velde te versteek wat dit nie werklik
implementeer nie. Dit is belangrik wanneer jy tussen `http`, `httpx`, `smb`,
`tcp`, en `websocket` wissel, omdat die veilige/geldige build surface nie langer ’n
plat statiese vorm is nie.
- As jy ’n custom agent/profile-paar bou en nie Mythic se
JSON message format of default crypto oor die netwerk wil gebruik nie, gebruik ’n
`translation_container`: Mythic verwyder die UUID, gee die encrypted blob en key
material via gRPC aan die translator, en verwag agent-native bytes
terug. Dit is die skoon manier om binary protocols, custom framing, of
agent-side encryption te ondersteun sonder om die hele server te herskryf.
- Onthou dat linked/P2P callbacks nie net tasking aanstuur nie. Mythic se
`get_tasking`-flow kan ook responses plus `delegates`, `socks`,
`rpfwd`, en `interactive` data dra. In die praktyk kan een egress callback inner
callbacks en pivot channels in dieselfde polling loop bedien; indien die child
agents hul eie periodieke check-ins uitvoer, hou `get_delegate_tasks=false` die
parent daarvan om per ongeluk die inner callback se queued jobs te verbruik.

### Wrapper payloads

Wrapper payloads laat jou toe om dieselfde agent-logika te behou terwyl jy die on-disk-representasie verander wat afgelewer of volgehou word.

- `service_wrapper`: verander ’n ander payload in ’n Windows service executable, wat nuttig is wanneer die execution path ’n geldige service binary vereis.
- `scarecrow_wrapper`: wrap versoenbare shellcode met die ScareCrow loader om loader-backed outputs soos EXE/DLL/CPL te genereer.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo is ’n Windows agent wat in C# met die 4.0 .NET Framework geskryf is, ontwerp vir gebruik in SpecterOps-trainingaanbiedinge.

Installeer dit met:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Huidige build/profile-notas

- Apollo kan tans `WinExe`-, `Shellcode`-, `Service`- en `Source`-payloads uitstuur.
- Die Apollo-profiele wat algemeen gebruik word, is `http`, `httpx`, `smb`, `tcp` en `websocket`.
- `httpx` is gewoonlik die meer buigsame opsie wanneer jy domain rotation, proxy support, custom message placement en message transforms benodig, eerder as die ouer statiese `http`-profiel.
- Apollo is een van die meer feature-complete community agents en stel tans Mythic-side integrations soos browser scripts, file/process browser views, screenshots, keylogging, SOCKS, rpfwd, Push C2 en P2P routing beskikbaar.
- Apollo ondersteun wrapper payloads soos `service_wrapper` en `scarecrow_wrapper`.
- Apollo ondersteun dynamic command loading, sodat jy die aanvanklike payload lean kan hou en later ekstra commands of Forge modules kan laai, in plaas daarvan om elke post-ex capability in die eerste build te compile.
- Wanneer shellcode output gegenereer word, stel Apollo se huidige builder ook Donut format choices (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) en Donut bypass behavior (`None`, `Abort on fail`, `Continue on fail`) beskikbaar. Dit is nuttig indien die einddoel is om die shellcode weer met `service_wrapper`, `scarecrow_wrapper` of ’n custom loader te wrap.
- `register_file` en `register_assembly` is die staging primitives vir `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` en `powerpick`. In huidige Apollo builds word daardie staged artifacts client-side as DPAPI-protected AES256 blobs gecache.
- `ls`- en `ps`-resultate integreer veral goed met Mythic se browser scripts en file/process browser, wat operator triage merkbaar vinniger maak in collaborative operations.
- Apollo se fork-and-run jobs erf hul sacrificial process settings van
`spawnto_x86` / `spawnto_x64`, erf parent selection van `ppid`, en
gebruik dan die tans geselekteerde injection primitive. In praktyk beteken dit
dat jou OPSEC tuning vir een command dikwels `execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` en `spawn`
terselfdertyd beïnvloed.
- Huidige gedokumenteerde Apollo injection backends sluit `CreateRemoteThread`,
`QueueUserAPC` (early-bird style) en `NtCreateThreadEx` via syscalls in. Gebruik
`get_injection_techniques` voor noisy post-exploitation en
`set_injection_technique` indien jy moet oorskakel vanaf ’n primitive wat
met die target of die command wat jy wil uitvoer, bots.
- `blockdlls` beïnvloed slegs sacrificial processes wat vir post-exploitation
jobs geskep word. Gekombineer met ’n minder suspicious `spawnto_x64`-target as die default
bare `rundll32.exe`, is dit een van die maklikste Apollo-side changes om te maak
voordat assembly/PowerShell-heavy tasking uitgevoer word.

Hierdie agent het baie commands wat dit baie soortgelyk aan Cobalt Strike se Beacon maak, met ’n paar extras. Onder andere ondersteun dit:

### Algemene actions

- `cat`: Druk die inhoud van ’n file uit
- `cd`: Verander die huidige working directory
- `cp`: Kopieer ’n file van een location na ’n ander
- `ls`: Lys files en directories in die huidige directory of gespesifiseerde path
- `ifconfig`: Kry network adapters en interfaces
- `netstat`: Kry TCP- en UDP-connection information
- `pwd`: Druk die huidige working directory uit
- `ps`: Lys running processes op die target system (met bykomende info)
- `jobs`: Lys alle running jobs wat met long-running tasking geassosieer word
- `download`: Download ’n file van die target system na die local machine
- `upload`: Upload ’n file van die local machine na die target system
- `reg_query`: Query registry keys en values op die target system
- `reg_write_value`: Skryf ’n nuwe value na ’n gespesifiseerde registry key
- `sleep`: Verander die agent se sleep interval, wat bepaal hoe gereeld dit by die Mythic server check-in
- En vele ander, gebruik `help` om die volledige lys van beskikbare commands te sien.

### Privilege escalation

- `getprivs`: Enable soveel moontlik privileges op die huidige thread token
- `getsystem`: Open ’n handle na winlogon en duplicate die token, wat privileges effektief na SYSTEM-vlak eskaleer
- `make_token`: Skep ’n nuwe logon session en apply dit op die agent, wat impersonation van ’n ander user moontlik maak
- `steal_token`: Steel ’n primary token van ’n ander process, wat die agent toelaat om daardie process se user te impersonate
- `pth`: Pass-the-Hash attack, wat die agent toelaat om as ’n user te authenticate deur hul NTLM hash te gebruik sonder dat die plaintext password benodig word
- `mimikatz`: Voer Mimikatz commands uit om credentials, hashes en ander sensitiewe information uit memory of die SAM database te extract
- `rev2self`: Revert die agent se token na sy primary token, wat privileges effektief terug na die oorspronklike vlak laat val
- `ppid`: Verander die parent process vir post-exploitation jobs deur ’n nuwe parent process ID te spesifiseer, wat beter control oor die job execution context moontlik maak
- `printspoofer`: Voer PrintSpoofer commands uit om print spooler security measures te bypass, wat privilege escalation of code execution moontlik maak
- `dcsync`: Sync ’n user se Kerberos keys na die local machine, wat offline password cracking of verdere attacks moontlik maak
- `ticket_cache_add`: Voeg ’n Kerberos ticket by die huidige logon session of ’n gespesifiseerde een, wat ticket reuse of impersonation moontlik maak

### Process execution

- `assembly_inject`: Laat toe om ’n .NET assembly loader in ’n remote process te inject
- `blockdlls`: Blokkeer DLLs wat nie deur Microsoft gesign is nie om in post-exploitation jobs te load
- `execute_assembly`: Execute ’n .NET assembly in die context van die agent
- `execute_coff`: Execute ’n COFF file in memory, wat in-memory execution van compiled code moontlik maak
- `execute_pe`: Execute ’n unmanaged executable (PE)
- `keylog_inject`: Inject ’n keylogger in ’n ander process en stream keystrokes terug na Mythic se keylog view
- `screenshot` / `screenshot_inject`: Capture die huidige desktop direk of
deur ’n screenshot assembly in ’n target process/session te inject
- `get_injection_techniques`: Wys beskikbare injection techniques en die tans geselekteerde een
- `inline_assembly`: Execute ’n .NET assembly in ’n disposable AppDomain, wat tydelike execution van code moontlik maak sonder om die agent se hoofprocess te beïnvloed
- `register_assembly`: Register ’n .NET assembly vir latere execution
- `register_file`: Register ’n file in die agent cache vir latere `execute_*`- of PowerShell-tasking
- `run`: Execute ’n binary op die target system deur die system se PATH te gebruik om die executable te vind
- `set_injection_technique`: Verander die injection primitive wat deur post-exploitation jobs gebruik word
- `shinject`: Inject shellcode in ’n remote process, wat in-memory execution van arbitrary code moontlik maak
- `inject`: Inject agent shellcode in ’n remote process, wat in-memory execution van die agent se code moontlik maak
- `spawn`: Spawn ’n nuwe agent session in die gespesifiseerde executable, wat execution van shellcode in ’n nuwe process moontlik maak
- `spawnto_x64` en `spawnto_x86`: Verander die default binary wat in post-exploitation jobs gebruik word na ’n gespesifiseerde path, in plaas daarvan om `rundll32.exe` sonder params te gebruik, wat baie noisy is.

### Mythic Forge

Dit laat jou toe om **COFF/BOF**-files vanaf die Mythic Forge te **load**, wat ’n repository van pre-compiled payloads en tools is wat op die target system uitgevoer kan word. Met al die commands wat gelaai kan word, sal dit moontlik wees om algemene actions uit te voer deur hulle in die huidige agent process as BOFs uit te voer (gewoonlik met beter OPSEC as wanneer ’n separate process gespawn word).

Begin deur hulle te installeer met:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Gebruik vervolgens `forge_collections` om die COFF/BOF-modules van die Mythic Forge te vertoon, sodat jy hulle kan kies en in die agent se geheue kan laai vir uitvoering. By verstek word die volgende 2 versamelings in Apollo bygevoeg:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Nadat een module gelaai is, sal dit in die lys verskyn as nog ’n command, soos `forge_bof_sa-whoami` of `forge_bof_sa-netuser`.

Vir BOFs, onthou dat Forge **nie** bloot een plat argumentstring
aan Apollo deurgee nie. Dit karteer BOF-parameters na Mythic se getikte-skikkingformaat en stuur dit dan aan Apollo se `execute_coff`-vloei deur. As ’n Forge-gelaaide BOF vreemd optree, kontroleer die verwagte BOF-argumenttipes / entrypoint eerder as net die command line wat jy ingetik het. Let ook daarop dat Apollo se nuwer BOF loader argumenthantering verander het in verhouding tot baie ouer 2.3.1-era builds, sodat verouderde BOFs of ou versamelings uitsluitlik kan misluk omdat die marshaling-verwagtings verander het.

### PowerShell & scripting-uitvoering

- `powershell_import`: Importeer ’n nuwe PowerShell-script (.ps1) na die agent se cache vir latere uitvoering
- `powershell`: Voer ’n PowerShell-command in die konteks van die agent uit, wat gevorderde scripting en outomatisering moontlik maak
- `powerpick`: Injecteer ’n PowerShell loader assembly in ’n opofferingsproses en voer ’n PowerShell-command uit (sonder PowerShell-logging).
- `psinject`: Voer PowerShell in ’n gespesifiseerde proses uit, wat geteikende uitvoering van scripts in die konteks van ’n ander proses moontlik maak
- `shell`: Voer ’n shell-command in die konteks van die agent uit, soortgelyk aan die uitvoering van ’n command in cmd.exe

### Laterale Beweging

- `jump_psexec`: Gebruik die PsExec-tegniek om lateraal na ’n nuwe host te beweeg deur eers die Apollo-agent executable (apollo.exe) daarheen te kopieer en dit uit te voer.
- `jump_wmi`: Gebruik die WMI-tegniek om lateraal na ’n nuwe host te beweeg deur eers die Apollo-agent executable (apollo.exe) daarheen te kopieer en dit uit te voer.
- `link` en `unlink`: Skep en verwyder P2P-skakels (byvoorbeeld oor SMB/TCP) tussen callbacks.
- `wmiexecute`: Voer ’n command op die plaaslike of gespesifiseerde afgeleë stelsel uit met behulp van WMI, met opsionele credentials vir impersonation.
- `net_dclist`: Haal ’n lys van domain controllers vir die gespesifiseerde domain op, wat nuttig is om potensiële teikens vir laterale beweging te identifiseer.
- `net_localgroup`: Lys plaaslike groepe op die gespesifiseerde rekenaar, en gebruik localhost as verstek indien geen rekenaar gespesifiseer word nie.
- `net_localgroup_member`: Haal plaaslike groepslidmaatskap vir ’n gespesifiseerde groep op die plaaslike of afgeleë rekenaar op, wat enumeration van users in spesifieke groepe moontlik maak.
- `net_shares`: Lys remote shares en hul toeganklikheid op die gespesifiseerde rekenaar, wat nuttig is om potensiële teikens vir laterale beweging te identifiseer.
- `socks`: Aktiveer ’n SOCKS 5-compliant proxy op die teikennetwerk, wat tunneling van verkeer deur die compromised host moontlik maak. Versoenbaar met tools soos proxychains.
- `rpfwd`: Begin luister op ’n gespesifiseerde port op die teikenhost en forward verkeer deur Mythic na ’n remote IP en port, wat remote access tot services op die teikennetwerk moontlik maak.
- `listpipes`: Lys alle named pipes op die plaaslike stelsel, wat nuttig kan wees vir laterale beweging of privilege escalation deur met IPC-meganismes te interaksie.

Vir die laervlak-WMI-uitvoeringsprimitiewe wat onderliggend deur `jump_wmi` of `wmiexecute` gebruik word, kyk na [WmiExec](lateral-movement/wmiexec.md). Vir breër pivoting-patrone, kyk na [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Diverse Commands
- `help`: Vertoon gedetailleerde inligting oor spesifieke commands of algemene inligting oor alle beskikbare commands in die agent.
- `clear`: Merk tasks as 'cleared' sodat hulle nie deur agents opgetel kan word nie. Jy kan `all` spesifiseer om alle tasks te clear, of `task Num` om ’n spesifieke task te clear.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon is ’n Golang-agent wat in **Linux- en macOS**-executables compile.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Huidige build/profiel-notas

- Huidige Poseidon-builds teiken Linux en macOS op beide `x86_64` en `arm64`.
- Ondersteunde uitvoerformate sluit in native uitvoerbare lêers plus shared-library-styl uitvoer soos `dylib` en `so`.
- Poseidon ondersteun `http`, `websocket`, `tcp` en `dynamichttp`, en huidige builders stel multi-egress-instellings soos `egress_order` en failover-drempels bloot.
- Poseidon se huidige capability-metadata adverteer ook browser scripts, file/process browser-integrasie, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd en P2P, sodat dit as ’n werklike Linux/macOS-pivot node kan werk eerder as net ’n eenvoudige remote shell.
- Build-tyd-opsies soos `proxy_bypass` en `garble` is die moeite werd om na te gaan wanneer jy óf skoner netwerkgedrag óf ekstra Go binary obfuscation benodig.
- `pty` is een van die nuttigste nuwer quality-of-life-opdragte vir Linux/macOS-
bedrywighede, omdat dit ’n interactive PTY oopmaak en ’n Mythic-kant-
poort kan blootstel vir vollediger terminale-interaksie sonder om na die ouer `sleep 0`
+ SOCKS-workaround terug te val.
- Poseidon se huidige dokumentasie is veral interessant vir macOS-swaar
tradecraft: `jxa` voer JavaScript for Automation in-memory uit,
`screencapture` neem die aangemelde desktop vas, `clipboard_monitor` stroom
pasteboard-veranderinge, `execute_library` laai ’n plaaslike dylib en roep ’n
funksie daaruit aan, en `libinject` dwing ’n afgeleë proses om ’n on-disk
dylib te laai.
- Vir langlopende take, onthou dat Poseidon post-exploitation-werk
in goroutines/threads uitvoer wat cooperative eerder as hard-killable is. Die
dokumentasie noem ook uitdruklik dat daar tans geen ingeboude agent
obfuscation is nie, dus maak build/profiel-vlak tradecraft meer saak as met sterk
geobfuskeerde kommersiële implants.

Vir macOS-spesifieke tradecraft rondom Mythic-gesteunde operasies, JAMF-abuse of MDM-as-C2-idees, kyk na [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Wanneer dit op Linux of macOS gebruik word, het dit ’n paar interessante opdragte:

### Algemene aksies

- `cat`: Druk die inhoud van ’n lêer
- `cd`: Verander die huidige werkgids
- `chmod`: Verander die toestemmings van ’n lêer
- `config`: Bekyk huidige config- en host-inligting
- `cp`: Kopieer ’n lêer van een ligging na ’n ander
- `curl`: Voer ’n enkele web request uit met opsionele headers en method
- `upload`: Laai ’n lêer na die target op
- `download`: Laai ’n lêer van die target-stelsel na die plaaslike masjien af
- En vele meer

### Soek na sensitiewe inligting

- `triagedirectory`: Vind interessante lêers binne ’n gids op ’n host, soos sensitiewe lêers of credentials.
- `getenv`: Kry al die huidige environment variables.

### macOS-spesifieke tradecraft

- `jxa`: Voer JavaScript for Automation in-memory via `OSAScript` uit, wat
nuttig is vir native macOS post-exploitation sonder om afsonderlike script-
lêers te laat.
- `clipboard_monitor`: Poll die pasteboard en rapporteer veranderinge terug aan Mythic,
wat handig is vir credential/token theft-workflows wat op copy/paste staatmaak.
- `screencapture`: Neem die gebruiker se desktop op macOS vas.
- `execute_library`: Laai ’n dylib vanaf skyf en roep ’n spesifieke exported function aan.
- `libinject`: Inject ’n shellcode stub wat ’n ander macOS-proses dwing om ’n dylib vanaf skyf te laai.
- `persist_launchd`: Skep LaunchAgent / LaunchDaemon-persistence direk vanaf die agent.

### Beweeg lateraal

- `ssh`: SSH na ’n host met die aangewese credentials en maak ’n PTY oop sonder om ssh te spawn.
- `sshauth`: SSH na gespesifiseerde host(s) met die aangewese credentials. Jy kan dit ook gebruik om ’n spesifieke opdrag op die remote hosts via SSH uit te voer of om lêers daarmee te SCP.
- `link_tcp`: Link na ’n ander agent oor TCP, wat direkte kommunikasie tussen agents moontlik maak.
- `link_webshell`: Link na ’n agent deur die webshell P2P-profiel te gebruik, wat remote access tot die agent se webinterface moontlik maak.
- `rpfwd`: Start of stop ’n Reverse Port Forward, wat remote access tot dienste op die target-netwerk moontlik maak.
- `socks`: Start of stop ’n SOCKS5-proxy op die target-netwerk, wat tunneling van verkeer deur die compromised host moontlik maak. Versoenbaar met tools soos proxychains.
- `portscan`: Scan host(s) vir oop poorte, nuttig om potensiële targets vir lateral movement of verdere attacks te identifiseer.

### Prosesuitvoering

- `shell`: Voer ’n enkele shell-opdrag via /bin/sh uit, wat direkte uitvoering van opdragte op die target-stelsel moontlik maak.
- `run`: Voer ’n opdrag vanaf skyf met arguments uit, wat die uitvoering van binaries of scripts op die target-stelsel moontlik maak.
- `pty`: Maak ’n interactive PTY oop, wat direkte interaksie met die shell op die target-stelsel moontlik maak.






## Verwysings

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [Transforming Red Team Ops with Mythic’s Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
{{#include ../banners/hacktricks-training.md}}
