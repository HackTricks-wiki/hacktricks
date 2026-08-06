# Mythic

{{#include ../banners/hacktricks-training.md}}

## Wat is Mythic?

Mythic is 'n oopbron, modulêre, samewerkende command and control (C2)-raamwerk wat vir red teaming ontwerp is. Dit stel operators in staat om agents (payloads) oor verskillende bedryfstelsels, insluitend Windows, Linux en macOS, te bestuur en te ontplooi. Mythic bied 'n blaaier-UI vir multi-operator tasking, lêerhantering, SOCKS/rpfwd-bestuur en payload-generering.

Anders as monolitiese raamwerke, bevat die Mythic-repository self **nie** payload-tipes of C2-profiele nie. Agents, wrappers en C2-profiele word gewoonlik as eksterne komponente geïnstalleer en kan onafhanklik van Mythic core opgedateer word.

### Installasie

Om Mythic te installeer, volg die instruksies op die amptelike **[Mythic repo](https://github.com/its-a-feature/Mythic)**. 'n Algemene bootstrap vanuit die Mythic-gids is:
```bash
sudo make
sudo ./mythic-cli start
```
As Mythic reeds loop, kan jy normaalweg ’n nuwe agent of profile byvoeg met `./mythic-cli install github ...` en dan óf Mythic herbegin óf net die nuwe komponent direk begin.

### Agents

Mythic ondersteun verskeie agents, wat die **payloads is wat take op die gekompromitteerde stelsels uitvoer**. Elke agent kan volgens spesifieke behoeftes aangepas word en op verskillende bedryfstelsels loop.

By verstek het Mythic geen agents geïnstalleer nie. Die open-source community agents is beskikbaar by [**https://github.com/MythicAgents**](https://github.com/MythicAgents), en die [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) is nuttig om vinnig die ondersteunde bedryfstelsels, payload-formate, wrappers en C2 profiles na te gaan.<sup>[[1]](#references)</sup>

Om ’n agent vanaf daardie org te installeer, kan jy uitvoer:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Die `sudo -E`-vorm is nuttig wanneer jy vanuit ’n nie-root-omgewing installeer. Jy kan nuwe agente met die vorige opdrag byvoeg, selfs al loop Mythic reeds.

### C2-profiele

C2-profiele in Mythic definieer **hoe agente met die Mythic-bediener kommunikeer**. Hulle spesifiseer die kommunikasieprotokol, enkripsiemetodes en ander instellings. Jy kan C2-profiele deur die Mythic-webkoppelvlak skep en bestuur.

By verstek word Mythic sonder profiele geïnstalleer. Dit is egter moontlik om sommige profiele vanaf die repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) af te laai deur die volgende uit te voer:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Huidige profiele wat vir operators relevant is om in gedagte te hou:

- [`http`](https://github.com/MythicC2Profiles/http): basiese asynchronous GET/POST-verkeer.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): meer buigsame HTTP-verkeer met veelvuldige callback-domains, fail-over/round-robin-rotasie, pasgemaakte headers/query parameters, en message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) wat in cookies, headers, query parameters of die body geplaas word.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-gedrewe HTTP-message shaping wanneer die statiese `http`-profiel te herkenbaar is.

### Huidige platformnotas

- Baie publieke agents en profiele installeer nou met voorafgeboude remote container images.
As jy 'n komponent fork of dit plaaslik patch en Mythic steeds die ou
gedrag gebruik, ondersoek die gegenereerde `.env`-inskrywings vir `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT`, en `*_USE_VOLUME`; die aktivering van
`*_USE_BUILD_CONTEXT="true"` is gewoonlik wat Mythic van jou plaaslike Docker
context laat herbou, in plaas daarvan om stilweg die remote image te hergebruik.
- Browser scripts is een van Mythic se waardevolste quality-of-life-features
vir operators: hulle kan rou command output in tabelle, screenshot viewers,
download links, search links en buttons omskep wat follow-on tasking direk
vanuit die UI uitreik. Huidige Mythic builds laat elke operator toe om hul eie
scripts te behou, dit globaal of per task te aktiveer, en die beste resultate te
verkry wanneer agents gestruktureerde JSON eerder as plaintext terugstuur. Dit
is veral nuttig vir herhalende `ls`, `ps`, triage- en file-browser-workflows.<sup>[[4]](#references)[[6]](#references)</sup>
- Nuwer Mythic builds ondersteun ook interactive tasking- en Push C2-patterns
wat die behoefte aan `sleep 0` polling tydens PTY/SOCKS/rpfwd-swaar
operasies verminder. Wanneer 'n agent/profile dit ondersteun, is dit gewoonlik
laer in overhead as om die server met konstante check-ins te oorlaai net om 'n
interaktiewe kanaal bruikbaar te hou.<sup>[[3]](#references)</sup>
- Huidige 3.4-era Mythic builders is meer context-aware as wat ouer writeups
impliseer: build parameters kan nou gegroepeer of versteek word op grond van die
gekose OS of ander build options, payload types kan verklaar of hulle
veelvuldige C2 profiles of veelvuldige instances van dieselfde C2 in een build
ondersteun, en C2 parameter deviations laat 'n agent toe om velde te versteek
wat dit nie werklik implementeer nie. Dit is belangrik wanneer jy tussen `http`, `httpx`, `smb`,
`tcp` en `websocket` wissel, omdat die veilige/geldige build surface nie meer 'n
plat statiese vorm is nie.<sup>[[5]](#references)</sup>
- As jy 'n pasgemaakte agent/profile-paar bou en nie Mythic se JSON-messageformaat
of verstek-crypto op die wire wil hê nie, gebruik 'n
`translation_container`: Mythic verwyder die UUID, gee die encrypted blob en
key material via gRPC aan die translator, en verwag agent-native bytes
terug. Dit is die skoon manier om binary protocols, custom framing of
agent-side encryption te ondersteun sonder om die hele server te herskryf.
- Onthou dat linked/P2P callbacks nie net tasking aanstuur nie. Mythic se
`get_tasking`-flow kan ook responses plus `delegates`,
`socks`, `rpfwd` en `interactive`-data dra. In die praktyk kan een egress callback
inner callbacks en pivot channels in dieselfde polling loop bedien; indien die child
agents hul eie periodieke check-ins uitvoer, hou `get_delegate_tasks=false` die
parent daarvan om per ongeluk die inner callback se queued jobs te verbruik.

### Wrapper payloads

Wrapper payloads laat jou toe om dieselfde agent logic te behou terwyl jy die on-disk-representasie wat gelewer of gepersisteer word, verander.

- `service_wrapper`: omskep 'n ander payload in 'n Windows service executable, wat nuttig is wanneer die execution path 'n geldige service binary vereis.
- `scarecrow_wrapper`: wrap versoenbare shellcode met die ScareCrow loader om loader-backed outputs soos EXE/DLL/CPL te genereer.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo is 'n Windows-agent geskryf in C# wat die 4.0 .NET Framework gebruik, ontwerp vir gebruik in SpecterOps se training-aanbiedinge.<sup>[[2]](#references)</sup>

Installeer dit met:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Huidige build-/profielnotas

- Apollo kan tans `WinExe`-, `Shellcode`-, `Service`- en `Source`-payloads genereer.
- Die algemeen gebruikte Apollo-profiele is `http`, `httpx`, `smb`, `tcp` en `websocket`.
- `httpx` is gewoonlik die meer buigsame opsie wanneer jy domeinrotasie, proxy-ondersteuning, pasgemaakte boodskapplasing en message transforms benodig, eerder as die ouer statiese `http`-profiel.
- Apollo is een van die meer volledige community agents en stel tans Mythic-side-integrasies beskikbaar, soos browser scripts, file/process browser views, screenshots, keylogging, SOCKS, rpfwd, Push C2 en P2P routing.
- Apollo ondersteun wrapper payloads soos `service_wrapper` en `scarecrow_wrapper`.
- Apollo ondersteun dynamic command loading, sodat jy die aanvanklike payload klein kan hou en later ekstra commands of Forge-modules kan laai, in plaas daarvan om elke post-exploitation-vermoë in die eerste build te compileer.
- Wanneer shellcode-output gegenereer word, stel Apollo se huidige builder ook Donut-formaatkeuses (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) en Donut-bypass-gedrag (`None`, `Abort on fail`, `Continue on fail`) beskikbaar. Dit is nuttig indien die einddoel is om die shellcode weer met `service_wrapper`, `scarecrow_wrapper` of 'n custom loader te verpak.
- `register_file` en `register_assembly` is die staging-primitives vir `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` en `powerpick`. In huidige Apollo-builds word daardie staged artifacts aan die client-kant as DPAPI-beskermde AES256-blobs gecache.
- `ls`- en `ps`-resultate integreer besonder goed met Mythic se browser scripts en file/process browser, wat operator triage merkbaar vinniger maak in samewerkende operasies.
- Apollo se fork-and-run-jobs erf hul sacrificial process-instellings van
`spawnto_x86` / `spawnto_x64`, erf parent selection van `ppid`, en gebruik
dan die tans geselekteerde injection primitive. In die praktyk beteken dit dat
jou OPSEC-tuning vir een command dikwels tegelykertyd
`execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` en
`spawn` beïnvloed.
- Huidige gedokumenteerde Apollo injection backends sluit `CreateRemoteThread`,
`QueueUserAPC` (early-bird-styl) en `NtCreateThreadEx` via syscalls in. Gebruik
`get_injection_techniques` voordat jy lawaaierige post-exploitation uitvoer, en
`set_injection_technique` indien jy moet wegskakel van 'n primitive wat met die
target of die command wat jy wil uitvoer bots.
- `blockdlls` beïnvloed slegs sacrificial processes wat vir post-exploitation
jobs geskep word. Gekombineer met 'n minder verdagte `spawnto_x64`-target as die
verstek kaal `rundll32.exe`, is dit een van die maklikste Apollo-side-veranderings
om aan te bring voordat assembly-/PowerShell-swaar tasking uitgevoer word.

Hierdie agent het baie commands wat dit baie soortgelyk aan Cobalt Strike se Beacon met enkele ekstras maak. Onder andere ondersteun dit:

### Algemene aksies

- `cat`: Druk die inhoud van 'n file
- `cd`: Verander die huidige working directory
- `cp`: Copy 'n file van een ligging na 'n ander
- `ls`: Lys files en directories in die huidige directory of gespesifiseerde path
- `ifconfig`: Kry network adapters en interfaces
- `netstat`: Kry TCP- en UDP-connection information
- `pwd`: Druk die huidige working directory
- `ps`: Lys running processes op die target system (met bykomende info)
- `jobs`: Lys alle running jobs wat met long-running tasking geassosieer word
- `download`: Download 'n file van die target system na die plaaslike machine
- `upload`: Upload 'n file van die plaaslike machine na die target system
- `reg_query`: Query registry keys en values op die target system
- `reg_write_value`: Skryf 'n nuwe value na 'n gespesifiseerde registry key
- `sleep`: Verander die agent se sleep interval, wat bepaal hoe gereeld dit by die Mythic-server aanmeld
- En vele ander; gebruik `help` om die volledige lys van beskikbare commands te sien.

### Privilege escalation

- `getprivs`: Enable soveel privileges as moontlik op die huidige thread token
- `getsystem`: Open 'n handle na winlogon en duplicate die token, wat privileges effektief na SYSTEM-vlak eskaleer
- `make_token`: Skep 'n nuwe logon session en pas dit op die agent toe, wat impersonation van 'n ander user toelaat
- `steal_token`: Steel 'n primary token van 'n ander process, wat die agent toelaat om daardie process se user te impersonate
- `pth`: Pass-the-Hash attack, wat die agent toelaat om as 'n user te authenticateer deur hul NTLM-hash te gebruik sonder die plaintext password
- `mimikatz`: Run Mimikatz commands om credentials, hashes en ander sensitiewe information uit memory of die SAM-database te extract
- `rev2self`: Revert die agent se token na sy primary token, wat privileges effektief terugbring na die oorspronklike vlak
- `ppid`: Verander die parent process vir post-exploitation-jobs deur 'n nuwe parent process ID te spesifiseer, wat beter beheer oor die job execution context moontlik maak
- `printspoofer`: Execute PrintSpoofer commands om print spooler-security measures te bypass, wat privilege escalation of code execution moontlik maak
- `dcsync`: Sync 'n user se Kerberos-keys na die plaaslike machine, wat offline password cracking of verdere attacks moontlik maak
- `ticket_cache_add`: Add 'n Kerberos-ticket tot die huidige logon session of 'n gespesifiseerde een, wat ticket reuse of impersonation moontlik maak

### Process execution

- `assembly_inject`: Laat toe dat 'n .NET assembly loader in 'n remote process geïnject word
- `blockdlls`: Blokkeer nie-Microsoft-gesigned DLLs om in post-exploitation-jobs gelaai te word
- `execute_assembly`: Execute 'n .NET assembly in die context van die agent
- `execute_coff`: Execute 'n COFF-file in memory, wat in-memory execution van compiled code moontlik maak
- `execute_pe`: Execute 'n unmanaged executable (PE)
- `keylog_inject`: Inject 'n keylogger in 'n ander process en stream keystrokes terug na Mythic se keylog view
- `screenshot` / `screenshot_inject`: Capture die huidige desktop direk, of
deur 'n screenshot assembly in 'n target process/session te inject
- `get_injection_techniques`: Wys beskikbare injection techniques en die tans geselekteerde een
- `inline_assembly`: Execute 'n .NET assembly in 'n disposable AppDomain, wat tydelike execution van code moontlik maak sonder om die agent se hoofprocess te beïnvloed
- `register_assembly`: Register 'n .NET assembly vir latere execution
- `register_file`: Register 'n file in die agent cache vir latere `execute_*`- of PowerShell-tasking
- `run`: Execute 'n binary op die target system deur die system se PATH te gebruik om die executable te vind
- `set_injection_technique`: Verander die injection primitive wat deur post-exploitation-jobs gebruik word
- `shinject`: Inject shellcode in 'n remote process, wat in-memory execution van arbitrary code moontlik maak
- `inject`: Inject agent shellcode in 'n remote process, wat in-memory execution van die agent se code moontlik maak
- `spawn`: Spawn 'n nuwe agent session in die gespesifiseerde executable, wat die execution van shellcode in 'n nuwe process moontlik maak
- `spawnto_x64` en `spawnto_x86`: Verander die default binary wat in post-exploitation-jobs gebruik word na 'n gespesifiseerde path, in plaas daarvan om `rundll32.exe` sonder params te gebruik, wat baie noisy is.

### Mythic Forge

Dit laat jou toe om **COFF/BOF**-files uit die Mythic Forge te laai, wat 'n repository van pre-compiled payloads en tools is wat op die target system uitgevoer kan word. Met al die commands wat gelaai kan word, sal dit moontlik wees om algemene aksies uit te voer deur hulle as BOFs in die huidige agent process uit te voer (gewoonlik met beter OPSEC as om 'n aparte process te spawn).

Begin hulle installeer met:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Gebruik vervolgens `forge_collections` om die COFF/BOF-modules van die Mythic Forge te wys, sodat jy hulle kan kies en in die agent se geheue kan laai vir uitvoering. By verstek word die volgende 2 versamelings in Apollo bygevoeg:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Nadat een module gelaai is, sal dit in die lys verskyn as nog ’n opdrag, soos `forge_bof_sa-whoami` of `forge_bof_sa-netuser`.

Vir BOFs, onthou dat Forge **nie** bloot een plat argumentstring aan Apollo deurgee nie. Dit karteer BOF-parameters na Mythic se getikte-skikkingformaat en stuur hulle dan deur na Apollo se `execute_coff`-vloei. As ’n Forge-gelaaide BOF vreemd optree, kontroleer die verwagte BOF-argumenttipes / entrypoint eerder as net die opdragreël wat jy getik het. Let ook daarop dat Apollo se nuwer BOF-loader argumenthantering verander het in vergelyking met baie ouer 2.3.1-era-bouweergawes. Verouderde BOFs of ou versamelings kan dus misluk bloot omdat die marshalling-verwagtings verander het.

### PowerShell & scripting execution

- `powershell_import`: Voer ’n nuwe PowerShell-script (.ps1) in die agent se kas in vir latere uitvoering
- `powershell`: Voer ’n PowerShell-opdrag binne die agent se konteks uit, wat gevorderde scripting en outomatisering moontlik maak
- `powerpick`: Injecteer ’n PowerShell-loader assembly in ’n opofferingsproses en voer ’n PowerShell-opdrag uit (sonder powershell-logging).
- `psinject`: Voer PowerShell in ’n gespesifiseerde proses uit, wat geteikende uitvoering van scripts binne die konteks van ’n ander proses moontlik maak
- `shell`: Voer ’n shell-opdrag binne die agent se konteks uit, soortgelyk aan die uitvoering van ’n opdrag in cmd.exe

### Laterale Beweging

- `jump_psexec`: Gebruik die PsExec-tegniek om lateraal na ’n nuwe gasheer te beweeg deur eers die Apollo-agent se uitvoerbare lêer (apollo.exe) te kopieer en dit uit te voer.
- `jump_wmi`: Gebruik die WMI-tegniek om lateraal na ’n nuwe gasheer te beweeg deur eers die Apollo-agent se uitvoerbare lêer (apollo.exe) te kopieer en dit uit te voer.
- `link` en `unlink`: Skep en verwyder P2P-skakels (byvoorbeeld oor SMB/TCP) tussen callbacks.
- `wmiexecute`: Voer ’n opdrag op die plaaslike of gespesifiseerde afgeleë stelsel uit deur WMI te gebruik, met opsionele credentials vir impersonation.
- `net_dclist`: Haal ’n lys van domain controllers vir die gespesifiseerde domein op, wat nuttig is om moontlike teikens vir laterale beweging te identifiseer.
- `net_localgroup`: Lys plaaslike groepe op die gespesifiseerde rekenaar, met localhost as verstek indien geen rekenaar gespesifiseer is nie.
- `net_localgroup_member`: Haal lidmaatskap van ’n plaaslike groep vir ’n gespesifiseerde groep op die plaaslike of afgeleë rekenaar op, wat enumerasie van gebruikers in spesifieke groepe moontlik maak.
- `net_shares`: Lys afgeleë shares en hul toeganklikheid op die gespesifiseerde rekenaar, wat nuttig is om moontlike teikens vir laterale beweging te identifiseer.
- `socks`: Aktiveer ’n SOCKS 5-compliant proxy op die teiken-netwerk, wat tunneling van verkeer deur die gekompromitteerde gasheer moontlik maak. Versoenbaar met tools soos proxychains.
- `rpfwd`: Begin luister op ’n gespesifiseerde poort op die teikengasheer en stuur verkeer deur Mythic na ’n afgeleë IP en poort aan, wat afgeleë toegang tot dienste op die teiken-netwerk moontlik maak.
- `listpipes`: Lys alle named pipes op die plaaslike stelsel, wat nuttig kan wees vir laterale beweging of privilege escalation deur met IPC-meganismes te interaksie.

Vir die laervlak-WMI-uitvoeringsprimitiewe wat onderliggend deur `jump_wmi` of `wmiexecute` gebruik word, kyk na [WmiExec](lateral-movement/wmiexec.md). Vir breër pivoting-patrone, kyk na [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Vertoon gedetailleerde inligting oor spesifieke opdragte of algemene inligting oor alle beskikbare opdragte in die agent.
- `clear`: Merk take as 'cleared' sodat hulle nie deur agents opgetel kan word nie. Jy kan `all` spesifiseer om alle take skoon te maak, of `task Num` om ’n spesifieke taak skoon te maak.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon is ’n Golang-agent wat in **Linux- en macOS**-uitvoerbare lêers kompileer.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Huidige build/profile-notas

- Huidige Poseidon-builds teiken Linux en macOS op beide `x86_64` en `arm64`.
- Ondersteunde uitvoerformate sluit native uitvoerbare lêers sowel as shared-library-styl-uitvoer soos `dylib` en `so` in.
- Poseidon ondersteun `http`, `websocket`, `tcp` en `dynamichttp`, en huidige builders stel multi-egress-instellings soos `egress_order` en failover-drempels bloot.
- Poseidon se huidige capability-metadata adverteer ook browser scripts, file/process browser integration, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd en P2P. Dit beteken dit kan as ’n werklike Linux/macOS pivot node werk eerder as net ’n eenvoudige remote shell.
- Build-tyd-opsies soos `proxy_bypass` en `garble` is die moeite werd om na te gaan wanneer jy óf skoner netwerkgedrag óf ekstra Go binary obfuscation benodig.
- `pty` is een van die nuttigste nuwer quality-of-life-opdragte vir Linux/macOS-operasies, omdat dit ’n interaktiewe PTY oopmaak en ’n Mythic-kantpoort vir vollediger terminal interaction kan blootstel sonder om die ouer `sleep 0` + SOCKS-workaround te gebruik.
- Poseidon se huidige docs is veral interessant vir macOS-heavy tradecraft: `jxa` voer JavaScript for Automation in-memory uit, `screencapture` neem die aangemelde desktop vas, `clipboard_monitor` stroom pasteboard-veranderinge, `execute_library` laai ’n plaaslike dylib en roep ’n funksie daaruit, en `libinject` dwing ’n remote process om ’n dylib vanaf die skyf te laai.
- Vir langlopende take, onthou dat Poseidon post-exploitation-werk uitvoer in goroutines/threads wat cooperative eerder as hard-killable is. Die docs noem ook uitdruklik dat daar tans geen ingeboude agent obfuscation is nie, dus is build/profile-vlak tradecraft belangriker as met sterk geobfuskeerde kommersiële implants.

Vir macOS-spesifieke tradecraft rondom Mythic-backed-operasies, JAMF abuse of MDM-as-C2-idees, kyk na [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Wanneer dit op Linux of macOS gebruik word, het dit ’n paar interessante opdragte:

### Algemene aksies

- `cat`: Druk die inhoud van ’n lêer
- `cd`: Verander die huidige werkgids
- `chmod`: Verander die permissions van ’n lêer
- `config`: Bekyk huidige config en host-inligting
- `cp`: Kopieer ’n lêer van een ligging na ’n ander
- `curl`: Voer ’n enkele web request uit met opsionele headers en method
- `upload`: Laai ’n lêer na die target op
- `download`: Laai ’n lêer vanaf die target system na die plaaslike masjien af
- En vele meer

### Soek sensitiewe inligting

- `triagedirectory`: Vind interessante lêers binne ’n gids op ’n host, soos sensitiewe lêers of credentials.
- `getenv`: Kry al die huidige environment variables.

### macOS-spesifieke tradecraft

- `jxa`: Voer JavaScript for Automation in-memory via `OSAScript` uit, wat nuttig is vir native macOS post-exploitation sonder om afsonderlike script-lêers neer te lê.
- `clipboard_monitor`: Poll die pasteboard en rapporteer veranderinge terug aan Mythic, wat handig is vir credential/token theft-workflows wat op copy/paste staatmaak.
- `screencapture`: Neem die gebruiker se desktop op macOS vas.
- `execute_library`: Laai ’n dylib vanaf die skyf en roep ’n spesifieke exported function.
- `libinject`: Inject ’n shellcode stub wat ’n ander macOS process dwing om ’n dylib vanaf die skyf te laai.
- `persist_launchd`: Skep LaunchAgent / LaunchDaemon persistence direk vanaf die agent.

### Beweeg lateraal

- `ssh`: SSH na ’n host met die aangewese credentials en maak ’n PTY oop sonder om ssh te spawn.
- `sshauth`: SSH na gespesifiseerde host(s) met die aangewese credentials. Jy kan dit ook gebruik om ’n spesifieke command op die remote hosts via SSH uit te voer of om lêers met SCP te kopieer.
- `link_tcp`: Link na ’n ander agent oor TCP, wat direkte kommunikasie tussen agents moontlik maak.
- `link_webshell`: Link na ’n agent met die webshell P2P-profile, wat remote access tot die agent se web interface moontlik maak.
- `rpfwd`: Start of stop ’n Reverse Port Forward, wat remote access tot dienste op die target network moontlik maak.
- `socks`: Start of stop ’n SOCKS5-proxy op die target network, wat tunneling van traffic deur die compromised host moontlik maak. Versoenbaar met tools soos proxychains.
- `portscan`: Scan host(s) vir oop poorte, nuttig om potensiële teikens vir lateral movement of verdere attacks te identifiseer.

### Process execution

- `shell`: Voer ’n enkele shell command via /bin/sh uit, wat direkte execution van commands op die target system moontlik maak.
- `run`: Voer ’n command vanaf die skyf met arguments uit, wat die execution van binaries of scripts op die target system moontlik maak.
- `pty`: Maak ’n interaktiewe PTY oop, wat direkte interaksie met die shell op die target system moontlik maak.

## Verwysings

- [1] [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transforming Red Team Ops with Mythic's Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)

{{#include ../banners/hacktricks-training.md}}
