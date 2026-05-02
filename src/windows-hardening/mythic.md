# Mythic

{{#include ../banners/hacktricks-training.md}}

## Wat is Mythic?

Mythic is 'n open-source, modulêre, samewerkende command and control (C2) framework ontwerp vir red teaming. Dit laat operators toe om agents (payloads) oor verskillende bedryfstelsels te bestuur en te ontplooi, insluitend Windows, Linux, en macOS. Mythic bied 'n browser UI vir multi-operator tasking, file handling, SOCKS/rpfwd management, en payload generation.

Anders as monolitiese frameworks, stuur die Mythic repository self nie payload types of C2 profiles saam nie. Agents, wrappers, en C2 profiles word tipies as eksterne komponente geïnstalleer en kan onafhanklik van Mythic core opgedateer word.

### Installation

Om Mythic te installeer, volg die instruksies op die amptelike **[Mythic repo](https://github.com/its-a-feature/Mythic)**. 'n Algemene bootstrap vanaf die Mythic directory is:
```bash
sudo make
sudo ./mythic-cli start
```
As Mythic reeds loop, kan jy gewoonlik ’n nuwe agent of profiel byvoeg met `./mythic-cli install github ...` en dan óf Mythic herbegin óf net die nuwe komponent direk begin.

### Agents

Mythic ondersteun verskeie agents, wat die **payloads is wat take op die gekompromitteerde stelsels uitvoer**. Elke agent kan aangepas word vir spesifieke behoeftes en kan op verskillende bedryfstelsels loop.

By verstek het Mythic geen agents geïnstalleer nie. Die open-source gemeenskap se agents is by [**https://github.com/MythicAgents**](https://github.com/MythicAgents), en die [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) is nuttig om vinnig ondersteunde bedryfstelsels, payload-formate, wrappers, en C2 profiles te kontroleer.

Om ’n agent van daardie org te installeer, kan jy hardloop:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Die `sudo -E` vorm is nuttig wanneer jy vanaf ’n nie-root-omgewing installeer. Jy kan nuwe agents byvoeg met die vorige command selfs al is Mythic reeds aan die gang.

### C2 Profiles

C2 profiles in Mythic definieer **hoe agents met die Mythic server kommunikeer**. Hulle spesifiseer die communication protocol, encryption methods, en ander settings. Jy kan C2 profiles skep en bestuur deur die Mythic web interface.

By default word Mythic met geen profiles geïnstalleer nie, maar dit is moontlik om sommige profiles van die repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) af te laai deur:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Huidige operator-relevante profiles om in gedagte te hou:

- [`http`](https://github.com/MythicC2Profiles/http): basiese asinchrone GET/POST-verkeer.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): meer buigsame HTTP-verkeer met veelvuldige callback domains, fail-over/round-robin-rotasie, pasgemaakte headers/query parameters, en message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) wat in cookies, headers, query parameters, of body geplaas word.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-gedrewe HTTP message shaping wanneer die statiese `http` profile te herkenbaar is.

### Wrapper payloads

Wrapper payloads laat jou toe om dieselfde agent logic te behou terwyl jy die on-disk representation verander wat afgelewer of gepersist word.

- `service_wrapper`: verander ’n ander payload in ’n Windows service executable, wat nuttig is wanneer die execution path ’n geldige service binary vereis.
- `scarecrow_wrapper`: omvou compatible shellcode met die ScareCrow loader om loader-backte outputs soos EXE/DLL/CPL te genereer.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo is ’n Windows agent geskryf in C# met die 4.0 .NET Framework, ontwerp om gebruik te word in SpecterOps training offerings.

Installeer dit met:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Huidige build/profile notas

- Apollo kan tans `WinExe`, `Shellcode`, `Service`, en `Source` payloads uitstuur.
- Die algemeen gebruikte Apollo profiles is `http`, `httpx`, `smb`, `tcp`, en `websocket`.
- `httpx` is gewoonlik die meer buigsame opsie wanneer jy domain rotation, proxy support, custom message placement, en message transforms nodig het in plaas van die ouer statiese `http` profile.
- Apollo ondersteun wrapper payloads soos `service_wrapper` en `scarecrow_wrapper`.
- `register_file` en `register_assembly` is die staging primitives vir `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, en `powerpick`. In huidige Apollo builds word daardie staged artifacts client-side as DPAPI-beskermde AES256 blobs gekas.
- `ls` en `ps` resultate integreer veral goed met Mythic se browser scripts en file/process browser, wat operator triage merkbaar vinniger maak in collaborative operations.

Hierdie agent het baie commands wat dit baie soortgelyk maak aan Cobalt Strike se Beacon met 'n paar ekstra's. Onder hulle ondersteun dit:

### Common actions

- `cat`: Druk die inhoud van 'n file uit
- `cd`: Verander die current working directory
- `cp`: Kopieer 'n file van een location na 'n ander
- `ls`: Lys files en directories in die current directory of gespesifiseerde path
- `ifconfig`: Kry network adapters en interfaces
- `netstat`: Kry TCP en UDP connection information
- `pwd`: Druk die current working directory uit
- `ps`: Lys running processes op die target system (met bygevoegde info)
- `jobs`: Lys alle running jobs geassosieer met long-running tasking
- `download`: Download 'n file van die target system na die local machine
- `upload`: Upload 'n file van die local machine na die target system
- `reg_query`: Query registry keys en values op die target system
- `reg_write_value`: Skryf 'n nuwe value na 'n gespesifiseerde registry key
- `sleep`: Verander die agent se sleep interval, wat bepaal hoe gereeld dit by die Mythic server incheck
- En baie ander, gebruik `help` om die volle lys van beskikbare commands te sien.

### Privilege escalation

- `getprivs`: Enable soveel privileges as moontlik op die current thread token
- `getsystem`: Open 'n handle na winlogon en duplicate die token, en eskaleer effektief privileges na SYSTEM level
- `make_token`: Skep 'n nuwe logon session en pas dit toe op die agent, wat impersonation van 'n ander user moontlik maak
- `steal_token`: Steel 'n primary token van 'n ander process, wat die agent toelaat om daardie process se user te impersonate
- `pth`: Pass-the-Hash aanval, wat die agent toelaat om as 'n user te authenticate met hul NTLM hash sonder om die plaintext password nodig te hê
- `mimikatz`: Run Mimikatz commands om credentials, hashes, en ander sensitive information uit memory of die SAM database te extract
- `rev2self`: Revert die agent se token na sy primary token, en laat privileges effektief terugval na die original level
- `ppid`: Verander die parent process vir post-exploitation jobs deur 'n nuwe parent process ID te spesifiseer, wat beter control oor job execution context moontlik maak
- `printspoofer`: Execute PrintSpoofer commands om print spooler security measures te bypass, wat privilege escalation of code execution moontlik maak
- `dcsync`: Sync 'n user se Kerberos keys na die local machine, wat offline password cracking of verdere attacks moontlik maak
- `ticket_cache_add`: Voeg 'n Kerberos ticket by die current logon session of 'n gespesifiseerde een, wat ticket reuse of impersonation moontlik maak

### Process execution

- `assembly_inject`: Laat toe om 'n .NET assembly loader in 'n remote process in te inject
- `blockdlls`: Block nie-Microsoft signed DLLs om te load in post-exploitation jobs
- `execute_assembly`: Execute 'n .NET assembly in die context van die agent
- `execute_coff`: Execute 'n COFF file in memory, wat in-memory execution van compiled code moontlik maak
- `execute_pe`: Execute 'n unmanaged executable (PE)
- `get_injection_techniques`: Wys beskikbare injection techniques en die tans geselekteerde een
- `inline_assembly`: Execute 'n .NET assembly in 'n disposable AppDomain, wat tydelike execution van code moontlik maak sonder om die agent se main process te beïnvloed
- `register_assembly`: Registreer 'n .NET assembly vir latere execution
- `register_file`: Registreer 'n file in die agent cache vir latere `execute_*` of PowerShell tasking
- `run`: Execute 'n binary op die target system, met die system se PATH om die executable te vind
- `set_injection_technique`: Verander die injection primitive wat deur post-exploitation jobs gebruik word
- `shinject`: Inject shellcode in 'n remote process, wat in-memory execution van arbitrary code moontlik maak
- `inject`: Inject agent shellcode in 'n remote process, wat in-memory execution van die agent se code moontlik maak
- `spawn`: Spawn 'n nuwe agent session in die gespesifiseerde executable, wat execution van shellcode in 'n nuwe process moontlik maak
- `spawnto_x64` en `spawnto_x86`: Verander die default binary wat in post-exploitation jobs gebruik word na 'n gespesifiseerde path in plaas daarvan om `rundll32.exe` sonder params te gebruik, wat baie noisy is.

### Mythic Forge

Dit laat toe om **load COFF/BOF** files vanaf die Mythic Forge te, wat 'n repository is van pre-compiled payloads en tools wat op die target system uitgevoer kan word. Met al die commands wat gelaai kan word, sal dit moontlik wees om common actions uit te voer deur hulle in die current agent process as BOFs uit te voer (gewoonlik met beter OPSEC as om 'n aparte process te spawn).

Begin om hulle te installeer met:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, use `forge_collections` om die COFF/BOF modules van die Mythic Forge te wys om hulle te kan kies en in die agent se memory te laai vir execution. By default, the following 2 collections are added in Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

After one module is loaded, it'll appear in the list as another command like `forge_bof_sa-whoami` or `forge_bof_sa-netuser`.

### PowerShell & scripting execution

- `powershell_import`: Imports a new PowerShell script (.ps1) into the agent cache for later execution
- `powershell`: Executes a PowerShell command in the context of the agent, allowing for advanced scripting and automation
- `powerpick`: Injects a PowerShell loader assembly into a sacrificial process and executes a PowerShell command (without powershell logging).
- `psinject`: Executes PowerShell in a specified process, allowing for targeted execution of scripts in the context of another process
- `shell`: Executes a shell command in the context of the agent, similar to running a command in cmd.exe

### Lateral Movement

- `jump_psexec`: Uses the PsExec technique to move laterally to a new host by first copying over the Apollo agent executable (apollo.exe) and executing it.
- `jump_wmi`: Uses the WMI technique to move laterally to a new host by first copying over the Apollo agent executable (apollo.exe) and executing it.
- `link` and `unlink`: Create and tear down P2P links (for example over SMB/TCP) between callbacks.
- `wmiexecute`: Executes a command on the local or specified remote system using WMI, with optional credentials for impersonation.
- `net_dclist`: Retrieves a list of domain controllers for the specified domain, useful for identifying potential targets for lateral movement.
- `net_localgroup`: Lists local groups on the specified computer, defaulting to localhost if no computer is specified.
- `net_localgroup_member`: Retrieves local group membership for a specified group on the local or remote computer, allowing for enumeration of users in specific groups.
- `net_shares`: Lists remote shares and their accessibility on the specified computer, useful for identifying potential targets for lateral movement.
- `socks`: Enables a SOCKS 5 compliant proxy on the target network, allowing for tunneling of traffic through the compromised host. Compatible with tools like proxychains.
- `rpfwd`: Starts listening on a specified port on the target host and forwards traffic through Mythic to a remote IP and port, allowing for remote access to services on the target network.
- `listpipes`: Lists all named pipes on the local system, which can be useful for lateral movement or privilege escalation by interacting with IPC mechanisms.

For the lower-level WMI execution primitives used underneath `jump_wmi` or `wmiexecute`, check [WmiExec](lateral-movement/wmiexec.md). For broader pivoting patterns, check [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Displays detailed information about specific commands or general information about all available commands in the agent.
- `clear`: Marks tasks as 'cleared' so they can't be picked up by agents. You can specify `all` to clear all tasks or `task Num` to clear a specific task.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon is a Golang agent that compiles into **Linux and macOS** executables.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Current build/profile notes

- Huidige Poseidon-builds teiken Linux en macOS op beide `x86_64` en `arm64`.
- Ondersteunde uitvoerformate sluit in native uitvoerbare lêers plus shared-library-styl uitsette soos `dylib` en `so`.
- Poseidon ondersteun `http`, `websocket`, `tcp`, en `dynamichttp`, en huidige builders stel multi-egress instellings bloot soos `egress_order` en failover-drempels.
- Build-time opsies soos `proxy_bypass` en `garble` is die moeite werd om na te kyk wanneer jy óf skoner netwerkgedrag óf ekstra Go binary obfuscation nodig het.

Vir macOS-spesifieke tradecraft rondom Mythic-backed operations, JAMF abuse, of MDM-as-C2 idees, kyk [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Wanneer dit op Linux of macOS gebruik word, het dit 'n paar interessante commands:

### Common actions

- `cat`: Druk die inhoud van 'n lêer uit
- `cd`: Verander die huidige working directory
- `chmod`: Verander die permissions van 'n lêer
- `config`: Bekyk huidige config en host information
- `cp`: Kopieer 'n lêer van een ligging na 'n ander
- `curl`: Voer 'n enkele web request uit met opsionele headers en method
- `upload`: Laai 'n lêer op na die target
- `download`: Laai 'n lêer van die target system af na die local machine
- En nog baie meer

### Search Sensitive Information

- `triagedirectory`: Vind interessante lêers binne 'n directory op 'n host, soos sensitive files of credentials.
- `getenv`: Kry al die huidige environment variables.

### Move laterally

- `ssh`: SSH na host met die aangewese credentials en open 'n PTY sonder om ssh te spawn.
- `sshauth`: SSH na gespesifiseerde host(s) met die aangewese credentials. Jy kan dit ook gebruik om 'n spesifieke command op die remote hosts via SSH uit te voer of om dit te gebruik om files via SCP te kopieer.
- `link_tcp`: Koppel aan nog 'n agent oor TCP, wat direkte communication tussen agents toelaat.
- `link_webshell`: Koppel aan 'n agent met die webshell P2P profile, wat remote access tot die agent se web interface toelaat.
- `rpfwd`: Begin of Stop 'n Reverse Port Forward, wat remote access tot services op die target network toelaat.
- `socks`: Begin of Stop 'n SOCKS5 proxy op die target network, wat tunneling van traffic deur die compromised host toelaat. Versoenbaar met tools soos proxychains.
- `portscan`: Skandeer host(s) vir oop ports, nuttig om potensiële targets vir lateral movement of verdere attacks te identifiseer.

### Process execution

- `shell`: Voer 'n enkele shell command uit via /bin/sh, wat direkte execution van commands op die target system toelaat.
- `run`: Voer 'n command van disk uit met arguments, wat die execution van binaries of scripts op die target system toelaat.
- `pty`: Open 'n interaktiewe PTY, wat direkte interaksie met die shell op die target system toelaat.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
{{#include ../banners/hacktricks-training.md}}
