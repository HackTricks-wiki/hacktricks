# AD CS Μόνιμη παραμονή στο Domain

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή είναι μια περίληψη των τεχνικών domain persistence που μοιράζονται στο [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Δείτε το για περισσότερες λεπτομέρειες.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

Πώς μπορείτε να καταλάβετε ότι ένα certificate είναι CA certificate;

Μπορεί να καθοριστεί ότι ένα certificate είναι CA certificate εάν πληρούνται αρκετές προϋποθέσεις:

- Το certificate αποθηκεύεται στον CA server, με το private key του να προστατεύεται από το DPAPI της μηχανής, ή από hardware όπως TPM/HSM εάν το λειτουργικό σύστημα το υποστηρίζει.
- Τα πεδία Issuer και Subject του certificate ταιριάζουν με το distinguished name της CA.
- Μια επέκταση "CA Version" υπάρχει αποκλειστικά στα CA certificates.
- Το certificate δεν περιλαμβάνει πεδία Extended Key Usage (EKU).

Για να εξαχθεί το private key αυτού του certificate, το εργαλείο `certsrv.msc` στον CA server είναι η υποστηριζόμενη μέθοδος μέσω του ενσωματωμένου GUI. Παρ' όλα αυτά, αυτό το certificate δεν διαφέρει από άλλα που είναι αποθηκευμένα στο σύστημα· επομένως μέθοδοι όπως η [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) μπορούν να εφαρμοστούν για την εξαγωγή.

Το certificate και το private key μπορούν επίσης να αποκτηθούν χρησιμοποιώντας Certipy με την ακόλουθη εντολή:
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
> Ο χρήστης που στοχεύεται για πλαστογράφηση πιστοποιητικού πρέπει να είναι ενεργός και ικανός να αυθεντικοποιηθεί στο Active Directory για να επιτύχει η διαδικασία. Η πλαστογράφηση πιστοποιητικού για ειδικούς λογαριασμούς όπως krbtgt είναι αναποτελεσματική.

Αυτό το πλαστογραφημένο πιστοποιητικό θα είναι **έγκυρο** μέχρι την καθορισμένη ημερομηνία λήξης και όσο **το root CA πιστοποιητικό είναι έγκυρο** (συνήθως από 5 έως **10+ χρόνια**). Είναι επίσης έγκυρο για **μηχανήματα**, οπότε σε συνδυασμό με το **S4U2Self**, ένας επιτιθέμενος μπορεί να **διατηρήσει persistence σε οποιαδήποτε domain machine** για όσο το πιστοποιητικό CA είναι έγκυρο.\ Επιπλέον, τα **πιστοποιητικά που δημιουργούνται** με αυτή τη μέθοδο **δεν μπορούν να ανακληθούν**, καθώς η CA δεν είναι ενήμερη γι' αυτά.

### Λειτουργία υπό την αυστηρή εφαρμογή αντιστοίχισης πιστοποιητικών (2025+)

Από τις 11 Φεβρουαρίου 2025 (μετά την κυκλοφορία του KB5014754), οι domain controllers έχουν ως προεπιλογή το **Full Enforcement** για τις αντιστοιχίσεις πιστοποιητικών. Στην πράξη αυτό σημαίνει ότι τα πλαστογραφημένα πιστοποιητικά σας πρέπει είτε:

- Να περιέχουν μια ισχυρή σύνδεση με τον λογαριασμό-στόχο (για παράδειγμα, την SID security extension), ή
- Να συνοδεύονται από μια ισχυρή, ρητή αντιστοίχιση στο αντικείμενο-στόχο μέσω του `altSecurityIdentities` attribute.

Μια αξιόπιστη προσέγγιση για persistence είναι να δημιουργήσετε (mint) ένα πλαστογραφημένο πιστοποιητικό αλυσοδεμένο στην κλεμμένη Enterprise CA και στη συνέχεια να προσθέσετε μια ισχυρή, ρητή αντιστοίχιση στο victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Σημειώσεις
- Εάν μπορείτε να δημιουργήσετε forged certificates που περιλαμβάνουν την SID security extension, αυτά θα αντιστοιχούν implicit ακόμα και υπό Full Enforcement. Διαφορετικά, προτιμήστε explicit strong mappings. Δείτε [account-persistence](account-persistence.md) για περισσότερα σχετικά με explicit mappings.
- Revocation δεν βοηθάει εδώ τους αμυνόμενους: τα forged certificates είναι άγνωστα στη CA database και επομένως δεν μπορούν να ανακληθούν.

## Εμπιστοσύνη σε Rogue CA Certificates - DPERSIST2

Το αντικείμενο `NTAuthCertificates` έχει οριστεί να περιέχει ένα ή περισσότερα **CA certificates** μέσα στο attribute `cacertificate`, το οποίο χρησιμοποιεί το Active Directory (AD). Η διαδικασία επαλήθευσης από τον **domain controller** ελέγχει το αντικείμενο `NTAuthCertificates` για μια εγγραφή που ταιριάζει με την **CA specified** στο πεδίο Issuer του πιστοποιητικού που εκτελεί την authentication. Η authentication προχωράει αν βρεθεί αντιστοιχία.

Ένα self-signed CA πιστοποιητικό μπορεί να προστεθεί στο αντικείμενο `NTAuthCertificates` από έναν επιτιθέμενο, εφόσον έχει έλεγχο πάνω σε αυτό το AD object. Κανονικά, μόνο μέλη της ομάδας **Enterprise Admin**, μαζί με **Domain Admins** ή **Administrators** στο **forest root’s domain**, έχουν άδεια να τροποποιήσουν αυτό το αντικείμενο. Μπορούν να επεξεργαστούν το αντικείμενο `NTAuthCertificates` χρησιμοποιώντας `certutil.exe` με την εντολή `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ή χρησιμοποιώντας το [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Επιπλέον χρήσιμες εντολές για αυτή την τεχνική:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Αυτή η ικανότητα είναι ιδιαίτερα σχετική όταν χρησιμοποιείται σε συνδυασμό με μια προηγουμένως περιγραφείσα μέθοδο που περιλαμβάνει το ForgeCert για δυναμική δημιουργία πιστοποιητικών.

> Post-2025 mapping considerations: η προσθήκη ενός rogue CA στο NTAuth καθιερώνει μόνο την εμπιστοσύνη στην issuing CA. Για να χρησιμοποιηθούν leaf certificates για logon όταν οι DCs βρίσκονται σε **Full Enforcement**, το leaf πρέπει είτε να περιέχει την επέκταση SID security είτε να υπάρχει ισχυρός ρητός mapping στο αντικείμενο-στόχο (π.χ. Issuer+Serial στο `altSecurityIdentities`). Δείτε {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Οι ευκαιρίες για **persistence** μέσω **τροποποιήσεων security descriptor σε στοιχεία του AD CS** είναι πολλές. Τροποποιήσεις που περιγράφονται στην ενότητα "[Domain Escalation](domain-escalation.md)" μπορούν να υλοποιηθούν κακόβουλα από έναν attacker με elevated access. Αυτό περιλαμβάνει την προσθήκη "control rights" (π.χ., WriteOwner/WriteDACL/etc.) σε ευαίσθητα στοιχεία όπως:

- Το **CA server’s AD computer** object
- Τον **CA server’s RPC/DCOM server**
- Οποιοδήποτε **descendant AD object or container** στο **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (για παράδειγμα, το Certificate Templates container, το Certification Authorities container, το NTAuthCertificates object, κ.λπ.)
- **AD groups delegated rights to control AD CS** από προεπιλογή ή από την οργάνωση (όπως το built-in Cert Publishers group και οποιοδήποτε από τα μέλη του)

Ένα παράδειγμα κακόβουλης υλοποίησης θα περιλάμβανε έναν attacker, που έχει **elevated permissions** στο domain, να προσθέτει το δικαίωμα **`WriteOwner`** στο default πρότυπο πιστοποιητικού **`User`**, με τον attacker να είναι ο principal για το δικαίωμα. Για να το εκμεταλλευτεί, ο attacker πρώτα θα άλλαζε την ιδιοκτησία του template **`User`** στον εαυτό του. Στη συνέχεια, η τιμή **mspki-certificate-name-flag** θα οριζόταν σε **1** στο template για να ενεργοποιηθεί το **`ENROLLEE_SUPPLIES_SUBJECT`**, επιτρέποντας σε έναν user να παρέχει Subject Alternative Name στο request. Κατόπιν, ο attacker θα μπορούσε να **enroll** χρησιμοποιώντας το **template**, επιλέγοντας ένα όνομα **domain administrator** ως alternative name, και να χρησιμοποιήσει το αποκτηθέν πιστοποιητικό για authentication ως ο DA.

Πρακτικά χειριστήρια που μπορεί να ρυθμίσουν οι attackers για μακροχρόνια domain persistence (βλέπε {{#ref}}domain-escalation.md{{#endref}} για πλήρεις λεπτομέρειες και detection):

- Flags πολιτικής CA που επιτρέπουν SAN από requesters (π.χ., ενεργοποίηση `EDITF_ATTRIBUTESUBJECTALTNAME2`). Αυτό κρατάει διαδρομές τύπου ESC1 εκμεταλλεύσιμες.
- Template DACL ή ρυθμίσεις που επιτρέπουν issuance ικανό για authentication (π.χ., προσθήκη Client Authentication EKU, ενεργοποίηση `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Έλεγχος του `NTAuthCertificates` object ή των CA containers για συνεχή επανεισαγωγή rogue issuers εάν οι defenders επιχειρήσουν cleanup.

> [!TIP]
> Σε hardened περιβάλλοντα μετά το KB5014754, ο συνδυασμός αυτών των misconfigurations με ρητά ισχυρά mappings (`altSecurityIdentities`) διασφαλίζει ότι τα εκδιδομένα ή πλαστογραφημένα πιστοποιητικά παραμένουν χρησιμοποιήσιμα ακόμη και όταν οι DCs εφαρμόζουν strong mapping.



## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
