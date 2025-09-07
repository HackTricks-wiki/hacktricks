# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή είναι μια περίληψη των τεχνικών διατήρησης στο domain που περιλαμβάνονται στο [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Δείτε το για περισσότερες λεπτομέρειες.

## Πλαστογράφηση Πιστοποιητικών με Κλαπέντα Πιστοποιητικά CA - DPERSIST1

Πώς μπορείτε να γνωρίζετε ότι ένα πιστοποιητικό είναι πιστοποιητικό CA;

Ένα πιστοποιητικό θεωρείται πιστοποιητικό CA αν πληρούνται διάφορες προϋποθέσεις:

- Το πιστοποιητικό είναι αποθηκευμένο στον CA server, με το ιδιωτικό κλειδί προστατευμένο από το DPAPI του μηχανήματος, ή από hardware όπως TPM/HSM εάν το λειτουργικό σύστημα το υποστηρίζει.
- Τα πεδία Issuer και Subject του πιστοποιητικού ταιριάζουν με το distinguished name του CA.
- Υπάρχει επέκταση "CA Version" αποκλειστικά στα πιστοποιητικά CA.
- Το πιστοποιητικό δεν περιέχει πεδία Extended Key Usage (EKU).

Για να εξαγάγετε το ιδιωτικό κλειδί αυτού του πιστοποιητικού, το εργαλείο `certsrv.msc` στον CA server είναι η υποστηριζόμενη μέθοδος μέσω του ενσωματωμένου GUI. Παρ' όλα αυτά, αυτό το πιστοποιητικό δεν διαφέρει από άλλα που είναι αποθηκευμένα στο σύστημα· επομένως, μπορούν να εφαρμοστούν μέθοδοι όπως η [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) για την εξαγωγή.

Το πιστοποιητικό και το ιδιωτικό κλειδί μπορούν επίσης να ληφθούν χρησιμοποιώντας το Certipy με την ακόλουθη εντολή:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Αφού αποκτηθεί το πιστοποιητικό CA και το private key του σε μορφή `.pfx`, εργαλεία όπως το [ForgeCert](https://github.com/GhostPack/ForgeCert) μπορούν να χρησιμοποιηθούν για να δημιουργήσουν έγκυρα πιστοποιητικά:
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
> Ο χρήστης που στοχεύεται για πλαστογράφηση πιστοποιητικού πρέπει να είναι ενεργός και ικανός να αυθεντικοποιηθεί στο Active Directory για να πετύχει η διαδικασία. Η πλαστογράφηση πιστοποιητικού για ειδικούς λογαριασμούς όπως krbtgt είναι αναποτελεσματική.

Αυτό το πλαστογραφημένο πιστοποιητικό θα είναι **έγκυρο** μέχρι την καθορισμένη ημερομηνία λήξης και όσο το ριζικό πιστοποιητικό CA είναι **έγκυρο** (συνήθως από 5 έως **10+ χρόνια**). Είναι επίσης έγκυρο για **μηχανήματα**, οπότε σε συνδυασμό με το **S4U2Self**, ένας επιτιθέμενος μπορεί να **διατηρήσει persistence σε οποιονδήποτε υπολογιστή του domain** για όσο το πιστοποιητικό CA είναι έγκυρο.\
Επιπλέον, τα **πιστοποιητικά που παράγονται** με αυτή τη μέθοδο **δεν μπορούν να ανακληθούν**, καθώς η CA δεν τα γνωρίζει.

### Operating under Strong Certificate Mapping Enforcement (2025+)

Since February 11, 2025 (after KB5014754 rollout), domain controllers default to **Full Enforcement** for certificate mappings. Practically this means your forged certificates must either:

- Να περιέχουν έναν ισχυρό σύνδεσμο με τον στοχευόμενο λογαριασμό (π.χ. την επέκταση ασφάλειας SID), ή
- Να συνοδεύονται από μια ισχυρή, ρητή αντιστοίχιση στο attribute `altSecurityIdentities` του στοχευόμενου αντικειμένου.

Μια αξιόπιστη προσέγγιση για persistence είναι να δημιουργήσετε ένα πλαστογραφημένο πιστοποιητικό συνδεδεμένο με την κλεμμένη Enterprise CA και στη συνέχεια να προσθέσετε μια ισχυρή ρητή αντιστοίχιση στον victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notes
- Εάν μπορείτε να δημιουργήσετε πλαστά πιστοποιητικά που περιλαμβάνουν την επέκταση ασφάλειας SID, αυτά θα αντιστοιχιστούν έμμεσα ακόμη και υπό Full Enforcement. Διαφορετικά, προτιμήστε ρητές ισχυρές αντιστοιχίσεις. Δείτε
[account-persistence](account-persistence.md) για περισσότερα σχετικά με ρητές αντιστοιχίσεις.
- Η ανάκληση δεν βοηθά τους υπερασπιστές εδώ: τα πλαστά πιστοποιητικά είναι άγνωστα στη βάση δεδομένων του CA και επομένως δεν μπορούν να ανακληθούν.

## Trusting Rogue CA Certificates - DPERSIST2

Το αντικείμενο `NTAuthCertificates` ορίζεται να περιέχει ένα ή περισσότερα **πιστοποιητικά CA** στο χαρακτηριστικό `cacertificate`, το οποίο χρησιμοποιεί το Active Directory (AD). Η διαδικασία επαλήθευσης από τον **ελεγκτή τομέα** περιλαμβάνει τον έλεγχο του αντικειμένου `NTAuthCertificates` για μια εγγραφή που ταιριάζει με την **CA που αναφέρεται** στο πεδίο Issuer του πιστοποιητικού που πραγματοποιεί την πιστοποίηση. Η αυθεντικοποίηση προχωρά εάν βρεθεί ταύτιση.

Ένα self-signed CA certificate μπορεί να προστεθεί στο αντικείμενο `NTAuthCertificates` από έναν επιτιθέμενο, εφόσον έχει έλεγχο πάνω σε αυτό το AD αντικείμενο. Κανονικά, μόνο μέλη της ομάδας **Enterprise Admin**, μαζί με **Domain Admins** ή **Administrators** στον **forest root’s domain**, έχουν άδεια να τροποποιήσουν αυτό το αντικείμενο. Μπορούν να επεξεργαστούν το αντικείμενο `NTAuthCertificates` χρησιμοποιώντας `certutil.exe` με την εντολή `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ή χρησιμοποιώντας το [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Αυτή η δυνατότητα είναι ιδιαίτερα σχετική όταν χρησιμοποιείται σε συνδυασμό με μια προηγουμένως περιγραφείσα μέθοδο που περιλαμβάνει το ForgeCert για δυναμική δημιουργία πιστοποιητικών.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Οι ευκαιρίες για **persistence** μέσω **security descriptor modifications of AD CS** components είναι άφθονες. Οι τροποποιήσεις που περιγράφονται στην "[Domain Escalation](domain-escalation.md)" ενότητα μπορούν να υλοποιηθούν κακόβουλα από έναν attacker με αυξημένη πρόσβαση. Αυτό περιλαμβάνει την προσθήκη "control rights" (π.χ., WriteOwner/WriteDACL/etc.) σε ευαίσθητα components όπως:

- Το αντικείμενο **AD computer** του CA server
- Ο **RPC/DCOM server** του CA server
- Οποιοδήποτε **descendant AD object or container** στο **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (για παράδειγμα, το Certificate Templates container, το Certification Authorities container, το NTAuthCertificates object, κ.λπ.)
- **AD groups delegated rights to control AD CS** είτε από προεπιλογή είτε από τον οργανισμό (όπως η built-in Cert Publishers group και οποιοδήποτε από τα μέλη της)

Ένα παράδειγμα κακόβουλης υλοποίησης θα περιελάμβανε έναν attacker, ο οποίος έχει **elevated permissions** στο domain, να προσθέτει την άδεια **`WriteOwner`** στο προεπιλεγμένο certificate template **`User`**, με τον attacker να είναι ο principal για το δικαίωμα. Για να το εκμεταλλευτεί, ο attacker πρώτα θα άλλαζε την ιδιοκτησία του template **`User`** στον εαυτό του. Έπειτα, το **`mspki-certificate-name-flag`** θα οριζόταν σε **1** στο template για να ενεργοποιηθεί το **`ENROLLEE_SUPPLIES_SUBJECT`**, επιτρέποντας σε έναν χρήστη να παρέχει ένα Subject Alternative Name στο request. Στη συνέχεια, ο attacker θα μπορούσε να **enroll** χρησιμοποιώντας το **template**, επιλέγοντας ένα όνομα **domain administrator** ως alternative name, και να χρησιμοποιήσει το αποκτηθέν certificate για authentication ως DA.

Πρακτικοί ρυθμιστικοί μοχλοί που οι attackers μπορεί να ορίσουν για μακροχρόνια domain persistence (βλ. {{#ref}}domain-escalation.md{{#endref}} για πλήρεις λεπτομέρειες και detection):

- CA policy flags that allow SAN from requesters (e.g., enabling `EDITF_ATTRIBUTESUBJECTALTNAME2`). This keeps ESC1-like paths exploitable.
- Template DACL or settings that allow authentication-capable issuance (e.g., adding Client Authentication EKU, enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlling the `NTAuthCertificates` object or the CA containers to continuously re-introduce rogue issuers if defenders attempt cleanup.

> [!TIP]
> Σε hardened περιβάλλοντα μετά το KB5014754, ο συνδυασμός αυτών των misconfigurations με ρητές ισχυρές αντιστοιχίσεις (`altSecurityIdentities`) εξασφαλίζει ότι τα issued ή forged certificates παραμένουν usable ακόμη και όταν οι DCs επιβάλλουν strong mapping.



## References

- Microsoft KB5014754 – Αλλαγές στην certificate-based authentication στους Windows domain controllers (enforcement timeline και strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference και χρήση forge/auth. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
