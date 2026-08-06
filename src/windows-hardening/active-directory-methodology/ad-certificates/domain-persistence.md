# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή είναι μια σύνοψη των τεχνικών domain persistence που παρουσιάζονται στο [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Ανατρέξτε σε αυτό για περισσότερες λεπτομέρειες.<sup>[[5]](#references)</sup>

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

Πώς μπορείτε να καταλάβετε ότι ένα πιστοποιητικό είναι CA certificate;

Μπορεί να προσδιοριστεί ότι ένα πιστοποιητικό είναι CA certificate εάν πληρούνται αρκετές προϋποθέσεις:<sup>[[5]](#references)</sup>

- Το πιστοποιητικό είναι αποθηκευμένο στον CA server, με το ιδιωτικό του κλειδί ασφαλισμένο από το DPAPI του μηχανήματος ή από hardware, όπως TPM/HSM, εάν το υποστηρίζει το λειτουργικό σύστημα.
- Τα πεδία Issuer και Subject του πιστοποιητικού αντιστοιχούν στο distinguished name του CA.
- Μια επέκταση "CA Version" υπάρχει αποκλειστικά στα CA certificates.
- Το πιστοποιητικό δεν περιέχει πεδία Extended Key Usage (EKU).

Για την εξαγωγή του ιδιωτικού κλειδιού αυτού του πιστοποιητικού, το εργαλείο `certsrv.msc` στον CA server είναι η υποστηριζόμενη μέθοδος μέσω του ενσωματωμένου GUI. Παρ' όλα αυτά, αυτό το πιστοποιητικό δεν διαφέρει από τα υπόλοιπα που είναι αποθηκευμένα στο σύστημα· επομένως, μπορούν να εφαρμοστούν μέθοδοι όπως η [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) για την εξαγωγή του.

Το πιστοποιητικό και το ιδιωτικό κλειδί μπορούν επίσης να ληφθούν με το Certipy, χρησιμοποιώντας την ακόλουθη εντολή:<sup>[[2]](#references)</sup>
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Μετά την απόκτηση του πιστοποιητικού CA και του ιδιωτικού κλειδιού του σε μορφή `.pfx`, μπορούν να χρησιμοποιηθούν εργαλεία όπως το [ForgeCert](https://github.com/GhostPack/ForgeCert) για τη δημιουργία έγκυρων πιστοποιητικών:
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
> Ο χρήστης-στόχος για την πλαστογράφηση πιστοποιητικού πρέπει να είναι ενεργός και να μπορεί να πραγματοποιήσει authentication στο Active Directory, ώστε η διαδικασία να ολοκληρωθεί με επιτυχία. Η πλαστογράφηση πιστοποιητικού για ειδικούς λογαριασμούς όπως ο krbtgt είναι αναποτελεσματική.

Αυτό το πλαστογραφημένο πιστοποιητικό θα είναι **έγκυρο** μέχρι την ημερομηνία λήξης που καθορίστηκε και **όσο το πιστοποιητικό του root CA παραμένει έγκυρο** (συνήθως από 5 έως **10+ χρόνια**). Είναι επίσης έγκυρο για **μηχανήματα**, επομένως σε συνδυασμό με το **S4U2Self**, ένας attacker μπορεί να **διατηρήσει persistence σε οποιοδήποτε μηχάνημα του domain** για όσο διάστημα παραμένει έγκυρο το πιστοποιητικό του CA.\
Επιπλέον, τα **πιστοποιητικά που δημιουργούνται** με αυτήν τη μέθοδο **δεν μπορούν να ανακληθούν**, καθώς το CA δεν τα γνωρίζει.

### Λειτουργία υπό το Strong Certificate Mapping Enforcement (2025+)

Από τις 11 Φεβρουαρίου 2025 (μετά την ανάπτυξη του KB5014754), οι domain controllers χρησιμοποιούν από προεπιλογή το **Full Enforcement** για τα certificate mappings. Πρακτικά, αυτό σημαίνει ότι τα πλαστογραφημένα πιστοποιητικά σας πρέπει είτε:

- Να περιέχουν ισχυρή σύνδεση με τον λογαριασμό-στόχο (για παράδειγμα, το SID security extension), είτε
- Να συνδυάζονται με ένα ισχυρό, explicit mapping στο attribute `altSecurityIdentities` του αντικειμένου-στόχου.<sup>[[1]](#references)</sup>

Μια αξιόπιστη προσέγγιση για persistence είναι η δημιουργία ενός πλαστογραφημένου πιστοποιητικού που συνδέεται μέσω chain με το κλεμμένο Enterprise CA και, στη συνέχεια, η προσθήκη ενός ισχυρού explicit mapping στο victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Σημειώσεις
- Αν μπορείτε να δημιουργήσετε forged certificates που περιλαμβάνουν το SID security extension, αυτά θα αντιστοιχίζονται implicit ακόμη και υπό το Full Enforcement. Διαφορετικά, προτιμήστε explicit strong mappings. Δείτε το [account-persistence](account-persistence.md) για περισσότερες πληροφορίες σχετικά με τα explicit mappings.
- Η ανάκληση δεν βοηθά τους defenders εδώ: τα forged certificates είναι άγνωστα στη βάση δεδομένων της CA και επομένως δεν μπορούν να ανακληθούν.

#### Forging συμβατό με Full-Enforcement (SID-aware)

Τα ενημερωμένα εργαλεία σάς επιτρέπουν να ενσωματώνετε το SID απευθείας, διατηρώντας τα golden certificates usable ακόμη και όταν οι DCs απορρίπτουν weak mappings:<sup>[[3]](#references)</sup>
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Με την ενσωμάτωση του SID αποφεύγετε να αγγίξετε το `altSecurityIdentities`, το οποίο ενδέχεται να παρακολουθείται, ενώ εξακολουθείτε να ικανοποιείτε τους ελέγχους ισχυρής αντιστοίχισης.

## Εμπιστοσύνη σε Rogue CA Certificates - DPERSIST2

Το αντικείμενο `NTAuthCertificates` ορίζεται ώστε να περιέχει ένα ή περισσότερα **CA certificates** μέσα στο attribute `cacertificate`, τα οποία αξιοποιεί το Active Directory (AD). Η διαδικασία επαλήθευσης από τον **domain controller** περιλαμβάνει τον έλεγχο του αντικειμένου `NTAuthCertificates` για μια καταχώριση που αντιστοιχεί στο **CA** που καθορίζεται στο πεδίο Issuer του **certificate** που χρησιμοποιείται για authentication. Η authentication συνεχίζεται εάν βρεθεί αντιστοίχιση.<sup>[[5]](#references)</sup>

Ένα self-signed CA certificate μπορεί να προστεθεί στο αντικείμενο `NTAuthCertificates` από έναν attacker, υπό την προϋπόθεση ότι έχει τον έλεγχο αυτού του AD object. Κανονικά, μόνο μέλη της ομάδας **Enterprise Admin**, μαζί με τους **Domain Admins** ή τους **Administrators** στο **forest root’s domain**, έχουν δικαίωμα τροποποίησης αυτού του object. Μπορούν να επεξεργαστούν το αντικείμενο `NTAuthCertificates` χρησιμοποιώντας το `certutil.exe` με την εντολή `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` ή χρησιμοποιώντας το [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Πρόσθετες χρήσιμες εντολές για αυτήν την τεχνική:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Αυτή η δυνατότητα είναι ιδιαίτερα σχετική όταν χρησιμοποιείται σε συνδυασμό με μια μέθοδο που περιγράφηκε προηγουμένως και περιλαμβάνει το ForgeCert για τη δυναμική δημιουργία certificates.

> Μετά το mapping του 2025: η τοποθέτηση ενός rogue CA στο NTAuth εγκαθιδρύει trust μόνο στο issuing CA. Για να χρησιμοποιηθούν leaf certificates για logon όταν οι DCs βρίσκονται σε **Full Enforcement**, το leaf πρέπει είτε να περιέχει το SID security extension είτε να υπάρχει strong explicit mapping στο αντικείμενο-στόχο (για παράδειγμα, Issuer+Serial στο `altSecurityIdentities`). Δείτε {{#ref}}account-persistence.md{{#endref}}.

## Κακόβουλη εσφαλμένη ρύθμιση - DPERSIST3

Οι ευκαιρίες για **persistence** μέσω τροποποιήσεων των **security descriptors** των στοιχείων του AD CS είναι πολλές. Οι τροποποιήσεις που περιγράφονται στην ενότητα "[Domain Escalation](domain-escalation.md)" μπορούν να υλοποιηθούν κακόβουλα από έναν attacker με elevated access. Αυτό περιλαμβάνει την προσθήκη "control rights" (π.χ. WriteOwner/WriteDACL/etc.) σε ευαίσθητα στοιχεία όπως:<sup>[[5]](#references)</sup>

- Το αντικείμενο **AD computer** του **CA server**
- Ο **RPC/DCOM server** του **CA server**
- Οποιοδήποτε **descendant AD object ή container** στο **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (για παράδειγμα, το Certificate Templates container, το Certification Authorities container, το NTAuthCertificates object κ.λπ.)
- **AD groups** στα οποία έχουν εκχωρηθεί δικαιώματα για τον έλεγχο του AD CS από προεπιλογή ή από τον οργανισμό (όπως το ενσωματωμένο Cert Publishers group και οποιοδήποτε από τα μέλη του)

Ένα παράδειγμα κακόβουλης υλοποίησης θα περιλάμβανε έναν attacker, ο οποίος διαθέτει **elevated permissions** στο domain, να προσθέτει το δικαίωμα **`WriteOwner`** στο προεπιλεγμένο **`User`** certificate template, με τον attacker να αποτελεί το principal για το συγκεκριμένο δικαίωμα. Για να το εκμεταλλευτεί, ο attacker θα άλλαζε πρώτα την ownership του **`User`** template υπέρ του. Στη συνέχεια, το **`mspki-certificate-name-flag`** θα οριζόταν σε **1** στο template, ώστε να ενεργοποιηθεί το **`ENROLLEE_SUPPLIES_SUBJECT`**, επιτρέποντας σε έναν user να παρέχει ένα Subject Alternative Name στο request. Έπειτα, ο attacker θα μπορούσε να κάνει **enroll** χρησιμοποιώντας το **template**, επιλέγοντας ως alternative name το όνομα ενός **domain administrator**, και να χρησιμοποιήσει το certificate που αποκτήθηκε για authentication ως DA.

Πρακτικές ρυθμίσεις που μπορεί να ορίσει ένας attacker για μακροχρόνιο domain persistence (δείτε το {{#ref}}domain-escalation.md{{#endref}} για πλήρεις λεπτομέρειες και detection):

- CA policy flags που επιτρέπουν SAN από requesters (π.χ. ενεργοποίηση του `EDITF_ATTRIBUTESUBJECTALTNAME2`). Αυτό διατηρεί exploitable τα paths τύπου ESC1.
- Template DACL ή settings που επιτρέπουν issuance με δυνατότητα authentication (π.χ. προσθήκη Client Authentication EKU, ενεργοποίηση του `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Έλεγχος του `NTAuthCertificates` object ή των CA containers, ώστε να επανεισάγονται συνεχώς rogue issuers αν οι defenders επιχειρήσουν cleanup.

> [!TIP]
> Σε hardened environments μετά το KB5014754, ο συνδυασμός αυτών των misconfigurations με explicit strong mappings (`altSecurityIdentities`) διασφαλίζει ότι τα certificates που έχουν εκδοθεί ή forged παραμένουν usable ακόμη και όταν οι DCs επιβάλλουν strong mapping.

### Κατάχρηση ανανέωσης certificate (ESC14) για persistence

Αν παραβιάσετε ένα certificate με δυνατότητα authentication (ή ένα Enrollment Agent certificate), μπορείτε να το **renew** επ' αόριστον, όσο το issuing template παραμένει published και το CA εξακολουθεί να trustάρει την issuer chain. Η ανανέωση διατηρεί τα αρχικά identity bindings, αλλά επεκτείνει τη validity, καθιστώντας δύσκολη την απομάκρυνση, εκτός αν διορθωθεί το template ή γίνει republish το CA.<sup>[[4]](#references)</sup>
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Αν οι domain controllers βρίσκονται σε **Full Enforcement**, προσθέστε `-sid <victim SID>` (ή χρησιμοποιήστε ένα template που εξακολουθεί να περιλαμβάνει το SID security extension), ώστε το renewed leaf certificate να συνεχίσει να αντιστοιχίζεται ισχυρά χωρίς να αγγίξετε το `altSecurityIdentities`. Οι επιτιθέμενοι με δικαιώματα διαχειριστή CA μπορούν επίσης να τροποποιήσουν το `policy\RenewalValidityPeriodUnits`, για να επιμηκύνουν τη διάρκεια ισχύος των renewed certificates πριν εκδώσουν ένα certificate για τον εαυτό τους.<sup>[[2]](#references)[[4]](#references)</sup>


## Αναφορές

- [1] [Microsoft KB5014754 – Αλλαγές στο authentication βάσει certificate σε Windows domain controllers (χρονοδιάγραμμα enforcement και strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Αναφορά εντολών και χρήση forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (ενσωματωμένο forge με υποστήριξη SID)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Επισκόπηση του ESC14 renewal abuse](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Κατάχρηση των Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
