# Πιστοποιητικά AD

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή

### Στοιχεία ενός πιστοποιητικού

- Το **Subject** του πιστοποιητικού προσδιορίζει τον κάτοχό του.
- Ένα **Public Key** αντιστοιχίζεται με ένα ιδιωτικό κλειδί, ώστε να συνδέεται το πιστοποιητικό με τον νόμιμο κάτοχό του.
- Η **Validity Period**, η οποία ορίζεται από τις ημερομηνίες **NotBefore** και **NotAfter**, καθορίζει τη διάρκεια ισχύος του πιστοποιητικού.
- Ένας μοναδικός **Serial Number**, που παρέχεται από την Certificate Authority (CA), προσδιορίζει κάθε πιστοποιητικό.
- Το **Issuer** αναφέρεται στην CA που εξέδωσε το πιστοποιητικό.
- Το **SubjectAlternativeName** επιτρέπει την προσθήκη ονομάτων για το subject, προσφέροντας μεγαλύτερη ευελιξία στην ταυτοποίησή του.
- Το **Basic Constraints** προσδιορίζει αν το πιστοποιητικό προορίζεται για CA ή για τελική οντότητα και ορίζει περιορισμούς χρήσης.
- Τα **Extended Key Usages (EKUs)** καθορίζουν τους συγκεκριμένους σκοπούς του πιστοποιητικού, όπως η υπογραφή κώδικα ή η κρυπτογράφηση email, μέσω Object Identifiers (OIDs).
- Το **Signature Algorithm** καθορίζει τη μέθοδο υπογραφής του πιστοποιητικού.
- Η **Signature**, η οποία δημιουργείται με το ιδιωτικό κλειδί του issuer, εγγυάται τη γνησιότητα του πιστοποιητικού.<sup>[[4]](#references)</sup>

### Ειδικές επισημάνσεις

- Τα **Subject Alternative Names (SANs)** διευρύνουν τη δυνατότητα εφαρμογής ενός πιστοποιητικού σε πολλαπλές ταυτότητες, κάτι κρίσιμο για διακομιστές με πολλαπλά domains. Οι ασφαλείς διαδικασίες έκδοσης είναι απαραίτητες για την αποφυγή κινδύνων πλαστοπροσωπίας από attackers που χειραγωγούν τον ορισμό SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) στο Active Directory (AD)

Το AD CS αναγνωρίζει τα πιστοποιητικά CA σε ένα AD forest μέσω ειδικών containers, καθένα από τα οποία εξυπηρετεί ξεχωριστό σκοπό:<sup>[[4]](#references)</sup>

- Το container **Certification Authorities** περιέχει αξιόπιστα πιστοποιητικά root CA.
- Το container **Enrolment Services** περιέχει πληροφορίες για Enterprise CAs και τα certificate templates τους.
- Το αντικείμενο **NTAuthCertificates** περιλαμβάνει πιστοποιητικά CA που είναι εξουσιοδοτημένα για authentication στο AD.
- Το container **AIA (Authority Information Access)** διευκολύνει την επικύρωση της αλυσίδας πιστοποιητικών με ενδιάμεσα και cross CA certificates.

### Απόκτηση πιστοποιητικού: Ροή αιτήματος πιστοποιητικού από client

1. Η διαδικασία αιτήματος αρχίζει όταν οι clients εντοπίζουν μια Enterprise CA.
2. Μετά τη δημιουργία ζεύγους δημόσιου-ιδιωτικού κλειδιού, δημιουργείται ένα CSR που περιέχει ένα public key και άλλα στοιχεία.
3. Η CA αξιολογεί το CSR με βάση τα διαθέσιμα certificate templates και εκδίδει το πιστοποιητικό σύμφωνα με τα δικαιώματα του template.
4. Μετά την έγκριση, η CA υπογράφει το πιστοποιητικό με το ιδιωτικό της κλειδί και το επιστρέφει στον client.<sup>[[4]](#references)</sup>

### Certificate Templates

Αυτά τα templates, τα οποία ορίζονται στο AD, περιγράφουν τις ρυθμίσεις και τα δικαιώματα έκδοσης πιστοποιητικών, συμπεριλαμβανομένων των επιτρεπόμενων EKUs και των δικαιωμάτων enrollment ή τροποποίησης, τα οποία είναι κρίσιμα για τη διαχείριση της πρόσβασης στις υπηρεσίες πιστοποιητικών.<sup>[[4]](#references)</sup>

**Η έκδοση του schema του template έχει σημασία.** Τα παλαιότερα **v1** templates (για παράδειγμα, το ενσωματωμένο template **WebServer**) δεν διαθέτουν αρκετές σύγχρονες δυνατότητες επιβολής πολιτικών. Η έρευνα **ESC15/EKUwu** έδειξε ότι σε **v1 templates**, ο αιτών μπορεί να ενσωματώσει **Application Policies/EKUs** στο CSR, οι οποίες **υπερισχύουν των** EKUs που έχουν ρυθμιστεί στο template. Έτσι, μπορούν να αποκτηθούν πιστοποιητικά client-auth, enrollment agent ή code-signing με μόνο δικαιώματα enrollment. Προτιμήστε **v2/v3 templates**, αφαιρέστε ή αντικαταστήστε τα προεπιλεγμένα v1 templates και περιορίστε αυστηρά τα EKUs στον προβλεπόμενο σκοπό τους.<sup>[[1]](#references)</sup>

## Enrollment πιστοποιητικών

Η διαδικασία enrollment πιστοποιητικών ξεκινά από έναν διαχειριστή, ο οποίος **δημιουργεί ένα certificate template**, το οποίο στη συνέχεια **δημοσιεύεται** από μια Enterprise Certificate Authority (CA). Έτσι, το template γίνεται διαθέσιμο για enrollment από clients, με την προσθήκη του ονόματός του στο πεδίο `certificatetemplates` ενός αντικειμένου Active Directory.<sup>[[4]](#references)</sup>

Για να ζητήσει ένας client πιστοποιητικό, πρέπει να του έχουν εκχωρηθεί **δικαιώματα enrollment**. Αυτά τα δικαιώματα ορίζονται από security descriptors στο certificate template και στην ίδια την Enterprise CA. Για να είναι επιτυχές ένα αίτημα, πρέπει να έχουν εκχωρηθεί δικαιώματα και στις δύο θέσεις.

### Δικαιώματα enrollment template

Αυτά τα δικαιώματα καθορίζονται μέσω Access Control Entries (ACEs), οι οποίες ορίζουν δικαιώματα όπως:

- Δικαιώματα **Certificate-Enrollment** και **Certificate-AutoEnrollment**, καθένα από τα οποία συνδέεται με συγκεκριμένα GUIDs.
- Το **ExtendedRights**, το οποίο επιτρέπει όλα τα εκτεταμένα δικαιώματα.
- Τα **FullControl/GenericAll**, τα οποία παρέχουν πλήρη έλεγχο του template.

### Δικαιώματα enrollment Enterprise CA

Τα δικαιώματα της CA καθορίζονται στο security descriptor της, στο οποίο μπορείτε να αποκτήσετε πρόσβαση μέσω της κονσόλας διαχείρισης Certificate Authority. Ορισμένες ρυθμίσεις επιτρέπουν ακόμη και σε χρήστες με χαμηλά προνόμια να αποκτούν απομακρυσμένη πρόσβαση, κάτι που μπορεί να αποτελεί κίνδυνο ασφαλείας.

### Πρόσθετοι έλεγχοι έκδοσης

Ενδέχεται να εφαρμόζονται ορισμένοι έλεγχοι, όπως:

- **Έγκριση διαχειριστή**: Θέτει τα αιτήματα σε εκκρεμότητα μέχρι να εγκριθούν από έναν διαχειριστή πιστοποιητικών.
- **Enrolment Agents και εξουσιοδοτημένες υπογραφές**: Καθορίζουν τον αριθμό των απαιτούμενων υπογραφών σε ένα CSR και τα απαραίτητα Application Policy OIDs.

### Μέθοδοι υποβολής αιτημάτων πιστοποιητικών

Η υποβολή αιτημάτων πιστοποιητικών μπορεί να γίνει μέσω:

1. Του **Windows Client Certificate Enrollment Protocol** (MS-WCCE), με χρήση διεπαφών DCOM.
2. Του **ICertPassage Remote Protocol** (MS-ICPR), μέσω named pipes ή TCP/IP.
3. Της **web interface enrollment πιστοποιητικών**, με εγκατεστημένο τον ρόλο Certificate Authority Web Enrollment.
4. Του **Certificate Enrollment Service** (CES), σε συνδυασμό με την υπηρεσία Certificate Enrollment Policy (CEP).
5. Του **Network Device Enrollment Service** (NDES) για συσκευές δικτύου, με χρήση του Simple Certificate Enrollment Protocol (SCEP).

Οι χρήστες Windows μπορούν επίσης να ζητούν πιστοποιητικά μέσω του GUI (`certmgr.msc` ή `certlm.msc`) ή εργαλείων γραμμής εντολών (`certreq.exe` ή της εντολής PowerShell `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Έλεγχος ταυτότητας με πιστοποιητικό

Το Active Directory (AD) υποστηρίζει τον έλεγχο ταυτότητας με πιστοποιητικό, χρησιμοποιώντας κυρίως τα πρωτόκολλα **Kerberos** και **Secure Channel (Schannel)**.

### Διαδικασία ελέγχου ταυτότητας Kerberos

Στη διαδικασία ελέγχου ταυτότητας Kerberos, το αίτημα ενός χρήστη για Ticket Granting Ticket (TGT) υπογράφεται με το **ιδιωτικό κλειδί** του πιστοποιητικού του χρήστη. Το αίτημα υποβάλλεται σε αρκετούς ελέγχους από τον ελεγκτή τομέα, μεταξύ των οποίων η **ισχύς**, η **αλυσίδα πιστοποιητικών** και η **κατάσταση ανάκλησης** του πιστοποιητικού. Οι έλεγχοι περιλαμβάνουν επίσης την επαλήθευση ότι το πιστοποιητικό προέρχεται από αξιόπιστη πηγή και την επιβεβαίωση ότι ο εκδότης υπάρχει στο **NTAUTH certificate store**. Αν οι έλεγχοι ολοκληρωθούν επιτυχώς, εκδίδεται ένα TGT. Το αντικείμενο **`NTAuthCertificates`** στο AD βρίσκεται στη διαδρομή:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

είναι καθοριστικής σημασίας για την εδραίωση εμπιστοσύνης στην πιστοποίηση μέσω πιστοποιητικών.<sup>[[4]](#references)</sup>

Μετά τη διάθεση του **KB5014754**, η σύγχρονη πιστοποίηση Kerberos μέσω πιστοποιητικών αφορά κυρίως την **ισχύ της αντιστοίχισης** και όχι μόνο τα EKU.<sup>[[2]](#references)</sup> Σε ενισχυμένα forests:

- Ένα πιστοποιητικό που περιέχει μόνο **UPN/DNS SAN** ενδέχεται να μην αρκεί πλέον για σύνδεση.
- Το KDC προτιμά μια **ισχυρή σύνδεση**, συνήθως την **επέκταση ασφαλείας SID** (`1.3.6.1.4.1.311.25.2`) ή μια ισχυρή ρητή αντιστοίχιση στο `altSecurityIdentities`.
- Αν το πιστοποιητικό δεν έχει ισχυρή αντιστοίχιση, οι DC καταγράφουν τα **Kdcsvc Event ID 39/41** σε λειτουργία συμβατότητας και αρνούνται την πιστοποίηση σε λειτουργία επιβολής.
- Σε μικτές διαδρομές επίθεσης, τα **ESC9/ESC16** έχουν σημασία επειδή αφαιρούν την επέκταση SID από τα εκδιδόμενα πιστοποιητικά· στη συνέχεια, οι operators βασίζονται σε ρητές αντιστοιχίσεις ή σε μορφές SID URL στο SAN, όπου το επιτρέπει η διαδρομή επίθεσης.

### Πιστοποίηση Secure Channel (Schannel)

Το Schannel διευκολύνει τις ασφαλείς συνδέσεις TLS/SSL. Κατά τη χειραψία, ο client παρουσιάζει ένα πιστοποιητικό το οποίο, αν επικυρωθεί επιτυχώς, εξουσιοδοτεί την πρόσβαση. Η αντιστοίχιση ενός πιστοποιητικού με έναν λογαριασμό AD μπορεί να περιλαμβάνει τη συνάρτηση **S4U2Self** του Kerberos ή το **Subject Alternative Name (SAN)** του πιστοποιητικού, μεταξύ άλλων μεθόδων.<sup>[[4]](#references)</sup>

Το Schannel είναι επίσης η πρακτική εναλλακτική όταν το **PKINIT** δεν είναι διαθέσιμο. Για παράδειγμα, αν ένας domain controller δεν διαθέτει κατάλληλο πιστοποιητικό **Smart Card Logon**, τα εργαλεία `certipy auth`/PKINIT ενδέχεται να μην μπορούν να λάβουν TGT, αλλά το ίδιο πιστοποιητικό μπορεί να χρησιμοποιηθεί για πιστοποίηση και λειτουργίες LDAP μέσω **LDAPS** ή **LDAP StartTLS**.

### Απαρίθμηση υπηρεσιών πιστοποιητικών AD

Οι υπηρεσίες πιστοποιητικών του AD μπορούν να απαριθμηθούν μέσω ερωτημάτων LDAP, αποκαλύπτοντας πληροφορίες για τις **Enterprise Certificate Authorities (CA)** και τις διαμορφώσεις τους. Αυτές οι πληροφορίες είναι προσβάσιμες σε κάθε χρήστη που έχει πιστοποιηθεί στον τομέα, χωρίς ειδικά προνόμια. Εργαλεία όπως τα **[Certify](https://github.com/GhostPack/Certify)** και **[Certipy](https://github.com/ly4k/Certipy)** χρησιμοποιούνται για απαρίθμηση και αξιολόγηση ευπαθειών σε περιβάλλοντα AD CS.

Οι εντολές για τη χρήση αυτών των εργαλείων περιλαμβάνουν:

```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Πρόσφατες ευπάθειες και ενημερώσεις ασφαλείας (2022-2025)

| Έτος | ID / Όνομα | Επίπτωση | Βασικά συμπεράσματα |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Κλιμάκωση προνομίων* μέσω πλαστογράφησης πιστοποιητικών λογαριασμών μηχανημάτων κατά το PKINIT. | Η ενημέρωση περιλαμβάνεται στις ενημερώσεις ασφαλείας της **10ης Μαΐου 2022**. Οι έλεγχοι και οι ρυθμίσεις ισχυρής αντιστοίχισης εισήχθησαν μέσω του **KB5014754**· τα περιβάλλοντα θα πρέπει πλέον να βρίσκονται σε λειτουργία *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Απομακρυσμένη εκτέλεση κώδικα* στους ρόλους AD CS Web Enrollment (certsrv) και CES. | Τα δημόσια PoC είναι περιορισμένα, αλλά τα ευάλωτα στοιχεία IIS είναι συχνά εκτεθειμένα εσωτερικά. Εγκαταστήστε την ενημέρωση ασφαλείας της **Ιουλιανής Patch Tuesday του 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Σε **v1 templates**, ένας αιτών με δικαιώματα εγγραφής μπορεί να ενσωματώσει **Application Policies/EKUs** στο CSR, τα οποία υπερισχύουν των EKU του template, με αποτέλεσμα την έκδοση πιστοποιητικών για client-auth, enrollment agent ή code-signing. | Διορθώθηκε στις **12 Νοεμβρίου 2024**. Αντικαταστήστε ή αναβαθμίστε τα v1 templates (π.χ. το προεπιλεγμένο WebServer), περιορίστε τα EKU στον προβλεπόμενο σκοπό και περιορίστε τα δικαιώματα εγγραφής. |

### Χρονοδιάγραμμα hardening της Microsoft (KB5014754)

Η Microsoft εισήγαγε μια διαδικασία ανάπτυξης τριών φάσεων (Compatibility → Audit → Enforcement), ώστε ο έλεγχος ταυτότητας πιστοποιητικών Kerberos να πάψει να βασίζεται σε αδύναμες έμμεσες αντιστοιχίσεις. Από τις **11 Φεβρουαρίου 2025**, οι domain controllers μεταβαίνουν αυτόματα σε **Full Enforcement**, αν δεν έχει οριστεί η τιμή μητρώου `StrongCertificateBindingEnforcement`. Αργότερα, η Microsoft ενημέρωσε το χρονοδιάγραμμα, ώστε η επιστροφή στη λειτουργία compatibility να παραμείνει δυνατή έως την ενημέρωση ασφαλείας της **9ης Σεπτεμβρίου 2025**.<sup>[[2]](#references)</sup> Οι διαχειριστές θα πρέπει:

1. Να εγκαταστήσουν ενημερώσεις σε όλους τους DC και τους AD CS servers (Μάιος 2022 ή νεότερες).
2. Να παρακολουθούν τα Event ID 39/41 για αδύναμες αντιστοιχίσεις κατά τη φάση *Audit*.
3. Να επανεκδώσουν τα client-auth certificates με τη νέα **SID extension** ή να ρυθμίσουν ισχυρές χειροκίνητες αντιστοιχίσεις πριν η επιβολή αποκλείσει τις αδύναμες αντιστοιχίσεις.

### Σημειώσεις για operators σε hardened forests

- **Τα ESC1/ESC6 από μόνα τους δεν αποτελούν πλέον όλη την εικόνα** σε περιβάλλοντα του 2025 και μετά. Αν ζητήσετε πιστοποιητικό για άλλον principal, συνήθως χρειάζεστε επίσης ένα ισχυρό στοιχείο αντιστοίχισης, όπως τη SID extension ή μια ρητή αντιστοίχιση.
- Το **ESC15 (EKUwu)** είναι κυρίως χρήσιμο σε περιβάλλοντα χωρίς τις απαραίτητες ενημερώσεις, καθώς μετατρέπει ακίνδυνα **v1** templates, όπως το **WebServer**, σε πιστοποιητικά κατάλληλα για authentication ή enrollment agent, εισάγοντας **Application Policies**. Το Kerberos PKINIT εξακολουθεί να ελέγχει τα EKU, αλλά το **LDAP Schannel** λαμβάνει επίσης υπόψη τα Application Policies, οπότε η κατάχρηση μέσω LDAP παραμένει σχετική.<sup>[[1]](#references)</sup>
- Το **ESC16** είναι ρύθμιση σε επίπεδο CA: αν η CA απενεργοποιήσει καθολικά την επέκταση ασφαλείας SID, κάθε πιστοποιητικό που εκδίδεται καταλήγει να βασίζεται σε ασθενέστερη συμπεριφορά αντιστοίχισης, εκτός αν η αλυσίδα επίθεσης εισαγάγει SID με άλλη υποστηριζόμενη μορφή.
- **Τα δικαιώματα ESC7 είναι διακριτά:** μια εκχώρηση `ManageCA` στην CA μπορεί να επιτρέπει αλλαγές σε ρυθμίσεις όπως το `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), ενώ το `ManageCertificates` διέπει την έγκριση αιτημάτων. Μια ρητή άρνηση δικαιωμάτων διαχειριστή πιστοποιητικών μπορεί να αποκλείσει αυτή τη διαδρομή έγκρισης, ακόμη κι αν υπάρχει και Allow· αξιολογήστε το αποτελεσματικό ACL της CA πριν συνδυάσετε ρυθμίσεις και templates. Δείτε την [αξιολόγηση ACL της CA από τη Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Βελτιώσεις εντοπισμού και hardening

* Ο **αισθητήρας AD CS του Defender for Identity (2023-2024)** εμφανίζει πλέον αξιολογήσεις κατάστασης για ESC1-ESC8/ESC11 και δημιουργεί ειδοποιήσεις σε πραγματικό χρόνο, όπως *“Έκδοση πιστοποιητικού domain controller για μη-DC”* (ESC8) και *“Αποτροπή εγγραφής πιστοποιητικών με αυθαίρετα Application Policies”* (ESC15). Εγκαταστήστε αισθητήρες σε όλους τους AD CS servers, ώστε να επωφεληθείτε από αυτές τις δυνατότητες εντοπισμού.<sup>[[3]](#references)</sup>
* Απενεργοποιήστε ή περιορίστε αυστηρά την επιλογή **“Supply in the request”** σε όλα τα templates· προτιμήστε ρητά καθορισμένες τιμές SAN/EKU.
* Αφαιρέστε το **Any Purpose** ή το **No EKU** από τα templates, εκτός αν είναι απολύτως απαραίτητα (αντιμετωπίζει περιπτώσεις ESC2).
* Απαιτήστε **έγκριση διαχειριστή** ή ειδικές ροές εργασίας Enrollment Agent για ευαίσθητα templates (π.χ. WebServer / CodeSigning).
* Περιορίστε τα web enrollment (`certsrv`) και τα CES/NDES endpoints σε έμπιστα δίκτυα ή τοποθετήστε τα πίσω από authentication με client certificate.
* Επιβάλετε κρυπτογράφηση RPC enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) για τον μετριασμό του ESC11 (RPC relay). Η ρύθμιση είναι **ενεργοποιημένη από προεπιλογή**, αλλά συχνά απενεργοποιείται για legacy clients, γεγονός που επαναφέρει τον κίνδυνο relay.
* Ασφαλίστε τα **IIS-based enrollment endpoints** (CES/Certsrv): απενεργοποιήστε το NTLM όπου είναι δυνατόν ή απαιτήστε HTTPS + Extended Protection, ώστε να αποκλείσετε τα ESC8 relay.

Αξιολογήστε το ESC11 στον host που εκτελεί την CA, ο οποίος μπορεί να είναι domain member server και όχι domain controller. Διαβάστε το `InterfaceFlags` της ενεργής CA από το `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`· μια τιμή που δεν μπορεί να αναγνωστεί ή απουσιάζει αποτελεί άγνωστο αποτέλεσμα, όχι απόδειξη ότι η κρυπτογράφηση RPC είναι απενεργοποιημένη. Αν το bit `IF_ENFORCEENCRYPTICERTREQUEST` είναι μηδενικό, αυτό αποτελεί ένδειξη προς διερεύνηση, αλλά εξακολουθούν να απαιτούνται προσβάσιμο endpoint enrollment RPC, διαπιστευτήρια που μπορούν να εξαναγκαστούν και κατάλληλο certificate template. Για το ESC8, μια πρόκληση HTTP NTLM από μόνη της δεν αρκεί: επιβεβαιώστε ότι υπάρχει λειτουργικό endpoint enrollment.

---

## References

- [1] [EKUwu: Όχι άλλο ένα AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Αλλαγές στον έλεγχο ταυτότητας βάσει πιστοποιητικών σε Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Αξιολογήσεις κατάστασης ασφαλείας πιστοποιητικών - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Κατάχρηση του Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
