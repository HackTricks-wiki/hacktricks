# Πιστοποιητικά AD

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή

### Στοιχεία ενός πιστοποιητικού

- Το **Subject** του πιστοποιητικού δηλώνει τον κάτοχό του.
- Ένα **Public Key** συνδυάζεται με ένα ιδιωτικά κατεχόμενο κλειδί, ώστε να συνδέει το πιστοποιητικό με τον νόμιμο κάτοχό του.
- Η **Validity Period**, η οποία ορίζεται από τις ημερομηνίες **NotBefore** και **NotAfter**, προσδιορίζει τη διάρκεια ισχύος του πιστοποιητικού.
- Ένας μοναδικός **Serial Number**, ο οποίος παρέχεται από την Αρχή Πιστοποίησης (CA), προσδιορίζει κάθε πιστοποιητικό.
- Το **Issuer** αναφέρεται στην CA που εξέδωσε το πιστοποιητικό.
- Το **SubjectAlternativeName** επιτρέπει τον καθορισμό πρόσθετων ονομάτων για το subject, προσφέροντας μεγαλύτερη ευελιξία στην ταυτοποίηση.
- Το **Basic Constraints** προσδιορίζει αν το πιστοποιητικό προορίζεται για CA ή για τελική οντότητα και ορίζει περιορισμούς χρήσης.
- Τα **Extended Key Usages (EKUs)** καθορίζουν τους ειδικούς σκοπούς του πιστοποιητικού, όπως την υπογραφή κώδικα ή την κρυπτογράφηση email, μέσω Object Identifiers (OIDs).
- Το **Signature Algorithm** καθορίζει τη μέθοδο υπογραφής του πιστοποιητικού.
- Το **Signature**, το οποίο δημιουργείται με το ιδιωτικό κλειδί του εκδότη, εγγυάται τη γνησιότητα του πιστοποιητικού.<sup>[[4]](#references)</sup>

### Ειδικές επισημάνσεις

- Τα **Subject Alternative Names (SANs)** διευρύνουν τη δυνατότητα εφαρμογής ενός πιστοποιητικού σε πολλαπλές ταυτότητες, κάτι κρίσιμο για διακομιστές με πολλούς τομείς. Οι ασφαλείς διαδικασίες έκδοσης είναι απαραίτητες για την αποτροπή κινδύνων πλαστοπροσωπίας από attackers που χειρίζονται τις προδιαγραφές SAN.<sup>[[4]](#references)</sup>

### Αρχές Πιστοποίησης (CAs) στο Active Directory (AD)

Το AD CS αναγνωρίζει τα πιστοποιητικά CA σε ένα AD forest μέσω καθορισμένων containers, καθένα από τα οποία εξυπηρετεί έναν μοναδικό ρόλο:<sup>[[4]](#references)</sup>

- Το container **Certification Authorities** περιέχει αξιόπιστα πιστοποιητικά root CA.
- Το container **Enrolment Services** περιλαμβάνει πληροφορίες για τις Enterprise CAs και τα certificate templates τους.
- Το αντικείμενο **NTAuthCertificates** περιλαμβάνει πιστοποιητικά CA εξουσιοδοτημένα για authentication στο AD.
- Το container **AIA (Authority Information Access)** διευκολύνει την επικύρωση της αλυσίδας πιστοποιητικών με intermediate και cross CA certificates.

### Απόκτηση πιστοποιητικού: Ροή αιτήματος πιστοποιητικού client

1. Η διαδικασία αιτήματος ξεκινά όταν οι clients εντοπίζουν μια Enterprise CA.
2. Δημιουργείται ένα CSR, το οποίο περιέχει ένα public key και άλλα στοιχεία, αφού δημιουργηθεί ένα ζεύγος public-private key.
3. Η CA αξιολογεί το CSR με βάση τα διαθέσιμα certificate templates και εκδίδει το πιστοποιητικό σύμφωνα με τα δικαιώματα του template.
4. Μετά την έγκριση, η CA υπογράφει το πιστοποιητικό με το ιδιωτικό της κλειδί και το επιστρέφει στον client.<sup>[[4]](#references)</sup>

### Certificate templates

Αυτά τα templates, τα οποία ορίζονται στο AD, καθορίζουν τις ρυθμίσεις και τα δικαιώματα για την έκδοση πιστοποιητικών, συμπεριλαμβανομένων των επιτρεπόμενων EKUs και των δικαιωμάτων εγγραφής ή τροποποίησης, τα οποία είναι κρίσιμα για τη διαχείριση της πρόσβασης στις υπηρεσίες πιστοποιητικών.<sup>[[4]](#references)</sup>

**Η έκδοση του schema του template έχει σημασία.** Τα παλαιότερα templates **v1** (για παράδειγμα, το ενσωματωμένο template **WebServer**) δεν διαθέτουν αρκετούς σύγχρονους μηχανισμούς επιβολής πολιτικών. Η έρευνα **ESC15/EKUwu** έδειξε ότι σε templates **v1**, ο αιτών μπορεί να ενσωματώσει **Application Policies/EKUs** στο CSR, τα οποία **υπερισχύουν των** EKUs που έχουν ρυθμιστεί στο template, επιτρέποντας την έκδοση πιστοποιητικών client-auth, enrollment agent ή code-signing μόνο με δικαιώματα εγγραφής. Προτιμήστε templates **v2/v3**, αφαιρέστε ή αντικαταστήστε τις προεπιλογές v1 και περιορίστε αυστηρά τα EKUs στον προβλεπόμενο σκοπό τους.<sup>[[1]](#references)</sup>

## Εγγραφή πιστοποιητικών

Η διαδικασία εγγραφής πιστοποιητικών ξεκινά από έναν administrator που **δημιουργεί ένα certificate template**, το οποίο στη συνέχεια **δημοσιεύεται** από μια Enterprise Certificate Authority (CA). Έτσι το template γίνεται διαθέσιμο για εγγραφή από clients, διαδικασία που πραγματοποιείται προσθέτοντας το όνομα του template στο πεδίο `certificatetemplates` ενός αντικειμένου Active Directory.<sup>[[4]](#references)</sup>

Για να μπορεί ένας client να ζητήσει πιστοποιητικό, πρέπει να του παραχωρηθούν **δικαιώματα εγγραφής**. Αυτά τα δικαιώματα ορίζονται μέσω security descriptors στο certificate template και στην ίδια την Enterprise CA. Για να είναι επιτυχές το αίτημα, πρέπει να παραχωρηθούν δικαιώματα και στις δύο τοποθεσίες.

### Δικαιώματα εγγραφής template

Αυτά τα δικαιώματα καθορίζονται μέσω Access Control Entries (ACEs), οι οποίες ορίζουν δικαιώματα όπως:

- Δικαιώματα **Certificate-Enrollment** και **Certificate-AutoEnrollment**, καθένα από τα οποία συνδέεται με συγκεκριμένα GUIDs.
- **ExtendedRights**, που επιτρέπουν όλα τα εκτεταμένα δικαιώματα.
- **FullControl/GenericAll**, που παρέχουν πλήρη έλεγχο του template.

### Δικαιώματα εγγραφής Enterprise CA

Τα δικαιώματα της CA περιγράφονται στο security descriptor της, στο οποίο υπάρχει πρόσβαση μέσω της κονσόλας διαχείρισης Certificate Authority. Ορισμένες ρυθμίσεις επιτρέπουν ακόμη και σε χρήστες με χαμηλά προνόμια απομακρυσμένη πρόσβαση, κάτι που ενδέχεται να αποτελεί κίνδυνο για την ασφάλεια.

### Πρόσθετοι έλεγχοι έκδοσης

Ενδέχεται να εφαρμόζονται ορισμένοι έλεγχοι, όπως:

- **Έγκριση διαχειριστή**: Διατηρεί τα αιτήματα σε εκκρεμότητα μέχρι να εγκριθούν από certificate manager.
- **Enrolment Agents και Authorized Signatures**: Καθορίζουν τον αριθμό των απαιτούμενων υπογραφών σε ένα CSR και τα απαραίτητα Application Policy OIDs.

### Μέθοδοι αιτήματος πιστοποιητικών

Τα πιστοποιητικά μπορούν να ζητηθούν μέσω:

1. Του **Windows Client Certificate Enrollment Protocol** (MS-WCCE), με χρήση διεπαφών DCOM.
2. Του **ICertPassage Remote Protocol** (MS-ICPR), μέσω named pipes ή TCP/IP.
3. Της **web interface εγγραφής πιστοποιητικών**, με εγκατεστημένο τον ρόλο Certificate Authority Web Enrollment.
4. Της **Certificate Enrollment Service** (CES), σε συνδυασμό με την υπηρεσία Certificate Enrollment Policy (CEP).
5. Της **Network Device Enrollment Service** (NDES) για συσκευές δικτύου, με χρήση του Simple Certificate Enrollment Protocol (SCEP).

Οι χρήστες Windows μπορούν επίσης να ζητήσουν πιστοποιητικά μέσω του GUI (`certmgr.msc` ή `certlm.msc`) ή εργαλείων γραμμής εντολών (`certreq.exe` ή της εντολής PowerShell `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Πιστοποίηση με πιστοποιητικό

Το Active Directory (AD) υποστηρίζει πιστοποίηση με πιστοποιητικό, κυρίως μέσω των πρωτοκόλλων **Kerberos** και **Secure Channel (Schannel)**.

### Διαδικασία πιστοποίησης Kerberos

Στη διαδικασία πιστοποίησης Kerberos, το αίτημα ενός χρήστη για Ticket Granting Ticket (TGT) υπογράφεται με το **ιδιωτικό κλειδί** του πιστοποιητικού του. Το αίτημα υποβάλλεται σε διάφορους ελέγχους από τον ελεγκτή τομέα, μεταξύ άλλων για την **εγκυρότητα**, την **αλυσίδα πιστοποιητικών** και την **κατάσταση ανάκλησης** του πιστοποιητικού. Οι έλεγχοι περιλαμβάνουν επίσης την επαλήθευση ότι το πιστοποιητικό προέρχεται από αξιόπιστη πηγή και την επιβεβαίωση ότι ο εκδότης υπάρχει στο **χώρο αποθήκευσης πιστοποιητικών NTAUTH**. Αν οι έλεγχοι ολοκληρωθούν με επιτυχία, εκδίδεται ένα TGT. Το αντικείμενο **`NTAuthCertificates`** στο AD βρίσκεται στη διεύθυνση:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

είναι κεντρικής σημασίας για την εδραίωση εμπιστοσύνης στην πιστοποίηση μέσω certificate.<sup>[[4]](#references)</sup>

Μετά τη διάθεση του **KB5014754**, η σύγχρονη πιστοποίηση Kerberos μέσω certificate αφορά κυρίως την **ισχύ της αντιστοίχισης** και όχι μόνο τα EKU.<sup>[[2]](#references)</sup> Σε hardened forests:

- Ένα certificate που περιέχει μόνο **UPN/DNS SAN** μπορεί να μην αρκεί πλέον για σύνδεση.
- Το KDC προτιμά μια **ισχυρή σύνδεση**, συνήθως μέσω της **επέκτασης ασφαλείας SID** (`1.3.6.1.4.1.311.25.2`) ή μιας ισχυρής ρητής αντιστοίχισης στο `altSecurityIdentities`.
- Αν το certificate δεν διαθέτει ισχυρή αντιστοίχιση, οι DC καταγράφουν το **Kdcsvc Event ID 39/41** σε λειτουργία συμβατότητας και αρνούνται την πιστοποίηση σε λειτουργία επιβολής.
- Σε μικτές διαδρομές επίθεσης, τα **ESC9/ESC16** έχουν σημασία επειδή αφαιρούν την επέκταση SID από τα certificates που εκδίδονται. Στη συνέχεια, οι operators βασίζονται σε ρητές αντιστοιχίσεις ή σε μορφές SID URL στο SAN, εφόσον τις υποστηρίζει η διαδρομή επίθεσης.

### Πιστοποίηση Secure Channel (Schannel)

Το Schannel διευκολύνει ασφαλείς συνδέσεις TLS/SSL. Κατά τη χειραψία, ο client παρουσιάζει ένα certificate το οποίο, αν επικυρωθεί με επιτυχία, εξουσιοδοτεί την πρόσβαση. Η αντιστοίχιση ενός certificate σε έναν λογαριασμό AD μπορεί να χρησιμοποιεί τη λειτουργία **S4U2Self** του Kerberos ή το **Subject Alternative Name (SAN)** του certificate, μεταξύ άλλων μεθόδων.<sup>[[4]](#references)</sup>

Το Schannel αποτελεί επίσης την πρακτική εναλλακτική όταν το **PKINIT** δεν είναι διαθέσιμο. Για παράδειγμα, αν ένας domain controller δεν διαθέτει κατάλληλο certificate **Smart Card Logon**, τα εργαλεία `certipy auth`/PKINIT μπορεί να αποτύχουν να λάβουν TGT, αλλά το ίδιο certificate μπορεί να χρησιμοποιηθεί για πιστοποίηση και λειτουργίες LDAP μέσω **LDAPS** ή **LDAP StartTLS**.

### Απαρίθμηση των AD Certificate Services

Οι υπηρεσίες certificates του AD μπορούν να απαριθμηθούν μέσω ερωτημάτων LDAP, αποκαλύπτοντας πληροφορίες για τις **Enterprise Certificate Authorities (CAs)** και τις ρυθμίσεις τους. Αυτές οι πληροφορίες είναι προσβάσιμες από οποιονδήποτε χρήστη έχει πιστοποιηθεί στον domain, χωρίς ειδικά προνόμια. Εργαλεία όπως τα **[Certify](https://github.com/GhostPack/Certify)** και **[Certipy](https://github.com/ly4k/Certipy)** χρησιμοποιούνται για απαρίθμηση και αξιολόγηση ευπαθειών σε περιβάλλοντα AD CS.

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

| Έτος | ID / Όνομα | Επιπτώσεις | Βασικά συμπεράσματα |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Κλιμάκωση προνομίων* μέσω πλαστογράφησης πιστοποιητικών λογαριασμών μηχανημάτων κατά το PKINIT. | Το patch περιλαμβάνεται στις ενημερώσεις ασφαλείας της **10ης Μαΐου 2022**. Οι έλεγχοι και οι μηχανισμοί ισχυρής αντιστοίχισης εισήχθησαν μέσω του **KB5014754**· τα περιβάλλοντα θα πρέπει πλέον να βρίσκονται σε λειτουργία *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Απομακρυσμένη εκτέλεση κώδικα* στους ρόλους AD CS Web Enrollment (certsrv) και CES. | Τα δημόσια PoC είναι περιορισμένα, αλλά τα ευάλωτα στοιχεία IIS είναι συχνά εκτεθειμένα εσωτερικά. Εγκαταστήστε το patch που κυκλοφόρησε στο Patch Tuesday του **Ιουλίου 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Σε **v1 templates**, ένας αιτών με δικαιώματα enrollment μπορεί να ενσωματώσει **Application Policies/EKUs** στο CSR, τα οποία υπερισχύουν των EKUs του template και οδηγούν στην έκδοση πιστοποιητικών για client-auth, enrollment agent ή code-signing. | Έχει διορθωθεί από τις **12 Νοεμβρίου 2024**. Αντικαταστήστε ή καταργήστε τα v1 templates (π.χ. το προεπιλεγμένο WebServer), περιορίστε τα EKUs ανάλογα με τον σκοπό και περιορίστε τα δικαιώματα enrollment. |

### Χρονοδιάγραμμα ενίσχυσης ασφάλειας της Microsoft (KB5014754)

Η Microsoft εισήγαγε μια ανάπτυξη τριών φάσεων (Compatibility → Audit → Enforcement), ώστε ο Kerberos certificate authentication να απομακρυνθεί από τις αδύναμες έμμεσες αντιστοιχίσεις. Από τις **11 Φεβρουαρίου 2025**, οι domain controllers μεταβαίνουν αυτόματα σε **Full Enforcement**, αν δεν έχει οριστεί η τιμή μητρώου `StrongCertificateBindingEnforcement`. Αργότερα, η Microsoft ενημέρωσε το χρονοδιάγραμμα, ώστε να παραμείνει δυνατή η επιστροφή σε compatibility mode έως την ενημέρωση ασφαλείας της **9ης Σεπτεμβρίου 2025**.<sup>[[2]](#references)</sup> Οι διαχειριστές θα πρέπει:

1. Να εγκαταστήσουν τα patches σε όλους τους DC και τους AD CS servers (Μάιος 2022 ή νεότερα).
2. Να παρακολουθούν τα Event ID 39/41 για αδύναμες αντιστοιχίσεις κατά τη φάση *Audit*.
3. Να επανεκδώσουν τα client-auth certificates με τη νέα **SID extension** ή να διαμορφώσουν ισχυρές χειροκίνητες αντιστοιχίσεις, προτού η enforcement αποκλείσει τις αδύναμες αντιστοιχίσεις.

### Σημειώσεις για operators σε ενισχυμένα forests

- **Τα ESC1/ESC6 από μόνα τους δεν είναι πλέον όλη η ιστορία** σε περιβάλλοντα του 2025 και μετά. Αν ζητήσετε πιστοποιητικό για άλλο principal, συνήθως χρειάζεστε επίσης ένα ισχυρό τεκμήριο αντιστοίχισης, όπως τη SID extension ή μια ρητή αντιστοίχιση.
- Το **ESC15 (EKUwu)** είναι κυρίως χρήσιμο σε περιβάλλοντα χωρίς patch, καθώς μετατρέπει αβλαβή **v1** templates, όπως το **WebServer**, σε templates που μπορούν να εκδώσουν πιστοποιητικά για authentication ή enrollment agent, εισάγοντας **Application Policies**. Το Kerberos PKINIT εξακολουθεί να ελέγχει τα EKUs, αλλά το **LDAP Schannel** λαμβάνει επίσης υπόψη τα Application Policies, διατηρώντας σχετική την κατάχρηση μέσω LDAP.<sup>[[1]](#references)</sup>
- Το **ESC16** είναι ρύθμιση σε επίπεδο CA: αν η CA απενεργοποιήσει συνολικά τη SID security extension, κάθε πιστοποιητικό που εκδίδεται επιστρέφει σε ασθενέστερη συμπεριφορά αντιστοίχισης, εκτός αν η αλυσίδα επίθεσης εισάγει SID με άλλη υποστηριζόμενη μορφή.
- **Τα δικαιώματα ESC7 είναι διακριτά:** μια εκχώρηση `ManageCA` στην CA μπορεί να επιτρέψει αλλαγές σε ρυθμίσεις όπως το `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), ενώ το `ManageCertificates` ελέγχει την έγκριση αιτημάτων. Μια ρητή Deny για δικαιώματα certificate-manager μπορεί να αποκλείσει αυτή τη διαδρομή έγκρισης, ακόμη κι αν υπάρχει και Allow· αξιολογήστε το αποτελεσματικό ACL της CA πριν συνδυάσετε ρυθμίσεις και templates. Δείτε την [αξιολόγηση ACL CA της Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Βελτιώσεις εντοπισμού και ενίσχυσης ασφάλειας

* Ο αισθητήρας **Defender for Identity AD CS (2023-2024)** εμφανίζει πλέον αξιολογήσεις κατάστασης για ESC1-ESC8/ESC11 και δημιουργεί ειδοποιήσεις σε πραγματικό χρόνο, όπως *“Έκδοση πιστοποιητικού domain controller για μη-DC”* (ESC8) και *“Αποτροπή enrollment πιστοποιητικών με αυθαίρετα Application Policies”* (ESC15). Βεβαιωθείτε ότι οι αισθητήρες έχουν εγκατασταθεί σε όλους τους AD CS servers για να αξιοποιήσετε αυτούς τους εντοπισμούς.<sup>[[3]](#references)</sup>
* Απενεργοποιήστε ή περιορίστε αυστηρά την επιλογή **“Supply in the request”** σε όλα τα templates· προτιμήστε ρητά καθορισμένες τιμές SAN/EKU.
* Αφαιρέστε τα **Any Purpose** ή **No EKU** από τα templates, εκτός αν είναι απολύτως απαραίτητα (αντιμετωπίζει σενάρια ESC2).
* Απαιτήστε **έγκριση manager** ή ειδικές ροές εργασίας Enrollment Agent για ευαίσθητα templates (π.χ. WebServer / CodeSigning).
* Περιορίστε τα web enrollment endpoints (`certsrv`) και τα endpoints CES/NDES σε έμπιστα δίκτυα ή πίσω από authentication με client certificate.
* Επιβάλετε κρυπτογράφηση RPC enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) για τον μετριασμό του ESC11 (RPC relay). Η σημαία είναι **ενεργοποιημένη από προεπιλογή**, αλλά συχνά απενεργοποιείται για legacy clients, επαναφέροντας τον κίνδυνο relay.
* Ασφαλίστε τα **IIS-based enrollment endpoints** (CES/Certsrv): απενεργοποιήστε το NTLM όπου είναι δυνατό ή απαιτήστε HTTPS + Extended Protection για να αποκλείσετε τα ESC8 relays.

Αξιολογήστε το ESC11 στον host που εκτελεί την CA, ο οποίος μπορεί να είναι domain member server και όχι domain controller. Διαβάστε το `InterfaceFlags` της ενεργής CA, στη διαδρομή `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`· μια μη αναγνώσιμη ή απούσα τιμή αποτελεί άγνωστο αποτέλεσμα, όχι απόδειξη ότι η κρυπτογράφηση RPC είναι απενεργοποιημένη. Ένα καθαρό bit `IF_ENFORCEENCRYPTICERTREQUEST` αποτελεί ένδειξη ρύθμισης που χρειάζεται περαιτέρω διερεύνηση και εξακολουθεί να απαιτεί προσβάσιμο enrollment RPC endpoint, διαπιστευτήρια που μπορούν να εξαναγκαστούν και κατάλληλο certificate template. Για το ESC8, μια πρόκληση HTTP NTLM από μόνη της δεν αρκεί: επιβεβαιώστε ότι υπάρχει λειτουργικό enrollment endpoint.

---

## References

- [1] [EKUwu: Όχι απλώς άλλο ένα AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Αλλαγές στο authentication μέσω πιστοποιητικών σε Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Αξιολογήσεις κατάστασης ασφάλειας πιστοποιητικών - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Κατάχρηση των Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
