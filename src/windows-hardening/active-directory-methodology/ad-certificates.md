# Πιστοποιητικά AD

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή

### Στοιχεία ενός Πιστοποιητικού

- Το **Subject** του πιστοποιητικού υποδηλώνει τον κάτοχό του.
- Ένα **Public Key** συνδυάζεται με ένα ιδιωτικά διατηρούμενο κλειδί, ώστε να συνδέεται το πιστοποιητικό με τον νόμιμο κάτοχό του.
- Η **Validity Period**, η οποία ορίζεται από τις ημερομηνίες **NotBefore** και **NotAfter**, καθορίζει τη διάρκεια ισχύος του πιστοποιητικού.
- Ένας μοναδικός **Serial Number**, που παρέχεται από το Certificate Authority (CA), αναγνωρίζει κάθε πιστοποιητικό.
- Το **Issuer** αναφέρεται στο CA που εξέδωσε το πιστοποιητικό.
- Το **SubjectAlternativeName** επιτρέπει πρόσθετα ονόματα για το subject, ενισχύοντας την ευελιξία της ταυτοποίησης.
- Τα **Basic Constraints** προσδιορίζουν αν το πιστοποιητικό αφορά CA ή τελική οντότητα και καθορίζουν περιορισμούς χρήσης.
- Τα **Extended Key Usages (EKUs)** καθορίζουν τους συγκεκριμένους σκοπούς του πιστοποιητικού, όπως υπογραφή κώδικα ή κρυπτογράφηση email, μέσω Object Identifiers (OIDs).
- Ο **Signature Algorithm** καθορίζει τη μέθοδο υπογραφής του πιστοποιητικού.
- Η **Signature**, η οποία δημιουργείται με το ιδιωτικό κλειδί του issuer, εγγυάται την αυθεντικότητα του πιστοποιητικού.<sup>[[4]](#references)</sup>

### Ειδικές 고려σεις

- Τα **Subject Alternative Names (SANs)** επεκτείνουν τη δυνατότητα εφαρμογής ενός πιστοποιητικού σε πολλαπλές ταυτότητες, κάτι κρίσιμο για servers με πολλαπλά domains. Οι ασφαλείς διαδικασίες έκδοσης είναι απαραίτητες για την αποφυγή κινδύνων impersonation από attackers που χειραγωγούν την προδιαγραφή SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) στο Active Directory (AD)

Το AD CS αναγνωρίζει τα CA certificates σε ένα AD forest μέσω καθορισμένων containers, καθένα από τα οποία επιτελεί μοναδικό ρόλο:<sup>[[4]](#references)</sup>

- Το container **Certification Authorities** περιέχει trusted root CA certificates.
- Το container **Enrolment Services** περιγράφει τα Enterprise CAs και τα certificate templates τους.
- Το object **NTAuthCertificates** περιλαμβάνει CA certificates που είναι εξουσιοδοτημένα για authentication στο AD.
- Το container **AIA (Authority Information Access)** διευκολύνει την επικύρωση της αλυσίδας πιστοποιητικών με intermediate και cross CA certificates.

### Απόκτηση Πιστοποιητικού: Ροή Αιτήματος Client Certificate

1. Η διαδικασία αιτήματος ξεκινά όταν οι clients εντοπίζουν ένα Enterprise CA.
2. Δημιουργείται ένα CSR, το οποίο περιέχει ένα public key και άλλα στοιχεία, μετά τη δημιουργία ζεύγους public-private key.
3. Το CA αξιολογεί το CSR σε σχέση με τα διαθέσιμα certificate templates και εκδίδει το πιστοποιητικό βάσει των permissions του template.
4. Μετά την έγκριση, το CA υπογράφει το πιστοποιητικό με το ιδιωτικό του κλειδί και το επιστρέφει στον client.<sup>[[4]](#references)</sup>

### Certificate Templates

Τα templates αυτά, τα οποία ορίζονται μέσα στο AD, περιγράφουν τις ρυθμίσεις και τα permissions για την έκδοση πιστοποιητικών, συμπεριλαμβανομένων των επιτρεπόμενων EKUs και των δικαιωμάτων enrollment ή τροποποίησης, και είναι κρίσιμα για τη διαχείριση της πρόσβασης στις certificate services.<sup>[[4]](#references)</sup>

**Η έκδοση του template στο schema έχει σημασία.** Τα παλαιότερα templates **v1** (για παράδειγμα, το ενσωματωμένο template **WebServer**) δεν διαθέτουν αρκετούς σύγχρονους μηχανισμούς enforcement. Η έρευνα **ESC15/EKUwu** έδειξε ότι σε **v1 templates**, ο requester μπορεί να ενσωματώσει **Application Policies/EKUs** στο CSR, τα οποία έχουν **προτεραιότητα έναντι των** EKUs που έχουν ρυθμιστεί στο template, επιτρέποντας client-auth, enrollment agent ή code-signing certificates μόνο με enrollment rights. Προτιμήστε **v2/v3 templates**, αφαιρέστε ή αντικαταστήστε τα προεπιλεγμένα v1 templates και περιορίστε αυστηρά τα EKUs στον προβλεπόμενο σκοπό.<sup>[[1]](#references)</sup>

## Certificate Enrollment

Η διαδικασία enrollment για certificates ξεκινά από έναν administrator, ο οποίος **δημιουργεί ένα certificate template**. Στη συνέχεια, το template **δημοσιεύεται** από ένα Enterprise Certificate Authority (CA). Έτσι το template γίνεται διαθέσιμο για enrollment από clients, μέσω της προσθήκης του ονόματος του template στο πεδίο `certificatetemplates` ενός object του Active Directory.<sup>[[4]](#references)</sup>

Για να ζητήσει ένας client certificate, πρέπει να έχουν εκχωρηθεί **enrollment rights**. Αυτά τα δικαιώματα ορίζονται μέσω security descriptors στο certificate template και στο ίδιο το Enterprise CA. Για να είναι επιτυχές ένα αίτημα, πρέπει να έχουν εκχωρηθεί permissions και στις δύο τοποθεσίες.

### Template Enrollment Rights

Αυτά τα δικαιώματα καθορίζονται μέσω Access Control Entries (ACEs), οι οποίες περιγράφουν permissions όπως:

- Τα δικαιώματα **Certificate-Enrollment** και **Certificate-AutoEnrollment**, καθένα από τα οποία συνδέεται με συγκεκριμένα GUIDs.
- Τα **ExtendedRights**, τα οποία επιτρέπουν όλα τα extended permissions.
- Τα **FullControl/GenericAll**, τα οποία παρέχουν πλήρη έλεγχο στο template.

### Enterprise CA Enrollment Rights

Τα δικαιώματα του CA περιγράφονται στο security descriptor του, το οποίο είναι προσβάσιμο μέσω της κονσόλας διαχείρισης Certificate Authority. Ορισμένες ρυθμίσεις επιτρέπουν ακόμη και σε low-privileged users απομακρυσμένη πρόσβαση, γεγονός που μπορεί να αποτελέσει security concern.

### Additional Issuance Controls

Ενδέχεται να εφαρμόζονται ορισμένοι έλεγχοι, όπως:

- **Manager Approval**: Θέτει τα αιτήματα σε κατάσταση pending μέχρι να εγκριθούν από certificate manager.
- **Enrolment Agents and Authorized Signatures**: Καθορίζουν τον αριθμό των απαιτούμενων υπογραφών σε ένα CSR και τα απαραίτητα Application Policy OIDs.

### Μέθοδοι Αιτήματος Πιστοποιητικών

Τα certificates μπορούν να ζητηθούν μέσω:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), με χρήση DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), μέσω named pipes ή TCP/IP.
3. Του **certificate enrollment web interface**, με εγκατεστημένο τον ρόλο Certificate Authority Web Enrollment.
4. Του **Certificate Enrollment Service** (CES), σε συνδυασμό με το service Certificate Enrollment Policy (CEP).
5. Του **Network Device Enrollment Service** (NDES) για network devices, με χρήση του Simple Certificate Enrollment Protocol (SCEP).

Οι Windows users μπορούν επίσης να ζητήσουν certificates μέσω του GUI (`certmgr.msc` ή `certlm.msc`) ή μέσω command-line tools (`certreq.exe` ή της εντολής `Get-Certificate` του PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Έλεγχος ταυτότητας με πιστοποιητικό

Το Active Directory (AD) υποστηρίζει έλεγχο ταυτότητας με πιστοποιητικό, χρησιμοποιώντας κυρίως τα πρωτόκολλα **Kerberos** και **Secure Channel (Schannel)**.

### Διαδικασία ελέγχου ταυτότητας Kerberos

Στη διαδικασία ελέγχου ταυτότητας Kerberos, το αίτημα ενός χρήστη για ένα Ticket Granting Ticket (TGT) υπογράφεται με χρήση του **ιδιωτικού κλειδιού** του πιστοποιητικού του χρήστη. Αυτό το αίτημα υποβάλλεται σε διάφορες επικυρώσεις από τον domain controller, συμπεριλαμβανομένων της **ισχύος**, της **αλυσίδας** και της **κατάστασης ανάκλησης** του πιστοποιητικού. Οι επικυρώσεις περιλαμβάνουν επίσης την επαλήθευση ότι το πιστοποιητικό προέρχεται από αξιόπιστη πηγή και την επιβεβαίωση της παρουσίας του εκδότη στο **NTAUTH certificate store**. Οι επιτυχείς επικυρώσεις οδηγούν στην έκδοση ενός TGT. Το αντικείμενο **`NTAuthCertificates`** στο AD, βρίσκεται στη διεύθυνση:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
είναι κεντρικής σημασίας για την建立 εμπιστοσύνης κατά την certificate authentication.<sup>[[4]](#references)</sup>

Από την ανάπτυξη του **KB5014754**, η σύγχρονη Kerberos certificate auth αφορά κυρίως το **mapping strength**, όχι μόνο τα EKUs.<sup>[[2]](#references)</sup> Σε hardened forests:

- Ένα certificate που περιέχει μόνο **UPN/DNS SAN** μπορεί να μην επαρκεί πλέον για logon.
- Το KDC προτιμά ένα **strong binding**, συνήθως το **SID security extension** (`1.3.6.1.4.1.311.25.2`) ή ένα strong explicit mapping στο `altSecurityIdentities`.
- Αν το cert δεν διαθέτει strong mapping, οι DCs καταγράφουν τα **Kdcsvc Event ID 39/41** σε compatibility mode και απορρίπτουν το auth σε enforcement mode.
- Σε mixed attack paths, τα **ESC9/ESC16** έχουν σημασία επειδή αφαιρούν το SID extension από τα issued certs· οι operators βασίζονται στη συνέχεια σε explicit mappings ή σε SAN URL SID formats, όπου το υποστηρίζει το attack path.

### Secure Channel (Schannel) Authentication

Το Schannel διευκολύνει ασφαλείς συνδέσεις TLS/SSL, όπου κατά τη διάρκεια ενός handshake ο client παρουσιάζει ένα certificate το οποίο, αν επικυρωθεί επιτυχώς, εξουσιοδοτεί την πρόσβαση. Το mapping ενός certificate σε έναν AD account μπορεί να περιλαμβάνει τη συνάρτηση **S4U2Self** του Kerberos ή το **Subject Alternative Name (SAN)** του certificate, μεταξύ άλλων μεθόδων.<sup>[[4]](#references)</sup>

Το Schannel αποτελεί επίσης το πρακτικό fallback όταν το **PKINIT** δεν είναι διαθέσιμο. Για παράδειγμα, αν ένας domain controller δεν διαθέτει κατάλληλο certificate **Smart Card Logon**, τα `certipy auth`/PKINIT tooling μπορεί να αποτύχουν να αποκτήσουν TGT, όμως το ίδιο certificate μπορεί να εξακολουθεί να χρησιμοποιείται μέσω **LDAPS** ή **LDAP StartTLS** για authentication και LDAP operations.

### AD Certificate Services Enumeration

Οι certificate services του AD μπορούν να απαριθμηθούν μέσω LDAP queries, αποκαλύπτοντας πληροφορίες σχετικά με τις **Enterprise Certificate Authorities (CAs)** και τις διαμορφώσεις τους. Αυτό είναι προσβάσιμο από οποιονδήποτε domain-authenticated user χωρίς special privileges. Εργαλεία όπως τα **[Certify](https://github.com/GhostPack/Certify)** και **[Certipy](https://github.com/ly4k/Certipy)** χρησιμοποιούνται για enumeration και vulnerability assessment σε περιβάλλοντα AD CS.

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
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* μέσω spoofing πιστοποιητικών λογαριασμών υπολογιστών κατά το PKINIT. | Το patch περιλαμβάνεται στις ενημερώσεις ασφαλείας της **10ης Μαΐου 2022**. Οι έλεγχοι auditing και strong-mapping εισήχθησαν μέσω του **KB5014754**· τα περιβάλλοντα θα πρέπει πλέον να βρίσκονται σε λειτουργία *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* στα roles AD CS Web Enrollment (certsrv) και CES. | Τα public PoCs είναι περιορισμένα, όμως τα ευάλωτα components του IIS είναι συχνά εκτεθειμένα εσωτερικά. Εφαρμόστε το patch που κυκλοφόρησε στο Patch Tuesday του **Ιουλίου 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Σε **v1 templates**, ένας requester με δικαιώματα enrollment μπορεί να ενσωματώσει **Application Policies/EKUs** στο CSR, τα οποία έχουν προτεραιότητα έναντι των EKUs του template, παράγοντας client-auth, enrollment agent ή code-signing certificates. | Έχει γίνει patch από τις **12 Νοεμβρίου 2024**. Αντικαταστήστε ή κάντε supersede τα v1 templates (π.χ. το προεπιλεγμένο WebServer), περιορίστε τα EKUs σύμφωνα με τον σκοπό τους και περιορίστε τα δικαιώματα enrollment.  |

### Χρονοδιάγραμμα hardening της Microsoft (KB5014754)

Η Microsoft εισήγαγε ένα rollout τριών φάσεων (Compatibility → Audit → Enforcement) για να απομακρύνει το Kerberos certificate authentication από τα weak implicit mappings. Από τις **11 Φεβρουαρίου 2025**, οι domain controllers μεταβαίνουν αυτόματα σε **Full Enforcement** αν δεν έχει οριστεί η registry value `StrongCertificateBindingEnforcement`. Η Microsoft ενημέρωσε αργότερα το χρονοδιάγραμμα, ώστε η επιστροφή σε compatibility mode να παραμένει δυνατή έως την ενημέρωση ασφαλείας της **9ης Σεπτεμβρίου 2025**.<sup>[[2]](#references)</sup> Οι administrators θα πρέπει:

1. Να κάνουν patch σε όλους τους DCs και τους AD CS servers (Μάιος 2022 ή νεότερο).
2. Να παρακολουθούν τα Event ID 39/41 για weak mappings κατά τη φάση *Audit*.
3. Να επανεκδίδουν client-auth certificates με το νέο **SID extension** ή να ρυθμίζουν strong manual mappings πριν το enforcement αποκλείσει τα weak mappings.

### Σημειώσεις για operators σε hardened forests

- Το **ESC1/ESC6 από μόνο του δεν αποτελεί πλέον ολόκληρη την εικόνα** σε περιβάλλοντα 2025+. Αν ζητήσετε certificate για άλλο principal, συνήθως χρειάζεστε επίσης ένα strong mapping artifact, όπως το SID extension ή ένα explicit mapping.
- Το **ESC15 (EKUwu)** είναι κυρίως χρήσιμο σε unpatched περιβάλλοντα, επειδή μετατρέπει ακίνδυνα **v1** templates, όπως το **WebServer**, σε authentication- ή enrollment-agent-capable certificates μέσω injection **Application Policies**. Το Kerberos PKINIT εξακολουθεί να αξιολογεί τα EKUs, όμως το **LDAP Schannel** επίσης αναγνωρίζει τα Application Policies, γεγονός που διατηρεί σχετικό το LDAP-based abuse.<sup>[[1]](#references)</sup>
- Το **ESC16** είναι ρύθμιση σε επίπεδο CA: αν το CA απενεργοποιήσει global το SID security extension, κάθε certificate που εκδίδεται επιστρέφει σε ασθενέστερη συμπεριφορά mapping, εκτός αν η attack chain εισάγει SID μέσω άλλης υποστηριζόμενης μορφής.

---

## Βελτιώσεις σε Detection και Hardening

* Το **Defender for Identity AD CS sensor (2023-2024)** εμφανίζει πλέον posture assessments για ESC1-ESC8/ESC11 και δημιουργεί real-time alerts, όπως *“Domain-controller certificate issuance for a non-DC”* (ESC8) και *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Βεβαιωθείτε ότι sensors έχουν αναπτυχθεί σε όλους τους AD CS servers, ώστε να αξιοποιούνται αυτές οι detections.<sup>[[3]](#references)</sup>
* Απενεργοποιήστε ή περιορίστε αυστηρά την επιλογή **“Supply in the request”** σε όλα τα templates· προτιμήστε ρητά καθορισμένες τιμές SAN/EKU.
* Αφαιρέστε τα **Any Purpose** ή **No EKU** από τα templates, εκτός αν απαιτούνται απολύτως (αντιμετωπίζει σενάρια ESC2).
* Απαιτήστε **manager approval** ή αποκλειστικές ροές εργασίας Enrollment Agent για ευαίσθητα templates (π.χ. WebServer / CodeSigning).
* Περιορίστε το web enrollment (`certsrv`) και τα CES/NDES endpoints σε trusted networks ή τοποθετήστε τα πίσω από client-certificate authentication.
* Επιβάλετε RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) για τον περιορισμό του ESC11 (RPC relay). Το flag είναι **ενεργοποιημένο από προεπιλογή**, όμως συχνά απενεργοποιείται για legacy clients, γεγονός που επαναφέρει τον κίνδυνο relay.
* Ασφαλίστε τα **IIS-based enrollment endpoints** (CES/Certsrv): απενεργοποιήστε το NTLM όπου είναι δυνατό ή απαιτήστε HTTPS + Extended Protection για τον αποκλεισμό των ESC8 relays.

---

## Αναφορές

- [1] [EKUwu: Όχι απλώς άλλο ένα AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Αλλαγές στο certificate-based authentication σε Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Assessments ασφαλείας για certificates - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../banners/hacktricks-training.md}}
