# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή

### Components of a Certificate

- Το **Subject** του certificate δηλώνει τον κάτοχό του.
- Ένα **Public Key** αντιστοιχίζεται με ένα privately held key για να συνδέσει το certificate με τον νόμιμο κάτοχό του.
- Η **Validity Period**, οριζόμενη από τις ημερομηνίες **NotBefore** και **NotAfter**, καθορίζει τη διάρκεια ισχύος του certificate.
- Ένας μοναδικός **Serial Number**, που παρέχεται από το Certificate Authority (CA), αναγνωρίζει κάθε certificate.
- Το **Issuer** αναφέρεται στο CA που εξέδωσε το certificate.
- Το **SubjectAlternativeName** επιτρέπει πρόσθετα ονόματα για το subject, βελτιώνοντας την ευελιξία αναγνώρισης.
- Οι **Basic Constraints** αναγνωρίζουν αν το certificate είναι για CA ή για end entity και ορίζουν περιορισμούς χρήσης.
- Τα **Extended Key Usages (EKUs)** καθορίζουν τους συγκεκριμένους σκοπούς του certificate, όπως code signing ή email encryption, μέσω Object Identifiers (OIDs).
- Ο **Signature Algorithm** καθορίζει τη μέθοδο υπογραφής του certificate.
- Η **Signature**, που δημιουργείται με το private key του issuer, εγγυάται την αυθεντικότητα του certificate.

### Special Considerations

- Τα **Subject Alternative Names (SANs)** επεκτείνουν την εφαρμοσιμότητα ενός certificate σε πολλαπλές ταυτότητες, κάτι κρίσιμο για servers με πολλαπλά domains. Οι ασφαλείς διαδικασίες έκδοσης είναι ζωτικής σημασίας για την αποφυγή κινδύνων impersonation από attackers που χειρίζονται το SAN specification.

### Certificate Authorities (CAs) in Active Directory (AD)

Το AD CS αναγνωρίζει CA certificates σε ένα AD forest μέσω καθορισμένων containers, καθένα με ξεχωριστό ρόλο:

- Το container **Certification Authorities** περιέχει trusted root CA certificates.
- Το container **Enrolment Services** περιγράφει Enterprise CAs και τα certificate templates τους.
- Το αντικείμενο **NTAuthCertificates** περιλαμβάνει CA certificates εξουσιοδοτημένα για AD authentication.
- Το container **AIA (Authority Information Access)** διευκολύνει την επικύρωση certificate chain με intermediate και cross CA certificates.

### Certificate Acquisition: Client Certificate Request Flow

1. Η διαδικασία request ξεκινά όταν οι clients εντοπίζουν ένα Enterprise CA.
2. Δημιουργείται ένα CSR, που περιέχει ένα public key και άλλα στοιχεία, αφού πρώτα παραχθεί ένα public-private key pair.
3. Το CA αξιολογεί το CSR σε σχέση με τα διαθέσιμα certificate templates, εκδίδοντας το certificate με βάση τα permissions του template.
4. Μετά την έγκριση, το CA υπογράφει το certificate με το private key του και το επιστρέφει στον client.

### Certificate Templates

Ορισμένα μέσα στο AD, αυτά τα templates περιγράφουν τις ρυθμίσεις και τα permissions για την έκδοση certificates, συμπεριλαμβανομένων των επιτρεπόμενων EKUs και των δικαιωμάτων enrollment ή modification, κρίσιμα για τη διαχείριση πρόσβασης στις certificate services.

**Template schema version matters.** Τα παλαιότερα **v1** templates (για παράδειγμα, το ενσωματωμένο **WebServer** template) δεν έχουν αρκετούς σύγχρονους enforcement knobs. Η έρευνα **ESC15/EKUwu** έδειξε ότι σε **v1 templates**, ένας requester μπορεί να ενσωματώσει **Application Policies/EKUs** στο CSR που έχουν **προτεραιότητα έναντι** των EKUs που έχουν ρυθμιστεί στο template, επιτρέποντας client-auth, enrollment agent, ή code-signing certificates μόνο με enrollment rights. Προτιμήστε **v2/v3 templates**, αφαιρέστε ή αντικαταστήστε τα v1 defaults, και περιορίστε αυστηρά τα EKUs στον προβλεπόμενο σκοπό.

## Certificate Enrollment

Η διαδικασία enrollment για certificates ξεκινά από έναν administrator που **δημιουργεί ένα certificate template**, το οποίο στη συνέχεια **δημοσιεύεται** από μια Enterprise Certificate Authority (CA). Αυτό καθιστά το template διαθέσιμο για client enrollment, ένα βήμα που επιτυγχάνεται με την προσθήκη του ονόματος του template στο πεδίο `certificatetemplates` ενός Active Directory object.

Για να ζητήσει ένας client ένα certificate, πρέπει να του έχουν δοθεί **enrollment rights**. Αυτά τα δικαιώματα ορίζονται από security descriptors στο certificate template και στο Enterprise CA το ίδιο. Τα permissions πρέπει να έχουν δοθεί και στις δύο τοποθεσίες για να είναι επιτυχής ένα request.

### Template Enrollment Rights

Αυτά τα δικαιώματα καθορίζονται μέσω Access Control Entries (ACEs), περιγράφοντας permissions όπως:

- Τα δικαιώματα **Certificate-Enrollment** και **Certificate-AutoEnrollment**, καθένα συσχετισμένο με συγκεκριμένα GUIDs.
- Το **ExtendedRights**, που επιτρέπει όλα τα extended permissions.
- Το **FullControl/GenericAll**, που παρέχει πλήρη έλεγχο πάνω στο template.

### Enterprise CA Enrollment Rights

Τα δικαιώματα του CA περιγράφονται στο security descriptor του, το οποίο είναι προσβάσιμο μέσω της Certificate Authority management console. Ορισμένες ρυθμίσεις επιτρέπουν ακόμη και σε low-privileged users remote access, κάτι που μπορεί να αποτελέσει ζήτημα ασφάλειας.

### Additional Issuance Controls

Ορισμένοι έλεγχοι μπορεί να ισχύουν, όπως:

- **Manager Approval**: Τοποθετεί τα requests σε κατάσταση pending μέχρι να εγκριθούν από certificate manager.
- **Enrolment Agents and Authorized Signatures**: Καθορίζουν τον αριθμό των απαιτούμενων signatures σε ένα CSR και τα απαραίτητα Application Policy OIDs.

### Methods to Request Certificates

Τα certificates μπορούν να ζητηθούν μέσω:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), χρησιμοποιώντας DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), μέσω named pipes ή TCP/IP.
3. Του **certificate enrollment web interface**, με εγκατεστημένο το Certificate Authority Web Enrollment role.
4. Του **Certificate Enrollment Service** (CES), σε συνδυασμό με το Certificate Enrollment Policy (CEP) service.
5. Του **Network Device Enrollment Service** (NDES) για network devices, χρησιμοποιώντας το Simple Certificate Enrollment Protocol (SCEP).

Οι Windows users μπορούν επίσης να ζητήσουν certificates μέσω του GUI (`certmgr.msc` ή `certlm.msc`) ή μέσω command-line tools (`certreq.exe` ή της PowerShell εντολής `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Πιστοποίηση με Certificate

Το Active Directory (AD) υποστηρίζει certificate authentication, κυρίως χρησιμοποιώντας τα πρωτόκολλα **Kerberos** και **Secure Channel (Schannel)**.

### Διαδικασία Kerberos Authentication

Στη διαδικασία Kerberos authentication, ένα αίτημα ενός χρήστη για Ticket Granting Ticket (TGT) υπογράφεται χρησιμοποιώντας το **private key** του certificate του χρήστη. Αυτό το αίτημα περνά από αρκετούς ελέγχους από τον domain controller, συμπεριλαμβανομένων της **validity** του certificate, της **path** του και της **revocation status** του. Οι έλεγχοι περιλαμβάνουν επίσης την επαλήθευση ότι το certificate προέρχεται από αξιόπιστη πηγή και την επιβεβαίωση της παρουσίας του issuer στο **NTAUTH certificate store**. Η επιτυχής ολοκλήρωση των ελέγχων έχει ως αποτέλεσμα την έκδοση ενός TGT. Το αντικείμενο **`NTAuthCertificates`** στο AD, που βρίσκεται στο:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
είναι κεντρικό για τη δημιουργία trust για certificate authentication.

Since the **KB5014754** rollout, modern Kerberos certificate auth is mostly about **mapping strength**, not just EKUs. In hardened forests:

- Ένα certificate που περιέχει μόνο ένα **UPN/DNS SAN** μπορεί να μην αρκεί πλέον για logon.
- Το KDC προτιμά ένα **strong binding**, συνήθως το **SID security extension** (`1.3.6.1.4.1.311.25.2`) ή ένα strong explicit mapping στο `altSecurityIdentities`.
- Αν το cert δεν έχει strong mapping, τα DCs καταγράφουν **Kdcsvc Event ID 39/41** σε compatibility mode και αρνούνται το auth σε enforcement mode.
- Σε mixed attack paths, τα **ESC9/ESC16** έχουν σημασία γιατί αφαιρούν το SID extension από τα issued certs· οι operators τότε βασίζονται σε explicit mappings ή SAN URL SID formats όπου το attack path τα υποστηρίζει.

### Secure Channel (Schannel) Authentication

Το Schannel διευκολύνει secure TLS/SSL connections, όπου κατά τη διάρκεια ενός handshake, ο client παρουσιάζει ένα certificate που, αν επικυρωθεί επιτυχώς, εξουσιοδοτεί την πρόσβαση. Το mapping ενός certificate σε έναν AD account μπορεί να περιλαμβάνει τη Kerberos **S4U2Self** function ή το **Subject Alternative Name (SAN)** του certificate, μεταξύ άλλων μεθόδων.

Το Schannel είναι επίσης το πρακτικό fallback όταν το **PKINIT** δεν είναι διαθέσιμο. Για παράδειγμα, αν ένας domain controller δεν έχει κατάλληλο certificate **Smart Card Logon**, τα `certipy auth`/PKINIT tooling μπορεί να αποτύχουν να πάρουν ένα TGT, αλλά το ίδιο certificate μπορεί να είναι ακόμη usable απέναντι σε **LDAPS** ή **LDAP StartTLS** για authentication και LDAP operations.

### AD Certificate Services Enumeration

Οι certificate services του AD μπορούν να enumerated μέσω LDAP queries, αποκαλύπτοντας πληροφορίες για **Enterprise Certificate Authorities (CAs)** και τις configurations τους. Αυτό είναι προσβάσιμο από οποιονδήποτε domain-authenticated user χωρίς ειδικά privileges. Tools όπως τα **[Certify](https://github.com/GhostPack/Certify)** και **[Certipy](https://github.com/ly4k/Certipy)** χρησιμοποιούνται για enumeration και vulnerability assessment σε AD CS environments.

Commands για τη χρήση αυτών των tools περιλαμβάνουν:
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

## Πρόσφατες Ευπάθειες & Ενημερώσεις Ασφαλείας (2022-2025)

| Έτος | ID / Όνομα | Επιπτώσεις | Βασικά συμπεράσματα |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* με spoofing machine account certificates κατά το PKINIT. | Το patch περιλαμβάνεται στις ενημερώσεις ασφαλείας της **10ης Μαΐου 2022**. Το auditing & strong-mapping controls εισήχθησαν μέσω του **KB5014754**· τα περιβάλλοντα θα πρέπει πλέον να βρίσκονται σε λειτουργία *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* στα AD CS Web Enrollment (certsrv) και CES roles. | Τα δημόσια PoCs είναι περιορισμένα, αλλά τα ευάλωτα IIS components είναι συχνά εκτεθειμένα εσωτερικά. Patch από το Patch Tuesday του **Ιουλίου 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Σε **v1 templates**, ένας requester με enrollment rights μπορεί να ενσωματώσει **Application Policies/EKUs** στο CSR που προτιμώνται έναντι των template EKUs, παράγοντας client-auth, enrollment agent ή code-signing certificates. | Διορθώθηκε από τις **12 Νοεμβρίου 2024**. Αντικαταστήστε ή υπερκαλύψτε τα v1 templates (π.χ. default WebServer), περιορίστε τα EKUs σύμφωνα με τον σκοπό και περιορίστε τα enrollment rights. |

### Χρονοδιάγραμμα hardening της Microsoft (KB5014754)

Η Microsoft εισήγαγε μια ανάπτυξη τριών φάσεων (Compatibility → Audit → Enforcement) για να μεταφέρει την πιστοποίηση Kerberos μέσω certificates μακριά από τα αδύναμα implicit mappings. Από τις **11 Φεβρουαρίου 2025**, οι domain controllers μεταβαίνουν αυτόματα σε **Full Enforcement** αν δεν έχει οριστεί η τιμή registry `StrongCertificateBindingEnforcement`. Η Microsoft αργότερα ενημέρωσε το χρονοδιάγραμμα ώστε η επιστροφή σε compatibility mode να παραμένει δυνατή μέχρι την ενημέρωση ασφαλείας της **9ης Σεπτεμβρίου 2025**. Οι administrators θα πρέπει:

1. Να κάνουν patch όλους τους DCs & AD CS servers (Μάιος 2022 ή νεότερο).
2. Να παρακολουθούν τα Event ID 39/41 για weak mappings κατά τη φάση *Audit*.
3. Να επανεκδώσουν client-auth certificates με το νέο **SID extension** ή να διαμορφώσουν strong manual mappings πριν το enforcement μπλοκάρει τα weak mappings.

### Σημειώσεις operator για hardened forests

- Το **ESC1/ESC6 μόνο του δεν είναι πλέον όλη η εικόνα** σε περιβάλλοντα 2025+. Αν ζητήσετε ένα cert για άλλο principal, συνήθως χρειάζεστε επίσης ένα strong mapping artifact όπως το SID extension ή ένα explicit mapping.
- Το **ESC15 (EKUwu)** είναι κυρίως χρήσιμο σε unpatched περιβάλλοντα, επειδή μετατρέπει ακίνδυνα **v1** templates όπως το **WebServer** σε certs ικανά για authentication ή enrollment-agent μέσω injection των **Application Policies**. Το Kerberos PKINIT εξακολουθεί να αξιολογεί EKUs, αλλά το **LDAP Schannel** επίσης τιμά τα Application Policies, κάτι που διατηρεί σχετική την LDAP-based abuse.
- Το **ESC16** είναι ένα CA-wide knob: αν το CA απενεργοποιήσει global το SID security extension, κάθε issued certificate επιστρέφει προς πιο αδύναμη συμπεριφορά mapping, εκτός αν η αλυσίδα επίθεσης εισάγει ένα SID με άλλο υποστηριζόμενο format.

---

## Βελτιώσεις Detection & Hardening

* Ο **Defender for Identity AD CS sensor (2023-2024)** πλέον εμφανίζει posture assessments για ESC1-ESC8/ESC11 και δημιουργεί real-time alerts όπως *“Domain-controller certificate issuance for a non-DC”* (ESC8) και *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Βεβαιωθείτε ότι τα sensors έχουν αναπτυχθεί σε όλους τους AD CS servers για να επωφεληθείτε από αυτές τις detections.
* Απενεργοποιήστε ή περιορίστε αυστηρά την επιλογή **“Supply in the request”** σε όλα τα templates· προτιμήστε ρητά ορισμένες τιμές SAN/EKU.
* Αφαιρέστε τα **Any Purpose** ή **No EKU** από τα templates εκτός αν είναι απολύτως απαραίτητα (αντιμετωπίζει σενάρια ESC2).
* Απαιτήστε **manager approval** ή ειδικά Enrollment Agent workflows για ευαίσθητα templates (π.χ. WebServer / CodeSigning).
* Περιορίστε τα web enrollment (`certsrv`) και CES/NDES endpoints σε trusted networks ή πίσω από client-certificate authentication.
* Επιβάλετε RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) για mitigation του ESC11 (RPC relay). Το flag είναι **on by default**, αλλά συχνά απενεργοποιείται για legacy clients, κάτι που επανανοίγει το relay risk.
* Ασφαλίστε τα **IIS-based enrollment endpoints** (CES/Certsrv): απενεργοποιήστε το NTLM όπου είναι δυνατό ή απαιτήστε HTTPS + Extended Protection για να μπλοκάρετε τα ESC8 relays.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
