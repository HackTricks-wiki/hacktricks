# Πιστοποιητικά AD

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή

### Components ενός Πιστοποιητικού

- Το **Subject** του πιστοποιητικού υποδηλώνει τον κάτοχό του.
- Ένα **Public Key** συνδυάζεται με ένα ιδιωτικά διατηρούμενο κλειδί, ώστε να συνδέεται το πιστοποιητικό με τον νόμιμο κάτοχό του.
- Η **Validity Period**, η οποία ορίζεται από τις ημερομηνίες **NotBefore** και **NotAfter**, προσδιορίζει τη διάρκεια ισχύος του πιστοποιητικού.
- Ένας μοναδικός **Serial Number**, ο οποίος παρέχεται από την Certificate Authority (CA), προσδιορίζει κάθε πιστοποιητικό.
- Το **Issuer** αναφέρεται στην CA που εξέδωσε το πιστοποιητικό.
- Το **SubjectAlternativeName** επιτρέπει πρόσθετα ονόματα για το subject, ενισχύοντας την ευελιξία της ταυτοποίησης.
- Τα **Basic Constraints** προσδιορίζουν αν το πιστοποιητικό αφορά CA ή end entity και καθορίζουν περιορισμούς χρήσης.
- Τα **Extended Key Usages (EKUs)** καθορίζουν τους συγκεκριμένους σκοπούς του πιστοποιητικού, όπως code signing ή email encryption, μέσω Object Identifiers (OIDs).
- Ο **Signature Algorithm** καθορίζει τη μέθοδο υπογραφής του πιστοποιητικού.
- Η **Signature**, η οποία δημιουργείται με το ιδιωτικό κλειδί του issuer, εγγυάται την αυθεντικότητα του πιστοποιητικού.<sup>[[1]](#references)</sup>

### Ειδικές considerations

- Τα **Subject Alternative Names (SANs)** επεκτείνουν την εφαρμοσιμότητα ενός πιστοποιητικού σε πολλαπλές ταυτότητες, κάτι κρίσιμο για servers με πολλαπλά domains. Οι ασφαλείς διαδικασίες έκδοσης είναι απαραίτητες για την αποφυγή κινδύνων impersonation από attackers που χειραγωγούν την προδιαγραφή SAN.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) στο Active Directory (AD)

Το AD CS αναγνωρίζει τα CA certificates σε ένα AD forest μέσω καθορισμένων containers, καθένα από τα οποία εξυπηρετεί μοναδικούς ρόλους:<sup>[[1]](#references)</sup>

- Το container **Certification Authorities** περιέχει trusted root CA certificates.
- Το container **Enrolment Services** περιέχει πληροφορίες για τα Enterprise CAs και τα certificate templates τους.
- Το object **NTAuthCertificates** περιλαμβάνει CA certificates που είναι εξουσιοδοτημένα για AD authentication.
- Το container **AIA (Authority Information Access)** διευκολύνει την επικύρωση της certificate chain με intermediate και cross CA certificates.

### Απόκτηση Certificate: Client Certificate Request Flow

1. Η διαδικασία request ξεκινά όταν οι clients εντοπίζουν ένα Enterprise CA.
2. Δημιουργείται ένα CSR, το οποίο περιέχει ένα public key και άλλα στοιχεία, αφού δημιουργηθεί ένα public-private key pair.
3. Η CA αξιολογεί το CSR σε σχέση με τα διαθέσιμα certificate templates και εκδίδει το certificate βάσει των permissions του template.
4. Μετά την έγκριση, η CA υπογράφει το certificate με το ιδιωτικό της κλειδί και το επιστρέφει στον client.<sup>[[1]](#references)</sup>

### Certificate Templates

Τα templates αυτά ορίζονται μέσα στο AD και περιγράφουν τις ρυθμίσεις και τα permissions για την έκδοση certificates, συμπεριλαμβανομένων των επιτρεπόμενων EKUs και των δικαιωμάτων enrollment ή modification, τα οποία είναι κρίσιμα για τη διαχείριση της πρόσβασης στις certificate services.<sup>[[1]](#references)</sup>

## Certificate Enrollment

Η διαδικασία enrollment για certificates ξεκινά από έναν administrator, ο οποίος **δημιουργεί ένα certificate template**, το οποίο στη συνέχεια **δημοσιεύεται** από μια Enterprise Certificate Authority (CA). Έτσι το template γίνεται διαθέσιμο για client enrollment, μέσω της προσθήκης του ονόματος του template στο πεδίο `certificatetemplates` ενός Active Directory object.<sup>[[1]](#references)</sup>

Για να μπορέσει ένας client να ζητήσει ένα certificate, πρέπει να εκχωρηθούν **enrollment rights**. Αυτά τα δικαιώματα ορίζονται από security descriptors στο certificate template και στην ίδια την Enterprise CA. Για να είναι επιτυχές ένα request, πρέπει να εκχωρηθούν permissions και στις δύο τοποθεσίες.<sup>[[1]](#references)</sup>

### Template Enrollment Rights

Αυτά τα δικαιώματα καθορίζονται μέσω Access Control Entries (ACEs), οι οποίες περιγράφουν permissions όπως:<sup>[[1]](#references)</sup>

- Δικαιώματα **Certificate-Enrollment** και **Certificate-AutoEnrollment**, καθένα από τα οποία συνδέεται με συγκεκριμένα GUIDs.
- **ExtendedRights**, τα οποία επιτρέπουν όλα τα extended permissions.
- **FullControl/GenericAll**, τα οποία παρέχουν πλήρη έλεγχο στο template.

### Enterprise CA Enrollment Rights

Τα δικαιώματα της CA περιγράφονται στο security descriptor της, το οποίο είναι προσβάσιμο μέσω της κονσόλας διαχείρισης Certificate Authority. Ορισμένες ρυθμίσεις επιτρέπουν ακόμη και σε low-privileged users remote access, κάτι που θα μπορούσε να αποτελέσει security concern.<sup>[[1]](#references)</sup>

### Πρόσθετοι Issuance Controls

Μπορεί να εφαρμόζονται ορισμένα controls, όπως:<sup>[[1]](#references)</sup>

- **Manager Approval**: Τοποθετεί τα requests σε κατάσταση pending μέχρι να εγκριθούν από έναν certificate manager.
- **Enrolment Agents and Authorized Signatures**: Καθορίζουν τον απαιτούμενο αριθμό signatures σε ένα CSR και τα απαραίτητα Application Policy OIDs.

### Methods για Request Certificates

Τα certificates μπορούν να ζητηθούν μέσω:<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), με χρήση DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), μέσω named pipes ή TCP/IP.
3. Του **certificate enrollment web interface**, με εγκατεστημένο το Certificate Authority Web Enrollment role.
4. Του **Certificate Enrollment Service** (CES), σε συνδυασμό με το Certificate Enrollment Policy (CEP) service.
5. Του **Network Device Enrollment Service** (NDES) για network devices, με χρήση του Simple Certificate Enrollment Protocol (SCEP).

Οι Windows users μπορούν επίσης να ζητήσουν certificates μέσω του GUI (`certmgr.msc` ή `certlm.msc`) ή μέσω command-line tools (`certreq.exe` ή της εντολής `Get-Certificate` του PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Πιστοποίηση Certificate

Το Active Directory (AD) υποστηρίζει authentication μέσω certificate, χρησιμοποιώντας κυρίως τα πρωτόκολλα **Kerberos** και **Secure Channel (Schannel)**.<sup>[[1]](#references)</sup>

### Διαδικασία Kerberos Authentication

Στη διαδικασία Kerberos authentication, το request ενός χρήστη για ένα Ticket Granting Ticket (TGT) υπογράφεται χρησιμοποιώντας το **private key** του certificate του χρήστη. Αυτό το request υποβάλλεται σε διάφορους ελέγχους από τον domain controller, συμπεριλαμβανομένων των **validity**, **path** και **revocation status** του certificate. Οι έλεγχοι περιλαμβάνουν επίσης την επαλήθευση ότι το certificate προέρχεται από trusted source και την επιβεβαίωση ότι ο issuer υπάρχει στο **NTAUTH certificate store**. Οι επιτυχείς έλεγχοι έχουν ως αποτέλεσμα την έκδοση ενός TGT. Το αντικείμενο **`NTAuthCertificates`** στο AD, το οποίο βρίσκεται στη διεύθυνση:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
είναι θεμελιώδες για την establishing trust κατά το certificate authentication.<sup>[[1]](#references)</sup>

### Secure Channel (Schannel) Authentication

Το Schannel διευκολύνει ασφαλείς συνδέσεις TLS/SSL, όπου κατά τη διάρκεια ενός handshake, ο client παρουσιάζει ένα certificate το οποίο, εφόσον επικυρωθεί επιτυχώς, εξουσιοδοτεί την πρόσβαση.<sup>[[2]](#references)</sup> Η αντιστοίχιση ενός certificate σε έναν AD account μπορεί να περιλαμβάνει τη συνάρτηση **S4U2Self** του Kerberos ή το **Subject Alternative Name (SAN)** του certificate, μεταξύ άλλων μεθόδων.<sup>[[1]](#references)</sup>

### Απαρίθμηση υπηρεσιών πιστοποιητικών AD

Οι υπηρεσίες πιστοποιητικών του AD μπορούν να απαριθμηθούν μέσω LDAP queries, αποκαλύπτοντας πληροφορίες σχετικά με τις **Enterprise Certificate Authorities (CAs)** και τις διαμορφώσεις τους. Αυτό είναι προσβάσιμο από οποιονδήποτε domain-authenticated user χωρίς special privileges.<sup>[[1]](#references)</sup> Εργαλεία όπως τα **[Certify](https://github.com/GhostPack/Certify)** και **[Certipy](https://github.com/ly4k/Certipy)** χρησιμοποιούνται για enumeration και vulnerability assessment σε περιβάλλοντα AD CS.<sup>[[3]](#references)</sup>

Οι εντολές για τη χρήση αυτών των εργαλείων περιλαμβάνουν:
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
## Αναφορές

- [1] [Certified Pre-Owned: Κατάχρηση των Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [Τι είναι η αυθεντικοποίηση Client μέσω SSL/TLS και πώς λειτουργεί;](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
