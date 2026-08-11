# Πιστοποιητικά AD

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή

### Στοιχεία ενός πιστοποιητικού

- Το **Subject** του πιστοποιητικού υποδεικνύει τον κάτοχό του.
- Ένα **Public Key** συνδυάζεται με ένα ιδιωτικά διατηρούμενο κλειδί, ώστε να συνδέεται το πιστοποιητικό με τον νόμιμο κάτοχό του.
- Η **Validity Period**, η οποία ορίζεται από τις ημερομηνίες **NotBefore** και **NotAfter**, προσδιορίζει τη διάρκεια ισχύος του πιστοποιητικού.
- Ένας μοναδικός **Serial Number**, ο οποίος παρέχεται από την Certificate Authority (CA), αναγνωρίζει κάθε πιστοποιητικό.
- Το **Issuer** αναφέρεται στην CA που έχει εκδώσει το πιστοποιητικό.
- Το **SubjectAlternativeName** επιτρέπει πρόσθετα ονόματα για το subject, ενισχύοντας την ευελιξία ταυτοποίησης.
- Οι **Basic Constraints** προσδιορίζουν αν το πιστοποιητικό αφορά CA ή τελική οντότητα και καθορίζουν περιορισμούς χρήσης.
- Τα **Extended Key Usages (EKUs)** καθορίζουν τους συγκεκριμένους σκοπούς του πιστοποιητικού, όπως υπογραφή κώδικα ή κρυπτογράφηση email, μέσω Object Identifiers (OIDs).
- Ο **Signature Algorithm** καθορίζει τη μέθοδο υπογραφής του πιστοποιητικού.
- Η **Signature**, η οποία δημιουργείται με το ιδιωτικό κλειδί του issuer, εγγυάται την αυθεντικότητα του πιστοποιητικού.<sup>[[1]](#references)</sup>

### Ειδικές considerations

- Τα **Subject Alternative Names (SANs)** διευρύνουν την εφαρμογή ενός πιστοποιητικού σε πολλαπλές ταυτότητες, κάτι κρίσιμο για servers με πολλαπλά domains. Οι ασφαλείς διαδικασίες έκδοσης είναι απαραίτητες για την αποφυγή κινδύνων impersonation από attackers που χειραγωγούν τον καθορισμό του SAN.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) στο Active Directory (AD)

Το AD CS αναγνωρίζει τα πιστοποιητικά CA σε ένα AD forest μέσω καθορισμένων containers, καθένα από τα οποία εξυπηρετεί μοναδικούς ρόλους:<sup>[[1]](#references)</sup>

- Το container **Certification Authorities** περιέχει αξιόπιστα πιστοποιητικά root CA.
- Το container **Enrolment Services** περιγράφει τις Enterprise CAs και τα certificate templates τους.
- Το object **NTAuthCertificates** περιλαμβάνει πιστοποιητικά CA που είναι εξουσιοδοτημένα για authentication στο AD.
- Το container **AIA (Authority Information Access)** διευκολύνει την επικύρωση της αλυσίδας πιστοποιητικών με intermediate και cross CA certificates.

### Απόκτηση πιστοποιητικού: Ροή αίτησης Client Certificate

1. Η διαδικασία αίτησης ξεκινά όταν οι clients εντοπίζουν μια Enterprise CA.
2. Δημιουργείται ένα CSR, το οποίο περιέχει ένα public key και άλλα στοιχεία, μετά τη δημιουργία ενός ζεύγους public-private keys.
3. Η CA αξιολογεί το CSR σε σχέση με τα διαθέσιμα certificate templates και εκδίδει το πιστοποιητικό βάσει των permissions του template.
4. Μετά την έγκριση, η CA υπογράφει το πιστοποιητικό με το ιδιωτικό της κλειδί και το επιστρέφει στον client.<sup>[[1]](#references)</sup>

### Certificate Templates

Αυτά τα templates, τα οποία ορίζονται στο AD, περιγράφουν τις ρυθμίσεις και τα permissions για την έκδοση πιστοποιητικών, συμπεριλαμβανομένων των επιτρεπόμενων EKUs και των δικαιωμάτων enrollment ή modification, τα οποία είναι κρίσιμα για τη διαχείριση της πρόσβασης στις certificate services.<sup>[[1]](#references)</sup>

## Certificate Enrollment

Η διαδικασία enrollment για πιστοποιητικά ξεκινά από έναν administrator, ο οποίος **δημιουργεί ένα certificate template**, το οποίο στη συνέχεια **δημοσιεύεται** από μια Enterprise Certificate Authority (CA). Έτσι, το template γίνεται διαθέσιμο για enrollment από clients, μέσω της προσθήκης του ονόματος του template στο πεδίο `certificatetemplates` ενός object του Active Directory.<sup>[[1]](#references)</sup>

Για να μπορέσει ένας client να ζητήσει ένα πιστοποιητικό, πρέπει να εκχωρηθούν **enrollment rights**. Αυτά τα rights καθορίζονται από security descriptors στο certificate template και στην ίδια την Enterprise CA. Πρέπει να εκχωρηθούν permissions και στις δύο τοποθεσίες, ώστε μια αίτηση να ολοκληρωθεί επιτυχώς.<sup>[[1]](#references)</sup>

### Template Enrollment Rights

Αυτά τα rights καθορίζονται μέσω Access Control Entries (ACEs), οι οποίες περιγράφουν permissions όπως:<sup>[[1]](#references)</sup>

- Τα rights **Certificate-Enrollment** και **Certificate-AutoEnrollment**, καθένα από τα οποία συνδέεται με συγκεκριμένα GUIDs.
- Τα **ExtendedRights**, τα οποία επιτρέπουν όλα τα extended permissions.
- Τα **FullControl/GenericAll**, τα οποία παρέχουν πλήρη έλεγχο στο template.

### Enterprise CA Enrollment Rights

Τα rights της CA περιγράφονται στο security descriptor της, το οποίο είναι προσβάσιμο μέσω της management console του Certificate Authority. Ορισμένες ρυθμίσεις επιτρέπουν ακόμη και σε low-privileged users remote access, γεγονός που μπορεί να αποτελέσει security concern.<sup>[[1]](#references)</sup>

### Πρόσθετοι έλεγχοι έκδοσης

Ενδέχεται να εφαρμόζονται ορισμένοι έλεγχοι, όπως:<sup>[[1]](#references)</sup>

- **Manager Approval**: Θέτει τις αιτήσεις σε κατάσταση pending μέχρι να εγκριθούν από certificate manager.
- **Enrolment Agents and Authorized Signatures**: Καθορίζουν τον αριθμό των απαιτούμενων signatures σε ένα CSR και τα απαραίτητα Application Policy OIDs.

### Μέθοδοι αίτησης πιστοποιητικών

Τα πιστοποιητικά μπορούν να ζητηθούν μέσω:<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), με χρήση DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), μέσω named pipes ή TCP/IP.
3. Του **certificate enrollment web interface**, με εγκατεστημένο τον ρόλο Certificate Authority Web Enrollment.
4. Του **Certificate Enrollment Service** (CES), σε συνδυασμό με την υπηρεσία Certificate Enrollment Policy (CEP).
5. Του **Network Device Enrollment Service** (NDES) για network devices, με χρήση του Simple Certificate Enrollment Protocol (SCEP).

Οι Windows users μπορούν επίσης να ζητήσουν πιστοποιητικά μέσω του GUI (`certmgr.msc` ή `certlm.msc`) ή μέσω command-line tools (`certreq.exe` ή της εντολής `Get-Certificate` του PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Πιστοποίηση μέσω Certificate

Το Active Directory (AD) υποστηρίζει πιστοποίηση μέσω certificate, χρησιμοποιώντας κυρίως τα πρωτόκολλα **Kerberos** και **Secure Channel (Schannel)**.<sup>[[1]](#references)</sup>

### Διαδικασία Πιστοποίησης Kerberos

Στη διαδικασία πιστοποίησης Kerberos, το αίτημα ενός χρήστη για Ticket Granting Ticket (TGT) υπογράφεται χρησιμοποιώντας το **private key** του certificate του χρήστη. Αυτό το αίτημα υποβάλλεται σε διάφορες επικυρώσεις από τον domain controller, συμπεριλαμβανομένων της **validity**, του **path** και της κατάστασης ανάκλησης του certificate. Οι επικυρώσεις περιλαμβάνουν επίσης την επαλήθευση ότι το certificate προέρχεται από αξιόπιστη πηγή και την επιβεβαίωση της παρουσίας του εκδότη στο **NTAUTH certificate store**. Οι επιτυχείς επικυρώσεις οδηγούν στην έκδοση ενός TGT. Το αντικείμενο **`NTAuthCertificates`** στο AD, το οποίο βρίσκεται στη διεύθυνση:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
είναι κεντρικής σημασίας για την establishing trust κατά την certificate authentication.<sup>[[1]](#references)</sup>

### Αυθεντικοποίηση Secure Channel (Schannel)

Το Schannel διευκολύνει τις ασφαλείς συνδέσεις TLS/SSL, όπου, κατά τη διάρκεια ενός handshake, ο client παρουσιάζει ένα certificate το οποίο, εάν επικυρωθεί επιτυχώς, εξουσιοδοτεί την πρόσβαση.<sup>[[2]](#references)</sup> Η αντιστοίχιση ενός certificate σε έναν λογαριασμό AD μπορεί να περιλαμβάνει τη συνάρτηση **S4U2Self** του Kerberos ή το **Subject Alternative Name (SAN)** του certificate, μεταξύ άλλων μεθόδων.<sup>[[1]](#references)</sup>

### Enumeration των AD Certificate Services

Τα certificate services του AD μπορούν να γίνουν enumerate μέσω queries LDAP, αποκαλύπτοντας πληροφορίες σχετικά με τις **Enterprise Certificate Authorities (CAs)** και τις διαμορφώσεις τους. Αυτό είναι προσβάσιμο από οποιονδήποτε domain-authenticated user χωρίς ειδικά privileges.<sup>[[1]](#references)</sup> Εργαλεία όπως τα **[Certify](https://github.com/GhostPack/Certify)** και **[Certipy](https://github.com/ly4k/Certipy)** χρησιμοποιούνται για enumeration και vulnerability assessment σε περιβάλλοντα AD CS.<sup>[[3]](#references)</sup>

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
Το Rubeus μπορεί επίσης να χρησιμοποιήσει ένα προστατευμένο με κωδικό πρόσβασης πιστοποιητικό PFX για authentication μέσω PKINIT και να ζητήσει ένα TGT. Το προαιρετικό switch `/getcredentials` ζητά ένα U2U service ticket και επιχειρεί να ανακτήσει το NT hash του account:<sup>[[4]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```
## References

- [1] [Certified Pre-Owned: Κατάχρηση των Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [Τι είναι η αυθεντικοποίηση πελάτη SSL/TLS και πώς λειτουργεί;](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../../banners/hacktricks-training.md}}
