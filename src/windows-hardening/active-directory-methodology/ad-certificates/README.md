# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- Το **Subject** του πιστοποιητικού δηλώνει τον κάτοχό του.
- Ένα **Public Key** είναι σε ζεύγος με ένα ιδιωτικά φυλασσόμενο κλειδί για να συνδέει το πιστοποιητικό με τον νόμιμο κάτοχό του.
- Η **Validity Period**, ορισμένη από τις ημερομηνίες **NotBefore** και **NotAfter**, προσδιορίζει τη χρονική διάρκεια ισχύος του πιστοποιητικού.
- Ένας μοναδικός **Serial Number**, που παρέχεται από την Certificate Authority (CA), αναγνωρίζει κάθε πιστοποιητικό.
- Ο **Issuer** αναφέρεται στην CA που έχει εκδώσει το πιστοποιητικό.
- Το **SubjectAlternativeName** επιτρέπει πρόσθετα ονόματα για τον subject, αυξάνοντας την ευελιξία στην αναγνώριση.
- Τα **Basic Constraints** υποδεικνύουν αν το πιστοποιητικό είναι για μια CA ή για ένα end entity και ορίζουν περιορισμούς χρήσης.
- Τα **Extended Key Usages (EKUs)** καθορίζουν τους συγκεκριμένους σκοπούς του πιστοποιητικού, όπως code signing ή email encryption, μέσω Object Identifiers (OIDs).
- Ο **Signature Algorithm** προσδιορίζει τη μέθοδο υπογραφής του πιστοποιητικού.
- Η **Signature**, δημιουργημένη με το ιδιωτικό κλειδί του issuer, εγγυάται την αυθεντικότητα του πιστοποιητικού.

### Special Considerations

- Τα **Subject Alternative Names (SANs)** επεκτείνουν την εφαρμοσιμότητα ενός πιστοποιητικού σε πολλαπλές ταυτότητες, κρίσιμα για servers με πολλούς domains. Απαιτούνται ασφαλείς διαδικασίες έκδοσης για να αποφευχθεί ο κίνδυνος impersonation από attackers που χειρίζονται την προδιαγραφή του SAN.

### Certificate Authorities (CAs) in Active Directory (AD)

Το AD CS αναγνωρίζει τα CA certificates σε ένα AD forest μέσω καθορισμένων containers, το καθένα με ξεχωριστό ρόλο:

- Το **Certification Authorities** container περιέχει trusted root CA certificates.
- Το **Enrolment Services** container περιγράφει Enterprise CAs και τα certificate templates τους.
- Το **NTAuthCertificates** object περιλαμβάνει CA certificates εξουσιοδοτημένα για AD authentication.
- Το **AIA (Authority Information Access)** container διευκολύνει την επικύρωση της certificate chain με intermediate και cross CA certificates.

### Certificate Acquisition: Client Certificate Request Flow

1. Η διαδικασία αίτησης ξεκινά με τους clients να εντοπίζουν ένα Enterprise CA.
2. Δημιουργείται ένα CSR που περιέχει ένα public key και άλλες πληροφορίες, μετά τη δημιουργία ενός ζεύγους public-private key.
3. Η CA αξιολογεί το CSR σε σχέση με τα διαθέσιμα certificate templates και εκδίδει το πιστοποιητικό βάσει των permissions του template.
4. Μετά την έγκριση, η CA υπογράφει το πιστοποιητικό με το ιδιωτικό της κλειδί και το επιστρέφει στον client.

### Certificate Templates

Ορισμένα μέσα στο AD, αυτά τα templates περιγράφουν τις ρυθμίσεις και τα δικαιώματα για την έκδοση πιστοποιητικών, συμπεριλαμβανομένων των επιτρεπόμενων EKUs και των δικαιωμάτων enrollment ή modification, κρίσιμα για τη διαχείριση πρόσβασης στις υπηρεσίες πιστοποιητικών.

## Certificate Enrollment

Η διαδικασία enrollment για πιστοποιητικά αρχίζει από έναν administrator που **δημιουργεί ένα certificate template**, το οποίο στη συνέχεια **δημοσιεύεται** από μια Enterprise Certificate Authority (CA). Αυτό καθιστά το template διαθέσιμο για client enrollment, ένα βήμα που επιτυγχάνεται προσθέτοντας το όνομα του template στο πεδίο `certificatetemplates` ενός Active Directory object.

Για να κάνει ένας client αίτηση για πιστοποιητικό, πρέπει να του έχουν χορηγηθεί **enrollment rights**. Αυτά τα δικαιώματα ορίζονται από security descriptors πάνω στο certificate template και στην Enterprise CA ίδια. Τα permissions πρέπει να χορηγηθούν και στις δύο τοποθεσίες για να είναι επιτυχημένη μια αίτηση.

### Template Enrollment Rights

Αυτά τα rights καθορίζονται μέσω Access Control Entries (ACEs), που περιγράφουν permissions όπως:

- **Certificate-Enrollment** και **Certificate-AutoEnrollment** rights, το καθένα συνδεδεμένο με συγκεκριμένα GUIDs.
- **ExtendedRights**, που επιτρέπουν όλα τα extended permissions.
- **FullControl/GenericAll**, που παρέχουν πλήρη έλεγχο πάνω στο template.

### Enterprise CA Enrollment Rights

Τα rights της CA περιγράφονται στο security descriptor της, προσβάσιμο μέσω της κονσόλας διαχείρισης Certificate Authority. Ορισμένες ρυθμίσεις επιτρέπουν ακόμη και σε low-privileged users απομακρυσμένη πρόσβαση, κάτι που μπορεί να αποτελεί θέμα ασφαλείας.

### Additional Issuance Controls

Μπορεί να εφαρμόζονται ορισμένοι έλεγχοι έκδοσης, όπως:

- **Manager Approval**: Τοποθετεί αιτήσεις σε pending κατάσταση έως ότου εγκριθούν από certificate manager.
- **Enrolment Agents and Authorized Signatures**: Προσδιορίζουν τον αριθμό απαιτούμενων signatures σε ένα CSR και τα αναγκαία Application Policy OIDs.

### Methods to Request Certificates

Πιστοποιητικά μπορούν να ζητηθούν μέσω:

1. Του **Windows Client Certificate Enrollment Protocol** (MS-WCCE), χρησιμοποιώντας DCOM interfaces.
2. Του **ICertPassage Remote Protocol** (MS-ICPR), μέσω named pipes ή TCP/IP.
3. Του **certificate enrollment web interface**, με εγκατεστημένο το Certificate Authority Web Enrollment role.
4. Της **Certificate Enrollment Service** (CES), σε συνδυασμό με την Certificate Enrollment Policy (CEP) service.
5. Της **Network Device Enrollment Service** (NDES) για network devices, χρησιμοποιώντας το Simple Certificate Enrollment Protocol (SCEP).

Οι Windows users μπορούν επίσης να αιτηθούν πιστοποιητικά μέσω του GUI (`certmgr.msc` ή `certlm.msc`) ή εργαλείων command-line (`certreq.exe` ή την εντολή PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Αυθεντικοποίηση με Πιστοποιητικά

Το Active Directory (AD) υποστηρίζει αυθεντικοποίηση με πιστοποιητικά, χρησιμοποιώντας κυρίως τα πρωτόκολλα **Kerberos** και **Secure Channel (Schannel)**.

### Διαδικασία αυθεντικοποίησης Kerberos

Στη διαδικασία αυθεντικοποίησης Kerberos, το αίτημα ενός χρήστη για ένα Ticket Granting Ticket (TGT) υπογράφεται χρησιμοποιώντας το **ιδιωτικό κλειδί** του πιστοποιητικού του χρήστη. Το αίτημα αυτό υπόκειται σε διάφορους ελέγχους από τον domain controller, συμπεριλαμβανομένης της **έγκυρότητας** του πιστοποιητικού, της **διαδρομής (path)** και της **κατάστασης ανάκλησης**. Οι έλεγχοι περιλαμβάνουν επίσης την επαλήθευση ότι το πιστοποιητικό προέρχεται από αξιόπιστη πηγή και την επιβεβαίωση της παρουσίας του εκδότη στο **NTAUTH certificate store**. Επιτυχείς έλεγχοι έχουν ως αποτέλεσμα την έκδοση ενός TGT. Το **`NTAuthCertificates`** αντικείμενο στο AD, που βρίσκεται στο:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
είναι κεντρικό για την εγκαθίδρυση εμπιστοσύνης για την πιστοποίηση μέσω πιστοποιητικών.

### Αυθεντικοποίηση Secure Channel (Schannel)

Το Schannel διευκολύνει ασφαλείς συνδέσεις TLS/SSL, όπου κατά τη διάρκεια ενός handshake, ο πελάτης παρουσιάζει ένα πιστοποιητικό που, εφόσον επικυρωθεί επιτυχώς, εξουσιοδοτεί την πρόσβαση. Η αντιστοίχηση ενός πιστοποιητικού σε λογαριασμό AD μπορεί να περιλαμβάνει τη λειτουργία του Kerberos **S4U2Self** ή το **Subject Alternative Name (SAN)** του πιστοποιητικού, μεταξύ άλλων μεθόδων.

### Εντοπισμός AD Certificate Services

Οι υπηρεσίες πιστοποιητικών του AD μπορούν να ανιχνευθούν μέσω ερωτημάτων LDAP, αποκαλύπτοντας πληροφορίες για **Enterprise Certificate Authorities (CAs)** και τις ρυθμίσεις τους. Αυτό είναι προσβάσιμο από οποιονδήποτε χρήστη πιστοποιημένο στο domain χωρίς ειδικά προνόμια. Εργαλεία όπως **[Certify](https://github.com/GhostPack/Certify)** και **[Certipy](https://github.com/ly4k/Certipy)** χρησιμοποιούνται για την απογραφή και την αξιολόγηση ευπαθειών σε περιβάλλοντα AD CS.

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

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
