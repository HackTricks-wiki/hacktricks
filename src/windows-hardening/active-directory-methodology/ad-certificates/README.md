# Πιστοποιητικά AD

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή

### Συστατικά ενός Πιστοποιητικού

- Το **Subject** του πιστοποιητικού υποδεικνύει τον ιδιοκτήτη του.
- Ένα **Public Key** συζεύγνυται με ένα ιδιωτικά κρατούμενο κλειδί για να συνδέσει το πιστοποιητικό με τον νόμιμο κάτοχό του.
- Η **Validity Period**, οριζόμενη από τις ημερομηνίες **NotBefore** και **NotAfter**, προσδιορίζει τη χρονική διάρκεια ισχύος του πιστοποιητικού.
- Ένας μοναδικός **Serial Number**, που παρέχεται από το Certificate Authority (CA), ταυτοποιεί κάθε πιστοποιητικό.
- Ο **Issuer** αναφέρεται στο CA που εξέδωσε το πιστοποιητικό.
- **SubjectAlternativeName** επιτρέπει επιπλέον ονόματα για το subject, βελτιώνοντας την ευελιξία στην ταυτοποίηση.
- Τα **Basic Constraints** προσδιορίζουν αν το πιστοποιητικό προορίζεται για CA ή για τελικό ον και ορίζουν περιορισμούς χρήσης.
- Τα **Extended Key Usages (EKUs)** καθορίζουν τους συγκεκριμένους σκοπούς του πιστοποιητικού, όπως code signing ή email encryption, μέσω Object Identifiers (OIDs).
- Ο **Signature Algorithm** καθορίζει τη μέθοδο υπογραφής του πιστοποιητικού.
- Η **Signature**, δημιουργημένη με το ιδιωτικό κλειδί του issuer, εγγυάται την αυθεντικότητα του πιστοποιητικού.

### Ειδικές Παρατηρήσεις

- Τα **Subject Alternative Names (SANs)** επεκτείνουν την εφαρμοσιμότητα ενός πιστοποιητικού σε πολλαπλές ταυτότητες, κρίσιμο για servers με πολλαπλούς domains. Ασφαλείς διαδικασίες έκδοσης είναι ζωτικής σημασίας για να αποφευχθεί ο κίνδυνος impersonation από επιτιθέμενους που χειραγωγούν την προδιαγραφή SAN.

### Certificate Authorities (CAs) σε Active Directory (AD)

Το AD CS αναγνωρίζει CA certificates σε ένα AD forest μέσω καθορισμένων containers, το καθένα εξυπηρετεί διαφορετικούς ρόλους:

- Το container **Certification Authorities** φυλάσσει trusted root CA certificates.
- Το container **Enrolment Services** περιγράφει Enterprise CAs και τα certificate templates τους.
- Το αντικείμενο **NTAuthCertificates** περιλαμβάνει CA certificates εξουσιοδοτημένα για AD authentication.
- Το container **AIA (Authority Information Access)** διευκολύνει την επαλήθευση αλυσίδας πιστοποιητικών με intermediate και cross CA certificates.

### Απόκτηση Πιστοποιητικού: Client Certificate Request Flow

1. Η διαδικασία αίτησης ξεκινά με τους clients να εντοπίζουν ένα Enterprise CA.
2. Δημιουργείται ένα CSR που περιέχει ένα public key και άλλα στοιχεία, αφού προηγουμένως παραχθεί ένα ζεύγος public-private κλειδιών.
3. Το CA αξιολογεί το CSR σε σχέση με διαθέσιμα certificate templates, εκδίδοντας το πιστοποιητικό βάσει των δικαιωμάτων του template.
4. Μετά την έγκριση, το CA υπογράφει το πιστοποιητικό με το ιδιωτικό του κλειδί και το επιστρέφει στον client.

### Certificate Templates

Ορισμένα εντός του AD, αυτά τα templates περιγράφουν ρυθμίσεις και δικαιώματα για την έκδοση πιστοποιητικών, συμπεριλαμβανομένων των επιτρεπόμενων EKUs και δικαιωμάτων enrollment ή τροποποίησης, κρίσιμα για τη διαχείριση πρόσβασης στις υπηρεσίες πιστοποιητικών.

## Certificate Enrollment

Η διαδικασία enrollment για πιστοποιητικά ξεκινά από έναν administrator που **δημιουργεί ένα certificate template**, το οποίο στη συνέχεια **δημοσιεύεται** από ένα Enterprise Certificate Authority (CA). Αυτό καθιστά το template διαθέσιμο για client enrollment, ένα βήμα που επιτυγχάνεται με την προσθήκη του ονόματος του template στο πεδίο `certificatetemplates` ενός Active Directory αντικειμένου.

Για να μπορεί ένας client να αιτηθεί πιστοποιητικό, πρέπει να του χορηγηθούν **enrollment rights**. Αυτά τα δικαιώματα ορίζονται από security descriptors στο certificate template και στο ίδιο το Enterprise CA. Τα permissions πρέπει να δοθούν και στις δύο τοποθεσίες για να είναι επιτυχής η αίτηση.

### Template Enrollment Rights

Αυτά τα δικαιώματα καθορίζονται μέσω Access Control Entries (ACEs), περιγράφοντας δικαιώματα όπως:

- **Certificate-Enrollment** και **Certificate-AutoEnrollment** rights, κάθε ένα συνδεδεμένο με συγκεκριμένα GUIDs.
- **ExtendedRights**, επιτρέποντας όλα τα extended permissions.
- **FullControl/GenericAll**, παρέχοντας πλήρη έλεγχο επί του template.

### Enterprise CA Enrollment Rights

Τα δικαιώματα του CA περιγράφονται στον security descriptor του, προσβάσιμο μέσω της κονσόλας διαχείρισης Certificate Authority. Ορισμένες ρυθμίσεις επιτρέπουν ακόμη και σε χρήστες με χαμηλά προνόμια απομακρυσμένη πρόσβαση, κάτι που μπορεί να αποτελέσει ζήτημα ασφάλειας.

### Πρόσθετοι Έλεγχοι Έκδοσης

Μπορεί να εφαρμόζονται ορισμένοι έλεγχοι, όπως:

- **Manager Approval**: Τοποθετεί τις αιτήσεις σε pending κατάσταση μέχρι να εγκριθούν από certificate manager.
- **Enrolment Agents and Authorized Signatures**: Προσδιορίζουν τον αριθμό απαιτούμενων signatures σε ένα CSR και τα απαραίτητα Application Policy OIDs.

### Μέθοδοι Αίτησης Πιστοποιητικών

Πιστοποιητικά μπορούν να ζητηθούν μέσω:

1. του **Windows Client Certificate Enrollment Protocol** (MS-WCCE), χρησιμοποιώντας DCOM interfaces.
2. του **ICertPassage Remote Protocol** (MS-ICPR), μέσω named pipes ή TCP/IP.
3. του **certificate enrollment web interface**, με εγκατεστημένο το Certificate Authority Web Enrollment role.
4. της **Certificate Enrollment Service** (CES), σε συνδυασμό με την υπηρεσία Certificate Enrollment Policy (CEP).
5. της **Network Device Enrollment Service** (NDES) για network devices, χρησιμοποιώντας το Simple Certificate Enrollment Protocol (SCEP).

Χρήστες Windows μπορούν επίσης να αιτηθούν πιστοποιητικά μέσω GUI (`certmgr.msc` ή `certlm.msc`) ή εργαλείων γραμμής εντολών (`certreq.exe` ή την εντολή PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Αυθεντικοποίηση με Πιστοποιητικά

Active Directory (AD) υποστηρίζει επαλήθευση μέσω πιστοποιητικών, κυρίως χρησιμοποιώντας τα πρωτόκολλα **Kerberos** και **Secure Channel (Schannel)**.

### Διαδικασία Αυθεντικοποίησης Kerberos

Στη διαδικασία αυθεντικοποίησης Kerberos, το αίτημα ενός χρήστη για Ticket Granting Ticket (TGT) υπογράφεται με το **ιδιωτικό κλειδί** του πιστοποιητικού του χρήστη. Αυτό το αίτημα υπόκειται σε πολλαπλούς ελέγχους από τον domain controller, συμπεριλαμβανομένης της **ισχύος**, της **διαδρομής** και της **κατάστασης ανάκλησης** του πιστοποιητικού. Οι επαληθεύσεις περιλαμβάνουν επίσης τον έλεγχο ότι το πιστοποιητικό προέρχεται από αξιόπιστη πηγή και την επιβεβαίωση της παρουσίας του εκδότη στο **NTAUTH certificate store**. Οι επιτυχείς επαληθεύσεις οδηγούν στην έκδοση ενός TGT. Το **`NTAuthCertificates`** αντικείμενο στο AD, που βρίσκεται στο:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
είναι κεντρικό για την εγκαθίδρυση εμπιστοσύνης για τον έλεγχο ταυτότητας με πιστοποιητικά.

### Secure Channel (Schannel) Authentication

Το Schannel διευκολύνει ασφαλείς συνδέσεις TLS/SSL, όπου κατά τη διάρκεια του handshake ο client παρουσιάζει ένα πιστοποιητικό που, εάν επικυρωθεί επιτυχώς, εξουσιοδοτεί την πρόσβαση. Η αντιστοίχιση ενός πιστοποιητικού σε λογαριασμό AD μπορεί να περιλαμβάνει τη λειτουργία του Kerberos **S4U2Self** ή το **Subject Alternative Name (SAN)** του πιστοποιητικού, μεταξύ άλλων μεθόδων.

### AD Certificate Services Enumeration

Οι υπηρεσίες πιστοποιητικών του AD μπορούν να ανιχνευθούν μέσω ερωτημάτων LDAP, αποκαλύπτοντας πληροφορίες για τις **Enterprise Certificate Authorities (CAs)** και τις διαμορφώσεις τους. Αυτό είναι προσβάσιμο από οποιονδήποτε χρήστη αυθεντικοποιημένο στο domain χωρίς ειδικά προνόμια. Εργαλεία όπως **[Certify](https://github.com/GhostPack/Certify)** και **[Certipy](https://github.com/ly4k/Certipy)** χρησιμοποιούνται για την ανίχνευση και την αξιολόγηση ευπαθειών σε περιβάλλοντα AD CS.

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
