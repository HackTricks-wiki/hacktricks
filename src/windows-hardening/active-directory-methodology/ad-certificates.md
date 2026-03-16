# Πιστοποιητικά AD

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή

### Συστατικά ενός Πιστοποιητικού

- Το **Subject** του πιστοποιητικού υποδεικνύει τον κάτοχό του.
- Ένα **Public Key** συνδυάζεται με ένα ιδιωτικό κλειδί για να συνδέσει το πιστοποιητικό με τον νόμιμο κάτοχό του.
- Η **Validity Period**, καθοριζόμενη από τις ημερομηνίες **NotBefore** και **NotAfter**, ορίζει τη χρονική διάρκεια ισχύος του πιστοποιητικού.
- Ένας μοναδικός **Serial Number**, που παρέχεται από την Certificate Authority (CA), αναγνωρίζει κάθε πιστοποιητικό.
- Ο **Issuer** αναφέρεται στην CA που εξέδωσε το πιστοποιητικό.
- Το **SubjectAlternativeName** επιτρέπει επιπλέον ονόματα για το **Subject**, αυξάνοντας την ευελιξία στην ταυτοποίηση.
- Οι **Basic Constraints** καθορίζουν αν το πιστοποιητικό είναι για μια CA ή για ένα end entity και ορίζουν περιορισμούς χρήσης.
- Τα **Extended Key Usages (EKUs)** καθορίζουν τους συγκεκριμένους σκοπούς του πιστοποιητικού, όπως code signing ή email encryption, μέσω Object Identifiers (OIDs).
- Ο **Signature Algorithm** προσδιορίζει τη μέθοδο υπογραφής του πιστοποιητικού.
- Η **Signature**, δημιουργημένη με το ιδιωτικό κλειδί του issuer, εγγυάται την αυθεντικότητα του πιστοποιητικού.

### Ειδικές Σκέψεις

- Οι **Subject Alternative Names (SANs)** επεκτείνουν την εφαρμογή ενός πιστοποιητικού σε πολλαπλές ταυτότητες, κρίσιμο για servers με πολλαπλά domains. Απαιτούνται ασφαλείς διαδικασίες έκδοσης για να αποφευχθεί ο κίνδυνος προσποίησης από επιτιθέμενους που χειραγωγούν το πεδίο SAN.

### Certificate Authorities (CAs) στο Active Directory (AD)

Το AD CS αναγνωρίζει πιστοποιητικά CA σε ένα AD forest μέσω καθορισμένων containers, το καθένα με ξεχωριστό ρόλο:

- Το container **Certification Authorities** φιλοξενεί αξιόπιστα root CA certificates.
- Το container **Enrolment Services** περιγράφει τις Enterprise CAs και τα certificate templates τους.
- Το αντικείμενο **NTAuthCertificates** περιλαμβάνει CA certificates εξουσιοδοτημένα για AD authentication.
- Το container **AIA (Authority Information Access)** διευκολύνει την επικύρωση της αλυσίδας πιστοποιητικών με intermediate και cross CA certificates.

### Απόκτηση Πιστοποιητικού: Ροή Αίτησης Πιστοποιητικού Πελάτη

1. Η διαδικασία αίτησης ξεκινά με τους clients να εντοπίζουν μια Enterprise CA.
2. Δημιουργείται ένα CSR που περιέχει ένα public key και άλλα στοιχεία, μετά τη δημιουργία ενός ζεύγους δημόσιου-ιδιωτικού κλειδιού.
3. Η CA αξιολογεί το CSR σε σχέση με διαθέσιμα certificate templates και εκδίδει το πιστοποιητικό βάσει των δικαιωμάτων του template.
4. Μετά την έγκριση, η CA υπογράφει το πιστοποιητικό με το ιδιωτικό της κλειδί και το επιστρέφει στον client.

### Certificate Templates

Ορισμένα στο AD, αυτά τα templates καθορίζουν τις ρυθμίσεις και τα δικαιώματα για την έκδοση πιστοποιητικών, συμπεριλαμβανομένων των επιτρεπόμενων EKUs και των δικαιωμάτων enrollment ή modification, κρίσιμα για τη διαχείριση πρόσβασης στις υπηρεσίες πιστοποιητικών.

**Η έκδοση σχήματος του template έχει σημασία.** Τα παλαιά **v1** templates (για παράδειγμα, το ενσωματωμένο **WebServer** template) στερούνται πολλών σύγχρονων μηχανισμών επιβολής. Η έρευνα **ESC15/EKUwu** έδειξε ότι σε **v1 templates**, ο αιτών μπορεί να ενσωματώσει **Application Policies/EKUs** στο CSR που προτιμώνται σε σχέση με τα EKUs που έχουν ρυθμιστεί στο template, επιτρέποντας την έκδοση client-auth, enrollment agent ή code-signing πιστοποιητικών με μόνο δικαιώματα enrollment. Προτιμήστε **v2/v3 templates**, αφαιρέστε ή υπερισχύστε τις προεπιλογές v1 και περιορίστε αυστηρά τα EKUs στον προοριζόμενο σκοπό.

## Εγγραφή Πιστοποιητικού

Η διαδικασία εγγραφής για πιστοποιητικά ξεκινά από έναν administrator που **δημιουργεί ένα certificate template**, το οποίο στη συνέχεια **δημοσιεύεται** από μια Enterprise Certificate Authority (CA). Αυτό καθιστά το template διαθέσιμο για enrollment πελατών, βήμα που πραγματοποιείται προσθέτοντας το όνομα του template στο πεδίο `certificatetemplates` ενός Active Directory αντικειμένου.

Για να ζητήσει ένας client ένα πιστοποιητικό, πρέπει να χορηγηθούν **enrollment rights**. Αυτά τα δικαιώματα ορίζονται από security descriptors στο certificate template και στην ίδια την Enterprise CA. Τα permissions πρέπει να χορηγηθούν και στις δύο τοποθεσίες για να είναι επιτυχής το αίτημα.

### Δικαιώματα Enrollment στο Template

Τα δικαιώματα αυτά καθορίζονται μέσω Access Control Entries (ACEs), αναφέροντας δικαιώματα όπως:

- Τα δικαιώματα **Certificate-Enrollment** και **Certificate-AutoEnrollment**, το καθένα σχετιζόμενο με συγκεκριμένα GUIDs.
- **ExtendedRights**, επιτρέποντας όλα τα extended permissions.
- **FullControl/GenericAll**, παρέχοντας πλήρη έλεγχο επί του template.

### Δικαιώματα Enrollment στην Enterprise CA

Τα δικαιώματα της CA καθορίζονται στον security descriptor της, προσβάσιμο μέσω του Certificate Authority management console. Ορισμένες ρυθμίσεις επιτρέπουν ακόμη και σε χρήστες με χαμηλά προνόμια remote access, κάτι που μπορεί να αποτελεί ζήτημα ασφάλειας.

### Επιπλέον Έλεγχοι Έκδοσης

Μπορεί να εφαρμόζονται συγκεκριμένοι έλεγχοι, όπως:

- **Manager Approval**: Τοποθετεί αιτήματα σε κατάσταση pending μέχρι να εγκριθούν από certificate manager.
- **Enrolment Agents and Authorized Signatures**: Καθορίζουν τον αριθμό απαιτούμενων υπογραφών σε ένα CSR και τα απαραίτητα Application Policy OIDs.

### Μέθοδοι Αίτησης Πιστοποιητικών

Μπορούν να ζητηθούν πιστοποιητικά μέσω:

1. Το **Windows Client Certificate Enrollment Protocol** (MS-WCCE), χρησιμοποιώντας DCOM interfaces.
2. Το **ICertPassage Remote Protocol** (MS-ICPR), μέσω named pipes ή TCP/IP.
3. Η **certificate enrollment web interface**, με εγκατεστημένο τον ρόλο Certificate Authority Web Enrollment.
4. Η **Certificate Enrollment Service** (CES), σε συνδυασμό με την Certificate Enrollment Policy (CEP) υπηρεσία.
5. Η **Network Device Enrollment Service** (NDES) για network devices, χρησιμοποιώντας το Simple Certificate Enrollment Protocol (SCEP).

Οι χρήστες Windows μπορούν επίσης να ζητήσουν πιστοποιητικά μέσω του GUI (`certmgr.msc` ή `certlm.msc`) ή μέσω εργαλείων γραμμής εντολών (`certreq.exe` ή της PowerShell εντολής `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Πιστοποίηση με Πιστοποιητικό

Το Active Directory (AD) υποστηρίζει πιστοποίηση με πιστοποιητικά, χρησιμοποιώντας κυρίως τα πρωτόκολλα **Kerberos** και **Secure Channel (Schannel)**.

### Διαδικασία Πιστοποίησης Kerberos

Στη διαδικασία πιστοποίησης Kerberos, το αίτημα ενός χρήστη για Ticket Granting Ticket (TGT) υπογράφεται με το **ιδιωτικό κλειδί** του πιστοποιητικού του χρήστη. Το αίτημα αυτό υπόκειται σε διάφορους ελέγχους από τον domain controller, συμπεριλαμβανομένης της **εγκυρότητας**, της **αλυσίδας πιστοποιητικών** και της **κατάστασης ανάκλησης** του πιστοποιητικού. Οι έλεγχοι περιλαμβάνουν επίσης την επαλήθευση ότι το πιστοποιητικό προέρχεται από αξιόπιστη πηγή και την επιβεβαίωση της παρουσίας του εκδότη στο **NTAUTH certificate store**. Οι επιτυχημένοι έλεγχοι οδηγούν στην έκδοση ενός TGT. Το αντικείμενο **`NTAuthCertificates`** στο AD, βρίσκεται στο:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
είναι κεντρικό για την εγκαθίδρυση εμπιστοσύνης για την πιστοποίηση με πιστοποιητικά.

### Πιστοποίηση Secure Channel (Schannel)

Schannel διευκολύνει ασφαλείς συνδέσεις TLS/SSL, όπου κατά τη διάρκεια ενός handshake, ο client παρουσιάζει ένα πιστοποιητικό που, αν επικυρωθεί με επιτυχία, εξουσιοδοτεί την πρόσβαση. Η αντιστοίχιση ενός πιστοποιητικού σε λογαριασμό AD μπορεί να περιλαμβάνει τη λειτουργία του Kerberos’s **S4U2Self** ή το πιστοποιητικό **Subject Alternative Name (SAN)**, μεταξύ άλλων μεθόδων.

### AD Certificate Services Enumeration

Οι υπηρεσίες πιστοποιητικών του AD μπορούν να καταγραφούν μέσω ερωτημάτων LDAP, αποκαλύπτοντας πληροφορίες για **Enterprise Certificate Authorities (CAs)** και τις διαμορφώσεις τους. Αυτό είναι προσβάσιμο από οποιονδήποτε χρήστη που έχει πιστοποιηθεί στο domain χωρίς ειδικά προνόμια. Εργαλεία όπως **[Certify](https://github.com/GhostPack/Certify)** και **[Certipy](https://github.com/ly4k/Certipy)** χρησιμοποιούνται για απογραφή και αξιολόγηση ευπαθειών σε περιβάλλοντα AD CS.

Οι εντολές για τη χρήση αυτών των εργαλείων περιλαμβάνουν:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

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
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Αναβάθμιση προνομίων* με πλαστογράφηση πιστοποιητικών λογαριασμών μηχανής κατά τη διάρκεια του PKINIT. | Το patch περιλαμβάνεται στις ενημερώσεις ασφαλείας της **10 Μαΐου 2022**. Εισήχθησαν λειτουργίες auditing και έλεγχοι ισχυρής χαρτογράφησης μέσω του **KB5014754**· τα περιβάλλοντα θα πρέπει τώρα να βρίσκονται σε *Full Enforcement* mode.  |
| 2023 | **CVE-2023-35350 / 35351** | *Εκτέλεση απομακρυσμένου κώδικα* σε AD CS Web Enrollment (certsrv) και ρόλους CES. | Τα δημόσια PoC είναι περιορισμένα, αλλά τα ευάλωτα στοιχεία του IIS συχνά εκτίθενται εσωτερικά. Patch από **Ιούλιος 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Σε **v1 templates**, ένας αιτών με δικαιώματα εγγραφής μπορεί να ενσωματώσει **Application Policies/EKUs** στο CSR που υπερισχύουν των EKU του template, παράγοντας πιστοποιητικά client-auth, enrollment agent ή code-signing. | Διορθώθηκε στις **12 Νοεμβρίου 2024**. Αντικαταστήστε ή υπερισχύστε τα v1 templates (π.χ. default WebServer), περιορίστε τα EKUs ανά πρόθεση και περιορίστε τα δικαιώματα εγγραφής. |

### Microsoft hardening timeline (KB5014754)

Η Microsoft εισήγαγε ένα rollout τριών φάσεων (Compatibility → Audit → Enforcement) για να απομακρύνει την πιστοποίηση Kerberos με πιστοποιητικά από αδύναμες έμμεσες χαρτογραφήσεις. Από τις **11 Φεβρουαρίου 2025**, οι domain controllers μεταβαίνουν αυτόματα σε **Full Enforcement** εάν η τιμή μητρώου StrongCertificateBindingEnforcement δεν έχει οριστεί. Οι διαχειριστές θα πρέπει να:

1. Εφαρμόσουν όλα τα patches σε DCs & AD CS servers (Μάιος 2022 ή μεταγενέστερα).
2. Παρακολουθούν Event ID 39/41 για αδύναμες χαρτογραφήσεις κατά τη φάση του *Audit*.
3. Επανα-εκδώσουν πιστοποιητικά client-auth με τη νέα **SID extension** ή ρυθμίσουν ισχυρές χειροκίνητες χαρτογραφήσεις πριν τον Φεβρουάριο του 2025.

---

## Ανίχνευση & Βελτιώσεις Σκληρής Ρύθμισης

* **Defender for Identity AD CS sensor (2023-2024)** εμφανίζει πλέον αξιολογήσεις κατάστασης για ESC1-ESC8/ESC11 και δημιουργεί ειδοποιήσεις σε πραγματικό χρόνο όπως *“Domain-controller certificate issuance for a non-DC”* (ESC8) και *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Βεβαιωθείτε ότι οι sensors έχουν αναπτυχθεί σε όλους τους AD CS servers για να ωφεληθείτε από αυτές τις ανιχνεύσεις.
* Απενεργοποιήστε ή περιορίστε αυστηρά την επιλογή **“Supply in the request”** σε όλα τα templates· προτιμήστε ρητά ορισμένες τιμές SAN/EKU.
* Αφαιρέστε **Any Purpose** ή **No EKU** από templates εκτός εάν είναι απολύτως απαραίτητα (αντιμετωπίζει σενάρια ESC2).
* Απαιτείστε **έγκριση διαχειριστή** ή αποκλειστικά workflows Enrollment Agent για ευαίσθητα templates (π.χ. WebServer / CodeSigning).
* Περιορίστε το web enrollment (`certsrv`) και τα endpoints CES/NDES σε αξιόπιστα δίκτυα ή πίσω από client-certificate authentication.
* Επιβάλετε κρυπτογράφηση RPC enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) για να μειώσετε το ESC11 (RPC relay). Η ρύθμιση είναι **on by default**, αλλά συχνά απενεργοποιείται για legacy clients, ανοίγοντας ξανά τον κίνδυνο relay.
* Ασφαλίστε τα **IIS-based enrollment endpoints** (CES/Certsrv): απενεργοποιήστε NTLM όπου είναι δυνατόν ή απαιτήστε HTTPS + Extended Protection για να μπλοκάρετε τα ESC8 relays.

---



## Αναφορές

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
