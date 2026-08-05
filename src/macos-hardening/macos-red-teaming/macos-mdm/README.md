# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Για να μάθετε περισσότερα σχετικά με τα macOS MDMs, δείτε:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Βασικά

### **Επισκόπηση του MDM (Mobile Device Management)**

Το [Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) χρησιμοποιείται για την εποπτεία διαφόρων συσκευών τελικών χρηστών, όπως smartphones, laptops και tablets. Ειδικά για τις πλατφόρμες της Apple (iOS, macOS, tvOS), περιλαμβάνει ένα σύνολο εξειδικευμένων δυνατοτήτων, APIs και πρακτικών. Η λειτουργία του MDM βασίζεται σε έναν συμβατό MDM server, ο οποίος είναι είτε εμπορικά διαθέσιμος είτε open-source, και πρέπει να υποστηρίζει το [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Τα βασικά σημεία περιλαμβάνουν:

- Κεντρικό έλεγχο των συσκευών.
- Εξάρτηση από έναν MDM server που συμμορφώνεται με το MDM protocol.
- Δυνατότητα του MDM server να αποστέλλει διάφορες εντολές στις συσκευές, όπως απομακρυσμένη διαγραφή δεδομένων ή εγκατάσταση ρυθμίσεων.

### **Βασικά στοιχεία του DEP (Device Enrollment Program)**

Το [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) της Apple απλοποιεί την ενσωμάτωση του Mobile Device Management (MDM), διευκολύνοντας τη ρύθμιση zero-touch για συσκευές iOS, macOS και tvOS. Το DEP αυτοματοποιεί τη διαδικασία enrollment, επιτρέποντας στις συσκευές να είναι λειτουργικές αμέσως μετά την αποσυσκευασία τους, με ελάχιστη παρέμβαση από τον χρήστη ή τον administrator. Στις βασικές δυνατότητες περιλαμβάνονται:

- Επιτρέπει στις συσκευές να εγγράφονται αυτόνομα σε έναν προκαθορισμένο MDM server κατά την αρχική ενεργοποίηση.
- Είναι κυρίως χρήσιμο για ολοκαίνουργιες συσκευές, αλλά εφαρμόζεται επίσης σε συσκευές που υποβάλλονται σε reconfiguration.
- Διευκολύνει μια απλή διαδικασία setup, ώστε οι συσκευές να είναι γρήγορα έτοιμες για χρήση από τον οργανισμό.

### **Ζητήματα ασφάλειας**

Είναι σημαντικό να σημειωθεί ότι η ευκολία enrollment που παρέχει το DEP, αν και χρήσιμη, μπορεί επίσης να δημιουργήσει security risks. Αν δεν εφαρμόζονται επαρκή μέτρα προστασίας για το MDM enrollment, οι attackers θα μπορούσαν να εκμεταλλευτούν αυτήν την απλοποιημένη διαδικασία για να εγγράψουν τη συσκευή τους στον MDM server του οργανισμού, παρουσιάζοντάς την ως εταιρική συσκευή.<sup>[2]</sup>

> [!CAUTION]
> **Security Alert**: Το απλοποιημένο DEP enrollment θα μπορούσε να επιτρέψει τη μη εξουσιοδοτημένη εγγραφή συσκευής στον MDM server του οργανισμού, αν δεν υπάρχουν κατάλληλες δικλίδες ασφαλείας.

### Βασικά στοιχεία: Τι είναι το SCEP (Simple Certificate Enrolment Protocol);

- Ένα σχετικά παλιό protocol, το οποίο δημιουργήθηκε πριν το TLS και το HTTPS διαδοθούν ευρέως.
- Παρέχει στους clients έναν τυποποιημένο τρόπο αποστολής ενός **Certificate Signing Request** (CSR), με σκοπό τη χορήγηση ενός certificate. Ο client ζητά από τον server να του δώσει ένα signed certificate.

### Τι είναι τα Configuration Profiles (γνωστά και ως mobileconfigs);

- Ο επίσημος τρόπος της Apple για **ρύθμιση/επιβολή configuration του system**.
- File format που μπορεί να περιέχει πολλαπλά payloads.
- Βασίζεται σε property lists (του τύπου XML).
- «μπορούν να υπογραφούν και να κρυπτογραφηθούν για την επικύρωση της προέλευσής τους, τη διασφάλιση της ακεραιότητάς τους και την προστασία του περιεχομένου τους». Basics — Page 70, iOS Security Guide, January 2018.

## Protocols

### MDM

- Συνδυασμός APNs (**Apple server**s) + RESTful API (**MDM** **vendor** servers)
- Η **Communication** πραγματοποιείται μεταξύ μιας **device** και ενός server που σχετίζεται με ένα **device** **management** **product**
- Οι **Commands** παραδίδονται από το MDM στη συσκευή σε **plist-encoded dictionaries**
- Όλα μέσω **HTTPS**. Οι MDM servers μπορούν να χρησιμοποιούν (και συνήθως χρησιμοποιούν) pinning.
- Η Apple παρέχει στον MDM vendor ένα **APNs certificate** για authentication

### DEP

- **3 APIs**: 1 για resellers, 1 για MDM vendors, 1 για device identity (undocumented):
- Το λεγόμενο [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Χρησιμοποιείται από τους MDM servers για τη συσχέτιση των DEP profiles με συγκεκριμένες συσκευές.
- Το [DEP API used by Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) για enrollment συσκευών, έλεγχο της κατάστασης enrollment και έλεγχο της κατάστασης συναλλαγών.
- Το undocumented private DEP API. Χρησιμοποιείται από τις Apple Devices για να ζητήσουν το DEP profile τους. Στο macOS, το binary `cloudconfigurationd` είναι υπεύθυνο για την επικοινωνία μέσω αυτού του API.
- Πιο σύγχρονο και βασισμένο σε **JSON** (σε αντίθεση με το **plist**)
- Η Apple παρέχει ένα **OAuth token** στον MDM vendor

**DEP "cloud service" API**

- RESTful
- συγχρονίζει device records από την Apple στον MDM server
- συγχρονίζει τα “DEP profiles” από τον MDM server στην Apple (και στη συνέχεια παραδίδονται από την Apple στη συσκευή)
- Ένα DEP “profile” περιέχει:
- URL του MDM vendor server
- Πρόσθετα trusted certificates για το server URL (προαιρετικό pinning)
- Επιπλέον ρυθμίσεις (π.χ. ποιες οθόνες θα παραλειφθούν στο Setup Assistant)

## Serial Number

Οι Apple devices που κατασκευάστηκαν μετά το 2010 διαθέτουν γενικά **12-character alphanumeric** serial numbers, όπου τα **πρώτα τρία ψηφία αντιπροσωπεύουν την τοποθεσία κατασκευής**, τα επόμενα **δύο** υποδεικνύουν το **έτος** και την **εβδομάδα** κατασκευής, τα επόμενα **τρία** ψηφία παρέχουν έναν **unique** **identifier** και τα **τελευταία** **τέσσερα** ψηφία αντιπροσωπεύουν τον **model number**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Βήματα για enrollment και management

1. Device record creation (Reseller, Apple): Δημιουργείται το record για τη νέα συσκευή
2. Device record assignment (Customer): Η συσκευή αντιστοιχίζεται σε έναν MDM server
3. Device record sync (MDM vendor): Ο MDM συγχρονίζει τα device records και προωθεί τα DEP profiles στην Apple
4. DEP check-in (Device): Η συσκευή λαμβάνει το DEP profile της
5. Profile retrieval (Device)
6. Profile installation (Device) a. incl. MDM, SCEP and root CA payloads
7. MDM command issuance (Device)

![Serial Number - Βήματα για enrollment και management: 7. MDM command issuance (Device)](<../../../images/image (694).png>)

Το αρχείο `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` εξάγει functions που μπορούν να θεωρηθούν **high-level "steps"** της διαδικασίας enrollment.

### Step 4: DEP check-in - Λήψη του Activation Record

Αυτό το μέρος της διαδικασίας πραγματοποιείται όταν ένας **user εκκινεί ένα Mac για πρώτη φορά** (ή μετά από πλήρες wipe)

![Βήματα για enrollment και management - Step 4: DEP check-in - Λήψη του Activation Record: Αυτό το μέρος της διαδικασίας πραγματοποιείται όταν ένας user εκκινεί ένα Mac για πρώτη φορά (ή μετά από πλήρες...](<../../../images/image (1044).png>)

ή κατά την εκτέλεση του `sudo profiles show -type enrollment`

- Καθορισμός του **αν η συσκευή είναι DEP enabled**
- Το Activation Record είναι η εσωτερική ονομασία του **DEP “profile”**
- Ξεκινά μόλις η συσκευή συνδεθεί στο Internet
- Καθοδηγείται από το **`CPFetchActivationRecord`**
- Υλοποιείται από το **`cloudconfigurationd`** μέσω XPC. Το **"Setup Assistant**" (όταν η συσκευή εκκινείται για πρώτη φορά) ή η εντολή **`profiles`** θα **επικοινωνήσει με αυτό το daemon** για να ανακτήσει το activation record.
- LaunchDaemon (εκτελείται πάντα ως root)

Ακολουθούνται μερικά βήματα για τη λήψη του Activation Record, τα οποία εκτελούνται από το **`MCTeslaConfigurationFetcher`**. Αυτή η διαδικασία χρησιμοποιεί encryption με την ονομασία **Absinthe**<sup>[1]</sup>

1. Ανάκτηση **certificate**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Αρχικοποίηση** state από το certificate (**`NACInit`**)
1. Χρησιμοποιούνται διάφορα device-specific δεδομένα (δηλαδή το **Serial Number μέσω `IOKit`**)
3. Ανάκτηση **session key**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Establish του session (**`NACKeyEstablishment`**)
5. Υποβολή του request
1. POST στο [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile), με αποστολή των δεδομένων `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Το JSON payload είναι encrypted με χρήση του Absinthe (**`NACSign`**)
3. Όλα τα requests πραγματοποιούνται μέσω HTTPs και χρησιμοποιούνται τα ενσωματωμένα root certificates

![Βήματα για enrollment και management - Step 4: DEP check-in - Λήψη του Activation Record: 3. Όλα τα requests πραγματοποιούνται μέσω HTTPs και χρησιμοποιούνται τα ενσωματωμένα root certificates](<../../../images/image (566) (1).png>)

Η απάντηση είναι ένα JSON dictionary με ορισμένα σημαντικά δεδομένα, όπως:

- **url**: URL του MDM vendor host για το activation profile
- **anchor-certs**: Array από DER certificates που χρησιμοποιούνται ως trusted anchors

### **Step 5: Profile Retrieval**

![Step 4: DEP check-in - Λήψη του Activation Record - Step 5: Profile Retrieval: Step 5: Profile Retrieval](<../../../images/image (444).png>)

- Το request αποστέλλεται στο **url που παρέχεται στο DEP profile**.
- Τα **Anchor certificates** χρησιμοποιούνται για την **αξιολόγηση της trust**, αν παρέχονται.
- Υπενθύμιση: η ιδιότητα **anchor_certs** του DEP profile
- Το **request είναι ένα απλό .plist** με device identification
- Παραδείγματα: **UDID, OS version**.
- CMS-signed, DER-encoded
- Υπογράφεται με χρήση του **device identity certificate (από το APNS)**
- Η **certificate chain** περιλαμβάνει το expired **Apple iPhone Device CA**

![Step 4: DEP check-in - Λήψη του Activation Record - Step 5: Profile Retrieval: Υπογράφεται με χρήση του device identity certificate (από το APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Step 6: Profile Installation

- Μετά την ανάκτησή του, το **profile αποθηκεύεται στο system**
- Αυτό το βήμα ξεκινά αυτόματα (αν βρίσκεται στο **setup assistant**)
- Καθοδηγείται από το **`CPInstallActivationProfile`**
- Υλοποιείται από το mdmclient μέσω XPC
- LaunchDaemon (ως root) ή LaunchAgent (ως user), ανάλογα με το context
- Τα configuration profiles διαθέτουν πολλαπλά payloads προς εγκατάσταση
- Το framework διαθέτει plugin-based architecture για την εγκατάσταση profiles
- Κάθε payload type συσχετίζεται με ένα plugin
- Μπορεί να είναι XPC (στο framework) ή classic Cocoa (στο ManagedClient.app)
- Παράδειγμα:
- Τα Certificate Payloads χρησιμοποιούν το CertificateService.xpc

Συνήθως, το **activation profile** που παρέχεται από έναν MDM vendor θα **περιλαμβάνει τα ακόλουθα payloads**:

- `com.apple.mdm`: για το **enroll** της συσκευής στο MDM
- `com.apple.security.scep`: για την ασφαλή παροχή ενός **client certificate** στη συσκευή.
- `com.apple.security.pem`: για την **εγκατάσταση trusted CA certificates** στο System Keychain της συσκευής.
- Η εγκατάσταση του MDM payload ισοδυναμεί με το **MDM check-in στο documentation**
- Το payload **περιέχει βασικές properties**:
- - MDM Check-In URL (**`CheckInURL`**)
- MDM Command Polling URL (**`ServerURL`**) + APNs topic για την ενεργοποίησή του
- Για την εγκατάσταση του MDM payload, αποστέλλεται request στο **`CheckInURL`**
- Υλοποιείται στο **`mdmclient`**
- Το MDM payload μπορεί να εξαρτάται από άλλα payloads
- Επιτρέπει **requests με pinning σε συγκεκριμένα certificates**:
- Property: **`CheckInURLPinningCertificateUUIDs`**
- Property: **`ServerURLPinningCertificateUUIDs`**
- Παραδίδεται μέσω PEM payload
- Επιτρέπει στη συσκευή να αποκτήσει identity certificate:
- Property: IdentityCertificateUUID
- Παραδίδεται μέσω SCEP payload

### **Step 7: Ακρόαση για MDM commands**

- Μετά την ολοκλήρωση του MDM check-in, ο vendor μπορεί να **εκδίδει push notifications χρησιμοποιώντας APNs**
- Κατά τη λήψη, η διαχείριση γίνεται από το **`mdmclient`**
- Για το polling των MDM commands, αποστέλλεται request στο ServerURL
- Χρησιμοποιείται το MDM payload που εγκαταστάθηκε προηγουμένως:
- **`ServerURLPinningCertificateUUIDs`** για pinning του request
- **`IdentityCertificateUUID`** για TLS client certificate

## Attacks

### Enrollment συσκευών σε άλλους οργανισμούς

Όπως αναφέρθηκε προηγουμένως, για να προσπαθήσει κάποιος να κάνει enrollment μιας συσκευής σε έναν οργανισμό **χρειάζεται μόνο ένα Serial Number που ανήκει σε αυτόν τον Οργανισμό**. Μόλις γίνει το enrollment της συσκευής, αρκετοί οργανισμοί θα εγκαταστήσουν sensitive data στη νέα συσκευή: certificates, applications, WiFi passwords, VPN configurations [και ούτω καθεξής](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Ως εκ τούτου, αυτό θα μπορούσε να αποτελέσει ένα επικίνδυνο entrypoint για attackers, αν η διαδικασία enrollment δεν προστατεύεται σωστά:<sup>[2]</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## References

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
