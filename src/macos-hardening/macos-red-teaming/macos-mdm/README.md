# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Για να μάθετε σχετικά με τα macOS MDM, δείτε:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Βασικά

### **Επισκόπηση MDM (Mobile Device Management)**

Το [Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) χρησιμοποιείται για την επίβλεψη διάφορων συσκευών τελικών χρηστών, όπως smartphones, laptops και tablets. Ειδικά για τις πλατφόρμες της Apple (iOS, macOS, tvOS), περιλαμβάνει ένα σύνολο εξειδικευμένων δυνατοτήτων, APIs και πρακτικών. Η λειτουργία του MDM βασίζεται σε έναν συμβατό MDM server, ο οποίος είναι είτε εμπορικά διαθέσιμος είτε open-source και πρέπει να υποστηρίζει το [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Βασικά σημεία:

- Κεντρικοποιημένος έλεγχος των συσκευών.
- Εξάρτηση από έναν MDM server που συμμορφώνεται με το MDM protocol.
- Δυνατότητα του MDM server να αποστέλλει διάφορες εντολές στις συσκευές, όπως απομακρυσμένη διαγραφή δεδομένων ή εγκατάσταση ρυθμίσεων.

### **Βασικά στοιχεία του DEP (Device Enrollment Program)**

Το [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) της Apple απλοποιεί την ενσωμάτωση του Mobile Device Management (MDM), επιτρέποντας zero-touch configuration για συσκευές iOS, macOS και tvOS. Το DEP αυτοματοποιεί τη διαδικασία enrollment, επιτρέποντας στις συσκευές να είναι λειτουργικές αμέσως μετά την αποσυσκευασία τους, με ελάχιστη παρέμβαση από τον χρήστη ή τον administrator. Βασικές πτυχές:

- Επιτρέπει στις συσκευές να εγγράφονται αυτόνομα σε έναν προκαθορισμένο MDM server κατά την αρχική ενεργοποίηση.
- Είναι κυρίως χρήσιμο για ολοκαίνουργιες συσκευές, αλλά εφαρμόζεται επίσης σε συσκευές που υποβάλλονται σε reconfiguration.
- Διευκολύνει μια απλή εγκατάσταση, ώστε οι συσκευές να είναι γρήγορα έτοιμες για οργανωτική χρήση.

### **Ζητήματα ασφάλειας**

Είναι σημαντικό να σημειωθεί ότι η ευκολία enrollment που παρέχει το DEP, παρότι είναι επωφελής, μπορεί επίσης να δημιουργήσει security risks. Αν δεν επιβάλλονται επαρκή protective measures για το MDM enrollment, οι attackers ενδέχεται να εκμεταλλευτούν αυτήν την απλοποιημένη διαδικασία για να εγγράψουν τη συσκευή τους στον MDM server του οργανισμού, παρουσιάζοντάς την ως εταιρική συσκευή.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Security Alert**: Το απλοποιημένο DEP enrollment θα μπορούσε να επιτρέψει μη εξουσιοδοτημένη εγγραφή συσκευής στον MDM server του οργανισμού, αν δεν έχουν εφαρμοστεί οι κατάλληλες safeguards.

### Βασικά στοιχεία: Τι είναι το SCEP (Simple Certificate Enrolment Protocol);

- Ένα σχετικά παλιό protocol, το οποίο δημιουργήθηκε πριν το TLS και το HTTPS διαδοθούν ευρέως.
- Παρέχει στους clients έναν τυποποιημένο τρόπο αποστολής ενός **Certificate Signing Request** (CSR), με σκοπό τη χορήγηση certificate. Ο client ζητά από τον server να του δώσει ένα signed certificate.

### Τι είναι τα Configuration Profiles (γνωστά και ως mobileconfigs);

- Ο επίσημος τρόπος της Apple για **ρύθμιση/επιβολή system configuration.**
- File format που μπορεί να περιέχει πολλαπλά payloads.
- Βασίζονται σε property lists (του τύπου XML).
- «can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.» Basics — Page 70, iOS Security Guide, January 2018.

## Protocols

### MDM

- Συνδυασμός APNs (**Apple server**s) + RESTful API (**MDM** **vendor** servers)
- Η **Communication** πραγματοποιείται μεταξύ μιας **device** και ενός server που σχετίζεται με ένα **device** **management** **product**
- Οι **Commands** παραδίδονται από το MDM στη συσκευή σε **plist-encoded dictionaries**
- Όλα μέσω **HTTPS**. Οι MDM servers μπορούν να χρησιμοποιούν (και συνήθως χρησιμοποιούν) pinning.
- Η Apple χορηγεί στον MDM vendor ένα **APNs certificate** για authentication

### DEP

- **3 APIs**: 1 για resellers, 1 για MDM vendors, 1 για device identity (undocumented):
- Το λεγόμενο [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Χρησιμοποιείται από τους MDM servers για τη συσχέτιση DEP profiles με συγκεκριμένες συσκευές.
- Το [DEP API used by Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) για enrollment συσκευών, έλεγχο της κατάστασης enrollment και έλεγχο της κατάστασης συναλλαγών.
- Το undocumented private DEP API. Χρησιμοποιείται από τις Apple Devices για να ζητούν το DEP profile τους. Στο macOS, το binary `cloudconfigurationd` είναι υπεύθυνο για την επικοινωνία μέσω αυτού του API.
- Πιο σύγχρονο και βασισμένο σε **JSON** (αντί για plist)
- Η Apple χορηγεί ένα **OAuth token** στον MDM vendor

**DEP "cloud service" API**

- RESTful
- συγχρονίζει τα device records από την Apple στον MDM server
- συγχρονίζει τα “DEP profiles” στην Apple από τον MDM server (τα οποία παραδίδονται αργότερα από την Apple στη συσκευή)
- Ένα DEP “profile” περιέχει:
- URL του MDM vendor server
- Πρόσθετα trusted certificates για το server URL (προαιρετικό pinning)
- Επιπλέον settings (π.χ. ποιες οθόνες θα παραλειφθούν στο Setup Assistant)

## Serial Number

Οι συσκευές Apple που κατασκευάστηκαν μετά το 2010 διαθέτουν γενικά **12-character alphanumeric** serial numbers, όπου τα **πρώτα τρία ψηφία αντιπροσωπεύουν την τοποθεσία κατασκευής**, τα επόμενα **δύο** υποδεικνύουν το **έτος** και την **εβδομάδα** κατασκευής, τα επόμενα **τρία** ψηφία παρέχουν ένα **μοναδικό** **identifier** και τα **τελευταία** **τέσσερα** ψηφία αντιπροσωπεύουν τον **model number**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Βήματα για enrollment και management

1. Δημιουργία device record (Reseller, Apple): Δημιουργείται το record για τη νέα συσκευή
2. Αντιστοίχιση device record (Customer): Η συσκευή αντιστοιχίζεται σε έναν MDM server
3. Συγχρονισμός device record (MDM vendor): Ο MDM συγχρονίζει τα device records και προωθεί τα DEP profiles στην Apple
4. DEP check-in (Device): Η συσκευή λαμβάνει το DEP profile της
5. Ανάκτηση profile (Device)
6. Εγκατάσταση profile (Device) a. συμπεριλαμβανομένων των MDM, SCEP και root CA payloads
7. Έκδοση MDM command (Device)

![Serial Number - Βήματα για enrollment και management: 7. Έκδοση MDM command (Device)](<../../../images/image (694).png>)

Το αρχείο `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` εξάγει functions που μπορούν να θεωρηθούν **high-level "steps"** της διαδικασίας enrollment.

### Βήμα 4: DEP check-in - Λήψη του Activation Record

Αυτό το μέρος της διαδικασίας πραγματοποιείται όταν ένας **user εκκινεί ένα Mac για πρώτη φορά** (ή μετά από πλήρες wipe)

![Βήματα για enrollment και management - Βήμα 4: DEP check-in - Λήψη του Activation Record: Αυτό το μέρος της διαδικασίας πραγματοποιείται όταν ένας user εκκινεί ένα Mac για πρώτη φορά (ή μετά από πλήρες...](<../../../images/image (1044).png>)

ή κατά την εκτέλεση της εντολής `sudo profiles show -type enrollment`

- Καθορισμός του **αν η συσκευή έχει ενεργοποιημένο το DEP**
- Το Activation Record είναι η εσωτερική ονομασία για το DEP “profile”
- Ξεκινά μόλις η συσκευή συνδεθεί στο Internet
- Κατευθύνεται από το **`CPFetchActivationRecord`**
- Υλοποιείται από το **`cloudconfigurationd`** μέσω XPC. Το **"Setup Assistant**" (όταν η συσκευή εκκινείται για πρώτη φορά) ή η εντολή **`profiles`** θα **επικοινωνήσει με αυτό το daemon** για να ανακτήσει το activation record.
- LaunchDaemon (εκτελείται πάντα ως root)

Για τη λήψη του Activation Record εκτελούνται μερικά βήματα από το **`MCTeslaConfigurationFetcher`**. Αυτή η διαδικασία χρησιμοποιεί encryption που ονομάζεται **Absinthe**<sup>[[1]](#references)</sup>

1. Ανάκτηση **certificate**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Initialize** state από το certificate (**`NACInit`**)
1. Χρησιμοποιεί διάφορα device-specific data (δηλαδή **Serial Number μέσω `IOKit`**)
3. Ανάκτηση **session key**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Establishment του session (**`NACKeyEstablishment`**)
5. Υποβολή του request
1. POST στο [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) με αποστολή των δεδομένων `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Το JSON payload είναι encrypted με χρήση του Absinthe (**`NACSign`**)
3. Όλα τα requests πραγματοποιούνται μέσω HTTPs, με χρήση των built-in root certificates

![Βήματα για enrollment και management - Βήμα 4: DEP check-in - Λήψη του Activation Record: 3. Όλα τα requests πραγματοποιούνται μέσω HTTPs, με χρήση των built-in root certificates](<../../../images/image (566) (1).png>)

Η response είναι ένα JSON dictionary με ορισμένα σημαντικά δεδομένα, όπως:

- **url**: URL του MDM vendor host για το activation profile
- **anchor-certs**: Array από DER certificates που χρησιμοποιούνται ως trusted anchors

### **Βήμα 5: Ανάκτηση Profile**

![Βήμα 4: DEP check-in - Λήψη του Activation Record - Βήμα 5: Ανάκτηση Profile: Βήμα 5: Ανάκτηση Profile](<../../../images/image (444).png>)

- Το request αποστέλλεται στο **url που παρέχεται στο DEP profile**.
- Τα **Anchor certificates** χρησιμοποιούνται για **evaluate trust**, εφόσον παρέχονται.
- Υπενθύμιση: η ιδιότητα **anchor_certs** του DEP profile
- Το **Request είναι ένα απλό .plist** με device identification
- Παραδείγματα: **UDID, OS version**.
- CMS-signed, DER-encoded
- Signed με χρήση του **device identity certificate (από το APNS)**
- Το **Certificate chain** περιλαμβάνει το expired **Apple iPhone Device CA**

![Βήμα 4: DEP check-in - Λήψη του Activation Record - Βήμα 5: Ανάκτηση Profile: Signed με χρήση του device identity certificate (από το APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Βήμα 6: Εγκατάσταση Profile

- Μόλις ανακτηθεί, το **profile αποθηκεύεται στο system**
- Αυτό το βήμα ξεκινά αυτόματα (αν βρίσκεται στο **setup assistant**)
- Κατευθύνεται από το **`CPInstallActivationProfile`**
- Υλοποιείται από το mdmclient μέσω XPC
- LaunchDaemon (ως root) ή LaunchAgent (ως user), ανάλογα με το context
- Τα Configuration profiles διαθέτουν πολλαπλά payloads προς εγκατάσταση
- Το framework έχει plugin-based architecture για την εγκατάσταση profiles
- Κάθε payload type συσχετίζεται με ένα plugin
- Μπορεί να είναι XPC (στο framework) ή classic Cocoa (στο ManagedClient.app)
- Παράδειγμα:
- Τα Certificate Payloads χρησιμοποιούν το CertificateService.xpc

Συνήθως, το **activation profile** που παρέχεται από έναν MDM vendor θα **περιλαμβάνει τα ακόλουθα payloads**:

- `com.apple.mdm`: για **enroll** της συσκευής στο MDM
- `com.apple.security.scep`: για την ασφαλή παροχή ενός **client certificate** στη συσκευή.
- `com.apple.security.pem`: για την **εγκατάσταση trusted CA certificates** στο System Keychain της συσκευής.
- Η εγκατάσταση του MDM payload ισοδυναμεί με **MDM check-in σύμφωνα με την τεκμηρίωση**
- Το payload **περιέχει βασικές ιδιότητες**:
- - MDM Check-In URL (**`CheckInURL`**)
- MDM Command Polling URL (**`ServerURL`**) + APNs topic για την ενεργοποίησή του
- Για την εγκατάσταση του MDM payload, το request αποστέλλεται στο **`CheckInURL`**
- Υλοποιείται στο **`mdmclient`**
- Το MDM payload μπορεί να εξαρτάται από άλλα payloads
- Επιτρέπει **requests με pinning σε συγκεκριμένα certificates**:
- Ιδιότητα: **`CheckInURLPinningCertificateUUIDs`**
- Ιδιότητα: **`ServerURLPinningCertificateUUIDs`**
- Παραδίδεται μέσω PEM payload
- Επιτρέπει στη συσκευή να συσχετιστεί με ένα identity certificate:
- Ιδιότητα: IdentityCertificateUUID
- Παραδίδεται μέσω SCEP payload

### **Βήμα 7: Ακρόαση για MDM commands**

- Μετά την ολοκλήρωση του MDM check-in, ο vendor μπορεί να **εκδίδει push notifications μέσω APNs**
- Κατά τη λήψη τους, ο χειρισμός γίνεται από το **`mdmclient`**
- Για το polling των MDM commands, το request αποστέλλεται στο ServerURL
- Χρησιμοποιεί το MDM payload που εγκαταστάθηκε προηγουμένως:
- **`ServerURLPinningCertificateUUIDs`** για pinning του request
- **`IdentityCertificateUUID`** για TLS client certificate

## Attacks

### Enrolling Devices in Other Organisations

Όπως αναφέρθηκε προηγουμένως, για να επιχειρηθεί enrollment μιας συσκευής σε έναν οργανισμό **απαιτείται μόνο ένα Serial Number που ανήκει σε αυτόν τον Οργανισμό**. Μόλις ολοκληρωθεί το enrollment της συσκευής, αρκετοί οργανισμοί θα εγκαταστήσουν sensitive data στη νέα συσκευή: certificates, applications, WiFi passwords, VPN configurations [και ούτω καθεξής](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Επομένως, αυτό θα μπορούσε να αποτελέσει επικίνδυνο entrypoint για attackers, αν η διαδικασία enrollment δεν προστατεύεται σωστά:<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## References

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
