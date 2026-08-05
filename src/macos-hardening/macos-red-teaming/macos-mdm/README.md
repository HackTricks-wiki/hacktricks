# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Για να μάθετε περισσότερα σχετικά με τα macOS MDMs, δείτε:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Βασικά

### **Επισκόπηση του MDM (Mobile Device Management)**

Το [Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) χρησιμοποιείται για την επίβλεψη διαφόρων συσκευών τελικών χρηστών, όπως smartphones, laptops και tablets. Ειδικά για τις πλατφόρμες της Apple (iOS, macOS, tvOS), περιλαμβάνει ένα σύνολο εξειδικευμένων δυνατοτήτων, APIs και πρακτικών. Η λειτουργία του MDM βασίζεται σε έναν συμβατό MDM server, ο οποίος είναι είτε εμπορικά διαθέσιμος είτε open-source, και πρέπει να υποστηρίζει το [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Τα βασικά σημεία περιλαμβάνουν:

- Κεντρικός έλεγχος των συσκευών.
- Εξάρτηση από έναν MDM server που συμμορφώνεται με το MDM protocol.
- Δυνατότητα του MDM server να αποστέλλει διάφορες εντολές στις συσκευές, όπως απομακρυσμένη διαγραφή δεδομένων ή εγκατάσταση ρυθμίσεων.

### **Βασικά στοιχεία του DEP (Device Enrollment Program)**

Το [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) που παρέχεται από την Apple απλοποιεί την ενσωμάτωση του Mobile Device Management (MDM), διευκολύνοντας τη ρύθμιση zero-touch για συσκευές iOS, macOS και tvOS. Το DEP αυτοματοποιεί τη διαδικασία enrollment, επιτρέποντας στις συσκευές να είναι λειτουργικές αμέσως μετά την έξοδό τους από το κουτί, με ελάχιστη παρέμβαση από τον χρήστη ή τον administrator. Οι βασικές πτυχές περιλαμβάνουν:

- Επιτρέπει στις συσκευές να εγγράφονται αυτόνομα σε έναν προκαθορισμένο MDM server κατά την αρχική ενεργοποίηση.
- Είναι κυρίως χρήσιμο για ολοκαίνουργιες συσκευές, αλλά εφαρμόζεται επίσης σε συσκευές που υποβάλλονται σε reconfiguration.
- Διευκολύνει μια απλή διαδικασία εγκατάστασης, ώστε οι συσκευές να είναι γρήγορα έτοιμες για οργανωτική χρήση.

### **Ζητήματα ασφαλείας**

Είναι σημαντικό να σημειωθεί ότι η ευκολία enrollment που παρέχει το DEP, παρότι είναι χρήσιμη, μπορεί επίσης να δημιουργήσει κινδύνους ασφαλείας. Εάν δεν εφαρμοστούν επαρκή μέτρα προστασίας για το MDM enrollment, οι attackers ενδέχεται να εκμεταλλευτούν αυτή την απλοποιημένη διαδικασία για να εγγράψουν τη συσκευή τους στον MDM server του οργανισμού, παρουσιάζοντάς την ως εταιρική συσκευή.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Security Alert**: Το απλοποιημένο DEP enrollment θα μπορούσε να επιτρέψει μη εξουσιοδοτημένη εγγραφή συσκευής στον MDM server του οργανισμού, εάν δεν υπάρχουν τα κατάλληλα safeguards.

### Βασικά στοιχεία: Τι είναι το SCEP (Simple Certificate Enrolment Protocol);

- Ένα σχετικά παλιό protocol, το οποίο δημιουργήθηκε πριν το TLS και το HTTPS διαδοθούν ευρέως.
- Παρέχει στους clients έναν τυποποιημένο τρόπο αποστολής ενός **Certificate Signing Request** (CSR), με σκοπό να τους χορηγηθεί ένα certificate. Ο client ζητά από τον server να του δώσει ένα signed certificate.

### Τι είναι τα Configuration Profiles (γνωστά και ως mobileconfigs);

- Ο επίσημος τρόπος της Apple για **ρύθμιση/επιβολή system configuration.**
- File format που μπορεί να περιέχει πολλαπλά payloads.
- Βασίζεται σε property lists (του τύπου XML).
- «Μπορούν να υπογραφούν και να κρυπτογραφηθούν για την επικύρωση της προέλευσής τους, τη διασφάλιση της ακεραιότητάς τους και την προστασία του περιεχομένου τους.» Basics — Page 70, iOS Security Guide, January 2018.

## Protocols

### MDM

- Συνδυασμός APNs (**Apple server**s) + RESTful API (**MDM** **vendor** servers)
- Η **Communication** πραγματοποιείται μεταξύ μιας **device** και ενός server που συνδέεται με ένα **device** **management** **product**
- Οι **Commands** αποστέλλονται από το MDM στη συσκευή σε **plist-encoded dictionaries**
- Όλα μέσω **HTTPS**. Οι MDM servers μπορούν να χρησιμοποιούν (και συνήθως χρησιμοποιούν) pinning.
- Η Apple χορηγεί στον MDM vendor ένα **APNs certificate** για authentication

### DEP

- **3 APIs**: 1 για resellers, 1 για MDM vendors, 1 για device identity (undocumented):
- Το λεγόμενο [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Χρησιμοποιείται από τους MDM servers για τη συσχέτιση DEP profiles με συγκεκριμένες συσκευές.
- Το [DEP API used by Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) για enrollment συσκευών, έλεγχο της κατάστασης enrollment και έλεγχο της κατάστασης συναλλαγών.
- Το undocumented private DEP API. Χρησιμοποιείται από τις Apple Devices για να ζητούν το DEP profile τους. Στο macOS, το binary `cloudconfigurationd` είναι υπεύθυνο για την επικοινωνία μέσω αυτού του API.
- Πιο σύγχρονο και βασισμένο σε **JSON** (αντί για **plist**)
- Η Apple χορηγεί ένα **OAuth token** στον MDM vendor

**DEP "cloud service" API**

- RESTful
- συγχρονίζει device records από την Apple στον MDM server
- συγχρονίζει τα “DEP profiles” από τον MDM server στην Apple (και στη συνέχεια παραδίδονται από την Apple στη συσκευή)
- Ένα DEP “profile” περιέχει:
- URL του MDM vendor server
- Πρόσθετα trusted certificates για το server URL (optional pinning)
- Επιπλέον ρυθμίσεις (π.χ. ποιες οθόνες θα παραλείπονται στο Setup Assistant)

## Serial Number

Οι συσκευές Apple που κατασκευάστηκαν μετά το 2010 έχουν γενικά **12-character alphanumeric** serial numbers, όπου τα **τρία πρώτα ψηφία αντιπροσωπεύουν την τοποθεσία κατασκευής**, τα **επόμενα δύο** υποδεικνύουν το **έτος** και την **εβδομάδα** κατασκευής, τα **επόμενα τρία** ψηφία παρέχουν ένα **unique** **identifier** και τα **τελευταία τέσσερα** ψηφία αντιπροσωπεύουν τον **model number**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Βήματα για enrollment και management

1. Δημιουργία device record (Reseller, Apple): Δημιουργείται το record για τη νέα συσκευή
2. Αντιστοίχιση device record (Customer): Η συσκευή αντιστοιχίζεται σε έναν MDM server
3. Συγχρονισμός device record (MDM vendor): Το MDM συγχρονίζει τα device records και προωθεί τα DEP profiles στην Apple
4. DEP check-in (Device): Η συσκευή λαμβάνει το DEP profile της
5. Ανάκτηση profile (Device)
6. Εγκατάσταση profile (Device) a. incl. MDM, SCEP και root CA payloads
7. Έκδοση MDM command (Device)

![Serial Number - Βήματα για enrollment και management: 7. Έκδοση MDM command (Device)](<../../../images/image (694).png>)

Το αρχείο `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` εξάγει functions που μπορούν να θεωρηθούν **high-level "steps"** της διαδικασίας enrollment.

### Step 4: DEP check-in - Λήψη του Activation Record

Αυτό το μέρος της διαδικασίας πραγματοποιείται όταν ένας **user εκκινεί έναν Mac για πρώτη φορά** (ή μετά από πλήρες wipe)

![Βήματα για enrollment και management - Step 4: DEP check-in - Λήψη του Activation Record: Αυτό το μέρος της διαδικασίας πραγματοποιείται όταν ένας user εκκινεί έναν Mac για πρώτη φορά (ή μετά από πλήρες...](<../../../images/image (1044).png>)

ή κατά την εκτέλεση του `sudo profiles show -type enrollment`

- Καθορισμός του **αν η συσκευή έχει ενεργοποιημένο το DEP**
- Το Activation Record είναι η εσωτερική ονομασία για το DEP “profile”
- Ξεκινά μόλις η συσκευή συνδεθεί στο Internet
- Υλοποιείται από το **`CPFetchActivationRecord`**
- Υλοποιείται από το **`cloudconfigurationd`** μέσω XPC. Το **"Setup Assistant**" (όταν η συσκευή εκκινείται για πρώτη φορά) ή η εντολή **`profiles`** θα **επικοινωνήσει με αυτό το daemon** για να ανακτήσει το activation record.
- LaunchDaemon (εκτελείται πάντα ως root)

Ακολουθούνται μερικά βήματα για τη λήψη του Activation Record, τα οποία εκτελούνται από το **`MCTeslaConfigurationFetcher`**. Αυτή η διαδικασία χρησιμοποιεί μια encryption που ονομάζεται **Absinthe**<sup>[[1]](#references)</sup>

1. Ανάκτηση **certificate**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Αρχικοποίηση** του state από το certificate (**`NACInit`**)
1. Χρησιμοποιεί διάφορα device-specific data (π.χ. **Serial Number μέσω `IOKit`**)
3. Ανάκτηση **session key**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Establish του session (**`NACKeyEstablishment`**)
5. Πραγματοποίηση του request
1. POST στο [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) με αποστολή των data `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Το JSON payload είναι encrypted με χρήση Absinthe (**`NACSign`**)
3. Όλα τα requests πραγματοποιούνται μέσω HTTPs, με χρήση των ενσωματωμένων root certificates

![Βήματα για enrollment και management - Step 4: DEP check-in - Λήψη του Activation Record: 3. Όλα τα requests πραγματοποιούνται μέσω HTTPs, με χρήση των ενσωματωμένων root certificates](<../../../images/image (566) (1).png>)

Η response είναι ένα JSON dictionary με ορισμένα σημαντικά data, όπως:

- **url**: URL του MDM vendor host για το activation profile
- **anchor-certs**: Array από DER certificates που χρησιμοποιούνται ως trusted anchors

### **Step 5: Ανάκτηση Profile**

![Step 4: DEP check-in - Λήψη του Activation Record - Step 5: Ανάκτηση Profile: Step 5: Ανάκτηση Profile](<../../../images/image (444).png>)

- Το request αποστέλλεται στο **url που παρέχεται στο DEP profile**.
- Τα **Anchor certificates** χρησιμοποιούνται για την **αξιολόγηση του trust**, εάν παρέχονται.
- Υπενθύμιση: το property **anchor_certs** του DEP profile
- Το **Request είναι ένα απλό .plist** με device identification
- Παραδείγματα: **UDID, OS version**.
- CMS-signed, DER-encoded
- Υπογράφεται με χρήση του **device identity certificate (from APNS)**
- Το **Certificate chain** περιλαμβάνει expired **Apple iPhone Device CA**

![Step 4: DEP check-in - Λήψη του Activation Record - Step 5: Ανάκτηση Profile: Υπογράφεται με χρήση του device identity certificate (from APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Step 6: Εγκατάσταση Profile

- Μετά την ανάκτησή του, το **profile αποθηκεύεται στο system**
- Αυτό το βήμα ξεκινά αυτόματα (εάν βρίσκεται στο **setup assistant**)
- Υλοποιείται από το **`CPInstallActivationProfile`**
- Υλοποιείται από το mdmclient μέσω XPC
- LaunchDaemon (ως root) ή LaunchAgent (ως user), ανάλογα με το context
- Τα Configuration profiles διαθέτουν πολλαπλά payloads προς εγκατάσταση
- Το framework διαθέτει plugin-based architecture για την εγκατάσταση profiles
- Κάθε payload type συσχετίζεται με ένα plugin
- Μπορεί να είναι XPC (στο framework) ή classic Cocoa (στο ManagedClient.app)
- Παράδειγμα:
- Τα Certificate Payloads χρησιμοποιούν το CertificateService.xpc

Συνήθως, το **activation profile** που παρέχεται από έναν MDM vendor θα **περιλαμβάνει τα ακόλουθα payloads**:

- `com.apple.mdm`: για **enroll** της συσκευής στο MDM
- `com.apple.security.scep`: για την ασφαλή παροχή ενός **client certificate** στη συσκευή.
- `com.apple.security.pem`: για την **εγκατάσταση trusted CA certificates** στο System Keychain της συσκευής.
- Η εγκατάσταση του MDM payload ισοδυναμεί με το **MDM check-in στη documentation**
- Το Payload **περιέχει βασικά properties**:
- - MDM Check-In URL (**`CheckInURL`**)
- MDM Command Polling URL (**`ServerURL`**) + APNs topic για την ενεργοποίησή του
- Για την εγκατάσταση του MDM payload, το request αποστέλλεται στο **`CheckInURL`**
- Υλοποιείται στο **`mdmclient`**
- Το MDM payload μπορεί να εξαρτάται από άλλα payloads
- Επιτρέπει **requests να γίνονται pinned σε συγκεκριμένα certificates**:
- Property: **`CheckInURLPinningCertificateUUIDs`**
- Property: **`ServerURLPinningCertificateUUIDs`**
- Παραδίδεται μέσω PEM payload
- Επιτρέπει στη συσκευή να συσχετίζεται με ένα identity certificate:
- Property: IdentityCertificateUUID
- Παραδίδεται μέσω SCEP payload

### **Step 7: Ακρόαση για MDM commands**

- Μετά την ολοκλήρωση του MDM check-in, ο vendor μπορεί να **εκδώσει push notifications με χρήση των APNs**
- Κατά τη λήψη τους, γίνεται handling από το **`mdmclient`**
- Για το polling των MDM commands, αποστέλλεται request στο ServerURL
- Χρησιμοποιεί το MDM payload που εγκαταστάθηκε προηγουμένως:
- **`ServerURLPinningCertificateUUIDs`** για pinning του request
- **`IdentityCertificateUUID`** για TLS client certificate

## Attacks

### Enrollment Devices σε Άλλους Οργανισμούς

Όπως αναφέρθηκε προηγουμένως, για να προσπαθήσει κάποιος να κάνει enrollment μιας συσκευής σε έναν οργανισμό **χρειάζεται μόνο ένα Serial Number που ανήκει σε αυτόν τον Οργανισμό**. Μόλις γίνει enrollment της συσκευής, αρκετοί οργανισμοί θα εγκαταστήσουν sensitive data στη νέα συσκευή: certificates, applications, WiFi passwords, VPN configurations [και ούτω καθεξής](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Επομένως, αυτό θα μπορούσε να αποτελέσει επικίνδυνο entrypoint για attackers, εάν η διαδικασία enrollment δεν προστατεύεται σωστά:<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## References

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
