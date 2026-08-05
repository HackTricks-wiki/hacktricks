# Εγγραφή συσκευών σε άλλους οργανισμούς

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή

Όπως [**αναφέρθηκε προηγουμένως**](#what-is-mdm-mobile-device-management)**,** για να επιχειρήσετε να εγγράψετε μια συσκευή σε έναν οργανισμό **χρειάζεται μόνο ένας Serial Number που ανήκει σε αυτόν τον οργανισμό**. Μόλις εγγραφεί η συσκευή, αρκετοί οργανισμοί εγκαθιστούν ευαίσθητα δεδομένα στη νέα συσκευή: certificates, applications, κωδικούς WiFi, διαμορφώσεις VPN [και ούτω καθεξής](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Επομένως, αυτό θα μπορούσε να αποτελέσει επικίνδυνο entrypoint για attackers, εάν η διαδικασία εγγραφής δεν προστατεύεται σωστά.

**Τα παρακάτω αποτελούν σύνοψη της έρευνας [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Δείτε την για περισσότερες τεχνικές λεπτομέρειες!**<sup>[1]</sup>

## Επισκόπηση της ανάλυσης των DEP και MDM Binary

Η έρευνα εξετάζει τα binaries που σχετίζονται με τα Device Enrollment Program (DEP) και Mobile Device Management (MDM) στο macOS. Τα βασικά στοιχεία περιλαμβάνουν:

- **`mdmclient`**: Επικοινωνεί με MDM servers και ενεργοποιεί DEP check-ins σε εκδόσεις macOS πριν από την 10.13.4.
- **`profiles`**: Διαχειρίζεται Configuration Profiles και ενεργοποιεί DEP check-ins σε εκδόσεις macOS 10.13.4 και νεότερες.
- **`cloudconfigurationd`**: Διαχειρίζεται τις επικοινωνίες με το DEP API και ανακτά Device Enrollment profiles.

Τα DEP check-ins χρησιμοποιούν τις functions `CPFetchActivationRecord` και `CPGetActivationRecord` από το private Configuration Profiles framework για την ανάκτηση του Activation Record, με την `CPFetchActivationRecord` να συντονίζεται με το `cloudconfigurationd` μέσω XPC.<sup>[1]</sup>

## Reverse Engineering του Tesla Protocol και του Absinthe Scheme

Το DEP check-in περιλαμβάνει την αποστολή, από το `cloudconfigurationd` προς το _iprofiles.apple.com/macProfile_, ενός κρυπτογραφημένου και υπογεγραμμένου JSON payload. Το payload περιλαμβάνει το Serial Number της συσκευής και την ενέργεια "RequestProfileConfiguration". Το encryption scheme που χρησιμοποιείται αναφέρεται εσωτερικά ως "Absinthe". Η αποκάλυψη του τρόπου λειτουργίας αυτού του scheme είναι περίπλοκη και περιλαμβάνει πολλά βήματα, γεγονός που οδήγησε στη διερεύνηση εναλλακτικών μεθόδων για την εισαγωγή αυθαίρετων Serial Numbers στο αίτημα Activation Record.<sup>[1]</sup>

## Proxying DEP Requests

Οι προσπάθειες interception και τροποποίησης DEP requests προς το _iprofiles.apple.com_ με εργαλεία όπως το Charles Proxy παρεμποδίστηκαν από την κρυπτογράφηση του payload και τα μέτρα ασφαλείας SSL/TLS. Ωστόσο, η ενεργοποίηση της configuration `MCCloudConfigAcceptAnyHTTPSCertificate` επιτρέπει την παράκαμψη της επικύρωσης του server certificate, αν και η κρυπτογραφημένη φύση του payload εξακολουθεί να εμποδίζει την τροποποίηση του Serial Number χωρίς το decryption key.<sup>[1]</sup>

## Instrumenting System Binaries που αλληλεπιδρούν με το DEP

Το instrumenting system binaries όπως το `cloudconfigurationd` απαιτεί την απενεργοποίηση του System Integrity Protection (SIP) στο macOS. Με απενεργοποιημένο το SIP, εργαλεία όπως το LLDB μπορούν να χρησιμοποιηθούν για attach σε system processes και για πιθανή τροποποίηση του Serial Number που χρησιμοποιείται στις αλληλεπιδράσεις με το DEP API. Αυτή η μέθοδος είναι προτιμότερη, καθώς αποφεύγει την πολυπλοκότητα των entitlements και του code signing.

**Exploiting Binary Instrumentation:**
Η τροποποίηση του DEP request payload πριν από το JSON serialization στο `cloudconfigurationd` αποδείχθηκε αποτελεσματική. Η διαδικασία περιλάμβανε:

1. Attach του LLDB στο `cloudconfigurationd`.
2. Εντοπισμό του σημείου όπου ανακτάται το system Serial Number.
3. Injection ενός αυθαίρετου Serial Number στη memory, πριν από την κρυπτογράφηση και την αποστολή του payload.

Αυτή η μέθοδος επέτρεψε την ανάκτηση πλήρων DEP profiles για αυθαίρετα Serial Numbers, επιδεικνύοντας μια πιθανή ευπάθεια.<sup>[1]</sup>

### Αυτοματοποίηση του Instrumentation με Python

Η διαδικασία exploitation αυτοματοποιήθηκε με τη χρήση Python και του LLDB API, καθιστώντας εφικτό το programmatic injection αυθαίρετων Serial Numbers και την ανάκτηση των αντίστοιχων DEP profiles.<sup>[1]</sup>

### Πιθανές επιπτώσεις των ευπαθειών DEP και MDM

Η έρευνα ανέδειξε σημαντικές ανησυχίες ασφαλείας:

1. **Information Disclosure**: Με την παροχή ενός DEP-registered Serial Number, μπορούν να ανακτηθούν ευαίσθητες πληροφορίες οργανισμών που περιέχονται στο DEP profile.<sup>[1]</sup>

## Αναφορές

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
