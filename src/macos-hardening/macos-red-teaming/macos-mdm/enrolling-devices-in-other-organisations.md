# Εγγραφή συσκευών σε άλλους οργανισμούς

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή

Όπως [**έχει σχολιαστεί προηγουμένως**](#what-is-mdm-mobile-device-management)**,** προκειμένου να επιχειρηθεί η εγγραφή μιας συσκευής σε έναν οργανισμό **χρειάζεται μόνο ένας Serial Number που ανήκει σε αυτόν τον οργανισμό**. Μόλις εγγραφεί η συσκευή, αρκετοί οργανισμοί εγκαθιστούν ευαίσθητα δεδομένα στη νέα συσκευή: certificates, applications, κωδικούς WiFi, VPN configurations [και ούτω καθεξής](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Επομένως, αυτό θα μπορούσε να αποτελέσει ένα επικίνδυνο entrypoint για attackers, εάν η διαδικασία εγγραφής δεν προστατεύεται σωστά.

**Το παρακάτω αποτελεί σύνοψη της έρευνας [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Ανατρέξτε σε αυτή για περισσότερες τεχνικές λεπτομέρειες!**<sup>[[1]](#references)</sup>

## Επισκόπηση της ανάλυσης των DEP και MDM Binaries

Η έρευνα εξετάζει διεξοδικά τα binaries που σχετίζονται με τα Device Enrollment Program (DEP) και Mobile Device Management (MDM) στο macOS. Τα βασικά components περιλαμβάνουν:

- **`mdmclient`**: Επικοινωνεί με MDM servers και ενεργοποιεί DEP check-ins σε εκδόσεις macOS πριν από την 10.13.4.
- **`profiles`**: Διαχειρίζεται Configuration Profiles και ενεργοποιεί DEP check-ins σε εκδόσεις macOS 10.13.4 και νεότερες.
- **`cloudconfigurationd`**: Διαχειρίζεται τις επικοινωνίες με το DEP API και ανακτά Device Enrollment profiles.

Τα DEP check-ins χρησιμοποιούν τις functions `CPFetchActivationRecord` και `CPGetActivationRecord` από το private Configuration Profiles framework για την ανάκτηση του Activation Record, με την `CPFetchActivationRecord` να συντονίζει την επικοινωνία με το `cloudconfigurationd` μέσω XPC.<sup>[[1]](#references)</sup>

## Reverse Engineering του Tesla Protocol και του Absinthe Scheme

Το DEP check-in περιλαμβάνει την αποστολή από το `cloudconfigurationd` ενός encrypted, signed JSON payload στο _iprofiles.apple.com/macProfile_. Το payload περιλαμβάνει το serial number της συσκευής και την ενέργεια "RequestProfileConfiguration". Το encryption scheme που χρησιμοποιείται αναφέρεται εσωτερικά ως "Absinthe". Η αποκρυπτογράφηση αυτού του scheme είναι σύνθετη και περιλαμβάνει πολλά βήματα, γεγονός που οδήγησε στη διερεύνηση εναλλακτικών μεθόδων για την εισαγωγή αυθαίρετων serial numbers στο Activation Record request.<sup>[[1]](#references)</sup>

## Proxying DEP Requests

Οι προσπάθειες intercept και τροποποίησης των DEP requests προς το _iprofiles.apple.com_ με τη χρήση tools όπως το Charles Proxy παρεμποδίστηκαν από την κρυπτογράφηση του payload και τα μέτρα ασφαλείας SSL/TLS. Ωστόσο, η ενεργοποίηση του `MCCloudConfigAcceptAnyHTTPSCertificate` configuration επιτρέπει την παράκαμψη του server certificate validation, αν και η encrypted φύση του payload εξακολουθεί να εμποδίζει την τροποποίηση του serial number χωρίς το decryption key.<sup>[[1]](#references)</sup>

## Instrumenting System Binaries που αλληλεπιδρούν με το DEP

Το Instrumenting system binaries όπως το `cloudconfigurationd` απαιτεί την απενεργοποίηση του System Integrity Protection (SIP) στο macOS. Με απενεργοποιημένο το SIP, tools όπως το LLDB μπορούν να χρησιμοποιηθούν για attach σε system processes και για πιθανή τροποποίηση του serial number που χρησιμοποιείται στις DEP API interactions. Αυτή η μέθοδος είναι προτιμότερη, καθώς αποφεύγει τις πολυπλοκότητες των entitlements και του code signing.

**Exploiting Binary Instrumentation:**
Η τροποποίηση του DEP request payload πριν από το JSON serialization στο `cloudconfigurationd` αποδείχθηκε αποτελεσματική. Η διαδικασία περιλάμβανε:

1. Attach στο `cloudconfigurationd` με το LLDB.
2. Εντοπισμό του σημείου όπου ανακτάται το system serial number.
3. Injection ενός αυθαίρετου serial number στη μνήμη, πριν από την κρυπτογράφηση και την αποστολή του payload.

Αυτή η μέθοδος επέτρεψε την ανάκτηση πλήρων DEP profiles για αυθαίρετα serial numbers, αποδεικνύοντας μια πιθανή ευπάθεια.<sup>[[1]](#references)</sup>

### Αυτοματοποίηση του Instrumentation με Python

Η διαδικασία exploitation αυτοματοποιήθηκε με τη χρήση Python και του LLDB API, καθιστώντας εφικτό το programmatic injection αυθαίρετων serial numbers και την ανάκτηση των αντίστοιχων DEP profiles.<sup>[[1]](#references)</sup>

### Πιθανές επιπτώσεις των DEP και MDM Vulnerabilities

Η έρευνα ανέδειξε σημαντικές ανησυχίες ασφαλείας:

1. **Information Disclosure**: Με την παροχή ενός DEP-registered serial number, μπορούν να ανακτηθούν ευαίσθητες πληροφορίες του οργανισμού που περιέχονται στο DEP profile.<sup>[[1]](#references)</sup>

## Αναφορές

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
