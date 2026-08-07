# Εγγραφή συσκευών σε άλλους οργανισμούς

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή

Όπως [**αναφέρθηκε προηγουμένως**](#what-is-mdm-mobile-device-management)**,** προκειμένου να επιχειρηθεί η εγγραφή μιας συσκευής σε έναν οργανισμό **απαιτείται μόνο ένας Serial Number που ανήκει σε αυτόν τον οργανισμό**. Μόλις εγγραφεί η συσκευή, αρκετοί οργανισμοί θα εγκαταστήσουν ευαίσθητα δεδομένα στη νέα συσκευή: certificates, applications, κωδικούς WiFi, VPN configurations [και ούτω καθεξής](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Επομένως, αυτό θα μπορούσε να αποτελέσει επικίνδυνο entrypoint για attackers, εάν η διαδικασία εγγραφής δεν προστατεύεται σωστά.

**Ακολουθεί μια περίληψη της έρευνας [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Ανατρέξτε σε αυτή για περισσότερες τεχνικές λεπτομέρειες!**<sup>[[1]](#references)</sup>

## Επισκόπηση της Binary Analysis των DEP και MDM

Η έρευνα εξετάζει τα binaries που σχετίζονται με το Device Enrollment Program (DEP) και το Mobile Device Management (MDM) στο macOS. Τα βασικά components περιλαμβάνουν:

- **`mdmclient`**: Επικοινωνεί με MDM servers και ενεργοποιεί DEP check-ins σε εκδόσεις macOS πριν από την 10.13.4.
- **`profiles`**: Διαχειρίζεται Configuration Profiles και ενεργοποιεί DEP check-ins σε εκδόσεις macOS 10.13.4 και νεότερες.
- **`cloudconfigurationd`**: Διαχειρίζεται τις επικοινωνίες με το DEP API και ανακτά Device Enrollment profiles.

Τα DEP check-ins χρησιμοποιούν τις functions `CPFetchActivationRecord` και `CPGetActivationRecord` από το private Configuration Profiles framework για την ανάκτηση του Activation Record, με την `CPFetchActivationRecord` να συντονίζει την επικοινωνία με το `cloudconfigurationd` μέσω XPC.<sup>[[1]](#references)</sup>

## Reverse Engineering του Tesla Protocol και του Absinthe Scheme

Στο DEP check-in, το `cloudconfigurationd` στέλνει ένα encrypted, signed JSON payload στο _iprofiles.apple.com/macProfile_. Το payload περιλαμβάνει το serial number της συσκευής και την action "RequestProfileConfiguration". Το encryption scheme που χρησιμοποιείται αναφέρεται εσωτερικά ως "Absinthe". Η αποκάλυψη του τρόπου λειτουργίας αυτού του scheme είναι σύνθετη και περιλαμβάνει πολλά βήματα, γεγονός που οδήγησε στην εξερεύνηση εναλλακτικών μεθόδων για την εισαγωγή αυθαίρετων serial numbers στο αίτημα Activation Record.<sup>[[1]](#references)</sup>

## Proxying DEP Requests

Οι προσπάθειες interception και τροποποίησης των DEP requests προς το _iprofiles.apple.com_ με εργαλεία όπως το Charles Proxy παρεμποδίστηκαν από το payload encryption και τα μέτρα ασφάλειας SSL/TLS. Ωστόσο, η ενεργοποίηση του configuration `MCCloudConfigAcceptAnyHTTPSCertificate` επιτρέπει την παράκαμψη της επικύρωσης του server certificate, αν και η encrypted φύση του payload εξακολουθεί να αποτρέπει την τροποποίηση του serial number χωρίς το decryption key.<sup>[[1]](#references)</sup>

## Instrumenting System Binaries που αλληλεπιδρούν με το DEP

Το Instrumenting system binaries όπως το `cloudconfigurationd` απαιτεί την απενεργοποίηση του System Integrity Protection (SIP) στο macOS. Με απενεργοποιημένο το SIP, εργαλεία όπως το LLDB μπορούν να χρησιμοποιηθούν για attach σε system processes και πιθανή τροποποίηση του serial number που χρησιμοποιείται στις αλληλεπιδράσεις με το DEP API. Αυτή η μέθοδος είναι προτιμητέα, καθώς αποφεύγει τις πολυπλοκότητες των entitlements και του code signing.<sup>[[1]](#references)</sup>

**Exploiting Binary Instrumentation:**
Η τροποποίηση του DEP request payload πριν από το JSON serialization στο `cloudconfigurationd` αποδείχθηκε αποτελεσματική. Η διαδικασία περιλάμβανε:

1. Attach με LLDB στο `cloudconfigurationd`.
2. Εντοπισμό του σημείου όπου γίνεται η ανάκτηση του system serial number.
3. Inject ενός αυθαίρετου serial number στη μνήμη, πριν από το encryption και την αποστολή του payload.

Αυτή η μέθοδος επέτρεψε την ανάκτηση πλήρων DEP profiles για αυθαίρετα serial numbers, αποδεικνύοντας μια πιθανή ευπάθεια.<sup>[[1]](#references)</sup>

### Αυτοματοποίηση του Instrumentation με Python

Η διαδικασία exploitation αυτοματοποιήθηκε με τη χρήση Python και του LLDB API, καθιστώντας εφικτό το programmatic inject αυθαίρετων serial numbers και την ανάκτηση των αντίστοιχων DEP profiles.<sup>[[1]](#references)</sup>

### Πιθανές επιπτώσεις των ευπαθειών DEP και MDM

Η έρευνα ανέδειξε σημαντικές ανησυχίες ασφάλειας:

1. **Αποκάλυψη πληροφοριών**: Με την παροχή ενός DEP-registered serial number, μπορούν να ανακτηθούν ευαίσθητες πληροφορίες του οργανισμού που περιέχονται στο DEP profile.<sup>[[1]](#references)</sup>

## Αναφορές

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
