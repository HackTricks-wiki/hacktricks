# Εγγραφή συσκευών σε άλλους οργανισμούς

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή

Το Apple Automated Device Enrollment (πρώην DEP) ξεκινά με την αναγνώριση μιας συσκευής που έχει αντιστοιχιστεί σε έναν οργανισμό. Η έρευνα του 2018 που συνοψίζεται εδώ έδειξε ότι η γνώση ενός αντιστοιχισμένου serial number αρκούσε για την ανάκτηση των enrollment profiles ορισμένων οργανισμών, επειδή αυτοί οι οργανισμοί δεν απαιτούσαν επαρκή πρόσθετη authentication. Πρόκειται για ιστορικό εύρημα και όχι για ισχυρισμό ότι κάθε σύγχρονο MDM μπορεί να συνδεθεί μόνο με ένα serial number. Τα profiles μπορεί να περιέχουν certificates, applications, Wi-Fi secrets, VPN settings και άλλες ευαίσθητες ρυθμίσεις.<sup>[[1]](#references)[[2]](#references)</sup>

**Ακολουθεί μια σύνοψη της έρευνας [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Ελέγξτε την για περισσότερες τεχνικές λεπτομέρειες!**<sup>[[1]](#references)</sup>

## Επισκόπηση της Ανάλυσης Binaries των DEP και MDM

Η έρευνα ανέλυσε binaries που σχετίζονται με το DEP και το MDM στις εκδόσεις macOS που ήταν διαθέσιμες εκείνη την περίοδο. Τα ονόματα και οι αρμοδιότητες των components μπορεί να αλλάζουν μεταξύ των releases:

- **`mdmclient`**: Επικοινωνεί με MDM servers και ενεργοποιεί DEP check-ins σε εκδόσεις macOS πριν από την 10.13.4.
- **`profiles`**: Διαχειρίζεται Configuration Profiles και ενεργοποιεί DEP check-ins σε εκδόσεις macOS 10.13.4 και μεταγενέστερες.
- **`cloudconfigurationd`**: Διαχειρίζεται τις DEP API communications και ανακτά τα Device Enrollment profiles.

Τα DEP check-ins χρησιμοποιούν τις functions `CPFetchActivationRecord` και `CPGetActivationRecord` από το private Configuration Profiles framework για την ανάκτηση του Activation Record, με την `CPFetchActivationRecord` να συντονίζεται με το `cloudconfigurationd` μέσω XPC.<sup>[[1]](#references)</sup>

## Reverse Engineering του Tesla Protocol και του Absinthe Scheme

Το DEP check-in περιλαμβάνει την αποστολή, από το `cloudconfigurationd`, ενός encrypted, signed JSON payload στο _iprofiles.apple.com/macProfile_. Το payload περιλαμβάνει το serial number της συσκευής και την action "RequestProfileConfiguration". Το encryption scheme που χρησιμοποιείται αναφέρεται εσωτερικά ως "Absinthe". Η αποκάλυψη του τρόπου λειτουργίας αυτού του scheme είναι σύνθετη και περιλαμβάνει πολλά βήματα, γεγονός που οδήγησε στη διερεύνηση εναλλακτικών μεθόδων για την εισαγωγή arbitrary serial numbers στο Activation Record request.<sup>[[1]](#references)</sup>

## Proxying DEP Requests

Οι προσπάθειες intercept και τροποποίησης DEP requests προς το _iprofiles.apple.com_ με εργαλεία όπως το Charles Proxy παρεμποδίστηκαν από την payload encryption και τα μέτρα ασφάλειας SSL/TLS. Ωστόσο, η ενεργοποίηση της ρύθμισης `MCCloudConfigAcceptAnyHTTPSCertificate` επιτρέπει την παράκαμψη του server certificate validation, αν και η encrypted φύση του payload εξακολουθεί να αποτρέπει την τροποποίηση του serial number χωρίς το decryption key.<sup>[[1]](#references)</sup>

## Instrumenting System Binaries που αλληλεπιδρούν με το DEP

Το Instrumenting system binaries όπως το `cloudconfigurationd` απαιτεί την απενεργοποίηση του System Integrity Protection (SIP) στο macOS. Με απενεργοποιημένο το SIP, εργαλεία όπως το LLDB μπορούν να χρησιμοποιηθούν για attach σε system processes και πιθανή τροποποίηση του serial number που χρησιμοποιείται στις DEP API interactions. Αυτή η μέθοδος είναι προτιμότερη, καθώς αποφεύγει τις πολυπλοκότητες των entitlements και του code signing.<sup>[[1]](#references)</sup>

**Exploiting Binary Instrumentation:**
Η τροποποίηση του DEP request payload πριν από το JSON serialization στο `cloudconfigurationd` αποδείχθηκε αποτελεσματική. Η διαδικασία περιλάμβανε:

1. Attach με LLDB στο `cloudconfigurationd`.
2. Εντοπισμό του σημείου όπου ανακτάται το system serial number.
3. Εισαγωγή ενός arbitrary serial number στη memory πριν από την κρυπτογράφηση και την αποστολή του payload.

Αυτή η μέθοδος επέτρεψε στους researchers να ανακτήσουν DEP profiles για παρεχόμενα, αντιστοιχισμένα serial numbers. Δεν έκανε ένα μη αντιστοιχισμένο arbitrary serial number έγκυρο.<sup>[[1]](#references)</sup>

### Αυτοματοποίηση του Instrumentation με Python

Η διαδικασία exploitation αυτοματοποιήθηκε με Python και το LLDB API, καθιστώντας εφικτή την προγραμματιστική εισαγωγή arbitrary serial numbers και την ανάκτηση των αντίστοιχων DEP profiles.<sup>[[1]](#references)</sup>

### Πιθανές επιπτώσεις των DEP και MDM Vulnerabilities

Η έρευνα ανέδειξε σημαντικές ανησυχίες ασφάλειας:

1. **Information Disclosure**: Με την παροχή ενός DEP-registered serial number, μπορούν να ανακτηθούν ευαίσθητες πληροφορίες οργανισμών που περιέχονται στο DEP profile.<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Ασφάλεια του Device Enrollment Program](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
{{#include ../../../banners/hacktricks-training.md}}
