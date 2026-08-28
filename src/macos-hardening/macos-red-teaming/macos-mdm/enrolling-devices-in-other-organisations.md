# Εγγραφή συσκευών σε άλλους οργανισμούς

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή

Το Apple Automated Device Enrollment (πρώην DEP) ξεκινά με την αναγνώριση μιας συσκευής που έχει αντιστοιχιστεί σε έναν οργανισμό. Η έρευνα του 2018 που συνοψίζεται εδώ έδειξε ότι η γνώση ενός αντιστοιχισμένου serial number ήταν αρκετή για την ανάκτηση των enrollment profiles ορισμένων οργανισμών, επειδή αυτοί οι οργανισμοί δεν απαιτούσαν επαρκή πρόσθετη authentication. Πρόκειται για ιστορικό εύρημα και όχι για ισχυρισμό ότι κάθε σύγχρονο MDM μπορεί να γίνει join μόνο με ένα serial number. Τα profiles ενδέχεται να περιέχουν certificates, applications, Wi-Fi secrets, VPN settings και άλλες ευαίσθητες ρυθμίσεις.<sup>[[1]](#references)[[2]](#references)</sup>

**Ακολουθεί μια σύνοψη της έρευνας [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Ελέγξτε την για περισσότερες τεχνικές λεπτομέρειες!**<sup>[[1]](#references)</sup>

## Επισκόπηση της Ανάλυσης Binary των DEP και MDM

Η έρευνα ανέλυσε binaries που σχετίζονται με το DEP και το MDM στις εκδόσεις macOS που ήταν τρέχουσες εκείνη την περίοδο. Τα ονόματα και οι αρμοδιότητες των components ενδέχεται να αλλάζουν μεταξύ releases:

- **`mdmclient`**: Επικοινωνεί με MDM servers και ενεργοποιεί DEP check-ins σε εκδόσεις macOS πριν από την 10.13.4.
- **`profiles`**: Διαχειρίζεται Configuration Profiles και ενεργοποιεί DEP check-ins σε εκδόσεις macOS 10.13.4 και μεταγενέστερες.
- **`cloudconfigurationd`**: Διαχειρίζεται τις επικοινωνίες του DEP API και ανακτά Device Enrollment profiles.

Τα DEP check-ins χρησιμοποιούν τις functions `CPFetchActivationRecord` και `CPGetActivationRecord` από το private Configuration Profiles framework για να ανακτήσουν το Activation Record, με την `CPFetchActivationRecord` να συντονίζεται με το `cloudconfigurationd` μέσω XPC.<sup>[[1]](#references)</sup>

## Reverse Engineering του Tesla Protocol και του Absinthe Scheme

Το DEP check-in περιλαμβάνει την αποστολή από το `cloudconfigurationd` ενός encrypted, signed JSON payload στο _iprofiles.apple.com/macProfile_. Το payload περιλαμβάνει το serial number της συσκευής και την action "RequestProfileConfiguration". Το encryption scheme που χρησιμοποιείται αναφέρεται εσωτερικά ως "Absinthe". Η αποκρυπτογράφηση αυτού του scheme είναι σύνθετη και περιλαμβάνει πολλά βήματα, γεγονός που οδήγησε στη διερεύνηση εναλλακτικών μεθόδων για την εισαγωγή arbitrary serial numbers στο request του Activation Record.<sup>[[1]](#references)</sup>

## Proxying DEP Requests

Οι προσπάθειες interception και τροποποίησης DEP requests προς το _iprofiles.apple.com_ με εργαλεία όπως το Charles Proxy παρεμποδίστηκαν από την encryption του payload και τα μέτρα ασφάλειας SSL/TLS. Ωστόσο, η ενεργοποίηση της ρύθμισης `MCCloudConfigAcceptAnyHTTPSCertificate` επιτρέπει την παράκαμψη του server certificate validation, αν και η encrypted φύση του payload εξακολουθεί να αποτρέπει την τροποποίηση του serial number χωρίς το decryption key.<sup>[[1]](#references)</sup>

## Instrumenting System Binaries που Αλληλεπιδρούν με το DEP

Το instrumenting system binaries όπως το `cloudconfigurationd` απαιτεί την απενεργοποίηση του System Integrity Protection (SIP) στο macOS. Με απενεργοποιημένο το SIP, εργαλεία όπως το LLDB μπορούν να χρησιμοποιηθούν για attach σε system processes και πιθανή τροποποίηση του serial number που χρησιμοποιείται στις DEP API interactions. Αυτή η μέθοδος είναι προτιμότερη, καθώς αποφεύγει τις πολυπλοκότητες των entitlements και του code signing.<sup>[[1]](#references)</sup>

**Exploiting Binary Instrumentation:**
Η τροποποίηση του DEP request payload πριν από το JSON serialization στο `cloudconfigurationd` αποδείχθηκε αποτελεσματική. Η διαδικασία περιλάμβανε:

1. Attach του LLDB στο `cloudconfigurationd`.
2. Εντοπισμό του σημείου όπου γίνεται fetch το system serial number.
3. Injection ενός arbitrary serial number στη memory πριν από την encryption και την αποστολή του payload.

Αυτή η μέθοδος επέτρεψε στους ερευνητές να ανακτήσουν DEP profiles για serial numbers που είχαν δοθεί και αντιστοιχιστεί. Δεν έκανε έγκυρο ένα arbitrary serial number που δεν ήταν αντιστοιχισμένο.<sup>[[1]](#references)</sup>

### Αυτοματοποίηση του Instrumentation με Python

Η διαδικασία exploitation αυτοματοποιήθηκε με Python και το LLDB API, καθιστώντας εφικτό το programmatic injection arbitrary serial numbers και την ανάκτηση των αντίστοιχων DEP profiles.<sup>[[1]](#references)</sup>

## Επανεξέταση το 2025: Rogue Enrollment από VM

Η έρευνα του Black Hat Asia 2025 έδειξε ότι το αρχικό trust-boundary πρόβλημα μπορεί να εξακολουθεί να είναι σημαντικό στο **MDM layer**: αντί να κάνουν patch το `cloudconfigurationd` με LLDB, οι ερευνητές εκτέλεσαν macOS υπό QEMU/KVM με OpenCore και παρείχαν την υποψήφια identity μέσω του SMBIOS της VM. Το μη τροποποιημένο macOS enrollment stack εκτέλεσε στη συνέχεια το encrypted Apple exchange. Επομένως, publicly leaked serials και candidates που μοιάζουν έγκυροι μπορούν να ελεγχθούν χωρίς την κατοχή του αντίστοιχου physical Mac· για επιτυχία εξακολουθεί να απαιτείται το serial να είναι αντιστοιχισμένο σε έναν οργανισμό και το enrollment path του οργανισμού να έχει ανεπαρκή authentication.<sup>[[3]](#references)</sup>

Για μια authorized lab device, οι σχετικές τιμές OpenCore `PlatformInfo` περιλαμβάνουν ένα product model και serial (σε πραγματικές deployments, το ROM και το UUID διατηρούνται επίσης internally consistent):<sup>[[3]](#references)</sup>
```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```
Η ίδια έρευνα εντόπισε την κατάσταση `CheckProfilesFetchRateLimit` στο ιδιωτικό αρχείο `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck`. Επειδή ο έλεγχος διατηρούνταν στον client, η τροποποίηση των αποθηκευμένων τιμών χρόνου τον εξουδετέρωνε. Αυτά τα paths δεν τεκμηριώνονται και εξαρτώνται από την έκδοση, αλλά είναι χρήσιμα reversing pivots κατά την αξιολόγηση ενός τρέχοντος macOS build:<sup>[[3]](#references)</sup>
```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```
Το δεύτερο artifact μπορεί να αποκαλύψει το cached activation record, συμπεριλαμβανομένου του αν η ροή χρησιμοποιεί άμεσο `ConfigurationURL` ή authenticated `ConfigurationWebURL`. Ελέγξτε τόσο τη διαφημιζόμενη ροή όσο και τυχόν MDM-specific legacy enrollment endpoints: η ενεργοποίηση του SSO μόνο στην κύρια web ροή δεν προστατεύει ένα παράλληλο direct endpoint. Για την πλήρη ακολουθία του protocol, δείτε το [macOS MDM overview](README.md).<sup>[[3]](#references)</sup>

### Αναζήτηση Secrets μετά το Enrollment

Ένα rogue enrollment είναι μόνο το entry point. Μετά το enrollment, ελέγξτε κάθε delivered profile, bootstrap policy, package-repository configuration, agent installation script και self-service item. Η έρευνα του 2025 ανέκτησε παραδείγματα Wi-Fi credentials, shared local-administrator passwords, signed cloud-storage URLs, webhook URLs, security-agent activation data και MDM/API credentials. Ένα tenant API credential σε delivered script μπορεί να μετατρέψει ένα rogue endpoint σε έλεγχο άλλων managed devices, επομένως αναζητήστε τόσο στο live filesystem όσο και σε downloaded/cached policy content.<sup>[[3]](#references)</sup>

Χρήσιμοι στόχοι ελέγχου περιλαμβάνουν:<sup>[[3]](#references)</sup>

- Εγκατεστημένα `.mobileconfig` payloads και τη Configuration Profiles database.
- PreStage/bootstrap scripts και packages που δημιουργούν accounts ή εγκαθιστούν EDR/VPN agents.
- Munki ή άλλα package repository URLs, ειδικά query strings που περιέχουν bearer/SAS-style signatures.
- Self-service catalogs και τα backing policy APIs τους, συμπεριλαμβανομένων legacy routes που ενδέχεται να μην επιβάλλουν το enrollment SSO policy.
- Shell history και cached policy output για `password`, `token`, `secret`, `Authorization`, webhook hostnames και vendor API endpoints.

### Ενίσχυση του Trust Boundary

Αντιμετωπίστε έναν serial number ως inventory/routing attribute, **όχι** ως απόδειξη κατοχής. Απαιτήστε user authentication για enrollment και self service, δημιουργήστε unique per-device local administrator passwords και μην ενσωματώνετε ποτέ tenant API credentials ή reusable infrastructure secrets σε profiles ή scripts. Διατηρήστε οποιοδήποτε unavoidable bootstrap token short-lived και περιορισμένο στη single action και τη συσκευή που provisioned.<sup>[[3]](#references)</sup>

Σε Apple-silicon Macs που εκτελούν macOS 14 ή νεότερο, το Managed Device Attestation μπορεί να συνδέσει κρυπτογραφικά την ταυτότητα με το Secure Enclave. Το Apple-rooted attestation του μπορεί να περιλαμβάνει fresh nonce μαζί με το serial number, UDID, OS version, SIP state και secure-boot state· στη συνέχεια το ACME μπορεί να εκδώσει hardware-bound client identity. Χρησιμοποιήστε αυτή την identity για την προστασία του MDM channel και για τον έλεγχο high-value certificates, VPN access και άλλων resources, διατηρώντας παράλληλα ξεχωριστό user authentication, επειδή το device attestation αποδεικνύει τη συσκευή και όχι τον operator.<sup>[[4]](#references)</sup>

## Πιθανές επιπτώσεις των DEP και MDM vulnerabilities

Η έρευνα ανέδειξε σημαντικές ανησυχίες ασφαλείας:

1. **Αποκάλυψη πληροφοριών**: Με την παροχή ενός DEP-registered serial number, μπορούν να ανακτηθούν ευαίσθητες organizational information που περιέχονται στο DEP profile.<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — Ασφάλεια του MDM Me Maybe: Device Enrollment Program](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Impostor Syndrome: Hacking Apple MDMs Using Rogue Device Enrolments](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Apple Platform Security — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}
