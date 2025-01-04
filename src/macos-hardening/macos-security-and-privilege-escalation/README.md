# macOS Security & Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic MacOS

Αν δεν είστε εξοικειωμένοι με το macOS, θα πρέπει να αρχίσετε να μαθαίνετε τα βασικά του macOS:

- Ειδικά αρχεία & δικαιώματα macOS:

{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- Κοινές χρήστες macOS

{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**

{{#ref}}
macos-applefs.md
{{#endref}}

- Η **αρχιτεκτονική** του k**ernel**

{{#ref}}
mac-os-architecture/
{{#endref}}

- Κοινές υπηρεσίες & πρωτόκολλα δικτύου macOS

{{#ref}}
macos-protocols.md
{{#endref}}

- **Ανοιχτού κώδικα** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Για να κατεβάσετε ένα `tar.gz`, αλλάξτε μια διεύθυνση URL όπως [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) σε [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

Σε εταιρείες, τα συστήματα **macOS** είναι πολύ πιθανό να είναι **διαχειριζόμενα με MDM**. Επομένως, από την προοπτική ενός επιτιθέμενου είναι ενδιαφέρον να γνωρίζει **πώς λειτουργεί**:

{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Επιθεώρηση, Αποσφαλμάτωση και Fuzzing

{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS Security Protections

{{#ref}}
macos-security-protections/
{{#endref}}

## Attack Surface

### File Permissions

Αν μια **διαδικασία που εκτελείται ως root γράφει** ένα αρχείο που μπορεί να ελεγχθεί από έναν χρήστη, ο χρήστης θα μπορούσε να το εκμεταλλευτεί για να **κάνει αναβάθμιση δικαιωμάτων**.\
Αυτό θα μπορούσε να συμβεί στις παρακάτω καταστάσεις:

- Το αρχείο που χρησιμοποιήθηκε είχε ήδη δημιουργηθεί από έναν χρήστη (ανήκει στον χρήστη)
- Το αρχείο που χρησιμοποιήθηκε είναι εγγράψιμο από τον χρήστη λόγω ομάδας
- Το αρχείο που χρησιμοποιήθηκε είναι μέσα σε έναν φάκελο που ανήκει στον χρήστη (ο χρήστης θα μπορούσε να δημιουργήσει το αρχείο)
- Το αρχείο που χρησιμοποιήθηκε είναι μέσα σε έναν φάκελο που ανήκει στο root αλλά ο χρήστης έχει δικαίωμα εγγραφής σε αυτόν λόγω ομάδας (ο χρήστης θα μπορούσε να δημιουργήσει το αρχείο)

Η δυνατότητα **δημιουργίας ενός αρχείου** που θα χρησιμοποιηθεί από το **root**, επιτρέπει σε έναν χρήστη να **εκμεταλλευτεί το περιεχόμενό του** ή ακόμη και να δημιουργήσει **symlinks/hardlinks** για να το δείξει σε άλλη τοποθεσία.

Για αυτούς τους τύπους ευπαθειών μην ξεχάσετε να **ελέγξετε ευάλωτους εγκαταστάτες `.pkg`**:

{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### File Extension & URL scheme app handlers

Περίεργες εφαρμογές που έχουν καταχωρηθεί από επεκτάσεις αρχείων θα μπορούσαν να εκμεταλλευτούν και διαφορετικές εφαρμογές μπορούν να καταχωρηθούν για να ανοίγουν συγκεκριμένα πρωτόκολλα

{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

Στο macOS, οι **εφαρμογές και τα δυαδικά αρχεία μπορούν να έχουν δικαιώματα** για πρόσβαση σε φακέλους ή ρυθμίσεις που τους καθιστούν πιο προνομιούχες από άλλες.

Επομένως, ένας επιτιθέμενος που θέλει να συμβιβάσει επιτυχώς μια μηχανή macOS θα χρειαστεί να **αναβαθμίσει τα δικαιώματα TCC** (ή ακόμη και **να παρακάμψει το SIP**, ανάλογα με τις ανάγκες του).

Αυτά τα δικαιώματα δίνονται συνήθως με τη μορφή **entitlements** με τις οποίες είναι υπογεγραμμένη η εφαρμογή, ή η εφαρμογή μπορεί να έχει ζητήσει κάποιες προσβάσεις και μετά την **έγκριση τους από τον χρήστη** μπορούν να βρεθούν στις **βάσεις δεδομένων TCC**. Ένας άλλος τρόπος με τον οποίο μια διαδικασία μπορεί να αποκτήσει αυτά τα δικαιώματα είναι να είναι **παιδί μιας διαδικασίας** με αυτά τα **δικαιώματα**, καθώς συνήθως **κληρονομούνται**.

Ακολουθήστε αυτούς τους συνδέσμους για να βρείτε διαφορετικούς τρόπους για να [**αναβαθμίσετε δικαιώματα στο TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), για να [**παρακάμψετε το TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) και πώς στο παρελθόν [**έχει παρακαμφθεί το SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Traditional Privilege Escalation

Φυσικά, από την προοπτική των κόκκινων ομάδων, θα πρέπει επίσης να ενδιαφέρεστε να αναβαθμίσετε σε root. Ελέγξτε την παρακάτω ανάρτηση για μερικές συμβουλές:

{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS Compliance

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## References

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
- [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
