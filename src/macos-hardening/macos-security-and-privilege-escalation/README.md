# Ασφάλεια macOS & Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Βασικά στοιχεία του MacOS

Αν δεν είστε εξοικειωμένοι με το macOS, θα πρέπει να ξεκινήσετε μαθαίνοντας τα βασικά του macOS:

- Ειδικά **αρχεία & δικαιώματα** του macOS:


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- Συνήθεις **χρήστες** του macOS


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

- Συνήθεις υπηρεσίες **δικτύου & πρωτόκολλα** του macOS


{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Για να κατεβάσετε ένα `tar.gz`, αλλάξτε ένα URL όπως [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) σε [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

Στις εταιρείες, τα συστήματα **macOS** είναι πολύ πιθανό να είναι **managed with a MDM**. Επομένως, από την οπτική γωνία ενός attacker, είναι ενδιαφέρον να γνωρίζει **πώς λειτουργεί αυτό**:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Επιθεώρηση, Debugging και Fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Προστασίες ασφαλείας του MacOS


{{#ref}}
macos-security-protections/
{{#endref}}

## Attack Surface

### Δικαιώματα αρχείων

Αν μια **διεργασία που εκτελείται ως root γράφει** σε ένα αρχείο που μπορεί να ελεγχθεί από έναν χρήστη, ο χρήστης θα μπορούσε να το εκμεταλλευτεί για **escalate privileges**.\
Αυτό μπορεί να συμβεί στις ακόλουθες περιπτώσεις:

- Το αρχείο που χρησιμοποιείται έχει ήδη δημιουργηθεί από έναν χρήστη (ανήκει στον χρήστη)
- Το αρχείο που χρησιμοποιείται είναι εγγράψιμο από τον χρήστη λόγω ενός group
- Το αρχείο που χρησιμοποιείται βρίσκεται μέσα σε έναν κατάλογο που ανήκει στον χρήστη (ο χρήστης θα μπορούσε να δημιουργήσει το αρχείο)
- Το αρχείο που χρησιμοποιείται βρίσκεται μέσα σε έναν κατάλογο που ανήκει στον root, αλλά ο χρήστης έχει write access σε αυτόν λόγω ενός group (ο χρήστης θα μπορούσε να δημιουργήσει το αρχείο)

Η δυνατότητα **δημιουργίας ενός αρχείου** που πρόκειται να **χρησιμοποιηθεί από τον root** επιτρέπει σε έναν χρήστη να **εκμεταλλευτεί το περιεχόμενό του** ή ακόμη και να δημιουργήσει **symlinks/hardlinks** που να δείχνουν σε άλλη τοποθεσία.

Για αυτού του είδους τα vulnerabilities, μην ξεχνάτε να **ελέγχετε ευάλωτους `.pkg` installers**:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### File Extension & URL scheme app handlers

Παράξενες εφαρμογές που έχουν καταχωριστεί μέσω file extensions θα μπορούσαν να γίνουν αντικείμενο abuse, ενώ διαφορετικές εφαρμογές μπορούν να καταχωριστούν ώστε να ανοίγουν συγκεκριμένα protocols


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

Στο macOS, οι **εφαρμογές και τα binaries μπορούν να έχουν δικαιώματα** πρόσβασης σε φακέλους ή ρυθμίσεις, γεγονός που τις καθιστά πιο privileged από άλλες.

Επομένως, ένας attacker που θέλει να compromise επιτυχώς ένα macOS machine θα χρειαστεί να **escalate τα TCC privileges** (ή ακόμη και να **bypass το SIP**, ανάλογα με τις ανάγκες του).

Αυτά τα privileges συνήθως παρέχονται με τη μορφή **entitlements** με τα οποία έχει υπογραφεί η εφαρμογή, ή η εφαρμογή μπορεί να έχει ζητήσει ορισμένες προσβάσεις και, μετά την **έγκρισή τους από τον χρήστη**, αυτές μπορούν να βρεθούν στις **TCC databases**. Ένας άλλος τρόπος με τον οποίο μια διεργασία μπορεί να αποκτήσει αυτά τα privileges είναι να είναι **child μιας διεργασίας** με αυτά τα **privileges**, καθώς συνήθως **κληρονομούνται**.

Ακολουθήστε αυτούς τους συνδέσμους για να βρείτε διαφορετικούς τρόπους να [**escalate privileges στο TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), να [**bypass το TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) και να δείτε πώς στο παρελθόν [**έχει γίνει bypass του SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## Παραδοσιακό Privilege Escalation στο macOS

Φυσικά, από την οπτική γωνία ενός red team, θα πρέπει επίσης να σας ενδιαφέρει το escalation σε root. Ελέγξτε το ακόλουθο post για μερικές υποδείξεις:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## Συμμόρφωση macOS

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Αναφορές

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
