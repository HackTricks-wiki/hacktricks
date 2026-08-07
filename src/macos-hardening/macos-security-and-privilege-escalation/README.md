# Ασφάλεια macOS & Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Βασικά για το macOS

Αν δεν είστε εξοικειωμένοι με το macOS, θα πρέπει να ξεκινήσετε μαθαίνοντας τα βασικά του macOS:

- Ειδικά **αρχεία & permissions του macOS:**


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- Συνηθισμένοι **users του macOS**


{{#ref}}
macos-users.md
{{#endref}}

- Το **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- Η **architecture** του k**ernel**


{{#ref}}
mac-os-architecture/
{{#endref}}

- Συνηθισμένα **network services & protocols του macOS**


{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Για να κατεβάσετε ένα `tar.gz`, αλλάξτε ένα URL όπως το [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) σε [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

Στις εταιρείες, τα συστήματα **macOS** είναι πολύ πιθανό να είναι **managed με ένα MDM**. Επομένως, από την οπτική γωνία ενός attacker, είναι ενδιαφέρον να γνωρίζετε **πώς λειτουργεί**:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Inspecting, Debugging και Fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Security Protections του MacOS


{{#ref}}
macos-security-protections/
{{#endref}}

## Attack Surface

### File Permissions

Αν ένα **process που εκτελείται ως root γράφει** σε ένα file που μπορεί να ελεγχθεί από έναν user, ο user θα μπορούσε να το εκμεταλλευτεί για να **κάνει privilege escalation**.\
Αυτό θα μπορούσε να συμβεί στις ακόλουθες περιπτώσεις:

- Το file που χρησιμοποιήθηκε είχε ήδη δημιουργηθεί από έναν user (ανήκει στον user)
- Το file που χρησιμοποιήθηκε είναι writable από τον user λόγω ενός group
- Το file που χρησιμοποιήθηκε βρίσκεται μέσα σε ένα directory που ανήκει στον user (ο user θα μπορούσε να δημιουργήσει το file)
- Το file που χρησιμοποιήθηκε βρίσκεται μέσα σε ένα directory που ανήκει στον root, αλλά ο user έχει write access σε αυτό λόγω ενός group (ο user θα μπορούσε να δημιουργήσει το file)

Η δυνατότητα **δημιουργίας ενός file** που πρόκειται να **χρησιμοποιηθεί από τον root** επιτρέπει σε έναν user να **εκμεταλλευτεί το περιεχόμενό του** ή ακόμη και να δημιουργήσει **symlinks/hardlinks** που το δείχνουν σε άλλη τοποθεσία.

Για αυτόν τον τύπο vulnerabilities μην ξεχνάτε να **ελέγχετε vulnerable `.pkg` installers**:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### File Extension & URL scheme app handlers

Παράξενα apps που είναι registered από file extensions θα μπορούσαν να γίνουν abused και διαφορετικές εφαρμογές μπορούν να γίνουν registered ώστε να ανοίγουν συγκεκριμένα protocols


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

Στο macOS, **applications και binaries μπορούν να έχουν permissions** για πρόσβαση σε folders ή settings που τα καθιστούν πιο privileged από άλλα.

Επομένως, ένας attacker που θέλει να compromise επιτυχώς ένα macOS machine θα χρειαστεί να **κάνει escalate τα TCC privileges** του (ή ακόμη και να **κάνει bypass το SIP**, ανάλογα με τις ανάγκες του).

Αυτά τα privileges συνήθως παρέχονται με τη μορφή **entitlements** με τα οποία είναι signed η εφαρμογή ή η εφαρμογή μπορεί να έχει ζητήσει συγκεκριμένες προσβάσεις και, αφού ο **user τις εγκρίνει**, μπορούν να βρεθούν στα **TCC databases**. Ένας ακόμη τρόπος με τον οποίο ένα process μπορεί να αποκτήσει αυτά τα privileges είναι να είναι **child ενός process** με αυτά τα **privileges**, καθώς συνήθως **κληρονομούνται**.<sup>[[5]](#references)</sup>

Ακολουθήστε αυτούς τους links για να βρείτε διαφορετικούς τρόπους να [**κάνετε escalate privileges στο TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), να [**κάνετε bypass το TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) και να δείτε πώς στο παρελθόν [**έχει γίνει bypass του SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## Traditional Privilege Escalation στο macOS

Φυσικά, από την οπτική γωνία των red teams, θα πρέπει επίσης να σας ενδιαφέρει το privilege escalation σε root. Ελέγξτε το ακόλουθο post για μερικές υποδείξεις:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS Compliance

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## References

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
