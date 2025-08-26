# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB αναφέρεται στην κατάχρηση αρχείων Interface Builder (.xib/.nib) μέσα σε ένα υπογεγραμμένο macOS app bundle για να εκτελεστεί λογική ελεγχόμενη από τον επιτιθέμενο μέσα στη στοχευόμενη διεργασία, κληρονομώντας έτσι τα entitlements και τις TCC permissions. Αυτή η τεχνική τεκμηριώθηκε αρχικά από xpn (MDSec) και αργότερα γενικεύτηκε και επεκτάθηκε σημαντικά από Sector7, οι οποίοι επίσης κάλυψαν τις μετριάσεις της Apple σε macOS 13 Ventura και macOS 14 Sonoma. Για υπόβαθρο και σε βάθος ανάλυση, δείτε τις αναφορές στο τέλος.

> TL;DR
> • Before macOS 13 Ventura: η αντικατάσταση του MainMenu.nib ενός bundle (ή άλλου nib που φορτώνεται κατά την εκκίνηση) μπορούσε με αξιοπιστία να επιτύχει process injection και συχνά privilege escalation.
> • Since macOS 13 (Ventura) and improved in macOS 14 (Sonoma): first‑launch deep verification, bundle protection, Launch Constraints, και η νέα TCC “App Management” permission σε μεγάλο βαθμό αποτρέπουν την μετατροπή nib μετά την εκκίνηση από ανεξάρτητες εφαρμογές. Επιθέσεις μπορεί ακόμα να είναι δυνατές σε ειδικές περιπτώσεις (π.χ. tooling του ίδιου developer που τροποποιεί τις δικές του εφαρμογές, ή terminals που έχουν χορηγηθεί App Management/Full Disk Access από τον χρήστη).

## What are NIB/XIB files

Nib (συντ. NeXT Interface Builder) αρχεία είναι σειριοποιημένα γραφήματα αντικειμένων UI που χρησιμοποιούνται από AppKit apps. Το σύγχρονο Xcode αποθηκεύει επεξεργάσιμα XML .xib αρχεία τα οποία μεταγλώττονται σε .nib κατά το build time. Μια τυπική εφαρμογή φορτώνει το κύριο UI της μέσω `NSApplicationMain()` που διαβάζει το κλειδί `NSMainNibFile` από το Info.plist της εφαρμογής και στιγμιοποιεί (instantiates) το γράφημα αντικειμένων κατά την εκτέλεση.

Key points that enable the attack:
- Το φόρτωμα NIB στιγμιοποιεί αυθαίρετες Objective‑C κλάσεις χωρίς να απαιτεί να συμμορφώνονται με NSSecureCoding (ο nib loader της Apple καταφεύγει σε `init`/`initWithFrame:` όταν `initWithCoder:` δεν είναι διαθέσιμο).
- Τα Cocoa Bindings μπορούν να καταχραστούν για να καλέσουν μεθόδους καθώς τα nibs στιγμιοποιούνται, συμπεριλαμβανομένων αλυσιδωτών κλήσεων που δεν απαιτούν καμία αλληλεπίδραση χρήστη.

## Dirty NIB injection process (attacker view)

Η κλασική ροή πριν το Ventura:
1) Create a malicious .xib
- Προσθέστε ένα `NSAppleScript` αντικείμενο (ή άλλες “gadget” κλάσεις όπως `NSTask`).
- Προσθέστε ένα `NSTextField` του οποίου ο title περιέχει το payload (π.χ. AppleScript ή command arguments).
- Προσθέστε ένα ή περισσότερα `NSMenuItem` αντικείμενα συνδεδεμένα μέσω bindings για να καλέσουν μεθόδους στο target αντικείμενο.

2) Auto‑trigger without user clicks
- Χρησιμοποιήστε bindings για να ορίσετε τον target/selector ενός menu item και στη συνέχεια καλέστε την ιδιωτική μέθοδο `_corePerformAction` ώστε η ενέργεια να ενεργοποιηθεί αυτόματα όταν το nib φορτώνει. Αυτό αφαιρεί την ανάγκη ο χρήστης να κάνει κλικ σε ένα κουμπί.

Minimal example of an auto‑trigger chain inside a .xib (abridged for clarity):
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
Αυτό επιτυγχάνει αυθαίρετη εκτέλεση AppleScript στη διεργασία στόχου κατά το φόρτωμα του nib. Προχωρημένες αλυσίδες μπορούν:
- Να δημιουργήσουν αυθαίρετες κλάσεις AppKit (π.χ., `NSTask`) και να καλέσουν μεθόδους χωρίς ορίσματα όπως `-launch`.
- Να καλέσουν αυθαίρετους selectors με αντικειμενικά ορίσματα μέσω του παραπάνω binding trick.
- Να φορτώσουν AppleScriptObjC.framework για να γεφυρώσουν σε Objective‑C και ακόμη να καλέσουν επιλεγμένα C APIs.
- Σε παλαιότερα συστήματα που περιλαμβάνουν ακόμα Python.framework, να γεφυρώσουν σε Python και στη συνέχεια να χρησιμοποιήσουν `ctypes` για να καλέσουν αυθαίρετες C συναρτήσεις (έρευνα Sector7).

3) Replace the app’s nib
- Αντιγράψτε το target.app σε μια εγγράψιμη τοποθεσία, αντικαταστήστε π.χ. `Contents/Resources/MainMenu.nib` με το κακόβουλο nib, και τρέξτε το target.app. Πριν το Ventura, μετά από μια εφάπαξ αξιολόγηση από το Gatekeeper, οι επακόλουθες εκκινήσεις εκτελούσαν μόνο επιφανειακούς ελέγχους υπογραφής, οπότε μη εκτελέσιμοι πόροι (όπως .nib) δεν επαληθεύονταν εκ νέου.

Example AppleScript payload for a visible test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Σύγχρονες προστασίες macOS (Ventura/Monterey/Sonoma/Sequoia)

Η Apple εισήγαγε αρκετές συστημικές μετρήσεις που μειώνουν δραστικά την αποτελεσματικότητα του Dirty NIB στα σύγχρονα macOS:
- First‑launch deep verification and bundle protection (macOS 13 Ventura)
- Κατά το πρώτο άνοιγμα οποιασδήποτε εφαρμογής (quarantined ή όχι), ένας βαθύς έλεγχος υπογραφής καλύπτει όλους τους πόρους του bundle. Μετά από αυτό, το bundle γίνεται προστατευμένο: μόνο εφαρμογές από τον ίδιο developer (ή που έχουν ρητά επιτραπεί από την εφαρμογή) μπορούν να τροποποιήσουν τα περιεχόμενά του. Άλλες εφαρμογές απαιτούν τη νέα TCC “App Management” permission για να γράψουν στο bundle μιας άλλης εφαρμογής.
- Launch Constraints (macOS 13 Ventura)
- Οι System/Apple‑bundled εφαρμογές δεν μπορούν να αντιγραφούν σε άλλα μέρη και να εκκινηθούν· αυτό καταστρέφει την προσέγγιση “copy to /tmp, patch, run” για τις εφαρμογές του OS.
- Improvements in macOS 14 Sonoma
- Η Apple ενίσχυσε το App Management και διόρθωσε γνωστές παρακάμψεις (π.χ. CVE‑2023‑40450) που σημείωσε η Sector7. Το Python.framework αφαιρέθηκε νωρίτερα (macOS 12.3), σπάζοντας κάποιες αλυσίδες privilege‑escalation.
- Gatekeeper/Quarantine changes
- Για ευρύτερη συζήτηση για το Gatekeeper, την provenance, και τις αλλαγές αξιολόγησης που επηρέασαν αυτή τη τεχνική, δείτε τη σελίδα που αναφέρεται παρακάτω.

> Πρακτική επίπτωση
> • Στο Ventura+ γενικά δεν μπορείτε να τροποποιήσετε το .nib ενός τρίτου μέρους εκτός αν η διεργασία σας έχει App Management ή είναι υπογεγραμμένη από το ίδιο Team ID με τον στόχο (π.χ., developer tooling).
> • Η παροχή App Management ή Full Disk Access σε shells/terminals ανοίγει ουσιαστικά ξανά αυτή την επιφάνεια επίθεσης για οτιδήποτε μπορεί να εκτελέσει κώδικα μέσα στο context αυτού του terminal.


### Αντιμετώπιση των Launch Constraints

Οι Launch Constraints εμποδίζουν την εκτέλεση πολλών Apple εφαρμογών από μη‑προεπιλεγμένες τοποθεσίες ξεκινώντας με το Ventura. Εάν βασιζόσασταν σε pre‑Ventura ροές εργασίας όπως το να αντιγράψετε μια Apple app σε έναν προσωρινό φάκελο, να τροποποιήσετε το `MainMenu.nib`, και να την εκτελέσετε, αναμένετε ότι αυτό θα αποτύχει σε >= 13.0.


## Εντοπισμός στόχων και nibs (χρήσιμο για research / legacy systems)

- Εντοπίστε εφαρμογές των οποίων το UI είναι nib‑driven:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Βρείτε υποψήφιους πόρους nib μέσα σε ένα bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Επικυρώστε code signatures σε βάθος (θα αποτύχει αν τροποποιήσατε resources και δεν κάνατε re‑sign):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Σημείωση: Σε σύγχρονο macOS θα σας αποκλείσει επίσης η bundle protection/TCC όταν προσπαθείτε να γράψετε στο bundle μιας άλλης εφαρμογής χωρίς κατάλληλη εξουσιοδότηση.


## Ανίχνευση και συμβουλές DFIR

- Παρακολούθηση ακεραιότητας αρχείων στους πόρους των bundle
- Παρακολουθήστε αλλαγές mtime/ctime στο `Contents/Resources/*.nib` και σε άλλους μη‑εκτελέσιμους πόρους σε εγκατεστημένες εφαρμογές.
- Ενοποιημένα logs και συμπεριφορά διεργασιών
- Παρακολουθήστε για απρόσμενη εκτέλεση AppleScript μέσα σε GUI εφαρμογές και για διεργασίες που φορτώνουν AppleScriptObjC ή Python.framework. Παράδειγμα:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Προληπτικές αξιολογήσεις
- Τρέχετε περιοδικά `codesign --verify --deep` σε κρίσιμες εφαρμογές για να βεβαιώνεστε ότι οι πόροι παραμένουν ανέπαφοι.
- Πλαίσιο προνομίων
- Ελέγξτε ποιος/τι έχει στο TCC “App Management” ή Full Disk Access (ειδικά terminals και management agents). Η αφαίρεση αυτών από γενικής‑χρήσης shells αποτρέπει την εύκολη επανενεργοποίηση της παραποίησης τύπου Dirty NIB.


## Αμυντική ενίσχυση (προγραμματιστές και αμυντές)

- Προτιμήστε programmatic UI ή περιορίστε τι δημιουργείται από nibs. Αποφύγετε τη συμπερίληψη ισχυρών κλάσεων (π.χ., `NSTask`) στα nib graphs και αποφύγετε bindings που καλούν έμμεσα selectors σε αυθαίρετα αντικείμενα.
- Υιοθετήστε το hardened runtime με Library Validation (ήδη στάνταρ για σύγχρονες εφαρμογές). Αν και αυτό δεν σταματά από μόνο του την nib injection, μπλοκάρει το εύκολο φόρτωμα native κώδικα και αναγκάζει τους επιτιθέμενους σε payloads μόνο με scripting.
- Μην ζητάτε ή εξαρτάστε από ευρείες App Management permissions σε εργαλεία γενικής χρήσης. Εάν MDM απαιτεί App Management, απομονώστε αυτό το περιβάλλον από τα user‑driven shells.
- Επαληθεύετε τακτικά την ακεραιότητα του app bundle σας και κάντε τους μηχανισμούς ενημέρωσης να αυτοθεραπεύουν τους πόρους του bundle.


## Σχετική ανάγνωση στο HackTricks

Μάθετε περισσότερα για το Gatekeeper, το quarantine και τις αλλαγές provenance που επηρεάζουν αυτήν την τεχνική:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Αναφορές

- xpn – DirtyNIB (αρχική περιγραφή με παράδειγμα Pages): https://blog.xpnsec.com/dirtynib/
- Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024): https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/

{{#include ../../../banners/hacktricks-training.md}}
