# Χειριστές εφαρμογών για επεκτάσεις αρχείων και URL schemes στο macOS

{{#include ../../banners/hacktricks-training.md}}

## Βάση δεδομένων LaunchServices

Πρόκειται για μια βάση δεδομένων με όλες τις εγκατεστημένες εφαρμογές στο macOS, από την οποία μπορούν να ανακτηθούν πληροφορίες για κάθε εφαρμογή, όπως τα υποστηριζόμενα **URL schemes**, οι **τύποι εγγράφων**, τα **UTI** και οι προεπιλεγμένοι χειριστές.

Μπορείτε να εξαγάγετε αυτήν τη βάση δεδομένων με:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Ή χρησιμοποιώντας το εργαλείο [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Το **`/usr/libexec/lsd`** είναι ο εγκέφαλος της βάσης δεδομένων. Παρέχει **διάφορες υπηρεσίες XPC**, όπως οι `.lsd.installation`, `.lsd.open`, `.lsd.openurl` και άλλες. Ωστόσο, **απαιτεί επίσης ορισμένα entitlements** από τις εφαρμογές για να μπορούν να χρησιμοποιούν τις εκτεθειμένες λειτουργίες XPC, όπως τα `.launchservices.changedefaulthandler` ή `.launchservices.changeurlschemehandler` για την αλλαγή των προεπιλεγμένων εφαρμογών για τύπους MIME ή σχήματα URL, και άλλες.

Το **`/System/Library/CoreServices/launchservicesd`** δηλώνει την υπηρεσία `com.apple.coreservices.launchservicesd` και μπορείτε να του υποβάλετε ερωτήματα για να λάβετε πληροφορίες σχετικά με εφαρμογές που εκτελούνται. Μπορείτε να του υποβάλετε ερωτήματα με το εργαλείο συστήματος **`/usr/bin/lsappinfo`** ή με το [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Από την οπτική του χειριστή, έχετε υπόψη ότι συνήθως υπάρχουν **δύο χρήσιμες όψεις**:

- Η **βάση δεδομένων καταχωρίσεων** που διαχειρίζονται τα LaunchServices / `lsd` (και υποστηρίζεται από αρχεία `.csstore`).
- Οι **προεπιλεγμένες ρυθμίσεις που ισχύουν ανά χρήστη**, αποθηκευμένες στο `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, μέσα στον πίνακα `LSHandlers`.

Αυτή η διάκριση έχει σημασία: μια εφαρμογή μπορεί να είναι **καταχωρισμένη** ως κατάλληλη για τον χειρισμό ενός τύπου ή σχήματος, αλλά η **τρέχουσα προεπιλογή** μπορεί να είναι ένα διαφορετικό bundle ID.

Στις πρόσφατες εκδόσεις macOS, η αναζήτηση καταχωρίσεων δεν περιορίζεται στον φάκελο `/Applications`: εφαρμογές σε άλλους προσβάσιμους φακέλους που είναι ορατοί στο Spotlight, καθώς και σε προσαρτημένους/κοινόχρηστους τόμους, μπορούν να προστεθούν στο μητρώο. Επομένως, κατά τη διαλογή, διατηρήστε τις πληροφορίες `path` και τόμου από το `lsregister -dump` και μην υποθέτετε ότι η κατάργηση μιας εφαρμογής από το μητρώο είναι μόνιμη όσο το bundle παραμένει ανιχνεύσιμο.<sup>[[4]](#references)</sup>

## Χειριστές εφαρμογών για επεκτάσεις αρχείων και σχήματα URL

Η ακόλουθη γραμμή μπορεί να είναι χρήσιμη για να εντοπίσετε τις εφαρμογές που μπορούν να ανοίγουν αρχεία ανάλογα με την επέκτασή τους:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```

Ή χρησιμοποιήστε κάτι όπως [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):

```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```

Μπορείτε επίσης να ελέγξετε τις επεκτάσεις που υποστηρίζει μια εφαρμογή εκτελώντας:

```bash
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
				<string>css</string>
				<string>pdf</string>
				<string>webarchive</string>
				<string>webbookmark</string>
				<string>webhistory</string>
				<string>webloc</string>
				<string>download</string>
				<string>safariextz</string>
				<string>gif</string>
				<string>html</string>
				<string>htm</string>
				<string>js</string>
				<string>jpg</string>
				<string>jpeg</string>
				<string>jp2</string>
				<string>txt</string>
				<string>text</string>
				<string>png</string>
				<string>tiff</string>
				<string>tif</string>
				<string>url</string>
				<string>ico</string>
				<string>xhtml</string>
				<string>xht</string>
				<string>xml</string>
				<string>xbl</string>
				<string>svg</string>
```

## Απαρίθμηση ενεργών handlers

Το πιο χρήσιμο αρχείο για τις **προεπιλεγμένες εφαρμογές του τρέχοντος χρήστη** είναι συνήθως:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Για να κάνετε dump τους handlers **URL scheme** από αυτό:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Για να κάνετε dump τους handlers **content-type / UTI**:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Για να επιλύσετε το δέντρο UTI ενός δείγματος αρχείου:

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

Αν θέλετε ένα πιο φιλικό CLI για να δείτε ή να αλλάξετε τις προεπιλεγμένες ρυθμίσεις:

```bash
# Classic tool
# https://github.com/moretension/duti
duti -x jpg                    # Show current default for extension
duti -s com.apple.Safari public.html all
duti -s com.apple.Finder ftp   # Set default for ftp://

# Newer tool
# https://github.com/jackchuka/dutix
dutix targets show public.html
dutix targets show ftp
dutix apps show Safari
```

### Παρακάμψεις `Open With` ανά αρχείο

Η επίλυση χειριστή έχει επίσης ένα **ειδικό για κάθε αρχείο** επίπεδο. Πριν καταφύγει στο UTI του αρχείου και στην καθολική προεπιλογή του χρήστη, το LaunchServices ελέγχει το extended attribute `com.apple.LaunchServices.OpenWith`. Το Finder το δημιουργεί όταν επιλέγεται το **Always Open With** για ένα αρχείο· η τιμή του είναι μια δυαδική λίστα ιδιοτήτων που περιέχει μια διαδρομή εφαρμογής, ένα αναγνωριστικό bundle και έναν επιλογέα έκδοσης.<sup>[[3]](#references)</sup>

Επιθεωρήστε και αποκωδικοποιήστε το χωρίς να εμπιστεύεστε την επέκταση ονόματος αρχείου:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Αυτό είναι χρήσιμο όταν ένα μεμονωμένο δέλεαρ ανοίγει με μια απροσδόκητη εφαρμογή, παρόλο που τα `duti`, `dutix` ή `LSHandlers` αναφέρουν μια αβλαβή καθολική προεπιλογή. Σε ένα ελεγχόμενο εργαστήριο, μπορείτε να αντιγράψετε την ακριβή αδιαφανή τιμή από ένα αρχείο που έχει ρυθμιστεί μέσω του Finder· η διαγραφή της επαναφέρει την κανονική επίλυση βάσει τύπου:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Ενδιαφέροντα κλειδιά του Info.plist

Κατά την αρχική αξιολόγηση ενός πακέτου εφαρμογής, τα σημαντικότερα κλειδιά είναι:

- **`CFBundleDocumentTypes`**: ομάδες εγγράφων που δηλώνει ότι μπορεί να ανοίξει το πακέτο.
- **`LSItemContentTypes`**: ο **σύγχρονος / προτιμώμενος** τρόπος σύνδεσης τύπων εγγράφων με UTI.
- **`LSHandlerRank`**: κατάταξη που χρησιμοποιείται από το LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: προσαρμοσμένα URI schemes που υλοποιεί η εφαρμογή.
- **`UTExportedTypeDeclarations`**: UTI που **ανήκουν** στην εφαρμογή.
- **`UTImportedTypeDeclarations`**: UTI που δεν ανήκουν στην εφαρμογή, αλλά θέλει να αναγνωρίζει το σύστημα.

Μια χρήσιμη εντολή για γρήγορη αξιολόγηση είναι η εξής:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Μια λεπτή αλλά σημαντική λεπτομέρεια: αν υπάρχει το **`LSItemContentTypes`**, παλαιότερα κλειδιά όπως τα **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** και **`CFBundleTypeOSTypes`** αποτελούν ουσιαστικά legacy δεδομένα συμβατότητας. Για την επίλυση του πραγματικού handler, εστιάστε πρώτα στη διαδρομή UTI.

## Offensive notes

Οι εφαρμογές δεν χρειάζεται να εκτελεστούν για να αποκτήσουν ενδιαφέρον οι δηλώσεις handler, αλλά **η απλή εγγραφή ενός bundle `.app` δεν εγγυάται την άμεση καταχώρισή του**. Το Finder μπορεί να καταχωρίσει μια εφαρμογή όταν την εντοπίσει, ακόμη και όταν ο χρήστης περιηγείται στον φάκελό της· η καταχώριση μπορεί επίσης να γίνει κατά την εκκίνηση ή τη σύνδεση ή μέσω ρητής κλήσης καταχώρισης. Ελέγξτε το `lsregister -dump` πριν δοκιμάσετε μια δήλωση. Η καταχώριση από μόνη της ούτε εκκινεί την εφαρμογή ούτε την καθιστά τον ενεργό προεπιλεγμένο handler.<sup>[[5]](#references)</sup> Για τις προϋποθέσεις persistence, δείτε το [URL Scheme & File-Type Handlers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices).

Αυτό είναι χρήσιμο τόσο για έρευνα σχετικά με **persistence / hijacking** όσο και για **αλυσίδες αρχικής πρόσβασης**:

- Μια κακόβουλη εφαρμογή μπορεί να δηλώσει ένα **σπάνιο extension** ή ένα **custom UTI** και να περιμένει μέχρι το θύμα να ανοίξει το αρχείο-δόλωμα.
- Μια κακόβουλη εφαρμογή μπορεί να καταχωρίσει ένα **custom URL scheme** στο οποίο μπορεί να αποκτήσει πρόσβαση μέσω browser, εφαρμογής Electron, εγγράφου γραφείου, προγράμματος-πελάτη συνομιλίας ή άλλης βοηθητικής εφαρμογής.<sup>[[1]](#references)</sup>
- Για να διαχωρίσετε την κανονική επίλυση προεπιλογής από τη δοκιμή ενός συγκεκριμένου υποψήφιου handler, καλέστε το scheme μέσω του LaunchServices με `open 'targetscheme://host/path?value=test'` και, στη συνέχεια, στοχεύστε ένα συγκεκριμένο καταχωρισμένο bundle με `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Αυτό είναι χρήσιμο για τον έλεγχο του τρόπου με τον οποίο η εφαρμογή υποδοχής επικυρώνει και αποκωδικοποιεί στοιχεία URL που ελέγχονται από τον εισβολέα.<sup>[[1]](#references)</sup>
- Αν επεξεργαστείτε ένα bundle εφαρμογής μετά τη δημιουργία του, μπορείτε να αναγκάσετε το LaunchServices να το αναλύσει ξανά με:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Κατά τον έλεγχο ύποπτων bundles, δώστε ιδιαίτερη προσοχή στα εξής:

- **`LSHandlerRank=Owner`** σε ασυνήθιστους τύπους.
- **Ευρείες** arrays **`CFBundleDocumentTypes`** που δηλώνουν πολλές επεκτάσεις.
- **Helper / wrapper apps** των οποίων η μόνη ενδιαφέρουσα συμπεριφορά ενεργοποιείται μέσω ενός document ή URI handler.
- Αρχεία τύπου **shortcut** (`.webloc`, `.inetloc`, `.fileloc`) που τελικά κάνουν dispatch στο LaunchServices. Για τεχνάσματα τύπου `.fileloc` και σχετικές πτυχές του Gatekeeper, δείτε [αυτήν τη σελίδα](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

### Παράμετροι URL που προωθούνται σε downstream επιλογές

Η επιβεβαίωση ενός browser για εξωτερικό πρωτόκολλο εγκρίνει μόνο το άνοιγμα του handler· δεν καθιστά αξιόπιστες τις παραμέτρους του URL. Ακολουθήστε τον parser URL της εφαρμογής που λαμβάνει το αίτημα, μέχρι οποιαδήποτε library, media engine, helper process ή επιλογή εγγραφής αρχείων. Αναζητήστε ένα πρόθεμα στα query keys που μετατρέπει τα πεδία του URL σε ονόματα downstream επιλογών. Δοκιμάστε τόσο κυριολεκτικούς όσο και percent-encoded διαχωριστές, χρησιμοποιώντας έναν ακίνδυνο marker σε έναν προσωρινό λογαριασμό.<sup>[[6]](#references)</sup>

Επαληθεύστε την **τελική επιλογή που δέχεται το downstream component**, όχι μόνο το αρχικό parsing της εφαρμογής. Ένας handler επέτρεπε σε prefixed query keys να φτάσουν σε εντολές εισόδου του mpv· ο αποκλεισμός αυτής της επιλογής εξακολουθούσε να αφήνει διαθέσιμη μια διαδρομή εγγραφής αρχείων. Δοκιμάστε την προσβάσιμη κατηγορία επιλογών, όχι μόνο ένα γνωστό επικίνδυνο key.<sup>[[7]](#references)</sup>

### Ενσωματωμένος handler `applescript://`

Ο URL handler `applescript://com.apple.scripteditor` δέχεται `action=new` και μια παράμετρο `script` με URL encoding. Επομένως, ένας σύνδεσμος σε browser μπορεί να ανοίξει το Script Editor με AppleScript ελεγχόμενο από τον επιτιθέμενο ήδη στον editor, παρακάμπτοντας το βήμα επικόλλησης στο Terminal. Αυτό **δεν σημαίνει αυτόματη εκτέλεση**: ο browser μπορεί να ζητήσει άδεια για το άνοιγμα του Script Editor και ο χρήστης πρέπει να εκτελέσει το script.<sup>[[8]](#references)</sup>

Οι πρόσφατες εκδόσεις macOS μπορεί να εμφανίσουν προειδοποίηση για το script document, ενώ το XProtect σαρώνει το AppleScript κατά την εκτέλεση.<sup>[[8]](#references)[[9]](#references)</sup>

Χρησιμοποιήστε έναν ακίνδυνο τοπικό έλεγχο για να εξετάσετε τον handler και τις προτροπές στην έκδοση macOS που αξιολογείτε· θα πρέπει απλώς να συμπληρώνει τον editor μέχρι να πατηθεί το **Run**.<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

Αν ο στόχος σας είναι η παθητική εκτέλεση κώδικα απλώς με την περιήγηση σε έναν φάκελο ή την επιλογή ενός αρχείου, δείτε επίσης την ειδική σελίδα για τους [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), καθώς πρόκειται για μια διαφορετική, αλλά στενά συνδεδεμένη, επιφάνεια χειρισμού αρχείων.



## References

- [1] [Objective-See - Απομακρυσμένη εκμετάλλευση Mac μέσω προσαρμοσμένων URL schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Παράκαμψη της πύλης: Μια πιο προσεκτική ματιά στα ελαττώματα του Gatekeeper στο macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Πώς το macOS ανοίγει ένα αρχείο με τη σωστή εφαρμογή](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Έλεγχος του LaunchServices στο macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple - Βασικές έννοιες του Launch Services](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer - Έρευνα εκτέλεσης εντολών μέσω του URL scheme του IINA](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA - Μη ασφαλής διαχείριση επιλογών mpv στο URL scheme του](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs - Η τεχνική ClickFix χρησιμοποιεί το Script Editor αντί για το Terminal](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple - Προστασίες του Terminal και των scripts](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}
