# macOS χειριστές εφαρμογών για επεκτάσεις αρχείων και URL schemes

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Πρόκειται για μια βάση δεδομένων με όλες τις εγκατεστημένες εφαρμογές στο macOS, από την οποία μπορείτε να αντλήσετε πληροφορίες για κάθε εγκατεστημένη εφαρμογή, όπως τα υποστηριζόμενα **URL schemes**, **document types**, **UTIs** και τους προεπιλεγμένους χειριστές.

Μπορείτε να κάνετε dump αυτής της βάσης δεδομένων με:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Ή χρησιμοποιώντας το εργαλείο [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Το **`/usr/libexec/lsd`** είναι ο εγκέφαλος της βάσης δεδομένων. Παρέχει **αρκετές υπηρεσίες XPC**, όπως `.lsd.installation`, `.lsd.open`, `.lsd.openurl` και άλλες. Ωστόσο, απαιτεί επίσης **ορισμένα entitlements** από τις εφαρμογές για να μπορούν να χρησιμοποιούν τις εκτεθειμένες λειτουργίες XPC, όπως τα `.launchservices.changedefaulthandler` ή `.launchservices.changeurlschemehandler`, για την αλλαγή των προεπιλεγμένων εφαρμογών για τύπους MIME ή σχήματα URL, καθώς και άλλες λειτουργίες.

Το **`/System/Library/CoreServices/launchservicesd`** παρέχει την υπηρεσία `com.apple.coreservices.launchservicesd` και μπορεί να ερωτηθεί για τη λήψη πληροφοριών σχετικά με εφαρμογές που εκτελούνται. Μπορείτε να το ερωτήσετε με το εργαλείο συστήματος **`/usr/bin/lsappinfo`** ή με το [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Από την οπτική του operator, έχετε υπόψη ότι συνήθως υπάρχουν **δύο χρήσιμες όψεις**:

- Η **βάση δεδομένων εγγραφών** που διαχειρίζεται το LaunchServices / `lsd` (και βασίζεται σε αρχεία `.csstore`).
- Οι **ενεργές προεπιλογές ανά χρήστη**, που αποθηκεύονται στον πίνακα `LSHandlers` του `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`.

Αυτή η διάκριση έχει σημασία: μια εφαρμογή μπορεί να είναι **καταχωρισμένη** ως εφαρμογή που μπορεί να χειριστεί έναν τύπο ή ένα σχήμα, αλλά η **τρέχουσα προεπιλογή** μπορεί να εξακολουθεί να είναι ένα άλλο bundle ID.

Σε πρόσφατες εκδόσεις του macOS, η αναζήτηση εφαρμογών προς καταχώριση δεν περιορίζεται στον φάκελο `/Applications`: εφαρμογές σε άλλους φακέλους που είναι ορατοί στο Spotlight και προσβάσιμοι, καθώς και σε προσαρτημένους/κοινόχρηστους τόμους, μπορούν να προστεθούν στο μητρώο. Επομένως, κατά τη διαλογή, διατηρήστε τις πληροφορίες `path` και τόμου από το `lsregister -dump` και μην υποθέτετε ότι η κατάργηση εγγραφής μιας εφαρμογής είναι μόνιμη όσο το bundle παραμένει ανιχνεύσιμο.<sup>[[4]](#references)</sup>

## Χειριστές εφαρμογών για επεκτάσεις αρχείων και σχήματα URL

Η ακόλουθη εντολή μπορεί να είναι χρήσιμη για τον εντοπισμό των εφαρμογών που μπορούν να ανοίγουν αρχεία ανάλογα με την επέκτασή τους:

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

Μπορείτε επίσης να ελέγξετε τις επεκτάσεις που υποστηρίζει μια εφαρμογή κάνοντας τα εξής:

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

## Απαρίθμηση των ενεργών χειριστών

Το πιο χρήσιμο αρχείο για τους **προεπιλεγμένους χειριστές του τρέχοντος χρήστη** είναι συνήθως:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Για να κάνετε dump τους handlers του **URL scheme** από αυτό:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Για να εξαγάγετε τους χειριστές **content-type / UTI**:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Για να επιλύσετε το δέντρο UTI ενός δείγματος αρχείου:

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

Αν θέλετε ένα πιο φιλικό CLI για να αναζητήσετε ή να αλλάξετε τις προεπιλογές:

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

Η επίλυση του handler έχει επίσης ένα επίπεδο **ειδικό για κάθε αρχείο**. Πριν χρησιμοποιήσει το UTI του αρχείου και την καθολική προεπιλογή του χρήστη, το LaunchServices ελέγχει το extended attribute `com.apple.LaunchServices.OpenWith`. Το Finder το δημιουργεί όταν επιλέγεται το **Always Open With** για ένα αρχείο· η τιμή του είναι ένα binary property list που περιέχει μια διαδρομή εφαρμογής, ένα bundle identifier και έναν επιλογέα έκδοσης.<sup>[[3]](#references)</sup>

Επιθεωρήστε και αποκωδικοποιήστε το χωρίς να εμπιστεύεστε την επέκταση αρχείου:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Αυτό είναι χρήσιμο όταν ένα μεμονωμένο δόλωμα ανοίγει με μια απροσδόκητη εφαρμογή, παρόλο που τα `duti`, `dutix` ή `LSHandlers` αναφέρουν μια ακίνδυνη καθολική προεπιλογή. Για ένα ελεγχόμενο εργαστήριο, η ακριβής αδιαφανής τιμή μπορεί να αντιγραφεί από ένα αρχείο που έχει ρυθμιστεί μέσω του Finder· η διαγραφή της επαναφέρει την κανονική επίλυση βάσει τύπου:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Ενδιαφέροντα κλειδιά του Info.plist

Κατά την αρχική αξιολόγηση ενός bundle εφαρμογής, αυτά τα κλειδιά είναι τα πιο σημαντικά:

- **`CFBundleDocumentTypes`**: ομάδες εγγράφων που δηλώνει ότι μπορεί να ανοίξει το bundle.
- **`LSItemContentTypes`**: ο **σύγχρονος / προτιμώμενος** τρόπος σύνδεσης τύπων εγγράφων με UTIs.
- **`LSHandlerRank`**: κατάταξη που χρησιμοποιείται από το LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: προσαρμοσμένα URI schemes που υλοποιεί η εφαρμογή.
- **`UTExportedTypeDeclarations`**: UTIs που **ανήκουν** στην εφαρμογή.
- **`UTImportedTypeDeclarations`**: UTIs που δεν ανήκουν στην εφαρμογή, αλλά θέλει να αναγνωρίζει το σύστημα.

Μια χρήσιμη εντολή για γρήγορη αξιολόγηση είναι η εξής:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Μια λεπτή αλλά σημαντική λεπτομέρεια: αν υπάρχει το **`LSItemContentTypes`**, παλαιότερα κλειδιά όπως τα **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** και **`CFBundleTypeOSTypes`** αποτελούν ουσιαστικά δεδομένα συμβατότητας για παλαιότερες εκδόσεις. Για την πραγματική επίλυση χειριστών, δώστε πρώτα προτεραιότητα στη διαδρομή UTI.

## Επιθετικές σημειώσεις

Δεν χρειάζεται να εκτελεστούν οι εφαρμογές για να αποκτήσουν ενδιαφέρον. Ένα αποθηκευμένο ή κλωνοποιημένο πακέτο `.app` μπορεί να **αναλυθεί αυτόματα από το `lsd` μόλις γραφτεί στον δίσκο**, ενώ οι δηλωμένοι τύποι εγγράφων / τα URL schemes του μπορεί να καταχωριστούν χωρίς ο χρήστης να εκκινήσει ποτέ το πακέτο.

Αυτό είναι χρήσιμο τόσο για **έρευνα persistence / hijacking** όσο και για **αλυσίδες αρχικής πρόσβασης**:

- Μια κακόβουλη εφαρμογή μπορεί να διεκδικήσει μια **σπάνια επέκταση** ή ένα **custom UTI** και να περιμένει μέχρι το θύμα να ανοίξει το αρχείο-δόλωμα.
- Μια κακόβουλη εφαρμογή μπορεί να καταχωρίσει ένα **custom URL scheme** στο οποίο υπάρχει πρόσβαση από browser, εφαρμογή Electron, έγγραφο Office, εφαρμογή συνομιλιών ή άλλη βοηθητική εφαρμογή.<sup>[[1]](#references)</sup>
- Για να διαχωρίσετε την κανονική επίλυση προεπιλογών από τη δοκιμή ενός συγκεκριμένου υποψήφιου χειριστή, καλέστε το scheme μέσω LaunchServices με `open 'targetscheme://host/path?value=test'` και, στη συνέχεια, στοχεύστε ένα συγκεκριμένο καταχωρισμένο bundle με `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Αυτό είναι χρήσιμο για τον έλεγχο του τρόπου με τον οποίο η εφαρμογή που λαμβάνει το αίτημα επικυρώνει και αποκωδικοποιεί στοιχεία URL που ελέγχονται από τον επιτιθέμενο.<sup>[[1]](#references)</sup>
- Αν επεξεργαστείτε ένα app bundle αφού το δημιουργήσετε, μπορείτε να αναγκάσετε το LaunchServices να το αναλύσει ξανά με:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Κατά τον έλεγχο ύποπτων bundles, δώστε ιδιαίτερη προσοχή στα εξής:

- **`LSHandlerRank=Owner`** για ασυνήθιστους τύπους.
- **Ευρείες** λίστες `CFBundleDocumentTypes` που δηλώνουν πολλές επεκτάσεις.
- **Helper / wrapper apps** των οποίων η μόνη ενδιαφέρουσα συμπεριφορά ενεργοποιείται μέσω ενός document ή URI handler.
- Αρχεία που μοιάζουν με συντομεύσεις (`.webloc`, `.inetloc`, `.fileloc`) και τελικά εκτελούν dispatch μέσω του LaunchServices. Για τεχνικές τύπου `.fileloc` και σχετικά θέματα με το Gatekeeper, δείτε [αυτή την άλλη σελίδα](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Αν ο στόχος σας είναι η παθητική εκτέλεση κώδικα απλώς με την περιήγηση σε έναν φάκελο ή την επιλογή ενός αρχείου, δείτε επίσης την ειδική σελίδα για τους [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), καθώς πρόκειται για διαφορετική, αλλά στενά σχετική, επιφάνεια file-handler.



## References

- [1] [Objective-See - Απομακρυσμένη εκμετάλλευση Mac μέσω προσαρμοσμένων URL schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Παρακάμπτοντας την πύλη: Μια πιο προσεκτική ματιά στα ελαττώματα του Gatekeeper στο macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Πώς το macOS ανοίγει ένα αρχείο με τη σωστή εφαρμογή](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Έλεγχος του LaunchServices στο macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
