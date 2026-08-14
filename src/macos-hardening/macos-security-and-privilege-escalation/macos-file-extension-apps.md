# macOS handlers εφαρμογών για File Extension και URL scheme

{{#include ../../banners/hacktricks-training.md}}

## Βάση δεδομένων LaunchServices

Πρόκειται για μια βάση δεδομένων όλων των εγκατεστημένων εφαρμογών στο macOS, την οποία μπορείτε να αναζητήσετε για να λάβετε πληροφορίες σχετικά με κάθε εγκατεστημένη εφαρμογή, όπως τα υποστηριζόμενα **URL schemes**, οι **document types**, τα **UTIs** και οι προεπιλεγμένοι handlers.

Είναι δυνατή η εξαγωγή αυτής της βάσης δεδομένων με:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ή χρησιμοποιώντας το tool [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Το **`/usr/libexec/lsd`** είναι ο πυρήνας της database. Παρέχει **several XPC services**, όπως τα `.lsd.installation`, `.lsd.open`, `.lsd.openurl` και άλλα. Ωστόσο, **απαιτεί επίσης ορισμένα entitlements** για τις εφαρμογές, ώστε να μπορούν να χρησιμοποιούν τις εκτεθειμένες XPC functionalities, όπως τα `.launchservices.changedefaulthandler` ή `.launchservices.changeurlschemehandler`, για την αλλαγή των default εφαρμογών για MIME types ή URL schemes, καθώς και άλλα.

Το **`/System/Library/CoreServices/launchservicesd`** δηλώνει το service `com.apple.coreservices.launchservicesd` και μπορεί να γίνει query για τη λήψη πληροφοριών σχετικά με τις εφαρμογές που εκτελούνται. Μπορεί να γίνει query με το system tool **`/usr/bin/lsappinfo`** ή με το [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Από την οπτική γωνία ενός operator, έχετε υπόψη ότι συνήθως υπάρχουν **δύο χρήσιμες views**:

- Η **registration database** που διαχειρίζεται το LaunchServices / `lsd` και υποστηρίζεται από αρχεία `.csstore`.
- Τα **per-user effective defaults** που αποθηκεύονται στο `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, μέσα στο array `LSHandlers`.

Αυτή η διάκριση είναι σημαντική: μια εφαρμογή μπορεί να είναι **registered** ως ικανή να χειρίζεται έναν τύπο ή scheme, αλλά το **τρέχον default** μπορεί να είναι ένα άλλο bundle ID.

Σε πρόσφατες εκδόσεις του macOS, η ανακάλυψη registrations δεν περιορίζεται στο `/Applications`: εφαρμογές σε άλλους φακέλους που είναι ορατοί στο Spotlight και προσβάσιμοι, καθώς και σε mounted/shared volumes, μπορούν να εισέλθουν στο registry. Επομένως, κατά το triage, διατηρείτε τις πληροφορίες `path` και volume από το `lsregister -dump` και μην υποθέτετε ότι το unregistering μιας εφαρμογής είναι μόνιμο όσο το bundle παραμένει discoverable.<sup>[[4]](#references)</sup>

## File Extension & URL scheme app handlers

Η ακόλουθη γραμμή μπορεί να είναι χρήσιμη για την εύρεση των εφαρμογών που μπορούν να ανοίξουν αρχεία, ανάλογα με το extension:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Ή χρησιμοποιήστε κάτι όπως το [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Μπορείτε επίσης να ελέγξετε τις επεκτάσεις που υποστηρίζει μια εφαρμογή κάνοντας:
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
## Enumerating effective handlers

Το πιο χρήσιμο αρχείο για τις **προεπιλογές του τρέχοντος χρήστη** είναι συνήθως:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Για να κάνετε dump τους χειριστές **URL scheme** από αυτό:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Για την **εξαγωγή των χειριστών content-type / UTI**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Για να προσδιορίσετε το δέντρο UTI ενός δείγματος αρχείου:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Αν θέλετε ένα πιο φιλικό CLI για να ελέγχετε ή να αλλάζετε τις προεπιλογές:
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
### Ανά αρχείο overrides `Open With`

Η επίλυση handler διαθέτει επίσης ένα **file-specific** επίπεδο. Πριν καταφύγει στο UTI του αρχείου και στο global default του χρήστη, το LaunchServices ελέγχει το extended attribute `com.apple.LaunchServices.OpenWith`. Το Finder το δημιουργεί όταν επιλέγεται το **Always Open With** για ένα αρχείο· η τιμή του είναι ένα binary property list που περιέχει ένα application path, bundle identifier και version selector.<sup>[[3]](#references)</sup>

Επιθεωρήστε και αποκωδικοποιήστε το χωρίς να εμπιστεύεστε το filename extension:
```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```
Αυτό είναι χρήσιμο όταν ένα single lure ανοίγει με μια απροσδόκητη εφαρμογή, παρόλο που τα `duti`, `dutix` ή `LSHandlers` αναφέρουν ένα benign global default. Σε ένα controlled lab, η ακριβής opaque value μπορεί να αντιγραφεί από ένα αρχείο που έχει ρυθμιστεί μέσω του Finder· η διαγραφή της επαναφέρει τη φυσιολογική επίλυση βάσει τύπου:
```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```
## Ενδιαφέροντα κλειδιά του Info.plist

Κατά το triaging ενός application bundle, αυτά τα κλειδιά έχουν τη μεγαλύτερη σημασία:

- **`CFBundleDocumentTypes`**: ομάδες εγγράφων που το bundle δηλώνει ότι μπορεί να ανοίξει.
- **`LSItemContentTypes`**: ο **σύγχρονος / προτιμώμενος** τρόπος σύνδεσης τύπων εγγράφων με UTIs.
- **`LSHandlerRank`**: η κατάταξη που χρησιμοποιεί το LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI schemes που υλοποιεί η εφαρμογή.
- **`UTExportedTypeDeclarations`**: UTIs που η εφαρμογή **κατέχει**.
- **`UTImportedTypeDeclarations`**: UTIs που η εφαρμογή δεν κατέχει, αλλά θέλει να αναγνωρίζει το σύστημα.

Μια χρήσιμη γρήγορη εντολή triage είναι:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Μια λεπτομέρεια που είναι διακριτική αλλά σημαντική: αν υπάρχει το **`LSItemContentTypes`**, παλαιότερα keys όπως τα **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** και **`CFBundleTypeOSTypes`** αποτελούν ουσιαστικά legacy compatibility data. Για την πραγματική επίλυση των handlers, εστιάστε πρώτα στη διαδρομή UTI.

## Επιθετικές σημειώσεις

Οι εφαρμογές δεν χρειάζεται να εκτελεστούν για να αποκτήσουν ενδιαφέρον. Ένα dropped ή cloned `.app` bundle μπορεί να γίνει **automatically parsed από το `lsd` μόλις εγγραφεί στον δίσκο**, ενώ οι δηλωμένοι τύποι εγγράφων / URL schemes μπορεί να καταχωριστούν χωρίς ο χρήστης να εκκινήσει ποτέ το bundle.

Αυτό είναι χρήσιμο τόσο για **έρευνα persistence / hijacking** όσο και για **initial-access chains**:

- Μια malicious app μπορεί να διεκδικήσει ένα **σπάνιο extension** ή ένα **custom UTI** και να περιμένει μέχρι το θύμα να ανοίξει το lure file.
- Μια malicious app μπορεί να καταχωρίσει ένα **custom URL scheme**, προσβάσιμο από browser, Electron app, office document, chat client ή άλλη helper app.<sup>[[1]](#references)</sup>
- Για να διαχωρίσετε τη φυσιολογική default resolution από τον έλεγχο ενός συγκεκριμένου candidate handler, καλέστε το scheme μέσω LaunchServices με `open 'targetscheme://host/path?value=test'` και, στη συνέχεια, στοχεύστε ένα συγκεκριμένο registered bundle με `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Αυτό είναι χρήσιμο για auditing του τρόπου με τον οποίο η receiving app επικυρώνει και αποκωδικοποιεί attacker-controlled URL components.<sup>[[1]](#references)</sup>
- Αν επεξεργαστείτε ένα app bundle μετά το building του, μπορείτε να υποχρεώσετε το LaunchServices να το κάνει re-parse με:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Κατά τη δοκιμή ύποπτων bundles, δώστε ιδιαίτερη προσοχή στα εξής:

- **`LSHandlerRank=Owner`** σε ασυνήθιστους τύπους.
- Ευρείς πίνακες **`CFBundleDocumentTypes`** που δηλώνουν πολλές επεκτάσεις.
- **Helper / wrapper apps** των οποίων η μόνη ενδιαφέρουσα συμπεριφορά βρίσκεται πίσω από έναν document ή URI handler.
- Αρχεία που μοιάζουν με shortcuts (`.webloc`, `.inetloc`, `.fileloc`) και τελικά κάνουν dispatch στο LaunchServices. Για τεχνικές τύπου `.fileloc` και σχετικά Gatekeeper angles, δείτε [αυτή την άλλη σελίδα](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Αν ο στόχος σας είναι παθητικό code-execution μόνο με την περιήγηση σε έναν φάκελο ή την επιλογή ενός αρχείου, ελέγξτε επίσης την ειδική σελίδα για [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), καθώς πρόκειται για διαφορετική αλλά στενά συνδεδεμένη επιφάνεια file-handler.



## References

- [1] [Objective-See - Απομακρυσμένη εκμετάλλευση Mac μέσω Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Παράκαμψη του Gate: Μια πιο προσεκτική ματιά στα ελαττώματα του Gatekeeper στο macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Πώς το macOS ανοίγει ένα αρχείο με τη σωστή εφαρμογή](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Έλεγχος του LaunchServices στο macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
