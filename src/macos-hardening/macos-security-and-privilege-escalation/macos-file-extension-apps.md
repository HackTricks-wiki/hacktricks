# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Αυτή είναι μια βάση δεδομένων με όλες τις εγκατεστημένες εφαρμογές στο macOS, η οποία μπορεί να ερωτηθεί για να ληφθούν πληροφορίες σχετικά με κάθε εγκατεστημένη εφαρμογή, όπως τα υποστηριζόμενα **URL schemes**, **document types**, **UTIs**, και τα προεπιλεγμένα handlers.

Είναι δυνατό να γίνει dump αυτής της βάσης δεδομένων με:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ή χρησιμοποιώντας το εργαλείο [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** είναι ο πυρήνας της βάσης δεδομένων. Παρέχει **αρκετές XPC services** όπως `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, και περισσότερες. Αλλά επίσης **απαιτεί ορισμένα entitlements** από τις applications ώστε να μπορούν να χρησιμοποιήσουν τις exposed XPC functionalities, όπως `.launchservices.changedefaulthandler` ή `.launchservices.changeurlschemehandler` για να αλλάξουν default apps για MIME types ή URL schemes και άλλα.

**`/System/Library/CoreServices/launchservicesd`** δηλώνει το service `com.apple.coreservices.launchservicesd` και μπορεί να ερωτηθεί για να πάρεις πληροφορίες σχετικά με τις running applications. Μπορεί να ερωτηθεί με το system tool **`/usr/bin/lsappinfo`** ή με [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Από οπτική operator, να θυμάσαι ότι συνήθως υπάρχουν **δύο χρήσιμες προβολές**:

- Η **registration database** που διαχειρίζεται το LaunchServices / `lsd` (υποστηρίζεται από `.csstore` files).
- Τα **per-user effective defaults** που αποθηκεύονται στο `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` μέσα στον πίνακα `LSHandlers`.

Αυτή η διάκριση έχει σημασία: μια application μπορεί να είναι **registered** ως ικανή να χειριστεί έναν τύπο ή scheme, αλλά το **current default** μπορεί να είναι ακόμα άλλο bundle ID.

## File Extension & URL scheme app handlers

Η ακόλουθη γραμμή μπορεί να είναι χρήσιμη για να βρεις τις applications που μπορούν να ανοίξουν files ανάλογα με την extension:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Ή χρησιμοποίησε κάτι σαν [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Μπορείτε επίσης να ελέγξετε τις επεκτάσεις που υποστηρίζονται από μια εφαρμογή κάνοντας:
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
## Απαρίθμηση effective handlers

Το πιο χρήσιμο αρχείο για τα **current user's defaults** είναι συνήθως:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Για να κάνετε dump των handlers **URL scheme** από αυτό:
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
Αν θέλεις ένα πιο φιλικό CLI για να κάνεις query ή να αλλάξεις defaults:
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
## Interesting Info.plist keys

Κατά το triage ενός application bundle, αυτά τα keys έχουν τη μεγαλύτερη σημασία:

- **`CFBundleDocumentTypes`**: ομάδες εγγράφων που το bundle δηλώνει ότι μπορεί να ανοίξει.
- **`LSItemContentTypes`**: ο **modern / preferred** τρόπος για να συνδέεις document types με UTIs.
- **`LSHandlerRank`**: ranking που χρησιμοποιείται από το LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI schemes που υλοποιεί το app.
- **`UTExportedTypeDeclarations`**: UTIs που το app **owns**.
- **`UTImportedTypeDeclarations`**: UTIs που το app δεν owns αλλά θέλει το σύστημα να αναγνωρίζει.

Ένα χρήσιμο quick triage command είναι:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Μια λεπτή αλλά σημαντική λεπτομέρεια: αν υπάρχει το **`LSItemContentTypes`**, τα παλαιότερα keys όπως **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** και **`CFBundleTypeOSTypes`** είναι ουσιαστικά legacy δεδομένα συμβατότητας. Για την πραγματική επίλυση handler, δώσε πρώτα προτεραιότητα στο UTI path.

## Επιθετικές σημειώσεις

Οι εφαρμογές δεν χρειάζεται να εκτελεστούν για να γίνουν ενδιαφέρουσες. Ένα dropped ή cloned `.app` bundle μπορεί να **αναλυθεί αυτόματα από το `lsd` μόλις γραφτεί στο disk**, και οι δηλωμένοι document types / URL schemes μπορεί να εγγραφούν χωρίς ο χρήστης να εκκινήσει ποτέ το bundle.

Αυτό είναι χρήσιμο τόσο για έρευνα **persistence / hijacking** όσο και για **initial-access chains**:

- Μια κακόβουλη app μπορεί να διεκδικήσει μια **σπάνια επέκταση** ή ένα **custom UTI** και να περιμένει το θύμα να ανοίξει το lure file.
- Μια κακόβουλη app μπορεί να καταχωρίσει ένα **custom URL scheme** προσβάσιμο από browser, Electron app, office document, chat client ή κάποιο άλλο helper app.
- Αν επεξεργαστείς ένα app bundle μετά το build, μπορείς να αναγκάσεις το LaunchServices να το ξανα-αναλύσει με:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Όταν ελέγχετε ύποπτα bundles, δώστε ιδιαίτερη προσοχή στα:

- **`LSHandlerRank=Owner`** σε ασυνήθιστους τύπους.
- **Ευρείς `CFBundleDocumentTypes`** πίνακες που ισχυρίζονται πολλές επεκτάσεις.
- **Helper / wrapper apps** των οποίων η μόνη ενδιαφέρουσα συμπεριφορά βρίσκεται πίσω από έναν document ή URI handler.
- **Αρχεία τύπου shortcut** (`.webloc`, `.inetloc`, `.fileloc`) που τελικά δρομολογούν στο LaunchServices. Για `.fileloc`-style τεχνικές και σχετικές πλευρές του Gatekeeper, δείτε [this other page](macos-security-protections/macos-fs-tricks/README.md).

Αν ο στόχος σας είναι passive code-execution απλώς από το browsing σε έναν φάκελο ή την επιλογή ενός αρχείου, ελέγξτε επίσης την ειδική σελίδα για [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), καθώς αυτό είναι ένα διαφορετικό αλλά στενά σχετικό file-handler surface.

## References

- [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
{{#include ../../banners/hacktricks-training.md}}
