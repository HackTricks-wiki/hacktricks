# Χειριστές εφαρμογών για επεκτάσεις αρχείων και URL schemes στο macOS

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Πρόκειται για μια database όλων των εγκατεστημένων εφαρμογών στο macOS, από την οποία μπορούν να ανακτηθούν πληροφορίες για κάθε εγκατεστημένη εφαρμογή, όπως τα υποστηριζόμενα **URL schemes**, οι **document types**, τα **UTIs** και οι προεπιλεγμένοι handlers.

Είναι δυνατή η εκτέλεση dump αυτής της database με:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ή χρησιμοποιώντας το εργαλείο [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Το **`/usr/libexec/lsd`** είναι ο εγκέφαλος της βάσης δεδομένων. Παρέχει **αρκετές XPC services**, όπως τα `.lsd.installation`, `.lsd.open`, `.lsd.openurl` και άλλα. Ωστόσο, **απαιτεί επίσης ορισμένα entitlements** για τις εφαρμογές, ώστε αυτές να μπορούν να χρησιμοποιούν τις εκτεθειμένες λειτουργίες XPC, όπως τα `.launchservices.changedefaulthandler` ή `.launchservices.changeurlschemehandler`, για την αλλαγή των προεπιλεγμένων εφαρμογών για τύπους MIME ή URL schemes, καθώς και άλλα.

Το **`/System/Library/CoreServices/launchservicesd`** δηλώνει το service `com.apple.coreservices.launchservicesd` και μπορεί να ερωτηθεί για τη λήψη πληροφοριών σχετικά με τις εφαρμογές που εκτελούνται. Μπορεί να ερωτηθεί με το system tool **`/usr/bin/lsappinfo`** ή με το [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Από την οπτική γωνία ενός operator, έχετε υπόψη ότι συνήθως υπάρχουν **δύο χρήσιμες όψεις**:

- Η **registration database** που διαχειρίζεται το LaunchServices / `lsd` (και υποστηρίζεται από αρχεία `.csstore`).
- Τα **effective defaults ανά χρήστη**, που αποθηκεύονται στο `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, μέσα στον πίνακα `LSHandlers`.

Αυτή η διάκριση έχει σημασία: μια εφαρμογή μπορεί να είναι **registered** ως ικανή να διαχειρίζεται έναν τύπο ή scheme, αλλά το **τρέχον default** μπορεί να εξακολουθεί να είναι ένα άλλο bundle ID.

## App handlers για επεκτάσεις αρχείων και URL schemes

Η παρακάτω γραμμή μπορεί να είναι χρήσιμη για την εύρεση των εφαρμογών που μπορούν να ανοίξουν αρχεία, ανάλογα με την extension:
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
## Enumerating effective handlers

Το πιο χρήσιμο αρχείο για τις **προεπιλογές του τρέχοντος χρήστη** είναι συνήθως:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Για να κάνετε dump τους handlers του **URL scheme** από αυτό:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Για την εξαγωγή των **content-type / UTI** handlers:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Για την επίλυση του δέντρου UTI ενός δείγματος αρχείου:
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
## Ενδιαφέροντα κλειδιά Info.plist

Κατά την αρχική ανάλυση ενός application bundle, αυτά τα κλειδιά έχουν τη μεγαλύτερη σημασία:

- **`CFBundleDocumentTypes`**: ομάδες εγγράφων που δηλώνει το bundle ότι μπορεί να ανοίξει.
- **`LSItemContentTypes`**: ο **σύγχρονος / προτιμώμενος** τρόπος σύνδεσης τύπων εγγράφων με UTIs.
- **`LSHandlerRank`**: κατάταξη που χρησιμοποιείται από το LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI schemes που υλοποιούνται από την εφαρμογή.
- **`UTExportedTypeDeclarations`**: UTIs που **ανήκουν** στην εφαρμογή.
- **`UTImportedTypeDeclarations`**: UTIs που δεν ανήκουν στην εφαρμογή, αλλά η εφαρμογή θέλει να αναγνωρίζει το σύστημα.

Μια χρήσιμη εντολή για γρήγορη αρχική ανάλυση είναι:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Μια λεπτομέρεια που είναι διακριτική αλλά σημαντική: αν υπάρχει το **`LSItemContentTypes`**, παλαιότερα keys όπως τα **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** και **`CFBundleTypeOSTypes`** αποτελούν ουσιαστικά legacy compatibility data. Για την πραγματική επίλυση handlers, εστιάστε πρώτα στο μονοπάτι UTI.

## Offensive notes

Οι εφαρμογές δεν χρειάζεται να εκτελεστούν για να αποκτήσουν ενδιαφέρον. Ένα dropped ή cloned `.app` bundle μπορεί να γίνει **parse αυτόματα από το `lsd` μόλις εγγραφεί στον δίσκο**, ενώ οι δηλωμένοι document types / URL schemes μπορεί να καταχωριστούν χωρίς ο χρήστης να εκκινήσει ποτέ το bundle.

Αυτό είναι χρήσιμο τόσο για **persistence / hijacking research** όσο και για **initial-access chains**:

- Ένα malicious app μπορεί να διεκδικήσει ένα **σπάνιο extension** ή ένα **custom UTI** και να περιμένει από το θύμα να ανοίξει το lure file.
- Ένα malicious app μπορεί να καταχωρίσει ένα **custom URL scheme**, προσβάσιμο από browser, Electron app, office document, chat client ή άλλο helper app.<sup>[[1]](#references)</sup>
- Αν επεξεργαστείτε ένα app bundle μετά το building του, μπορείτε να αναγκάσετε το LaunchServices να το κάνει re-parse με:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Κατά τον έλεγχο ύποπτων bundles, δώστε ιδιαίτερη προσοχή στα εξής:

- **`LSHandlerRank=Owner`** σε μη συνηθισμένους τύπους.
- **Ευρείς πίνακες `CFBundleDocumentTypes`** που δηλώνουν πολλές επεκτάσεις.
- **Helper / wrapper apps** των οποίων η μοναδική ενδιαφέρουσα συμπεριφορά ενεργοποιείται μέσω document ή URI handler.
- **Αρχεία που μοιάζουν με shortcuts** (`.webloc`, `.inetloc`, `.fileloc`) και τελικά κάνουν dispatch στο LaunchServices. Για τεχνικές τύπου `.fileloc` και σχετικές προσεγγίσεις στο Gatekeeper, δείτε [αυτήν τη σελίδα](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Αν ο στόχος σας είναι παθητικό code-execution απλώς με την περιήγηση σε έναν φάκελο ή την επιλογή ενός αρχείου, δείτε επίσης την ειδική σελίδα για [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), καθώς πρόκειται για διαφορετική αλλά στενά σχετιζόμενη επιφάνεια file-handler.

## Αναφορές

- [1] [Objective-See - Απομακρυσμένη εκμετάλλευση Mac μέσω Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Παράκαμψη του Gate: Μια πιο προσεκτική ματιά στα ελαττώματα του Gatekeeper στο macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
