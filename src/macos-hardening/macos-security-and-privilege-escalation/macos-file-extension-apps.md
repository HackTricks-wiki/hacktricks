# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Αυτή είναι μια βάση δεδομένων όλων των εγκατεστημένων εφαρμογών στο macOS που μπορεί να ερωτηθεί για να αποκτήσει πληροφορίες σχετικά με κάθε εγκατεστημένη εφαρμογή, όπως τα URL schemes που υποστηρίζει και τους MIME τύπους.

Είναι δυνατή η εξαγωγή αυτής της βάσης δεδομένων με:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ή χρησιμοποιώντας το εργαλείο [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** είναι ο εγκέφαλος της βάσης δεδομένων. Παρέχει **διάφορες υπηρεσίες XPC** όπως `.lsd.installation`, `.lsd.open`, `.lsd.openurl` και άλλες. Αλλά απαιτεί επίσης **ορισμένα δικαιώματα** για τις εφαρμογές ώστε να μπορούν να χρησιμοποιούν τις εκτεθειμένες λειτουργίες XPC, όπως `.launchservices.changedefaulthandler` ή `.launchservices.changeurlschemehandler` για να αλλάξουν τις προεπιλεγμένες εφαρμογές για τύπους mime ή σχήματα url και άλλα.

**`/System/Library/CoreServices/launchservicesd`** διεκδικεί την υπηρεσία `com.apple.coreservices.launchservicesd` και μπορεί να ερωτηθεί για να αποκτήσει πληροφορίες σχετικά με τις τρέχουσες εφαρμογές. Μπορεί να ερωτηθεί με το εργαλείο του συστήματος /**`usr/bin/lsappinfo`** ή με [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

## Χειριστές εφαρμογών για επεκτάσεις αρχείων & σχήματα URL

Η παρακάτω γραμμή μπορεί να είναι χρήσιμη για να βρείτε τις εφαρμογές που μπορούν να ανοίξουν αρχεία ανάλογα με την επέκταση:
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
```
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
{{#include ../../banners/hacktricks-training.md}}
