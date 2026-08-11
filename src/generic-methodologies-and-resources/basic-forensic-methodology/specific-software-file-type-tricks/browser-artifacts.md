# Αντικείμενα Browser

{{#include ../../../banners/hacktricks-training.md}}

## Αντικείμενα Browser <a href="#id-3def" id="id-3def"></a>

Τα αντικείμενα Browser περιλαμβάνουν διάφορους τύπους δεδομένων που αποθηκεύονται από τους web browsers, όπως ιστορικό πλοήγησης, σελιδοδείκτες και δεδομένα cache. Αυτά τα αντικείμενα διατηρούνται σε συγκεκριμένους φακέλους μέσα στο λειτουργικό σύστημα, με διαφορετική τοποθεσία και ονομασία ανά browser, αλλά γενικά αποθηκεύουν παρόμοιους τύπους δεδομένων.

Ακολουθεί μια σύνοψη των πιο συνηθισμένων browser artifacts:

- **Ιστορικό πλοήγησης**: Καταγράφει τις επισκέψεις του χρήστη σε websites και είναι χρήσιμο για τον εντοπισμό επισκέψεων σε malicious sites.
- **Δεδομένα Autocomplete**: Προτάσεις που βασίζονται σε συχνές αναζητήσεις και παρέχουν χρήσιμες πληροφορίες όταν συνδυάζονται με το ιστορικό πλοήγησης.
- **Σελιδοδείκτες**: Websites που αποθηκεύονται από τον χρήστη για γρήγορη πρόσβαση.
- **Extensions και Add-ons**: Browser extensions ή add-ons που έχουν εγκατασταθεί από τον χρήστη.
- **Cache**: Αποθηκεύει web περιεχόμενο (π.χ. εικόνες, αρχεία JavaScript) για τη βελτίωση του χρόνου φόρτωσης των websites και είναι πολύτιμο για forensic analysis.
- **Logins**: Αποθηκευμένα credentials σύνδεσης.
- **Favicons**: Εικονίδια που σχετίζονται με websites και εμφανίζονται σε tabs και σελιδοδείκτες, χρήσιμα για πρόσθετες πληροφορίες σχετικά με τις επισκέψεις του χρήστη.
- **Browser Sessions**: Δεδομένα που σχετίζονται με ανοιχτές browser sessions.
- **Downloads**: Καταγραφές αρχείων που κατέβηκαν μέσω του browser.
- **Form Data**: Πληροφορίες που εισήχθησαν σε web forms και αποθηκεύτηκαν για μελλοντικές προτάσεις autofill.
- **Thumbnails**: Εικόνες προεπισκόπησης websites.
- **Custom Dictionary.txt**: Λέξεις που προστέθηκαν από τον χρήστη στο dictionary του browser.

## Firefox

Ο Firefox οργανώνει τα δεδομένα του χρήστη μέσα σε profiles, τα οποία αποθηκεύονται σε συγκεκριμένες τοποθεσίες ανάλογα με το λειτουργικό σύστημα:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Ένα αρχείο `profiles.ini` μέσα σε αυτούς τους φακέλους καταγράφει τα user profiles. Τα δεδομένα κάθε profile αποθηκεύονται σε έναν φάκελο που ονομάζεται σύμφωνα με τη μεταβλητή `Path` μέσα στο `profiles.ini`, ο οποίος βρίσκεται στον ίδιο κατάλογο με το ίδιο το `profiles.ini`. Αν ο φάκελος ενός profile λείπει, ενδέχεται να έχει διαγραφεί.

Μέσα σε κάθε φάκελο profile μπορείτε να βρείτε αρκετά σημαντικά αρχεία:<sup>[[1]](#references)</sup>

- **places.sqlite**: Αποθηκεύει ιστορικό, σελιδοδείκτες και downloads. Εργαλεία όπως το [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) στα Windows μπορούν να προσπελάσουν τα δεδομένα ιστορικού.
- Χρησιμοποιήστε συγκεκριμένα SQL queries για την εξαγωγή πληροφοριών ιστορικού και downloads.
- **bookmarkbackups**: Περιέχει backup των σελιδοδεικτών.
- **formhistory.sqlite**: Αποθηκεύει δεδομένα web forms.
- **handlers.json**: Διαχειρίζεται protocol handlers.
- **persdict.dat**: Λέξεις του custom dictionary.
- **addons.json** και **extensions.sqlite**: Πληροφορίες σχετικά με τα εγκατεστημένα add-ons και extensions.
- **cookies.sqlite**: Αποθήκευση cookies, με το [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) διαθέσιμο για inspection στα Windows.
- **cache2/entries** ή **startupCache**: Δεδομένα cache, προσβάσιμα μέσω εργαλείων όπως το [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Αποθηκεύει favicons.
- **prefs.js**: Ρυθμίσεις και preferences του χρήστη.
- **downloads.sqlite**: Παλαιότερη βάση δεδομένων downloads, η οποία πλέον έχει ενσωματωθεί στο places.sqlite.
- **thumbnails**: Thumbnails websites.
- **logins.json**: Κρυπτογραφημένες πληροφορίες σύνδεσης.
- **key4.db** ή **key3.db**: Αποθηκεύει encryption keys για την προστασία ευαίσθητων πληροφοριών.

Επιπλέον, ο έλεγχος των anti-phishing settings του browser μπορεί να γίνει με αναζήτηση εγγραφών `browser.safebrowsing` στο `prefs.js`, οι οποίες υποδεικνύουν αν οι λειτουργίες safe browsing είναι ενεργοποιημένες ή απενεργοποιημένες.<sup>[[2]](#references)</sup>

Για να προσπαθήσετε να αποκρυπτογραφήσετε το master password, μπορείτε να χρησιμοποιήσετε το [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Με το ακόλουθο script και call μπορείτε να καθορίσετε ένα password file για brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Artifacts φυλλομετρητών - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Το Google Chrome αποθηκεύει τα προφίλ χρηστών σε συγκεκριμένες τοποθεσίες, ανάλογα με το λειτουργικό σύστημα:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Μέσα σε αυτούς τους καταλόγους, τα περισσότερα δεδομένα χρηστών μπορούν να βρεθούν στους φακέλους **Default/** ή **ChromeDefaultData/**. Τα ακόλουθα αρχεία περιέχουν σημαντικά δεδομένα:<sup>[[1]](#references)</sup>

- **History**: Περιέχει URL, λήψεις και λέξεις-κλειδιά αναζητήσεων. Στα Windows, μπορεί να χρησιμοποιηθεί το [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) για την ανάγνωση του ιστορικού. Η στήλη "Transition Type" έχει διάφορες σημασίες, όπως κλικ χρηστών σε συνδέσμους, πληκτρολογημένα URL, υποβολές φορμών και επαναφορτώσεις σελίδων.
- **Cookies**: Αποθηκεύει cookies. Για επιθεώρηση, είναι διαθέσιμο το [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Περιέχει αποθηκευμένα δεδομένα. Για επιθεώρηση, οι χρήστες Windows μπορούν να χρησιμοποιήσουν το [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Οι εφαρμογές desktop που βασίζονται στο Electron (π.χ. το Discord) χρησιμοποιούν επίσης το Chromium Simple Cache και αφήνουν πλούσια artifacts στον δίσκο. Δείτε:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Σελιδοδείκτες χρηστών.
- **Web Data**: Περιέχει ιστορικό φορμών.
- **Favicons**: Αποθηκεύει favicons ιστοτόπων.
- **Login Data**: Περιλαμβάνει διαπιστευτήρια σύνδεσης, όπως usernames και passwords.
- **Current Session**/**Current Tabs**: Δεδομένα σχετικά με την τρέχουσα συνεδρία περιήγησης και τις ανοιχτές καρτέλες.
- **Last Session**/**Last Tabs**: Πληροφορίες σχετικά με τους ιστοτόπους που ήταν ενεργοί κατά την τελευταία συνεδρία πριν κλείσει το Chrome.
- **Extensions**: Κατάλογοι για browser extensions και addons.
- **Thumbnails**: Αποθηκεύει thumbnails ιστοτόπων.
- **Preferences**: Ένα αρχείο με πλούσιες πληροφορίες, όπως ρυθμίσεις για plugins, extensions, pop-ups, ειδοποιήσεις και άλλα.
- **Ενσωματωμένο anti-phishing του browser**: Για να ελέγξετε αν είναι ενεργοποιημένη η προστασία anti-phishing και από malware, εκτελέστε `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Αναζητήστε `{"enabled: true,"}` στην έξοδο.<sup>[[2]](#references)</sup>

## **Ανάκτηση δεδομένων SQLite DB**

Όπως μπορείτε να παρατηρήσετε στις προηγούμενες ενότητες, τόσο το Chrome όσο και το Firefox χρησιμοποιούν βάσεις δεδομένων **SQLite** για την αποθήκευση δεδομένων. Είναι δυνατή η **ανάκτηση διαγραμμένων εγγραφών με χρήση του εργαλείου** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ή** του [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Το Internet Explorer 11 διαχειρίζεται τα δεδομένα και τα metadata του σε διάφορες τοποθεσίες, διευκολύνοντας τον διαχωρισμό των αποθηκευμένων πληροφοριών και των αντίστοιχων λεπτομερειών τους για εύκολη πρόσβαση και διαχείριση.

### Αποθήκευση metadata

Τα metadata του Internet Explorer αποθηκεύονται στο `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (όπου το VX είναι V01, V16 ή V24). Το συνοδευτικό αρχείο `V01.log` ενδέχεται να εμφανίζει ασυμφωνίες στον χρόνο τροποποίησης σε σχέση με το `WebcacheVX.data`, υποδεικνύοντας την ανάγκη επιδιόρθωσης με χρήση του `esentutl /r V01 /d`. Αυτά τα metadata, τα οποία φιλοξενούνται σε μια βάση δεδομένων ESE, μπορούν να ανακτηθούν και να επιθεωρηθούν με εργαλεία όπως τα photorec και [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), αντίστοιχα. Στον πίνακα **Containers**, μπορεί κανείς να διακρίνει τους συγκεκριμένους πίνακες ή containers όπου αποθηκεύεται κάθε τμήμα δεδομένων, συμπεριλαμβανομένων των λεπτομερειών cache για άλλα εργαλεία της Microsoft, όπως το Skype.

### Επιθεώρηση cache

Το εργαλείο [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) επιτρέπει την επιθεώρηση της cache και απαιτεί την τοποθεσία του φακέλου εξαγωγής των δεδομένων cache. Τα metadata για την cache περιλαμβάνουν το όνομα αρχείου, τον κατάλογο, τον αριθμό προσβάσεων, την προέλευση του URL και timestamps που υποδεικνύουν τους χρόνους δημιουργίας, πρόσβασης, τροποποίησης και λήξης της cache.

### Διαχείριση cookies

Τα cookies μπορούν να εξεταστούν με χρήση του [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), με metadata που περιλαμβάνουν ονόματα, URL, αριθμούς προσβάσεων και διάφορες χρονικές λεπτομέρειες. Τα persistent cookies αποθηκεύονται στο `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, ενώ τα session cookies βρίσκονται στη μνήμη.

### Λεπτομέρειες λήψεων

Τα metadata των λήψεων είναι προσβάσιμα μέσω του [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), με συγκεκριμένα containers που περιέχουν δεδομένα όπως URL, τύπο αρχείου και τοποθεσία λήψης. Τα φυσικά αρχεία μπορούν να βρεθούν στο `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Ιστορικό περιήγησης

Για την εξέταση του ιστορικού περιήγησης, μπορεί να χρησιμοποιηθεί το [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), το οποίο απαιτεί την τοποθεσία των εξαχθέντων αρχείων ιστορικού και τη ρύθμιση για το Internet Explorer. Τα metadata εδώ περιλαμβάνουν χρόνους τροποποίησης και πρόσβασης, καθώς και αριθμούς προσβάσεων. Τα αρχεία ιστορικού βρίσκονται στο `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Πληκτρολογημένα URL

Τα πληκτρολογημένα URL και οι χρόνοι χρήσης τους αποθηκεύονται στο registry, στο `NTUSER.DAT`, στις τοποθεσίες `Software\Microsoft\InternetExplorer\TypedURLs` και `Software\Microsoft\InternetExplorer\TypedURLsTime`, καταγράφοντας τα τελευταία 50 URL που εισήγαγε ο χρήστης και τους χρόνους τελευταίας εισαγωγής τους.

## Microsoft Edge

Το Microsoft Edge αποθηκεύει δεδομένα χρηστών στο `%userprofile%\Appdata\Local\Packages`. Οι διαδρομές για διάφορους τύπους δεδομένων είναι:<sup>[[1]](#references)</sup>

- **Διαδρομή προφίλ**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Ιστορικό, cookies και λήψεις**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Ρυθμίσεις, σελιδοδείκτες και λίστα ανάγνωσης**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Τελευταίες ενεργές συνεδρίες**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Τα δεδομένα του Safari αποθηκεύονται στο `/Users/$User/Library/Safari`. Τα βασικά αρχεία περιλαμβάνουν:<sup>[[3]](#references)</sup>

- **History.db**: Περιέχει τους πίνακες `history_visits` και `history_items` με URL και timestamps επισκέψεων. Χρησιμοποιήστε το `sqlite3` για την εκτέλεση ερωτημάτων.
- **Downloads.plist**: Πληροφορίες σχετικά με αρχεία που έχουν ληφθεί.
- **Bookmarks.plist**: Αποθηκεύει URL σελιδοδεικτών.
- **TopSites.plist**: Ιστότοποι με τις περισσότερες επισκέψεις.
- **Extensions.plist**: Λίστα των browser extensions του Safari. Χρησιμοποιήστε τα `plutil` ή `pluginkit` για ανάκτηση.
- **UserNotificationPermissions.plist**: Domains που επιτρέπεται να στέλνουν push notifications. Χρησιμοποιήστε το `plutil` για parsing.
- **LastSession.plist**: Καρτέλες από την τελευταία συνεδρία. Χρησιμοποιήστε το `plutil` για parsing.
- **Ενσωματωμένο anti-phishing του browser**: Ελέγξτε το με χρήση της εντολής `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Απόκριση 1 υποδεικνύει ότι η λειτουργία είναι ενεργή.<sup>[[2]](#references)</sup>

## Opera

Τα δεδομένα του Opera βρίσκονται στο `/Users/$USER/Library/Application Support/com.operasoftware.Opera` και χρησιμοποιούν την ίδια μορφή με το Chrome για το ιστορικό και τις λήψεις.

- **Ενσωματωμένο anti-phishing του browser**: Επαληθεύστε αν το `fraud_protection_enabled` στο αρχείο Preferences έχει οριστεί σε `true`, χρησιμοποιώντας `grep`.<sup>[[2]](#references)</sup>

Αυτές οι διαδρομές και οι εντολές είναι απαραίτητες για την πρόσβαση και την κατανόηση των δεδομένων περιήγησης που αποθηκεύονται από διαφορετικούς web browsers.

## References

- [1] [Forensics web browsers: Ένας οδηγός για τη διεξαγωγή forensic analysis web browsers](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Απόκριση σε περιστατικά στο macOS | Μέρος 3: Χειρισμός συστήματος](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Απόκριση σε περιστατικά στο OS X: Scripting και Analysis από τον Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
