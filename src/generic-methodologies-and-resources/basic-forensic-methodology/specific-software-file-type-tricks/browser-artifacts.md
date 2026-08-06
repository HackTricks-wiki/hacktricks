# Τεχνουργήματα περιηγητών

{{#include ../../../banners/hacktricks-training.md}}

## Τεχνουργήματα Firefox <a href="#id-3def" id="id-3def"></a>

Τα τεχνουργήματα των περιηγητών περιλαμβάνουν διάφορους τύπους δεδομένων που αποθηκεύονται από τους web περιηγητές, όπως το ιστορικό περιήγησης, οι σελιδοδείκτες και τα δεδομένα cache. Αυτά τα τεχνουργήματα διατηρούνται σε συγκεκριμένους φακέλους μέσα στο λειτουργικό σύστημα, με διαφορετική τοποθεσία και όνομα ανά περιηγητή, αλλά συνήθως αποθηκεύουν παρόμοιους τύπους δεδομένων.

Ακολουθεί μια σύνοψη των πιο συνηθισμένων τεχνουργημάτων περιηγητών:

- **Ιστορικό περιήγησης**: Καταγράφει τις επισκέψεις του χρήστη σε ιστοτόπους και είναι χρήσιμο για τον εντοπισμό επισκέψεων σε κακόβουλους ιστοτόπους.
- **Δεδομένα αυτόματης συμπλήρωσης**: Προτάσεις που βασίζονται σε συχνές αναζητήσεις και παρέχουν χρήσιμες πληροφορίες όταν συνδυάζονται με το ιστορικό περιήγησης.
- **Σελιδοδείκτες**: Ιστότοποι που αποθηκεύτηκαν από τον χρήστη για γρήγορη πρόσβαση.
- **Extensions και Add-ons**: Extensions ή add-ons περιηγητών που έχουν εγκατασταθεί από τον χρήστη.
- **Cache**: Αποθηκεύει περιεχόμενο ιστού (π.χ. εικόνες, αρχεία JavaScript) για τη βελτίωση των χρόνων φόρτωσης των ιστοτόπων και είναι πολύτιμο για forensic analysis.
- **Συνδέσεις**: Αποθηκευμένα credentials σύνδεσης.
- **Favicons**: Εικονίδια που σχετίζονται με ιστοτόπους και εμφανίζονται σε tabs και σελιδοδείκτες, χρήσιμα για πρόσθετες πληροφορίες σχετικά με τις επισκέψεις του χρήστη.
- **Συνεδρίες περιηγητή**: Δεδομένα που σχετίζονται με ανοιχτές συνεδρίες περιηγητή.
- **Downloads**: Καταγραφές αρχείων που λήφθηκαν μέσω του περιηγητή.
- **Δεδομένα φορμών**: Πληροφορίες που εισήχθησαν σε web φόρμες και αποθηκεύτηκαν για μελλοντικές προτάσεις autofill.
- **Thumbnails**: Εικόνες προεπισκόπησης ιστοτόπων.
- **Custom Dictionary.txt**: Λέξεις που προστέθηκαν από τον χρήστη στο λεξικό του περιηγητή.

## Firefox

Ο Firefox οργανώνει τα δεδομένα των χρηστών σε profiles, τα οποία αποθηκεύονται σε συγκεκριμένες τοποθεσίες ανάλογα με το λειτουργικό σύστημα:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Ένα αρχείο `profiles.ini` μέσα σε αυτούς τους καταλόγους παραθέτει τα profiles των χρηστών. Τα δεδομένα κάθε profile αποθηκεύονται σε έναν φάκελο με όνομα που ορίζεται στη μεταβλητή `Path` μέσα στο `profiles.ini`, ο οποίος βρίσκεται στον ίδιο κατάλογο με το ίδιο το `profiles.ini`. Αν ο φάκελος ενός profile λείπει, ενδέχεται να έχει διαγραφεί.

Μέσα σε κάθε φάκελο profile μπορείτε να βρείτε αρκετά σημαντικά αρχεία:<sup>[[1]](#references)</sup>

- **places.sqlite**: Αποθηκεύει το ιστορικό, τους σελιδοδείκτες και τα downloads. Εργαλεία όπως το [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) στα Windows μπορούν να αποκτήσουν πρόσβαση στα δεδομένα ιστορικού.
- Χρησιμοποιήστε συγκεκριμένα SQL queries για την εξαγωγή πληροφοριών ιστορικού και downloads.
- **bookmarkbackups**: Περιέχει αντίγραφα ασφαλείας των σελιδοδεικτών.
- **formhistory.sqlite**: Αποθηκεύει δεδομένα web φορμών.
- **handlers.json**: Διαχειρίζεται protocol handlers.
- **persdict.dat**: Λέξεις του custom dictionary.
- **addons.json** και **extensions.sqlite**: Πληροφορίες σχετικά με εγκατεστημένα add-ons και extensions.
- **cookies.sqlite**: Αποθήκευση cookies, με το [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) διαθέσιμο για επιθεώρηση στα Windows.
- **cache2/entries** ή **startupCache**: Δεδομένα cache, προσβάσιμα μέσω εργαλείων όπως το [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Αποθηκεύει favicons.
- **prefs.js**: Ρυθμίσεις και προτιμήσεις χρήστη.
- **downloads.sqlite**: Παλαιότερη database downloads, η οποία πλέον έχει ενσωματωθεί στο places.sqlite.
- **thumbnails**: Thumbnails ιστοτόπων.
- **logins.json**: Κρυπτογραφημένες πληροφορίες σύνδεσης.
- **key4.db** ή **key3.db**: Αποθηκεύει encryption keys για την προστασία ευαίσθητων πληροφοριών.

Επιπλέον, ο έλεγχος των ρυθμίσεων anti-phishing του περιηγητή μπορεί να γίνει με αναζήτηση εγγραφών `browser.safebrowsing` στο `prefs.js`, οι οποίες υποδεικνύουν αν οι λειτουργίες safe browsing είναι ενεργοποιημένες ή απενεργοποιημένες.<sup>[[2]](#references)</sup>

Για να προσπαθήσετε να κάνετε decrypt το master password, μπορείτε να χρησιμοποιήσετε το [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Με το ακόλουθο script και call μπορείτε να καθορίσετε ένα αρχείο passwords για brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Αρχεία τεχνουργημάτων browsers - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Το Google Chrome αποθηκεύει τα user profiles σε συγκεκριμένες τοποθεσίες, ανάλογα με το λειτουργικό σύστημα:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Σε αυτούς τους καταλόγους, τα περισσότερα δεδομένα χρηστών βρίσκονται στους φακέλους **Default/** ή **ChromeDefaultData/**. Τα ακόλουθα αρχεία περιέχουν σημαντικά δεδομένα:<sup>[[1]](#references)</sup>

- **History**: Περιέχει URLs, downloads και search keywords. Στα Windows, μπορεί να χρησιμοποιηθεί το [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) για την ανάγνωση του history. Η στήλη "Transition Type" έχει διάφορες σημασίες, όπως clicks χρηστών σε links, typed URLs, form submissions και page reloads.
- **Cookies**: Αποθηκεύει cookies. Για inspection, είναι διαθέσιμο το [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Περιέχει cached δεδομένα. Για inspection, οι χρήστες Windows μπορούν να χρησιμοποιήσουν το [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Οι desktop εφαρμογές που βασίζονται στο Electron (π.χ. το Discord) χρησιμοποιούν επίσης Chromium Simple Cache και αφήνουν πλούσια on-disk artifacts. Δείτε:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Τα bookmarks του χρήστη.
- **Web Data**: Περιέχει form history.
- **Favicons**: Αποθηκεύει τα favicons των websites.
- **Login Data**: Περιλαμβάνει login credentials, όπως usernames και passwords.
- **Current Session**/**Current Tabs**: Δεδομένα σχετικά με το τρέχον browsing session και τα ανοιχτά tabs.
- **Last Session**/**Last Tabs**: Πληροφορίες σχετικά με τα sites που ήταν ενεργά κατά το τελευταίο session, πριν κλείσει το Chrome.
- **Extensions**: Κατάλογοι για browser extensions και addons.
- **Thumbnails**: Αποθηκεύει thumbnails των websites.
- **Preferences**: Ένα αρχείο με πολλές πληροφορίες, συμπεριλαμβανομένων settings για plugins, extensions, pop-ups, notifications και άλλα.
- **Browser’s built-in anti-phishing**: Για να ελέγξετε αν είναι ενεργοποιημένα τα anti-phishing και malware protection, εκτελέστε `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Αναζητήστε `{"enabled: true,"}` στο output.<sup>[[2]](#references)</sup>

## **SQLite DB Data Recovery**

Όπως μπορείτε να παρατηρήσετε στις προηγούμενες ενότητες, τόσο το Chrome όσο και το Firefox χρησιμοποιούν **SQLite** databases για την αποθήκευση των δεδομένων. Είναι δυνατή η **ανάκτηση διαγραμμένων entries με χρήση του tool** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ή του** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Ο Internet Explorer 11 διαχειρίζεται τα δεδομένα και τα metadata του σε διάφορες τοποθεσίες, διευκολύνοντας τον διαχωρισμό των αποθηκευμένων πληροφοριών και των αντίστοιχων λεπτομερειών για εύκολη πρόσβαση και διαχείριση.

### Metadata Storage

Τα metadata του Internet Explorer αποθηκεύονται στο `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (όπου το VX είναι V01, V16 ή V24). Το συνοδευτικό αρχείο `V01.log` μπορεί να εμφανίζει διαφορές στον χρόνο τροποποίησης σε σχέση με το `WebcacheVX.data`, υποδεικνύοντας την ανάγκη repair με χρήση του `esentutl /r V01 /d`. Αυτά τα metadata, τα οποία φιλοξενούνται σε ESE database, μπορούν να ανακτηθούν και να επιθεωρηθούν με tools όπως τα photorec και [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), αντίστοιχα. Στον πίνακα **Containers**, μπορείτε να εντοπίσετε τους συγκεκριμένους πίνακες ή containers όπου αποθηκεύεται κάθε τμήμα δεδομένων, συμπεριλαμβανομένων των cache details για άλλα Microsoft tools, όπως το Skype.

### Cache Inspection

Το tool [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) επιτρέπει το cache inspection και απαιτεί την τοποθεσία του folder εξαγωγής των cache δεδομένων. Τα metadata για το cache περιλαμβάνουν filename, directory, access count, URL origin και timestamps που υποδεικνύουν τους χρόνους δημιουργίας, πρόσβασης, τροποποίησης και λήξης του cache.

### Cookies Management

Τα cookies μπορούν να εξεταστούν με το [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), με metadata που περιλαμβάνουν names, URLs, access counts και διάφορες time-related λεπτομέρειες. Τα persistent cookies αποθηκεύονται στο `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, ενώ τα session cookies βρίσκονται στη memory.

### Download Details

Τα metadata των downloads είναι προσβάσιμα μέσω του [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), με συγκεκριμένα containers που περιέχουν δεδομένα όπως URL, file type και download location. Τα physical files μπορούν να βρεθούν στο `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browsing History

Για την εξέταση του browsing history, μπορεί να χρησιμοποιηθεί το [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), το οποίο απαιτεί την τοποθεσία των extracted history files και configuration για τον Internet Explorer. Τα metadata εδώ περιλαμβάνουν modification και access times, καθώς και access counts. Τα history files βρίσκονται στο `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Typed URLs

Τα typed URLs και οι χρόνοι χρήσης τους αποθηκεύονται στο registry, μέσα στο `NTUSER.DAT`, στις τοποθεσίες `Software\Microsoft\InternetExplorer\TypedURLs` και `Software\Microsoft\InternetExplorer\TypedURLsTime`, καταγράφοντας τα τελευταία 50 URLs που εισήγαγε ο χρήστης και τους χρόνους τελευταίας εισαγωγής τους.

## Microsoft Edge

Το Microsoft Edge αποθηκεύει τα δεδομένα χρηστών στο `%userprofile%\Appdata\Local\Packages`. Τα paths για τους διάφορους τύπους δεδομένων είναι τα εξής:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Τα δεδομένα του Safari αποθηκεύονται στο `/Users/$User/Library/Safari`. Τα βασικά αρχεία περιλαμβάνουν τα εξής:<sup>[[3]](#references)</sup>

- **History.db**: Περιέχει τους πίνακες `history_visits` και `history_items`, με URLs και timestamps επισκέψεων. Χρησιμοποιήστε το `sqlite3` για query.
- **Downloads.plist**: Πληροφορίες για downloaded files.
- **Bookmarks.plist**: Αποθηκεύει bookmarked URLs.
- **TopSites.plist**: Τα sites με τις περισσότερες επισκέψεις.
- **Extensions.plist**: Λίστα των Safari browser extensions. Χρησιμοποιήστε τα `plutil` ή `pluginkit` για ανάκτηση.
- **UserNotificationPermissions.plist**: Τα domains που επιτρέπεται να στέλνουν push notifications. Χρησιμοποιήστε το `plutil` για parsing.
- **LastSession.plist**: Τα tabs από το τελευταίο session. Χρησιμοποιήστε το `plutil` για parsing.
- **Browser’s built-in anti-phishing**: Ελέγξτε το με την εντολή `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Η απόκριση 1 υποδεικνύει ότι το feature είναι ενεργό.<sup>[[2]](#references)</sup>

## Opera

Τα δεδομένα του Opera βρίσκονται στο `/Users/$USER/Library/Application Support/com.operasoftware.Opera` και χρησιμοποιούν το ίδιο format με το Chrome για το history και τα downloads.

- **Browser’s built-in anti-phishing**: Επαληθεύστε αν το `fraud_protection_enabled` στο αρχείο Preferences έχει οριστεί σε `true`, χρησιμοποιώντας `grep`.<sup>[[2]](#references)</sup>

Αυτά τα paths και οι εντολές είναι απαραίτητα για την πρόσβαση και την κατανόηση των browsing δεδομένων που αποθηκεύονται από διαφορετικούς web browsers.

## References

- [1] [Forensics web browsers: Οδηγός για τη διενέργεια forensic analysis σε web browsers](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Απόκριση σε περιστατικά στο macOS | Μέρος 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Απόκριση σε περιστατικά στο OS X: Scripting and Analysis από τον Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)

{{#include ../../../banners/hacktricks-training.md}}
