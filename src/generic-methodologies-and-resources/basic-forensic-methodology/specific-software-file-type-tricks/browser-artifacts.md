# Artifacts Browser

## Artifacts Browser <a href="#id-3def" id="id-3def"></a>

Τα artifacts του browser περιλαμβάνουν διάφορους τύπους δεδομένων που αποθηκεύονται από τους web browsers, όπως το ιστορικό περιήγησης, οι σελιδοδείκτες και τα δεδομένα cache. Αυτά τα artifacts διατηρούνται σε συγκεκριμένους φακέλους μέσα στο λειτουργικό σύστημα, με διαφορετική τοποθεσία και όνομα ανά browser, αλλά γενικά αποθηκεύουν παρόμοιους τύπους δεδομένων.

Ακολουθεί μια σύνοψη των πιο συνηθισμένων browser artifacts:

- **Ιστορικό περιήγησης**: Καταγράφει τις επισκέψεις του χρήστη σε websites και είναι χρήσιμο για τον εντοπισμό επισκέψεων σε malicious websites.
- **Δεδομένα Autocomplete**: Προτάσεις που βασίζονται σε συχνές αναζητήσεις και προσφέρουν χρήσιμες πληροφορίες όταν συνδυάζονται με το ιστορικό περιήγησης.
- **Σελιδοδείκτες**: Websites που αποθηκεύονται από τον χρήστη για γρήγορη πρόσβαση.
- **Extensions και Add-ons**: Browser extensions ή add-ons που έχουν εγκατασταθεί από τον χρήστη.
- **Cache**: Αποθηκεύει περιεχόμενο του web (π.χ. εικόνες, αρχεία JavaScript) για τη βελτίωση των χρόνων φόρτωσης των websites και είναι πολύτιμη για forensic analysis.
- **Logins**: Αποθηκευμένα credentials σύνδεσης.
- **Favicons**: Εικονίδια που σχετίζονται με websites και εμφανίζονται σε tabs και σελιδοδείκτες, χρήσιμα για πρόσθετες πληροφορίες σχετικά με τις επισκέψεις του χρήστη.
- **Browser Sessions**: Δεδομένα που σχετίζονται με ανοιχτές browser sessions.
- **Downloads**: Καταγραφές αρχείων που έχουν ληφθεί μέσω του browser.
- **Form Data**: Πληροφορίες που εισάγονται σε web forms και αποθηκεύονται για μελλοντικές προτάσεις autofill.
- **Thumbnails**: Εικόνες προεπισκόπησης websites.
- **Custom Dictionary.txt**: Λέξεις που προστέθηκαν από τον χρήστη στο dictionary του browser.

## Firefox

Ο Firefox οργανώνει τα δεδομένα του χρήστη μέσα σε profiles, τα οποία αποθηκεύονται σε συγκεκριμένες τοποθεσίες ανάλογα με το λειτουργικό σύστημα:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Ένα αρχείο `profiles.ini` μέσα σε αυτούς τους καταλόγους παραθέτει τα user profiles. Τα δεδομένα κάθε profile αποθηκεύονται σε έναν φάκελο με όνομα που ορίζεται στη μεταβλητή `Path` μέσα στο `profiles.ini`, ο οποίος βρίσκεται στον ίδιο κατάλογο με το ίδιο το `profiles.ini`. Αν λείπει ο φάκελος ενός profile, ενδέχεται να έχει διαγραφεί.

Μέσα σε κάθε φάκελο profile μπορείτε να βρείτε αρκετά σημαντικά αρχεία:<sup>[[1]](#references)</sup>

- **places.sqlite**: Αποθηκεύει το ιστορικό, τους σελιδοδείκτες και τα downloads. Εργαλεία όπως το [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) στα Windows μπορούν να αποκτήσουν πρόσβαση στα δεδομένα ιστορικού.
- Χρησιμοποιήστε συγκεκριμένα SQL queries για την εξαγωγή πληροφοριών ιστορικού και downloads.
- **bookmarkbackups**: Περιέχει backups των σελιδοδεικτών.
- **formhistory.sqlite**: Αποθηκεύει δεδομένα web forms.
- **handlers.json**: Διαχειρίζεται protocol handlers.
- **persdict.dat**: Λέξεις του custom dictionary.
- **addons.json** και **extensions.sqlite**: Πληροφορίες σχετικά με εγκατεστημένα add-ons και extensions.
- **cookies.sqlite**: Αποθήκευση cookies, με το [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) διαθέσιμο για inspection στα Windows.
- **cache2/entries** ή **startupCache**: Δεδομένα cache, προσβάσιμα μέσω εργαλείων όπως το [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Αποθηκεύει favicons.
- **prefs.js**: Ρυθμίσεις και preferences του χρήστη.
- **downloads.sqlite**: Παλαιότερη βάση δεδομένων downloads, η οποία πλέον είναι ενσωματωμένη στο places.sqlite.
- **thumbnails**: Thumbnails websites.
- **logins.json**: Κρυπτογραφημένες πληροφορίες login.
- **key4.db** ή **key3.db**: Αποθηκεύει encryption keys για την προστασία ευαίσθητων πληροφοριών.

Επιπλέον, ο έλεγχος των anti-phishing settings του browser μπορεί να γίνει με αναζήτηση entries `browser.safebrowsing` στο `prefs.js`, τα οποία υποδεικνύουν αν οι λειτουργίες safe browsing είναι ενεργοποιημένες ή απενεργοποιημένες.<sup>[[2]](#references)</sup>

Για να προσπαθήσετε να αποκρυπτογραφήσετε το master password, μπορείτε να χρησιμοποιήσετε το [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Με το ακόλουθο script και call μπορείτε να καθορίσετε ένα αρχείο κωδικών για brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Browsers Artifacts - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Το Google Chrome αποθηκεύει τα user profiles σε συγκεκριμένες τοποθεσίες, ανάλογα με το λειτουργικό σύστημα:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Μέσα σε αυτούς τους καταλόγους, τα περισσότερα δεδομένα χρήστη μπορούν να βρεθούν στους φακέλους **Default/** ή **ChromeDefaultData/**. Τα ακόλουθα αρχεία περιέχουν σημαντικά δεδομένα:<sup>[[1]](#references)</sup>

- **History**: Περιέχει URL, downloads και search keywords. Στα Windows, μπορεί να χρησιμοποιηθεί το [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) για την ανάγνωση του history. Η στήλη "Transition Type" έχει διάφορες σημασίες, όπως clicks χρήστη σε links, typed URL, form submissions και page reloads.
- **Cookies**: Αποθηκεύει cookies. Για inspection, είναι διαθέσιμο το [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Περιέχει cached data. Για inspection, οι χρήστες Windows μπορούν να χρησιμοποιήσουν το [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Οι desktop apps που βασίζονται στο Electron (π.χ. το Discord) χρησιμοποιούν επίσης Chromium Simple Cache και αφήνουν πλούσια artifacts στον δίσκο. Δείτε:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Bookmarks χρήστη.
- **Web Data**: Περιέχει form history.
- **Favicons**: Αποθηκεύει τα favicons των websites.
- **Login Data**: Περιλαμβάνει login credentials, όπως usernames και passwords.
- **Current Session**/**Current Tabs**: Δεδομένα σχετικά με το τρέχον browsing session και τα ανοιχτά tabs.
- **Last Session**/**Last Tabs**: Πληροφορίες για τα sites που ήταν ενεργά κατά το τελευταίο session, πριν κλείσει το Chrome.
- **Extensions**: Κατάλογοι για browser extensions και addons.
- **Thumbnails**: Αποθηκεύει thumbnails websites.
- **Preferences**: Ένα αρχείο με πολλές πληροφορίες, συμπεριλαμβανομένων ρυθμίσεων για plugins, extensions, pop-ups, notifications και άλλα.
- **Browser’s built-in anti-phishing**: Για να ελέγξετε αν είναι ενεργοποιημένα τα anti-phishing και malware protection, εκτελέστε `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Αναζητήστε το `{"enabled: true,"}` στην έξοδο.<sup>[[2]](#references)</sup>

## **Ανάκτηση δεδομένων βάσης SQLite**

Όπως μπορείτε να παρατηρήσετε στις προηγούμενες ενότητες, τόσο το Chrome όσο και το Firefox χρησιμοποιούν βάσεις δεδομένων **SQLite** για την αποθήκευση των δεδομένων. Είναι δυνατή η **ανάκτηση διαγραμμένων entries με χρήση του tool** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ή** του [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Ο Internet Explorer 11 διαχειρίζεται τα δεδομένα και τα metadata του σε διάφορες τοποθεσίες, διευκολύνοντας τον διαχωρισμό των αποθηκευμένων πληροφοριών και των αντίστοιχων λεπτομερειών για εύκολη πρόσβαση και διαχείριση.

### Αποθήκευση metadata

Τα metadata του Internet Explorer αποθηκεύονται στο `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (όπου το VX είναι V01, V16 ή V24). Το συνοδευτικό αρχείο `V01.log` ενδέχεται να εμφανίζει ασυμφωνίες στον χρόνο τροποποίησης σε σχέση με το `WebcacheVX.data`, υποδεικνύοντας την ανάγκη επιδιόρθωσης με χρήση του `esentutl /r V01 /d`. Αυτά τα metadata, τα οποία φιλοξενούνται σε μια ESE database, μπορούν να ανακτηθούν και να επιθεωρηθούν με εργαλεία όπως τα photorec και [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), αντίστοιχα. Στον πίνακα **Containers**, μπορεί κανείς να διακρίνει τους συγκεκριμένους πίνακες ή containers όπου αποθηκεύεται κάθε τμήμα δεδομένων, συμπεριλαμβανομένων των cache details για άλλα Microsoft tools, όπως το Skype.

### Inspection του cache

Το tool [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) επιτρέπει την inspection του cache και απαιτεί την τοποθεσία του φακέλου extraction των cache data. Τα metadata για το cache περιλαμβάνουν filename, directory, access count, URL origin και timestamps που υποδεικνύουν τους χρόνους δημιουργίας, πρόσβασης, τροποποίησης και λήξης του cache.

### Διαχείριση cookies

Τα cookies μπορούν να εξερευνηθούν με χρήση του [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), με metadata που περιλαμβάνουν names, URL, access counts και διάφορες λεπτομέρειες σχετικές με τον χρόνο. Τα persistent cookies αποθηκεύονται στο `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, ενώ τα session cookies βρίσκονται στη μνήμη.

### Λεπτομέρειες downloads

Τα metadata των downloads είναι προσβάσιμα μέσω του [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), με συγκεκριμένα containers που περιέχουν δεδομένα όπως URL, file type και download location. Τα physical files μπορούν να βρεθούν στο `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browsing history

Για την ανασκόπηση του browsing history, μπορεί να χρησιμοποιηθεί το [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), το οποίο απαιτεί την τοποθεσία των extracted history files και configuration για τον Internet Explorer. Τα metadata εδώ περιλαμβάνουν modification times και access times, μαζί με access counts. Τα history files βρίσκονται στο `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Typed URLs

Τα typed URL και οι χρόνοι χρήσης τους αποθηκεύονται στο registry, μέσα στο `NTUSER.DAT`, στις τοποθεσίες `Software\Microsoft\InternetExplorer\TypedURLs` και `Software\Microsoft\InternetExplorer\TypedURLsTime`, καταγράφοντας τα τελευταία 50 URL που εισήγαγε ο χρήστης και τους τελευταίους χρόνους εισαγωγής τους.

## Microsoft Edge

Το Microsoft Edge αποθηκεύει δεδομένα χρήστη στο `%userprofile%\Appdata\Local\Packages`. Οι διαδρομές για διάφορους τύπους δεδομένων είναι:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Τα δεδομένα του Safari αποθηκεύονται στο `/Users/$User/Library/Safari`. Τα βασικά αρχεία περιλαμβάνουν:<sup>[[3]](#references)</sup>

- **History.db**: Περιέχει τους πίνακες `history_visits` και `history_items`, με URL και timestamps επισκέψεων. Χρησιμοποιήστε το `sqlite3` για query.
- **Downloads.plist**: Πληροφορίες για downloaded files.
- **Bookmarks.plist**: Αποθηκεύει bookmarked URL.
- **TopSites.plist**: Τα sites που επισκέπτεται συχνότερα ο χρήστης.
- **Extensions.plist**: Λίστα των Safari browser extensions. Χρησιμοποιήστε τα `plutil` ή `pluginkit` για ανάκτηση.
- **UserNotificationPermissions.plist**: Domains που επιτρέπεται να στέλνουν push notifications. Χρησιμοποιήστε το `plutil` για parsing.
- **LastSession.plist**: Tabs από το τελευταίο session. Χρησιμοποιήστε το `plutil` για parsing.
- **Browser’s built-in anti-phishing**: Ελέγξτε το με χρήση του `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Απόκριση 1 υποδεικνύει ότι η λειτουργία είναι ενεργή.<sup>[[2]](#references)</sup>

## Opera

Τα δεδομένα του Opera βρίσκονται στο `/Users/$USER/Library/Application Support/com.operasoftware.Opera` και χρησιμοποιούν το format του Chrome για history και downloads.

- **Browser’s built-in anti-phishing**: Επαληθεύστε αν το `fraud_protection_enabled` στο αρχείο Preferences έχει οριστεί σε `true`, χρησιμοποιώντας το `grep`.<sup>[[2]](#references)</sup>

Αυτές οι διαδρομές και οι εντολές είναι απαραίτητες για την πρόσβαση και την κατανόηση των browsing data που αποθηκεύουν διαφορετικοί web browsers.

## References

- [1] [Forensics web browsers: Οδηγός για τη διενέργεια forensic analysis web browsers](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Μέρος 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Scripting και Analysis από τον Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
