# Αποτυπώματα περιηγητή

{{#include ../../../banners/hacktricks-training.md}}

## Αποτυπώματα Browsers <a href="#id-3def" id="id-3def"></a>

Τα αποτυπώματα του προγράμματος περιήγησης περιλαμβάνουν διάφορους τύπους δεδομένων που αποθηκεύονται από τους web browsers, όπως το ιστορικό περιήγησης, τους σελιδοδείκτες και τα δεδομένα cache. Αυτά τα αποτυπώματα φυλάσσονται σε συγκεκριμένους φακέλους στο λειτουργικό σύστημα, με διαφορετική τοποθεσία και ονομασία ανά browser, αλλά γενικά αποθηκεύουν παρόμοιους τύπους δεδομένων.

Ακολουθεί μια περίληψη των πιο κοινών αποτυπωμάτων:

- **Navigation History**: Καταγράφει τις επισκέψεις του χρήστη σε ιστοσελίδες, χρήσιμο για τον εντοπισμό επισκέψεων σε κακόβουλους ιστότοπους.
- **Autocomplete Data**: Προτάσεις βασισμένες σε συχνές αναζητήσεις, που παρέχουν πληροφορίες όταν συνδυάζονται με το ιστορικό περιήγησης.
- **Bookmarks**: Ιστοσελίδες που αποθηκεύτηκαν από τον χρήστη για γρήγορη πρόσβαση.
- **Extensions and Add-ons**: Επεκτάσεις ή πρόσθετα που έχει εγκαταστήσει ο χρήστης.
- **Cache**: Αποθηκεύει περιεχόμενο web (π.χ. εικόνες, αρχεία JavaScript) για βελτίωση των χρόνων φόρτωσης, πολύτιμο για εγκληματολογική ανάλυση.
- **Logins**: Αποθηκευμένα διαπιστευτήρια σύνδεσης.
- **Favicons**: Εικονίδια συνδεδεμένα με ιστοτόπους, εμφανίζονται σε καρτέλες και σελιδοδείκτες, χρήσιμα για πρόσθετες πληροφορίες σχετικά με τις επισκέψεις του χρήστη.
- **Browser Sessions**: Δεδομένα σχετικά με ανοιχτές συνεδρίες του περιηγητή.
- **Downloads**: Καταγραφές αρχείων που έχουν ληφθεί μέσω του περιηγητή.
- **Form Data**: Πληροφορίες που εισήχθησαν σε φόρμες web, αποθηκευμένες για μελλοντικές προτάσεις αυτόματης συμπλήρωσης.
- **Thumbnails**: Εικόνες προεπισκόπησης ιστοσελίδων.
- **Custom Dictionary.txt**: Λέξεις που έχουν προστεθεί από τον χρήστη στο λεξικό του περιηγητή.

## Firefox

Ο Firefox οργανώνει τα δεδομένα χρηστών μέσα σε προφίλ, τα οποία αποθηκεύονται σε συγκεκριμένες τοποθεσίες ανάλογα με το λειτουργικό σύστημα:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Ένα αρχείο `profiles.ini` μέσα σε αυτούς τους καταλόγους παραθέτει τα προφίλ χρηστών. Τα δεδομένα κάθε προφίλ αποθηκεύονται σε έναν φάκελο με το όνομα που ορίζεται στη μεταβλητή `Path` μέσα στο `profiles.ini`, που βρίσκεται στον ίδιο κατάλογο με το `profiles.ini`. Εάν λείπει ο φάκελος ενός προφίλ, μπορεί να έχει διαγραφεί.

Μέσα σε κάθε φάκελο προφίλ μπορείτε να βρείτε αρκετά σημαντικά αρχεία:

- **places.sqlite**: Αποθηκεύει ιστορικό, σελιδοδείκτες και downloads. Εργαλεία όπως [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) στα Windows μπορούν να προσπελάσουν τα δεδομένα ιστορικού.
- Χρησιμοποιήστε συγκεκριμένα SQL queries για εξαγωγή πληροφοριών ιστορικού και downloads.
- **bookmarkbackups**: Περιέχει αντίγραφα ασφαλείας των σελιδοδεικτών.
- **formhistory.sqlite**: Αποθηκεύει δεδομένα από φόρμες web.
- **handlers.json**: Διαχειρίζεται τους χειριστές πρωτοκόλλων.
- **persdict.dat**: Λέξεις του προσαρμοσμένου λεξικού.
- **addons.json** και **extensions.sqlite**: Πληροφορίες για εγκατεστημένα add-ons και επεκτάσεις.
- **cookies.sqlite**: Αποθήκευση cookies, με το [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) διαθέσιμο για έλεγχο στα Windows.
- **cache2/entries** ή **startupCache**: Δεδομένα cache, προσβάσιμα μέσω εργαλείων όπως [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Αποθηκεύει favicons.
- **prefs.js**: Ρυθμίσεις και προτιμήσεις χρήστη.
- **downloads.sqlite**: Παλαιότερη βάση δεδομένων λήψεων, πλέον ενσωματωμένη στο places.sqlite.
- **thumbnails**: Μικρογραφίες ιστοσελίδων.
- **logins.json**: Κρυπτογραφημένες πληροφορίες σύνδεσης.
- **key4.db** ή **key3.db**: Αποθηκεύει κλειδιά κρυπτογράφησης που χρησιμοποιούνται για την προστασία ευαίσθητων πληροφοριών.

Επιπλέον, ο έλεγχος των ρυθμίσεων anti-phishing του περιηγητή μπορεί να γίνει αναζητώντας εγγραφές `browser.safebrowsing` στο `prefs.js`, κάτι που δείχνει εάν οι λειτουργίες safe browsing είναι ενεργές ή απενεργοποιημένες.

Για να προσπαθήσετε να αποκρυπτογραφήσετε το κύριο συνθηματικό, μπορείτε να χρησιμοποιήσετε [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Με το παρακάτω script και την κλήση μπορείτε να καθορίσετε ένα αρχείο κωδικών για brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![](<../../../images/image (692).png>)

## Google Chrome

Το Google Chrome αποθηκεύει τα προφίλ χρηστών σε συγκεκριμένες τοποθεσίες ανάλογα με το λειτουργικό σύστημα:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Μέσα σε αυτούς τους φακέλους, τα περισσότερα δεδομένα χρήστη βρίσκονται στους φακέλους **Default/** ή **ChromeDefaultData/**. Τα ακόλουθα αρχεία περιέχουν σημαντικά δεδομένα:

- **History**: Περιέχει URLs, λήψεις και λέξεις-κλειδιά αναζήτησης. Σε Windows, το [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) μπορεί να χρησιμοποιηθεί για ανάγνωση του ιστορικού. Η στήλη "Transition Type" έχει διάφορες σημασίες, συμπεριλαμβανομένων των κλικ χρηστών σε συνδέσμους, πληκτρολογημένων URLs, υποβολών φορμών και ανανεώσεων σελίδας.
- **Cookies**: Αποθηκεύει cookies. Για επιθεώρηση, είναι διαθέσιμο το [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Περιέχει δεδομένα cache. Για έλεγχο, οι χρήστες Windows μπορούν να χρησιμοποιήσουν το [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Electron-based desktop apps (π.χ., Discord) χρησιμοποιούν επίσης Chromium Simple Cache και αφήνουν πλούσια artifacts στο δίσκο. Δείτε:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Σελιδοδείκτες του χρήστη.
- **Web Data**: Περιέχει ιστορικό φορμών.
- **Favicons**: Αποθηκεύει favicons ιστοσελίδων.
- **Login Data**: Περιλαμβάνει διαπιστευτήρια σύνδεσης όπως usernames και passwords.
- **Current Session**/**Current Tabs**: Δεδομένα για την τρέχουσα περιήγηση και τις ανοιχτές καρτέλες.
- **Last Session**/**Last Tabs**: Πληροφορίες για τους ιστότοπους που ήταν ενεργοί στην τελευταία συνεδρία πριν το κλείσιμο του Chrome.
- **Extensions**: Φάκελοι για επεκτάσεις και πρόσθετα του browser.
- **Thumbnails**: Αποθηκεύει μικρογραφίες ιστοσελίδων.
- **Preferences**: Αρχείο πλούσιο σε πληροφορίες, συμπεριλαμβανομένων ρυθμίσεων για plugins, extensions, pop-ups, notifications και άλλα.
- **Browser’s built-in anti-phishing**: Για να ελέγξετε αν το anti-phishing και η προστασία από malware είναι ενεργοποιημένα, τρέξτε `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Αναζητήστε `{"enabled: true,"}` στο αποτέλεσμα.

## **SQLite DB Data Recovery**

Όπως φαίνεται στις προηγούμενες ενότητες, τόσο το Chrome όσο και το Firefox χρησιμοποιούν βάσεις δεδομένων **SQLite** για την αποθήκευση δεδομένων. Είναι δυνατή η **ανάκτηση διαγραμμένων εγγραφών χρησιμοποιώντας το εργαλείο** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ή** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Το Internet Explorer 11 διαχειρίζεται τα δεδομένα και τα μεταδεδομένα του σε διάφορες τοποθεσίες, βοηθώντας στο να διαχωρίζονται οι αποθηκευμένες πληροφορίες και οι αντίστοιχες λεπτομέρειες για ευκολότερη πρόσβαση και διαχείριση.

### Metadata Storage

Τα μεταδεδομένα για το Internet Explorer αποθηκεύονται στο `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (όπου VX είναι V01, V16 ή V24). Συνοδευτικά, το αρχείο `V01.log` μπορεί να δείχνει διαφορές χρόνων τροποποίησης σε σχέση με το `WebcacheVX.data`, υποδεικνύοντας την ανάγκη για επισκευή με `esentutl /r V01 /d`. Αυτά τα μεταδεδομένα, που φιλοξενούνται σε μια ESE βάση δεδομένων, μπορούν να ανακτηθούν και να εξεταστούν με εργαλεία όπως το photorec και το [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), αντίστοιχα. Στον πίνακα **Containers** μπορεί κανείς να διακρίνει τους συγκεκριμένους πίνακες ή containers όπου αποθηκεύεται κάθε κομμάτι δεδομένων, συμπεριλαμβανομένων πληροφοριών cache για άλλα εργαλεία της Microsoft όπως το Skype.

### Cache Inspection

Το εργαλείο [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) επιτρέπει την επιθεώρηση της cache, απαιτώντας την τοποθεσία του φακέλου εξαγωγής των δεδομένων της cache. Τα μεταδεδομένα της cache περιλαμβάνουν όνομα αρχείου, κατάλογο, αριθμό προσβάσεων, προέλευση URL και χρονικά στοιχεία που υποδεικνύουν τη δημιουργία, πρόσβαση, τροποποίηση και λήξη της cache.

### Cookies Management

Τα cookies μπορούν να εξερευνηθούν με το [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), με μεταδεδομένα που περιλαμβάνουν ονόματα, URLs, αριθμούς προσβάσεων και διάφορες χρονικές λεπτομέρειες. Τα μόνιμα cookies αποθηκεύονται στο `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, ενώ τα session cookies βρίσκονται στη μνήμη.

### Download Details

Τα μεταδεδομένα των λήψεων είναι προσβάσιμα μέσω του [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), με συγκεκριμένα containers που κρατούν δεδομένα όπως URL, τύπος αρχείου και τοποθεσία λήψης. Τα φυσικά αρχεία μπορούν να εντοπιστούν στο `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browsing History

Για να ελέγξετε το ιστορικό περιήγησης, μπορείτε να χρησιμοποιήσετε το [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), παρέχοντας την τοποθεσία των εξαγόμενων αρχείων ιστορικού και τις ρυθμίσεις για το Internet Explorer. Τα μεταδεδομένα εδώ περιλαμβάνουν χρόνους τροποποίησης και πρόσβασης, μαζί με αριθμούς προσβάσεων. Τα αρχεία ιστορικού βρίσκονται στο `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Typed URLs

Τα πληκτρολογημένα URLs και οι χρόνοι χρήσης τους αποθηκεύονται στο μητρώο υπό `NTUSER.DAT` στο `Software\Microsoft\InternetExplorer\TypedURLs` και `Software\Microsoft\InternetExplorer\TypedURLsTime`, παρακολουθώντας τα τελευταία 50 URLs που εισήγαγε ο χρήστης και τους χρόνους τελευταίας εισόδου τους.

## Microsoft Edge

Το Microsoft Edge αποθηκεύει δεδομένα χρήστη στο `%userprofile%\Appdata\Local\Packages`. Οι διαδρομές για διάφορους τύπους δεδομένων είναι:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Τα δεδομένα του Safari αποθηκεύονται στο `/Users/$User/Library/Safari`. Βασικά αρχεία περιλαμβάνουν:

- **History.db**: Περιέχει τους πίνακες `history_visits` και `history_items` με URLs και χρονικές σφραγίδες επισκέψεων. Χρησιμοποιήστε `sqlite3` για ερωτήματα.
- **Downloads.plist**: Πληροφορίες για τα αρχεία που κατεβάστηκαν.
- **Bookmarks.plist**: Αποθηκεύει bookmarked URLs.
- **TopSites.plist**: Οι πιο συχνά επισκεπτόμενοι ιστότοποι.
- **Extensions.plist**: Λίστα επεκτάσεων του Safari. Χρησιμοποιήστε `plutil` ή `pluginkit` για ανάκτηση.
- **UserNotificationPermissions.plist**: Domains που έχουν δικαίωμα να στέλνουν ειδοποιήσεις. Χρησιμοποιήστε `plutil` για ανάλυση.
- **LastSession.plist**: Tabs από την τελευταία συνεδρία. Χρησιμοποιήστε `plutil` για ανάλυση.
- **Browser’s built-in anti-phishing**: Ελέγξτε χρησιμοποιώντας `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Μια απάντηση 1 υποδεικνύει ότι η λειτουργία είναι ενεργή.

## Opera

Τα δεδομένα του Opera βρίσκονται στο `/Users/$USER/Library/Application Support/com.operasoftware.Opera` και χρησιμοποιούν την ίδια μορφή με το Chrome για ιστορικό και λήψεις.

- **Browser’s built-in anti-phishing**: Επαληθεύστε ελέγχοντας αν το `fraud_protection_enabled` στο αρχείο Preferences έχει τιμή `true` χρησιμοποιώντας `grep`.

Αυτές οι διαδρομές και οι εντολές είναι κρίσιμες για την πρόσβαση και την κατανόηση των δεδομένων περιήγησης που αποθηκεύουν οι διαφορετικοί web browsers.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**


{{#include ../../../banners/hacktricks-training.md}}
