# Browser Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Browsers Artifacts <a href="#id-3def" id="id-3def"></a>

Τα αποδεικτικά στοιχεία του προγράμματος περιήγησης περιλαμβάνουν διάφορους τύπους δεδομένων που αποθηκεύονται από τους προγράμματα περιήγησης ιστού, όπως το ιστορικό πλοήγησης, τα σελιδοδείκτες και τα δεδομένα cache. Αυτά τα αποδεικτικά στοιχεία διατηρούνται σε συγκεκριμένους φακέλους εντός του λειτουργικού συστήματος, διαφέροντας σε τοποθεσία και όνομα μεταξύ των προγραμμάτων περιήγησης, αλλά γενικά αποθηκεύουν παρόμοιους τύπους δεδομένων.

Ακολουθεί μια σύνοψη των πιο κοινών αποδεικτικών στοιχείων του προγράμματος περιήγησης:

- **Ιστορικό Πλοήγησης**: Παρακολουθεί τις επισκέψεις του χρήστη σε ιστότοπους, χρήσιμο για την αναγνώριση επισκέψεων σε κακόβουλους ιστότοπους.
- **Δεδομένα Αυτόματης Συμπλήρωσης**: Προτάσεις βασισμένες σε συχνές αναζητήσεις, προσφέροντας πληροφορίες όταν συνδυάζονται με το ιστορικό πλοήγησης.
- **Σελιδοδείκτες**: Ιστότοποι που αποθηκεύει ο χρήστης για γρήγορη πρόσβαση.
- **Επεκτάσεις και Πρόσθετα**: Επεκτάσεις προγράμματος περιήγησης ή πρόσθετα που έχει εγκαταστήσει ο χρήστης.
- **Cache**: Αποθηκεύει περιεχόμενο ιστού (π.χ., εικόνες, αρχεία JavaScript) για να βελτιώσει τους χρόνους φόρτωσης των ιστότοπων, πολύτιμο για την εγκληματολογική ανάλυση.
- **Συνδέσεις**: Αποθηκευμένα διαπιστευτήρια σύνδεσης.
- **Favicons**: Εικονίδια που σχετίζονται με ιστότοπους, που εμφανίζονται σε καρτέλες και σελιδοδείκτες, χρήσιμα για επιπλέον πληροφορίες σχετικά με τις επισκέψεις του χρήστη.
- **Συνεδρίες Προγράμματος Περιήγησης**: Δεδομένα που σχετίζονται με ανοιχτές συνεδρίες προγράμματος περιήγησης.
- **Λήψεις**: Καταγραφές αρχείων που έχουν ληφθεί μέσω του προγράμματος περιήγησης.
- **Δεδομένα Φόρμας**: Πληροφορίες που εισάγονται σε φόρμες ιστού, αποθηκευμένες για μελλοντικές προτάσεις αυτόματης συμπλήρωσης.
- **Μικρογραφίες**: Εικόνες προεπισκόπησης ιστότοπων.
- **Custom Dictionary.txt**: Λέξεις που έχει προσθέσει ο χρήστης στο λεξικό του προγράμματος περιήγησης.

## Firefox

Ο Firefox οργανώνει τα δεδομένα του χρήστη εντός προφίλ, που αποθηκεύονται σε συγκεκριμένες τοποθεσίες ανάλογα με το λειτουργικό σύστημα:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Ένα αρχείο `profiles.ini` εντός αυτών των καταλόγων καταγράφει τα προφίλ χρηστών. Τα δεδομένα κάθε προφίλ αποθηκεύονται σε έναν φάκελο που ονομάζεται στη μεταβλητή `Path` εντός του `profiles.ini`, που βρίσκεται στον ίδιο κατάλογο με το `profiles.ini` ίδιο. Εάν λείπει ο φάκελος ενός προφίλ, μπορεί να έχει διαγραφεί.

Μέσα σε κάθε φάκελο προφίλ, μπορείτε να βρείτε αρκετά σημαντικά αρχεία:

- **places.sqlite**: Αποθηκεύει ιστορικό, σελιδοδείκτες και λήψεις. Εργαλεία όπως το [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) στα Windows μπορούν να έχουν πρόσβαση στα δεδομένα ιστορικού.
- Χρησιμοποιήστε συγκεκριμένα SQL queries για να εξαγάγετε πληροφορίες ιστορικού και λήψεων.
- **bookmarkbackups**: Περιέχει αντίγραφα ασφαλείας των σελιδοδεικτών.
- **formhistory.sqlite**: Αποθηκεύει δεδομένα φόρμας ιστού.
- **handlers.json**: Διαχειρίζεται τους χειριστές πρωτοκόλλων.
- **persdict.dat**: Λέξεις προσαρμοσμένου λεξικού.
- **addons.json** και **extensions.sqlite**: Πληροφορίες σχετικά με εγκατεστημένα πρόσθετα και επεκτάσεις.
- **cookies.sqlite**: Αποθήκευση cookies, με το [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) διαθέσιμο για επιθεώρηση στα Windows.
- **cache2/entries** ή **startupCache**: Δεδομένα cache, προσβάσιμα μέσω εργαλείων όπως το [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Αποθηκεύει favicons.
- **prefs.js**: Ρυθμίσεις και προτιμήσεις χρήστη.
- **downloads.sqlite**: Παλιότερη βάση δεδομένων λήψεων, τώρα ενσωματωμένη στο places.sqlite.
- **thumbnails**: Μικρογραφίες ιστότοπων.
- **logins.json**: Κρυπτογραφημένες πληροφορίες σύνδεσης.
- **key4.db** ή **key3.db**: Αποθηκεύει κλειδιά κρυπτογράφησης για την ασφάλιση ευαίσθητων πληροφοριών.

Επιπλέον, η έρευνα για τις ρυθμίσεις κατά της απάτης του προγράμματος περιήγησης μπορεί να γίνει αναζητώντας τις καταχωρίσεις `browser.safebrowsing` στο `prefs.js`, υποδεικνύοντας εάν οι δυνατότητες ασφαλούς πλοήγησης είναι ενεργοποιημένες ή απενεργοποιημένες.

Για να προσπαθήσετε να αποκρυπτογραφήσετε τον κύριο κωδικό πρόσβασης, μπορείτε να χρησιμοποιήσετε [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Με το παρακάτω σενάριο και κλήση μπορείτε να καθορίσετε ένα αρχείο κωδικού πρόσβασης για brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![](<../../../images/image (417).png>)

## Google Chrome

Ο Google Chrome αποθηκεύει τα προφίλ χρηστών σε συγκεκριμένες τοποθεσίες ανάλογα με το λειτουργικό σύστημα:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Μέσα σε αυτούς τους καταλόγους, τα περισσότερα δεδομένα χρηστών μπορούν να βρεθούν στους φακέλους **Default/** ή **ChromeDefaultData/**. Τα παρακάτω αρχεία περιέχουν σημαντικά δεδομένα:

- **History**: Περιέχει URLs, λήψεις και λέξεις-κλειδιά αναζήτησης. Στα Windows, μπορεί να χρησιμοποιηθεί το [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) για να διαβαστεί το ιστορικό. Η στήλη "Transition Type" έχει διάφορες σημασίες, συμπεριλαμβανομένων των κλικ χρηστών σε συνδέσμους, πληκτρολογημένων URLs, υποβολών φορμών και ανανεώσεων σελίδων.
- **Cookies**: Αποθηκεύει cookies. Για επιθεώρηση, είναι διαθέσιμο το [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Περιέχει δεδομένα cache. Για επιθεώρηση, οι χρήστες Windows μπορούν να χρησιμοποιήσουν το [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).
- **Bookmarks**: Σελιδοδείκτες χρηστών.
- **Web Data**: Περιέχει ιστορικό φορμών.
- **Favicons**: Αποθηκεύει τα favicons ιστοσελίδων.
- **Login Data**: Περιλαμβάνει διαπιστευτήρια σύνδεσης όπως ονόματα χρηστών και κωδικούς πρόσβασης.
- **Current Session**/**Current Tabs**: Δεδομένα σχετικά με την τρέχουσα συνεδρία περιήγησης και τις ανοιχτές καρτέλες.
- **Last Session**/**Last Tabs**: Πληροφορίες σχετικά με τους ιστότοπους που ήταν ενεργοί κατά την τελευταία συνεδρία πριν κλείσει ο Chrome.
- **Extensions**: Κατάλογοι για επεκτάσεις και πρόσθετα του προγράμματος περιήγησης.
- **Thumbnails**: Αποθηκεύει μικρογραφίες ιστοσελίδων.
- **Preferences**: Ένα αρχείο πλούσιο σε πληροφορίες, συμπεριλαμβανομένων ρυθμίσεων για πρόσθετα, επεκτάσεις, αναδυόμενα παράθυρα, ειδοποιήσεις και άλλα.
- **Browser’s built-in anti-phishing**: Για να ελέγξετε αν είναι ενεργοποιημένη η προστασία κατά του phishing και του κακόβουλου λογισμικού, εκτελέστε `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Αναζητήστε `{"enabled: true,"}` στην έξοδο.

## **SQLite DB Data Recovery**

Όπως μπορείτε να παρατηρήσετε στις προηγούμενες ενότητες, τόσο ο Chrome όσο και ο Firefox χρησιμοποιούν **SQLite** βάσεις δεδομένων για να αποθηκεύσουν τα δεδομένα. Είναι δυνατόν να **ανακτηθούν διαγραμμένες εγγραφές χρησιμοποιώντας το εργαλείο** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ή** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Ο Internet Explorer 11 διαχειρίζεται τα δεδομένα και τα μεταδεδομένα του σε διάφορες τοποθεσίες, διευκολύνοντας τη διαχωριστική αποθήκευση των πληροφοριών και των αντίστοιχων λεπτομερειών για εύκολη πρόσβαση και διαχείριση.

### Metadata Storage

Τα μεταδεδομένα για τον Internet Explorer αποθηκεύονται στο `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (με το VX να είναι V01, V16 ή V24). Συνοδευόμενο από αυτό, το αρχείο `V01.log` μπορεί να δείξει διαφορές χρόνου τροποποίησης με το `WebcacheVX.data`, υποδεικνύοντας την ανάγκη επισκευής χρησιμοποιώντας `esentutl /r V01 /d`. Αυτά τα μεταδεδομένα, που φιλοξενούνται σε μια βάση δεδομένων ESE, μπορούν να ανακτηθούν και να επιθεωρηθούν χρησιμοποιώντας εργαλεία όπως το photorec και το [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), αντίστοιχα. Μέσα στον πίνακα **Containers**, μπορεί κανείς να διακρίνει τους συγκεκριμένους πίνακες ή κοντέινερ όπου αποθηκεύεται κάθε τμήμα δεδομένων, συμπεριλαμβανομένων των λεπτομερειών cache για άλλα εργαλεία της Microsoft όπως το Skype.

### Cache Inspection

Το εργαλείο [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) επιτρέπει την επιθεώρηση της cache, απαιτώντας την τοποθεσία του φακέλου εξαγωγής δεδομένων cache. Τα μεταδεδομένα για την cache περιλαμβάνουν το όνομα αρχείου, τον κατάλογο, τον αριθμό πρόσβασης, την προέλευση URL και χρονικές σφραγίδες που υποδεικνύουν τους χρόνους δημιουργίας, πρόσβασης, τροποποίησης και λήξης της cache.

### Cookies Management

Τα cookies μπορούν να εξερευνηθούν χρησιμοποιώντας το [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), με τα μεταδεδομένα να περιλαμβάνουν ονόματα, URLs, αριθμούς πρόσβασης και διάφορες λεπτομέρειες σχετικές με τον χρόνο. Τα μόνιμα cookies αποθηκεύονται στο `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, με τα cookies συνεδρίας να βρίσκονται στη μνήμη.

### Download Details

Τα μεταδεδομένα λήψεων είναι προσβάσιμα μέσω του [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), με συγκεκριμένα κοντέινερ να περιέχουν δεδομένα όπως URL, τύπο αρχείου και τοποθεσία λήψης. Τα φυσικά αρχεία μπορούν να βρεθούν κάτω από `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browsing History

Για να αναθεωρήσετε το ιστορικό περιήγησης, μπορεί να χρησιμοποιηθεί το [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), απαιτώντας την τοποθεσία των εξαγόμενων αρχείων ιστορικού και τη ρύθμιση για τον Internet Explorer. Τα μεταδεδομένα εδώ περιλαμβάνουν χρόνους τροποποίησης και πρόσβασης, καθώς και αριθμούς πρόσβασης. Τα αρχεία ιστορικού βρίσκονται στο `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Typed URLs

Οι πληκτρολογημένες URLs και οι χρόνοι χρήσης τους αποθηκεύονται στο μητρώο κάτω από `NTUSER.DAT` στο `Software\Microsoft\InternetExplorer\TypedURLs` και `Software\Microsoft\InternetExplorer\TypedURLsTime`, παρακολουθώντας τις τελευταίες 50 URLs που εισήγαγε ο χρήστης και τους τελευταίους χρόνους εισόδου τους.

## Microsoft Edge

Ο Microsoft Edge αποθηκεύει τα δεδομένα χρηστών στο `%userprofile%\Appdata\Local\Packages`. Οι διαδρομές για διάφορους τύπους δεδομένων είναι:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Τα δεδομένα του Safari αποθηκεύονται στο `/Users/$User/Library/Safari`. Κύρια αρχεία περιλαμβάνουν:

- **History.db**: Περιέχει πίνακες `history_visits` και `history_items` με URLs και χρονικές σφραγίδες επισκέψεων. Χρησιμοποιήστε το `sqlite3` για να κάνετε ερωτήσεις.
- **Downloads.plist**: Πληροφορίες σχετικά με τα ληφθέντα αρχεία.
- **Bookmarks.plist**: Αποθηκεύει τα URLs που έχουν προστεθεί στους σελιδοδείκτες.
- **TopSites.plist**: Οι πιο συχνά επισκεπτόμενοι ιστότοποι.
- **Extensions.plist**: Λίστα με τις επεκτάσεις του προγράμματος περιήγησης Safari. Χρησιμοποιήστε το `plutil` ή το `pluginkit` για να ανακτήσετε.
- **UserNotificationPermissions.plist**: Τομείς που επιτρέπεται να στέλνουν ειδοποιήσεις. Χρησιμοποιήστε το `plutil` για να αναλύσετε.
- **LastSession.plist**: Καρτέλες από την τελευταία συνεδρία. Χρησιμοποιήστε το `plutil` για να αναλύσετε.
- **Browser’s built-in anti-phishing**: Ελέγξτε χρησιμοποιώντας `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Μια απάντηση 1 υποδεικνύει ότι η δυνατότητα είναι ενεργή.

## Opera

Τα δεδομένα του Opera βρίσκονται στο `/Users/$USER/Library/Application Support/com.operasoftware.Opera` και μοιράζονται τη μορφή του Chrome για ιστορικό και λήψεις.

- **Browser’s built-in anti-phishing**: Επαληθεύστε ελέγχοντας αν το `fraud_protection_enabled` στο αρχείο Preferences είναι ρυθμισμένο σε `true` χρησιμοποιώντας `grep`.

Αυτές οι διαδρομές και οι εντολές είναι κρίσιμες για την πρόσβαση και την κατανόηση των δεδομένων περιήγησης που αποθηκεύονται από διάφορους ιστότοπους.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**

{{#include ../../../banners/hacktricks-training.md}}
