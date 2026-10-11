# Τεκμήρια προγράμματος περιήγησης

{{#include ../../../banners/hacktricks-training.md}}

## Τεκμήρια προγραμμάτων περιήγησης <a href="#id-3def" id="id-3def"></a>

Τα τεκμήρια προγραμμάτων περιήγησης περιλαμβάνουν διάφορους τύπους δεδομένων που αποθηκεύονται από τα προγράμματα περιήγησης ιστού, όπως ιστορικό περιήγησης, σελιδοδείκτες και δεδομένα προσωρινής μνήμης. Τα τεκμήρια αυτά διατηρούνται σε συγκεκριμένους φακέλους του λειτουργικού συστήματος, οι οποίοι διαφέρουν ως προς τη θέση και το όνομα ανάλογα με το πρόγραμμα περιήγησης, αλλά γενικά αποθηκεύουν παρόμοιους τύπους δεδομένων.

Ακολουθεί μια σύνοψη των πιο συνηθισμένων τεκμηρίων προγραμμάτων περιήγησης:

- **Ιστορικό περιήγησης**: Καταγράφει τις επισκέψεις του χρήστη σε ιστότοπους και είναι χρήσιμο για τον εντοπισμό επισκέψεων σε κακόβουλους ιστότοπους.
- **Δεδομένα αυτόματης συμπλήρωσης**: Προτάσεις που βασίζονται σε συχνές αναζητήσεις, οι οποίες προσφέρουν πληροφορίες όταν συνδυάζονται με το ιστορικό περιήγησης.
- **Σελιδοδείκτες**: Ιστότοποι που αποθηκεύει ο χρήστης για γρήγορη πρόσβαση.
- **Επεκτάσεις και πρόσθετα**: Επεκτάσεις ή πρόσθετα προγράμματος περιήγησης που έχει εγκαταστήσει ο χρήστης.
- **Προσωρινή μνήμη**: Αποθηκεύει περιεχόμενο ιστού (π.χ. εικόνες, αρχεία JavaScript) για να βελτιώνει τους χρόνους φόρτωσης των ιστότοπων και είναι πολύτιμη για την εγκληματολογική ανάλυση.
- **Στοιχεία σύνδεσης**: Αποθηκευμένα διαπιστευτήρια σύνδεσης.
- **Favicons**: Εικονίδια που σχετίζονται με ιστότοπους και εμφανίζονται στις καρτέλες και στους σελιδοδείκτες, χρήσιμα για πρόσθετες πληροφορίες σχετικά με τις επισκέψεις του χρήστη.
- **Συνεδρίες προγράμματος περιήγησης**: Δεδομένα που σχετίζονται με ανοιχτές συνεδρίες του προγράμματος περιήγησης.
- **Λήψεις**: Καταγραφές αρχείων που λήφθηκαν μέσω του προγράμματος περιήγησης.
- **Δεδομένα φορμών**: Πληροφορίες που εισάγονται σε φόρμες ιστού και αποθηκεύονται για μελλοντικές προτάσεις αυτόματης συμπλήρωσης.
- **Μικρογραφίες**: Εικόνες προεπισκόπησης ιστότοπων.
- **Custom Dictionary.txt**: Λέξεις που πρόσθεσε ο χρήστης στο λεξικό του προγράμματος περιήγησης.

## Firefox

Το Firefox οργανώνει τα δεδομένα χρηστών σε προφίλ, τα οποία αποθηκεύονται σε συγκεκριμένες τοποθεσίες ανάλογα με το λειτουργικό σύστημα:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Ένα αρχείο `profiles.ini` σε αυτούς τους καταλόγους παραθέτει τα προφίλ χρηστών. Τα δεδομένα κάθε προφίλ αποθηκεύονται σε έναν φάκελο με όνομα που ορίζεται στη μεταβλητή `Path` του `profiles.ini`, ο οποίος βρίσκεται στον ίδιο κατάλογο με το ίδιο το `profiles.ini`. Αν λείπει ο φάκελος ενός προφίλ, ενδέχεται να έχει διαγραφεί.

Σε κάθε φάκελο προφίλ βρίσκονται αρκετά σημαντικά αρχεία:<sup>[[1]](#references)</sup>

- **places.sqlite**: Αποθηκεύει το ιστορικό, τους σελιδοδείκτες και τις λήψεις. Εργαλεία όπως το [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) στα Windows μπορούν να έχουν πρόσβαση στα δεδομένα ιστορικού.
  - Χρησιμοποιήστε συγκεκριμένα ερωτήματα SQL για την εξαγωγή πληροφοριών ιστορικού και λήψεων.
- **bookmarkbackups**: Περιέχει αντίγραφα ασφαλείας των σελιδοδεικτών.
- **formhistory.sqlite**: Αποθηκεύει δεδομένα φορμών ιστού.
- **handlers.json**: Διαχειρίζεται τους χειριστές πρωτοκόλλων.
- **persdict.dat**: Λέξεις του προσαρμοσμένου λεξικού.
- **addons.json** και **extensions.sqlite**: Πληροφορίες για εγκατεστημένα πρόσθετα και επεκτάσεις.
- **cookies.sqlite**: Αποθήκευση cookies. Για την εξέτασή τους στα Windows είναι διαθέσιμο το [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** ή **startupCache**: Δεδομένα προσωρινής μνήμης, στα οποία μπορείτε να αποκτήσετε πρόσβαση με εργαλεία όπως το [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Αποθηκεύει favicons.
- **prefs.js**: Ρυθμίσεις και προτιμήσεις χρήστη.
- **downloads.sqlite**: Παλαιότερη βάση δεδομένων λήψεων, η οποία πλέον έχει ενσωματωθεί στο places.sqlite.
- **thumbnails**: Μικρογραφίες ιστοτόπων.
- **logins.json**: Κρυπτογραφημένες πληροφορίες σύνδεσης.
- **key4.db** ή **key3.db**: Αποθηκεύει κλειδιά κρυπτογράφησης για την προστασία ευαίσθητων πληροφοριών.

Επιπλέον, μπορείτε να ελέγξετε τις ρυθμίσεις anti-phishing του προγράμματος περιήγησης αναζητώντας καταχωρίσεις `browser.safebrowsing` στο `prefs.js`, οι οποίες υποδεικνύουν αν οι λειτουργίες ασφαλούς περιήγησης είναι ενεργοποιημένες ή απενεργοποιημένες.<sup>[[2]](#references)</sup>

Για να αποκρυπτογραφήσετε αποθηκευμένα στοιχεία σύνδεσης από ένα προσβάσιμο προφίλ, πρέπει να δώσετε τον [Κύριο κωδικό πρόσβασης του Firefox](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), εφόσον έχει οριστεί, ή να τον ανακτήσετε ξεχωριστά· το προφίλ δεν αποκαλύπτει αυτόν τον κωδικό πρόσβασης. Επιβεβαιώστε ότι τυχόν ανακτημένα στοιχεία σύνδεσης επιτρέπουν την αυθεντικοποίηση στον αντίστοιχο λογαριασμό ιστού. Για πρόσβαση root στο Unix απαιτείται ξεχωριστή απόδειξη ότι τα διαπιστευτήρια γίνονται επίσης δεκτά από τον μηχανισμό αυθεντικοποίησης του Unix για τον root. Μπορείτε να εξετάσετε τα αποθηκευμένα στοιχεία σύνδεσης με το [firefox_decrypt](https://github.com/unode/firefox_decrypt). Το ακόλουθο παράδειγμα ελέγχει υποψήφιους Κύριους κωδικούς πρόσβασης από ένα αρχείο κωδικών πρόσβασης:

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![Τεχνουργήματα browser - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Το Google Chrome αποθηκεύει τα προφίλ χρηστών σε συγκεκριμένες τοποθεσίες, ανάλογα με το λειτουργικό σύστημα:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Στους καταλόγους αυτούς, τα περισσότερα δεδομένα χρηστών βρίσκονται στους φακέλους **Default/** ή **ChromeDefaultData/**. Τα παρακάτω αρχεία περιέχουν σημαντικά δεδομένα:<sup>[[1]](#references)</sup>

- **History**: Περιέχει URL, λήψεις και λέξεις-κλειδιά αναζήτησης. Στα Windows, μπορείτε να χρησιμοποιήσετε το [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) για να διαβάσετε το ιστορικό. Η στήλη "Transition Type" έχει διάφορες σημασίες, όπως κλικ του χρήστη σε συνδέσμους, πληκτρολογημένα URL, υποβολές φορμών και επαναφορτώσεις σελίδων.
- **Cookies**: Αποθηκεύει cookies. Για την επιθεώρησή τους, διατίθεται το [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Περιέχει αποθηκευμένα δεδομένα. Για την επιθεώρησή τους, οι χρήστες Windows μπορούν να χρησιμοποιήσουν το [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

  Οι εφαρμογές desktop που βασίζονται στο Electron (π.χ. Discord) χρησιμοποιούν επίσης το Chromium Simple Cache και αφήνουν πλούσια τεχνουργήματα στον δίσκο. Δείτε:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: Σελιδοδείκτες χρήστη.
- **Web Data**: Περιέχει το ιστορικό φορμών.
- **Favicons**: Αποθηκεύει τα favicons ιστοτόπων.
- **Login Data**: Περιλαμβάνει διαπιστευτήρια σύνδεσης, όπως ονόματα χρηστών και κωδικούς πρόσβασης.
- **Current Session**/**Current Tabs**: Δεδομένα για την τρέχουσα περίοδο περιήγησης και τις ανοιχτές καρτέλες.
- **Last Session**/**Last Tabs**: Πληροφορίες για τους ιστοτόπους που ήταν ενεργοί κατά την τελευταία περίοδο περιήγησης πριν κλείσει το Chrome.
- **Extensions**: Κατάλογοι για επεκτάσεις και πρόσθετα του browser.
- **Thumbnails**: Αποθηκεύει μικρογραφίες ιστοτόπων.
- **Preferences**: Αρχείο με πολλές πληροφορίες, όπως ρυθμίσεις για πρόσθετα, επεκτάσεις, αναδυόμενα παράθυρα, ειδοποιήσεις και άλλα.
- **Browser’s built-in anti-phishing**: Για να ελέγξετε αν είναι ενεργοποιημένη η προστασία από phishing και malware, εκτελέστε `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Αναζητήστε το `{"enabled: true,"}` στην έξοδο.<sup>[[2]](#references)</sup>

Ο κατάλογος `Local Extension Settings/<extension-id>/` ενός προφίλ Chromium μπορεί να περιέχει τοπικά δεδομένα κατάστασης επέκτασης, όπως υλικό κλειδιού ενός password manager. Για παράδειγμα, η [Passbolt αναφέρει ότι το κρυπτογραφημένο ιδιωτικό κλειδί της αποθηκεύεται στον τοπικό χώρο αποθήκευσης της επέκτασης browser](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), ενώ το [Chrome extension ID της](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) προσδιορίζει τον σχετικό κατάλογο. Η παρουσία του καταλόγου από μόνη της ούτε αποδεικνύει ότι υπάρχει κλειδί ούτε ξεκλειδώνει ένα vault: ο χρήστης πρέπει να έχει πρόσβαση στα δεδομένα του προφίλ, σε ένα έγκυρο ιδιωτικό κλειδί και passphrase, καθώς και σε εξουσιοδοτημένη διαδικασία ανάκτησης/ταυτοποίησης στον server. Για ένα στοιχείο vault που περιέχει κωδικό πρόσβασης λογαριασμού λειτουργικού συστήματος απαιτείται ξεχωριστή επαλήθευση επαναχρησιμοποίησης του λογαριασμού. Η συνήθης απαρίθμηση πρέπει να αναφέρει μόνο τη διαδρομή αποθήκευσης, χωρίς να εξάγει τα αρχεία LevelDB ή τις μυστικές τιμές τους.

## **Ανάκτηση δεδομένων SQLite DB**

Όπως μπορείτε να παρατηρήσετε στις προηγούμενες ενότητες, τόσο το Chrome όσο και το Firefox χρησιμοποιούν βάσεις δεδομένων **SQLite** για την αποθήκευση δεδομένων. Είναι δυνατή η **ανάκτηση διαγραμμένων εγγραφών με το εργαλείο** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ή το** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Το Internet Explorer 11 διαχειρίζεται τα δεδομένα και τα μεταδεδομένα του σε διάφορες τοποθεσίες, ώστε να διαχωρίζονται οι αποθηκευμένες πληροφορίες από τις αντίστοιχες λεπτομέρειές τους και να είναι εύκολη η πρόσβαση και η διαχείρισή τους.

### Αποθήκευση μεταδεδομένων

Τα μεταδεδομένα του Internet Explorer αποθηκεύονται στο `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (όπου VX είναι V01, V16 ή V24). Το συνοδευτικό αρχείο `V01.log` ενδέχεται να εμφανίζει διαφορές στον χρόνο τροποποίησης σε σχέση με το `WebcacheVX.data`, υποδεικνύοντας ότι απαιτείται επιδιόρθωση με `esentutl /r V01 /d`. Αυτά τα μεταδεδομένα, που βρίσκονται σε μια βάση δεδομένων ESE, μπορούν να ανακτηθούν και να επιθεωρηθούν με εργαλεία όπως τα photorec και [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), αντίστοιχα. Στον πίνακα **Containers** μπορείτε να διακρίνετε τους συγκεκριμένους πίνακες ή περιέκτες όπου αποθηκεύεται κάθε τμήμα δεδομένων, συμπεριλαμβανομένων των λεπτομερειών cache για άλλα εργαλεία της Microsoft, όπως το Skype.

### Επιθεώρηση cache

Το εργαλείο [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) επιτρέπει την επιθεώρηση της cache και απαιτεί τη θέση του φακέλου εξαγωγής των δεδομένων cache. Τα μεταδεδομένα της cache περιλαμβάνουν όνομα αρχείου, κατάλογο, αριθμό προσβάσεων, προέλευση URL και χρονικές σημάνσεις δημιουργίας, πρόσβασης, τροποποίησης και λήξης της cache.

### Διαχείριση cookies

Μπορείτε να εξετάσετε τα cookies με το [IECookiesView](https://www.nirsoft.net/utils/iecookies.html). Τα μεταδεδομένα περιλαμβάνουν ονόματα, URL, αριθμό προσβάσεων και διάφορα στοιχεία χρόνου. Τα μόνιμα cookies αποθηκεύονται στο `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, ενώ τα cookies περιόδου λειτουργίας παραμένουν στη μνήμη.

### Λεπτομέρειες λήψεων

Τα μεταδεδομένα λήψεων είναι προσβάσιμα μέσω του [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), με συγκεκριμένους περιέκτες να διατηρούν δεδομένα όπως URL, τύπο αρχείου και τοποθεσία λήψης. Τα φυσικά αρχεία βρίσκονται στο `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Ιστορικό περιήγησης

Για να εξετάσετε το ιστορικό περιήγησης, μπορείτε να χρησιμοποιήσετε το [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), ορίζοντας τη θέση των εξαγμένων αρχείων ιστορικού και τις ρυθμίσεις για το Internet Explorer. Τα μεταδεδομένα περιλαμβάνουν χρόνους τροποποίησης και πρόσβασης, καθώς και αριθμούς προσβάσεων. Τα αρχεία ιστορικού βρίσκονται στο `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Πληκτρολογημένα URL

Τα πληκτρολογημένα URL και οι χρόνοι χρήσης τους αποθηκεύονται στο μητρώο, στο `NTUSER.DAT`, στις θέσεις `Software\Microsoft\InternetExplorer\TypedURLs` και `Software\Microsoft\InternetExplorer\TypedURLsTime`. Παρακολουθούν τα τελευταία 50 URL που πληκτρολόγησε ο χρήστης και τις αντίστοιχες ώρες τελευταίας εισαγωγής.

## Microsoft Edge

Το Microsoft Edge αποθηκεύει δεδομένα χρηστών στο `%userprofile%\Appdata\Local\Packages`. Οι διαδρομές για τους διάφορους τύπους δεδομένων είναι οι εξής:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Τα δεδομένα του Safari αποθηκεύονται στο `/Users/$User/Library/Safari`. Σημαντικά αρχεία είναι τα εξής:<sup>[[3]](#references)</sup>

- **History.db**: Περιέχει τους πίνακες `history_visits` και `history_items` με URL και χρονικές σημάνσεις επισκέψεων. Χρησιμοποιήστε το `sqlite3` για ερωτήματα.
- **Downloads.plist**: Πληροφορίες για αρχεία που έχουν ληφθεί.
- **Bookmarks.plist**: Αποθηκεύει URL σελιδοδεικτών.
- **TopSites.plist**: Ιστότοποι με τις περισσότερες επισκέψεις.
- **Extensions.plist**: Λίστα με τις επεκτάσεις του browser Safari. Χρησιμοποιήστε τα `plutil` ή `pluginkit` για να τις ανακτήσετε.
- **UserNotificationPermissions.plist**: Domains που επιτρέπεται να στέλνουν push notifications. Χρησιμοποιήστε το `plutil` για ανάλυση.
- **LastSession.plist**: Καρτέλες από την τελευταία περίοδο περιήγησης. Χρησιμοποιήστε το `plutil` για ανάλυση.
- **Browser’s built-in anti-phishing**: Ελέγξτε το με `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Η απόκριση 1 υποδεικνύει ότι η λειτουργία είναι ενεργή.<sup>[[2]](#references)</sup>

## Opera

Τα δεδομένα του Opera βρίσκονται στο `/Users/$USER/Library/Application Support/com.operasoftware.Opera` και χρησιμοποιούν την ίδια μορφή με το Chrome για το ιστορικό και τις λήψεις.

- **Browser’s built-in anti-phishing**: Επαληθεύστε με `grep` αν το `fraud_protection_enabled` στο αρχείο Preferences έχει οριστεί σε `true`.<sup>[[2]](#references)</sup>

Αυτές οι διαδρομές και οι εντολές είναι απαραίτητες για την πρόσβαση και την κατανόηση των δεδομένων περιήγησης που αποθηκεύουν διαφορετικοί web browsers.

## References

- [1] [Ψηφιακή εγκληματολογική ανάλυση web browsers: Οδηγός για την εγκληματολογική ανάλυση web browsers](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Απόκριση σε περιστατικά macOS | Μέρος 3: Χειραγώγηση συστήματος](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Απόκριση σε περιστατικά OS X: Scripting και ανάλυση, του Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
