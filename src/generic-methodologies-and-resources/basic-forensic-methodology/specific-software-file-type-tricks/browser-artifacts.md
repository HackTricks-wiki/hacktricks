# Τεκμήρια Browser

{{#include ../../../banners/hacktricks-training.md}}

## Τεκμήρια Browser <a href="#id-3def" id="id-3def"></a>

Τα τεκμήρια browser περιλαμβάνουν διάφορους τύπους δεδομένων που αποθηκεύονται από τους web browsers, όπως ιστορικό περιήγησης, σελιδοδείκτες και δεδομένα cache. Αυτά τα τεκμήρια φυλάσσονται σε συγκεκριμένους φακέλους του λειτουργικού συστήματος, των οποίων η τοποθεσία και το όνομα διαφέρουν ανά browser, αλλά συνήθως αποθηκεύουν παρόμοιους τύπους δεδομένων.

Ακολουθεί μια σύνοψη των πιο συνηθισμένων τεκμηρίων browser:

- **Ιστορικό περιήγησης**: Καταγράφει τις επισκέψεις του χρήστη σε ιστοτόπους και είναι χρήσιμο για τον εντοπισμό επισκέψεων σε κακόβουλους ιστοτόπους.
- **Δεδομένα αυτόματης συμπλήρωσης**: Προτάσεις που βασίζονται σε συχνές αναζητήσεις, οι οποίες προσφέρουν πληροφορίες όταν συνδυάζονται με το ιστορικό περιήγησης.
- **Σελιδοδείκτες**: Ιστότοποι που έχει αποθηκεύσει ο χρήστης για γρήγορη πρόσβαση.
- **Επεκτάσεις και πρόσθετα**: Επεκτάσεις ή πρόσθετα browser που έχει εγκαταστήσει ο χρήστης.
- **Cache**: Αποθηκεύει περιεχόμενο ιστού (π.χ. εικόνες, αρχεία JavaScript) για να επιταχύνει τη φόρτωση ιστοτόπων και είναι πολύτιμο για εγκληματολογική ανάλυση.
- **Συνδέσεις**: Αποθηκευμένα διαπιστευτήρια σύνδεσης.
- **Favicons**: Εικονίδια που σχετίζονται με ιστοτόπους και εμφανίζονται σε καρτέλες και σελιδοδείκτες, χρήσιμα για την άντληση πρόσθετων πληροφοριών σχετικά με τις επισκέψεις του χρήστη.
- **Συνεδρίες browser**: Δεδομένα σχετικά με τις ανοιχτές συνεδρίες browser.
- **Λήψεις**: Καταγραφές αρχείων που έχουν ληφθεί μέσω του browser.
- **Δεδομένα φορμών**: Πληροφορίες που έχουν καταχωριστεί σε web φόρμες και αποθηκεύονται για μελλοντικές προτάσεις αυτόματης συμπλήρωσης.
- **Μικρογραφίες**: Εικόνες προεπισκόπησης ιστοτόπων.
- **Custom Dictionary.txt**: Λέξεις που έχει προσθέσει ο χρήστης στο λεξικό του browser.

## Firefox

Ο Firefox οργανώνει τα δεδομένα χρήστη σε προφίλ, τα οποία αποθηκεύονται σε συγκεκριμένες τοποθεσίες ανάλογα με το λειτουργικό σύστημα:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Ένα αρχείο `profiles.ini` σε αυτούς τους καταλόγους περιέχει τα προφίλ χρηστών. Τα δεδομένα κάθε προφίλ αποθηκεύονται σε έναν φάκελο που ορίζεται στη μεταβλητή `Path` του `profiles.ini`, στον ίδιο κατάλογο με το ίδιο το `profiles.ini`. Αν λείπει ο φάκελος ενός προφίλ, ενδέχεται να έχει διαγραφεί.

Σε κάθε φάκελο προφίλ, μπορείτε να βρείτε αρκετά σημαντικά αρχεία:<sup>[[1]](#references)</sup>

- **places.sqlite**: Αποθηκεύει το ιστορικό, τους σελιδοδείκτες και τις λήψεις. Εργαλεία όπως το [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) στα Windows μπορούν να αποκτήσουν πρόσβαση στα δεδομένα ιστορικού.
  - Χρησιμοποιήστε συγκεκριμένα ερωτήματα SQL για να εξαγάγετε πληροφορίες ιστορικού και λήψεων.
- **bookmarkbackups**: Περιέχει αντίγραφα ασφαλείας των σελιδοδεικτών.
- **formhistory.sqlite**: Αποθηκεύει δεδομένα web φορμών.
- **handlers.json**: Διαχειρίζεται handlers πρωτοκόλλων.
- **persdict.dat**: Προσαρμοσμένες λέξεις λεξικού.
- **addons.json** και **extensions.sqlite**: Πληροφορίες για εγκατεστημένα πρόσθετα και επεκτάσεις.
- **cookies.sqlite**: Αποθήκευση cookies, τα οποία μπορούν να εξεταστούν στα Windows με το [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** ή **startupCache**: Δεδομένα cache, προσβάσιμα με εργαλεία όπως το [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Αποθηκεύει favicons.
- **prefs.js**: Ρυθμίσεις και προτιμήσεις χρήστη.
- **downloads.sqlite**: Παλαιότερη βάση δεδομένων λήψεων, η οποία πλέον έχει ενσωματωθεί στο places.sqlite.
- **thumbnails**: Μικρογραφίες ιστοτόπων.
- **logins.json**: Κρυπτογραφημένες πληροφορίες σύνδεσης.
- **key4.db** ή **key3.db**: Αποθηκεύει κλειδιά κρυπτογράφησης για την προστασία ευαίσθητων πληροφοριών.

Επιπλέον, μπορείτε να ελέγξετε τις ρυθμίσεις anti-phishing του browser αναζητώντας καταχωρίσεις `browser.safebrowsing` στο `prefs.js`, οι οποίες υποδεικνύουν αν οι λειτουργίες ασφαλούς περιήγησης είναι ενεργοποιημένες ή απενεργοποιημένες.<sup>[[2]](#references)</sup>

Για να αποκρυπτογραφήσετε αποθηκευμένα στοιχεία σύνδεσης από ένα προσβάσιμο προφίλ, πρέπει να δοθεί ή να ανακτηθεί χωριστά ο [Κύριος κωδικός πρόσβασης Firefox](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), εφόσον έχει οριστεί· το προφίλ δεν αποκαλύπτει αυτόν τον κωδικό πρόσβασης. Επιβεβαιώστε ότι τυχόν ανακτημένα στοιχεία σύνδεσης επιτρέπουν την αυθεντικοποίηση στον αντίστοιχο web λογαριασμό. Η πρόσβαση root στο Unix απαιτεί ξεχωριστή απόδειξη ότι τα διαπιστευτήρια γίνονται επίσης δεκτά για αυθεντικοποίηση Unix ως root. Μπορείτε να εξετάσετε τα αποθηκευμένα στοιχεία σύνδεσης με το [firefox_decrypt](https://github.com/unode/firefox_decrypt). Το ακόλουθο παράδειγμα δοκιμάζει υποψήφιους Κύριους κωδικούς πρόσβασης από ένα αρχείο κωδικών πρόσβασης:

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![Τεκμήρια περιηγητών - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Το Google Chrome αποθηκεύει τα προφίλ χρηστών σε συγκεκριμένες τοποθεσίες, ανάλογα με το λειτουργικό σύστημα:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Μέσα σε αυτούς τους καταλόγους, τα περισσότερα δεδομένα χρήστη βρίσκονται στους φακέλους **Default/** ή **ChromeDefaultData/**. Τα ακόλουθα αρχεία περιέχουν σημαντικά δεδομένα:<sup>[[1]](#references)</sup>

- **History**: Περιέχει URL, λήψεις και λέξεις-κλειδιά αναζήτησης. Στα Windows, μπορείτε να χρησιμοποιήσετε το [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) για να διαβάσετε το ιστορικό. Η στήλη "Transition Type" έχει διάφορες σημασίες, όπως κλικ του χρήστη σε συνδέσμους, URL που πληκτρολογήθηκαν, υποβολές φορμών και επαναφορτώσεις σελίδων.
- **Cookies**: Αποθηκεύει cookies. Για την εξέτασή τους, διατίθεται το [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Περιέχει δεδομένα προσωρινής αποθήκευσης. Για την εξέτασή τους, οι χρήστες Windows μπορούν να χρησιμοποιήσουν το [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

  Οι desktop εφαρμογές που βασίζονται στο Electron (π.χ., Discord) χρησιμοποιούν επίσης το Chromium Simple Cache και αφήνουν πλούσια τεκμήρια στον δίσκο. Δείτε:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: Σελιδοδείκτες χρήστη.
- **Web Data**: Περιέχει το ιστορικό φορμών.
- **Favicons**: Αποθηκεύει τα favicons ιστοτόπων.
- **Login Data**: Περιλαμβάνει διαπιστευτήρια σύνδεσης, όπως ονόματα χρήστη και κωδικούς πρόσβασης.
- **Current Session**/**Current Tabs**: Δεδομένα για την τρέχουσα περίοδο περιήγησης και τις ανοιχτές καρτέλες.
- **Last Session**/**Last Tabs**: Πληροφορίες για τους ιστοτόπους που ήταν ενεργοί κατά την τελευταία περίοδο περιήγησης, πριν κλείσει το Chrome.
- **Extensions**: Κατάλογοι για επεκτάσεις και πρόσθετα του προγράμματος περιήγησης.
- **Thumbnails**: Αποθηκεύει μικρογραφίες ιστοτόπων.
- **Preferences**: Αρχείο με πολλές πληροφορίες, όπως ρυθμίσεις για plugins, επεκτάσεις, αναδυόμενα παράθυρα, ειδοποιήσεις και άλλα.
- **Ενσωματωμένη προστασία από ηλεκτρονικό ψάρεμα στο πρόγραμμα περιήγησης**: Για να ελέγξετε αν είναι ενεργοποιημένη η προστασία από ηλεκτρονικό ψάρεμα και κακόβουλο λογισμικό, εκτελέστε `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Αναζητήστε την ένδειξη `{"enabled: true,"}` στην έξοδο.<sup>[[2]](#references)</sup>

Ο κατάλογος `Local Extension Settings/<extension-id>/` ενός προφίλ Chromium ενδέχεται να περιέχει τοπική κατάσταση επεκτάσεων, όπως υλικό κλειδιών για διαχειριστές κωδικών πρόσβασης. Για παράδειγμα, το [Passbolt αναφέρει ότι το κρυπτογραφημένο ιδιωτικό κλειδί του αποθηκεύεται στον τοπικό χώρο αποθήκευσης της επέκτασης του προγράμματος περιήγησης](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), ενώ το [Chrome extension ID του](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) προσδιορίζει τον σχετικό κατάλογο. Η παρουσία του καταλόγου από μόνη της δεν αποδεικνύει ότι υπάρχει κλειδί ούτε ξεκλειδώνει ένα vault: ο χρήστης πρέπει να έχει πρόσβαση στα δεδομένα του προφίλ, σε ένα έγκυρο ιδιωτικό κλειδί και passphrase, καθώς και σε μια εξουσιοδοτημένη διαδικασία ανάκτησης/επαλήθευσης ταυτότητας στον server. Για ένα στοιχείο vault που περιέχει κωδικό πρόσβασης λογαριασμού λειτουργικού συστήματος, απαιτείται ξεχωριστή επαλήθευση επαναχρησιμοποίησης λογαριασμού. Η συνήθης καταγραφή πρέπει να αναφέρει μόνο τη διαδρομή αποθήκευσης, χωρίς να εξάγει τα αρχεία LevelDB ή τις μυστικές τιμές τους.

## **Ανάκτηση δεδομένων από SQLite DB**

Όπως μπορείτε να δείτε στις προηγούμενες ενότητες, τόσο το Chrome όσο και το Firefox χρησιμοποιούν βάσεις δεδομένων **SQLite** για την αποθήκευση δεδομένων. Είναι δυνατή η **ανάκτηση διαγραμμένων εγγραφών με το εργαλείο** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ή το** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Ο Internet Explorer 11 διαχειρίζεται τα δεδομένα και τα μεταδεδομένα του σε διάφορες τοποθεσίες, διαχωρίζοντας τις αποθηκευμένες πληροφορίες από τις αντίστοιχες λεπτομέρειές τους για εύκολη πρόσβαση και διαχείριση.

### Αποθήκευση μεταδεδομένων

Τα μεταδεδομένα του Internet Explorer αποθηκεύονται στο `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (όπου VX είναι V01, V16 ή V24). Το συνοδευτικό αρχείο `V01.log` ενδέχεται να εμφανίζει αποκλίσεις στον χρόνο τροποποίησης σε σχέση με το `WebcacheVX.data`, κάτι που υποδεικνύει ότι χρειάζεται επιδιόρθωση με την εντολή `esentutl /r V01 /d`. Αυτά τα μεταδεδομένα, τα οποία βρίσκονται σε βάση δεδομένων ESE, μπορούν να ανακτηθούν και να εξεταστούν με εργαλεία όπως τα photorec και [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), αντίστοιχα. Στον πίνακα **Containers**, μπορείτε να εντοπίσετε τους συγκεκριμένους πίνακες ή περιέκτες όπου αποθηκεύεται κάθε τμήμα δεδομένων, συμπεριλαμβανομένων λεπτομερειών cache για άλλα εργαλεία της Microsoft, όπως το Skype.

### Εξέταση cache

Το εργαλείο [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) επιτρέπει την εξέταση της cache και απαιτεί τη διαδρομή του φακέλου εξαγωγής των δεδομένων cache. Τα μεταδεδομένα της cache περιλαμβάνουν το όνομα αρχείου, τον κατάλογο, τον αριθμό προσβάσεων, την προέλευση URL και χρονικές σημάνσεις που δείχνουν πότε δημιουργήθηκε, προσπελάστηκε, τροποποιήθηκε και έληξε το στοιχείο της cache.

### Διαχείριση cookies

Μπορείτε να εξετάσετε τα cookies με το [IECookiesView](https://www.nirsoft.net/utils/iecookies.html). Τα μεταδεδομένα περιλαμβάνουν ονόματα, URL, αριθμούς προσβάσεων και διάφορα στοιχεία σχετικά με τον χρόνο. Τα μόνιμα cookies αποθηκεύονται στο `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, ενώ τα cookies περιόδου λειτουργίας βρίσκονται στη μνήμη.

### Λεπτομέρειες λήψεων

Τα μεταδεδομένα λήψεων είναι προσβάσιμα μέσω του [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), με συγκεκριμένους περιέκτες να περιέχουν δεδομένα όπως URL, τύπο αρχείου και τοποθεσία λήψης. Τα φυσικά αρχεία βρίσκονται στο `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Ιστορικό περιήγησης

Για την επισκόπηση του ιστορικού περιήγησης, μπορείτε να χρησιμοποιήσετε το [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), το οποίο απαιτεί την τοποθεσία των εξαγμένων αρχείων ιστορικού και τη ρύθμιση παραμέτρων για τον Internet Explorer. Τα μεταδεδομένα περιλαμβάνουν χρόνους τροποποίησης και πρόσβασης, καθώς και αριθμούς προσβάσεων. Τα αρχεία ιστορικού βρίσκονται στο `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL που πληκτρολογήθηκαν

Τα URL που πληκτρολογήθηκαν και οι χρόνοι χρήσης τους αποθηκεύονται στο μητρώο, στο `NTUSER.DAT`, στις θέσεις `Software\Microsoft\InternetExplorer\TypedURLs` και `Software\Microsoft\InternetExplorer\TypedURLsTime`. Εκεί καταγράφονται τα τελευταία 50 URL που εισήγαγε ο χρήστης και οι τελευταίες χρονικές στιγμές εισαγωγής τους.

## Microsoft Edge

Το Microsoft Edge αποθηκεύει τα δεδομένα χρήστη στο `%userprofile%\Appdata\Local\Packages`. Οι διαδρομές για τους διάφορους τύπους δεδομένων είναι οι εξής:<sup>[[1]](#references)</sup>

- **Διαδρομή προφίλ**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Ιστορικό, cookies και λήψεις**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Ρυθμίσεις, σελιδοδείκτες και λίστα ανάγνωσης**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Τελευταίες ενεργές περίοδοι λειτουργίας**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Τα δεδομένα του Safari αποθηκεύονται στο `/Users/$User/Library/Safari`. Σημαντικά αρχεία είναι τα εξής:<sup>[[3]](#references)</sup>

- **History.db**: Περιέχει τους πίνακες `history_visits` και `history_items` με URL και χρονικές σημάνσεις επισκέψεων. Χρησιμοποιήστε το `sqlite3` για ερωτήματα.
- **Downloads.plist**: Πληροφορίες για ληφθέντα αρχεία.
- **Bookmarks.plist**: Αποθηκεύει URL σελιδοδεικτών.
- **TopSites.plist**: Ιστότοποι με τις περισσότερες επισκέψεις.
- **Extensions.plist**: Λίστα επεκτάσεων του προγράμματος περιήγησης Safari. Χρησιμοποιήστε το `plutil` ή το `pluginkit` για ανάκτηση.
- **UserNotificationPermissions.plist**: Τομείς στους οποίους επιτρέπεται η αποστολή push notifications. Χρησιμοποιήστε το `plutil` για ανάλυση.
- **LastSession.plist**: Καρτέλες από την τελευταία περίοδο λειτουργίας. Χρησιμοποιήστε το `plutil` για ανάλυση.
- **Ενσωματωμένη προστασία από ηλεκτρονικό ψάρεμα στο πρόγραμμα περιήγησης**: Ελέγξτε τη με την εντολή `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Η τιμή 1 υποδεικνύει ότι η λειτουργία είναι ενεργή.<sup>[[2]](#references)</sup>

## Opera

Τα δεδομένα του Opera βρίσκονται στο `/Users/$USER/Library/Application Support/com.operasoftware.Opera` και χρησιμοποιούν την ίδια μορφή με το Chrome για το ιστορικό και τις λήψεις.

- **Ενσωματωμένη προστασία από ηλεκτρονικό ψάρεμα στο πρόγραμμα περιήγησης**: Επαληθεύστε με την εντολή `grep` αν το `fraud_protection_enabled` στο αρχείο Preferences έχει οριστεί σε `true`.<sup>[[2]](#references)</sup>

Αυτές οι διαδρομές και εντολές είναι απαραίτητες για την πρόσβαση και την κατανόηση των δεδομένων περιήγησης που αποθηκεύουν τα διάφορα προγράμματα περιήγησης.

## References

- [1] [Ψηφιακή εγκληματολογική ανάλυση προγραμμάτων περιήγησης: Οδηγός για την ανάλυση προγραμμάτων περιήγησης](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Αντιμετώπιση περιστατικών σε macOS | Μέρος 3: Χειρισμός συστήματος](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Αντιμετώπιση περιστατικών σε OS X: Scripting και ανάλυση, του Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
