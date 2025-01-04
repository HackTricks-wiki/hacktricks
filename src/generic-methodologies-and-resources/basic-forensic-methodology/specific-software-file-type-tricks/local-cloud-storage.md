# Τοπική Αποθήκευση Cloud

{{#include ../../../banners/hacktricks-training.md}}

## OneDrive

Στα Windows, μπορείτε να βρείτε τον φάκελο OneDrive στο `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Και μέσα στο `logs\Personal` είναι δυνατόν να βρείτε το αρχείο `SyncDiagnostics.log` το οποίο περιέχει κάποια ενδιαφέροντα δεδομένα σχετικά με τα συγχρονισμένα αρχεία:

- Μέγεθος σε bytes
- Ημερομηνία δημιουργίας
- Ημερομηνία τροποποίησης
- Αριθμός αρχείων στο cloud
- Αριθμός αρχείων στον φάκελο
- **CID**: Μοναδικό ID του χρήστη OneDrive
- Χρόνος δημιουργίας αναφοράς
- Μέγεθος του HD του OS

Αφού βρείτε το CID, συνιστάται να **αναζητήσετε αρχεία που περιέχουν αυτό το ID**. Μπορείτε να βρείτε αρχεία με το όνομα: _**\<CID>.ini**_ και _**\<CID>.dat**_ που μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες όπως τα ονόματα των αρχείων που συγχρονίστηκαν με το OneDrive.

## Google Drive

Στα Windows, μπορείτε να βρείτε τον κύριο φάκελο Google Drive στο `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Αυτός ο φάκελος περιέχει ένα αρχείο που ονομάζεται Sync_log.log με πληροφορίες όπως τη διεύθυνση email του λογαριασμού, ονόματα αρχείων, χρονικές σφραγίδες, MD5 hashes των αρχείων, κ.λπ. Ακόμα και τα διαγραμμένα αρχεία εμφανίζονται σε αυτό το αρχείο καταγραφής με το αντίστοιχο MD5.

Το αρχείο **`Cloud_graph\Cloud_graph.db`** είναι μια βάση δεδομένων sqlite που περιέχει τον πίνακα **`cloud_graph_entry`**. Σε αυτόν τον πίνακα μπορείτε να βρείτε το **όνομα** των **συγχρονισμένων** **αρχείων**, την τροποποιημένη ώρα, το μέγεθος και το MD5 checksum των αρχείων.

Τα δεδομένα του πίνακα της βάσης δεδομένων **`Sync_config.db`** περιέχουν τη διεύθυνση email του λογαριασμού, τη διαδρομή των κοινών φακέλων και την έκδοση του Google Drive.

## Dropbox

Το Dropbox χρησιμοποιεί **SQLite βάσεις δεδομένων** για τη διαχείριση των αρχείων. Σε αυτό\
Μπορείτε να βρείτε τις βάσεις δεδομένων στους φακέλους:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Και οι κύριες βάσεις δεδομένων είναι:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Η επέκταση ".dbx" σημαίνει ότι οι **βάσεις δεδομένων** είναι **κρυπτογραφημένες**. Το Dropbox χρησιμοποιεί **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Για να κατανοήσετε καλύτερα την κρυπτογράφηση που χρησιμοποιεί το Dropbox, μπορείτε να διαβάσετε [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Ωστόσο, οι κύριες πληροφορίες είναι:

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Εκτός από αυτές τις πληροφορίες, για να αποκρυπτογραφήσετε τις βάσεις δεδομένων χρειάζεστε επίσης:

- Το **κρυπτογραφημένο κλειδί DPAPI**: Μπορείτε να το βρείτε στο μητρώο μέσα στο `NTUSER.DAT\Software\Dropbox\ks\client` (εξάγετε αυτά τα δεδομένα ως δυαδικά)
- Τις **hives** **`SYSTEM`** και **`SECURITY`**
- Τα **master keys DPAPI**: Τα οποία μπορούν να βρεθούν στο `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Το **όνομα χρήστη** και τον **κωδικό πρόσβασης** του χρήστη των Windows

Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το εργαλείο [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![](<../../../images/image (443).png>)

Αν όλα πάνε όπως αναμένεται, το εργαλείο θα υποδείξει το **κύριο κλειδί** που χρειάζεστε για να **ανακτήσετε το αρχικό**. Για να ανακτήσετε το αρχικό, απλώς χρησιμοποιήστε αυτή τη [συνταγή cyber_chef](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) βάζοντας το κύριο κλειδί ως "passphrase" μέσα στη συνταγή.

Το προκύπτον hex είναι το τελικό κλειδί που χρησιμοποιείται για την κρυπτογράφηση των βάσεων δεδομένων που μπορεί να αποκρυπτογραφηθεί με:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Η **`config.dbx`** βάση δεδομένων περιέχει:

- **Email**: Το email του χρήστη
- **usernamedisplayname**: Το όνομα του χρήστη
- **dropbox_path**: Διαδρομή όπου βρίσκεται ο φάκελος του dropbox
- **Host_id: Hash** που χρησιμοποιείται για την αυθεντικοποίηση στο cloud. Αυτό μπορεί να ανακληθεί μόνο από το διαδίκτυο.
- **Root_ns**: Αναγνωριστικό χρήστη

Η **`filecache.db`** βάση δεδομένων περιέχει πληροφορίες σχετικά με όλα τα αρχεία και τους φακέλους που συγχρονίζονται με το Dropbox. Ο πίνακας `File_journal` είναι αυτός με τις πιο χρήσιμες πληροφορίες:

- **Server_path**: Διαδρομή όπου βρίσκεται το αρχείο μέσα στον διακομιστή (αυτή η διαδρομή προηγείται από το `host_id` του πελάτη).
- **local_sjid**: Έκδοση του αρχείου
- **local_mtime**: Ημερομηνία τροποποίησης
- **local_ctime**: Ημερομηνία δημιουργίας

Άλλοι πίνακες μέσα σε αυτή τη βάση δεδομένων περιέχουν πιο ενδιαφέρουσες πληροφορίες:

- **block_cache**: hash όλων των αρχείων και φακέλων του Dropbox
- **block_ref**: Συσχετίζει το hash ID του πίνακα `block_cache` με το ID του αρχείου στον πίνακα `file_journal`
- **mount_table**: Κοινόχρηστοι φάκελοι του dropbox
- **deleted_fields**: Διαγραμμένα αρχεία του Dropbox
- **date_added**

{{#include ../../../banners/hacktricks-training.md}}
