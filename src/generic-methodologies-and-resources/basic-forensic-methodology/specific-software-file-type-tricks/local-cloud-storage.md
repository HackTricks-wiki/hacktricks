# Τοπική αποθήκευση Cloud

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

Στα Windows, μπορείτε να βρείτε τον φάκελο του OneDrive στο `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Και μέσα στο `logs\Personal` μπορείτε να βρείτε το αρχείο `SyncDiagnostics.log`, το οποίο περιέχει ενδιαφέροντα δεδομένα σχετικά με τα συγχρονισμένα αρχεία:

- Μέγεθος σε bytes
- Ημερομηνία δημιουργίας
- Ημερομηνία τροποποίησης
- Αριθμός αρχείων στο cloud
- Αριθμός αρχείων στον φάκελο
- **CID**: Μοναδικό ID του χρήστη του OneDrive
- Χρόνος δημιουργίας της αναφοράς
- Μέγεθος του HD του λειτουργικού συστήματος

Μόλις εντοπίσετε το CID, συνιστάται να **αναζητήσετε αρχεία που περιέχουν αυτό το ID**. Ενδέχεται να βρείτε αρχεία με τα ονόματα: _**\<CID>.ini**_ και _**\<CID>.dat**_, τα οποία μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες, όπως τα ονόματα των αρχείων που συγχρονίζονται με το OneDrive.

## Google Drive

Στα Windows, μπορείτε να βρείτε τον κύριο φάκελο του Google Drive στο `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Αυτός ο φάκελος περιέχει ένα αρχείο με το όνομα Sync_log.log, με πληροφορίες όπως τη διεύθυνση email του λογαριασμού, τα ονόματα αρχείων, timestamps, MD5 hashes των αρχείων κ.λπ. Ακόμη και τα διαγραμμένα αρχεία εμφανίζονται σε αυτό το αρχείο καταγραφής με το αντίστοιχο MD5.

Το αρχείο **`Cloud_graph\Cloud_graph.db`** είναι μια βάση δεδομένων sqlite, η οποία περιέχει τον πίνακα **`cloud_graph_entry`**. Σε αυτόν τον πίνακα μπορείτε να βρείτε το **όνομα** των **συγχρονισμένων** **αρχείων**, τον χρόνο τροποποίησης, το μέγεθος και το MD5 checksum των αρχείων.

Τα δεδομένα του πίνακα της βάσης δεδομένων **`Sync_config.db`** περιέχουν τη διεύθυνση email του λογαριασμού, τη διαδρομή των κοινόχρηστων φακέλων και την έκδοση του Google Drive.

## Dropbox

Το Dropbox χρησιμοποιεί **βάσεις δεδομένων SQLite** για τη διαχείριση των αρχείων. Σε αυτόν\
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

Για να κατανοήσετε καλύτερα την κρυπτογράφηση που χρησιμοποιεί το Dropbox, μπορείτε να διαβάσετε το [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Ωστόσο, οι κύριες πληροφορίες είναι:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Πέρα από αυτές τις πληροφορίες, για την αποκρυπτογράφηση των βάσεων δεδομένων εξακολουθείτε να χρειάζεστε:<sup>[[2]](#references)</sup>

- Το **κρυπτογραφημένο κλειδί DPAPI**: Μπορείτε να το βρείτε στο registry, μέσα στο `NTUSER.DAT\Software\Dropbox\ks\client` (εξαγάγετε αυτά τα δεδομένα ως binary)
- Τα hives **`SYSTEM`** και **`SECURITY`**
- Τα **κύρια κλειδιά DPAPI**: Μπορείτε να τα βρείτε στο `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Το **username** και το **password** του χρήστη των Windows

Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το εργαλείο [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το εργαλείο DataProtectionDecryptor](<../../../images/image (443).png>)

Αν όλα εξελιχθούν όπως αναμένεται, το εργαλείο θα υποδείξει το **primary key** που πρέπει να **χρησιμοποιήσετε για να ανακτήσετε το αρχικό**. Για να ανακτήσετε το αρχικό, απλώς χρησιμοποιήστε αυτό το [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) τοποθετώντας το primary key ως "passphrase" μέσα στο receipt.

Το resulting hex είναι το τελικό κλειδί που χρησιμοποιείται για την κρυπτογράφηση των βάσεων δεδομένων, οι οποίες μπορούν να αποκρυπτογραφηθούν με:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Η βάση δεδομένων **`config.dbx`** περιέχει:

- **Email**: Το email του χρήστη
- **usernamedisplayname**: Το όνομα του χρήστη
- **dropbox_path**: Η διαδρομή όπου βρίσκεται ο φάκελος του Dropbox
- **Host_id: Hash** που χρησιμοποιείται για authentication στο cloud. Αυτό μπορεί να ανακληθεί μόνο από τον ιστό.
- **Root_ns**: Αναγνωριστικό χρήστη

Η βάση δεδομένων **`filecache.db`** περιέχει πληροφορίες σχετικά με όλα τα αρχεία και τους φακέλους που συγχρονίζονται με το Dropbox. Ο πίνακας `File_journal` είναι αυτός με τις πιο χρήσιμες πληροφορίες:

- **Server_path**: Η διαδρομή όπου βρίσκεται το αρχείο μέσα στον server (αυτή η διαδρομή έχει ως πρόθεμα το `host_id` του client).
- **local_sjid**: Έκδοση του αρχείου
- **local_mtime**: Ημερομηνία τροποποίησης
- **local_ctime**: Ημερομηνία δημιουργίας

Άλλοι πίνακες μέσα σε αυτήν τη βάση δεδομένων περιέχουν πιο ενδιαφέρουσες πληροφορίες:

- **block_cache**: Hash όλων των αρχείων και των φακέλων του Dropbox
- **block_ref**: Συσχετίζει το hash ID του πίνακα `block_cache` με το file ID στον πίνακα `file_journal`
- **mount_table**: Κοινόχρηστοι φάκελοι του Dropbox
- **deleted_fields**: Διαγραμμένα αρχεία του Dropbox
- **date_added**

## Αναφορές

- [1] [Μια κριτική ανάλυση της ασφάλειας του λογισμικού Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Brush up on Dropbox DBX decryption](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)

{{#include ../../../banners/hacktricks-training.md}}
