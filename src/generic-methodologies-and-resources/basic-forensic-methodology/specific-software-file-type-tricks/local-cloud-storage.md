# Local Cloud Storage

{{#include ../../../banners/hacktricks-training.md}}

## OneDrive

Στα Windows, μπορείτε να βρείτε τον φάκελο του OneDrive στη διαδρομή `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Και μέσα στο `logs\Personal` μπορείτε να βρείτε το αρχείο `SyncDiagnostics.log`, το οποίο περιέχει ενδιαφέροντα δεδομένα σχετικά με τα συγχρονισμένα αρχεία:<sup>[[3]](#references)</sup>

- Μέγεθος σε bytes
- Ημερομηνία δημιουργίας
- Ημερομηνία τροποποίησης
- Αριθμός αρχείων στο cloud
- Αριθμός αρχείων στον φάκελο
- **CID**: Μοναδικό ID του χρήστη του OneDrive
- Ώρα δημιουργίας της αναφοράς
- Μέγεθος του HD του λειτουργικού συστήματος

Μόλις βρείτε το CID, συνιστάται να **αναζητήσετε αρχεία που περιέχουν αυτό το ID**. Ενδέχεται να βρείτε αρχεία με τα ονόματα: _**\<CID>.ini**_ και _**\<CID>.dat**_, τα οποία μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες, όπως τα ονόματα των αρχείων που συγχρονίζονται με το OneDrive.<sup>[[3]](#references)</sup>

## Google Drive

Στα Windows, μπορείτε να βρείτε τον κύριο φάκελο του Google Drive στη διαδρομή `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Αυτός ο φάκελος περιέχει ένα αρχείο που ονομάζεται Sync_log.log και καταγράφει τις συνεδρίες συγχρονισμού του client του Google Drive, καθώς και τα συμβάντα δημιουργίας, τροποποίησης και διαγραφής αρχείων.<sup>[[4]](#references)[[6]](#references)</sup>

Το αρχείο **`Cloud_graph\Cloud_graph.db`** είναι μια βάση δεδομένων sqlite.<sup>[[6]](#references)</sup> Περιέχει τον πίνακα **`cloud_graph_entry`**. Σε αυτόν τον πίνακα μπορείτε να βρείτε το **όνομα** των **συγχρονισμένων** **αρχείων**, τον χρόνο τροποποίησης, το μέγεθος και το MD5 checksum των αρχείων.

Ο πίνακας **`cloud_entry`** της σχετικής βάσης δεδομένων **`snapshot.db`** μπορεί να διατηρεί διαγραμμένες εγγραφές με ονόματα αρχείων, timestamps, μεγέθη και checksums.<sup>[[4]](#references)</sup>

Τα δεδομένα του πίνακα της βάσης δεδομένων **`Sync_config.db`** περιέχουν τη διεύθυνση email του λογαριασμού, τη διαδρομή των κοινόχρηστων φακέλων και την έκδοση του Google Drive.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Το Dropbox χρησιμοποιεί **βάσεις δεδομένων SQLite** για τη διαχείριση των αρχείων.<sup>[[2]](#references)</sup> Σε αυτό\
Μπορείτε να βρείτε τις βάσεις δεδομένων στους φακέλους:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Και οι κύριες βάσεις δεδομένων είναι:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Η επέκταση ".dbx" σημαίνει ότι οι **βάσεις δεδομένων** είναι **κρυπτογραφημένες**. Το Dropbox χρησιμοποιεί **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Για να κατανοήσετε καλύτερα την κρυπτογράφηση που χρησιμοποιεί το Dropbox, μπορείτε να διαβάσετε το [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Ωστόσο, οι βασικές πληροφορίες είναι:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Εκτός από αυτές τις πληροφορίες, για την αποκρυπτογράφηση των βάσεων δεδομένων εξακολουθείτε να χρειάζεστε:<sup>[[2]](#references)</sup>

- Το **κρυπτογραφημένο κλειδί DPAPI**: Μπορείτε να το βρείτε στο registry, μέσα στο `NTUSER.DAT\Software\Dropbox\ks\client` (εξαγάγετε αυτά τα δεδομένα ως binary)
- Τα hives **`SYSTEM`** και **`SECURITY`**
- Τα **master keys του DPAPI**: Μπορείτε να τα βρείτε στη διαδρομή `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Το **username** και το **password** του χρήστη των Windows

Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το tool [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το tool DataProtectionDecryptor](<../../../images/image (443).png>)

Αν όλα εξελιχθούν όπως αναμένεται, το tool θα υποδείξει το **primary key** που χρειάζεστε για να **ανακτήσετε το αρχικό**. Για να ανακτήσετε το αρχικό, χρησιμοποιήστε απλώς αυτή τη [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) τοποθετώντας το primary key ως "passphrase" μέσα στη receipt.

Το resulting hex είναι το τελικό κλειδί που χρησιμοποιείται για την κρυπτογράφηση των βάσεων δεδομένων, οι οποίες μπορούν να αποκρυπτογραφηθούν με:<sup>[[2]](#references)</sup>
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Η βάση δεδομένων **`config.dbx`** περιέχει:

- **Email**: Το email του χρήστη
- **usernamedisplayname**: Το όνομα του χρήστη
- **dropbox_path**: Η διαδρομή όπου βρίσκεται ο φάκελος Dropbox
- **Host_id: Hash** που χρησιμοποιείται για authentication στο cloud. Αυτό μπορεί να ανακληθεί μόνο από τον ιστό.
- **Root_ns**: Αναγνωριστικό χρήστη

Η βάση δεδομένων **`filecache.db`** περιέχει πληροφορίες για όλα τα αρχεία και τους φακέλους που συγχρονίζονται με το Dropbox. Ο πίνακας `File_journal` είναι αυτός που περιέχει τις πιο χρήσιμες πληροφορίες:<sup>[[5]](#references)</sup>

- **Server_path**: Η διαδρομή όπου βρίσκεται το αρχείο μέσα στον server (αυτή η διαδρομή έχει ως πρόθεμα το `host_id` του client).
- **local_sjid**: Έκδοση του αρχείου
- **local_mtime**: Ημερομηνία τροποποίησης
- **local_ctime**: Ημερομηνία δημιουργίας

Άλλοι πίνακες μέσα σε αυτή τη βάση δεδομένων περιέχουν πιο ενδιαφέρουσες πληροφορίες:

- **block_cache**: hash όλων των αρχείων και φακέλων του Dropbox
- **block_ref**: Συσχετίζει το hash ID του πίνακα `block_cache` με το file ID στον πίνακα `file_journal`
- **mount_table**: Κοινόχρηστοι φάκελοι του Dropbox
- **deleted_fields**: Διαγραμμένα αρχεία του Dropbox
- **date_added**

## References

- [1] [Κριτική ανάλυση της ασφάλειας του λογισμικού Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Ανασκόπηση της αποκρυπτογράφησης Dropbox DBX](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Forensic ανάλυση Cloud Storage (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [Υπόθεση διαρροής δεδομένων NIST CFReDS: Απαντήσεις για τη διαρροή](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Forensics του Dropbox](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artifacts από τη χρήση του Google Drive στα Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
