# Artifacts των Windows

{{#include ../../../banners/hacktricks-training.md}}

## Γενικά Artifacts των Windows

### Ειδοποιήσεις Windows 10

Στη διαδρομή `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` μπορείτε να βρείτε τη database `appdb.dat` (πριν από το Windows anniversary) ή τη `wpndatabase.db` (μετά το Windows Anniversary).

Μέσα σε αυτήν τη SQLite database, μπορείτε να βρείτε τον πίνακα `Notification` με όλες τις ειδοποιήσεις (σε μορφή XML), οι οποίες μπορεί να περιέχουν ενδιαφέροντα δεδομένα.

### Timeline

Το Timeline είναι ένα χαρακτηριστικό των Windows που παρέχει **χρονολογικό ιστορικό** των web pages που επισκεφθήκατε, των εγγράφων που επεξεργαστήκατε και των εφαρμογών που εκτελέστηκαν.

Η database βρίσκεται στη διαδρομή `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Αυτή η database μπορεί να ανοιχτεί με ένα SQLite tool ή με το tool [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **το οποίο δημιουργεί 2 αρχεία που μπορούν να ανοιχτούν με το tool** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Τα αρχεία που έχουν γίνει download μπορεί να περιέχουν το **ADS Zone.Identifier**, το οποίο υποδεικνύει **πώς** έγινε το **download** από το intranet, το internet κ.λπ. Ορισμένα software (όπως οι browsers) συνήθως προσθέτουν ακόμη **περισσότερες** **πληροφορίες**, όπως το **URL** από το οποίο έγινε το download του αρχείου.

## **Αντίγραφα ασφαλείας αρχείων**

### Κάδος Ανακύκλωσης

Στα Vista/Win7/Win8/Win10 ο **Κάδος Ανακύκλωσης** μπορεί να βρεθεί στον φάκελο **`$Recycle.bin`** στη ρίζα του drive (`C:\$Recycle.bin`).\
Όταν διαγράφεται ένα αρχείο σε αυτόν τον φάκελο, δημιουργούνται 2 συγκεκριμένα αρχεία:

- `$I{id}`: Πληροφορίες αρχείου (ημερομηνία κατά την οποία διαγράφηκε}
- `$R{id}`: Περιεχόμενα του αρχείου

![Αντίγραφα ασφαλείας αρχείων - Κάδος Ανακύκλωσης: $R{id}: Περιεχόμενα του αρχείου](<../../../images/image (1029).png>)

Έχοντας αυτά τα αρχεία, μπορείτε να χρησιμοποιήσετε το tool [**Rifiuti**](https://github.com/abelcheung/rifiuti2) για να λάβετε την αρχική διεύθυνση των διαγραμμένων αρχείων και την ημερομηνία κατά την οποία διαγράφηκαν (χρησιμοποιήστε το `rifiuti-vista.exe` για Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Το Shadow Copy είναι μια τεχνολογία που περιλαμβάνεται στα Microsoft Windows και μπορεί να δημιουργεί **αντίγραφα ασφαλείας** ή snapshots αρχείων ή volumes του υπολογιστή, ακόμη και όταν αυτά χρησιμοποιούνται.

Αυτά τα αντίγραφα ασφαλείας βρίσκονται συνήθως στο `\System Volume Information` από τη ρίζα του file system και το όνομα αποτελείται από **UIDs**, όπως φαίνεται στην παρακάτω εικόνα:

![Recycle Bin - Volume Shadow Copies: Αυτά τα αντίγραφα ασφαλείας βρίσκονται συνήθως στο System Volume Information από τη ρίζα του file system και το όνομα αποτελείται από UIDs, όπως φαίνεται στην...](<../../../images/image (94).png>)

Με το forensics image mounted μέσω του **ArsenalImageMounter**, μπορεί να χρησιμοποιηθεί το εργαλείο [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) για την επιθεώρηση ενός shadow copy και ακόμη και για την **εξαγωγή των αρχείων** από τα shadow copy backups.

![Recycle Bin - Volume Shadow Copies: Με το forensics image mounted μέσω του ArsenalImageMounter, το εργαλείο ShadowCopyView μπορεί να χρησιμοποιηθεί για την επιθεώρηση ενός shadow copy και ακόμη και για την εξαγωγή των αρχείων...](<../../../images/image (576).png>)

Η registry entry `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` περιέχει τα αρχεία και τα keys **που δεν πρέπει να γίνονται backup**:

![Recycle Bin - Volume Shadow Copies: Η registry entry HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore περιέχει τα αρχεία και τα keys που δεν πρέπει να γίνονται backup](<../../../images/image (254).png>)

Η registry `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` περιέχει επίσης πληροφορίες configuration σχετικά με τα `Volume Shadow Copies`.

### Office AutoSaved Files

Μπορείτε να βρείτε τα office autosaved files στο: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

Ένα shell item είναι ένα item που περιέχει πληροφορίες σχετικά με τον τρόπο πρόσβασης σε ένα άλλο αρχείο.

### Recent Documents (LNK)

Τα Windows **δημιουργούν αυτόματα** αυτά τα **shortcuts** όταν ο χρήστης **ανοίγει, χρησιμοποιεί ή δημιουργεί ένα αρχείο** στα:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Όταν δημιουργείται ένας φάκελος, δημιουργείται επίσης ένα link προς τον φάκελο, τον parent folder και τον grandparent folder.

Αυτά τα link files που δημιουργούνται αυτόματα **περιέχουν πληροφορίες σχετικά με την προέλευση**, όπως αν πρόκειται για **file** ή **folder**, τα **MAC** **timestamps** του αρχείου, πληροφορίες για το **volume** όπου είναι αποθηκευμένο το αρχείο και τον **folder του target file**. Αυτές οι πληροφορίες μπορεί να είναι χρήσιμες για την ανάκτηση αυτών των αρχείων σε περίπτωση που έχουν διαγραφεί.

Επίσης, η **ημερομηνία δημιουργίας του link** file είναι η πρώτη **χρονική στιγμή** κατά την οποία το αρχικό αρχείο **χρησιμοποιήθηκε για πρώτη φορά**, ενώ η **ημερομηνία** **τροποποίησης** του link file είναι η τελευταία **χρονική στιγμή** κατά την οποία χρησιμοποιήθηκε το origin file.

Για την επιθεώρηση αυτών των αρχείων μπορείτε να χρησιμοποιήσετε το [**LinkParser**](http://4discovery.com/our-tools/).

Σε αυτό το tool θα βρείτε **2 sets** από timestamps:

- **First Set:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Second Set:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Το πρώτο set των timestamps αναφέρεται στα **timestamps του ίδιου του αρχείου**. Το δεύτερο set αναφέρεται στα **timestamps του linked file**.

Μπορείτε να λάβετε τις ίδιες πληροφορίες εκτελώντας το Windows CLI tool: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Σε αυτή την περίπτωση, οι πληροφορίες θα αποθηκευτούν μέσα σε ένα αρχείο CSV.

### Jumplists

Πρόκειται για τα πρόσφατα αρχεία που υποδεικνύονται ανά εφαρμογή. Είναι η λίστα με τα **πρόσφατα αρχεία που χρησιμοποιήθηκαν από μια εφαρμογή**, την οποία μπορείτε να προσπελάσετε από κάθε εφαρμογή. Μπορούν να δημιουργηθούν **αυτόματα ή προσαρμοσμένα**.

Τα **jumplists** που δημιουργούνται αυτόματα αποθηκεύονται στο `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Τα jumplists ονομάζονται σύμφωνα με τη μορφή `{id}.autmaticDestinations-ms`, όπου το αρχικό ID είναι το ID της εφαρμογής.

Τα προσαρμοσμένα jumplists αποθηκεύονται στο `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` και δημιουργούνται από την εφαρμογή, συνήθως επειδή έχει συμβεί κάτι **σημαντικό** με το αρχείο (ίσως έχει επισημανθεί ως αγαπημένο).

Ο **χρόνος δημιουργίας** οποιουδήποτε jumplist υποδεικνύει την **πρώτη φορά που προσπελάστηκε το αρχείο**, ενώ ο **χρόνος τροποποίησης την τελευταία φορά**.

Μπορείτε να επιθεωρήσετε τα jumplists χρησιμοποιώντας το [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![Recent Documents (LNK) - Jumplists: Μπορείτε να επιθεωρήσετε τα jumplists χρησιμοποιώντας το JumplistExplorer](<../../../images/image (168).png>)

(_Σημειώστε ότι τα timestamps που παρέχονται από το JumplistExplorer σχετίζονται με το ίδιο το αρχείο του jumplist._)

### Shellbags

[**Ακολουθήστε αυτόν τον σύνδεσμο για να μάθετε τι είναι τα shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Χρήση Windows USBs

Είναι δυνατό να αναγνωριστεί ότι χρησιμοποιήθηκε μια συσκευή USB χάρη στη δημιουργία των εξής:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Σημειώστε ότι ορισμένα αρχεία LNK, αντί να δείχνουν στην αρχική διαδρομή, δείχνουν στον φάκελο WPDNSE:

![Shellbags - Χρήση Windows USBs: Σημειώστε ότι ορισμένα αρχεία LNK, αντί να δείχνουν στην αρχική διαδρομή, δείχνουν στον φάκελο WPDNSE](<../../../images/image (218).png>)

Τα αρχεία στον φάκελο WPDNSE είναι αντίγραφα των αρχικών, επομένως δεν θα επιβιώσουν μετά από επανεκκίνηση του PC και το GUID λαμβάνεται από ένα shellbag.

### Πληροφορίες Registry

[Ελέγξτε αυτήν τη σελίδα για να μάθετε](interesting-windows-registry-keys.md#usb-information) ποια registry keys περιέχουν ενδιαφέρουσες πληροφορίες σχετικά με συνδεδεμένες συσκευές USB.

### setupapi

Ελέγξτε το αρχείο `C:\Windows\inf\setupapi.dev.log` για να βρείτε τα timestamps σχετικά με το πότε πραγματοποιήθηκε η σύνδεση USB (αναζητήστε το `Section start`).

![Registry Information - setupapi: Ελέγξτε το αρχείο C: Windows inf setupapi.dev.log για να βρείτε τα timestamps σχετικά με το πότε πραγματοποιήθηκε η σύνδεση USB (αναζητήστε το Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

Το [**USBDetective**](https://usbdetective.com) μπορεί να χρησιμοποιηθεί για τη λήψη πληροφοριών σχετικά με τις συσκευές USB που έχουν συνδεθεί σε ένα image.

![setupapi - USB Detective: Το USBDetective μπορεί να χρησιμοποιηθεί για τη λήψη πληροφοριών σχετικά με τις συσκευές USB που έχουν συνδεθεί σε ένα image](<../../../images/image (452).png>)

### Plug and Play Cleanup

Η scheduled task γνωστή ως 'Plug and Play Cleanup' έχει σχεδιαστεί κυρίως για την αφαίρεση παρωχημένων εκδόσεων drivers. Σε αντίθεση με τον δηλωμένο σκοπό της, δηλαδή τη διατήρηση της πιο πρόσφατης έκδοσης του driver package, online πηγές υποδεικνύουν ότι στοχεύει επίσης drivers που έχουν παραμείνει ανενεργοί για 30 ημέρες. Κατά συνέπεια, drivers για removable devices που δεν έχουν συνδεθεί τις τελευταίες 30 ημέρες ενδέχεται να διαγραφούν.<sup>[[1]](#references)</sup>

Η task βρίσκεται στην ακόλουθη διαδρομή: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Παρέχεται ένα screenshot που απεικονίζει το περιεχόμενο της task: ![USB Detective - Plug and Play Cleanup: Η task βρίσκεται στην ακόλουθη διαδρομή: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Βασικά στοιχεία και ρυθμίσεις της task:**

- **pnpclean.dll**: Αυτό το DLL είναι υπεύθυνο για την πραγματική διαδικασία cleanup.
- **UseUnifiedSchedulingEngine**: Έχει οριστεί σε `TRUE`, υποδεικνύοντας τη χρήση του generic task scheduling engine.
- **MaintenanceSettings**:
- **Period ('P1M')**: Κατευθύνει το Task Scheduler να ξεκινά την task cleanup κάθε μήνα, κατά τη διάρκεια της κανονικής Automatic maintenance.
- **Deadline ('P2M')**: Δίνει εντολή στο Task Scheduler, αν η task αποτύχει για δύο συνεχόμενους μήνες, να εκτελέσει την task κατά τη διάρκεια emergency Automatic maintenance.

Αυτή η ρύθμιση εξασφαλίζει την τακτική maintenance και cleanup των drivers, με πρόβλεψη για επανάληψη της task σε περίπτωση συνεχόμενων αποτυχιών.

**Για περισσότερες πληροφορίες ελέγξτε:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)<sup>[[1]](#references)</sup>

## Emails

Τα emails περιέχουν **2 ενδιαφέροντα μέρη: τα headers και το περιεχόμενο** του email. Στα **headers** μπορείτε να βρείτε πληροφορίες όπως:

- **Ποιος** έστειλε τα emails (email address, IP, mail servers που ανακατεύθυναν το email)
- **Πότε** στάλθηκε το email

Επίσης, μέσα στα headers `References` και `In-Reply-To` μπορείτε να βρείτε το ID των messages:

![Plug and Play Cleanup - Emails: Πότε στάλθηκε το email](<../../../images/image (593).png>)

### Windows Mail App

Αυτή η εφαρμογή αποθηκεύει emails σε HTML ή text. Μπορείτε να βρείτε τα emails μέσα σε subfolders στο `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Τα emails αποθηκεύονται με την επέκταση `.dat`.

Τα **metadata** των emails και οι **contacts** μπορούν να βρεθούν μέσα στη **EDB database**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Αλλάξτε την επέκταση** του αρχείου από `.vol` σε `.edb` και μπορείτε να χρησιμοποιήσετε το εργαλείο [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) για να το ανοίξετε. Μέσα στον πίνακα `Message` μπορείτε να δείτε τα emails.

### Microsoft Outlook

Όταν χρησιμοποιούνται Exchange servers ή Outlook clients, υπάρχουν ορισμένα MAPI headers:

- `Mapi-Client-Submit-Time`: Η ώρα του συστήματος κατά την οποία στάλθηκε το email
- `Mapi-Conversation-Index`: Ο αριθμός των child messages του thread και το timestamp κάθε message του thread
- `Mapi-Entry-ID`: Αναγνωριστικό message.
- `Mappi-Message-Flags` και `Pr_last_Verb-Executed`: Πληροφορίες σχετικά με τον MAPI client (έγινε read το message; δεν έγινε read; απαντήθηκε; ανακατευθύνθηκε; out of the office;)

Στον Microsoft Outlook client, όλα τα sent/received messages, τα contacts data και τα calendar data αποθηκεύονται σε ένα PST file στη:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Το registry path `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` υποδεικνύει το file που χρησιμοποιείται.

Μπορείτε να ανοίξετε το PST file χρησιμοποιώντας το εργαλείο [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![Windows Mail App - Microsoft Outlook: Μπορείτε να ανοίξετε το PST file χρησιμοποιώντας το εργαλείο Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

Ένα **OST file** δημιουργείται από το Microsoft Outlook όταν έχει ρυθμιστεί με **IMAP** ή έναν **Exchange** server και αποθηκεύει παρόμοιες πληροφορίες με ένα PST file. Αυτό το file συγχρονίζεται με τον server, διατηρώντας δεδομένα για **τους τελευταίους 12 μήνες** έως ένα **μέγιστο μέγεθος 50GB**, και βρίσκεται στον ίδιο κατάλογο με το PST file. Για να δείτε ένα OST file, μπορείτε να χρησιμοποιήσετε το [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Ανάκτηση Attachments

Τα χαμένα attachments ενδέχεται να μπορούν να ανακτηθούν από:

- Για **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Για **IE11 και νεότερα**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

Το **Thunderbird** χρησιμοποιεί **MBOX files** για την αποθήκευση δεδομένων, τα οποία βρίσκονται στο `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Image Thumbnails

- **Windows XP και 8-8.1**: Η πρόσβαση σε έναν φάκελο με thumbnails δημιουργεί ένα αρχείο `thumbs.db` που αποθηκεύει previews εικόνων, ακόμη και μετά τη διαγραφή τους.
- **Windows 7/10**: Το `thumbs.db` δημιουργείται όταν η πρόσβαση γίνεται μέσω network μέσω UNC path.
- **Windows Vista και νεότερα**: Τα thumbnail previews συγκεντρώνονται στο `%userprofile%\AppData\Local\Microsoft\Windows\Explorer`, σε files με ονόματα **thumbcache_xxx.db**. Τα [**Thumbsviewer**](https://thumbsviewer.github.io) και [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) είναι tools για την προβολή αυτών των files.

### Windows Registry Information

Το Windows Registry, το οποίο αποθηκεύει εκτεταμένα δεδομένα σχετικά με τη δραστηριότητα του συστήματος και των χρηστών, περιέχεται σε files στις εξής τοποθεσίες:

- `%windir%\System32\Config` για διάφορα subkeys του `HKEY_LOCAL_MACHINE`.
- `%UserProfile%{User}\NTUSER.DAT` για το `HKEY_CURRENT_USER`.
- Οι εκδόσεις Windows Vista και νεότερες δημιουργούν backup των registry files του `HKEY_LOCAL_MACHINE` στο `%Windir%\System32\Config\RegBack\`.
- Επιπλέον, πληροφορίες εκτέλεσης προγραμμάτων αποθηκεύονται στο `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` από τα Windows Vista και τον Windows 2008 Server και έπειτα.

### Tools

Ορισμένα tools είναι χρήσιμα για την ανάλυση των registry files:

- **Registry Editor**: Είναι εγκατεστημένο στα Windows. Πρόκειται για ένα GUI για την πλοήγηση στο Windows Registry της τρέχουσας session.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Επιτρέπει τη φόρτωση του registry file και την πλοήγηση σε αυτό μέσω GUI. Περιέχει επίσης Bookmarks που επισημαίνουν keys με ενδιαφέρουσες πληροφορίες.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Διαθέτει επίσης GUI που επιτρέπει την πλοήγηση στο loaded registry και περιέχει plugins που επισημαίνουν ενδιαφέρουσες πληροφορίες μέσα στο loaded registry.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Μια ακόμη GUI application ικανή να εξάγει τις σημαντικές πληροφορίες από το loaded registry.

### Ανάκτηση Διαγραμμένου Element

Όταν διαγράφεται ένα key, επισημαίνεται ως τέτοιο, αλλά μέχρι να χρειαστεί ο χώρος που καταλαμβάνει δεν θα αφαιρεθεί. Επομένως, χρησιμοποιώντας tools όπως το **Registry Explorer**, είναι δυνατή η ανάκτηση αυτών των deleted keys.

### Last Write Time

Κάθε Key-Value περιέχει ένα **timestamp** που υποδεικνύει την τελευταία φορά που τροποποιήθηκε.

### SAM

Το file/hive **SAM** περιέχει τα hashes των **users, groups και passwords των users** του συστήματος.

Στο `SAM\Domains\Account\Users` μπορείτε να λάβετε το username, το RID, το τελευταίο login, το τελευταίο αποτυχημένο logon, τον login counter, την password policy και το πότε δημιουργήθηκε ο λογαριασμός. Για να λάβετε τα **hashes**, χρειάζεστε επίσης το file/hive **SYSTEM**.

### Interesting entries in the Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

Στο [this post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) μπορείτε να μάθετε σχετικά με τις κοινές Windows processes για τον εντοπισμό ύποπτων συμπεριφορών.<sup>[[2]](#references)</sup>

### Windows Recent APPs

Μέσα στο registry `NTUSER.DAT`, στο path `Software\Microsoft\Current Version\Search\RecentApps`, μπορείτε να βρείτε subkeys με πληροφορίες σχετικά με την **εφαρμογή που εκτελέστηκε**, την **τελευταία φορά** που εκτελέστηκε και τον **αριθμό των φορών** που ξεκίνησε.

### BAM (Background Activity Moderator)

Μπορείτε να ανοίξετε το file `SYSTEM` με έναν registry editor και, μέσα στο path `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`, να βρείτε πληροφορίες σχετικά με τις **εφαρμογές που εκτελέστηκαν από κάθε user** (σημειώστε το `{SID}` στο path) και **την ώρα** κατά την οποία εκτελέστηκαν (η ώρα βρίσκεται μέσα στην τιμή Data του registry).

### Windows Prefetch

Το Prefetch είναι μια technique που επιτρέπει σε έναν υπολογιστή να **λαμβάνει αθόρυβα τους απαραίτητους πόρους που απαιτούνται για την εμφάνιση περιεχομένου** στο οποίο ένας user **ενδέχεται να αποκτήσει πρόσβαση στο άμεσο μέλλον**, ώστε οι πόροι να προσπελαύνονται γρηγορότερα.

Το Windows prefetch αποτελείται από τη δημιουργία **caches των εκτελεσμένων προγραμμάτων**, ώστε να είναι δυνατή η ταχύτερη φόρτωσή τους. Αυτά τα caches δημιουργούνται ως `.pf` files μέσα στο path: `C:\Windows\Prefetch`. Υπάρχει όριο 128 files στα XP/VISTA/WIN7 και 1024 files στα Win8/Win10.

Το όνομα του file δημιουργείται ως `{program_name}-{hash}.pf` (το hash βασίζεται στο path και στα arguments του executable). Στα W10 αυτά τα files είναι compressed. Σημειώστε ότι η απλή παρουσία του file υποδεικνύει ότι **το πρόγραμμα εκτελέστηκε** κάποια στιγμή.

Το file `C:\Windows\Prefetch\Layout.ini` περιέχει τα **ονόματα των φακέλων των files που γίνονται prefetched**. Αυτό το file περιέχει **πληροφορίες σχετικά με τον αριθμό των executions**, τις **ημερομηνίες** εκτέλεσης και τα **files** που **άνοιξε** το πρόγραμμα.

Για να επιθεωρήσετε αυτά τα files μπορείτε να χρησιμοποιήσετε το tool [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

Το **Superprefetch** έχει τον ίδιο στόχο με το prefetch, **να φορτώνει τα προγράμματα γρηγορότερα**, προβλέποντας τι πρόκειται να φορτωθεί στη συνέχεια. Ωστόσο, δεν αντικαθιστά την υπηρεσία prefetch.\
Αυτή η υπηρεσία δημιουργεί αρχεία βάσης δεδομένων στη διαδρομή `C:\Windows\Prefetch\Ag*.db`.

Σε αυτές τις βάσεις δεδομένων μπορείτε να βρείτε το **όνομα** του **προγράμματος**, τον **αριθμό** των **εκτελέσεων**, τα **αρχεία** που **άνοιξαν**, τον **τόμο** στον οποίο έγινε **πρόσβαση**, την **πλήρη** **διαδρομή**, τα **χρονικά διαστήματα** και τις **χρονοσφραγίδες**.

Μπορείτε να αποκτήσετε πρόσβαση σε αυτές τις πληροφορίες χρησιμοποιώντας το εργαλείο [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

Το **System Resource Usage Monitor** (SRUM) **παρακολουθεί** τους **πόρους** που **καταναλώνονται** **από μια διεργασία**. Εμφανίστηκε στα W8 και αποθηκεύει τα δεδομένα σε μια βάση δεδομένων ESE που βρίσκεται στη διαδρομή `C:\Windows\System32\sru\SRUDB.dat`.

Παρέχει τις ακόλουθες πληροφορίες:

- AppID και Path
- Ο χρήστης που εκτέλεσε τη διεργασία
- Απεσταλμένα Bytes
- Ληφθέντα Bytes
- Διεπαφή δικτύου
- Διάρκεια σύνδεσης
- Διάρκεια διεργασίας

Αυτές οι πληροφορίες ενημερώνονται κάθε 60 λεπτά.

Μπορείτε να ανακτήσετε τα δεδομένα από αυτό το αρχείο χρησιμοποιώντας το εργαλείο [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

Το **AppCompatCache**, γνωστό επίσης ως **ShimCache**, αποτελεί μέρος του **Application Compatibility Database**, που αναπτύχθηκε από τη **Microsoft** για την αντιμετώπιση προβλημάτων συμβατότητας εφαρμογών. Αυτό το στοιχείο του συστήματος καταγράφει διάφορα μεταδεδομένα αρχείων, τα οποία περιλαμβάνουν:

- Πλήρη διαδρομή του αρχείου
- Μέγεθος του αρχείου
- Τελευταία τροποποίηση στο **$Standard_Information** (SI)
- Τελευταία ενημέρωση του ShimCache
- Process Execution Flag

Τα δεδομένα αποθηκεύονται στο registry, σε συγκεκριμένες τοποθεσίες ανάλογα με την έκδοση του λειτουργικού συστήματος:

- Για τα XP, τα δεδομένα αποθηκεύονται στη διαδρομή `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`, με χωρητικότητα 96 entries.
- Για τον Server 2003, καθώς και για τις εκδόσεις Windows 2008, 2012, 2016, 7, 8 και 10, η διαδρομή αποθήκευσης είναι `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache`, με χωρητικότητα 512 και 1024 entries, αντίστοιχα.

Για την ανάλυση των αποθηκευμένων πληροφοριών, συνιστάται η χρήση του [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser).

![SRUM - AppCompatCache (ShimCache): Για την ανάλυση των αποθηκευμένων πληροφοριών, συνιστάται η χρήση του AppCompatCacheParser tool](<../../../images/image (75).png>)

### Amcache

Το αρχείο **Amcache.hve** είναι ουσιαστικά ένα registry hive που καταγράφει λεπτομέρειες σχετικά με εφαρμογές που έχουν εκτελεστεί σε ένα σύστημα. Συνήθως βρίσκεται στη διαδρομή `C:\Windows\AppCompat\Programas\Amcache.hve`.

Αυτό το αρχείο είναι αξιοσημείωτο επειδή αποθηκεύει καταγραφές πρόσφατα εκτελεσμένων processes, συμπεριλαμβανομένων των διαδρομών προς τα executable αρχεία και των SHA1 hashes τους. Αυτές οι πληροφορίες είναι εξαιρετικά χρήσιμες για την παρακολούθηση της δραστηριότητας των εφαρμογών σε ένα σύστημα.

Για την εξαγωγή και ανάλυση των δεδομένων από το **Amcache.hve**, μπορεί να χρησιμοποιηθεί το εργαλείο [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Η παρακάτω εντολή αποτελεί παράδειγμα χρήσης του AmcacheParser για την ανάλυση των περιεχομένων του αρχείου **Amcache.hve** και την εξαγωγή των αποτελεσμάτων σε μορφή CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Μεταξύ των αρχείων CSV που δημιουργούνται, το `Amcache_Unassociated file entries` είναι ιδιαίτερα αξιοσημείωτο λόγω των πλούσιων πληροφοριών που παρέχει σχετικά με μη συσχετισμένες καταχωρίσεις αρχείων.

Το πιο ενδιαφέρον αρχείο CVS που δημιουργείται είναι το `Amcache_Unassociated file entries`.

### RecentFileCache

Αυτό το artifact μπορεί να βρεθεί μόνο σε W7, στη διαδρομή `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`, και περιέχει πληροφορίες σχετικά με την πρόσφατη εκτέλεση ορισμένων binaries.

Μπορείτε να χρησιμοποιήσετε το tool [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) για να κάνετε parse το αρχείο.

### Scheduled tasks

Μπορείτε να τα εξαγάγετε από τις διαδρομές `C:\Windows\Tasks` ή `C:\Windows\System32\Tasks` και να τα διαβάσετε ως XML.

### Services

Μπορείτε να τα βρείτε στο registry, στη διαδρομή `SYSTEM\ControlSet001\Services`. Μπορείτε να δείτε τι πρόκειται να εκτελεστεί και πότε.

### **Windows Store**

Οι εγκατεστημένες εφαρμογές μπορούν να βρεθούν στη διαδρομή `\ProgramData\Microsoft\Windows\AppRepository\`\
Αυτό το repository διαθέτει ένα **log** με **κάθε εφαρμογή που έχει εγκατασταθεί** στο σύστημα, μέσα στη database **`StateRepository-Machine.srd`**.

Μέσα στον Application table αυτής της database, είναι δυνατό να βρεθούν οι στήλες: "Application ID", "PackageNumber" και "Display Name". Αυτές οι στήλες περιέχουν πληροφορίες σχετικά με προεγκατεστημένες και εγκατεστημένες εφαρμογές και μπορούν να δείξουν αν κάποιες εφαρμογές απεγκαταστάθηκαν, επειδή τα IDs των εγκατεστημένων εφαρμογών θα πρέπει να είναι διαδοχικά.

Είναι επίσης δυνατό να **βρεθούν εγκατεστημένες εφαρμογές** στη registry path: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Και **απεγκατεστημένες** **εφαρμογές** στη: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Events

Οι πληροφορίες που εμφανίζονται μέσα στα Windows events είναι:

- Τι συνέβη
- Timestamp (UTC + 0)
- Users που εμπλέκονται
- Hosts που εμπλέκονται (hostname, IP)
- Assets στα οποία έγινε πρόσβαση (files, folder, printer, services)

Τα logs βρίσκονται στη διαδρομή `C:\Windows\System32\config` πριν από τα Windows Vista και στη `C:\Windows\System32\winevt\Logs` μετά τα Windows Vista. Πριν από τα Windows Vista, τα event logs ήταν σε binary format, ενώ μετά από αυτά είναι σε **XML format** και χρησιμοποιούν την επέκταση **.evtx**.

Η τοποθεσία των event files μπορεί να βρεθεί στο SYSTEM registry, στη διαδρομή **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Μπορούν να προβληθούν από το Windows Event Viewer (**`eventvwr.msc`**) ή με άλλα tools όπως το [**Event Log Explorer**](https://eventlogxp.com) **ή το** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Κατανόηση του Windows Security Event Logging

Τα access events καταγράφονται στο security configuration file που βρίσκεται στη διαδρομή `C:\Windows\System32\winevt\Security.evtx`. Το μέγεθος αυτού του file μπορεί να ρυθμιστεί και, όταν η χωρητικότητά του εξαντληθεί, τα παλαιότερα events αντικαθίστανται. Τα καταγεγραμμένα events περιλαμβάνουν user logins και logoffs, ενέργειες χρηστών και αλλαγές στις security settings, καθώς και πρόσβαση σε files, folders και shared assets.

### Βασικά Event IDs για User Authentication:

- **EventID 4624**: Υποδεικνύει ότι ένας user έκανε επιτυχές authentication.
- **EventID 4625**: Υποδεικνύει αποτυχία authentication.
- **EventIDs 4634/4647**: Αντιστοιχούν σε user logoff events.
- **EventID 4672**: Υποδεικνύει login με administrative privileges.

#### Sub-types μέσα στα EventID 4634/4647:

- **Interactive (2)**: Απευθείας user login.
- **Network (3)**: Πρόσβαση σε shared folders.
- **Batch (4)**: Εκτέλεση batch processes.
- **Service (5)**: Εκκίνηση services.
- **Proxy (6)**: Proxy authentication.
- **Unlock (7)**: Ξεκλείδωμα οθόνης με password.
- **Network Cleartext (8)**: Μετάδοση clear text password, συχνά από IIS.
- **New Credentials (9)**: Χρήση διαφορετικών credentials για πρόσβαση.
- **Remote Interactive (10)**: Login μέσω remote desktop ή terminal services.
- **Cache Interactive (11)**: Login με cached credentials χωρίς επικοινωνία με domain controller.
- **Cache Remote Interactive (12)**: Remote login με cached credentials.
- **Cached Unlock (13)**: Ξεκλείδωμα με cached credentials.

#### Status και Sub Status Codes για το EventID 4625:

- **0xC0000064**: Το user name δεν υπάρχει - Θα μπορούσε να υποδεικνύει username enumeration attack.
- **0xC000006A**: Σωστό user name αλλά λανθασμένο password - Πιθανό password guessing ή brute-force attempt.
- **0xC0000234**: Ο user account έχει κλειδωθεί - Μπορεί να ακολουθήσει brute-force attack που προκαλεί πολλαπλά failed logins.
- **0xC0000072**: Ο account είναι disabled - Μη εξουσιοδοτημένες προσπάθειες πρόσβασης σε disabled accounts.
- **0xC000006F**: Logon εκτός επιτρεπόμενου χρονικού διαστήματος - Υποδεικνύει προσπάθειες πρόσβασης εκτός των καθορισμένων login hours, πιθανό σημάδι μη εξουσιοδοτημένης πρόσβασης.
- **0xC0000070**: Παραβίαση workstation restrictions - Θα μπορούσε να αποτελεί προσπάθεια login από μη εξουσιοδοτημένη τοποθεσία.
- **0xC0000193**: Λήξη account - Προσπάθειες πρόσβασης με expired user accounts.
- **0xC0000071**: Expired password - Login attempts με outdated passwords.
- **0xC0000133**: Time sync issues - Μεγάλες χρονικές αποκλίσεις μεταξύ client και server μπορεί να υποδεικνύουν πιο εξελιγμένα attacks, όπως pass-the-ticket.
- **0xC0000224**: Απαιτείται mandatory password change - Συχνές υποχρεωτικές αλλαγές μπορεί να υποδεικνύουν προσπάθεια αποσταθεροποίησης της account security.
- **0xC0000225**: Υποδεικνύει system bug και όχι security issue.
- **0xC000015b**: Denied logon type - Απόπειρα πρόσβασης με μη εξουσιοδοτημένο logon type, όπως ένας user που προσπαθεί να εκτελέσει service logon.

#### EventID 4616:

- **Time Change**: Τροποποίηση του system time, η οποία θα μπορούσε να αποκρύψει το timeline των events.

#### EventID 6005 και 6006:

- **System Startup and Shutdown**: Το EventID 6005 υποδεικνύει την εκκίνηση του system, ενώ το EventID 6006 σηματοδοτεί τον τερματισμό του.

#### EventID 1102:

- **Log Deletion**: Εκκαθάριση των security logs, κάτι που συχνά αποτελεί red flag για συγκάλυψη illicit activities.

#### EventIDs για USB Device Tracking:

- **20001 / 20003 / 10000**: Πρώτη σύνδεση USB device.
- **10100**: USB driver update.
- **EventID 112**: Χρόνος εισαγωγής USB device.

Για πρακτικά παραδείγματα σχετικά με την προσομοίωση αυτών των login types και των ευκαιριών credential dumping, ανατρέξτε στο [detailed guide της Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Οι λεπτομέρειες των events, συμπεριλαμβανομένων των status και sub-status codes, παρέχουν επιπλέον insight για τις αιτίες των events, ιδιαίτερα στο Event ID 4625.

### Ανάκτηση Windows Events

Για να αυξήσετε τις πιθανότητες ανάκτησης deleted Windows Events, συνιστάται να απενεργοποιήσετε τον suspect computer αποσυνδέοντάς τον απευθείας από το ρεύμα. Το **Bulk_extractor**, ένα recovery tool που καθορίζει την επέκταση `.evtx`, συνιστάται για την προσπάθεια ανάκτησης τέτοιων events.

### Εντοπισμός Common Attacks μέσω Windows Events

Για έναν comprehensive οδηγό σχετικά με τη χρήση των Windows Event IDs για τον εντοπισμό common cyber attacks, επισκεφθείτε το [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute Force Attacks

Μπορούν να εντοπιστούν από πολλαπλές καταγραφές EventID 4625, ακολουθούμενες από ένα EventID 4624 αν το attack επιτύχει.

#### Time Change

Καταγράφεται από το EventID 4616· οι αλλαγές στο system time μπορούν να δυσκολέψουν τη forensic analysis.

#### USB Device Tracking

Χρήσιμα System EventIDs για USB device tracking περιλαμβάνουν τα 20001/20003/10000 για αρχική χρήση, το 10100 για driver updates και το EventID 112 από το DeviceSetupManager για timestamps εισαγωγής.

#### System Power Events

Το EventID 6005 υποδεικνύει system startup, ενώ το EventID 6006 σηματοδοτεί shutdown.

#### Log Deletion

Το Security EventID 1102 σηματοδοτεί τη διαγραφή logs, ένα κρίσιμο event για τη forensic analysis.

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigating Common Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)

{{#include ../../../banners/hacktricks-training.md}}
