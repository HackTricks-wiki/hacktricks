# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Generic Windows Artifacts

### Windows 10 Notifications

Η βάση δεδομένων ειδοποιήσεων ανά χρήστη βρίσκεται στη διεύθυνση `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (για παράδειγμα, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Οι πρώτες εκδόσεις των Windows 10 χρησιμοποιούσαν το `appdb.dat`, ενώ η Anniversary Update (1607) εισήγαγε το `wpndatabase.db`. Η SQLite database περιλαμβάνει έναν πίνακα `Notification` με payloads ειδοποιήσεων και πεδία χρονισμού, αν και η διατήρηση και τα διαθέσιμα δεδομένα διαφέρουν ανά έκδοση και πολιτική εκκαθάρισης.<sup>[[3]](#references)</sup>

### Χρονολόγιο

Το Windows Timeline είναι μια λειτουργία ιστορικού δραστηριότητας που μπορεί να περιέχει εγγραφές για υποστηριζόμενες εφαρμογές, έγγραφα και άλλες δραστηριότητες χρήστη· η κάλυψή του εξαρτάται από την εφαρμογή και την έκδοση των Windows.<sup>[[4]](#references)</sup>

Η database βρίσκεται στη διεύθυνση `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Μπορεί να ανοιχτεί με SQLite ή να γίνει parsing με το [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), του οποίου το output μπορεί να εξεταστεί με το [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Τα αρχεία που έχουν ληφθεί από εκτός του τοπικού trust boundary μπορεί να περιέχουν το **`Zone.Identifier` alternate data stream**, το οποίο καταγράφει πληροφορίες ζώνης και μπορεί να περιλαμβάνει metadata προέλευσης, όπως ένα URL. Η παρουσία και τα πεδία του εξαρτώνται από τον producer και την πολιτική του συστήματος.<sup>[[6]](#references)</sup>

## **Αντίγραφα ασφαλείας αρχείων**

### Κάδος Ανακύκλωσης

Στα Vista και νεότερα, ο **Κάδος Ανακύκλωσης** βρίσκεται στον φάκελο **`$Recycle.bin`** στη ρίζα του drive (για παράδειγμα, `C:\$Recycle.bin`).\
Όταν διαγράφεται ένα αρχείο σε αυτόν τον φάκελο, δημιουργούνται 2 συγκεκριμένα αρχεία:

- `$I{id}`: Πληροφορίες αρχείου, συμπεριλαμβανομένων της ώρας διαγραφής και της αρχικής διαδρομής
- `$R{id}`: Περιεχόμενο του αρχείου

![File Backups - Recycle Bin: $R{id}: Content of the file](<../../../images/image (1029).png>)

Έχοντας αυτά τα αρχεία, μπορείτε να χρησιμοποιήσετε το [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) για να εξαγάγετε την αρχική διαδρομή και την ώρα διαγραφής (χρησιμοποιήστε την έκδοση που είναι κατάλληλη για την έκδοση των Windows-στόχου).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Το Volume Shadow Copy Service (VSS) μπορεί να δημιουργεί shadow copies των τόμων σε συγκεκριμένο χρονικό σημείο, ενώ τα αρχεία χρησιμοποιούνται· ένα shadow copy δεν αποτελεί υποκατάστατο μιας forensic image.<sup>[[8]](#references)</sup>

Τα metadata του copy συνδέονται συνήθως με το `\System Volume Information` στη ρίζα του τόμου, με identifiers που διαφέρουν ανάλογα με το σύστημα:

![Recycle Bin - Volume Shadow Copies: Αυτά τα backups βρίσκονται συνήθως στο System Volume Information στη ρίζα του file system και το όνομα αποτελείται από UIDs που εμφανίζονται στο...](<../../../images/image (94).png>)

Μετά το mounting μιας image με κατάλληλο forensic mounter, το [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) μπορεί να απαριθμήσει τα διαθέσιμα VSS snapshots και να περιηγηθεί ή να αντιγράψει αρχεία από αυτά.<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Με το mounting της forensics image με το ArsenalImageMounter, το εργαλείο ShadowCopyView μπορεί να χρησιμοποιηθεί για την επιθεώρηση ενός shadow copy και ακόμη και για την εξαγωγή των files...](<../../../images/image (576).png>)

Η configuration του VSS registry writer περιλαμβάνει το `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, το οποίο μπορεί να καθορίζει αρχεία και keys που εξαιρούνται από το backup:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Το registry entry HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore περιέχει τα files και τα keys που δεν πρέπει να γίνονται backup](<../../../images/image (254).png>)

Το key `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` περιέχει επίσης configuration της υπηρεσίας VSS.<sup>[[8]](#references)</sup>

### Office AutoSaved Files

Οι τοποθεσίες AutoRecover διαφέρουν ανάλογα με την Office εφαρμογή, την έκδοση και τη configuration. Για το Word, η Microsoft τεκμηριώνει το `%APPDATA%\Microsoft\Word` ως την προεπιλεγμένη τοποθεσία· ελέγξτε τις ρυθμίσεις της εφαρμογής για το ενεργό path.<sup>[[12]](#references)</sup>

## Shell Items

Ένα shell item είναι ένα item που περιέχει πληροφορίες σχετικά με τον τρόπο πρόσβασης σε άλλο αρχείο.

### Recent Documents (LNK)

Τα Windows συνήθως δημιουργούν shortcuts για πρόσφατα items όταν ένας χρήστης ανοίγει ή με άλλον τρόπο αποκτά πρόσβαση σε ένα item:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Η πρόσβαση σε έναν φάκελο μπορεί επίσης να δημιουργήσει links για τον φάκελο και τους σχετικούς parent folders.

Αυτά τα link files μπορεί να περιέχουν τον τύπο του target, τους MAC times του target, πληροφορίες τόμου και το path του target. Αυτά τα metadata μπορεί να βοηθήσουν στην αναγνώριση ενός διαγραμμένου target, όμως το artifact από μόνο του δεν αποτελεί απόδειξη ότι το target ανοίχτηκε από συγκεκριμένο χρήστη.<sup>[[13]](#references)[[14]](#references)</sup>

Τα filesystem timestamps του ίδιου του LNK και τα ενσωματωμένα timestamps του target είναι διαφορετικά. Μην ερμηνεύετε τη δημιουργία του link ως την πρώτη χρήση ή την τροποποίηση του link ως την τελευταία χρήση χωρίς corroborating artifacts· το format αποθηκεύει τα timestamps του target ξεχωριστά από τα timestamps του link file.<sup>[[13]](#references)[[14]](#references)</sup>

Το υπάρχον link του [**LinkParser**](http://4discovery.com/our-tools/) διατηρείται ως historical option, όμως η τεκμηρίωσή του δεν ήταν διαθέσιμη κατά την ανασκόπηση. Για έναν documented command-line parser, χρησιμοποιήστε το [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Αυτά τα εργαλεία συνήθως εμφανίζουν δύο σύνολα timestamps:

- **Timestamps του target:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Timestamps του link-file:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Το πρώτο σύνολο αναφέρεται στο target· το δεύτερο σύνολο αναφέρεται στο ίδιο το LNK file. Ερμηνεύστε και τα δύο σύμφωνα με την τεκμηρίωση του parser και το filesystem context.<sup>[[14]](#references)[[15]](#references)</sup>

Μπορείτε να λάβετε τις ίδιες πληροφορίες εκτελώντας το Windows CLI tool: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Σε αυτήν την περίπτωση, οι πληροφορίες θα αποθηκευτούν σε ένα αρχείο CSV.

### Jumplists

Οι Jump Lists είναι λίστες ανά εφαρμογή με πρόσφατα στοιχεία ή στοιχεία που σχετίζονται με συγκεκριμένες εργασίες και μπορεί να είναι αυτόματες ή προσαρμοσμένες.<sup>[[13]](#references)</sup>

Οι Automatic Jump Lists αποθηκεύονται στο `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` και χρησιμοποιούν ονόματα όπως `{id}.automaticDestinations-ms`, όπου το ID προσδιορίζει την εφαρμογή.

Οι Custom Jump Lists αποθηκεύονται στο `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`. Η εφαρμογή ελέγχει ποιες εγγραφές εργασιών ή στοιχείων δημιουργεί.

Οι χρόνοι δημιουργίας και τροποποίησης του filesystem περιγράφουν το αρχείο Jump List και όχι αυτόματα την πρώτη και την τελευταία πρόσβαση σε κάθε καταχωρισμένο στόχο. Συσχετίστε τις αναλυμένες εγγραφές με τα timestamps του αρχείου και άλλα artifacts.<sup>[[13]](#references)</sup>

Μπορείτε να επιθεωρήσετε τις Jump Lists χρησιμοποιώντας το [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: Μπορείτε να επιθεωρήσετε τις jumplists χρησιμοποιώντας το JumplistExplorer](<../../../images/image (168).png>)

(_Σημειώστε ότι τα timestamps που παρέχονται από το JumplistExplorer σχετίζονται με το ίδιο το αρχείο jumplist_)

### Shellbags

[**Ακολουθήστε αυτόν τον σύνδεσμο για να μάθετε τι είναι τα shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Χρήση Windows USBs

Η χρήση USB μπορεί μερικές φορές να επιβεβαιωθεί από artifacts που δημιουργούνται όταν γίνεται πρόσβαση σε αρχεία από removable media, όπως:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Εργαλεία όπως το [**USBDetective**](https://usbdetective.com) συσχετίζουν αυτά τα artifacts με εγγραφές συσκευών USB, αλλά η διαθεσιμότητα των artifacts εξαρτάται από την έκδοση των Windows και την εφαρμογή.<sup>[[18]](#references)</sup>

Σε δοκιμές που τεκμηριώθηκαν για workflows MTP σε Windows XP και Windows 7, ορισμένα LNKs έδειχναν σε έναν φάκελο `WPDNSE` αντί για την αρχική διαδρομή.<sup>[[16]](#references)</sup>

![Shellbags - Use of Windows USBs: Σημειώστε ότι ορισμένα αρχεία LNK, αντί να δείχνουν στην αρχική διαδρομή, δείχνουν στον φάκελο WPDNSE](<../../../images/image (218).png>)

Η συγκεκριμένη μελέτη παρατήρησε αντίγραφα στο `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`. Τα προσωρινά περιεχόμενα δεν διατηρήθηκαν μετά από επανεκκίνηση στις δοκιμές της, ενώ το GUID μπορούσε να συσχετιστεί με δεδομένα shellbag. Αντιμετωπίστε το ως συμπεριφορά που εξαρτάται από το OS, τη συσκευή και την εφαρμογή και όχι ως καθολικό κανόνα.<sup>[[16]](#references)</sup>

### Πληροφορίες Registry

[Ελέγξτε αυτήν τη σελίδα για να μάθετε](interesting-windows-registry-keys.md#usb-information) ποια registry keys περιέχουν ενδιαφέρουσες πληροφορίες για συνδεδεμένες συσκευές USB.

### setupapi

Στα Vista και νεότερα, επιθεωρήστε το `C:\Windows\inf\setupapi.dev.log` για δραστηριότητα εγκατάστασης συσκευών. Οι επικεφαλίδες των ενοτήτων περιλαμβάνουν timestamps `Section start`. Τεκμηριώνουν την επεξεργασία του setup και θα πρέπει να συσχετίζονται με άλλα στοιχεία σύνδεσης, αντί να θεωρούνται ακριβής χρόνος φυσικής σύνδεσης.<sup>[[17]](#references)</sup>

![Registry Information - setupapi: Ελέγξτε το αρχείο C: Windows inf setupapi.dev.log για να λάβετε τα timestamps σχετικά με το πότε πραγματοποιήθηκε η σύνδεση USB (αναζητήστε το Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

Το [**USBDetective**](https://usbdetective.com) μπορεί να χρησιμοποιηθεί για τη λήψη πληροφοριών σχετικά με τις συσκευές USB που έχουν συνδεθεί σε ένα image.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: Το USBDetective μπορεί να χρησιμοποιηθεί για τη λήψη πληροφοριών σχετικά με τις συσκευές USB που έχουν συνδεθεί σε ένα image](<../../../images/image (452).png>)

### Plug and Play Cleanup

Το scheduled task που είναι γνωστό ως `Plug and Play Cleanup` αφαιρεί παλιές εκδόσεις drivers. Ένας ορισμός task των Windows 10 που τεκμηριώθηκε από τον Adam Harrison στοχεύει επίσης drivers που ήταν ανενεργοί για 30 ημέρες, επομένως τα στοιχεία drivers removable devices μπορεί να διαγραφούν. Επιβεβαιώστε τον τοπικό ορισμό του task και το Windows build πριν γενικεύσετε αυτήν τη συμπεριφορά.<sup>[[1]](#references)</sup>

Το task βρίσκεται στην ακόλουθη διαδρομή: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

**Βασικά στοιχεία και ρυθμίσεις του task:**

- **pnpclean.dll**: Αυτό το DLL είναι υπεύθυνο για την πραγματική διαδικασία cleanup.
- **UseUnifiedSchedulingEngine**: Έχει οριστεί σε `TRUE`, υποδεικνύοντας τη χρήση του generic task scheduling engine.
- **MaintenanceSettings**:
- **Period ('P1M')**: Κατευθύνει το Task Scheduler να ξεκινά το cleanup task κάθε μήνα, κατά τη διάρκεια της κανονικής Automatic maintenance.
- **Deadline ('P2M')**: Δίνει εντολή στο Task Scheduler, εάν το task αποτύχει για δύο συνεχόμενους μήνες, να εκτελεί το task κατά τη διάρκεια emergency Automatic maintenance.

Αυτή η ρύθμιση προγραμματίζει τακτική συντήρηση και επαναλήψεις μετά από συνεχόμενες αποτυχίες. Το ακριβές XML και η συμπεριφορά εξαρτώνται από την έκδοση.<sup>[[1]](#references)</sup>

**Για περισσότερες πληροφορίες, ελέγξτε:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Emails

Τα Emails περιέχουν **2 ενδιαφέροντα μέρη: τα headers και το content** του email. Στα **headers** μπορείτε να βρείτε πληροφορίες όπως:

- **Ποιος** έστειλε τα emails (email address, IP, mail servers που ανακατεύθυναν το email)
- **Πότε** στάλθηκε το email

Επίσης, τα headers `References` και `In-Reply-To` μπορούν να περιέχουν message IDs που χρησιμοποιούνται για τη συσχέτιση απαντήσεων με μια συνομιλία.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Emails: Πότε στάλθηκε το email](<../../../images/image (593).png>)

### Windows Mail App

Αυτή η εφαρμογή αποθηκεύει το περιεχόμενο των emails σε βοηθητικά αρχεία κειμένου ή HTML σε paths όπως το `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Η ακριβής διάταξη των αριθμημένων folders και files μπορεί να διαφέρει ανά artifact.<sup>[[75]](#references)</sup>

Τα **metadata** των emails και οι **contacts** μπορούν να βρεθούν μέσα στη **βάση δεδομένων ESE** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

Το `store.vol` χρησιμοποιεί το format Extensible Storage Engine (ESE). Εργαστείτε σε αντίγραφο και χρησιμοποιήστε έναν ESE parser όπως το [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). Αν ένα tool απαιτεί suffix `.edb`, μετονομάστε μόνο το αντίγραφο και επαληθεύστε το table schema πριν βασιστείτε σε έναν πίνακα `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Κατά την επιθεώρηση των Outlook MAPI properties, οι canonical properties περιλαμβάνουν:

- `PidTagClientSubmitTime`: Η ώρα UTC κατά την οποία ο client υπέβαλε το μήνυμα.
- `PidTagConversationIndex`: Η σχετική θέση του μηνύματος σε ένα conversation thread.
- `PidTagEntryId`: Ένα identifier για το message object.
- `PidTagMessageFlags`: Status flags όπως submitted, read, unread ή having attachments.
- `PidTagLastVerbExecuted`: Η τελευταία operation που καταγράφηκε για το μήνυμα, όπως open, reply ή forward.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Οι τοποθεσίες των Outlook data files διαφέρουν ανάλογα με την έκδοση και τον τύπο account. Η Microsoft τεκμηριώνει αυτές τις συνήθεις τοποθεσίες για PST/OST files:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Το registry path `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` μπορεί να προσδιορίζει το Outlook profile και τη σχετική διαμόρφωση των data files.

Τα PST files μπορεί να περιέχουν messages, contacts, calendar data και άλλα Outlook items. Μπορείτε να επιθεωρήσετε ένα αντίγραφο με το [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: Μπορείτε να ανοίξετε το PST file χρησιμοποιώντας το tool Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

Ένα **OST file** είναι local cache για Exchange ή Microsoft 365 accounts. Το Cached Exchange Mode δεν εφαρμόζεται σε POP ή IMAP accounts. Η offline περίοδος είναι configurable και συχνά είναι 12 μήνες by default, ενώ τα size limits των PST/OST είναι ξεχωριστές configurable ρυθμίσεις. Για την προβολή ενός OST file μπορεί να χρησιμοποιηθεί το [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Ανάκτηση Attachments

Τα χαμένα attachments μπορεί να είναι ανακτήσιμα από:

- Για legacy Outlook/IE configurations: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Για νεότερες Outlook/IE11 configurations: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

Το **Thunderbird** αποθηκεύει τα profile data στο `%APPDATA%\Thunderbird\Profiles`. Οι mail folders χρησιμοποιούν συνήθως mbox files χωρίς extension, μέσα σε account-specific `Mail` ή `ImapMail` directories.<sup>[[29]](#references)[[30]](#references)</sup>

### Image Thumbnails

- **Windows XP**: Τα thumbnail previews αποθηκεύονταν συνήθως σε `thumbs.db` files ανά folder.
- **Network folders**: Ένα `thumbs.db` file μπορεί να δημιουργηθεί ακόμη για έναν UNC folder όταν είναι ενεργοποιημένη η σχετική συμπεριφορά thumbnails. Μην θεωρείτε ότι κάθε Windows version ή policy δημιουργεί ένα τέτοιο αρχείο.
- **Windows Vista και νεότερα**: Το system thumbnail cache είναι centralized στο `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`, με files όπως **thumbcache_xxx.db**. Το [**Thumbsviewer**](https://thumbsviewer.github.io) μπορεί να κάνει parse legacy `Thumbs.db`, ενώ το [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) μπορεί να κάνει parse σύγχρονες thumbnail-cache databases.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Πληροφορίες Windows Registry

Το Windows Registry, το οποίο αποθηκεύει system και user configuration data, περιέχεται σε hive files στις εξής τοποθεσίες:

- `%WINDIR%\System32\Config` για τα machine hives που υποστηρίζουν διάφορα `HKEY_LOCAL_MACHINE` subkeys.
- `%USERPROFILE%\NTUSER.DAT` για το `HKEY_CURRENT_USER` hive ενός χρήστη.
- Ορισμένες παλαιότερες Windows installations περιέχουν copies στο `%WINDIR%\System32\Config\RegBack\`. Τα Windows 10 version 1803 και νεότερα δεν γεμίζουν αυτόματα αυτό το directory, εκτός εάν είναι ενεργοποιημένο το periodic backup.<sup>[[34]](#references)[[35]](#references)</sup>
- Τα per-user shell και class-registration data αποθηκεύονται επίσης συνήθως στο `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` σε σύγχρονα Windows.<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

Ορισμένα tools είναι χρήσιμα για την ανάλυση registry hives. Επιβεβαιώστε τα supported hive formats και την έκδοση κάθε tool πριν βασιστείτε σε ένα output:

- **Registry Editor**: Είναι εγκατεστημένο στα Windows. Είναι ένα GUI για την περιήγηση στο Windows registry της τρέχουσας session.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Σας επιτρέπει να φορτώσετε το registry file και να περιηγηθείτε σε αυτό μέσω GUI. Περιλαμβάνει επίσης Bookmarks που επισημαίνουν keys με ενδιαφέρουσες πληροφορίες.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Διαθέτει επίσης GUI που επιτρέπει την περιήγηση στο loaded registry και περιλαμβάνει plugins που επισημαίνουν ενδιαφέρουσες πληροφορίες μέσα στο loaded registry.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Μια ακόμη GUI application ικανή να εξάγει πληροφορίες από ένα loaded registry hive.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Ανάκτηση Deleted Element

Τα deleted hive cells μπορεί να παραμείνουν έως ότου ο χώρος τους ξαναχρησιμοποιηθεί, αλλά η ανάκτηση εξαρτάται από την κατάσταση του hive και τον parser. Αντιμετωπίστε τα recovered deleted keys ως evidence που απαιτεί validation και όχι ως εγγυημένες records.

### Last Write Time

Τα registry keys περιέχουν timestamp τελευταίας εγγραφής. Τα Windows το εκθέτουν για το key ή για οποιοδήποτε από τα value entries του, επομένως μια value δεν έχει απαραίτητα δικό της ανεξάρτητο modification timestamp.<sup>[[69]](#references)</sup>

### SAM

Το **SAM** hive περιέχει local user και group account data, συμπεριλαμβανομένων password hashes που προστατεύονται από το boot-key material του system.<sup>[[38]](#references)[[39]](#references)</sup>

Στο `SAM\Domains\Account\Users` μπορείτε να λάβετε account identifiers και ορισμένα logon και policy fields. Η offline hash extraction απαιτεί επίσης το `SYSTEM` hive για την ανάκτηση του σχετικού boot-key material.<sup>[[38]](#references)[[39]](#references)</sup>

### Ενδιαφέρουσες εγγραφές στο Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

Ένα υπάρχον [post σχετικά με κοινά Windows processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) διατηρείται ως πρόσθετο reading. Επιβεβαιώστε claims σχετικά με τη συμπεριφορά των processes χρησιμοποιώντας την τρέχουσα τεκμηρίωση των Windows και τοπικά στοιχεία.<sup>[[2]](#references)</sup>

### Windows Recent APPs

Σε Windows 10 versions που το εκθέτουν, το `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` περιέχει per-application subkeys με fields όπως last-used time και launch count. Το artifact αφαιρέθηκε από μεταγενέστερες releases, επομένως επικυρώστε το target build.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Σε systems που εκθέτουν το Background Activity Moderator, επιθεωρήστε το `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` ή το νεότερο path `...\bam\State\UserSettings\{SID}`. Οι values χρησιμοποιούν ως keys τα user SIDs και μπορεί να περιέχουν tracked executable paths και execution data τύπου FILETIME. Το artifact εξαρτάται από την έκδοση και θα πρέπει να επιβεβαιώνεται με άλλα στοιχεία.<sup>[[63]](#references)</sup>

### Windows Prefetch

Το Prefetching αποθηκεύει resources και launch metadata σε cache, ώστε τα προγράμματα να ξεκινούν ταχύτερα.

Τα Prefetch files αποθηκεύονται ως `.pf` files στο `C:\Windows\Prefetch`. Τα όρια format, retention και αριθμού files διαφέρουν ανά Windows version. Η Microsoft τεκμηριώνει τη διατήρηση των τελευταίων οκτώ χρόνων εκτέλεσης και έως 1024 files στα Windows 8 και νεότερα, επομένως παλαιότερες περιγραφές με fixed limits δεν θα πρέπει να γενικεύονται.<sup>[[13]](#references)</sup>

Το filename χρησιμοποιεί συνήθως τη μορφή `{program_name}-{hash}.pf`, όπου το hash προκύπτει από το execution context, όπως path και arguments. Τα Windows 10 και νεότερα μπορεί να κάνουν compress το file. Η παρουσία του είναι χρήσιμο evidence εκτέλεσης, αλλά από μόνη της δεν αποτελεί απόδειξη εκτέλεσης από τον χρήστη και θα πρέπει να συσχετίζεται με άλλα artifacts.<sup>[[13]](#references)</sup>

Για την επιθεώρηση αυτών των files μπορείτε να χρησιμοποιήσετε το [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), το οποίο τεκμηριώνει directory parsing, CSV/HTML output και υποστήριξη decompression για τα αντίστοιχα Windows 10 Prefetch files.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

Το **Superfetch/SysMain** συμπληρώνει το Prefetch, χρησιμοποιώντας ιστορικά μοτίβα χρήσης για τη βελτίωση της φόρτωσης. Σε συστήματα που δημιουργούν αυτά τα αρχεία, τα αρχεία βάσης δεδομένων βρίσκονται συνήθως στο `C:\Windows\Prefetch\Ag*.db`. Η μορφή και η παρουσία τους εξαρτώνται από την έκδοση.<sup>[[41]](#references)</sup>

Αυτές οι βάσεις δεδομένων ενδέχεται να περιέχουν ονόματα εφαρμογών, πλήθος χρήσεων, αρχεία ή volumes στα οποία έγινε πρόσβαση, paths και χρονικά διαστήματα, αλλά δεν πρέπει να αντιμετωπίζονται ως ακριβές log εκτέλεσης.<sup>[[41]](#references)</sup>

Ο υπάρχων σύνδεσμος προς το [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) διατηρείται ως πιθανός parser. Πριν από τη χρήση, επαληθεύστε την τρέχουσα διαθεσιμότητά του και το υποστηριζόμενο output με βάση την τεκμηρίωση του tool.

### SRUM

Το **System Resource Usage Monitor** (SRUM) καταγράφει τη χρήση πόρων από εφαρμογές και χρήστες. Παρουσιάστηκε στα Windows 8 και αποθηκεύει δεδομένα στη βάση ESE `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Παρέχει τις ακόλουθες πληροφορίες:

- AppID and Path
- User/SID associated with the record
- Sent Bytes
- Received Bytes
- Network Interface
- Connection duration
- Process duration

Η συχνότητα συλλογής και η διατήρηση των δεδομένων εξαρτώνται από την υλοποίηση. Μην θεωρείτε ότι κάθε record αντιπροσωπεύει ένα ακριβές διάστημα εκτέλεσης 60 λεπτών.<sup>[[13]](#references)</sup>

Μπορείτε να κάνετε extract και review των δεδομένων με το [**srum_dump**](https://github.com/MarkBaggett/srum-dump), χρησιμοποιώντας τις επιλογές που τεκμηριώνονται στην τρέχουσα έκδοση του tool.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

Το **AppCompatCache**, γνωστό και ως **ShimCache**, αποτελεί μέρος της υποδομής συμβατότητας εφαρμογών των Windows και καταγράφει μεταδεδομένα αρχείων για αποφάσεις συμβατότητας. Η διαδρομή της κυψέλης, η μορφή των εγγραφών, η διατηρούμενη χωρητικότητα και τα πεδία διαφέρουν ανάλογα με την έκδοση των Windows· στα σύγχρονα Windows, το ShimCache από μόνο του δεν μπορεί να αποδείξει ότι ένας χρήστης εκτέλεσε ένα αρχείο. Αναλύστε τη σχετική κυψέλη `SYSTEM` με το εργαλείο [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) και επιβεβαιώστε τα αποτελέσματά του με artifacts εκτέλεσης.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Για την ανάλυση των αποθηκευμένων πληροφοριών, συνιστάται η χρήση του εργαλείου AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Το αρχείο **Amcache.hve** είναι μια κυψέλη registry που καταγράφει εφαρμογές και αρχεία που παρατηρούνται από τα Windows. Συνήθως βρίσκεται στη διεύθυνση `C:\Windows\AppCompat\Programs\Amcache.hve`.

Μπορεί να περιέχει συσχετισμένες και μη συσχετισμένες εγγραφές αρχείων, διαδρομές και τιμές SHA1, αλλά η παρουσία του αποτελεί evidence καταγραφής και από μόνη της δεν αποδεικνύει ότι εκτελέστηκε μια διεργασία.<sup>[[13]](#references)[[44]](#references)</sup>

Για την εξαγωγή και ανάλυση του **Amcache.hve**, χρησιμοποιήστε το εργαλείο [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Αυτή η εντολή αναλύει την κυψέλη και εγγράφει την έξοδο σε CSV.<sup>[[44]](#references)</sup>

Για παράδειγμα:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Μεταξύ των παραγόμενων CSV αρχείων, το `Amcache_Unassociated file entries` μπορεί να είναι χρήσιμο κατά τη διερεύνηση αρχείων που δεν σχετίζονται με αναγνωρισμένο πρόγραμμα.<sup>[[44]](#references)</sup>

### RecentFileCache

Σε συστήματα Windows 7, το `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` ενδέχεται να περιέχει πληροφορίες σχετικά με binaries που παρατηρήθηκαν πρόσφατα· η διαθεσιμότητα και η σημασιολογία εξαρτώνται από την έκδοση.

Μπορείτε να χρησιμοποιήσετε το [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) για την ανάλυση του αρχείου.<sup>[[45]](#references)</sup>

### Προγραμματισμένες εργασίες

Evidence σχετικά με scheduled tasks μπορεί να βρεθεί στο `C:\Windows\System32\Tasks` για σύγχρονες εργασίες και στο `C:\Windows\Tasks` με αρχεία `.job` για legacy εργασίες· εξετάστε το format ορισμού της εργασίας που αντιστοιχεί στο λειτουργικό σύστημα.<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Η βάση δεδομένων του Service Control Manager βρίσκεται στο `SYSTEM\CurrentControlSet\Services` (για ένα offline SYSTEM hive, εξετάστε το αντίστοιχο control-set key)· περιέχει configuration για services και drivers, όπως executable paths και start types.<sup>[[72]](#references)</sup>

### **Windows Store**

Οι εγκατεστημένες εφαρμογές Windows Store μπορεί να αναπαρίστανται κάτω από το `\ProgramData\Microsoft\Windows\AppRepository\`, συμπεριλαμβανομένης της database **`StateRepository-Machine.srd`**. Το schema και τα paths διαφέρουν ανάλογα με το Windows release.<sup>[[71]](#references)</sup>

Η database μπορεί να περιέχει application identifiers, package numbers και display names. Κενά στα identifiers δεν αποτελούν από μόνα τους απόδειξη ότι μια εφαρμογή απεγκαταστάθηκε· επιβεβαιώστε τα με την κατάσταση των packages και του registry.

Οι package registrations μπορεί επίσης να εμφανίζονται κάτω από το `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Η Microsoft τεκμηριώνει ένα version-specific `Deprovisioned` subkey για removed provisioned apps· μην θεωρείτε δεδομένο ότι ένα `Deleted` subkey υπάρχει σε κάθε build.<sup>[[70]](#references)</sup>

## Windows Events

Ανάλογα με τον provider, τα Windows events μπορεί να περιέχουν:

- Τι συνέβη
- Ένα timestamp `TimeCreated` που πρέπει να ερμηνεύεται με βάση το event schema και το time context του host
- Τους χρήστες που εμπλέκονται
- Τους hosts που εμπλέκονται (hostname, IP)
- Τα assets στα οποία έγινε πρόσβαση (αρχεία, φάκελοι, printers ή services).<sup>[[49]](#references)</sup>

Πριν από τα Windows Vista, τα event logs χρησιμοποιούσαν γενικά το legacy binary format κάτω από το `C:\Windows\System32\config`· τα Vista και νεότερα χρησιμοποιούν το Windows Event Log format, συνήθως κάτω από το `C:\Windows\System32\winevt\Logs`, με αρχεία `.evtx` που περιέχουν XML-rendered event data.<sup>[[46]](#references)[[47]](#references)</sup>

Το SYSTEM registry αποθηκεύει το channel configuration κάτω από το **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, συμπεριλαμβανομένων του configured file path και των retention settings.<sup>[[47]](#references)</sup>

Μπορούν να προβληθούν με το Windows Event Viewer (**`eventvwr.msc`**) ή με εργαλεία όπως το [**Event Log Explorer**](https://eventlogxp.com) και τα [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Κατανόηση του Windows Security Event Logging

Στα Vista και νεότερα, το Security channel αποθηκεύεται συνήθως στο `C:\Windows\System32\winevt\Logs\Security.evtx`. Το μέγιστο μέγεθος και η retention policy του είναι configurable· με circular logging, παλαιότερα records μπορεί να αντικατασταθούν όταν το αρχείο φτάσει το όριό του. Το channel μπορεί να καταγράφει authentication, logoff, privilege, audit-policy και object-access events όταν έχει ενεργοποιηθεί το σχετικό auditing.<sup>[[46]](#references)[[47]](#references)</sup>

### Βασικά Event IDs για User Authentication:

- **Event ID 4624**: Επιτυχές account logon.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Αποτυχημένο account logon.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Τερματίστηκε ένα logon session.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Ένας χρήστης ξεκίνησε logoff.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Εκχωρήθηκαν special privileges σε νέο logon· αυτό είναι συνηθισμένο για system και administrator accounts, επομένως δεν αποτελεί από μόνο του απόδειξη κακόβουλης δραστηριότητας.<sup>[[54]](#references)</sup>

#### Logon types που καταγράφονται συνήθως στα 4624, 4625, 4634 και 4647:

- **Interactive (2)**: Interactive local logon.
- **Network (3)**: Πρόσβαση σε shared resource.
- **Batch (4)**: Batch-process logon.
- **Service (5)**: Service logon.
- **Unlock (7)**: Unlock workstation.
- **NetworkCleartext (8)**: Network logon που παρέχει credentials σε cleartext στο authentication package.
- **NewCredentials (9)**: Logon που χρησιμοποιεί supplied alternate credentials για outbound connections.
- **RemoteInteractive (10)**: Remote Desktop ή Terminal Services logon.
- **CachedInteractive (11)**: Interactive logon με χρήση cached domain credentials.
- **CachedRemoteInteractive (12)**: Cached remote-interactive logon.
- **CachedUnlock (13)**: Unlock με χρήση cached credentials.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status και Sub Status Codes για το EventID 4625:

- **0xC0000064**: Δεν υπάρχει τέτοιος χρήστης.
- **0xC000006A**: Σωστό user name αλλά λανθασμένο password.
- **0xC0000234**: Ο account έχει κλειδωθεί.
- **0xC0000072**: Ο account είναι disabled.
- **0xC000006F**: Logon εκτός των επιτρεπόμενων ωρών.
- **0xC0000070**: Παραβίαση workstation restriction.
- **0xC0000193**: Ο account έχει λήξει.
- **0xC0000071**: Το password έχει λήξει.
- **0xC0000133**: Η διαφορά ώρας μεταξύ client και server είναι υπερβολικά μεγάλη.
- **0xC0000224**: Ο account πρέπει να αλλάξει το password του.
- **0xC0000225**: `STATUS_NOT_FOUND`; ο κωδικός από μόνος του δεν προσδιορίζει system bug ή attack.
- **0xC000015B**: Ο requested logon type δεν εκχωρείται στον account.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: Άλλαξε η ώρα του συστήματος. Πολλά events αντικατοπτρίζουν routine correction από το time service, επομένως συσχετίστε τον actor και την time source πριν το θεωρήσετε tampering.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008 και 6009:

- **Power and service context**: Το Event 12 καταγράφει την εκκίνηση του OS, το 13 την τερματισμό του OS, το 1074 μια planned shutdown ή restart, το 6008 υποδεικνύει unexpected shutdown και το 6009 καταγράφει την Windows version κατά το boot. Τα events 6005 και 6006 υποδεικνύουν αντίστοιχα ότι το Event Log service ξεκίνησε και σταμάτησε· δεν αποτελούν από μόνα τους απόδειξη εκκίνησης και τερματισμού του OS.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Το Event 1102 καταγράφει ότι το Security audit log διαγράφηκε· διερευνήστε τον actor και τα surrounding events αντί να υποθέσετε πρόθεση μόνο από αυτό το event.<sup>[[62]](#references)</sup>

#### EventIDs για USB Device Tracking:

- **20001 / 20003**: `UserPnp` device-installation events που μπορούν να βοηθήσουν στην τεκμηρίωση first-use ή installation activity.
- **10000 / 10100**: `DriverFrameworks-UserMode` events που μπορεί να συνοδεύουν device activity.
- **Event ID 112**: `DeviceSetupManager/Admin` activity που μπορεί να παρέχει insertion-related timestamps.
- Ο provider, το channel και η σημασιολογία των events διαφέρουν ανάλογα με την έκδοση των Windows· εξετάστε το provider name και το event payload πριν αποδώσετε σημασία.<sup>[[59]](#references)</sup>

Για πρακτικά παραδείγματα σχετικά με τα logon types και το associated credential material, δείτε τον [αναλυτικό οδηγό της Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Οι λεπτομέρειες των events, συμπεριλαμβανομένων του logon type, του status, του substatus, της source address και των process fields, παρέχουν context για το Event ID 4625· ένας status code ή ένα repeated failure pattern αποτελεί investigative lead και όχι conclusion.<sup>[[51]](#references)[[55]](#references)</sup>

### Ανάκτηση Windows Events

Επειδή τα event logs είναι συνήθως circular, records που έχουν αντικατασταθεί από τον logger μπορεί να μην είναι ανακτήσιμα. Διατηρήστε forensic image ή working copy πριν αλληλεπιδράσετε με live system· χρησιμοποιήστε validated parser ή carver, όπως το **Bulk_extractor**, μόνο αφού επιβεβαιώσετε ότι η έκδοση του tool υποστηρίζει τα target `.evtx` data, και μην αποσυνδέετε ένα running system αποκλειστικά για να προσπαθήσετε να ανακτήσετε events.<sup>[[46]](#references)</sup>

### Αναγνώριση Συνηθισμένων Attacks μέσω Windows Events

Για μια πρακτική αναφορά event IDs, δείτε το υπάρχον link [Red Team Recipe](https://redteamrecipe.com/event-codes/) και επικυρώστε τα παραδείγματά του με βάση την παραπάνω τεκμηρίωση των providers.

#### Brute Force Attacks

Συσχετίστε επαναλαμβανόμενες αποτυχίες Event ID 4625 με μεταγενέστερη επιτυχία 4624, το logon type, το status, την source και το account context· η ακολουθία αποτελεί indicator για διερεύνηση και όχι απόδειξη attack.<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Το Event ID 4616 καταγράφει αλλαγές στην ώρα του συστήματος, οι οποίες μπορεί να δυσκολέψουν την ανάλυση timeline· συγκρίνετέ το με time-service και host evidence.<sup>[[56]](#references)</sup>

#### USB Device Tracking

Τα USB event IDs είναι provider-specific· συσχετίστε τα `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 και `DeviceSetupManager/Admin` 112 με SetupAPI και registry artifacts.<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

Χρησιμοποιήστε τα 12/13/1074/6008/6009 για context εκκίνησης, τερματισμού, restart και unexpected power του OS· τα 6005/6006 σηματοδοτούν την εκκίνηση/διακοπή του Event Log service.<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Το Security Event ID 1102 καταγράφει ότι το Security audit log διαγράφηκε και πρέπει να συσχετίζεται με τον υπεύθυνο account και process.<sup>[[62]](#references)</sup>

## References

- [1] [Καθαρισμός Windows Plug and Play](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Διερεύνηση Συνηθισμένων Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Μια Digital Forensic Άποψη των Windows 10 Notifications](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Forensic tools του Eric Zimmerman](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier και Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Backup και restore operations του Registry μέσω VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Registry keys για backup και restore](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Πρόβλημα απόδοσης του Word στη θέση AutoRecover](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Incident Response Guidebook](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Forensics: Αναγνώριση Data Exfiltration Artifacts](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Καταχωρίσεις device installation log του SetupAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID και Related Types](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Εύρεση και μεταφορά Outlook data files](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Ενεργοποίηση Cached Exchange Mode](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Συγχρονίζεται μόνο υποσύνολο items](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Διαμόρφωση size limits για Outlook data files](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Πού αποθηκεύει το Thunderbird τα user data](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird account settings και mbox directories](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache interface](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [Το system registry δεν δημιουργεί backup στο RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Απομακρυσμένη επεξεργασία του registry](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Τεχνική επισκόπηση passwords](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch evidence](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Event Log File Format](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog registry key](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated event property](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Αντιμετώπιση unexpected reboots με χρήση system event logs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Αντιμετώπιση shutdown in process](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [USB Storage Device Forensics for Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastic Windows Logon Types](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Background activity moderator](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Το Quick Print σταματά να εκτυπώνει PDF attachments στο Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows Registry files](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Διατήρηση removed apps ώστε να μην επιστρέφουν κατά τη διάρκεια update](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: Αποτελέσματα δοκιμών FTK και Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Database of Installed Services](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Scheduled Tasks Fail with Error Task Scheduler Service Is Not Available](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Περιήγηση στη Windows Mail database](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
