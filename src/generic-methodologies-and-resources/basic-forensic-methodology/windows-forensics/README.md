# Artifacts των Windows

## Generic Windows Artifacts

### Ειδοποιήσεις Windows 10

Η βάση δεδομένων ειδοποιήσεων ανά χρήστη βρίσκεται στη διαδρομή `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (για παράδειγμα, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Οι πρώτες εκδόσεις των Windows 10 χρησιμοποιούσαν το `appdb.dat`, ενώ το Anniversary Update (1607) εισήγαγε το `wpndatabase.db`. Η SQLite database περιλαμβάνει έναν πίνακα `Notification` με payloads ειδοποιήσεων και πεδία χρονισμού, αν και η διατήρηση και τα διαθέσιμα δεδομένα διαφέρουν ανά έκδοση και πολιτική εκκαθάρισης.<sup>[[3]](#references)</sup>

### Timeline

Το Windows Timeline είναι μια λειτουργία ιστορικού δραστηριότητας που μπορεί να περιέχει εγγραφές για υποστηριζόμενες εφαρμογές, έγγραφα και άλλες δραστηριότητες χρήστη· η κάλυψή του εξαρτάται από την εφαρμογή και την έκδοση των Windows.<sup>[[4]](#references)</sup>

Η database βρίσκεται στη διαδρομή `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Μπορεί να ανοιχτεί με SQLite ή να γίνει parse με το [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), του οποίου η έξοδος μπορεί να εξεταστεί με το [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Τα αρχεία που κατεβαίνουν από το εξωτερικό όριο εμπιστοσύνης ενδέχεται να περιέχουν το **`Zone.Identifier` alternate data stream**, το οποίο καταγράφει πληροφορίες ζώνης και μπορεί να περιλαμβάνει metadata προέλευσης, όπως ένα URL. Η παρουσία και τα πεδία του εξαρτώνται από τον producer και την πολιτική του συστήματος.<sup>[[6]](#references)</sup>

## **Αντίγραφα ασφαλείας αρχείων**

### Recycle Bin

Στα Vista και μεταγενέστερα, το **Recycle Bin** βρίσκεται στον φάκελο **`$Recycle.bin`** στη ρίζα της μονάδας δίσκου (για παράδειγμα, `C:\$Recycle.bin`).\
Όταν διαγράφεται ένα αρχείο σε αυτόν τον φάκελο, δημιουργούνται 2 συγκεκριμένα αρχεία:

- `$I{id}`: Πληροφορίες αρχείου, συμπεριλαμβανομένων της ώρας διαγραφής και της αρχικής διαδρομής
- `$R{id}`: Περιεχόμενο του αρχείου

![Αντίγραφα ασφαλείας αρχείων - Recycle Bin: $R{id}: Περιεχόμενο του αρχείου](<../../../images/image (1029).png>)

Έχοντας αυτά τα αρχεία, μπορείτε να χρησιμοποιήσετε το [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) για να εξαγάγετε την αρχική διαδρομή και την ώρα διαγραφής (χρησιμοποιήστε την έκδοση που αντιστοιχεί στην έκδοση των Windows-στόχου).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Το Volume Shadow Copy Service (VSS) μπορεί να δημιουργεί shadow copies των volumes σε συγκεκριμένο χρονικό σημείο, ενώ τα αρχεία χρησιμοποιούνται· ένα shadow copy δεν αποτελεί υποκατάστατο μιας forensic image.<sup>[[8]](#references)</sup>

Τα metadata του copy συνήθως συσχετίζονται με το `\System Volume Information` στη ρίζα του volume, με identifiers που διαφέρουν ανάλογα με το σύστημα:

![Recycle Bin - Volume Shadow Copies: Αυτά τα αντίγραφα ασφαλείας συνήθως βρίσκονται στο System Volume Information στη ρίζα του file system και το όνομα αποτελείται από UIDs που εμφανίζονται στο...](<../../../images/image (94).png>)

Μετά το mounting μιας image με κατάλληλο forensic mounter, το [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) μπορεί να απαριθμήσει τα διαθέσιμα VSS snapshots και να περιηγηθεί ή να αντιγράψει αρχεία από αυτά.<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Με το mounting της forensics image με το ArsenalImageMounter, το εργαλείο ShadowCopyView μπορεί να χρησιμοποιηθεί για την επιθεώρηση ενός shadow copy και ακόμη και την εξαγωγή των αρχείων...](<../../../images/image (576).png>)

Η διαμόρφωση του VSS registry writer περιλαμβάνει το `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, όπου μπορούν να καθοριστούν αρχεία και keys που εξαιρούνται από το backup:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Η registry entry HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore περιέχει τα αρχεία και τα keys που δεν πρέπει να γίνονται backup](<../../../images/image (254).png>)

Το key `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` περιέχει επίσης τη διαμόρφωση της υπηρεσίας VSS.<sup>[[8]](#references)</sup>

### Office AutoSaved Files

Οι τοποθεσίες του AutoRecover διαφέρουν ανάλογα με την Office εφαρμογή, την έκδοση και τη διαμόρφωση. Για το Word, η Microsoft τεκμηριώνει το `%APPDATA%\Microsoft\Word` ως την προεπιλεγμένη τοποθεσία· ελέγξτε τις ρυθμίσεις της εφαρμογής για το ενεργό path.<sup>[[12]](#references)</sup>

## Shell Items

Ένα shell item είναι ένα item που περιέχει πληροφορίες σχετικά με τον τρόπο πρόσβασης σε άλλο αρχείο.

### Recent Documents (LNK)

Τα Windows συνήθως δημιουργούν shortcuts για πρόσφατα items όταν ένας χρήστης ανοίγει ή αποκτά με άλλον τρόπο πρόσβαση σε ένα item:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Η πρόσβαση σε έναν φάκελο μπορεί επίσης να δημιουργήσει links για τον φάκελο και τους σχετικούς parent φακέλους.

Αυτά τα link files μπορούν να περιέχουν τον τύπο του target, τα MAC times του target, πληροφορίες του volume και το path του target. Αυτά τα metadata μπορεί να βοηθήσουν στην αναγνώριση ενός removed target, όμως το artifact από μόνο του δεν αποτελεί απόδειξη ότι το target ανοίχτηκε από συγκεκριμένο χρήστη.<sup>[[13]](#references)[[14]](#references)</sup>

Τα filesystem timestamps του ίδιου του LNK και τα timestamps του target που είναι ενσωματωμένα σε αυτό είναι διαφορετικά. Μην ερμηνεύετε τη δημιουργία ενός link ως την πρώτη χρήση ή την τροποποίηση ενός link ως την τελευταία χρήση χωρίς corroborating artifacts· το format αποθηκεύει τα timestamps του target ξεχωριστά από τα timestamps του link file.<sup>[[13]](#references)[[14]](#references)</sup>

Το υπάρχον link του [**LinkParser**](http://4discovery.com/our-tools/) διατηρείται ως ιστορική επιλογή, όμως η τεκμηρίωσή του δεν ήταν διαθέσιμη κατά την αξιολόγηση. Για έναν documented command-line parser, χρησιμοποιήστε το [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Αυτά τα tools εμφανίζουν συνήθως δύο σύνολα timestamps:

- **Timestamps του target:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Timestamps του link-file:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Το πρώτο σύνολο αναφέρεται στο target· το δεύτερο σύνολο αναφέρεται στο ίδιο το LNK file. Ερμηνεύστε και τα δύο με βάση την τεκμηρίωση του parser και το filesystem context.<sup>[[14]](#references)[[15]](#references)</sup>

Μπορείτε να λάβετε τις ίδιες πληροφορίες εκτελώντας το Windows CLI tool: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Σε αυτήν την περίπτωση, οι πληροφορίες θα αποθηκευτούν σε ένα αρχείο CSV.

### Jumplists

Τα Jump Lists είναι λίστες ανά εφαρμογή με πρόσφατα στοιχεία ή στοιχεία συγκεκριμένων εργασιών και μπορεί να είναι αυτόματες ή προσαρμοσμένες.<sup>[[13]](#references)</sup>

Τα Automatic Jump Lists αποθηκεύονται στο `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` και χρησιμοποιούν ονόματα όπως `{id}.automaticDestinations-ms`, όπου το ID προσδιορίζει την εφαρμογή.

Τα Custom Jump Lists αποθηκεύονται στο `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`· η εφαρμογή ελέγχει ποιες καταχωρίσεις εργασιών ή στοιχείων δημιουργεί.

Οι χρόνοι δημιουργίας και τροποποίησης του filesystem περιγράφουν το αρχείο Jump List και όχι αυτόματα την πρώτη και την τελευταία πρόσβαση σε κάθε καταχωρισμένο στόχο. Συσχετίστε τις αναλυμένες καταχωρίσεις με τις χρονικές σημάνσεις του αρχείου και άλλα artifacts.<sup>[[13]](#references)</sup>

Μπορείτε να εξετάσετε τα Jump Lists χρησιμοποιώντας το [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: Μπορείτε να εξετάσετε τα jumplists χρησιμοποιώντας το JumplistExplorer](<../../../images/image (168).png>)

(_Σημειώστε ότι οι χρονικές σημάνσεις που παρέχονται από το JumplistExplorer σχετίζονται με το ίδιο το αρχείο jumplist_)

### Shellbags

[**Ακολουθήστε αυτόν τον σύνδεσμο για να μάθετε τι είναι τα shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Χρήση Windows USBs

Η χρήση USB μπορεί μερικές φορές να επιβεβαιωθεί από artifacts που δημιουργούνται όταν γίνεται πρόσβαση σε αρχεία από removable media, όπως:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Εργαλεία όπως το [**USBDetective**](https://usbdetective.com) συσχετίζουν αυτά τα artifacts με εγγραφές συσκευών USB, όμως η διαθεσιμότητα των artifacts εξαρτάται από την έκδοση των Windows και την εφαρμογή.<sup>[[18]](#references)</sup>

Σε δοκιμές που τεκμηριώθηκαν για workflows MTP σε Windows XP και Windows 7, ορισμένα LNKs έδειχναν σε έναν φάκελο `WPDNSE` αντί για την αρχική διαδρομή.<sup>[[16]](#references)</sup>

![Shellbags - Use of Windows USBs: Σημειώστε ότι ορισμένα αρχεία LNK, αντί να δείχνουν στην αρχική διαδρομή, δείχνουν στον φάκελο WPDNSE](<../../../images/image (218).png>)

Η μελέτη παρατήρησε αντίγραφα στο `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`· τα προσωρινά περιεχόμενα δεν παρέμεναν μετά από επανεκκίνηση στις δοκιμές της και το GUID μπορούσε να συσχετιστεί με δεδομένα shellbag. Αντιμετωπίστε το ως συμπεριφορά που εξαρτάται από το OS, τη συσκευή και την εφαρμογή και όχι ως καθολικό κανόνα.<sup>[[16]](#references)</sup>

### Πληροφορίες Registry

[Ελέγξτε αυτήν τη σελίδα για να μάθετε](interesting-windows-registry-keys.md#usb-information) ποια registry keys περιέχουν ενδιαφέρουσες πληροφορίες για συνδεδεμένες συσκευές USB.

### setupapi

Σε Vista και νεότερα, εξετάστε το `C:\Windows\inf\setupapi.dev.log` για δραστηριότητα εγκατάστασης συσκευών. Οι επικεφαλίδες των ενοτήτων περιλαμβάνουν χρονικές σημάνσεις `Section start`· τεκμηριώνουν την επεξεργασία εγκατάστασης και πρέπει να συσχετίζονται με άλλα στοιχεία σύνδεσης, αντί να θεωρούνται ακριβής χρόνος φυσικής εισαγωγής.<sup>[[17]](#references)</sup>

![Registry Information - setupapi: Ελέγξτε το αρχείο C: Windows inf setupapi.dev.log για να λάβετε τις χρονικές σημάνσεις σχετικά με το πότε πραγματοποιήθηκε η σύνδεση USB (αναζητήστε το Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

Το [**USBDetective**](https://usbdetective.com) μπορεί να χρησιμοποιηθεί για τη λήψη πληροφοριών σχετικά με τις συσκευές USB που έχουν συνδεθεί σε ένα image.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: Το USBDetective μπορεί να χρησιμοποιηθεί για τη λήψη πληροφοριών σχετικά με τις συσκευές USB που έχουν συνδεθεί σε ένα image](<../../../images/image (452).png>)

### Plug and Play Cleanup

Η scheduled task με το όνομα `Plug and Play Cleanup` καταργεί παρωχημένες εκδόσεις drivers. Ένας ορισμός task των Windows 10 που τεκμηριώθηκε από τον Adam Harrison στοχεύει επίσης drivers που είναι ανενεργοί για 30 ημέρες, επομένως τα στοιχεία drivers removable devices μπορεί να καθαριστούν· επιβεβαιώστε τον τοπικό ορισμό του task και το Windows build πριν γενικεύσετε αυτήν τη συμπεριφορά.<sup>[[1]](#references)</sup>

Το task βρίσκεται στην ακόλουθη διαδρομή: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

**Βασικά στοιχεία και ρυθμίσεις του task:**

- **pnpclean.dll**: Αυτό το DLL είναι υπεύθυνο για την πραγματική διαδικασία εκκαθάρισης.
- **UseUnifiedSchedulingEngine**: Ορίζεται σε `TRUE`, υποδεικνύοντας τη χρήση της generic task scheduling engine.
- **MaintenanceSettings**:
- **Period ('P1M')**: Κατευθύνει το Task Scheduler να ξεκινά το task κάθε μήνα κατά τη διάρκεια της κανονικής Automatic maintenance.
- **Deadline ('P2M')**: Δίνει εντολή στο Task Scheduler, αν το task αποτύχει για δύο συνεχόμενους μήνες, να το εκτελέσει κατά τη διάρκεια emergency Automatic maintenance.

Αυτή η διαμόρφωση προγραμματίζει τακτική συντήρηση και επαναλήψεις μετά από διαδοχικές αποτυχίες· το ακριβές XML και η συμπεριφορά εξαρτώνται από την έκδοση.<sup>[[1]](#references)</sup>

**Για περισσότερες πληροφορίες, ελέγξτε:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Emails

Τα Emails περιέχουν **2 ενδιαφέροντα μέρη: τις κεφαλίδες και το περιεχόμενο** του email. Στις **κεφαλίδες** μπορείτε να βρείτε πληροφορίες όπως:

- **Ποιος** έστειλε τα emails (διεύθυνση email, IP, mail servers που ανακατεύθυναν το email)
- **Πότε** στάλθηκε το email

Επίσης, οι κεφαλίδες `References` και `In-Reply-To` μπορούν να περιέχουν message IDs που χρησιμοποιούνται για τη συσχέτιση απαντήσεων με μια συνομιλία.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Emails: Πότε στάλθηκε το email](<../../../images/image (593).png>)

### Windows Mail App

Αυτή η εφαρμογή αποθηκεύει το περιεχόμενο των emails σε βοηθητικά αρχεία κειμένου ή HTML σε διαδρομές όπως `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`· η ακριβής διάταξη των αριθμημένων φακέλων και αρχείων μπορεί να διαφέρει ανά artifact.<sup>[[75]](#references)</sup>

Τα **metadata** των emails και οι **contacts** μπορούν να βρεθούν μέσα στη **βάση δεδομένων ESE** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

Το `store.vol` χρησιμοποιεί τη μορφή Extensible Storage Engine (ESE). Εργαστείτε σε αντίγραφο και χρησιμοποιήστε έναν ESE parser, όπως το [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)· αν ένα εργαλείο απαιτεί επίθημα `.edb`, μετονομάστε μόνο το αντίγραφο και επαληθεύστε το schema των tables πριν βασιστείτε σε έναν πίνακα `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Κατά την εξέταση ιδιοτήτων Outlook MAPI, οι canonical properties περιλαμβάνουν:

- `PidTagClientSubmitTime`: η ώρα UTC κατά την οποία ο client υπέβαλε το μήνυμα.
- `PidTagConversationIndex`: η σχετική θέση του μηνύματος σε ένα conversation thread.
- `PidTagEntryId`: ένα identifier για το message object.
- `PidTagMessageFlags`: status flags όπως submitted, read, unread ή having attachments.
- `PidTagLastVerbExecuted`: η τελευταία operation που καταγράφηκε για το μήνυμα, όπως open, reply ή forward.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Οι τοποθεσίες των Outlook data files διαφέρουν ανά έκδοση και τύπο account. Η Microsoft τεκμηριώνει τις ακόλουθες κοινές τοποθεσίες για αρχεία PST/OST:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Η registry path `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` μπορεί να προσδιορίζει το Outlook profile και τη σχετική διαμόρφωση data-file.

Τα αρχεία PST μπορούν να περιέχουν messages, contacts, calendar data και άλλα Outlook items. Μπορείτε να εξετάσετε ένα αντίγραφο με το [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: Μπορείτε να ανοίξετε το αρχείο PST χρησιμοποιώντας το εργαλείο Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

Ένα **OST file** είναι local cache για Exchange ή Microsoft 365 accounts· το Cached Exchange Mode δεν εφαρμόζεται σε POP ή IMAP accounts. Η offline period είναι παραμετροποιήσιμη και συχνά είναι 12 μήνες από προεπιλογή, ενώ τα size limits των PST/OST είναι ξεχωριστές παραμετροποιήσιμες ρυθμίσεις. Για την προβολή ενός OST file, μπορεί να χρησιμοποιηθεί το [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Ανάκτηση Attachments

Χαμένα attachments ενδέχεται να μπορούν να ανακτηθούν από:

- Για παλαιότερες διαμορφώσεις Outlook/IE: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Για νεότερες διαμορφώσεις Outlook/IE11: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

Το **Thunderbird** αποθηκεύει τα profile data στο `%APPDATA%\Thunderbird\Profiles`· οι mail folders χρησιμοποιούν συνήθως mbox files χωρίς extension στους ειδικούς για κάθε account καταλόγους `Mail` ή `ImapMail`.<sup>[[29]](#references)[[30]](#references)</sup>

### Image Thumbnails

- **Windows XP**: Οι thumbnail previews αποθηκεύονταν συνήθως σε αρχεία `thumbs.db` ανά folder.
- **Network folders**: Ένα αρχείο `thumbs.db` μπορεί να δημιουργείται ακόμη για έναν UNC folder όταν είναι ενεργοποιημένη η σχετική συμπεριφορά thumbnails· μην θεωρείτε ότι κάθε Windows version ή policy δημιουργεί ένα.
- **Windows Vista και νεότερα**: Το system thumbnail cache είναι συγκεντρωμένο στο `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`, με αρχεία όπως **thumbcache_xxx.db**. Το [**Thumbsviewer**](https://thumbsviewer.github.io) μπορεί να αναλύσει παλαιότερα `Thumbs.db`, ενώ το [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) μπορεί να αναλύσει σύγχρονες thumbnail-cache databases.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry Information

Το Windows Registry, το οποίο αποθηκεύει system και user configuration data, περιέχεται σε hive files στις εξής τοποθεσίες:

- `%WINDIR%\System32\Config` για τα machine hives που υποστηρίζουν διάφορα `HKEY_LOCAL_MACHINE` subkeys.
- `%USERPROFILE%\NTUSER.DAT` για το `HKEY_CURRENT_USER` hive ενός χρήστη.
- Ορισμένες παλαιότερες Windows installations περιέχουν αντίγραφα στο `%WINDIR%\System32\Config\RegBack\`· τα Windows 10 version 1803 και νεότερα δεν συμπληρώνουν αυτόματα αυτόν τον κατάλογο, εκτός αν είναι ενεργοποιημένο periodic backup.<sup>[[34]](#references)[[35]](#references)</sup>
- Τα per-user shell και class-registration data αποθηκεύονται επίσης συνήθως στο `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` σε σύγχρονα Windows.<sup>[[34]](#references)[[66]](#references)</sup>

### Εργαλεία

Ορισμένα εργαλεία είναι χρήσιμα για την ανάλυση registry hives· επιβεβαιώστε τα υποστηριζόμενα hive formats και την έκδοση κάθε εργαλείου πριν βασιστείτε σε output:

- **Registry Editor**: Είναι εγκατεστημένο στα Windows. Είναι ένα GUI για την περιήγηση στο Windows Registry της τρέχουσας session.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Σας επιτρέπει να φορτώσετε το registry file και να περιηγηθείτε σε αυτό μέσω GUI. Περιέχει επίσης Bookmarks που επισημαίνουν keys με ενδιαφέρουσες πληροφορίες.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Διαθέτει επίσης GUI για την περιήγηση στο φορτωμένο registry και plugins που επισημαίνουν ενδιαφέρουσες πληροφορίες μέσα σε αυτό.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Άλλη GUI εφαρμογή ικανή να εξάγει πληροφορίες από ένα φορτωμένο registry hive.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Ανάκτηση Deleted Element

Τα διαγραμμένα hive cells μπορεί να παραμένουν έως ότου ο χώρος τους επαναχρησιμοποιηθεί, όμως η ανάκτηση εξαρτάται από την κατάσταση του hive και τον parser· αντιμετωπίζετε τα ανακτημένα deleted keys ως στοιχεία που απαιτούν validation και όχι ως εγγυημένες records.

### Last Write Time

Τα registry keys διαθέτουν timestamp τελευταίας εγγραφής· τα Windows το εκθέτουν για το key ή οποιοδήποτε από τα value entries του, επομένως μια value δεν έχει απαραίτητα δικό της ανεξάρτητο modification timestamp.<sup>[[69]](#references)</sup>

### SAM

Το **SAM** hive περιέχει δεδομένα τοπικών user και group accounts, συμπεριλαμβανομένων password hashes που προστατεύονται από το boot-key material του system.<sup>[[38]](#references)[[39]](#references)</sup>

Στο `SAM\Domains\Account\Users` μπορείτε να λάβετε account identifiers και ορισμένα logon και policy fields. Η offline hash extraction απαιτεί επίσης το `SYSTEM` hive για την ανάκτηση του σχετικού boot-key material.<sup>[[38]](#references)[[39]](#references)</sup>

### Ενδιαφέρουσες καταχωρίσεις στο Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

Ένα υπάρχον [post σχετικά με συνηθισμένα Windows processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) διατηρείται ως πρόσθετο υλικό ανάγνωσης· επιβεβαιώστε τυχόν claims σχετικά με τη συμπεριφορά των processes με την τρέχουσα τεκμηρίωση των Windows και τοπικά στοιχεία.<sup>[[2]](#references)</sup>

### Windows Recent APPs

Σε Windows 10 versions που το υποστηρίζουν, το `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` περιέχει subkeys ανά εφαρμογή με fields όπως last-used time και launch count· το artifact αφαιρέθηκε από μεταγενέστερες releases, επομένως επικυρώστε το target build.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Σε systems που εκθέτουν το Background Activity Moderator, εξετάστε το `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` ή τη νεότερη διαδρομή `...\bam\State\UserSettings\{SID}`. Οι values αντιστοιχίζονται με βάση το user SID και μπορεί να περιέχουν tracked executable paths και execution data τύπου FILETIME· το artifact εξαρτάται από την έκδοση και πρέπει να επιβεβαιώνεται με άλλα στοιχεία.<sup>[[63]](#references)</sup>

### Windows Prefetch

Το Prefetching αποθηκεύει resources και launch metadata σε cache, ώστε τα programs να ξεκινούν ταχύτερα.

Τα Prefetch files αποθηκεύονται ως `.pf` files στο `C:\Windows\Prefetch`· η μορφή, η διατήρηση και τα όρια πλήθους files διαφέρουν ανά Windows version. Η Microsoft τεκμηριώνει διατήρηση των τελευταίων οκτώ execution times και έως 1024 files σε Windows 8 και νεότερα, επομένως παλαιότερες περιγραφές fixed limits δεν πρέπει να γενικεύονται.<sup>[[13]](#references)</sup>

Το filename χρησιμοποιεί συνήθως τη μορφή `{program_name}-{hash}.pf`, με το hash να προκύπτει από execution context, όπως path και arguments· τα Windows 10 και νεότερα μπορεί να κάνουν compress το file. Η παρουσία του αποτελεί χρήσιμο execution evidence, αλλά από μόνη της δεν αποδεικνύει ότι το εκτέλεσε χρήστης και πρέπει να συσχετίζεται με άλλα artifacts.<sup>[[13]](#references)</sup>

Για την εξέταση αυτών των files μπορείτε να χρησιμοποιήσετε το [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), το οποίο τεκμηριώνει directory parsing, CSV/HTML output και decompression support για τα αντίστοιχα Windows 10 Prefetch files.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

Το **Superfetch/SysMain** συμπληρώνει το Prefetch χρησιμοποιώντας ιστορικά μοτίβα χρήσης για τη βελτίωση της φόρτωσης. Σε συστήματα που τα δημιουργούν, τα αρχεία βάσης δεδομένων βρίσκονται συνήθως στη θέση `C:\Windows\Prefetch\Ag*.db`· η μορφή και η παρουσία τους εξαρτώνται από την έκδοση.<sup>[[41]](#references)</sup>

Αυτές οι βάσεις δεδομένων ενδέχεται να περιέχουν ονόματα εφαρμογών, αριθμούς χρήσης, αρχεία ή τόμους στους οποίους έγινε πρόσβαση, διαδρομές και χρονικά εύρη, αλλά δεν πρέπει να αντιμετωπίζονται ως ακριβές αρχείο καταγραφής εκτέλεσης.<sup>[[41]](#references)</sup>

Ο υπάρχων σύνδεσμος προς το [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) διατηρείται ως πιθανός parser· επαληθεύστε τη διαθεσιμότητα και την υποστηριζόμενη μορφή εξόδου του με βάση την τεκμηρίωση του tool πριν από τη χρήση.

### SRUM

Το **System Resource Usage Monitor** (SRUM) καταγράφει τη χρήση πόρων από εφαρμογές και χρήστες. Εισήχθη στα Windows 8 και αποθηκεύει δεδομένα στη βάση δεδομένων ESE `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Παρέχει τις ακόλουθες πληροφορίες:

- AppID και Path
- User/SID που σχετίζεται με την εγγραφή
- Sent Bytes
- Received Bytes
- Network Interface
- Connection duration
- Process duration

Η συχνότητα συλλογής και η διατήρηση των δεδομένων εξαρτώνται από την υλοποίηση· μην υποθέτετε ότι κάθε εγγραφή αντιπροσωπεύει ακριβές διάστημα εκτέλεσης 60 λεπτών.<sup>[[13]](#references)</sup>

Μπορείτε να εξαγάγετε και να εξετάσετε δεδομένα με το [**srum_dump**](https://github.com/MarkBaggett/srum-dump), χρησιμοποιώντας τις επιλογές που τεκμηριώνονται στην τρέχουσα έκδοση του tool.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

Το **AppCompatCache**, γνωστό και ως **ShimCache**, αποτελεί μέρος της υποδομής συμβατότητας εφαρμογών των Windows και καταγράφει metadata αρχείων για αποφάσεις συμβατότητας. Η διαδρομή του hive, η μορφή των εγγραφών, η διατηρούμενη χωρητικότητα και τα πεδία διαφέρουν ανά έκδοση των Windows· στα σύγχρονα Windows, το ShimCache από μόνο του δεν μπορεί να αποδείξει ότι ένας χρήστης εκτέλεσε ένα αρχείο. Κάντε parse στο σχετικό `SYSTEM` hive με το εργαλείο [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) και συσχετίστε τα αποτελέσματά του με artifacts εκτέλεσης.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Για το parse των αποθηκευμένων πληροφοριών, συνιστάται η χρήση του εργαλείου AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Το αρχείο **Amcache.hve** είναι ένα registry hive που καταγράφει εφαρμογές και αρχεία που εντοπίστηκαν από τα Windows. Συνήθως βρίσκεται στη διεύθυνση `C:\Windows\AppCompat\Programs\Amcache.hve`.

Μπορεί να περιέχει συσχετισμένες και μη συσχετισμένες εγγραφές αρχείων, paths και τιμές SHA1, αλλά η παρουσία του αποτελεί evidence inventory και από μόνη της δεν αποδεικνύει ότι εκτελέστηκε κάποια διεργασία.<sup>[[13]](#references)[[44]](#references)</sup>

Για την εξαγωγή και ανάλυση του **Amcache.hve**, χρησιμοποιήστε το εργαλείο [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Αυτή η εντολή κάνει parse στο hive και γράφει output σε CSV.<sup>[[44]](#references)</sup>

Για παράδειγμα:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Μεταξύ των παραγόμενων αρχείων CSV, το `Amcache_Unassociated file entries` μπορεί να είναι χρήσιμο κατά τη διερεύνηση αρχείων που δεν συσχετίζονται με αναγνωρισμένο πρόγραμμα.<sup>[[44]](#references)</sup>

### RecentFileCache

Σε συστήματα Windows 7, το `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` μπορεί να περιέχει πληροφορίες σχετικά με binaries που παρατηρήθηκαν πρόσφατα· η διαθεσιμότητα και η σημασία του εξαρτώνται από την έκδοση.

Μπορείτε να χρησιμοποιήσετε το [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) για την ανάλυση του αρχείου.<sup>[[45]](#references)</sup>

### Προγραμματισμένες εργασίες

Evidence για προγραμματισμένες εργασίες μπορεί να βρεθεί στο `C:\Windows\System32\Tasks` για σύγχρονες εργασίες και στο `C:\Windows\Tasks` με αρχεία `.job` για παλαιού τύπου εργασίες· εξετάστε το format ορισμού εργασίας που αντιστοιχεί στο λειτουργικό σύστημα.<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Η βάση δεδομένων του Service Control Manager βρίσκεται στο `SYSTEM\CurrentControlSet\Services` (για ένα offline SYSTEM hive, εξετάστε το αντίστοιχο control-set key)· περιέχει ρυθμίσεις services και drivers, όπως διαδρομές εκτελέσιμων αρχείων και τύπους εκκίνησης.<sup>[[72]](#references)</sup>

### **Windows Store**

Οι εγκατεστημένες εφαρμογές του Windows Store μπορεί να αναπαρίστανται στο `\ProgramData\Microsoft\Windows\AppRepository\`, συμπεριλαμβανομένης της βάσης δεδομένων **`StateRepository-Machine.srd`**. Το schema και οι διαδρομές διαφέρουν ανά έκδοση των Windows.<sup>[[71]](#references)</sup>

Η βάση δεδομένων μπορεί να περιέχει identifiers εφαρμογών, αριθμούς packages και εμφανιζόμενα ονόματα. Τα κενά στα identifiers δεν αποτελούν από μόνα τους απόδειξη ότι μια εφαρμογή απεγκαταστάθηκε· επιβεβαιώστε τα με την κατάσταση των packages και του registry.

Οι registrations των packages μπορεί επίσης να εμφανίζονται στο `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Η Microsoft τεκμηριώνει ένα version-specific subkey `Deprovisioned` για provisioned apps που αφαιρέθηκαν· μην υποθέτετε ότι υπάρχει subkey `Deleted` σε κάθε build.<sup>[[70]](#references)</sup>

## Windows Events

Ανάλογα με τον provider, τα Windows events μπορεί να περιέχουν:

- Τι συνέβη
- Ένα timestamp `TimeCreated` που πρέπει να ερμηνεύεται με βάση το event schema και το χρονικό πλαίσιο του host
- Τους εμπλεκόμενους χρήστες
- Τους εμπλεκόμενους hosts (hostname, IP)
- Τα assets στα οποία έγινε πρόσβαση (files, folders, printers ή services).<sup>[[49]](#references)</sup>

Πριν από τα Windows Vista, τα event logs χρησιμοποιούσαν γενικά το παλαιού τύπου binary format στο `C:\Windows\System32\config`· τα Vista και νεότερα χρησιμοποιούν το Windows Event Log format, συνήθως στο `C:\Windows\System32\winevt\Logs`, με αρχεία `.evtx` που περιέχουν event data σε XML.<sup>[[46]](#references)[[47]](#references)</sup>

Το SYSTEM registry αποθηκεύει τη ρύθμιση των channels στο **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, συμπεριλαμβανομένης της διαμορφωμένης διαδρομής αρχείου και των ρυθμίσεων διατήρησης.<sup>[[47]](#references)</sup>

Μπορούν να προβληθούν με το Windows Event Viewer (**`eventvwr.msc`**) ή με εργαλεία όπως τα [**Event Log Explorer**](https://eventlogxp.com) και [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Understanding Windows Security Event Logging

Στα Vista και νεότερα, το Security channel αποθηκεύεται συνήθως στο `C:\Windows\System32\winevt\Logs\Security.evtx`. Το μέγιστο μέγεθος και η πολιτική διατήρησης είναι διαμορφώσιμα· με circular logging, παλαιότερες εγγραφές μπορεί να αντικατασταθούν όταν το αρχείο φτάσει το όριό του. Το channel μπορεί να καταγράφει authentication, logoff, privilege, audit-policy και object-access events όταν έχει ενεργοποιηθεί το σχετικό auditing.<sup>[[46]](#references)[[47]](#references)</sup>

### Key Event IDs for User Authentication:

- **Event ID 4624**: Επιτυχές account logon.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Αποτυχημένο account logon.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Τερματίστηκε μια logon session.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Ένας χρήστης ξεκίνησε logoff.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Εκχωρήθηκαν ειδικά privileges σε νέο logon· αυτό είναι συνηθισμένο για system και administrator accounts και επομένως δεν αποτελεί από μόνο του απόδειξη κακόβουλης δραστηριότητας.<sup>[[54]](#references)</sup>

#### Logon types commonly recorded in 4624, 4625, 4634, and 4647:

- **Interactive (2)**: Interactive local logon.
- **Network (3)**: Πρόσβαση σε shared resource.
- **Batch (4)**: Logon από batch process.
- **Service (5)**: Service logon.
- **Unlock (7)**: Ξεκλείδωμα workstation.
- **NetworkCleartext (8)**: Network logon που παρέχει credentials σε cleartext στο authentication package.
- **NewCredentials (9)**: Logon που χρησιμοποιεί παρεχόμενα alternate credentials για outbound connections.
- **RemoteInteractive (10)**: Remote Desktop ή Terminal Services logon.
- **CachedInteractive (11)**: Interactive logon με χρήση cached domain credentials.
- **CachedRemoteInteractive (12)**: Cached remote-interactive logon.
- **CachedUnlock (13)**: Ξεκλείδωμα με χρήση cached credentials.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: Δεν υπάρχει τέτοιος χρήστης.
- **0xC000006A**: Σωστό user name αλλά λανθασμένος κωδικός πρόσβασης.
- **0xC0000234**: Ο account έχει κλειδωθεί.
- **0xC0000072**: Ο account είναι disabled.
- **0xC000006F**: Logon εκτός επιτρεπόμενου ωραρίου.
- **0xC0000070**: Παραβίαση περιορισμού workstation.
- **0xC0000193**: Ο account έχει λήξει.
- **0xC0000071**: Ο κωδικός πρόσβασης έχει λήξει.
- **0xC0000133**: Η διαφορά ώρας μεταξύ client και server είναι υπερβολικά μεγάλη.
- **0xC0000224**: Ο account πρέπει να αλλάξει τον κωδικό πρόσβασής του.
- **0xC0000225**: `STATUS_NOT_FOUND`· ο κωδικός από μόνος του δεν προσδιορίζει system bug ή attack.
- **0xC000015B**: Ο requested logon type δεν εκχωρείται στον account.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: Η ώρα του συστήματος άλλαξε. Πολλά events αντικατοπτρίζουν συνήθη διόρθωση από το time service, επομένως συσχετίστε τον actor και την πηγή ώρας πριν το θεωρήσετε tampering.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008, and 6009:

- **Power and service context**: Το Event 12 καταγράφει την εκκίνηση του OS, το 13 την απενεργοποίηση του OS, το 1074 μια προγραμματισμένη απενεργοποίηση ή επανεκκίνηση, το 6008 υποδεικνύει απρόσμενη απενεργοποίηση και το 6009 καταγράφει την έκδοση των Windows κατά την εκκίνηση. Τα Events 6005 και 6006 υποδεικνύουν αντίστοιχα την έναρξη και τη διακοπή του Event Log service· δεν αποτελούν από μόνα τους απόδειξη εκκίνησης και τερματισμού του OS.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Το Event 1102 καταγράφει ότι το Security audit log εκκαθαρίστηκε· διερευνήστε τον actor και τα surrounding events αντί να υποθέσετε πρόθεση μόνο από αυτό το event.<sup>[[62]](#references)</sup>

#### EventIDs for USB Device Tracking:

- **20001 / 20003**: `UserPnp` device-installation events που μπορούν να βοηθήσουν στην τεκμηρίωση first-use ή installation activity.
- **10000 / 10100**: `DriverFrameworks-UserMode` events που μπορεί να συνοδεύουν device activity.
- **Event ID 112**: `DeviceSetupManager/Admin` activity που μπορεί να παρέχει timestamps σχετιζόμενα με insertion.
- Οι providers, τα channels και τα event semantics διαφέρουν ανά έκδοση των Windows· εξετάστε το provider name και το event payload πριν αποδώσετε σημασία.<sup>[[59]](#references)</sup>

Για πρακτικά παραδείγματα σχετικά με τα logon types και το αντίστοιχο credential material, δείτε τον [αναλυτικό οδηγό της Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Οι λεπτομέρειες των events, συμπεριλαμβανομένων των logon type, status, substatus, source address και process fields, παρέχουν context για το Event ID 4625· ένας status code ή ένα επαναλαμβανόμενο pattern αποτυχιών αποτελεί investigative lead και όχι συμπέρασμα.<sup>[[51]](#references)[[55]](#references)</sup>

### Recovering Windows Events

Επειδή τα event logs είναι συνήθως circular, οι εγγραφές που αντικαταστάθηκαν από τον logger μπορεί να μην είναι ανακτήσιμες. Διατηρήστε forensic image ή working copy πριν αλληλεπιδράσετε με live system· χρησιμοποιήστε validated parser ή carver, όπως το **Bulk_extractor**, μόνο αφού επιβεβαιώσετε ότι η έκδοση του εργαλείου υποστηρίζει τα δεδομένα `.evtx`-στόχο και μην αποσυνδέετε ένα system που εκτελείται αποκλειστικά για να προσπαθήσετε να ανακτήσετε events.<sup>[[46]](#references)</sup>

### Identifying Common Attacks via Windows Events

Για πρακτική αναφορά σε event IDs, δείτε τον υπάρχοντα σύνδεσμο [Red Team Recipe](https://redteamrecipe.com/event-codes/) και επικυρώστε τα παραδείγματά του με βάση την παραπάνω τεκμηρίωση των providers.

#### Brute Force Attacks

Συσχετίστε επαναλαμβανόμενες αποτυχίες Event ID 4625 με μεταγενέστερη επιτυχία 4624, το logon type, το status, την πηγή και το account context· η ακολουθία αποτελεί indicator για διερεύνηση και όχι απόδειξη attack.<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Το Event ID 4616 καταγράφει αλλαγές στην ώρα του system, οι οποίες μπορεί να περιπλέξουν την ανάλυση timeline· συγκρίνετέ το με στοιχεία του time service και του host.<sup>[[56]](#references)</sup>

#### USB Device Tracking

Τα USB event IDs εξαρτώνται από τον provider· συσχετίστε τα `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 και `DeviceSetupManager/Admin` 112 με artifacts των SetupAPI και registry.<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

Χρησιμοποιήστε τα 12/13/1074/6008/6009 για context σχετικά με εκκίνηση, απενεργοποίηση, επανεκκίνηση του OS και απρόσμενη απώλεια ισχύος· τα 6005/6006 σηματοδοτούν την έναρξη/διακοπή του Event Log service.<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Το Security Event ID 1102 καταγράφει ότι το Security audit log εκκαθαρίστηκε και πρέπει να συσχετίζεται με τον υπεύθυνο account και process.<sup>[[62]](#references)</sup>

## References

- [1] [Εκκαθάριση Windows Plug and Play](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Διερεύνηση συνηθισμένων Windows processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Μια digital forensic άποψη των Windows 10 notifications](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Forensic εργαλεία του Eric Zimmerman](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier και Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Λειτουργίες backup και restore του registry μέσω VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Registry keys για backup και restore](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Πρόβλημα απόδοσης του Word στη θέση AutoRecover](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Οδηγός Incident Response](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Binary File Format του Shell Link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Forensics: Αναγνώριση artifacts Data Exfiltration](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Εγγραφές device installation log του SetupAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID και σχετικοί τύποι](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Εύρεση και μεταφορά Outlook data files](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Ενεργοποίηση Cached Exchange Mode](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Συγχρονίζεται μόνο υποσύνολο items](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Ρύθμιση ορίων μεγέθους για Outlook data files](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Πού αποθηκεύει το Thunderbird τα user data](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Ρυθμίσεις Thunderbird accounts και mbox directories](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache interface](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [Το system registry δεν γίνεται backup στο RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Απομακρυσμένη επεξεργασία του registry](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Τεχνική επισκόπηση κωδικών πρόσβασης](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch evidence](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Event Log File Format](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog registry key](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [Ιδιότητα event TimeCreated](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: Τιμές NTSTATUS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Αντιμετώπιση απρόσμενων reboots με χρήση system event logs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Αντιμετώπιση shutdown σε εξέλιξη](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [USB Storage Device Forensics για Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
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
- [70] [Αποτροπή επανεμφάνισης removed apps κατά τη διάρκεια update](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: Αποτελέσματα δοκιμών FTK και Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Βάση δεδομένων εγκατεστημένων Services](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Οι Scheduled Tasks αποτυγχάνουν με το σφάλμα Task Scheduler Service Is Not Available](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Περιήγηση στη βάση δεδομένων Windows Mail](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
