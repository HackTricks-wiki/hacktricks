# Ενδιαφέροντα κλειδιά μητρώου των Windows

{{#include ../../../banners/hacktricks-training.md}}

Οι κυψέλες του Windows Registry είναι ένας από τους ταχύτερους τρόπους για να περάσετε από το _τι συνέβη;_ στο _ποιος χρήστης, πότε και από πού;_. Για ζωντανή ανάλυση, προτιμήστε το `CurrentControlSet`. Για ανάλυση κυψελών εκτός σύνδεσης, εντοπίστε πρώτα ποιο `ControlSet00x` ήταν ενεργό, αντί να ορίσετε σταθερά το `ControlSet001`.

### Πληροφορίες έκδοσης των Windows και κατόχου

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: έκδοση/build των Windows, χρόνος εγκατάστασης, καταχωρισμένος κάτοχος, όνομα προϊόντος και άλλα μεταδεδομένα build.
- `SYSTEM\Select`: αντιστοιχίζει τα `Current`, `Default` και `LastKnownGood` στις πραγματικές τιμές `ControlSet00x` που χρησιμοποιεί το σύστημα.

### Όνομα υπολογιστή

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: τρέχον hostname.

### Ρύθμιση ζώνης ώρας

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: ρυθμισμένη ζώνη ώρας και τιμές που σχετίζονται με τη θερινή ώρα.

### Παρακολούθηση χρόνου πρόσβασης

- `SYSTEM\CurrentControlSet\Control\FileSystem`: το `NtfsDisableLastAccessUpdate` υποδεικνύει αν ενημερώνονται οι χρονικές σημάνσεις τελευταίας πρόσβασης του NTFS.
- Για να την ενεργοποιήσετε, χρησιμοποιήστε: `fsutil behavior set disablelastaccess 0`

### Λεπτομέρειες τερματισμού λειτουργίας

- `SYSTEM\CurrentControlSet\Control\Windows`: χρόνος τελευταίου τερματισμού λειτουργίας.
- Τα παλαιότερα συστήματα ενδέχεται επίσης να εμφανίζουν μετρητές τερματισμού λειτουργίας στο `SYSTEM\CurrentControlSet\Control\Watchdog\Display`.

### Ρύθμιση δικτύου

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: διευθύνσεις IP διεπαφών, μισθώσεις DHCP, δεδομένα gateway και DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: όνομα/SSID προφίλ δικτύου, καθώς και χρόνοι πρώτης και τελευταίας σύνδεσης.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` και `...\Unmanaged\{GUID}`: δεδομένα συσχέτισης προφίλ, όπως διεύθυνση MAC gateway και επίθημα DNS.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: τοπικοί κοινόχρηστοι φάκελοι που δημοσιεύονται από τον υπολογιστή.

### Ιστορικό απομακρυσμένης πρόσβασης και κοινόχρηστων δικτύου

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: λίστα MRU εξερχόμενων συνδέσεων RDP (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: ιστορικό εξερχόμενων συνδέσεων RDP ανά υπολογιστή. Τα subkeys συνήθως αποθηκεύουν το `UsernameHint`, ενώ ο χρόνος `LastWrite` του κλειδιού αποτελεί χρήσιμο σημείο διερεύνησης.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: αντιστοιχισμένες μονάδες δικτύου, κοινόχρηστοι πόροι UNC και σημεία προσάρτησης αφαιρούμενων μέσων που συνδέονται με συγκεκριμένο χρήστη.

### Προγράμματα που εκκινούν αυτόματα και προγραμματισμένη persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` και `...\Tasks\{GUID}`: μεταδεδομένα προγραμματισμένων εργασιών. Αν υπάρχει εδώ μια εργασία, αλλά λείπει η τιμή `SD` από το `Tree\<TaskName>`, εξετάστε το ενδεχόμενο απόκρυψης ή αλλοίωσης εργασίας τύπου Tarrask και συσχετίστε την με το `C:\Windows\System32\Tasks\<TaskName>`.

### Αναζητήσεις, πληκτρολογημένες διαδρομές και MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: όροι αναζήτησης της Εξερεύνησης αρχείων.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: διαδρομές που πληκτρολογήθηκαν χειροκίνητα στην Εξερεύνηση αρχείων.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: οι τελευταίες 26 εντολές `Win + R`. Το `MRUList` διατηρεί τη σειρά τους.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: έγγραφα και φάκελοι που ανοίχτηκαν πρόσφατα.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: πρόσφατα αρχεία του Office.

### Παρακολούθηση δραστηριότητας χρήστη

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: ιστορικό εκτέλεσης μέσω GUI. Τα ονόματα των τιμών είναι κωδικοποιημένα με ROT13, ενώ τα δυαδικά δεδομένα περιλαμβάνουν μετρητές εκτέλεσης και τον χρόνο τελευταίας εκτέλεσης.<sup>[[1]](#references)</sup>
- Αντιμετωπίστε το `UserAssist` ως ισχυρό υποστηρικτικό στοιχείο, όχι ως οριστική απόδειξη: καταγράφει κυρίως εφαρμογές ή αρχεία `.lnk` που εκκινούνται μέσω της Εξερεύνησης αρχείων και μπορεί να παραλείψει εκτέλεση μέσω γραμμής εντολών ή υπηρεσίας. Στα Windows 10 και νεότερα, ορισμένες καταχωρίσεις δεν σημαίνουν απαραίτητα ότι η διεργασία εκτελέστηκε πλήρως.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` και `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: ίχνη εκτέλεσης σε σύγχρονα Windows 10/11, με απόδοση σε SID και χρόνο τελευταίας εκτέλεσης. Είναι ιδιαίτερα χρήσιμα για δυαδικά αρχεία που εκτελέστηκαν τοπικά, αλλά οι παλαιότερες καταχωρίσεις μπορεί να διαγράφονται γρήγορα και οι εκτελέσεις από κοινόχρηστους πόρους δικτύου ή αφαιρούμενα μέσα είναι λιγότερο αξιόπιστες.
- Για ευρύτερα τεχνουργήματα εκτέλεσης, όπως Prefetch, Amcache, ShimCache και SRUM, δείτε την κύρια [επισκόπηση της εγκληματολογικής ανάλυσης των Windows](./#programs-executed).

### Shellbags

- Τα Shellbags αποθηκεύονται τόσο στα `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` όσο και στα `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Οι καταχωρίσεις `NTUSER.DAT` είναι ιδιαίτερα χρήσιμες για περιήγηση σε UNC/δίκτυο, ενώ στα Windows Vista και νεότερα, τα τοπικά shellbags φακέλων και αφαιρούμενων μέσων αποθηκεύονται συνήθως στο `UsrClass.dat`.
- Μπορούν να δείξουν την ύπαρξη φακέλων, την περιήγηση σε αυτούς και τις προτιμήσεις προβολής τους, ακόμη κι αν ο φάκελος έχει διαγραφεί. Η πρόσβαση σε αρχεία αρχειοθέτησης μέσω της Εξερεύνησης αρχείων ή παρόμοιου προγράμματος μπορεί επίσης να αφήσει ίχνη shellbag.<sup>[[1]](#references)</sup>
- Δεν αποδεικνύουν όλα τα shellbags ότι η πρόσβαση στον φάκελο ήταν επιτυχής· διασταυρώστε τα με LNK, Jump Lists, χρονικές σημάνσεις ή αντιστοιχίσεις τόμων.
- Χρησιμοποιήστε το **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** ή το **SBECmd** για να τα αναλύσετε.

### Πληροφορίες USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: κύριο ευρετήριο συσκευών μαζικής αποθήκευσης USB (κατασκευαστής, προϊόν, αναθεώρηση, σειριακός αριθμός/στιγμιότυπο συσκευής).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: ευρύτερο ευρετήριο συσκευών USB, συμπεριλαμβανομένων συσκευών που δεν είναι αποθηκευτικά μέσα.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: σε πρόσφατες εκδόσεις Windows 10/11, είναι σημαντικό σημείο για χρονικές σημάνσεις κύκλου ζωής ανά συσκευή, όπως εγκατάσταση, πρώτη εγκατάσταση, τελευταία σύνδεση και τελευταία αποσύνδεση.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: αντιστοιχίζει τόμους και αναγνωριστικά συσκευών σε γράμματα μονάδων δίσκου / GUID τόμων. Μπορεί να διατηρηθεί μόνο η τελευταία αντιστοίχιση για ένα συγκεκριμένο γράμμα μονάδας δίσκου.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: χρήσιμο σημείο διερεύνησης για σειριακούς αριθμούς τόμων και μεταδεδομένα προηγούμενων μέσων.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: ιστορικό αλληλεπίδρασης συγκεκριμένου χρήστη με γράμματα μονάδων δίσκου και κοινόχρηστους πόρους.<sup>[[2]](#references)</sup>
- Τα σύγχρονα τηλέφωνα και tablet που συνδέονται μέσω MTP/PTP ενδέχεται **να μην** εμφανίζονται στο `USBSTOR`. Ελέγξτε επίσης τα `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` και `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Για να συσχετίσετε μια συσκευή με χρήστη, ακολουθήστε τα αναγνωριστικά συσκευής ή τόμου μέχρι τεχνουργήματα ανά χρήστη, όπως shellbags, LNK, Jump Lists, `RecentDocs` και `MountPoints2`.<sup>[[2]](#references)</sup>



## References

- [1] [Φύλλο αναφοράς ψηφιακής εγκληματολογίας Windows Registry 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [Ψηφιακή εγκληματολογία συσκευών USB στα Windows 10 και 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
