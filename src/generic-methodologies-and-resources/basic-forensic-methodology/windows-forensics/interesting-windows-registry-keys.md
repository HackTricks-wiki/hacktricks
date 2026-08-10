# Ενδιαφέροντα Windows Registry Keys

Τα Windows Registry hives είναι ένας από τους ταχύτερους τρόπους για να μεταβείτε από το _τι συνέβη;_ στο _ποιος χρήστης, πότε και από πού;_. Για live analysis προτιμήστε το `CurrentControlSet`. Για offline hive analysis, προσδιορίστε πρώτα ποιο `ControlSet00x` ήταν ενεργό αντί να θεωρείτε δεδομένο το `ControlSet001`.

### Πληροφορίες έκδοσης Windows και κατόχου

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: έκδοση/build των Windows, χρόνος εγκατάστασης, registered owner, όνομα προϊόντος και άλλα build metadata.
- `SYSTEM\Select`: αντιστοιχίζει τα `Current`, `Default` και `LastKnownGood` στις πραγματικές τιμές `ControlSet00x` που χρησιμοποιούνται από το σύστημα.

### Όνομα υπολογιστή

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: τρέχον hostname.

### Ρύθμιση ζώνης ώρας

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: ρυθμισμένη ζώνη ώρας και τιμές που σχετίζονται με το DST.

### Παρακολούθηση χρόνου πρόσβασης

- `SYSTEM\CurrentControlSet\Control\FileSystem`: το `NtfsDisableLastAccessUpdate` υποδεικνύει αν ενημερώνονται τα NTFS last-access timestamps.
- Για να το ενεργοποιήσετε, χρησιμοποιήστε: `fsutil behavior set disablelastaccess 0`

### Λεπτομέρειες τερματισμού

- `SYSTEM\CurrentControlSet\Control\Windows`: χρόνος τελευταίου τερματισμού.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: παλαιότερα συστήματα ενδέχεται επίσης να εκθέτουν counters τερματισμού.

### Network Configuration

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IPs διεπαφών, DHCP leases, δεδομένα gateway και DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: όνομα network profile/SSID, καθώς και χρόνοι πρώτης και τελευταίας σύνδεσης.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` και `...\Unmanaged\{GUID}`: δεδομένα συσχέτισης profile, όπως gateway MAC address και DNS suffix.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: local shared folders που δημοσιεύονται από το host.

### Remote Access και ιστορικό Network Share

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU list (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: outbound RDP history ανά host. Τα subkeys συνήθως αποθηκεύουν το `UsernameHint`, ενώ ο χρόνος `LastWrite` του key αποτελεί χρήσιμο pivot.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: mapped network drives, UNC shares και removable-media mount points που συνδέονται με συγκεκριμένο χρήστη.

### Προγράμματα που ξεκινούν αυτόματα και Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` και `...\Tasks\{GUID}`: scheduled task metadata. Αν υπάρχει task εδώ, αλλά λείπει η τιμή `SD` από το `Tree\<TaskName>`, εξετάστε το ενδεχόμενο hidden Tarrask-style task tampering και συσχετίστε το με το `C:\Windows\System32\Tasks\<TaskName>`.

### Αναζητήσεις, Typed Paths και MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: όροι αναζήτησης του File Explorer.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: paths του Explorer που πληκτρολογήθηκαν χειροκίνητα.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: οι τελευταίες 26 εντολές `Win + R`. Το `MRUList` διατηρεί τη σειρά τους.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: έγγραφα και φάκελοι που άνοιξαν πρόσφατα.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: πρόσφατα αρχεία του Office.

### Παρακολούθηση δραστηριότητας χρήστη

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: ιστορικό εκτέλεσης μέσω GUI. Τα value names είναι κωδικοποιημένα με ROT13 και τα binary data περιλαμβάνουν run counters και χρόνο τελευταίας εκτέλεσης.<sup>[[1]](#references)</sup>
- Αντιμετωπίστε το `UserAssist` ως ισχυρό supporting evidence και όχι ως standalone verdict: παρακολουθεί κυρίως apps ή αρχεία `.lnk` που εκκινήθηκαν μέσω του Explorer και μπορεί να παραλείψει command-line ή service execution. Σε Windows 10+, ορισμένα entries δεν σημαίνουν απαραίτητα ότι το process εκτελέστηκε πλήρως.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` και `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: modern Windows 10/11 execution traces με απόδοση σε SID και χρόνο τελευταίας εκτέλεσης. Είναι ιδιαίτερα χρήσιμα για locally executed binaries, αλλά παλαιότερα entries μπορεί να διαγραφούν γρήγορα και οι εκτελέσεις από network shares/removable media είναι λιγότερο αξιόπιστες.
- Για ευρύτερα execution artifacts, όπως Prefetch, Amcache, ShimCache και SRUM, δείτε το κύριο [Windows forensics overview](README.md#programs-executed).

### Shellbags

- Τα Shellbags αποθηκεύονται τόσο στα `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` όσο και στα `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Τα entries του `NTUSER.DAT` είναι ιδιαίτερα χρήσιμα για UNC/network browsing, ενώ το `UsrClass.dat` είναι το σημείο όπου τα Windows Vista+ αποθηκεύουν συνήθως local/removable-folder shellbags.
- Μπορούν να δείξουν την ύπαρξη και την περιήγηση σε φακέλους, καθώς και τις προτιμήσεις προβολής φακέλων, ακόμη και μετά τη διαγραφή του φακέλου. Πρόσβαση σε archive files μέσω Explorer-like ενεργειών μπορεί επίσης να αφήσει shellbag traces.<sup>[[1]](#references)</sup>
- Δεν αποδεικνύει κάθε shellbag επιτυχή πρόσβαση σε φάκελο, επομένως επιβεβαιώστε με LNKs, Jump Lists, timestamps ή volume mappings.
- Χρησιμοποιήστε τα **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** ή **SBECmd** για την ανάλυσή τους.

### Πληροφορίες USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: κύριο inventory συσκευών USB mass-storage (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: ευρύτερο USB device inventory, συμπεριλαμβανομένων non-storage συσκευών.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: σε πρόσφατα Windows 10/11 builds, αποτελεί πολύτιμο σημείο για per-device lifecycle timestamps, όπως install, first install, last arrival και last removal.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: αντιστοιχίζει volumes και device identifiers σε drive letters / volume GUIDs. Μπορεί να διατηρηθεί μόνο το τελευταίο mapping για ένα δεδομένο drive letter.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: χρήσιμο pivot για volume serial numbers και previous media metadata.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: user-specific ιστορικό αλληλεπίδρασης με drive letters και shares.<sup>[[2]](#references)</sup>
- Τα modern phones και tablets που συνδέονται μέσω MTP/PTP ενδέχεται **να μην** εμφανίζονται στο `USBSTOR`. Ελέγξτε επίσης τα `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` και `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Για να συνδέσετε μια συσκευή με έναν χρήστη, κάντε pivot από τα device ή volume identifiers σε per-user artifacts, όπως shellbags, LNKs, Jump Lists, `RecentDocs` και `MountPoints2`.<sup>[[2]](#references)</sup>

## References

- [1] [Cheat Sheet Windows Registry Forensics 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [Forensics συσκευών USB σε Windows 10 και 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
