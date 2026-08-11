# Ενδιαφέροντα Windows Registry Keys

{{#include ../../../banners/hacktricks-training.md}}

Τα Windows Registry hives είναι ένας από τους ταχύτερους τρόπους για να μεταβείτε από το _τι συνέβη;_ στο _ποιος χρήστης, πότε και από πού;_. Για live analysis προτιμήστε το `CurrentControlSet`. Για offline hive analysis, πρώτα προσδιορίστε ποιο `ControlSet00x` ήταν ενεργό αντί να χρησιμοποιείτε hardcoded το `ControlSet001`.

### Πληροφορίες έκδοσης Windows και κατόχου

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: έκδοση/build των Windows, χρόνος εγκατάστασης, registered owner, όνομα προϊόντος και άλλα build metadata.
- `SYSTEM\Select`: αντιστοιχίζει τα `Current`, `Default` και `LastKnownGood` στις πραγματικές τιμές `ControlSet00x` που χρησιμοποιούνται από το σύστημα.

### Όνομα υπολογιστή

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: τρέχον hostname.

### Ρύθμιση ζώνης ώρας

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: ρυθμισμένη ζώνη ώρας και τιμές σχετικές με DST.

### Παρακολούθηση χρόνου πρόσβασης

- `SYSTEM\CurrentControlSet\Control\FileSystem`: το `NtfsDisableLastAccessUpdate` υποδεικνύει αν ενημερώνονται τα timestamps τελευταίας πρόσβασης του NTFS.
- Για να το ενεργοποιήσετε, χρησιμοποιήστε: `fsutil behavior set disablelastaccess 0`

### Λεπτομέρειες τερματισμού

- `SYSTEM\CurrentControlSet\Control\Windows`: χρόνος τελευταίου τερματισμού.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: παλαιότερα συστήματα ενδέχεται επίσης να εκθέτουν counters τερματισμού.

### Ρυθμίσεις δικτύου

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IPs διεπαφών, DHCP leases, gateway και DNS data.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: όνομα network profile/SSID, καθώς και χρόνοι πρώτης και τελευταίας σύνδεσης.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` και `...\Unmanaged\{GUID}`: δεδομένα συσχέτισης profile, όπως MAC address του gateway και DNS suffix.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: local shared folders που δημοσιεύονται από το host.

### Ιστορικό απομακρυσμένης πρόσβασης και network shares

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU list (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: outbound RDP history ανά host. Τα subkeys συνήθως αποθηκεύουν το `UsernameHint`, ενώ ο χρόνος `LastWrite` του key είναι χρήσιμο pivot.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: mapped network drives, UNC shares και removable-media mount points που συνδέονται με συγκεκριμένο χρήστη.

### Προγράμματα που ξεκινούν αυτόματα και scheduled persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` και `...\Tasks\{GUID}`: metadata scheduled tasks. Αν υπάρχει task εδώ αλλά λείπει η τιμή `SD` από το `Tree\<TaskName>`, υποψιαστείτε hidden Tarrask-style task tampering και συσχετίστε το με το `C:\Windows\System32\Tasks\<TaskName>`.

### Αναζητήσεις, typed paths και MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: όροι αναζήτησης του File Explorer.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: paths του Explorer που πληκτρολογήθηκαν χειροκίνητα.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: οι τελευταίες 26 εντολές `Win + R`. Το `MRUList` διατηρεί τη σειρά τους.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: έγγραφα και φάκελοι που ανοίχτηκαν πρόσφατα.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: πρόσφατα αρχεία του Office.

### Παρακολούθηση δραστηριότητας χρήστη

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: ιστορικό εκτέλεσης μέσω GUI. Τα ονόματα των τιμών είναι κωδικοποιημένα με ROT13 και τα binary data περιλαμβάνουν counters εκτέλεσης και χρόνο τελευταίας εκτέλεσης.<sup>[[1]](#references)</sup>
- Αντιμετωπίστε το `UserAssist` ως ισχυρό supporting evidence και όχι ως standalone verdict: παρακολουθεί κυρίως apps ή `.lnk` files που εκκινούν μέσω Explorer και μπορεί να παραλείψει command-line ή service execution. Στα Windows 10+, ορισμένες entries δεν σημαίνουν απαραίτητα ότι η διεργασία εκτελέστηκε πλήρως.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` και `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: σύγχρονα execution traces των Windows 10/11 με SID attribution και χρόνο τελευταίας εκτέλεσης. Είναι ιδιαίτερα χρήσιμα για binaries που εκτελούνται τοπικά, αλλά παλαιότερες entries μπορεί να διαγράφονται γρήγορα και οι εκτελέσεις από network shares/removable media είναι λιγότερο αξιόπιστες.
- Για ευρύτερα execution artifacts, όπως Prefetch, Amcache, ShimCache και SRUM, δείτε το κύριο [Windows forensics overview](README.md#programs-executed).

### Shellbags

- Τα Shellbags αποθηκεύονται τόσο στα `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` όσο και στα `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Οι entries του `NTUSER.DAT` είναι ιδιαίτερα χρήσιμες για UNC/network browsing, ενώ το `UsrClass.dat` είναι το σημείο όπου τα Windows Vista+ αποθηκεύουν συνήθως local/removable-folder shellbags.
- Μπορούν να δείξουν ύπαρξη φακέλων, traversal και προτιμήσεις προβολής φακέλων ακόμη και μετά τη διαγραφή του φακέλου. Πρόσβαση τύπου Explorer σε archive files μπορεί επίσης να αφήσει shellbag traces.<sup>[[1]](#references)</sup>
- Δεν αποδεικνύει κάθε shellbag επιτυχή πρόσβαση σε φάκελο, επομένως συσχετίστε τα με LNKs, Jump Lists, timestamps ή volume mappings.
- Χρησιμοποιήστε τα **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** ή **SBECmd** για parsing.

### Πληροφορίες USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: κύριος κατάλογος USB mass-storage devices (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: ευρύτερος κατάλογος USB devices, συμπεριλαμβανομένων non-storage devices.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: σε πρόσφατα Windows 10/11 builds, αποτελεί σημείο υψηλής αξίας για per-device lifecycle timestamps, όπως install, first install, last arrival και last removal.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: αντιστοιχίζει volumes και device identifiers σε drive letters / volume GUIDs. Μπορεί να διατηρηθεί μόνο το τελευταίο mapping για ένα συγκεκριμένο drive letter.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: χρήσιμο pivot για volume serial numbers και previous media metadata.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: user-specific drive-letter και share interaction history.<sup>[[2]](#references)</sup>
- Τα σύγχρονα phones και tablets που συνδέονται μέσω MTP/PTP ενδέχεται **να μην** εμφανίζονται στο `USBSTOR`. Ελέγξτε επίσης τα `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` και `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Για να συνδέσετε μια συσκευή με έναν χρήστη, κάντε pivot από device ή volume identifiers σε per-user artifacts, όπως shellbags, LNKs, Jump Lists, `RecentDocs` και `MountPoints2`.<sup>[[2]](#references)</sup>

## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
