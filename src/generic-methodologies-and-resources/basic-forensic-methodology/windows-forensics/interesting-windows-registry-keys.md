# Ενδιαφέροντα Windows Registry Keys

{{#include ../../../banners/hacktricks-training.md}}

Τα Windows Registry hives είναι ένας από τους ταχύτερους τρόπους για να περάσεις από το _τι συνέβη?_ στο _ποιος user, πότε και από πού;_. Για live analysis προτίμησε `CurrentControlSet`; για offline hive analysis πρώτα εντόπισε ποιο `ControlSet00x` ήταν ενεργό αντί να κάνεις hardcode `ControlSet001`.

### Windows Version and Owner Info

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows edition/build, install time, registered owner, product name, και άλλα build metadata.
- `SYSTEM\Select`: αντιστοιχίζει τα `Current`, `Default` και `LastKnownGood` στις πραγματικές τιμές `ControlSet00x` που χρησιμοποιεί το σύστημα.

### Computer Name

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: τρέχον hostname.

### Time Zone Setting

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: ρυθμισμένη time zone και τιμές σχετικές με DST.

### Access Time Tracking

- `SYSTEM\CurrentControlSet\Control\FileSystem`: το `NtfsDisableLastAccessUpdate` δείχνει αν ενημερώνονται τα NTFS last-access timestamps.
- Για να το ενεργοποιήσεις, χρησιμοποίησε: `fsutil behavior set disablelastaccess 0`

### Shutdown Details

- `SYSTEM\CurrentControlSet\Control\Windows`: τελευταίος χρόνος shutdown.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: παλαιότερα συστήματα μπορεί επίσης να εκθέτουν counters shutdown.

### Network Configuration

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IPs της interface, DHCP leases, gateway και DNS data.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: network profile name/SSID μαζί με first και last connection times.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` και `...\Unmanaged\{GUID}`: profile correlation data όπως gateway MAC address και DNS suffix.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: local shared folders που έχουν δημοσιευτεί από τον host.

### Remote Access and Network Share History

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU list (`MRU0`..`MRU9`).
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: per-host outbound RDP history. Τα subkeys συνήθως αποθηκεύουν `UsernameHint`, και ο χρόνος `LastWrite` του key είναι χρήσιμο pivot.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: mapped network drives, UNC shares, και removable-media mount points συνδεδεμένα με συγκεκριμένο user.

### Programs that Start Automatically and Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` και `...\Tasks\{GUID}`: scheduled task metadata. Αν ένα task υπάρχει εδώ αλλά η τιμή `SD` λείπει από το `Tree\<TaskName>`, υποψιάσου hidden Tarrask-style task tampering και συσχέτισέ το με `C:\Windows\System32\Tasks\<TaskName>`.

### Searches, Typed Paths, and MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: όροι αναζήτησης του File Explorer.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: paths του Explorer που πληκτρολογήθηκαν χειροκίνητα.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: τα τελευταία 26 `Win + R` commands. Το `MRUList` διατηρεί τη σειρά τους.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: πρόσφατα ανοιγμένα documents και folders.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: πρόσφατα Office files.

### User Activity Tracking

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI-driven execution history. Τα value names είναι ROT13-encoded, και τα binary data περιλαμβάνουν counters εκτέλεσης και τελευταία ώρα εκτέλεσης.
- Αντιμετώπισε το `UserAssist` ως ισχυρό υποστηρικτικό evidence, όχι ως αυτόνομο verdict: κυρίως παρακολουθεί apps ή `.lnk` files που εκκινούνται μέσω Explorer και μπορεί να χάνει command-line ή service execution. Στα Windows 10+, ορισμένες εγγραφές δεν σημαίνουν απαραίτητα ότι το process εκτελέστηκε πλήρως.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` και `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: σύγχρονα Windows 10/11 execution traces με SID attribution και τελευταία ώρα εκτέλεσης. Είναι ιδιαίτερα χρήσιμα για locally executed binaries, αλλά παλαιότερες εγγραφές μπορεί να λήξουν γρήγορα και οι εκτελέσεις από network shares/removable media είναι λιγότερο αξιόπιστες.
- Για ευρύτερα execution artifacts όπως Prefetch, Amcache, ShimCache και SRUM, δες την κύρια [Windows forensics overview](README.md#programs-executed).

### Shellbags

- Τα Shellbags αποθηκεύονται τόσο στα `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` όσο και στα `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.
- Τα `NTUSER.DAT` entries είναι ιδιαίτερα χρήσιμα για UNC/network browsing, ενώ το `UsrClass.dat` είναι εκεί όπου τα Windows Vista+ συνήθως αποθηκεύουν local/removable-folder shellbags.
- Μπορούν να δείξουν folder existence, traversal και folder-view preferences ακόμα και αφού το folder διαγραφεί. Explorer-like access σε archive files μπορεί επίσης να αφήσει shellbag traces.
- Όχι κάθε shellbag αποδεικνύει επιτυχημένο folder access, οπότε επιβεβαίωσέ το με LNKs, Jump Lists, timestamps ή volume mappings.
- Χρησιμοποίησε **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** ή **SBECmd** για να τα parse-άρεις.

### USB Information

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: βασικό inventory USB mass-storage devices (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: ευρύτερο inventory USB devices, συμπεριλαμβανομένων non-storage devices.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: σε πρόσφατα Windows 10/11 builds αυτό είναι high-value σημείο για per-device lifecycle timestamps όπως install, first install, last arrival και last removal.
- `HKLM\SYSTEM\MountedDevices`: αντιστοιχίζει volumes και device identifiers σε drive letters / volume GUIDs. Μπορεί να επιβιώσει μόνο η τελευταία αντιστοίχιση για ένα given drive letter.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: χρήσιμο pivot για volume serial numbers και previous media metadata.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: user-specific ιστορικό αλληλεπίδρασης με drive letters και shares.
- Σύγχρονα phones και tablets που συνδέονται μέσω MTP/PTP μπορεί να **μην** εμφανίζονται κάτω από το `USBSTOR`. Έλεγξε επίσης τα `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` και `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.
- Για να συνδέσεις μια συσκευή με έναν user, κάνε pivot από device ή volume identifiers σε per-user artifacts όπως shellbags, LNKs, Jump Lists, `RecentDocs` και `MountPoints2`.



## References

- [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
