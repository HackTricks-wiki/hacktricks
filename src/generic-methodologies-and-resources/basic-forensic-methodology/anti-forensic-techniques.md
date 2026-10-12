# Τεχνικές Anti-Forensic

{{#include ../../banners/hacktricks-training.md}}

## Χρονικές σημάνσεις

Ένας εισβολέας μπορεί να ενδιαφέρεται να **αλλάξει τις χρονικές σημάνσεις των αρχείων** για να αποφύγει τον εντοπισμό.\
Οι χρονικές σημάνσεις μπορούν να βρεθούν στο MFT, στα attributes `$STANDARD_INFORMATION` \_\_ και \_\_ `$FILE_NAME`.

Και τα δύο attributes έχουν 4 χρονικές σημάνσεις: **Τροποποίηση**, **πρόσβαση**, **δημιουργία** και **τροποποίηση εγγραφής MFT** (MACE ή MACB).

Ο **Windows Explorer** και άλλα εργαλεία εμφανίζουν τις πληροφορίες από το **`$STANDARD_INFORMATION`**.

### TimeStomp - Εργαλείο Anti-Forensic

Αυτό το εργαλείο **τροποποιεί** τις πληροφορίες χρονικής σήμανσης μέσα στο **`$STANDARD_INFORMATION`**, **αλλά όχι** τις πληροφορίες μέσα στο **`$FILE_NAME`**. Επομένως, είναι δυνατό να **εντοπιστεί** **ύποπτη** **δραστηριότητα**.

### Usnjrnl

Το **USN Journal** (Update Sequence Number Journal) είναι μια λειτουργία του NTFS (Windows NT file system) που παρακολουθεί τις αλλαγές στον τόμο. Το εργαλείο [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) επιτρέπει την εξέταση αυτών των αλλαγών.

![TimeStomp - Εργαλείο Anti-forensic - Usnjrnl: Το USN Journal (Update Sequence Number Journal) είναι μια λειτουργία του NTFS (Windows NT file system) που παρακολουθεί τις αλλαγές στον τόμο. Το...](<../../images/image (801).png>)

Η προηγούμενη εικόνα δείχνει την **έξοδο** του **εργαλείου**, όπου παρατηρείται ότι **πραγματοποιήθηκαν ορισμένες αλλαγές** στο αρχείο.

### $LogFile

**Όλες οι αλλαγές μεταδεδομένων σε ένα file system καταγράφονται** μέσω μιας διαδικασίας γνωστής ως [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Τα καταγεγραμμένα μεταδεδομένα διατηρούνται σε ένα αρχείο με όνομα `**$LogFile**`, το οποίο βρίσκεται στον ριζικό κατάλογο ενός NTFS file system. Εργαλεία όπως το [LogFileParser](https://github.com/jschicht/LogFileParser) μπορούν να χρησιμοποιηθούν για την ανάλυση αυτού του αρχείου και τον εντοπισμό αλλαγών.

![Usnjrnl - $LogFile: Όλες οι αλλαγές μεταδεδομένων σε ένα file system καταγράφονται μέσω μιας διαδικασίας γνωστής ως write-ahead logging. Τα καταγεγραμμένα μεταδεδομένα διατηρούνται σε ένα αρχείο με όνομα $LogFile , το οποίο βρίσκεται στον ριζικό...](<../../images/image (137).png>)

Και πάλι, στην έξοδο του εργαλείου είναι δυνατό να δούμε ότι **πραγματοποιήθηκαν ορισμένες αλλαγές**.

Με το ίδιο εργαλείο είναι δυνατό να εντοπιστεί **πότε τροποποιήθηκαν οι χρονικές σημάνσεις**:

![Usnjrnl - $LogFile: Με το ίδιο εργαλείο είναι δυνατό να εντοπιστεί πότε τροποποιήθηκαν οι χρονικές σημάνσεις](<../../images/image (1089).png>)

- CTIME: Ώρα δημιουργίας του αρχείου
- ATIME: Ώρα τροποποίησης του αρχείου
- MTIME: Τροποποίηση εγγραφής MFT του αρχείου
- RTIME: Ώρα πρόσβασης στο αρχείο

### Σύγκριση `$STANDARD_INFORMATION` και `$FILE_NAME`

Ένας άλλος τρόπος εντοπισμού ύποπτων τροποποιημένων αρχείων είναι η σύγκριση των χρονικών σημάνσεων και στα δύο attributes, αναζητώντας **ασυμφωνίες**.

### Νανοδευτερόλεπτα

Οι χρονικές σημάνσεις του **NTFS** έχουν **ακρίβεια** **100 νανοδευτερολέπτων**. Επομένως, η εύρεση αρχείων με χρονικές σημάνσεις όπως 2010-10-10 10:10:**00.000:0000 είναι πολύ ύποπτη**.

### SetMace - Εργαλείο Anti-Forensic

Αυτό το εργαλείο μπορεί να τροποποιήσει και τα δύο attributes, `$STARNDAR_INFORMATION` και `$FILE_NAME`. Ωστόσο, από τα Windows Vista και μετά, απαιτείται ζωντανό OS για την τροποποίηση αυτών των πληροφοριών.

## Απόκρυψη δεδομένων

Το NFTS χρησιμοποιεί clusters και ένα ελάχιστο μέγεθος πληροφοριών. Αυτό σημαίνει ότι, αν ένα αρχείο καταλαμβάνει ενάμιση cluster, **το υπόλοιπο μισό δεν θα χρησιμοποιηθεί ποτέ** μέχρι να διαγραφεί το αρχείο. Έτσι, είναι δυνατό να **κρυφτούν δεδομένα σε αυτόν τον slack space**.

Υπάρχουν εργαλεία όπως το slacker που επιτρέπουν την απόκρυψη δεδομένων σε αυτόν τον «κρυφό» χώρο. Ωστόσο, η ανάλυση των `$logfile` και `$usnjrnl` μπορεί να δείξει ότι προστέθηκαν δεδομένα:

![SetMace - Εργαλείο Anti-forensic - Απόκρυψη δεδομένων: Υπάρχουν εργαλεία όπως το slacker που επιτρέπουν την απόκρυψη δεδομένων σε αυτόν τον «κρυφό» χώρο. Ωστόσο, η ανάλυση των $logfile και $usnjrnl μπορεί να δείξει ότι...](<../../images/image (1060).png>)

Στη συνέχεια, είναι δυνατό να ανακτηθεί ο slack space με εργαλεία όπως το FTK Imager. Σημειώστε ότι τέτοιου είδους εργαλεία μπορούν να αποθηκεύσουν το περιεχόμενο με συσκότιση ή ακόμη και κρυπτογραφημένο.

## UsbKill

Αυτό είναι ένα εργαλείο που **απενεργοποιεί τον υπολογιστή αν εντοπιστεί οποιαδήποτε αλλαγή στις θύρες USB**.\
Ένας τρόπος εντοπισμού του είναι να επιθεωρήσετε τις διεργασίες που εκτελούνται και να **ελέγξετε κάθε script Python που εκτελείται**.

## Live Linux Distributions

Αυτές οι διανομές **εκτελούνται στη μνήμη RAM**. Ο μόνος τρόπος εντοπισμού τους είναι **αν το NTFS file system έχει προσαρτηθεί με δικαιώματα εγγραφής**. Αν έχει προσαρτηθεί μόνο με δικαιώματα ανάγνωσης, δεν θα είναι δυνατός ο εντοπισμός της εισβολής.

## Ασφαλής διαγραφή

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Καθυστερημένη αυτοδιαγραφή στα Windows

Μια εικόνα Windows που εκτελείται μπορεί να είναι κλειδωμένη όσο η διεργασία της είναι ενεργή. Μια διεργασία μπορεί να αναθέσει τη διαγραφή σε ένα θυγατρικό `cmd.exe`, να χρησιμοποιήσει το `choice` ως χρονόμετρο και να τερματιστεί προτού το shell εκτελέσει το `del`. Η καθυστέρηση επιτρέπει στην αρχική διεργασία να αποδεσμεύσει το handle της εικόνας της· είναι απαραίτητο να μπουν εισαγωγικά γύρω από την πλήρη διαδρομή όταν αυτή περιέχει κενά.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Όταν αυτή η συμβολοσειρά παρέχεται απευθείας ως όρισμα στο `cmd.exe` και δεν πληκτρολογείται σε άλλη διαδραστική προτροπή `cmd`, χρησιμοποιήστε `&` αντί για `^&` και `>nul` αντί για `^>nul`. Αυτό αφαιρεί την καταχώριση καταλόγου· **δεν αποτελεί ασφαλή διαγραφή** και δεν αφαιρεί ίχνη εκτέλεσης, εργασιών, ημερολογίου συστήματος αρχείων ή άλλα εγκληματολογικά ίχνη. Αναζητήστε βραχύβιες διεργασίες-παιδιά `cmd.exe` των οποίων η γραμμή εντολών συνδυάζει `choice /T`, `Del` και τη διαδρομή της εικόνας της γονικής διεργασίας.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Ρυθμίσεις Windows

Είναι δυνατό να απενεργοποιηθούν διάφορες μέθοδοι καταγραφής των Windows, ώστε να δυσκολέψει πολύ η εγκληματολογική διερεύνηση.

### Απενεργοποίηση χρονικών σημάνσεων - UserAssist

Πρόκειται για ένα κλειδί μητρώου που διατηρεί τις ημερομηνίες και τις ώρες εκτέλεσης κάθε εκτελέσιμου αρχείου από τον χρήστη.

Για να απενεργοποιήσετε το UserAssist, απαιτούνται δύο βήματα:

1. Ορίστε και τα δύο κλειδιά μητρώου, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` και `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, σε μηδέν, ώστε να δηλώσετε ότι θέλετε να απενεργοποιηθεί το UserAssist.
2. Διαγράψτε τα δευτερεύοντα κλειδιά μητρώου που έχουν μορφή `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Απενεργοποίηση χρονικών σημάνσεων - Prefetch

Αυτό αποθηκεύει πληροφορίες για τις εφαρμογές που εκτελούνται, με στόχο τη βελτίωση της απόδοσης του συστήματος Windows. Ωστόσο, αυτές οι πληροφορίες μπορεί να είναι χρήσιμες και για εγκληματολογικές αναλύσεις.

- Εκτελέστε το `regedit`
- Επιλέξτε τη διαδρομή αρχείου `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Κάντε δεξί κλικ στα `EnablePrefetcher` και `EnableSuperfetch`
- Επιλέξτε «Τροποποίηση» για καθένα από αυτά, ώστε να αλλάξετε την τιμή από 1 (ή 3) σε 0
- Κάντε επανεκκίνηση

### Απενεργοποίηση χρονικών σημάνσεων - Ώρα τελευταίας πρόσβασης

Κάθε φορά που ανοίγεται ένας φάκελος σε τόμο NTFS σε διακομιστή Windows NT, το σύστημα **ενημερώνει ένα πεδίο χρονικής σήμανσης σε κάθε φάκελο που εμφανίζεται στη λίστα**, το οποίο ονομάζεται ώρα τελευταίας πρόσβασης. Σε έναν τόμο NTFS με έντονη χρήση, αυτό μπορεί να επηρεάσει την απόδοση.

1. Ανοίξτε τον Επεξεργαστή Μητρώου (Regedit.exe).
2. Μεταβείτε στο `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Αναζητήστε το `NtfsDisableLastAccessUpdate`. Αν δεν υπάρχει, προσθέστε αυτό το DWORD και ορίστε την τιμή του σε 1, για να απενεργοποιήσετε τη διαδικασία.
4. Κλείστε τον Επεξεργαστή Μητρώου και επανεκκινήστε τον διακομιστή.

### Διαγραφή ιστορικού USB

Όλες οι **καταχωρίσεις συσκευών USB** αποθηκεύονται στο Μητρώο των Windows, κάτω από το κλειδί μητρώου **USBSTOR**, το οποίο περιέχει δευτερεύοντα κλειδιά που δημιουργούνται κάθε φορά που συνδέετε μια συσκευή USB στον υπολογιστή ή στον φορητό υπολογιστή σας. Μπορείτε να βρείτε αυτό το κλειδί εδώ: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Διαγράφοντάς το**, θα διαγράψετε το ιστορικό USB.\
Μπορείτε επίσης να χρησιμοποιήσετε το εργαλείο [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), για να βεβαιωθείτε ότι τα έχετε διαγράψει (και για να τα διαγράψετε).

Ένα άλλο αρχείο που αποθηκεύει πληροφορίες για τις συσκευές USB είναι το `setupapi.dev.log` μέσα στο `C:\Windows\INF`. Θα πρέπει να διαγραφεί και αυτό.

### Απενεργοποίηση Shadow Copies

**Εμφανίστε** τις Shadow Copies με την εντολή `vssadmin list shadowstorage`\
**Διαγράψτε** τις εκτελώντας την εντολή `vssadmin delete shadow`

Μπορείτε επίσης να τις διαγράψετε μέσω γραφικού περιβάλλοντος, ακολουθώντας τα βήματα που περιγράφονται στο [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Για να απενεργοποιήσετε τις Shadow Copies, ακολουθήστε [τα βήματα από εδώ](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Ανοίξτε την εφαρμογή Services πληκτρολογώντας "services" στο πλαίσιο αναζήτησης κειμένου, αφού κάνετε κλικ στο κουμπί Έναρξη των Windows.
2. Από τη λίστα, βρείτε το "Volume Shadow Copy", επιλέξτε το και, στη συνέχεια, ανοίξτε τις Ιδιότητες κάνοντας δεξί κλικ.
3. Επιλέξτε «Disabled» από το αναπτυσσόμενο μενού "Startup type" και επιβεβαιώστε την αλλαγή κάνοντας κλικ στα Apply και OK.

Είναι επίσης δυνατό να τροποποιήσετε στο μητρώο τη ρύθμιση για τα αρχεία που θα αντιγράφονται στη Shadow Copy: `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Αντικατάσταση διαγραμμένων αρχείων

- Μπορείτε να χρησιμοποιήσετε ένα **εργαλείο των Windows**: `cipher /w:C`. Αυτό θα υποδείξει στο cipher να αφαιρέσει όλα τα δεδομένα από τον διαθέσιμο αχρησιμοποίητο χώρο του δίσκου C.
- Μπορείτε επίσης να χρησιμοποιήσετε εργαλεία όπως το [**Eraser**](https://eraser.heidi.ie)

### Διαγραφή αρχείων καταγραφής συμβάντων των Windows

- Windows + R --> eventvwr.msc --> Αναπτύξτε το "Windows Logs" --> Κάντε δεξί κλικ σε κάθε κατηγορία και επιλέξτε "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Απενεργοποίηση αρχείων καταγραφής συμβάντων των Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Στην ενότητα services, απενεργοποιήστε την υπηρεσία "Windows Event Log"
- `WEvtUtil.exec clear-log` ή `WEvtUtil.exe cl`

### Απενεργοποίηση του $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Προηγμένη καταγραφή και αλλοίωση ιχνών (2023-2025)

### Καταγραφή PowerShell ScriptBlock/Module

Οι πρόσφατες εκδόσεις των Windows 10/11 και του Windows Server διατηρούν **εκτενή εγκληματολογικά τεχνουργήματα του PowerShell** στο
`Microsoft-Windows-PowerShell/Operational` (συμβάντα 4104/4105/4106).  
Οι επιτιθέμενοι μπορούν να τα απενεργοποιήσουν ή να τα διαγράψουν επιτόπου:

```powershell
# Turn OFF ScriptBlock & Module logging (registry persistence)
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" \
                 -Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" \
                 -Name EnableModuleLogging -Value 0 -PropertyType DWord -Force

# In-memory wipe of recent PowerShell logs
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
  Remove-WinEvent               # requires admin & Win11 23H2+
```

Οι defenders θα πρέπει να παρακολουθούν για αλλαγές σε αυτά τα registry keys και για μαζική διαγραφή συμβάντων του PowerShell.

### ETW (Event Tracing for Windows) Patch

Τα προϊόντα endpoint security βασίζονται σε μεγάλο βαθμό στο ETW. Μια δημοφιλής μέθοδος evasion του 2024 είναι το patch των `ntdll!EtwEventWrite`/`EtwEventWriteFull` στη μνήμη, ώστε κάθε κλήση ETW να επιστρέφει `STATUS_SUCCESS` χωρίς να εκπέμπεται το συμβάν:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Τα δημόσια PoCs (π.χ. `EtwTiSwallow`) υλοποιούν την ίδια primitive σε PowerShell ή C++.  
Επειδή το patch είναι **τοπικό στη διεργασία**, τα EDR που εκτελούνται μέσα σε άλλες διεργασίες μπορεί να μην το εντοπίσουν.<sup>[[5]](#references)</sup>
Ανίχνευση: σύγκριση του `ntdll` στη μνήμη με αυτό στον δίσκο ή εγκατάσταση hook πριν από τη λειτουργία user-mode.

### Αναβίωση των Alternate Data Streams (ADS)

Σε καμπάνιες malware του 2023 (π.χ. loaders της **FIN12**) έχει παρατηρηθεί η τοποθέτηση binaries δεύτερου σταδίου μέσα σε ADS, ώστε να παραμένουν εκτός οπτικού πεδίου των παραδοσιακών scanners:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Enumerate τα streams με `dir /R`, `Get-Item -Stream *` ή το Sysinternals `streams64.exe`.
Η αντιγραφή του host file σε FAT/exFAT ή μέσω SMB αφαιρεί το hidden stream και μπορεί να χρησιμοποιηθεί
από τους ερευνητές για την ανάκτηση του payload.

### BYOVD & “AuKill” (2023)

Το Bring-Your-Own-Vulnerable-Driver χρησιμοποιείται πλέον συστηματικά για **anti-forensics** σε εισβολές ransomware.
Το open-source εργαλείο **AuKill** φορτώνει έναν υπογεγραμμένο αλλά ευάλωτο driver (`procexp152.sys`) για να
αναστείλει ή να τερματίσει τα EDR και τους forensic sensors **πριν από την κρυπτογράφηση και την καταστροφή των logs**:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Το driver αφαιρείται στη συνέχεια, αφήνοντας ελάχιστα τεχνουργήματα.<sup>[[1]](#references)</sup>  
Μετριασμός: ενεργοποιήστε τη λίστα αποκλεισμού ευάλωτων driver της Microsoft (HVCI/SAC) και ειδοποιήστε για δημιουργία υπηρεσιών πυρήνα από διαδρομές εγγράψιμες από χρήστες.

---

## Linux Anti-Forensics: Self-Patching και Cloud C2 (2023–2025)

### Αυτοεπιδιόρθωση παραβιασμένων υπηρεσιών για μείωση του εντοπισμού (Linux)
Οι αντίπαλοι ολοένα και συχνότερα «αυτοεπιδιορθώνουν» μια υπηρεσία αμέσως μετά την εκμετάλλευσή της, τόσο για να αποτρέψουν την εκ νέου εκμετάλλευσή της όσο και για να καταστείλουν τον εντοπισμό που βασίζεται σε ευπάθειες. Η ιδέα είναι να αντικατασταθούν τα ευάλωτα στοιχεία με τις πιο πρόσφατες νόμιμες upstream εκδόσεις των binaries/JAR, ώστε οι σαρωτές να αναφέρουν ότι ο host έχει ενημερωθεί, ενώ η persistence και το C2 παραμένουν.<sup>[[3]](#references)</sup>

Παράδειγμα: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Μετά το post-exploitation, οι επιτιθέμενοι έλαβαν νόμιμα JAR από το Maven Central (repo1.maven.org), διέγραψαν τα ευάλωτα JAR από την εγκατάσταση του ActiveMQ και επανεκκίνησαν τον broker.
- Έτσι έκλεισε η αρχική RCE, ενώ διατηρήθηκαν άλλα footholds (cron, αλλαγές στις ρυθμίσεις SSH, ξεχωριστά C2 implants).

Λειτουργικό παράδειγμα (ενδεικτικό)
```bash
# ActiveMQ install root (adjust as needed)
AMQ_DIR=/opt/activemq
cd "$AMQ_DIR"/lib

# Fetch patched JARs from Maven Central (versions as appropriate)
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-client/5.18.3/activemq-client-5.18.3.jar
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-openwire-legacy/5.18.3/activemq-openwire-legacy-5.18.3.jar

# Remove vulnerable files and ensure the service uses the patched ones
rm -f activemq-client-5.18.2.jar activemq-openwire-legacy-5.18.2.jar || true
ln -sf activemq-client-5.18.3.jar activemq-client.jar
ln -sf activemq-openwire-legacy-5.18.3.jar activemq-openwire-legacy.jar

# Apply changes without removing persistence
systemctl restart activemq || service activemq restart
```

Συμβουλές forensics/hunting
- Ελέγξτε τους καταλόγους υπηρεσιών για μη προγραμματισμένες αντικαταστάσεις binary/JAR:
  - Debian/Ubuntu: `dpkg -V activemq` και συγκρίνετε hashes/paths αρχείων με mirrors του repo.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Αναζητήστε εκδόσεις JAR που υπάρχουν στον δίσκο αλλά δεν ανήκουν στον package manager ή symbolic links που ενημερώθηκαν εκτός διαδικασίας.
- Χρονολόγιο: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` για συσχέτιση των ctime/mtime με το χρονικό παράθυρο της παραβίασης.
- Ιστορικό κελύφους/τηλεμετρία διεργασιών: ενδείξεις για `curl`/`wget` προς το `repo1.maven.org` ή άλλα artifact CDN αμέσως μετά την αρχική εκμετάλλευση.
- Διαχείριση αλλαγών: επαληθεύστε ποιος εφάρμοσε το «patch» και γιατί, όχι μόνο ότι υπάρχει εγκατεστημένη μια patched έκδοση.

### C2 μέσω cloud υπηρεσιών με bearer tokens και stagers anti-analysis
Το παρατηρημένο tradecraft συνδύαζε πολλαπλές διαδρομές C2 μεγάλης διάρκειας και συσκευασία anti-analysis:<sup>[[3]](#references)</sup>
- ELF loaders PyInstaller προστατευμένα με κωδικό πρόσβασης, ώστε να δυσχεραίνουν το sandboxing και τη στατική ανάλυση (π.χ. κρυπτογραφημένο PYZ, προσωρινή εξαγωγή κάτω από το `/_MEI*`).
  - Ενδείξεις: αποτελέσματα `strings` όπως `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Artifacts κατά τον χρόνο εκτέλεσης: εξαγωγή στο `/tmp/_MEI*` ή σε προσαρμοσμένες διαδρομές `--runtime-tmpdir`.
- C2 μέσω Dropbox, με hardcoded OAuth Bearer tokens
  - Δείκτες δικτύου: `api.dropboxapi.com` / `content.dropboxapi.com` με `Authorization: Bearer <token>`.
  - Αναζητήστε σε proxy/NetFlow/Zeek/Suricata εξερχόμενη HTTPS κίνηση προς domains του Dropbox από workloads διακομιστών που κανονικά δεν συγχρονίζουν αρχεία.
- Παράλληλο/εφεδρικό C2 μέσω tunneling (π.χ. Cloudflare Tunnel `cloudflared`), για διατήρηση του ελέγχου αν αποκλειστεί ένα κανάλι.
  - Host IOCs: διεργασίες/μονάδες `cloudflared`, ρυθμίσεις στο `~/.cloudflared/*.json`, εξερχόμενη κίνηση στη θύρα 443 προς Cloudflare edges.

### Persistence και «rollback της ενίσχυσης ασφαλείας» για διατήρηση της πρόσβασης (παραδείγματα Linux)
Οι επιτιθέμενοι συχνά συνδυάζουν self-patching με ανθεκτικές μεθόδους πρόσβασης:<sup>[[3]](#references)</sup>
- Cron/Anacron: αλλαγές στο stub `0anacron` σε κάθε κατάλογο `/etc/cron.*/` για περιοδική εκτέλεση.
  - Αναζητήστε:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Αναίρεση της σκλήρυνσης των ρυθμίσεων SSH: ενεργοποίηση συνδέσεων root και αλλαγή των προεπιλεγμένων κελυφών για λογαριασμούς με χαμηλά προνόμια.
  - Αναζητήστε ενδείξεις ενεργοποίησης σύνδεσης root:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Αναζητήστε ύποπτα διαδραστικά shells σε λογαριασμούς συστήματος (π.χ., `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Τυχαία beacon artifacts με σύντομα ονόματα (8 αλφαβητικούς χαρακτήρες), που αποθηκεύονται στον δίσκο και επικοινωνούν επίσης με cloud C2:
  - Εντοπισμός:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Οι defenders θα πρέπει να συσχετίζουν αυτά τα τεχνουργήματα με συμβάντα εξωτερικής έκθεσης και ενημέρωσης υπηρεσιών, ώστε να εντοπίζουν anti-forensic αυτο-αποκατάσταση που χρησιμοποιείται για να αποκρυφθεί η αρχική εκμετάλλευση.

## References

- [1] [Sophos X-Ops – AuKill: Ένα weaponized ευάλωτο driver για την απενεργοποίηση του EDR (Μάρτιος 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching του EtwEventWrite για stealth: Ανίχνευση και threat hunting (Ιούνιος 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching για persistence: Πώς το Linux malware DripDropper εξαπλώνεται στο cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Απόκρυψη του .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Αποκάλυψη μιας παραλλαγής SectopRAT ενσωματωμένης σε νόμιμο λογισμικό](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – εντολή choice](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – εντολή del](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
{{#include ../../banners/hacktricks-training.md}}
