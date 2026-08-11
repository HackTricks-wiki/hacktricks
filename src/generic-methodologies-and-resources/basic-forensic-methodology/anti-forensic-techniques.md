# Τεχνικές Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Χρονικές σημάνσεις

Ένας επιτιθέμενος μπορεί να ενδιαφέρεται να **αλλάξει τις χρονικές σημάνσεις των αρχείων** για να αποφύγει τον εντοπισμό.\
Είναι δυνατό να βρεθούν οι χρονικές σημάνσεις μέσα στο MFT στα attributes `$STANDARD_INFORMATION` \_\_ και \_\_ `$FILE_NAME`.

Και τα δύο attributes διαθέτουν 4 χρονικές σημάνσεις: **Τροποποίηση**, **πρόσβαση**, **δημιουργία** και **τροποποίηση εγγραφής MFT** (MACE ή MACB).

Ο **Windows explorer** και άλλα εργαλεία εμφανίζουν τις πληροφορίες από το **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Αυτό το εργαλείο **τροποποιεί** τις πληροφορίες χρονικών σημάνσεων μέσα στο **`$STANDARD_INFORMATION`**, **αλλά όχι** τις πληροφορίες μέσα στο **`$FILE_NAME`**. Επομένως, είναι δυνατό να **εντοπιστεί** **ύποπτη** **δραστηριότητα**.

### Usnjrnl

Το **USN Journal** (Update Sequence Number Journal) είναι μια δυνατότητα του NTFS (Windows NT file system) που παρακολουθεί τις αλλαγές στον τόμο. Το εργαλείο [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) επιτρέπει την εξέταση αυτών των αλλαγών.

![TimeStomp - Anti-forensic Tool - Usnjrnl: Το USN Journal (Update Sequence Number Journal) είναι μια δυνατότητα του NTFS (Windows NT file system) που παρακολουθεί τις αλλαγές στον τόμο. Το...](<../../images/image (801).png>)

Η προηγούμενη εικόνα είναι το **output** που εμφανίζεται από το **tool**, όπου μπορεί να παρατηρηθεί ότι **πραγματοποιήθηκαν ορισμένες αλλαγές** στο αρχείο.

### $LogFile

**Όλες οι αλλαγές metadata σε ένα file system καταγράφονται** σε μια διαδικασία γνωστή ως [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Τα καταγεγραμμένα metadata διατηρούνται σε ένα αρχείο με όνομα `**$LogFile**`, το οποίο βρίσκεται στον ριζικό κατάλογο ενός NTFS file system. Εργαλεία όπως το [LogFileParser](https://github.com/jschicht/LogFileParser) μπορούν να χρησιμοποιηθούν για την ανάλυση αυτού του αρχείου και τον εντοπισμό αλλαγών.

![Usnjrnl - $LogFile: Όλες οι αλλαγές metadata σε ένα file system καταγράφονται σε μια διαδικασία γνωστή ως write-ahead logging. Τα καταγεγραμμένα metadata διατηρούνται σε ένα αρχείο με όνομα $LogFile , το οποίο βρίσκεται στον ριζικό...](<../../images/image (137).png>)

Και πάλι, στο output του εργαλείου είναι δυνατό να δούμε ότι **πραγματοποιήθηκαν ορισμένες αλλαγές**.

Χρησιμοποιώντας το ίδιο εργαλείο, είναι δυνατό να εντοπιστεί **σε ποια χρονική στιγμή τροποποιήθηκαν οι χρονικές σημάνσεις**:

![Usnjrnl - $LogFile: Χρησιμοποιώντας το ίδιο εργαλείο, είναι δυνατό να εντοπιστεί σε ποια χρονική στιγμή τροποποιήθηκαν οι χρονικές σημάνσεις](<../../images/image (1089).png>)

- CTIME: Χρόνος δημιουργίας του αρχείου
- ATIME: Χρόνος τροποποίησης του αρχείου
- MTIME: Τροποποίηση εγγραφής MFT του αρχείου
- RTIME: Χρόνος πρόσβασης του αρχείου

### Σύγκριση `$STANDARD_INFORMATION` και `$FILE_NAME`

Ένας ακόμη τρόπος εντοπισμού ύποπτων τροποποιημένων αρχείων είναι η σύγκριση του χρόνου και στα δύο attributes, αναζητώντας **αναντιστοιχίες**.

### Nanoseconds

Οι χρονικές σημάνσεις του **NTFS** έχουν **ακρίβεια** **100 nanoseconds**. Επομένως, η εύρεση αρχείων με χρονικές σημάνσεις όπως 2010-10-10 10:10:**00.000:0000 είναι πολύ ύποπτη**.

### SetMace - Anti-forensic Tool

Αυτό το εργαλείο μπορεί να τροποποιήσει και τα δύο attributes, `$STARNDAR_INFORMATION` και `$FILE_NAME`. Ωστόσο, από τα Windows Vista και έπειτα, απαιτείται ένα live OS για την τροποποίηση αυτών των πληροφοριών.

## Απόκρυψη δεδομένων

Το NFTS χρησιμοποιεί clusters και το ελάχιστο μέγεθος πληροφοριών. Αυτό σημαίνει ότι, αν ένα αρχείο καταλαμβάνει ενάμιση cluster, **το υπόλοιπο μισό δεν πρόκειται να χρησιμοποιηθεί** μέχρι να διαγραφεί το αρχείο. Επομένως, είναι δυνατό να **κρυφτούν δεδομένα σε αυτόν τον slack space**.

Υπάρχουν εργαλεία όπως το slacker που επιτρέπουν την απόκρυψη δεδομένων σε αυτόν τον "κρυφό" χώρο. Ωστόσο, μια ανάλυση των `$logfile` και `$usnjrnl` μπορεί να δείξει ότι προστέθηκαν δεδομένα:

![SetMace - Anti-forensic Tool - Data Hiding: Υπάρχουν εργαλεία όπως το slacker που επιτρέπουν την απόκρυψη δεδομένων σε αυτόν τον "κρυφό" χώρο. Ωστόσο, μια ανάλυση των $logfile και $usnjrnl μπορεί να δείξει ότι...](<../../images/image (1060).png>)

Στη συνέχεια, είναι δυνατό να ανακτηθεί ο slack space χρησιμοποιώντας εργαλεία όπως το FTK Imager. Σημειώστε ότι αυτού του είδους τα εργαλεία μπορούν να αποθηκεύσουν το περιεχόμενο σε obfuscated ή ακόμη και encrypted μορφή.

## UsbKill

Πρόκειται για ένα εργαλείο που **απενεργοποιεί τον υπολογιστή αν εντοπιστεί οποιαδήποτε αλλαγή** στις θύρες **USB**.\
Ένας τρόπος εντοπισμού του είναι η επιθεώρηση των εκτελούμενων processes και η **εξέταση κάθε εκτελούμενου python script**.

## Live Linux Distributions

Αυτές οι distros **εκτελούνται μέσα στη μνήμη RAM**. Ο μόνος τρόπος εντοπισμού τους είναι **σε περίπτωση που το NTFS file-system έχει γίνει mount με write permissions**. Αν έχει γίνει mount μόνο με read permissions, δεν θα είναι δυνατός ο εντοπισμός της εισβολής.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Είναι δυνατό να απενεργοποιηθούν αρκετές μέθοδοι logging των Windows, ώστε να γίνει πολύ δυσκολότερη η forensic investigation.

### Disable Timestamps - UserAssist

Αυτό είναι ένα registry key που διατηρεί τις ημερομηνίες και τις ώρες κατά τις οποίες εκτελέστηκε κάθε executable από τον χρήστη.

Η απενεργοποίηση του UserAssist απαιτεί δύο βήματα:

1. Ορίστε δύο registry keys, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` και `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, και τα δύο σε μηδέν, ώστε να δηλωθεί ότι θέλουμε να απενεργοποιηθεί το UserAssist.
2. Διαγράψτε τα registry subtrees σας που μοιάζουν με `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disable Timestamps - Prefetch

Αυτό αποθηκεύει πληροφορίες σχετικά με τις εφαρμογές που εκτελέστηκαν, με στόχο τη βελτίωση της απόδοσης του Windows system. Ωστόσο, αυτό μπορεί επίσης να είναι χρήσιμο για forensic πρακτικές.

- Εκτελέστε το `regedit`
- Επιλέξτε το file path `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Κάντε δεξί κλικ στα `EnablePrefetcher` και `EnableSuperfetch`
- Επιλέξτε Modify σε καθένα από αυτά, για να αλλάξετε την τιμή από 1 (ή 3) σε 0
- Κάντε επανεκκίνηση

### Disable Timestamps - Last Access Time

Κάθε φορά που ανοίγει ένας φάκελος από έναν τόμο NTFS σε έναν Windows NT server, το σύστημα καταγράφει τον χρόνο για να **ενημερώσει ένα πεδίο χρονικής σήμανσης σε κάθε φάκελο που εμφανίζεται**, το οποίο ονομάζεται χρόνος τελευταίας πρόσβασης. Σε έναν heavily used NTFS volume, αυτό μπορεί να επηρεάσει την απόδοση.

1. Ανοίξτε το Registry Editor (Regedit.exe).
2. Μεταβείτε στο `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Αναζητήστε το `NtfsDisableLastAccessUpdate`. Αν δεν υπάρχει, προσθέστε αυτό το DWORD και ορίστε την τιμή του σε 1, γεγονός που θα απενεργοποιήσει τη διαδικασία.
4. Κλείστε το Registry Editor και κάντε reboot στον server.

### Delete USB History

Όλα τα **USB Device Entries** αποθηκεύονται στο Windows Registry, κάτω από το registry key **USBSTOR**, το οποίο περιέχει sub keys που δημιουργούνται κάθε φορά που συνδέετε μια USB Device στον PC ή Laptop σας. Μπορείτε να βρείτε αυτό το key εδώ: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Διαγράφοντάς το**, θα διαγράψετε το USB history.\
Μπορείτε επίσης να χρησιμοποιήσετε το εργαλείο [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), για να βεβαιωθείτε ότι τα διαγράψατε (και για να τα διαγράψετε).

Ένα ακόμη αρχείο που αποθηκεύει πληροφορίες σχετικά με τα USBs είναι το `setupapi.dev.log` μέσα στο `C:\Windows\INF`. Θα πρέπει να διαγραφεί και αυτό.

### Disable Shadow Copies

**Εμφανίστε** τα shadow copies με `vssadmin list shadowstorage`\
**Διαγράψτε** τα εκτελώντας `vssadmin delete shadow`

Μπορείτε επίσης να τα διαγράψετε μέσω GUI, ακολουθώντας τα βήματα που προτείνονται στο [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Για να απενεργοποιήσετε τα shadow copies, [βήματα από εδώ](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Ανοίξτε το Services program πληκτρολογώντας "services" στο text search box, αφού κάνετε κλικ στο Windows start button.
2. Από τη λίστα, βρείτε το "Volume Shadow Copy", επιλέξτε το και, στη συνέχεια, ανοίξτε τα Properties κάνοντας δεξί κλικ.
3. Επιλέξτε Disabled από το drop-down menu "Startup type" και, στη συνέχεια, επιβεβαιώστε την αλλαγή κάνοντας κλικ στα Apply και OK.

Είναι επίσης δυνατό να τροποποιηθεί στο registry ποια αρχεία πρόκειται να αντιγραφούν στο shadow copy, μέσω του `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Overwrite deleted files

- Μπορείτε να χρησιμοποιήσετε ένα **Windows tool**: `cipher /w:C`. Αυτό θα δώσει εντολή στο cipher να αφαιρέσει δεδομένα από τον διαθέσιμο αχρησιμοποίητο χώρο δίσκου μέσα στη μονάδα C.
- Μπορείτε επίσης να χρησιμοποιήσετε εργαλεία όπως το [**Eraser**](https://eraser.heidi.ie)

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> Αναπτύξτε το "Windows Logs" --> Κάντε δεξί κλικ σε κάθε category και επιλέξτε "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Στην ενότητα services, απενεργοποιήστε το service "Windows Event Log"
- `WEvtUtil.exec clear-log` ή `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Οι πρόσφατες εκδόσεις των Windows 10/11 και του Windows Server διατηρούν **πλούσια PowerShell forensic artifacts** στο
`Microsoft-Windows-PowerShell/Operational` (events 4104/4105/4106).
Οι attackers μπορούν να τα απενεργοποιήσουν ή να τα διαγράψουν on-the-fly:
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
Οι defenders θα πρέπει να παρακολουθούν για αλλαγές σε αυτά τα registry keys και για αφαίρεση PowerShell events σε μεγάλο όγκο.

### ETW (Event Tracing for Windows) Patch

Τα προϊόντα endpoint security βασίζονται σε μεγάλο βαθμό στο ETW. Μια δημοφιλής μέθοδος evasion του 2024 είναι η επιδιόρθωση των `ntdll!EtwEventWrite`/`EtwEventWriteFull` στη μνήμη, ώστε κάθε κλήση ETW να επιστρέφει `STATUS_SUCCESS` χωρίς να εκπέμπει το event:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Δημόσια PoCs (π.χ. `EtwTiSwallow`) υλοποιούν το ίδιο primitive σε PowerShell ή C++.
Επειδή το patch είναι **process-local**, τα EDRs που εκτελούνται μέσα σε άλλες διεργασίες ενδέχεται να μην το εντοπίσουν.<sup>[[5]](#references)</sup>
Εντοπισμός: σύγκρινε το `ntdll` στη μνήμη με αυτό στον δίσκο ή κάνε hook πριν από το user-mode.

### Επανεμφάνιση των Alternate Data Streams (ADS)

Σε εκστρατείες malware το 2023 (π.χ. loaders του **FIN12**), έχει παρατηρηθεί η τοποθέτηση binaries δεύτερου σταδίου
μέσα σε ADS, ώστε να παραμένουν εκτός οπτικού πεδίου των παραδοσιακών scanners:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Απαριθμήστε τα streams με `dir /R`, `Get-Item -Stream *` ή το Sysinternals `streams64.exe`.
Η αντιγραφή του αρχείου host σε FAT/exFAT ή μέσω SMB θα αφαιρέσει το hidden stream και μπορεί να χρησιμοποιηθεί
από τους investigators για την ανάκτηση του payload.

### BYOVD & “AuKill” (2023)

Το Bring-Your-Own-Vulnerable-Driver χρησιμοποιείται πλέον τακτικά για **anti-forensics** σε ransomware
intrusions.
Το open-source tool **AuKill** φορτώνει έναν signed αλλά vulnerable driver (`procexp152.sys`) για να
αναστείλει ή να τερματίσει το EDR και τα forensic sensors **πριν από την κρυπτογράφηση και την καταστροφή των logs**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Ο driver αφαιρείται στη συνέχεια, αφήνοντας ελάχιστα artifacts.<sup>[[1]](#references)</sup>
Μετριασμοί: ενεργοποιήστε τη Microsoft vulnerable-driver blocklist (HVCI/SAC)
και δημιουργήστε alerts για τη δημιουργία kernel-service από διαδρομές εγγράψιμες από τον χρήστη.

---

## Linux Anti-Forensics: Self-Patching και Cloud C2 (2023–2025)

### Self‑patching παραβιασμένων services για τη μείωση του detection (Linux)
Οι adversaries εφαρμόζουν όλο και συχνότερα “self‑patch” σε ένα service αμέσως μετά την εκμετάλλευσή του, ώστε να αποτρέψουν τόσο την επανεκμετάλλευση όσο και τα detections που βασίζονται σε vulnerabilities. Η ιδέα είναι η αντικατάσταση των vulnerable components με τα πιο πρόσφατα legitimate upstream binaries/JARs, ώστε οι scanners να αναφέρουν ότι το host είναι patched, ενώ τα persistence και C2 παραμένουν ενεργά.<sup>[[3]](#references)</sup>

Παράδειγμα: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Μετά το post‑exploitation, οι attackers κατέβασαν legitimate JARs από το Maven Central (repo1.maven.org), διέγραψαν τα vulnerable JARs από την εγκατάσταση του ActiveMQ και έκαναν restart στον broker.
- Αυτό έκλεισε το αρχικό RCE, διατηρώντας παράλληλα άλλα footholds (cron, αλλαγές στη ρύθμιση SSH, ξεχωριστά C2 implants).

Operational example (illustrative)
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
Συμβουλές Forensic/hunting
- Ελέγξτε τους καταλόγους υπηρεσιών για μη προγραμματισμένες αντικαταστάσεις binary/JAR:
- Debian/Ubuntu: `dpkg -V activemq` και συγκρίνετε τα hashes/paths των αρχείων με mirrors των repos.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Αναζητήστε εκδόσεις JAR που υπάρχουν στον δίσκο αλλά δεν ανήκουν στον package manager ή symbolic links που ενημερώθηκαν εκτός της κανονικής διαδικασίας.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` για συσχέτιση των ctime/mtime με το χρονικό παράθυρο του compromise.
- Shell history/process telemetry: ενδείξεις χρήσης `curl`/`wget` προς το `repo1.maven.org` ή άλλα artifact CDNs αμέσως μετά το αρχικό exploitation.
- Change management: επιβεβαιώστε ποιος εφάρμοσε το “patch” και γιατί, όχι μόνο ότι υπάρχει εγκατεστημένη patched έκδοση.

### Cloud‑service C2 με bearer tokens και anti‑analysis stagers
Το παρατηρημένο tradecraft συνδύαζε πολλαπλά long‑haul C2 paths και anti‑analysis packaging:<sup>[[3]](#references)</sup>
- Password‑protected PyInstaller ELF loaders για παρεμπόδιση του sandboxing και του static analysis (π.χ. encrypted PYZ, προσωρινή αποσυμπίεση στο `/_MEI*`).
- Indicators: ευρήματα από `strings`, όπως `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Runtime artifacts: αποσυμπίεση στο `/tmp/_MEI*` ή σε custom paths μέσω `--runtime-tmpdir`.
- Dropbox‑backed C2 με hardcoded OAuth Bearer tokens
- Network markers: `api.dropboxapi.com` / `content.dropboxapi.com` με `Authorization: Bearer <token>`.
- Αναζητήστε σε proxy/NetFlow/Zeek/Suricata εξερχόμενες HTTPS συνδέσεις προς domains του Dropbox από server workloads που κανονικά δεν συγχρονίζουν αρχεία.
- Parallel/backup C2 μέσω tunneling (π.χ. Cloudflare Tunnel `cloudflared`), ώστε να διατηρείται ο έλεγχος αν ένα κανάλι μπλοκαριστεί.
- Host IOCs: διεργασίες/units `cloudflared`, config στο `~/.cloudflared/*.json`, εξερχόμενες συνδέσεις 443 προς Cloudflare edges.

### Persistence και “hardening rollback” για διατήρηση της πρόσβασης (παραδείγματα Linux)
Οι attackers συχνά συνδυάζουν self‑patching με durable access paths:<sup>[[3]](#references)</sup>
- Cron/Anacron: τροποποιήσεις στο stub `0anacron` σε κάθε κατάλογο `/etc/cron.*/` για περιοδική εκτέλεση.
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: ενεργοποίηση root logins και αλλαγή των default shells για λογαριασμούς με χαμηλά δικαιώματα.
- Hunt για ενεργοποίηση root login:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag τιμές όπως "yes" ή υπερβολικά permissive settings
```
- Hunt για ύποπτα interactive shells σε system accounts (π.χ. `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Random, short‑named beacon artifacts (8 alphabetical chars) που αποθηκεύονται στον δίσκο και επικοινωνούν επίσης με cloud C2:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Οι defenders θα πρέπει να συσχετίζουν αυτά τα artifacts με την εξωτερική έκθεση και τα γεγονότα patching των υπηρεσιών, ώστε να εντοπίζουν το anti‑forensic self‑remediation που χρησιμοποιείται για την απόκρυψη του αρχικού exploitation.

## References

- [1] [Sophos X-Ops – AuKill: Ένα weaponized vulnerable driver για την απενεργοποίηση του EDR (Μάρτιος 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching του EtwEventWrite για stealth: Detection & Hunting (Ιούνιος 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching για persistence: Πώς το DripDropper Linux malware κινείται μέσω του cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Απόκρυψη του .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
