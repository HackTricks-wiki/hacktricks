# Τεχνικές Anti-Forensic

## Χρονικές σημάνσεις

Ένας επιτιθέμενος μπορεί να ενδιαφέρεται να **αλλάξει τις χρονικές σημάνσεις των αρχείων** για να αποφύγει τον εντοπισμό.\
Είναι possible να βρεθούν οι χρονικές σημάνσεις μέσα στο MFT, στα attributes `$STANDARD_INFORMATION` \_\_ και \_\_ `$FILE_NAME`.

Και τα δύο attributes έχουν 4 χρονικές σημάνσεις: **Modification**, **access**, **creation** και **MFT registry modification** (MACE ή MACB).

Ο **Windows explorer** και άλλα εργαλεία εμφανίζουν τις πληροφορίες από το **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Αυτό το εργαλείο **τροποποιεί** τις πληροφορίες χρονικών σημάνσεων μέσα στο **`$STANDARD_INFORMATION`**, **αλλά** **όχι** τις πληροφορίες μέσα στο **`$FILE_NAME`**. Επομένως, είναι possible να **εντοπιστεί** **ύποπτη** **δραστηριότητα**.

### Usnjrnl

Το **USN Journal** (Update Sequence Number Journal) είναι μια δυνατότητα του NTFS (Windows NT file system) που παρακολουθεί τις αλλαγές στον τόμο. Το εργαλείο [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) επιτρέπει την εξέταση αυτών των αλλαγών.

![TimeStomp - Anti-forensic Tool - Usnjrnl: Το USN Journal (Update Sequence Number Journal) είναι μια δυνατότητα του NTFS (Windows NT file system) που παρακολουθεί τις αλλαγές στον τόμο. Το...](<../../images/image (801).png>)

Η προηγούμενη εικόνα είναι το **output** που εμφανίζεται από το **tool**, όπου μπορεί να παρατηρηθεί ότι πραγματοποιήθηκαν **ορισμένες αλλαγές** στο αρχείο.

### $LogFile

**Όλες οι αλλαγές metadata σε ένα file system καταγράφονται** σε μια διαδικασία γνωστή ως [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Τα καταγεγραμμένα metadata αποθηκεύονται σε ένα αρχείο με όνομα `**$LogFile**`, το οποίο βρίσκεται στον root directory ενός NTFS file system. Εργαλεία όπως το [LogFileParser](https://github.com/jschicht/LogFileParser) μπορούν να χρησιμοποιηθούν για την ανάλυση αυτού του αρχείου και τον εντοπισμό αλλαγών.

![Usnjrnl - $LogFile: Όλες οι αλλαγές metadata σε ένα file system καταγράφονται σε μια διαδικασία γνωστή ως write-ahead logging. Τα καταγεγραμμένα metadata αποθηκεύονται σε ένα αρχείο με όνομα $LogFile , το οποίο βρίσκεται στον root...](<../../images/image (137).png>)

Και πάλι, στο output του tool είναι possible να φανεί ότι **πραγματοποιήθηκαν ορισμένες αλλαγές**.

Χρησιμοποιώντας το ίδιο εργαλείο, είναι possible να εντοπιστεί **σε ποια χρονική στιγμή τροποποιήθηκαν οι χρονικές σημάνσεις**:

![Usnjrnl - $LogFile: Χρησιμοποιώντας το ίδιο εργαλείο είναι possible να εντοπιστεί σε ποια χρονική στιγμή τροποποιήθηκαν οι χρονικές σημάνσεις](<../../images/image (1089).png>)

- CTIME: Χρόνος δημιουργίας του αρχείου
- ATIME: Χρόνος τροποποίησης του αρχείου
- MTIME: Τροποποίηση του MFT registry του αρχείου
- RTIME: Χρόνος πρόσβασης στο αρχείο

### Σύγκριση `$STANDARD_INFORMATION` και `$FILE_NAME`

Ένας ακόμη τρόπος εντοπισμού ύποπτα τροποποιημένων αρχείων είναι η σύγκριση του χρόνου και στα δύο attributes, αναζητώντας **ασυμφωνίες**.

### Nanoseconds

Οι χρονικές σημάνσεις του **NTFS** έχουν **precision** **100 nanoseconds**. Επομένως, η εύρεση αρχείων με χρονικές σημάνσεις όπως 2010-10-10 10:10:**00.000:0000 είναι πολύ ύποπτη**.

### SetMace - Anti-forensic Tool

Αυτό το εργαλείο μπορεί να τροποποιήσει και τα δύο attributes `$STARNDAR_INFORMATION` και `$FILE_NAME`. Ωστόσο, από τα Windows Vista και μετά, απαιτείται ένα live OS για την τροποποίηση αυτών των πληροφοριών.

## Απόκρυψη δεδομένων

Το NFTS χρησιμοποιεί ένα cluster και το ελάχιστο μέγεθος πληροφοριών. Αυτό σημαίνει ότι αν ένα αρχείο καταλαμβάνει ένα cluster και μισό, **το υπόλοιπο μισό δεν πρόκειται να χρησιμοποιηθεί** μέχρι να διαγραφεί το αρχείο. Επομένως, είναι possible να **κρυφτούν δεδομένα σε αυτόν τον slack space**.

Υπάρχουν εργαλεία όπως το slacker που επιτρέπουν την απόκρυψη δεδομένων σε αυτόν τον "hidden" χώρο. Ωστόσο, μια ανάλυση των `$logfile` και `$usnjrnl` μπορεί να δείξει ότι προστέθηκαν δεδομένα:

![SetMace - Anti-forensic Tool - Απόκρυψη δεδομένων: Υπάρχουν εργαλεία όπως το slacker που επιτρέπουν την απόκρυψη δεδομένων σε αυτόν τον "hidden" χώρο. Ωστόσο, μια ανάλυση των $logfile και $usnjrnl μπορεί να δείξει ότι...](<../../images/image (1060).png>)

Στη συνέχεια, είναι possible να ανακτηθεί ο slack space με εργαλεία όπως το FTK Imager. Σημειώστε ότι αυτού του είδους τα εργαλεία μπορούν να αποθηκεύσουν το περιεχόμενο ως obfuscated ή ακόμη και encrypted.

## UsbKill

Πρόκειται για ένα εργαλείο που θα **απενεργοποιήσει τον υπολογιστή αν εντοπιστεί οποιαδήποτε αλλαγή στις** θύρες **USB**.\
Ένας τρόπος εντοπισμού του είναι η επιθεώρηση των running processes και ο **έλεγχος κάθε python script που εκτελείται**.

## Live Linux Distributions

Αυτές οι distros **εκτελούνται μέσα στη** μνήμη **RAM**. Ο μόνος τρόπος εντοπισμού τους είναι **σε περίπτωση που το NTFS file-system έχει γίνει mount με write permissions**. Αν έχει γίνει mount μόνο με read permissions, δεν θα είναι possible να εντοπιστεί η εισβολή.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Είναι possible να απενεργοποιηθούν αρκετές μέθοδοι logging των Windows, ώστε να γίνει πολύ δυσκολότερη η forensic investigation.

### Disable Timestamps - UserAssist

Πρόκειται για ένα registry key που διατηρεί τις ημερομηνίες και τις ώρες κατά τις οποίες εκτελέστηκε κάθε executable από τον χρήστη.

Η απενεργοποίηση του UserAssist απαιτεί δύο βήματα:

1. Ορίστε δύο registry keys, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` και `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, και τα δύο σε μηδέν, ώστε να δηλώσετε ότι θέλετε να απενεργοποιηθεί το UserAssist.
2. Διαγράψτε τα registry subtrees που μοιάζουν με `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disable Timestamps - Prefetch

Αυτό αποθηκεύει πληροφορίες σχετικά με τις εφαρμογές που εκτελέστηκαν, με στόχο τη βελτίωση της απόδοσης του Windows system. Ωστόσο, μπορεί επίσης να είναι χρήσιμο για forensic practices.

- Εκτελέστε το `regedit`
- Επιλέξτε το file path `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Κάντε δεξί click στα `EnablePrefetcher` και `EnableSuperfetch`
- Επιλέξτε Modify σε καθένα από αυτά, για να αλλάξετε την τιμή από 1 (ή 3) σε 0
- Κάντε Restart

### Disable Timestamps - Last Access Time

Κάθε φορά που ανοίγει ένας φάκελος από έναν NTFS volume σε έναν Windows NT server, το system καταγράφει την ώρα για να **ενημερώσει ένα πεδίο χρονικής σήμανσης σε κάθε καταχωρισμένο φάκελο**, το οποίο ονομάζεται last access time. Σε έναν heavily used NTFS volume, αυτό μπορεί να επηρεάσει την απόδοση.

1. Ανοίξτε το Registry Editor (Regedit.exe).
2. Μεταβείτε στο `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Αναζητήστε το `NtfsDisableLastAccessUpdate`. Αν δεν υπάρχει, προσθέστε αυτό το DWORD και ορίστε την τιμή του σε 1, ώστε να απενεργοποιηθεί η διαδικασία.
4. Κλείστε το Registry Editor και κάντε reboot στον server.

### Delete USB History

Όλα τα **USB Device Entries** αποθηκεύονται στο Windows Registry, κάτω από το registry key **USBSTOR**, το οποίο περιέχει sub keys που δημιουργούνται κάθε φορά που συνδέετε ένα USB Device στον PC ή Laptop σας. Μπορείτε να βρείτε αυτό το key εδώ `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Διαγράφοντάς το**, θα διαγράψετε το USB history.\
Μπορείτε επίσης να χρησιμοποιήσετε το εργαλείο [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), για να βεβαιωθείτε ότι τα έχετε διαγράψει (και για να τα διαγράψετε).

Ένα ακόμη αρχείο που αποθηκεύει πληροφορίες σχετικά με τα USB είναι το αρχείο `setupapi.dev.log` μέσα στο `C:\Windows\INF`. Θα πρέπει επίσης να διαγραφεί.

### Disable Shadow Copies

**Εμφανίστε σε λίστα** τα shadow copies με `vssadmin list shadowstorage`\
**Διαγράψτε** τα εκτελώντας `vssadmin delete shadow`

Μπορείτε επίσης να τα διαγράψετε μέσω GUI, ακολουθώντας τα βήματα που προτείνονται στο [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Για να απενεργοποιήσετε τα shadow copies, [βήματα από εδώ](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Ανοίξτε το Services program πληκτρολογώντας "services" στο text search box, αφού κάνετε click στο Windows start button.
2. Από τη λίστα, βρείτε το "Volume Shadow Copy", επιλέξτε το και, στη συνέχεια, ανοίξτε το Properties κάνοντας δεξί click.
3. Επιλέξτε Disabled από το drop-down menu "Startup type" και, στη συνέχεια, επιβεβαιώστε την αλλαγή κάνοντας click στα Apply και OK.

Είναι επίσης possible να τροποποιήσετε στο registry ποια αρχεία πρόκειται να αντιγραφούν στο shadow copy, στο `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Overwrite deleted files

- Μπορείτε να χρησιμοποιήσετε ένα **Windows tool**: `cipher /w:C` Αυτό θα υποδείξει στο cipher να αφαιρέσει δεδομένα από τον διαθέσιμο unused disk space μέσα στο C drive.
- Μπορείτε επίσης να χρησιμοποιήσετε εργαλεία όπως το [**Eraser**](https://eraser.heidi.ie)

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> Αναπτύξτε το "Windows Logs" --> Κάντε δεξί click σε κάθε category και επιλέξτε "Clear Log"
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

Οι πρόσφατες εκδόσεις των Windows 10/11 και του Windows Server διατηρούν **πλούσια PowerShell forensic artifacts** κάτω από
`Microsoft-Windows-PowerShell/Operational` (events 4104/4105/4106).
Οι επιτιθέμενοι μπορούν να τα απενεργοποιήσουν ή να τα διαγράψουν on-the-fly:
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
Οι Defenders θα πρέπει να παρακολουθούν για αλλαγές σε αυτά τα registry keys και για μαζική διαγραφή PowerShell events.

### ETW (Event Tracing for Windows) Patch

Τα προϊόντα endpoint security βασίζονται σε μεγάλο βαθμό στο ETW. Μια δημοφιλής μέθοδος evasion του 2024 είναι το patch των `ntdll!EtwEventWrite`/`EtwEventWriteFull` στη μνήμη, ώστε κάθε κλήση ETW να επιστρέφει `STATUS_SUCCESS` χωρίς να εκπέμπει το event:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Δημόσια PoCs (π.χ. `EtwTiSwallow`) υλοποιούν το ίδιο primitive σε PowerShell ή C++.
Επειδή το **patch είναι process-local**, τα EDR που εκτελούνται μέσα σε άλλες διεργασίες ενδέχεται να μην το εντοπίσουν.<sup>[[5]](#references)</sup>
Ανίχνευση: σύγκρινε το `ntdll` στη μνήμη με αυτό στον δίσκο ή κάνε hook πριν από το user-mode.

### Αναβίωση των Alternate Data Streams (ADS)

Σε malware campaigns του 2023 (π.χ. **FIN12** loaders), έχει παρατηρηθεί η τοποθέτηση second-stage binaries
μέσα σε ADS, ώστε να παραμένουν εκτός οπτικού πεδίου των traditional scanners:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumerate streams με `dir /R`, `Get-Item -Stream *` ή το Sysinternals `streams64.exe`.
Η αντιγραφή του host file σε FAT/exFAT ή μέσω SMB θα αφαιρέσει το hidden stream και μπορεί να χρησιμοποιηθεί
από investigators για την ανάκτηση του payload.

### BYOVD & “AuKill” (2023)

Το Bring-Your-Own-Vulnerable-Driver χρησιμοποιείται πλέον συστηματικά για **anti-forensics** σε ransomware
intrusions.
Το open-source tool **AuKill** φορτώνει έναν signed αλλά vulnerable driver (`procexp152.sys`) για να
αναστείλει ή να τερματίσει τα EDR και forensic sensors **πριν από την κρυπτογράφηση και την καταστροφή των logs**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Ο driver αφαιρείται στη συνέχεια, αφήνοντας ελάχιστα artifacts.<sup>[[1]](#references)</sup>
Mitigations: ενεργοποιήστε τη Microsoft vulnerable-driver blocklist (HVCI/SAC)
και δημιουργήστε alert για kernel-service creation από user-writable paths.

---

## Linux Anti-Forensics: Self-Patching και Cloud C2 (2023–2025)

### Self‑patching παραβιασμένων services για τη μείωση του detection (Linux)
Οι adversaries κάνουν όλο και συχνότερα “self‑patch” σε ένα service αμέσως μετά την εκμετάλλευσή του, ώστε να αποτρέψουν την επανεκμετάλλευση και να καταστείλουν τα vulnerability-based detections. Η ιδέα είναι η αντικατάσταση των vulnerable components με τα πιο πρόσφατα legitimate upstream binaries/JARs, ώστε οι scanners να αναφέρουν ότι το host είναι patched, ενώ το persistence και το C2 παραμένουν.<sup>[[3]](#references)</sup>

Παράδειγμα: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Μετά το post‑exploitation, οι attackers έκαναν fetch legitimate JARs από το Maven Central (repo1.maven.org), διέγραψαν τα vulnerable JARs από την εγκατάσταση του ActiveMQ και έκαναν restart τον broker.
- Αυτό έκλεισε το αρχικό RCE, ενώ διατηρήθηκαν άλλα footholds (cron, αλλαγές στο SSH config, ξεχωριστά C2 implants).

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
- Debian/Ubuntu: `dpkg -V activemq` και συγκρίνετε τα file hashes/paths με τα repo mirrors.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Αναζητήστε εκδόσεις JAR που υπάρχουν στον δίσκο αλλά δεν ανήκουν στον package manager ή symbolic links που ενημερώθηκαν εκτός της προβλεπόμενης διαδικασίας.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` για συσχέτιση των ctime/mtime με το χρονικό παράθυρο του compromise.
- Shell history/process telemetry: ενδείξεις για `curl`/`wget` προς το `repo1.maven.org` ή άλλα artifact CDNs αμέσως μετά το αρχικό exploitation.
- Change management: επικυρώστε ποιος εφάρμοσε το “patch” και γιατί, όχι μόνο ότι υπάρχει μια patched έκδοση.

### C2 cloud-service με bearer tokens και anti-analysis stagers
Το παρατηρημένο tradecraft συνδύαζε πολλαπλά long-haul C2 paths και anti-analysis packaging:<sup>[[3]](#references)</sup>
- Password-protected PyInstaller ELF loaders για παρεμπόδιση του sandboxing και του static analysis (π.χ. encrypted PYZ, προσωρινή εξαγωγή κάτω από `/_MEI*`).
- Indicators: hits από `strings` όπως `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Runtime artifacts: εξαγωγή στο `/tmp/_MEI*` ή σε custom paths που ορίζονται μέσω `--runtime-tmpdir`.
- Dropbox-backed C2 με hardcoded OAuth Bearer tokens
- Network markers: `api.dropboxapi.com` / `content.dropboxapi.com` με `Authorization: Bearer <token>`.
- Αναζητήστε σε proxy/NetFlow/Zeek/Suricata outbound HTTPS προς domains του Dropbox από server workloads που κανονικά δεν συγχρονίζουν αρχεία.
- Parallel/backup C2 μέσω tunneling (π.χ. Cloudflare Tunnel `cloudflared`), διατηρώντας τον έλεγχο αν ένα κανάλι αποκλειστεί.
- Host IOCs: διεργασίες/units `cloudflared`, config στο `~/.cloudflared/*.json`, outbound 443 προς Cloudflare edges.

### Persistence και “hardening rollback” για τη διατήρηση πρόσβασης (παραδείγματα Linux)
Οι attackers συχνά συνδυάζουν self-patching με durable access paths:<sup>[[3]](#references)</sup>
- Cron/Anacron: τροποποιήσεις στο `0anacron` stub σε κάθε κατάλογο `/etc/cron.*/` για periodic execution.
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: ενεργοποίηση root logins και αλλαγή των default shells για low-privileged accounts.
- Hunt για root login enablement:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Hunt για suspicious interactive shells σε system accounts (π.χ. `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Τυχαία, short-named beacon artifacts (8 alphabetical chars) που αποτίθενται στον δίσκο και επίσης επικοινωνούν με cloud C2:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Οι Defenders θα πρέπει να συσχετίζουν αυτά τα artifacts με την εξωτερική έκθεση και τα service patching events, ώστε να εντοπίζουν το anti-forensic self-remediation που χρησιμοποιείται για την απόκρυψη του αρχικού exploitation.

## References

- [1] [Sophos X-Ops – AuKill: Ένα weaponized vulnerable driver για την απενεργοποίηση του EDR (Μάρτιος 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching του EtwEventWrite για stealth: Detection & Hunting (Ιούνιος 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching για persistence: Πώς το Linux malware DripDropper κινείται μέσα στο cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Απόκρυψη του .NET σας - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
