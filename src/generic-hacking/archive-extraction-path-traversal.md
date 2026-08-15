# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Überblick

Viele Archivformate (ZIP, RAR, TAR, 7-ZIP usw.) erlauben es jedem Eintrag, einen eigenen **internen Pfad** zu enthalten. Wenn ein Extraktionsprogramm diesen Pfad blind übernimmt, wird ein manipuliertes Dateiname mit `..` oder einem **absoluten Pfad** (z. B. `C:\Windows\System32\`) außerhalb des vom Benutzer ausgewählten Verzeichnisses geschrieben.
Diese Klasse von Schwachstellen ist weithin als *Zip-Slip* oder **archive extraction path traversal** bekannt.<sup>[[6]](#references)</sup>

Die Folgen reichen vom Überschreiben beliebiger Dateien bis hin zur direkten Erreichung von **remote code execution (RCE)**, indem eine Payload an einem **auto-run**-Ort wie dem Windows-Ordner *Startup* abgelegt wird.

## Grundursache

1. Der Angreifer erstellt ein Archiv, in dessen Dateiköpfen eine oder mehrere der folgenden Angaben enthalten sind:
* Relative Traversal-Sequenzen (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute Pfade (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Oder manipulierte **symlinks**, die außerhalb des Zielverzeichnisses aufgelöst werden (häufig bei ZIP/TAR auf *nix*).
2. Das Opfer extrahiert das Archiv mit einem anfälligen Tool, das dem eingebetteten Pfad vertraut (oder symlinks folgt), anstatt ihn zu bereinigen oder die Extraktion auf das ausgewählte Verzeichnis zu beschränken.
3. Die Datei wird am vom Angreifer kontrollierten Ort geschrieben und ausgeführt/geladen, sobald das System oder der Benutzer diesen Pfad das nächste Mal auslöst.

### .NET `Path.Combine` + `ZipArchive` traversal

Ein häufiges .NET-Anti-Pattern besteht darin, das vorgesehene Ziel mit dem **benutzerkontrollierten** `ZipArchiveEntry.FullName` zu kombinieren und die Extraktion ohne Pfadnormalisierung durchzuführen:<sup>[[4]](#references)[[8]](#references)</sup>
```csharp
using (var zip = ZipFile.OpenRead(zipPath))
{
foreach (var entry in zip.Entries)
{
var dest = Path.Combine(@"C:\samples\queue\", entry.FullName); // drops base if FullName is absolute
entry.ExtractToFile(dest);
}
}
```
- Wenn `entry.FullName` mit `..\\` beginnt, führt es eine Traversierung durch; wenn es ein **absoluter Pfad** ist, wird die linke Komponente vollständig verworfen, wodurch sich als Extraktionsziel das **Schreiben beliebiger Dateien** ergibt.
- Proof-of-concept-Archiv zum Schreiben in ein benachbartes `app`-Verzeichnis, das von einem geplanten Scanner überwacht wird:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Das Ablegen dieses ZIP im überwachten Eingangsverzeichnis führt zu `C:\samples\app\0xdf.txt` und beweist damit Traversal außerhalb von `C:\samples\queue\`, wodurch nachgelagerte Primitives ermöglicht werden (z. B. DLL hijacks).

## Advanced Archive-Breakout Primitives

Behandle die Extraktion als eine Folge von Änderungen am Dateisystem und nicht als unabhängige Prüfungen von Dateinamen. Ein Eintrag, der beim Parsen sicher ist, kann unsicher werden, nachdem ein früheres Mitglied einen Link erstellt oder ersetzt; dasselbe Problem tritt auf, wenn ein Extractor ein Verzeichnis als sicher zwischenspeichert und später dessen Typ geändert wird.<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through**: Erstelle `pivot -> /tmp` und extrahiere anschließend ein reguläres Mitglied als `pivot/PWNED.txt`. Wenn der Extractor dem ersten Mitglied folgt, während er das zweite materialisiert, entweicht der Schreibvorgang, ohne dass `..` im zweiten Namen enthalten ist.
* **Directory-cache/TOCTOU collision**: Erzeuge das Verzeichnis `d/sub/`, ersetze `d/sub` durch einen Symlink auf `/tmp` und erzeuge anschließend `d/sub/PWNED.txt`. Dies zielt auf Extractors ab, die das Verzeichnis einmal validieren oder zwischenspeichern und es vor dem endgültigen Schreibvorgang nicht erneut prüfen.
* **Hardlink read/overwrite**: TAR und RAR können Hardlinks darstellen. Ein Hardlink auf eine vorhandene Host-Datei kann deren Inhalte offenlegen, wenn eine spätere Komponente den extrahierten Namen bereitstellt; ein kollidierender regulärer Eintrag kann stattdessen den verknüpften Inode überschreiben. Dies wird durch Regeln für dasselbe Dateisystem und die Hardlink-Berechtigungen des Betriebssystems eingeschränkt.
* **Pre-existing or cross-archive pivot**: Wiederhole den Test mit einem nicht leeren Zielverzeichnis. Ein Archive kann einen Link platzieren, und eine spätere Extraktion kann durch ihn schreiben, selbst wenn jedes Archive eine zustandslose Prüfung des Header-Namens besteht.<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

Vergleiche Namen anhand der Semantik des Dateisystems, das sie aufnehmen wird. Nützliche Differentialfälle umfassen `LINK` gegenüber `link` auf case-insensitiven Dateisystemen, NFC- gegenüber NFD-Unicode-Schreibweisen, kompatibilitätsäquivalente Namen wie `ﬁle` gegenüber `file`, doppelte Mitglieder, die einen Pfad von einem Verzeichnis in einen Symlink ändern, sowie Backslashes, die nur unter Windows als Trennzeichen interpretiert werden. Teste außerdem Namen mit ADS auf NTFS. Diese Fälle können dazu führen, dass der Validator zwei Pfade erkennt, während das Dateisystem einen einzigen auflöst.<sup>[[5]](#references)[[11]](#references)</sup>

Ein kompakter Korpus sollte daher geordnete Kombinationen aus **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, gemischten `/` und `\`, absoluten/rooted Namen sowie komprimierten Wrappers wie `.tar.gz` testen. Führe dies ausschließlich in einer disposable VM/einem Container aus und überwache sowohl das Ziel als auch den vorgesehenen externen Canary-Pfad.<sup>[[11]](#references)</sup>

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR für Windows sowie seine Windows-RAR/UnRAR-Komponenten validierten Dateinamen während der Extraktion nicht ordnungsgemäß. Der Fehler nutzte NTFS alternate data streams (ADS), um den ausgewählten Extraktionspfad zu umgehen und Dateien an unbeabsichtigte Speicherorte zu schreiben.<sup>[[5]](#references)</sup>
Ein schädliches RAR-Archiv mit einem Eintrag wie:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
würde **außerhalb** des ausgewählten Ausgabeordners und im *Startup*-Ordner des Benutzers landen. ESET beobachtete, dass dort schädliche LNK-Dateien entpackt und bei der Benutzeranmeldung ausgeführt wurden, wodurch Persistence und ein Pfad zu RCE ermöglicht wurden.<sup>[[5]](#references)</sup>

### Erstellen eines PoC-Archivs (Linux/Mac)

Da CVE-2025-8088 einen Traversal-Pfad in einem ADS-Namen verwendet, sollte ein speziell dafür entwickelter Generator zum Erstellen des RAR verwendet werden. Das Extrahieren darf anschließend nur in einem isolierten Lab mit einem verwundbaren WinRAR-Build getestet werden.<sup>[[5]](#references)</sup>

### Beobachtete Ausnutzung in freier Wildbahn

ESET berichtete über Spear-Phishing-Kampagnen von RomCom (Storm-0978/UNC2596), bei denen RAR-Archive angehängt wurden, die CVE-2025-8088 ausnutzten, um angepasste Backdoors bereitzustellen und Ransomware-Aktivitäten zu ermöglichen.<sup>[[5]](#references)</sup>

## Neuere Fälle (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Fehler**: ZIP-Einträge, die **symbolische Links** waren, wurden während des Extrahierens dereferenziert. Dadurch konnten Angreifer aus dem Zielverzeichnis ausbrechen und beliebige Pfade überschreiben. Die Benutzerinteraktion beschränkt sich auf das *Öffnen/Extrahieren* des Archivs.<sup>[[1]](#references)</sup>
* **Betroffen**: 7-Zip-Builds vor **25.00**. Der Fehler bei der Verarbeitung symbolischer Links wurde in **25.00** (Juli 2025) und späteren Versionen behoben.<sup>[[1]](#references)[[10]](#references)</sup>
* **Auswirkungspfad**: `Start Menu/Programs/Startup` oder Speicherorte, an denen Services ausgeführt werden, überschreiben → Code wird bei der nächsten Anmeldung oder beim Neustart des Service ausgeführt.
* **Kurzes Fixture zur symlink-Verarbeitung (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Dieses Archiv enthält einen symlink-Eintrag, der außerhalb des Extraktionsverzeichnisses zeigt. Verwende ein verwerfbares Ziel und überprüfe, dass der Extractor dem Link nicht folgt. Ein Write-through-Test benötigt außerdem einen regulären Datei-Eintrag unterhalb des symlink.

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Fehler**: `archiver.Unarchive()` kann einen ZIP-symlink extrahieren und ihn anschließend dereferenzieren, wenn ein späteres reguläres Member denselben Namen hat. Dadurch wird aus einem scheinbar innerhalb des Zielverzeichnisses liegenden Schreibvorgang ein Schreibvorgang außerhalb des Zielverzeichnisses.<sup>[[2]](#references)</sup>
* **Betroffen**: `github.com/mholt/archiver` ≤ 3.5.1 (das Projekt ist inzwischen deprecated).<sup>[[2]](#references)</sup>
* **Behebung**: Auf `mholt/archives` ≥ 0.1.0 wechseln oder Links ablehnen und jedes Ziel unmittelbar vor dem Öffnen erneut auflösen.<sup>[[2]](#references)</sup>
* **Minimaler Collision-Generator** (anschließend `archiver.Unarchive("exploit.zip", "/tmp/safe")` aufrufen):<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
link = zipfile.ZipInfo("./x")
link.create_system = 3
link.external_attr = 0o120777 << 16
z.writestr(link, "../../../tmp/PWNED")
z.writestr("./x", b"owned\n")
```

### Umgehung des gefilterten TAR-Extrahierens in CPython (CVE-2026-11940)

Auch `tarfile.extractall(filter="data")` und `filter="tar"` waren von Bypasses durch die Reihenfolge von Links betroffen. In diesem Fall verwies ein Hardlink auf einen symlink, der unter einem tieferen Pfad archiviert war. Die Fallback-Extraktion validierte den relativen symlink an diesem tiefen Speicherort, erstellte ihn jedoch am flacheren Speicherort des Hardlinks neu, wo dasselbe relative Ziel nach außen zeigte. Dies ist ein nützlicher allgemeiner Test: Die Validierung und die Materialisierung sollten bezüglich des Basisverzeichnisses oder des finalen Member-Typs unterschiedliche Annahmen treffen.<sup>[[12]](#references)</sup>

## Tipps zur Erkennung

* **Statische Prüfung** – Liste sowohl Member-Namen als auch Link-Ziele auf. Markiere `../`, `..\\`, absolute/Pfad-bezogene Pfade, symlinks, hardlinks, spezielle Dateien, doppelte Namen, Typänderungen sowie Kollisionen mit äquivalenten Groß-/Kleinschreibungs- oder Unicode-Darstellungen. Behalte bei der Prüfung die Reihenfolge der Einträge bei, da der Exploit von früheren Membern abhängen kann.<sup>[[11]](#references)</sup>
* **Kanonisierung** – Stelle sicher, dass der aufgelöste Parent-Pfad zusammen mit dem finalen Basename unterhalb des aufgelösten Zielverzeichnisses bleibt (Pfadkomponenten vergleichen, nicht nur ein rohes String-Präfix). Nach jedem vorhergehenden Member erneut prüfen. Eine einmalige Prüfung mit `realpath(join(dest, name))` ist durch das Ersetzen von Links verwundbar und kann bei einem noch nicht erstellten Leaf fehlschlagen.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox-Extraktion** – Entpacke in ein neues, verwerfbares Verzeichnis und verwende einen Extractor mit Pfad-/symlink-Prüfungen (beispielsweise die standardmäßigen sicheren Prüfungen von bsdtar oder 7-Zip ≥ 25.00). Überprüfe anschließend, dass der resultierende Baum keine nach außen zeigenden Links enthält. Die Isolation muss verhindern, dass ein bereits ausgelöster Escape Host-Pfade erreicht.<sup>[[1]](#references)[[9]](#references)</sup>
* **Nachgelagerte Lesezugriffe sind relevant** – Ein überlebender symlink oder hardlink kann zu einem Primitive für das Lesen beliebiger Dateien werden, wenn ein Previewer, CDN, Dateibrowser oder eine Package-Pipeline den extrahierten Namen später öffnet oder bereitstellt, selbst wenn die Extraktion selbst keine Datei außerhalb des Zielverzeichnisses erstellt hat.<sup>[[11]](#references)</sup>
* **Endpoint-Monitoring** – Alarmiere bei neuen ausführbaren Dateien, die kurz nach dem Öffnen eines Archivs durch WinRAR/7-Zip/usw. in `Startup`-/`Run`-/`cron`-Speicherorte geschrieben werden.

## Mitigation & Hardening

1. **Extractor aktualisieren** – WinRAR 7.13+ und 7-Zip 25.00+ enthalten Fixes für die genannten Pfad-/symlink-Probleme.<sup>[[1]](#references)[[5]](#references)</sup>
2. Extrahiere Archive nach Möglichkeit mit „**Do not extract paths**“ / „**Ignore paths**“. Bei nicht vertrauenswürdigen Eingaben sollten symbolische Links, Hardlinks, Devices und FIFOs abgelehnt werden, sofern die Anwendung sie nicht ausdrücklich benötigt.<sup>[[9]](#references)[[11]](#references)</sup>
3. Extrahiere in ein **neues leeres Verzeichnis**. Führe nicht vertrauenswürdige Member nicht mit einem Baum zusammen, der vom Angreifer ersetzbare Pfade enthält, und verwende kein Verzeichnis wieder, das von einem früheren Archiv angelegt wurde.<sup>[[11]](#references)</sup>
4. Unter Unix sollten Privilegien abgegeben und das Ziel in einem **chroot/Mount-Namespace** isoliert werden; unter Windows sollte **AppContainer** oder eine Sandbox verwendet werden. Ein Scan nach der Extraktion allein reicht nicht aus, da der Escape-Schreibvorgang vor dem Scan erfolgt.<sup>[[11]](#references)</sup>
5. In benutzerdefiniertem Code müssen die Separator-, Groß-/Kleinschreibungs- und Unicode-Regeln des Zielbetriebssystems angewendet sowie sowohl das Member als auch das Link-Ziel validiert werden. Löse das Ziel auf und öffne es, ohne Links zu folgen. Trenne eine Containment-Prüfung nicht von einem späteren Create-/Replace-Vorgang. Der Validator muss exakt dieselbe Basis und dieselbe Link-Emulation verwenden wie der Schreibpfad.<sup>[[11]](#references)[[12]](#references)</sup>

## Weitere betroffene / historische Fälle

* 2018 – Umfangreiches *Zip-Slip*-Advisory von Snyk, das zahlreiche Java-/Go-/JS-Libraries betraf.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): TAR-Extraktions-Traversal in Slugs (in v0.16.3 behoben).<sup>[[7]](#references)</sup>
* Jede benutzerdefinierte Extraktionslogik, die Header-Strings, aber nicht Link-Ziele und den finalen Dateisystempfad validiert, der für jeden Schreibvorgang verwendet wird.<sup>[[11]](#references)[[12]](#references)</sup>



## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip-symlink-ZIP-Traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Zip Slip in .NET verhindern](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL-Hijack-Kette](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – WinRAR-Tools jetzt aktualisieren: RomCom und andere nutzen Zero-Day-Schwachstelle aus (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Öffentliche Offenlegung einer kritischen Schwachstelle zum Überschreiben beliebiger Dateien: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug ist für Zip-Slip-Angriffe anfällig (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine-Methode](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Sichere Extraktions-Flags von bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Proof-of-Concept-Exploit für CVE-2025-11001 in 7-Zip gemeldet](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Spaß mit zip-slips, tar-slips, symlinks, hardlinks, collisions und mehr](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – Umgehung des tarfile-Extraktionsfilters für CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
{{#include ../banners/hacktricks-training.md}}
