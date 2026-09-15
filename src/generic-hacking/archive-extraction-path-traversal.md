# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Überblick

Viele Archivformate (ZIP, RAR, TAR, 7-ZIP usw.) erlauben es jedem Eintrag, einen eigenen **internen Pfad** zu enthalten. Wenn ein Extraktionsprogramm diesen Pfad blind berücksichtigt, wird ein Dateiname mit `..` oder einem **absoluten Pfad** (z. B. `C:\Windows\System32\`) außerhalb des vom Benutzer ausgewählten Verzeichnisses geschrieben.
Diese Klasse von Schwachstellen ist weithin als *Zip-Slip* oder **archive extraction path traversal** bekannt.<sup>[[6]](#references)</sup>

Die Folgen reichen vom Überschreiben beliebiger Dateien bis hin zur direkten Erreichung von **remote code execution (RCE)**, indem eine Payload an einem **auto-run**-Ort wie dem Windows-Ordner *Startup* abgelegt wird.

## Grundursache

1. Der Angreifer erstellt ein Archiv, in dessen Datei-Headern eine oder mehrere der folgenden Angaben enthalten sind:
* Relative Traversal-Sequenzen (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute Pfade (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Oder speziell erstellte **symlinks**, die außerhalb des Zielverzeichnisses aufgelöst werden (häufig bei ZIP/TAR auf *nix*).
2. Das Opfer extrahiert das Archiv mit einem verwundbaren Tool, das dem eingebetteten Pfad vertraut (oder symlinks folgt), anstatt ihn zu bereinigen oder die Extraktion unterhalb des ausgewählten Verzeichnisses zu erzwingen.
3. Die Datei wird am vom Angreifer kontrollierten Ort geschrieben und beim nächsten Auslösen dieses Pfads durch das System oder den Benutzer ausgeführt/geladen.

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
- Wenn `entry.FullName` mit `..\\` beginnt, erfolgt ein Pfad-Traversal; wenn es sich um einen **absoluten Pfad** handelt, wird die linke Komponente vollständig verworfen, wodurch ein **Schreiben in beliebige Dateien** als Extraktionsidentität ermöglicht wird.
- Proof-of-Concept-Archiv zum Schreiben in ein benachbartes `app`-Verzeichnis, das von einem geplanten Scanner überwacht wird:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Das Ablegen dieser ZIP-Datei im überwachten Posteingang führt zu `C:\samples\app\0xdf.txt` und beweist damit eine Traversal außerhalb von `C:\samples\queue\`, wodurch nachgelagerte Primitives (z. B. DLL hijacks) ermöglicht werden.

## Erweiterte Archive-Breakout-Primitives

Betrachte die Extraktion als eine Abfolge von Dateisystemmutationen und nicht als unabhängige Dateinamenprüfungen. Ein Eintrag, der beim Parsen sicher ist, kann unsicher werden, nachdem ein früheres Mitglied einen Link erstellt oder ersetzt hat; dasselbe Problem tritt auf, wenn ein Extractor ein Verzeichnis als sicher cached und später dessen Typ geändert wird.<sup>[[11]](#references)</sup>

### Link pivots und Kollisionen zwischen Einträgen

* **Symlink write-through**: Erstelle `pivot -> /tmp` und extrahiere anschließend ein reguläres Mitglied als `pivot/PWNED.txt`. Wenn der Extractor dem ersten Mitglied beim Materialisieren des zweiten folgt, entweicht der Schreibvorgang, ohne dass `..` im zweiten Namen enthalten ist.
* **Directory-cache/TOCTOU collision**: Erzeuge das Verzeichnis `d/sub/`, ersetze `d/sub` durch einen Symlink auf `/tmp` und erzeuge anschließend `d/sub/PWNED.txt`. Damit werden Extractors angegriffen, die das Verzeichnis einmal validieren oder cachen und es vor dem abschließenden Schreibvorgang nicht erneut prüfen.
* **Hardlink read/overwrite**: TAR und RAR können Hardlinks darstellen. Ein Hardlink auf eine vorhandene Host-Datei kann deren Inhalt offenlegen, wenn eine spätere Komponente den extrahierten Namen bereitstellt; ein kollidierender regulärer Eintrag kann stattdessen den verknüpften Inode überschreiben. Dies wird durch Regeln für dasselbe Dateisystem und durch Berechtigungen des Betriebssystems zum Erstellen von Hardlinks eingeschränkt.
* **Pre-existing or cross-archive pivot**: Wiederhole den Test mit einem nicht leeren Zielverzeichnis. Ein Archiv kann einen Link platzieren, und eine spätere Extraktion kann durch diesen Link schreiben, selbst wenn jedes Archiv eine zustandslose Prüfung des Header-Namens besteht.<sup>[[11]](#references)</sup>

### Kollisionen durch Dateisystemäquivalenz

Vergleiche Namen anhand der Semantik des Dateisystems, das sie empfangen wird. Nützliche differentielle Fälle umfassen `LINK` gegenüber `link` auf case-insensitiven Dateisystemen, NFC- gegenüber NFD-Unicode-Schreibweisen, kompatibilitätsäquivalente Namen wie `ﬁle` gegenüber `file`, doppelte Mitglieder, die einen Pfad von einem Verzeichnis in einen Symlink ändern, sowie Backslashes, die nur unter Windows als Trennzeichen interpretiert werden. Teste außerdem ADS-haltige Namen auf NTFS. Diese Fälle können dazu führen, dass der Validator zwei Pfade sieht, während das Dateisystem einen einzigen auflöst.<sup>[[5]](#references)[[11]](#references)</sup>

Ein kompaktes Corpus sollte daher geordnete Kombinationen aus **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, gemischten `/` und `\`, absoluten/rooted Namen sowie komprimierten Wrappers wie `.tar.gz` testen. Führe dies nur in einer wegwerfbaren VM/einem Container aus und überwache sowohl das Ziel als auch den vorgesehenen externen Canary-Pfad.<sup>[[11]](#references)</sup>

Die strukturelle Mehrdeutigkeit von ZIP kann dazu führen, dass ein Pre-Scan und der eigentliche Extractor unterschiedliche Eintragsnamen oder Bäume beobachten. Siehe [Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion), anstatt ausschließlich dem Output einer einzelnen ZIP-Library zu vertrauen.

## Praxisbeispiel – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR für Windows sowie dessen Windows-RAR/UnRAR-Komponenten validierten Dateinamen während der Extraktion nicht. Die Schwachstelle nutzte NTFS alternate data streams (ADS), um den ausgewählten Extraktionspfad zu umgehen und Dateien an unbeabsichtigte Speicherorte zu schreiben.<sup>[[5]](#references)</sup>
Ein schädliches RAR-Archiv mit einem Eintrag wie:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
würde schließlich **außerhalb** des ausgewählten Ausgabeordners und innerhalb des *Startup*-Ordners des Benutzers landen. ESET beobachtete, dass dort schädliche LNK-Dateien entpackt und bei der Benutzeranmeldung ausgeführt wurden, wodurch Persistenz und ein Pfad zu RCE ermöglicht wurden.<sup>[[5]](#references)</sup>

### Erstellen eines PoC-Archivs (Linux/Mac)

Da CVE-2025-8088 einen Traversal-Pfad in einem ADS-Namen verwendet, sollte ein speziell dafür entwickelter Generator zum Erstellen des RAR verwendet werden. Die Extraktion darf anschließend nur in einer isolierten Lab-Umgebung mit einem verwundbaren WinRAR-Build getestet werden.<sup>[[5]](#references)</sup>

### Beobachtete Exploitation in freier Wildbahn

ESET berichtete über Spear-Phishing-Kampagnen von RomCom (Storm-0978/UNC2596), bei denen RAR-Archive angehängt wurden, die CVE-2025-8088 ausnutzten, um angepasste Backdoors bereitzustellen und Ransomware-Operationen zu erleichtern.<sup>[[5]](#references)</sup>

## Neuere Fälle (2024–2026)

### 7-Zip-ZIP-Symlink-Traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP-Einträge, die **symbolische Links** waren, wurden während der Extraktion dereferenziert, wodurch Angreifer aus dem Zielverzeichnis ausbrechen und beliebige Pfade überschreiben konnten. Die Benutzerinteraktion beschränkt sich auf das *Öffnen/Extrahieren* des Archivs.<sup>[[1]](#references)</sup>
* **Betroffen**: 7-Zip-Builds vor **25.00**. Der Fehler bei der Verarbeitung symbolischer Links wurde in **25.00** (Juli 2025) und späteren Versionen behoben.<sup>[[1]](#references)[[10]](#references)</sup>
* **Auswirkungspfad**: `Start Menu/Programs/Startup` oder Service-Run-Speicherorte überschreiben → Code wird bei der nächsten Anmeldung oder beim Neustart des Services ausgeführt.
* **Kurzes Fixture zur Verarbeitung symbolischer Links (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Dieses Archiv enthält einen Symlink-Eintrag, der außerhalb des Extraktionsverzeichnisses zeigt. Verwende ein verwerfbares Ziel und überprüfe, dass der Extractor ihm nicht folgt. Ein Write-through-Test benötigt außerdem einen regulären Datei-Eintrag unterhalb des Symlinks.

### Go mholt/archiver `Unarchive()`-Symlink-Kollision (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` kann einen ZIP-Symlink extrahieren und ihn anschließend dereferenzieren, wenn ein späteres reguläres Member denselben Namen hat. Dadurch wird aus einem scheinbar innerhalb des Roots liegenden Write ein Write außerhalb des Roots.<sup>[[2]](#references)</sup>
* **Betroffen**: `github.com/mholt/archiver` ≤ 3.5.1 (das Projekt ist inzwischen deprecated).<sup>[[2]](#references)</sup>
* **Fix**: Auf `mholt/archives` ≥ 0.1.0 wechseln oder Links ablehnen und jedes Ziel unmittelbar vor dem Öffnen erneut auflösen.<sup>[[2]](#references)</sup>
* **Minimaler Kollisionsgenerator** (anschließend `archiver.Unarchive("exploit.zip", "/tmp/safe")` aufrufen):<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
link = zipfile.ZipInfo("./x")
link.create_system = 3
link.external_attr = 0o120777 << 16
z.writestr(link, "../../../tmp/PWNED")
z.writestr("./x", b"owned\n")
```

### Umgehung der gefilterten TAR-Extraktion in CPython (CVE-2026-11940)

Auch `tarfile.extractall(filter="data")` und `filter="tar"` waren von Link-Order-Umgehungen betroffen. In diesem Fall verwies ein Hardlink auf einen Symlink, der an einem tieferen Pfad archiviert war. Die Fallback-Extraktion validierte den relativen Symlink an dieser tiefen Position, erstellte ihn jedoch an der höher liegenden Position des Hardlinks neu, wo dasselbe relative Ziel ausbrach. Dies ist ein nützlicher allgemeiner Test: Die Validierung und die Materialisierung sollen bezüglich des Basisverzeichnisses oder des finalen Member-Typs nicht übereinstimmen.<sup>[[12]](#references)</sup>

### Escape des Hardlink-Ziels in Node `tar` durch eine Symlink-Kette (GHSA-83g3-92jg-28cx)

Das Node.js-`tar`-Package akzeptierte in `tar.extract()` einen Hardlink, dessen Ziel lexikalisch innerhalb des Extraktions-Roots zu liegen schien, sich jedoch durch zwei zuvor erstellte Symlinks außerhalb des Roots auflöste. Der Angriff funktioniert mit den standardmäßigen Extraktionsoptionen: Die Prüfungen des übergeordneten Zielverzeichnisses deckten den In-Root-Namen des Hardlinks ab, während das Hardlink-Ziel an das Dateisystem übergeben wurde, ohne die vollständige Kette zur Prüfung der Zugehörigkeit aufzulösen. `tar` ≤ 7.5.7 ist betroffen; 7.5.8 behebt das Problem.<sup>[[13]](#references)</sup>

Das wichtige Test-Fixture ist die **geordnete Beziehung** zwischen den Membern, nicht diese wörtlichen Namen:<sup>[[13]](#references)</sup>
```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```
Wenn die Extraktion erfolgreich ist, bleibt `exfil` im Ausgabebaum sichtbar, teilt sich jedoch einen Inode mit der ausgewählten Datei außerhalb; das Lesen davon leakt diese Datei, und das Schreiben darauf verändert das Original. Dieses Bypass-Beispiel zeigt, warum die Prüfung ausschließlich des endgültigen Pfads, das Entfernen absoluter Präfixe oder das Blockieren von `..` im hardlink-Header unzureichend ist: Link-Ziele müssen validiert werden, nachdem der gesamte zuvor extrahierte Dateisystemzustand angewendet wurde.<sup>[[13]](#references)</sup>

## Erkennungstipps

* **Statische Prüfung** – Liste sowohl Member-Namen als auch Link-Ziele auf. Markiere `../`, `..\\`, absolute/rooted paths, symlinks, hardlinks, special files, duplicate names, type changes sowie Kollisionen durch äquivalente Groß-/Kleinschreibung oder Unicode-Darstellungen. Bewahre bei der Prüfung die Reihenfolge der Einträge, da der Exploit von früheren Members abhängen kann.<sup>[[11]](#references)</sup>

```bash
bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
7z l -slt suspect.7z          # technical metadata, one field per line
zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
```

* **Kanonisierung** – Stelle sicher, dass der aufgelöste Parent-Pfad plus der endgültige Basename unterhalb des aufgelösten Zielpfads bleibt (vergleiche Pfadkomponenten, nicht ein rohes String-Präfix). Prüfe nach jedem vorhergehenden Member erneut; ein einmaliger Test mit `realpath(join(dest, name))` ist anfällig für den Austausch eines Links und kann bei einem noch nicht erstellten Leaf fehlschlagen.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox-Extraktion** – Dekomprimiere in ein neues, löschbares Verzeichnis mit einem Extractor, der Pfad-/symlink-Prüfungen durchführt (beispielsweise den standardmäßigen sicheren Prüfungen von bsdtar oder 7-Zip ≥ 25.00), und überprüfe anschließend, dass der resultierende Baum keine nach außen gerichteten Links enthält. Die Isolation muss verhindern, dass ein bereits ausgelöstes Entkommen Host-Pfade erreicht.<sup>[[1]](#references)[[9]](#references)</sup>
* **Nachgelagerte Lesezugriffe sind relevant** – Ein überlebender symlink oder hardlink kann zu einem Primitive für beliebiges Datei-Lesen werden, wenn ein Previewer, CDN, Dateibrowser oder eine Package-Pipeline später den extrahierten Namen öffnet oder bereitstellt, selbst wenn die Extraktion selbst keine Datei außerhalb erstellt hat.<sup>[[11]](#references)</sup>
* **Endpoint-Monitoring** – Löse einen Alarm aus, wenn kurz nach dem Öffnen eines Archivs durch WinRAR/7-Zip/usw. neue ausführbare Dateien an `Startup`-/`Run`-/`cron`-Orten geschrieben werden.

## Mitigation & Hardening

1. **Extractor aktualisieren** – WinRAR 7.13+, 7-Zip 25.00+ und Node `tar` 7.5.8+ enthalten Fixes für die genannten Path-/symlink-/link-target-Probleme.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Extrahiere Archive nach Möglichkeit mit „**Do not extract paths**“ / „**Ignore paths**“. Lehne bei nicht vertrauenswürdigen Eingaben symbolic links, hardlinks, devices und FIFOs ab, sofern die Anwendung diese nicht ausdrücklich benötigt.<sup>[[9]](#references)[[11]](#references)</sup>
3. Extrahiere in ein **neues, leeres Verzeichnis**. Führe nicht vertrauenswürdige Members nicht mit einem Baum zusammen, der vom Angreifer ersetzbare Pfade enthält, und verwende kein Verzeichnis erneut, das von einem früheren Archiv angelegt wurde.<sup>[[11]](#references)</sup>
4. Reduziere unter Unix die Berechtigungen und isoliere das Ziel in einem **chroot/mount namespace**; verwende unter Windows **AppContainer** oder eine Sandbox. Ein Scan nach der Extraktion allein ist unzureichend, da ein entkommenes Schreiben vor dem Scan erfolgt.<sup>[[11]](#references)</sup>
5. Wende in benutzerdefiniertem Code die Separator-/Groß-/Kleinschreibungs-/Unicode-Regeln des Zielbetriebssystems an und validiere sowohl das Member als auch das Link-Ziel. Löse das Ziel auf und öffne es, ohne Links zu folgen; trenne eine Containment-Prüfung nicht von einer späteren Create-/Replace-Operation. Der Validator muss exakt dieselbe Basis und dieselbe Link-Emulationssemantik wie der Schreibpfad verwenden.<sup>[[11]](#references)[[12]](#references)</sup>

## Weitere betroffene / historische Fälle

* 2018 – Umfangreiches *Zip-Slip*-Advisory von Snyk, das viele Java-/Go-/JS-Libraries betraf.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): TAR-Extraction-Traversal in Slugs (in v0.16.3 behoben).<sup>[[7]](#references)</sup>
* Jede benutzerdefinierte Extraktionslogik, die Header-Strings, aber nicht Link-Ziele und den endgültigen Dateisystempfad validiert, der für jeden Schreibvorgang verwendet wird.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip-symlink-ZIP-Traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Zip Slip in .NET verhindern](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL-Hijack-Kette](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – WinRAR-Tools jetzt aktualisieren: RomCom und andere nutzen Zero-Day-Schwachstelle aus (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Öffentliche Offenlegung einer kritischen Schwachstelle zum beliebigen Überschreiben von Dateien: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug anfällig für Zip-Slip-Angriff (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine-Methode](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Sichere Extraktions-Flags von bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Proof-of-Concept-Exploit für CVE-2025-11001 in 7-Zip gemeldet](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Spaß beim Hacking mit zip-slips, tar-slips, symlinks, hardlinks, collisions und mehr](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – Umgehung des tarfile-Extraction-Filters bei CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – Entkommen des node-tar-hardlink-Ziels durch symlink-Kette](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
{{#include ../banners/hacktricks-training.md}}
