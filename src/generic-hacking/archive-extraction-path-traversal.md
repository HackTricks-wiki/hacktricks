# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Übersicht

Viele Archivformate (ZIP, RAR, TAR, 7-ZIP usw.) erlauben jedem Eintrag, einen eigenen **internen Pfad** zu enthalten. Wenn ein Extraktionsprogramm diesen Pfad blind berücksichtigt, wird ein präparierter Dateiname mit `..` oder einem **absoluten Pfad** (z. B. `C:\Windows\System32\`) außerhalb des vom Benutzer ausgewählten Verzeichnisses geschrieben.
Diese Schwachstellenklasse ist weithin als *Zip-Slip* oder **archive extraction path traversal** bekannt.<sup>[[6]](#references)</sup>

Die Folgen reichen vom Überschreiben beliebiger Dateien bis zur direkten Ausführung von **remote code execution (RCE)**, indem ein Payload an einem **auto-run**-Ort wie dem Windows-Ordner *Startup* abgelegt wird.

## Ursache

1. Der Angreifer erstellt ein Archiv, in dessen Datei-Headern eine oder mehrere der folgenden Angaben enthalten sind:
* Relative Traversal-Sequenzen (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute Pfade (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Oder präparierte **symlinks**, die außerhalb des Zielverzeichnisses aufgelöst werden (häufig bei ZIP/TAR unter *nix*).
2. Das Opfer extrahiert das Archiv mit einem verwundbaren Tool, das dem eingebetteten Pfad vertraut (oder symlinks folgt), anstatt ihn zu bereinigen oder die Extraktion auf das ausgewählte Verzeichnis zu beschränken.
3. Die Datei wird am vom Angreifer kontrollierten Speicherort geschrieben und ausgeführt/geladen, sobald das System oder der Benutzer diesen Pfad das nächste Mal auslöst.

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
- Wenn `entry.FullName` mit `..\\` beginnt, durchläuft es Verzeichnisse; wenn es sich um einen **absolute path** handelt, wird die linke Komponente vollständig verworfen, wodurch als Extraktionsidentität ein **arbitrary file write** entsteht.
- Proof-of-concept-Archiv zum Schreiben in ein benachbartes `app`-Verzeichnis, das von einem geplanten Scanner überwacht wird:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Das Ablegen dieser ZIP-Datei im überwachten Eingangsordner führt zu `C:\samples\app\0xdf.txt`, wodurch die Traversierung außerhalb von `C:\samples\queue\` nachgewiesen wird und nachgelagerte Primitive (z. B. DLL hijacks) ermöglicht werden.

## Praxisbeispiel – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR für Windows sowie seine Windows-RAR/UnRAR-Komponenten validierten Dateinamen während der Extraktion nicht. Die Schwachstelle nutzte NTFS alternate data streams (ADS), um den ausgewählten Extraktionspfad zu umgehen und Dateien an unbeabsichtigte Speicherorte zu schreiben.<sup>[[5]](#references)</sup>
Ein bösartiges RAR-Archiv mit einem Eintrag wie:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
würde schließlich **außerhalb** des ausgewählten Ausgabeordners und im *Startup*-Ordner des Benutzers landen. ESET beobachtete, dass dort schädliche LNK-Dateien entpackt und bei der Benutzeranmeldung ausgeführt wurden, wodurch Persistenz und ein Pfad zu RCE ermöglicht wurden.<sup>[[5]](#references)</sup>

### Erstellen eines PoC-Archivs (Linux/Mac)

Da CVE-2025-8088 einen Traversal-Pfad in einem ADS-Namen verwendet, sollte ein speziell entwickelter Generator zum Erstellen des RAR verwendet werden. Das Extrahieren darf anschließend nur in einer isolierten Laborumgebung mit einem verwundbaren WinRAR-Build getestet werden.<sup>[[5]](#references)</sup>

### Beobachtete Ausnutzung in freier Wildbahn

ESET berichtete über Spear-Phishing-Kampagnen von RomCom (Storm-0978/UNC2596), bei denen RAR-Archive angehängt wurden, die CVE-2025-8088 missbrauchten, um angepasste Backdoors bereitzustellen und Ransomware-Operationen zu erleichtern.<sup>[[5]](#references)</sup>

## Neuere Fälle (2024–2025)

### 7-Zip ZIP-Symlink-Traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Fehler**: ZIP-Einträge, die **symbolische Links** waren, wurden während des Extrahierens dereferenziert, sodass Angreifer aus dem Zielverzeichnis ausbrechen und beliebige Pfade überschreiben konnten. Die Benutzerinteraktion beschränkt sich auf das *Öffnen/Extrahieren* des Archivs.<sup>[[1]](#references)</sup>
* **Betroffen**: 7-Zip-Builds vor **25.00**. Der Fehler bei der Verarbeitung symbolischer Links wurde in **25.00** (Juli 2025) und späteren Versionen behoben.<sup>[[1]](#references)[[10]](#references)</sup>
* **Auswirkungspfad**: `Start Menu/Programs/Startup` oder Speicherorte, die von Services ausgeführt werden, überschreiben → Code wird bei der nächsten Anmeldung oder beim Neustart des Services ausgeführt.
* **Kurzes Fixture zur Symlink-Verarbeitung (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Dieses Archiv enthält einen Symlink-Eintrag, der auf einen Pfad außerhalb des Extrahierverzeichnisses zeigt. Verwende ein entbehrliches Ziel und überprüfe, dass der Extractor dem Link nicht folgt. Für einen Write-through-Test ist außerdem ein regulärer Datei-Eintrag unterhalb des Symlinks erforderlich.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Fehler**: `archiver.Unarchive()` folgt `../` und symbolischen ZIP-Einträgen und schreibt außerhalb von `outputDir`.<sup>[[2]](#references)</sup>
* **Betroffen**: `github.com/mholt/archiver` ≤ 3.5.1 (das Projekt ist inzwischen veraltet).
* **Behebung**: Auf `mholt/archives` ≥ 0.1.0 umsteigen oder vor dem Schreiben Prüfungen des kanonischen Pfads implementieren.
* **Minimale Reproduktion**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Tipps zur Erkennung

* **Statische Prüfung** – Archiveinträge auflisten und jeden Namen markieren, der `../`, `..\\`, *absolute Pfade* (`/`, `C:`) oder Einträge vom Typ *symlink* enthält, deren Ziel außerhalb des Extrahierverzeichnisses liegt.
* **Kanonisierung** – Sicherstellen, dass `realpath(join(dest, name))` innerhalb von `realpath(dest)` bleibt (Pfadkomponenten vergleichen, nicht nur ein rohes String-Präfix). Andernfalls ablehnen.<sup>[[3]](#references)</sup>
* **Extraktion in einer Sandbox** – In ein entbehrliches Verzeichnis mit einem Extractor entpacken, der Pfad-/Symlink-Prüfungen durchführt (beispielsweise die standardmäßigen sicheren Prüfungen von bsdtar oder 7-Zip ≥ 25.00), und anschließend überprüfen, dass die resultierenden Pfade innerhalb des Verzeichnisses bleiben.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint-Monitoring** – Alarmieren, wenn kurz nachdem ein Archiv mit WinRAR/7-Zip/usw. geöffnet wurde, neue ausführbare Dateien in `Startup`-/`Run`-/`cron`-Speicherorte geschrieben werden.

## Maßnahmen & Härtung

1. **Extractor aktualisieren** – WinRAR 7.13+ und 7-Zip 25.00+ enthalten Fixes für die genannten Pfad-/Symlink-Probleme.<sup>[[1]](#references)[[5]](#references)</sup>
2. Archive nach Möglichkeit mit “**Do not extract paths**” / “**Ignore paths**” extrahieren.
3. Unter Unix Berechtigungen reduzieren und vor dem Extrahieren einen **chroot/namespace** mounten; unter Windows **AppContainer** oder eine Sandbox verwenden.
4. Bei selbst entwickeltem Code vor dem Erstellen/Schreiben mit `realpath()`/`PathCanonicalize()` normalisieren und jeden Eintrag ablehnen, der aus dem Zielverzeichnis ausbricht.

## Weitere betroffene / historische Fälle

* 2018 – Umfangreiche *Zip-Slip*-Meldung von Snyk, die zahlreiche Java-/Go-/JS-Libraries betraf.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): Traversal bei der TAR-Extraktion in Slugs (in v0.16.3 behoben).<sup>[[7]](#references)</sup>
* Jede benutzerdefinierte Extraktionslogik, die vor dem Schreiben `PathCanonicalize` / `realpath` nicht aufruft.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip-Symlink-Traversal in ZIP (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Zip Slip in .NET verhindern](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL-Hijack-Kette](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – WinRAR-Tools jetzt aktualisieren: RomCom und andere nutzen Zero-Day-Schwachstelle aus (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Öffentliche Bekanntgabe einer kritischen Schwachstelle zum beliebigen Überschreiben von Dateien: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug ist für Zip-Slip-Angriffe anfällig (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine-Methode](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Sichere Extraktions-Flags von bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Proof-of-Concept-Exploit für CVE-2025-11001 in 7-Zip gemeldet](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
