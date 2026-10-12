# Archive Extraction Path Traversal („Zip-Slip“)

{{#include ../banners/hacktricks-training.md}}

## Überblick

Viele Archivformate (ZIP, RAR, TAR, 7-ZIP usw.) erlauben es jedem Eintrag, einen eigenen **internen Pfad** zu enthalten. Wenn ein Extraktionsprogramm diesen Pfad ungeprüft übernimmt, wird ein präparierter Dateiname mit `..` oder einem **absoluten Pfad** (z. B. `C:\Windows\System32\`) außerhalb des vom Benutzer ausgewählten Verzeichnisses geschrieben.  
Diese Art von Sicherheitslücke ist weithin als *Zip-Slip* oder **archive extraction path traversal** bekannt.<sup>[[6]](#references)</sup>

Die Folgen reichen vom Überschreiben beliebiger Dateien bis hin zu **Remote Code Execution (RCE)**, indem eine Payload an einem **Autostart**-Speicherort wie dem Windows-Ordner *Startup* abgelegt wird.

## Ursache

1. Der Angreifer erstellt ein Archiv, in dem ein oder mehrere Dateiköpfe Folgendes enthalten:
   * Relative Traversal-Sequenzen (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
   * Absolute Pfade (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
   * Oder präparierte **Symlinks**, die außerhalb des Zielverzeichnisses aufgelöst werden (häufig in ZIP/TAR unter *nix*). 
2. Das Opfer extrahiert das Archiv mit einem verwundbaren Tool, das dem eingebetteten Pfad vertraut (oder Symlinks folgt), statt ihn zu bereinigen oder die Extraktion auf das ausgewählte Verzeichnis zu beschränken.
3. Die Datei wird an einem vom Angreifer kontrollierten Speicherort geschrieben und ausgeführt/geladen, sobald das System oder der Benutzer diesen Pfad das nächste Mal verwendet.

### .NET `Path.Combine` + `ZipArchive` traversal

Ein häufiges .NET-Anti-Pattern besteht darin, das vorgesehene Ziel mit dem **benutzergesteuerten** `ZipArchiveEntry.FullName` zu kombinieren und die Datei ohne Pfadnormalisierung zu extrahieren:<sup>[[4]](#references)[[8]](#references)</sup>

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

- Wenn `entry.FullName` mit `..\\` beginnt, ermöglicht es Path Traversal; bei einem **absoluten Pfad** wird die linke Pfadkomponente vollständig verworfen, wodurch ein **arbitrary file write** als Extraktionsziel möglich ist.
- Proof-of-concept-Archiv, um in ein benachbartes `app`-Verzeichnis zu schreiben, das von einem geplanten Scanner überwacht wird:

```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
    z.writestr("../app/0xdf.txt", "ABCD")
```

Wird diese ZIP-Datei in den überwachten Eingangsordner gelegt, entsteht `C:\samples\app\0xdf.txt`. Das beweist einen traversal außerhalb von `C:\samples\queue\` und ermöglicht nachfolgende Primitives (z. B. DLL-Hijacks).

### Vom Benutzer kontrolliertes Extraktionsverzeichnis

Teste auch das **an den Extractor übergebene Verzeichnis**, nicht nur die Namen der Archiveinträge. Eine Anwendung kann dieses Verzeichnis aus einem Titel, Projektnamen oder einem anderen Request-Feld ableiten. Ein Wert wie `../../../../app/module` kann das Extraktionsverzeichnis aus dem Upload-Bereich verschieben, bevor der Extractor irgendwelche Einträge verarbeitet. In diesem Fall kann sogar ein Archiv, das nur den sicheren Basisnamen `api.py` enthält, Anwendungscode überschreiben.<sup>[[14]](#references)[[15]](#references)</sup>

```python
# Vulnerable pattern: the ZIP entries themselves need no ../ components.
extract_root = os.path.join(site_root, "public", "files", user_title)
archive.extractall(extract_root)
```

Dies ist eine separate Containment-Grenze, unabhängig von klassischem Zip-Slip. Validieren Sie sowohl das aufgelöste Extraktionsverzeichnis als auch jeden aufgelösten Pfad eines Archiveintrags. Eine Prüfung des Stammverzeichnisses kann anhand der Pfadkomponenten statt eines Zeichenfolgenpräfixes erfolgen:<sup>[[14]](#references)</sup>

```python
base = Path(site_root, "public", "files").resolve()
dest = (base / user_title).resolve()
if not dest.is_relative_to(base):
    raise ValueError("extraction root escapes its base")
```

Für einen sicheren Test lädst du ein gültiges Archiv mit einer Canary-Datei hoch und platzierst Pfad-Traversal-Sequenzen in jedem Feld, das das Extraktionsverzeichnis auswählen kann. Überwache sowohl das vorgesehene Verzeichnis als auch einen entbehrlichen Pfad außerhalb davon. Wenn das Ziel ein importiertes Modul erreichen kann, kann dessen Überschreiben bei einem erneuten Laden der Worker zu code execution führen; ein HTTP 500 oder ein Verbindungsabbruch während dieses Neuladens beweist nicht, dass der Schreibvorgang fehlgeschlagen ist.<sup>[[14]](#references)[[15]](#references)</sup> Siehe auch die umfassendere [Methodik für Datei-Uploads](../pentesting-web/file-upload/).

## Erweiterte Archive-Breakout-Primitiven

Betrachte die Extraktion als eine Abfolge von Dateisystemänderungen und nicht als unabhängige Prüfungen von Dateinamen. Ein Eintrag, der beim Parsen sicher ist, kann unsicher werden, nachdem ein früheres Archivelement einen Link erstellt oder ersetzt hat. Dasselbe Problem tritt auf, wenn ein Extraktor ein Verzeichnis als sicher zwischenspeichert und dessen Typ später geändert wird.<sup>[[11]](#references)</sup>

### Link-Pivots und Eintragskollisionen

* **Symlink-Schreibzugriff**: Erstelle `pivot -> /tmp` und extrahiere anschließend ein reguläres Archivelement als `pivot/PWNED.txt`. Wenn der Extraktor dem ersten Eintrag beim Materialisieren des zweiten folgt, wird der Schreibvorgang aus dem Zielverzeichnis herausgeleitet, ohne dass der zweite Name `..` enthält.
* **Verzeichniscache-/TOCTOU-Kollision**: Erzeuge das Verzeichnis `d/sub/`, ersetze `d/sub` durch einen Symlink auf `/tmp` und erzeuge anschließend `d/sub/PWNED.txt`. Damit werden Extraktoren angegriffen, die das Verzeichnis nur einmal validieren oder zwischenspeichern und es vor dem abschließenden Schreibvorgang nicht erneut prüfen.
* **Hardlink-Lesezugriff/Überschreiben**: TAR und RAR können Hardlinks enthalten. Ein Hardlink auf eine vorhandene Hostdatei kann deren Inhalt offenlegen, wenn eine spätere Komponente den extrahierten Namen bereitstellt; ein kollidierender regulärer Eintrag kann stattdessen den verlinkten Inode überschreiben. Dies wird durch Regeln für dasselbe Dateisystem und die Berechtigungsregeln des Betriebssystems für Hardlinks eingeschränkt.
* **Vorhandener oder archivübergreifender Pivot**: Wiederhole den Test mit einem nicht leeren Zielverzeichnis. Ein Archiv kann einen Link platzieren, über den eine spätere Extraktion schreibt, selbst wenn jedes Archiv eine zustandslose Prüfung der Namen im Header besteht.<sup>[[11]](#references)</sup>

### Kollisionen durch Dateisystem-Äquivalenz

Vergleiche Namen anhand der Semantik des Dateisystems, in das sie geschrieben werden. Nützliche Differenzfälle sind `LINK` gegenüber `link` auf nicht zwischen Groß- und Kleinschreibung unterscheidenden Dateisystemen, NFC- gegenüber NFD-Unicode-Schreibweisen, kompatibilitätsäquivalente Namen wie `ﬁle` gegenüber `file`, doppelte Archivelemente, die einen Pfad von einem Verzeichnis in einen Symlink ändern, sowie Backslashes, die nur unter Windows als Trennzeichen interpretiert werden. Teste außerdem Namen mit ADS unter NTFS. Dadurch kann der Validator zwei Pfade sehen, während das Dateisystem sie als einen auflöst.<sup>[[5]](#references)[[11]](#references)</sup>

Ein kompaktes Testkorpus sollte daher geordnete Kombinationen aus **Verzeichnis → Symlink → Unterelement**, **Symlink → kollidierende reguläre Datei**, **Hardlink → kollidierende reguläre Datei**, gemischten `/` und `\`, absoluten/verankerten Namen und komprimierten Wrappern wie `.tar.gz` testen. Führe die Tests nur in einer entbehrlichen VM oder einem Container aus und überwache sowohl das Zielverzeichnis als auch den vorgesehenen externen Canary-Pfad.<sup>[[11]](#references)</sup>

ZIP-spezifische strukturelle Mehrdeutigkeiten können dazu führen, dass ein Vorscan und der eigentliche Extraktor unterschiedliche Eintragsnamen oder Verzeichnisbäume erkennen. Siehe [Verwechslung von Local-Header- und Central-Directory-Parsern](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion), anstatt nur dem Ergebnis einer einzelnen ZIP-Bibliothek zu vertrauen.

## Praxisbeispiel – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR für Windows und seine Windows-Komponenten RAR/UnRAR validierten Dateinamen bei der Extraktion nicht. Die Schwachstelle nutzte NTFS Alternate Data Streams (ADS), um den ausgewählten Extraktionspfad zu umgehen und Dateien an unbeabsichtigte Speicherorte zu schreiben.<sup>[[5]](#references)</sup>
Ein bösartiges RAR-Archiv mit einem Eintrag wie:

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```

würde **außerhalb** des ausgewählten Ausgabeverzeichnisses und im *Startup*-Ordner des Benutzers landen. ESET beobachtete, dass dort schädliche LNK-Dateien entpackt und bei der Benutzeranmeldung ausgeführt wurden, was Persistenz und einen Weg zu RCE ermöglichte.<sup>[[5]](#references)</sup>

### Erstellen eines PoC-Archivs (Linux/Mac)

Da CVE-2025-8088 einen Traversal-Pfad in einem ADS-Namen verwendet, sollte das RAR-Archiv mit einem speziell dafür entwickelten Generator erstellt und das Entpacken nur in einer isolierten Testumgebung mit einem verwundbaren WinRAR-Build getestet werden.<sup>[[5]](#references)</sup>

### Beobachtete Exploitation in freier Wildbahn

ESET berichtete über Spear-Phishing-Kampagnen von RomCom (Storm-0978/UNC2596), bei denen RAR-Archive angehängt wurden, die CVE-2025-8088 ausnutzten, um angepasste Backdoors bereitzustellen und Ransomware-Aktivitäten zu ermöglichen.<sup>[[5]](#references)</sup>

## Neuere Fälle (2024–2026)

### 7-Zip-ZIP-Symlink-Traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Fehler**: ZIP-Einträge, die **symbolische Links** waren, wurden beim Entpacken dereferenziert. Dadurch konnten Angreifer das Zielverzeichnis verlassen und beliebige Pfade überschreiben. Die Benutzerinteraktion beschränkt sich auf das *Öffnen/Entpacken* des Archivs.<sup>[[1]](#references)</sup>
* **Betroffen**: 7-Zip-Builds vor **25.00**. Der Fehler bei der Verarbeitung symbolischer Links wurde in **25.00** (Juli 2025) und späteren Versionen behoben.<sup>[[1]](#references)[[10]](#references)</sup>
* **Auswirkungspfad**: `Start Menu/Programs/Startup` oder von Diensten verwendete Pfade überschreiben → Code wird bei der nächsten Anmeldung oder beim Neustart des Dienstes ausgeführt.
* **Kurzes Testbeispiel zur Symlink-Verarbeitung (Linux)**:
  ```bash
  mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
  ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
  cd /tmp/archive-slip-test
  zip -y exploit.zip evil   # -y preserves symlinks
  7z x exploit.zip -o/tmp/archive-slip-target
  ```
  Dieses Archiv enthält einen symlink-Eintrag, der außerhalb des Extraktionsverzeichnisses verweist. Verwende ein entbehrliches Ziel und überprüfe, dass der Extractor diesem Verweis nicht folgt. Für einen Write-through-Test ist außerdem ein regulärer Datei-Eintrag unterhalb des symlink erforderlich.

### Go mholt/archiver `Unarchive()`-symlink-Kollision (CVE-2025-3445)
* **Fehler**: `archiver.Unarchive()` kann einen ZIP-symlink extrahieren und ihn anschließend dereferenzieren, wenn ein späteres reguläres Mitglied denselben Namen hat. Dadurch wird aus einem scheinbar innerhalb des Zielverzeichnisses stattfindenden Schreibvorgang ein Schreibvorgang außerhalb davon.<sup>[[2]](#references)</sup>
* **Betroffen**: `github.com/mholt/archiver` ≤ 3.5.1 (das Projekt ist inzwischen veraltet).<sup>[[2]](#references)</sup>
* **Behebung**: Wechsle zu `mholt/archives` ≥ 0.1.0 oder weise Links zurück und löse jedes Ziel unmittelbar vor dem Öffnen erneut auf.<sup>[[2]](#references)</sup>
* **Minimaler Kollisionsgenerator** (rufe anschließend `archiver.Unarchive("exploit.zip", "/tmp/safe")` auf):<sup>[[2]](#references)</sup>
  ```python
  import zipfile

  with zipfile.ZipFile("exploit.zip", "w") as z:
      link = zipfile.ZipInfo("./x")
      link.create_system = 3
      link.external_attr = 0o120777 << 16
      z.writestr(link, "../../../tmp/PWNED")
      z.writestr("./x", b"owned\n")
  ```

### Umgehung der CPython-TAR-Extraktionsfilter (CVE-2026-11940)

Auch `tarfile.extractall(filter="data")` und `filter="tar"` waren anfällig für Bypässe durch die Reihenfolge von Links. In diesem Fall verwies ein hardlink auf einen Symlink, der in einem tiefer liegenden Pfad archiviert war. Beim Fallback-Extrahieren wurde der relative Symlink am tiefer liegenden Speicherort validiert, aber am höher liegenden Speicherort des hardlinks neu erstellt, wo dasselbe relative Ziel aus dem Extraktionsverzeichnis herausführte. Ein sinnvoller allgemeiner Test: Dafür sorgen, dass sich Validierung und Materialisierung hinsichtlich des Basisverzeichnisses oder des endgültigen Member-Typs unterscheiden.<sup>[[12]](#references)</sup>

### Umgehung des hardlink-Zielpfads im Node-`tar`-Paket über eine Symlink-Kette (GHSA-83g3-92jg-28cx)

Das Node.js-`tar`-Paket akzeptierte mit `tar.extract()` einen hardlink, dessen Ziel lexikalisch innerhalb des Extraktionsverzeichnisses zu liegen schien, aber über zwei zuvor angelegte Symlinks nach außen führte. Der Angriff funktioniert mit den Standardoptionen für das Extrahieren: Prüfungen des Zielverzeichnisses deckten den In-Root-Namen des hardlinks ab, während das hardlink-Ziel an das Dateisystem übergeben wurde, ohne die vollständige Kette auf Begrenzung innerhalb des Extraktionsverzeichnisses zu prüfen. `tar` ≤ 7.5.7 ist betroffen; 7.5.8 behebt das Problem.<sup>[[13]](#references)</sup>

Entscheidend für die Test-Fixture ist die **Reihenfolge der Beziehung** zwischen den Membern, nicht deren konkrete Namen:<sup>[[13]](#references)</sup>

```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```

Wenn die Extraktion erfolgreich ist, bleibt `exfil` sichtbar im Ausgabebaum, teilt sich aber einen Inode mit der ausgewählten Datei außerhalb des Baums. Wenn man `exfil` liest, wird diese Datei geleakt; wenn man hineinschreibt, wird das Original geändert. Dieser Bypass zeigt, warum es nicht ausreicht, nur den endgültigen Pfad zu prüfen, absolute Präfixe zu entfernen oder `..` im hardlink-Header zu blockieren: Link-Ziele müssen validiert werden, nachdem der gesamte zuvor extrahierte Dateisystemzustand berücksichtigt wurde.<sup>[[13]](#references)</sup>

## Erkennungstipps

* **Statische Prüfung** – Liste sowohl die Namen der Einträge als auch die Link-Ziele auf. Achte auf `../`, `..\\`, absolute/verankerte Pfade, symlinks, hardlinks, Spezialdateien, doppelte Namen, Typänderungen sowie Kollisionen durch gleichwertige Schreibweisen mit anderer Groß-/Kleinschreibung oder Unicode-Darstellung. Behalte bei der Prüfung die Reihenfolge der Einträge bei, da der Exploit von früheren Einträgen abhängen kann.<sup>[[11]](#references)</sup>

  ```bash
  bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
  7z l -slt suspect.7z          # technical metadata, one field per line
  zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
  ```

* **Kanonisierung** – Stelle sicher, dass das aufgelöste Elternverzeichnis plus endgültiger Basisname unterhalb des aufgelösten Ziels bleibt (vergleiche Pfadkomponenten, nicht ein rohes String-Präfix). Prüfe nach jedem vorherigen Archiveintrag erneut; eine einmalige Prüfung mit `realpath(join(dest, name))` ist anfällig für den Austausch von Links und kann bei einem noch nicht erstellten Blatt fehlschlagen.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox-Extraktion** – Entpacke in ein neues, entbehrliches Verzeichnis und verwende einen Extractor mit Pfad-/Symlink-Prüfungen (zum Beispiel die standardmäßigen sicheren Prüfungen von bsdtar oder 7-Zip ≥ 25.00). Prüfe anschließend, dass der resultierende Verzeichnisbaum keine nach außen verweisenden Links enthält. Die Isolation muss verhindern, dass ein bereits ausgelöster Ausbruch Host-Pfade erreicht.<sup>[[1]](#references)[[9]](#references)</sup>
* **Nachgelagerte Lesezugriffe sind relevant** – Ein verbleibender Symlink oder Hardlink kann zum Primitive für beliebige Dateizugriffe werden, wenn ein Previewer, CDN, Dateibrowser oder eine Package-Pipeline den entpackten Namen später öffnet oder bereitstellt – selbst wenn beim Entpacken selbst keine Datei außerhalb des Ziels erstellt wurde.<sup>[[11]](#references)</sup>
* **Endpoint-Überwachung** – Alarmiere, wenn kurz nachdem ein Archiv mit WinRAR/7-Zip/etc. geöffnet wurde, neue ausführbare Dateien in `Startup`-/`Run`-/`cron`-Verzeichnisse geschrieben werden.

## Mitigation & Härtung

1. **Extractor aktualisieren** – WinRAR 7.13+, 7-Zip 25.00+ und Node `tar` 7.5.8+ enthalten Fixes für die genannten Probleme mit Pfaden, Symlinks und Link-Zielen.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Entpacke Archive, wenn möglich, mit „**Pfade nicht entpacken**“ / „**Pfade ignorieren**“. Lehne bei nicht vertrauenswürdigen Eingaben symbolische Links, Hardlinks, Geräte und FIFOs ab, sofern die Anwendung sie nicht ausdrücklich benötigt.<sup>[[9]](#references)[[11]](#references)</sup>
3. Entpacke in ein **neues, leeres Verzeichnis**. Führe nicht vertrauenswürdige Archiveinträge nicht mit einem Verzeichnisbaum zusammen, der Pfade enthält, die ein Angreifer ersetzen kann, und verwende kein Verzeichnis erneut, das durch ein früheres Archiv vorbereitet wurde.<sup>[[11]](#references)</sup>
4. Unter Unix: Entziehe Berechtigungen und isoliere das Ziel in einem **chroot/Mount-Namespace**; unter Windows: Verwende **AppContainer** oder eine Sandbox. Ein Scan nach dem Entpacken reicht nicht aus, da ein Schreibzugriff nach außen bereits vor dem Scan erfolgt.<sup>[[11]](#references)</sup>
5. Verwende in benutzerdefiniertem Code die Trennzeichen-, Groß-/Kleinschreibungs- und Unicode-Regeln des Zielbetriebssystems und validiere sowohl den Archiveintrag als auch das Link-Ziel. Löse das Ziel auf und öffne es, ohne Links zu folgen; trenne eine Prüfung auf Pfadbeschränkung nicht von einem späteren Erstellen/Ersetzen. Der Validator muss dieselbe Basis und dieselbe Link-Emulationssemantik wie der Schreibpfad verwenden.<sup>[[11]](#references)[[12]](#references)</sup>

## Weitere betroffene / historische Fälle

* 2018 – Umfangreiche *Zip-Slip*-Warnung von Snyk, die zahlreiche Java-/Go-/JS-Bibliotheken betrifft.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): TAR-Extraktions-Traversal in Slugs (behoben in v0.16.3).<sup>[[7]](#references)</sup>
* Jede benutzerdefinierte Extraktionslogik, die Header-Strings validiert, aber nicht Link-Ziele und den endgültigen Dateisystempfad, der für jeden Schreibzugriff verwendet wird.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip-Symlink-Traversal in ZIP-Archiven (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – Zip-Slip in mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Zip Slip in .NET verhindern](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno: ZipSlip → DLL-Hijack-Kette](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Aktualisiere jetzt die WinRAR-Tools: RomCom und andere nutzen Zero-Day-Schwachstelle aus (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Öffentliche Offenlegung einer kritischen Schwachstelle zum beliebigen Überschreiben von Dateien: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug anfällig für Zip-Slip-Angriff (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine-Methode](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Sichere Extraktionsoptionen von bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Proof-of-Concept-Exploit für CVE-2025-11001 in 7-Zip gemeldet](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Hacking-Spaß mit Zip-Slips, Tar-Slips, Symlinks, Hardlinks, Kollisionen und mehr](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – Umgehung des tarfile-Extraktionsfilters (CVE-2026-11940)](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – Entkommen aus dem Hardlink-Ziel von node-tar über eine Symlink-Kette](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
- [14] [Rhino Security Labs CVE PoC – Vom Benutzer kontrolliertes SCORM-Extraktionsverzeichnis](https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/master/CVE-2026-39405/README.md)
- [15] [Rhino Security Labs – Mehrere Schwachstellen in Frappe LMS führen zu Remote Code Execution](https://rhinosecuritylabs.com/research/multiple-vulnerabilities-in-frappe-lms-leading-to-remote-code-execution/)
{{#include ../banners/hacktricks-training.md}}
