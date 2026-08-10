# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

## Panoramica

Molti formati di archivio (ZIP, RAR, TAR, 7-ZIP, ecc.) consentono a ogni entry di contenere il proprio **percorso interno**. Quando un'utilità di estrazione rispetta ciecamente quel percorso, un nome file creato ad arte contenente `..` o un **percorso assoluto** (ad esempio `C:\Windows\System32\`) verrà scritto al di fuori della directory scelta dall'utente.
Questa classe di vulnerabilità è comunemente nota come *Zip-Slip* o **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Le conseguenze vanno dalla sovrascrittura di file arbitrari fino a ottenere direttamente la **remote code execution (RCE)** depositando un payload in una posizione di **auto-run**, come la cartella *Startup* di Windows.

## Causa principale

1. L'attaccante crea un archivio in cui una o più intestazioni di file contengono:
* Sequenze di traversal relative (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Percorsi assoluti (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Oppure **symlink** creati ad arte che si risolvono al di fuori della directory di destinazione (comune negli ZIP/TAR su *nix*).
2. La vittima estrae l'archivio con uno strumento vulnerabile che considera attendibile il percorso incorporato (o segue i symlink), invece di sanificarlo o di forzare l'estrazione all'interno della directory scelta.
3. Il file viene scritto nella posizione controllata dall'attaccante ed eseguito/caricato la volta successiva in cui il sistema o l'utente attiva quel percorso.

### .NET `Path.Combine` + `ZipArchive` traversal

Un anti-pattern comune in .NET consiste nel combinare la destinazione prevista con `ZipArchiveEntry.FullName`, controllato dall'utente, ed eseguire l'estrazione senza la normalizzazione del percorso:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Se `entry.FullName` inizia con `..\\`, esegue un traversal; se è un **absolute path**, il componente a sinistra viene scartato interamente, producendo un **arbitrary file write** come identità dell'estrazione.
- Archivio proof-of-concept per scrivere in una directory `app` adiacente monitorata da uno scanner pianificato:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Inserire quel file ZIP nella inbox monitorata crea `C:\samples\app\0xdf.txt`, dimostrando il traversal al di fuori di `C:\samples\queue\` e consentendo primitive successive (ad esempio, DLL hijacks).

## Esempio nel mondo reale – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR per Windows e i suoi componenti Windows RAR/UnRAR non riuscivano a convalidare i nomi dei file durante l'estrazione. La vulnerabilità utilizzava gli alternate data streams (ADS) di NTFS per aggirare il percorso di estrazione selezionato e scrivere file in posizioni non previste.<sup>[[5]](#references)</sup>
Un archivio RAR malevolo contenente un elemento come:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
would end up **outside** the selected output directory and inside the user’s *Startup* folder. ESET observed malicious LNK files being unpacked there and executed at user logon, providing persistence and a path to RCE.<sup>[[5]](#references)</sup>

### Creazione di un archivio PoC (Linux/Mac)

Because CVE-2025-8088 uses a traversal path in an ADS name, use a purpose-built generator to create the RAR, then test extraction only in an isolated lab with a vulnerable WinRAR build.<sup>[[5]](#references)</sup>

### Sfruttamento osservato in the Wild

ESET reported RomCom (Storm-0978/UNC2596) spear-phishing campaigns that attached RAR archives abusing CVE-2025-8088 to deploy customised backdoors and facilitate ransomware operations.<sup>[[5]](#references)</sup>

## Casi più recenti (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. User interaction is just *opening/extracting* the archive.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip builds before **25.00**. The symbolic-link processing flaw was fixed in **25.00** (July 2025) and later.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Overwrite `Start Menu/Programs/Startup` or service-run locations → code runs at next logon or service restart.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
This archive contains a symlink entry pointing outside the extraction directory; use a disposable target and verify that the extractor does not follow it. A write-through test also needs a regular-file entry beneath the symlink.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` follows `../` and symlinked ZIP entries, writing outside `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Fix**: Switch to `mholt/archives` ≥ 0.1.0 or implement canonical-path checks before write.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Suggerimenti per il rilevamento

* **Static inspection** – List archive entries and flag any name containing `../`, `..\\`, *absolute paths* (`/`, `C:`) or entries of type *symlink* whose target is outside the extraction dir.
* **Canonicalisation** – Ensure `realpath(join(dest, name))` stays inside `realpath(dest)` (compare path components, not only a raw string prefix). Reject otherwise.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Decompress into a disposable directory using an extractor with path/symlink checks (for example, bsdtar's default secure checks or 7-Zip ≥ 25.00), then verify resulting paths stay inside the directory.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – Alert on new executables written to `Startup`/`Run`/`cron` locations shortly after an archive is opened by WinRAR/7-Zip/etc.

## Mitigazione e hardening

1. **Update the extractor** – WinRAR 7.13+ and 7-Zip 25.00+ contain fixes for the cited path/symlink issues.<sup>[[1]](#references)[[5]](#references)</sup>
2. Extract archives with “**Do not extract paths**” / “**Ignore paths**” when possible.
3. On Unix, drop privileges & mount a **chroot/namespace** before extraction; on Windows, use **AppContainer** or a sandbox.
4. If writing custom code, normalise with `realpath()`/`PathCanonicalize()` **before** create/write, and reject any entry that escapes the destination.

## Casi aggiuntivi / storici

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (fixed in v0.16.3).<sup>[[7]](#references)</sup>
* Any custom extraction logic that fails to call `PathCanonicalize` / `realpath` prior to write.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Ricerca JFrog – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevenire Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Catena HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Aggiornare subito gli strumenti WinRAR: RomCom e altri sfruttano una vulnerabilità zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgazione pubblica di una vulnerabilità critica di sovrascrittura arbitraria dei file: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug vulnerabile a un attacco Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Metodo Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – flag di estrazione sicura di bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Segnalato un exploit Proof-of-Concept per CVE-2025-11001 in 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
