# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Panoramica

Molti formati di archivio (ZIP, RAR, TAR, 7-ZIP, ecc.) consentono a ogni entry di contenere il proprio **percorso interno**. Quando un'utility di estrazione considera ciecamente attendibile quel percorso, un nome file appositamente creato contenente `..` o un **percorso assoluto** (ad esempio `C:\Windows\System32\`) verrà scritto al di fuori della directory scelta dall'utente.
Questa classe di vulnerabilità è ampiamente nota come *Zip-Slip* o **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Le conseguenze vanno dalla sovrascrittura di file arbitrari fino all'ottenimento diretto della **remote code execution (RCE)** tramite il rilascio di un payload in una posizione di **auto-run**, come la cartella *Startup* di Windows.

## Causa principale

1. L'attaccante crea un archivio in cui uno o più header dei file contengono:
* Sequenze di traversal relative (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Percorsi assoluti (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Oppure **symlink** appositamente creati che si risolvono al di fuori della directory di destinazione (comune negli ZIP/TAR su *nix*).
2. La vittima estrae l'archivio con uno strumento vulnerabile che considera attendibile il percorso incorporato (o segue i symlink) invece di sanificarlo o di forzare l'estrazione all'interno della directory scelta.
3. Il file viene scritto nella posizione controllata dall'attaccante ed eseguito/caricato la volta successiva in cui il sistema o l'utente attiva quel percorso.

### Traversal `.NET` `Path.Combine` + `ZipArchive`

Un anti-pattern comune in .NET consiste nel combinare la destinazione prevista con `ZipArchiveEntry.FullName`, controllato dall'utente, ed eseguire l'estrazione senza normalizzare il percorso:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Se `entry.FullName` inizia con `..\\`, esegue un traversal; se è un **percorso assoluto**, il componente a sinistra viene completamente scartato, ottenendo una **scrittura arbitraria di file** come identità dell'estrazione.
- Archivio proof-of-concept per scrivere in una directory `app` adiacente monitorata da uno scanner pianificato:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
L'inserimento di quello ZIP nella inbox monitorata produce `C:\samples\app\0xdf.txt`, dimostrando il traversal al di fuori di `C:\samples\queue\` e abilitando primitive successive (ad esempio, DLL hijacks).

## Esempio reale – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR per Windows e i suoi componenti Windows RAR/UnRAR non riuscivano a validare i nomi dei file durante l'estrazione. La vulnerabilità utilizzava gli alternate data streams (ADS) di NTFS per eludere il percorso di estrazione selezionato e scrivere file in posizioni non previste.<sup>[[5]](#references)</sup>
Un archivio RAR dannoso contenente una voce come:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
finirebbe **all'esterno** della directory di output selezionata e all'interno della cartella *Startup* dell'utente. ESET ha osservato file LNK dannosi decompressi lì ed eseguiti al logon dell'utente, fornendo persistenza e una strada verso RCE.<sup>[[5]](#references)</sup>

### Creazione di un archivio PoC (Linux/Mac)

Poiché CVE-2025-8088 usa un path di traversal in un nome ADS, utilizza un generatore dedicato per creare il RAR, quindi testa l'estrazione solo in un lab isolato con una build vulnerabile di WinRAR.<sup>[[5]](#references)</sup>

### Sfruttamento osservato in the Wild

ESET ha segnalato campagne di spear-phishing di RomCom (Storm-0978/UNC2596) che allegavano archivi RAR sfruttando CVE-2025-8088 per distribuire backdoor personalizzate e facilitare operazioni ransomware.<sup>[[5]](#references)</sup>

## Casi più recenti (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: le voci ZIP che erano **symbolic link** venivano dereferenziate durante l'estrazione, consentendo agli attacker di uscire dalla directory di destinazione e sovrascrivere path arbitrari. L'interazione dell'utente consiste semplicemente nell'*aprire/estrarre* l'archivio.<sup>[[1]](#references)</sup>
* **Affected**: build di 7-Zip precedenti alla **25.00**. Il flaw nell'elaborazione dei symbolic link è stato corretto nella **25.00** (luglio 2025) e successive.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: sovrascrivere `Start Menu/Programs/Startup` o posizioni di esecuzione dei servizi → il codice viene eseguito al logon successivo o al riavvio del servizio.
* **Fixture rapida per la gestione dei symlink (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Questo archivio contiene una voce symlink che punta all'esterno della directory di estrazione; utilizza una destinazione usa e getta e verifica che l'extractor non la segua. Un test di write-through richiede inoltre una voce regular-file sotto il symlink.

### Zip-Slip di Go mholt/archiver Unarchive() (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` segue `../` e le voci ZIP symlink, scrivendo all'esterno di `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (il progetto è ora deprecato).
* **Fix**: passa a `mholt/archives` ≥ 0.1.0 o implementa controlli sui canonical path prima della scrittura.
* **Riproduzione minima**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Suggerimenti per il rilevamento

* **Ispezione statica** – Elenca le voci dell'archivio e segnala qualsiasi nome contenente `../`, `..\\`, *path assoluti* (`/`, `C:`) o voci di tipo *symlink* il cui target si trovi all'esterno della directory di estrazione.
* **Canonicalizzazione** – Assicurati che `realpath(join(dest, name))` resti all'interno di `realpath(dest)` (confronta i componenti del path, non solo un raw string prefix). Rifiuta altrimenti.<sup>[[3]](#references)</sup>
* **Estrazione in sandbox** – Decomprime in una directory usa e getta utilizzando un extractor con controlli su path/symlink (ad esempio i controlli secure predefiniti di bsdtar o 7-Zip ≥ 25.00), quindi verifica che i path risultanti restino all'interno della directory.<sup>[[1]](#references)[[9]](#references)</sup>
* **Monitoraggio degli endpoint** – Genera un alert quando vengono scritti nuovi eseguibili nelle posizioni `Startup`/`Run`/`cron` poco dopo l'apertura di un archivio tramite WinRAR/7-Zip/ecc.

## Mitigazione e hardening

1. **Aggiorna l'extractor** – WinRAR 7.13+ e 7-Zip 25.00+ contengono fix per i problemi relativi a d path/symlink.<sup>[[1]](#references)[[5]](#references)</sup>
2. Estrai gli archivi con “**Do not extract paths**” / “**Ignore paths**” quando possibile.
3. Su Unix, riduci i privilegi e monta un **chroot/namespace** prima dell'estrazione; su Windows, usa **AppContainer** o una sandbox.
4. Se scrivi codice personalizzato, normalizza con `realpath()`/`PathCanonicalize()` **prima** di create/write e rifiuta qualsiasi voce che esca dalla destinazione.

## Casi aggiuntivi / storici interessati

* 2018 – Advisory *Zip-Slip* di grandi dimensioni pubblicato da Snyk, che interessava numerose librerie Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – `go-slug` di HashiCorp (CVE-2025-0377), traversal durante l'estrazione TAR negli slug (corretto nella v0.16.3).<sup>[[7]](#references)</sup>
* Qualsiasi logica di estrazione personalizzata che non chiami `PathCanonicalize` / `realpath` prima della scrittura.

## References

- [1] [Trend Micro ZDI-25-949 – traversal di symlink ZIP in 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – Zip-Slip di mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevenire Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – catena HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Aggiorna subito gli strumenti WinRAR: RomCom e altri sfruttano una vulnerabilità zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgazione pubblica di una vulnerabilità critica di sovrascrittura arbitraria dei file: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug di HashiCorp vulnerabile a un attacco Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Metodo Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – flag di estrazione sicura di bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Segnalato un exploit Proof-of-Concept per CVE-2025-11001 in 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
