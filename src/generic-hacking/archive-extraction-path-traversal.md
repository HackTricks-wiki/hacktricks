# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Panoramica

Molti formati di archivio (ZIP, RAR, TAR, 7-ZIP, ecc.) consentono a ogni elemento di contenere il proprio **percorso interno**. Quando un'utilità di estrazione rispetta ciecamente tale percorso, un nome file appositamente creato contenente `..` o un **percorso assoluto** (ad esempio `C:\Windows\System32\`) verrà scritto al di fuori della directory scelta dall'utente.
Questa classe di vulnerabilità è ampiamente nota come *Zip-Slip* o **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Le conseguenze vanno dalla sovrascrittura di file arbitrari fino a ottenere direttamente la **remote code execution (RCE)** mediante il rilascio di un payload in una posizione **auto-run**, come la cartella *Startup* di Windows.

## Causa principale

1. L'attacker crea un archivio in cui uno o più header dei file contengono:
* Sequenze di traversal relative (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Percorsi assoluti (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Oppure **symlink** appositamente creati che puntano al di fuori della directory di destinazione (comune negli archivi ZIP/TAR su *nix*).
2. La vittima estrae l'archivio con uno strumento vulnerabile che considera attendibile il percorso incorporato (o segue i symlink), invece di sanificarlo o forzare l'estrazione all'interno della directory scelta.
3. Il file viene scritto nella posizione controllata dall'attacker ed eseguito/caricato la volta successiva in cui il sistema o l'utente attiva quel percorso.

### Traversal con `.NET` `Path.Combine` + `ZipArchive`

Un anti-pattern comune in .NET consiste nel combinare la destinazione prevista con `ZipArchiveEntry.FullName`, controllato dall'utente, ed estrarre senza normalizzare il percorso:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Se `entry.FullName` inizia con `..\\`, esegue il traversal; se è un **absolute path**, il componente a sinistra viene completamente scartato, ottenendo un **arbitrary file write** come identità dell'estrazione.
- Archive proof-of-concept per scrivere in una directory `app` adiacente monitorata da uno scanner pianificato:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
L'inserimento di quello ZIP nella inbox monitorata produce `C:\samples\app\0xdf.txt`, dimostrando un path traversal al di fuori di `C:\samples\queue\` e abilitando primitive successive (ad esempio, DLL hijacks).

## Esempio reale – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR per Windows e i relativi componenti Windows RAR/UnRAR non riuscivano a convalidare i nomi dei file durante l'estrazione. La vulnerabilità utilizzava gli alternate data streams (ADS) di NTFS per aggirare il percorso di estrazione selezionato e scrivere file in posizioni non previste.<sup>[[5]](#references)</sup>
Un archivio RAR malevolo contenente una voce come:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
finirebbe **al di fuori** della directory di output selezionata e all’interno della cartella *Startup* dell’utente. ESET ha osservato file LNK malevoli estratti in quella posizione ed eseguiti al logon dell’utente, fornendo persistenza e un percorso verso RCE.<sup>[[5]](#references)</sup>

### Creazione di un archivio PoC (Linux/Mac)

Poiché CVE-2025-8088 utilizza un percorso di traversal nel nome di un ADS, usa un generatore appositamente creato per produrre il RAR, quindi testa l’estrazione esclusivamente in un lab isolato con una build vulnerabile di WinRAR.<sup>[[5]](#references)</sup>

### Sfruttamento osservato in the Wild

ESET ha riportato campagne di spear-phishing di RomCom (Storm-0978/UNC2596) che allegavano archivi RAR sfruttando CVE-2025-8088 per distribuire backdoor personalizzate e agevolare operazioni ransomware.<sup>[[5]](#references)</sup>

## Casi più recenti (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: le entry ZIP che erano **symbolic link** venivano dereferenziate durante l’estrazione, consentendo agli attacker di uscire dalla directory di destinazione e sovrascrivere percorsi arbitrari. L’interazione dell’utente consiste semplicemente nell’*aprire/estrarre* l’archivio.<sup>[[1]](#references)</sup>
* **Affected**: build di 7-Zip precedenti alla **25.00**. Il flaw nell’elaborazione dei symbolic link è stato corretto nella **25.00** (luglio 2025) e nelle versioni successive.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: sovrascrivere `Start Menu/Programs/Startup` o posizioni usate dai servizi → il codice viene eseguito al logon successivo o al riavvio del servizio.
* **Fixture rapida per la gestione dei symlink (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Questo archivio contiene una entry symlink che punta al di fuori della directory di estrazione; usa una destinazione usa e getta e verifica che l’estrattore non la segua. Un test di write-through richiede inoltre una entry regular-file sotto il symlink.

### Zip-Slip di Go mholt/archiver Unarchive() (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` segue `../` e le entry ZIP symlink, scrivendo al di fuori di `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (il progetto è ora deprecato).
* **Fix**: passa a `mholt/archives` ≥ 0.1.0 oppure implementa controlli sui percorsi canonicali prima della scrittura.
* **Riproduzione minima**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Suggerimenti per il rilevamento

* **Ispezione statica** – Elenca le entry dell’archivio e segnala qualsiasi nome contenente `../`, `..\\`, *percorsi assoluti* (`/`, `C:`) o entry di tipo *symlink* il cui target si trovi al di fuori della directory di estrazione.
* **Canonicalizzazione** – Assicurati che `realpath(join(dest, name))` rimanga all’interno di `realpath(dest)` (confronta i componenti del percorso, non solo un prefisso stringa grezzo). Rifiuta il percorso in caso contrario.<sup>[[3]](#references)</sup>
* **Estrazione in sandbox** – Decomprimi in una directory usa e getta usando un estrattore con controlli su percorsi/symlink (per esempio i controlli secure predefiniti di bsdtar o 7-Zip ≥ 25.00), quindi verifica che i percorsi risultanti rimangano all’interno della directory.<sup>[[1]](#references)[[9]](#references)</sup>
* **Monitoraggio degli endpoint** – Genera un alert quando vengono scritti nuovi eseguibili nelle posizioni `Startup`/`Run`/`cron` poco dopo l’apertura di un archivio con WinRAR/7-Zip/ecc.

## Mitigazione e hardening

1. **Aggiorna l’estrattore** – WinRAR 7.13+ e 7-Zip 25.00+ contengono fix per i problemi di path/symlink citati.<sup>[[1]](#references)[[5]](#references)</sup>
2. Quando possibile, estrai gli archivi con “**Do not extract paths**” / “**Ignore paths**”.
3. Su Unix, riduci i privilegi e monta un **chroot/namespace** prima dell’estrazione; su Windows, usa **AppContainer** o una sandbox.
4. Se scrivi codice personalizzato, normalizza con `realpath()`/`PathCanonicalize()` **prima** di creare/scrivere e rifiuta qualsiasi entry che esca dalla destinazione.

## Casi aggiuntivi / storici affected

* 2018 – Advisory *Zip-Slip* su larga scala di Snyk, che interessava numerose librerie Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – `go-slug` di HashiCorp (CVE-2025-0377), traversal durante l’estrazione TAR negli slug (corretto nella v0.16.3).<sup>[[7]](#references)</sup>
* Qualsiasi logica di estrazione personalizzata che non chiami `PathCanonicalize` / `realpath` prima della scrittura.

## References

- [1] [Trend Micro ZDI-25-949 – traversal di symlink ZIP in 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Ricerca JFrog – Zip-Slip di mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevenire Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – catena HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Ricerca ESET – Aggiorna subito gli strumenti WinRAR: RomCom e altri sfruttano una vulnerabilità zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgazione pubblica di una vulnerabilità critica di sovrascrittura arbitraria dei file: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug di HashiCorp vulnerabile a un attacco Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Metodo Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – flag di estrazione sicura di bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Segnalato un exploit Proof-of-Concept per CVE-2025-11001 in 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
