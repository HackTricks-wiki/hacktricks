# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Panoramica

Molti formati di archivio (ZIP, RAR, TAR, 7-ZIP, ecc.) consentono a ogni entry di contenere il proprio **percorso interno**. Quando un'utility di estrazione rispetta ciecamente quel percorso, un nome file appositamente creato contenente `..` o un **percorso assoluto** (ad es. `C:\Windows\System32\`) verrà scritto al di fuori della directory scelta dall'utente.
Questa classe di vulnerabilità è ampiamente nota come *Zip-Slip* o **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Le conseguenze vanno dalla sovrascrittura di file arbitrari fino all'ottenimento diretto della **remote code execution (RCE)** tramite il deposito di un payload in una posizione di **auto-run**, come la cartella *Startup* di Windows.

## Causa principale

1. L'attacker crea un archivio in cui una o più intestazioni dei file contengono:
* Sequenze di traversal relative (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Percorsi assoluti (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Oppure **symlink** appositamente creati che risolvono al di fuori della directory target (comune negli archivi ZIP/TAR su sistemi *nix).
2. La vittima estrae l'archivio con uno strumento vulnerabile che si fida del percorso incorporato (o segue i symlink) invece di sanificarlo o forzare l'estrazione all'interno della directory scelta.
3. Il file viene scritto nella posizione controllata dall'attacker ed eseguito/caricato la volta successiva in cui il sistema o l'utente attiva quel percorso.

### Traversal con `.NET` `Path.Combine` + `ZipArchive`

Un anti-pattern comune in .NET consiste nel combinare la destinazione prevista con `ZipArchiveEntry.FullName` **controllato dall'utente** ed eseguire l'estrazione senza normalizzare il percorso:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Se `entry.FullName` inizia con `..\\`, esegue un traversal; se è un **absolute path**, il componente a sinistra viene scartato completamente, ottenendo una **scrittura arbitraria di file** come identità di estrazione.
- Proof-of-concept archive per scrivere in una directory `app` adiacente monitorata da uno scanner pianificato:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Inserire quello ZIP nella inbox monitorata produce `C:\samples\app\0xdf.txt`, dimostrando il traversal al di fuori di `C:\samples\queue\` e abilitando primitive successive (ad esempio, DLL hijacks).

## Advanced Archive-Breakout Primitives

Considera l'estrazione come una sequenza di mutazioni del filesystem, non come controlli indipendenti sui filename. Un'entry che è sicura quando viene analizzata può diventare non sicura dopo che un membro precedente crea o sostituisce un link; lo stesso problema si verifica quando un extractor memorizza una directory come sicura e in seguito ne cambia il tipo.<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through**: crea `pivot -> /tmp`, quindi estrai un membro regular come `pivot/PWNED.txt`. Se l'extractor segue il primo membro durante la materializzazione del secondo, la scrittura esce dalla destinazione senza che nel secondo nome sia presente `..`.
* **Directory-cache/TOCTOU collision**: emetti la directory `d/sub/`, sostituisci `d/sub` con un symlink a `/tmp`, quindi emetti `d/sub/PWNED.txt`. Questo prende di mira gli extractor che validano o memorizzano la directory una sola volta e non la controllano nuovamente prima della scrittura finale.
* **Hardlink read/overwrite**: TAR e RAR possono rappresentare hardlink. Un hardlink a un file dell'host già esistente può esporne i contenuti se un componente successivo serve il nome estratto; un'entry regular in collisione può invece sovrascrivere l'inode collegato. Questo è limitato dalle regole relative allo stesso filesystem e ai permessi degli hardlink del sistema operativo.
* **Pre-existing or cross-archive pivot**: riprova con una destinazione non vuota. Un archivio può piantare un link e un'estrazione successiva può scriverci attraverso, anche se ogni archivio supera un controllo stateless del nome nell'header.<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

Confronta i nomi utilizzando la semantica del filesystem che li riceverà. Casi differenziali utili includono `LINK` rispetto a `link` sui filesystem case-insensitive, grafie Unicode NFC rispetto a NFD, nomi equivalenti per compatibilità come `ﬁle` rispetto a `file`, membri duplicati che trasformano un path da directory a symlink e backslash interpretati come separatori solo su Windows. Testa anche i nomi contenenti ADS su NTFS. Questi casi possono fare sì che il validator rilevi due path mentre il filesystem ne risolve uno solo.<sup>[[5]](#references)[[11]](#references)</sup>

Un corpus compatto dovrebbe quindi testare combinazioni ordinate di **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, `/` e `\` misti, nomi assoluti/rooted e wrapper compressi come `.tar.gz`. Eseguilo solo in una VM/container disposable e monitora sia la destinazione sia il canary path esterno previsto.<sup>[[11]](#references)</sup>

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR per Windows e i suoi componenti Windows RAR/UnRAR non validavano i filename durante l'estrazione. La flaw utilizzava NTFS alternate data streams (ADS) per bypassare il path di estrazione selezionato e scrivere file in posizioni non previste.<sup>[[5]](#references)</sup>
Un archivio RAR malevolo contenente un'entry come:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
finirebbe **all’esterno** della directory di output selezionata e all’interno della cartella *Startup* dell’utente. ESET ha osservato file LNK malevoli estratti in quella posizione ed eseguiti al logon dell’utente, fornendo persistence e un percorso verso RCE.<sup>[[5]](#references)</sup>

### Creazione di un archivio PoC (Linux/Mac)

Poiché CVE-2025-8088 utilizza un traversal path nel nome di un ADS, usa un generatore appositamente realizzato per creare il RAR, quindi testa l’estrazione esclusivamente in un lab isolato con una build vulnerabile di WinRAR.<sup>[[5]](#references)</sup>

### Exploitation osservato in the wild

ESET ha segnalato campagne di spear-phishing di RomCom (Storm-0978/UNC2596) che allegavano archivi RAR abusando di CVE-2025-8088 per distribuire backdoor personalizzate e facilitare operazioni di ransomware.<sup>[[5]](#references)</sup>

## Casi più recenti (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: le entry ZIP che erano **symbolic link** venivano dereferenziate durante l’estrazione, consentendo agli attacker di uscire dalla directory di destinazione e sovrascrivere percorsi arbitrari. L’interazione dell’utente consiste semplicemente nell’*aprire/estrarre* l’archivio.<sup>[[1]](#references)</sup>
* **Affected**: build di 7-Zip precedenti alla **25.00**. Il difetto nell’elaborazione dei symbolic link è stato corretto nella **25.00** (luglio 2025) e nelle versioni successive.<sup>[[1]](#references)[[10]](#references)</sup>
* **Percorso dell’impatto**: sovrascrivere `Start Menu/Programs/Startup` o percorsi di esecuzione dei servizi → il codice viene eseguito al logon successivo o al riavvio del servizio.
* **Fixture rapida per la gestione dei symlink (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Questo archivio contiene una symlink entry che punta all’esterno della directory di estrazione; usa una destinazione disposable e verifica che l’extractor non la segua. Un write-through test richiede inoltre una regular-file entry sotto la symlink.

### Collisione di symlink in `Unarchive()` di Go mholt/archiver (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` può estrarre una symlink ZIP e dereferenziarla quando una successiva regular member ha lo stesso nome, trasformando una scrittura apparentemente in-root in una scrittura out-of-root.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (il progetto è ora deprecated).<sup>[[2]](#references)</sup>
* **Fix**: passa a `mholt/archives` ≥ 0.1.0 oppure rifiuta i link e ricalcola la destinazione immediatamente prima di ogni apertura.<sup>[[2]](#references)</sup>
* **Generatore minimo della collisione** (quindi chiama `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
link = zipfile.ZipInfo("./x")
link.create_system = 3
link.external_attr = 0o120777 << 16
z.writestr(link, "../../../tmp/PWNED")
z.writestr("./x", b"owned\n")
```

### Bypass dell’estrazione TAR filtrata di CPython (CVE-2026-11940)

Anche `tarfile.extractall(filter="data")` e `filter="tar"` hanno avuto bypass basati sull’ordine dei link. In questo caso, un hardlink faceva riferimento a una symlink archiviata in un percorso più profondo; l’estrazione di fallback validava la symlink relativa in quella posizione profonda, ma la ricreava nella posizione più superficiale dell’hardlink, dove lo stesso target relativo riusciva a uscire dalla directory. Questo è un test generale utile: fai in modo che validazione e materialisation non concordino sulla directory base o sul tipo finale della member.<sup>[[12]](#references)</sup>

## Suggerimenti per il rilevamento

* **Ispezione statica** – Elenca sia i nomi delle member sia i target dei link. Segnala `../`, `..\\`, percorsi assoluti/rooted, symlink, hardlink, file speciali, nomi duplicati, cambi di tipo e collisioni equivalenti per maiuscole/minuscole o Unicode. Mantieni l’ordine delle entry durante la revisione, perché l’exploit potrebbe dipendere dalle member precedenti.<sup>[[11]](#references)</sup>
* **Canonicalisation** – Assicurati che il parent risolto più il basename finale rimanga sotto la destinazione risolta (confronta i componenti del percorso, non un raw string prefix). Ricontrolla dopo ogni member precedente; un test `realpath(join(dest, name))` eseguito una sola volta è vulnerabile alla sostituzione dei link e potrebbe fallire per una leaf non ancora creata.<sup>[[3]](#references)[[11]](#references)</sup>
* **Estrazione in sandbox** – Decomprimi in una directory nuova e disposable usando un extractor con controlli su path/symlink (per esempio i secure checks predefiniti di bsdtar o 7-Zip ≥ 25.00), quindi verifica che l’albero risultante non contenga link verso l’esterno. L’isolamento deve impedire che un escape già attivato raggiunga i percorsi dell’host.<sup>[[1]](#references)[[9]](#references)</sup>
* **Le letture downstream sono importanti** – Una symlink o un hardlink sopravvissuto può diventare una primitive di arbitrary-file-read quando un previewer, CDN, file browser o package pipeline apre o espone successivamente il nome estratto, anche se l’estrazione non ha creato alcun file all’esterno.<sup>[[11]](#references)</sup>
* **Monitoraggio degli endpoint** – Genera un alert quando vengono scritti nuovi eseguibili nelle posizioni `Startup`/`Run`/`cron` poco dopo l’apertura di un archivio con WinRAR/7-Zip/ecc.

## Mitigation & Hardening

1. **Aggiorna l’extractor** – WinRAR 7.13+ e 7-Zip 25.00+ contengono fix per i problemi di path/symlink citati.<sup>[[1]](#references)[[5]](#references)</sup>
2. Estrai gli archivi con “**Do not extract paths**” / “**Ignore paths**” quando possibile. Per input non trusted, rifiuta symbolic link, hardlink, device e FIFO, a meno che l’applicazione non ne abbia esplicitamente bisogno.<sup>[[9]](#references)[[11]](#references)</sup>
3. Estrai in una **directory nuova e vuota**. Non fare il merge di member non trusted in un albero contenente percorsi sostituibili dall’attacker e non riutilizzare una directory piantata da un archivio precedente.<sup>[[11]](#references)</sup>
4. Su Unix, riduci i privilegi e isola la destinazione in un **chroot/mount namespace**; su Windows, usa **AppContainer** o una sandbox. Una scansione post-estrazione da sola non è sufficiente, perché una scrittura escaped avviene prima della scansione.<sup>[[11]](#references)</sup>
5. Nel codice custom, applica le regole di separatori/case/Unicode del sistema operativo target e valida sia la member sia il link target. Risolvi e apri la destinazione senza seguire i link; non separare un controllo di containment da una successiva operazione di create/replace. Il validator deve usare esattamente la stessa base e la stessa semantica di link-emulation del write path.<sup>[[11]](#references)[[12]](#references)</sup>

## Altri casi affected / storici

* 2018 – Advisory *Zip-Slip* di Snyk su larga scala, che interessava numerose librerie Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – `go-slug` di HashiCorp (CVE-2025-0377), traversal nell’estrazione TAR degli slug (corretto nella v0.16.3).<sup>[[7]](#references)</sup>
* Qualsiasi logica di estrazione custom che valida le stringhe degli header ma non i link target e il percorso finale del filesystem usato per ogni scrittura.<sup>[[11]](#references)[[12]](#references)</sup>



## References

- [1] [Trend Micro ZDI-25-949 – ZIP traversal tramite symlink di 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Ricerca JFrog – Zip-Slip di mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevenire Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Catena HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Ricerca ESET – Aggiorna subito gli strumenti WinRAR: RomCom e altri stanno sfruttando una vulnerabilità zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgazione pubblica di una vulnerabilità critica di arbitrary file overwrite: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug di HashiCorp vulnerabile a un attacco Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Metodo Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – flag di secure extraction di bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Segnalato un exploit Proof-of-Concept per CVE-2025-11001 in 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Divertirsi con zip-slip, tar-slip, symlink, hardlink, collisioni e altro](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – Bypass del filtro di estrazione tarfile per CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
{{#include ../banners/hacktricks-training.md}}
