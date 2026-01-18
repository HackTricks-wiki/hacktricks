# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Panoramica

Molti formati di archivio (ZIP, RAR, TAR, 7-ZIP, ecc.) permettono a ogni voce di portare il proprio **percorso interno**. Quando un'utilità di estrazione rispetta ciecamente quel percorso, un nome file creato ad arte contenente `..` o un **percorso assoluto** (es. `C:\Windows\System32\`) verrà scritto al di fuori della cartella scelta dall'utente.
Questa classe di vulnerabilità è ampiamente nota come *Zip-Slip* o **archive extraction path traversal**.

Le conseguenze variano dalla sovrascrittura di file arbitrari fino al raggiungimento diretto di **remote code execution (RCE)** depositando un payload in una posizione a **auto-avvio** come la cartella *Startup* di Windows.

## Causa principale

1. L'attaccante crea un archivio in cui uno o più header dei file contengono:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Or crafted **symlinks** that resolve outside the target dir (common in ZIP/TAR on *nix*).
2. La vittima estrae l'archivio con uno strumento vulnerabile che si fida del percorso incorporato (o segue i symlink) invece di sanitizzarlo o forzare l'estrazione al di sotto della directory scelta.
3. Il file viene scritto nella posizione controllata dall'attaccante ed eseguito/caricato la volta successiva che il sistema o l'utente attiva quel percorso.

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (inclusi il CLI `rar` / `unrar`, la DLL e il sorgente portable) non validava i nomi dei file durante l'estrazione.
Un archivio RAR malevolo contenente una voce come:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
terminerebbe **al di fuori** della directory di output selezionata e all'interno della cartella *Startup* dell'utente. Dopo il logon Windows esegue automaticamente tutto ciò che è presente lì, fornendo *persistente* RCE.

### Creazione di un archivio PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opzioni usate:
* `-ep`  – memorizza i percorsi dei file esattamente come forniti (non potare il `./` iniziale).

Consegnare `evil.rar` alla vittima e istruirla a estrarlo con una build vulnerabile di WinRAR.

### Observed Exploitation in the Wild

ESET ha segnalato campagne spear-phishing di RomCom (Storm-0978/UNC2596) che allegavano archivi RAR sfruttando CVE-2025-8088 per distribuire backdoor personalizzate e agevolare operazioni ransomware.

## Casi più recenti (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: le voci ZIP che sono **symbolic links** venivano de-referenziate durante l'estrazione, permettendo agli attaccanti di uscire dalla directory di destinazione e sovrascrivere percorsi arbitrari. L'interazione dell'utente è solo *aprire/estrarre* l'archivio.
* **Sistemi interessati**: 7-Zip 21.02–24.09 (build Windows & Linux). Corretto in **25.00** (luglio 2025) e successivi.
* **Percorso d'impatto**: sovrascrivere `Start Menu/Programs/Startup` o posizioni eseguite da servizi → codice eseguito al prossimo logon o al riavvio del servizio.
* **PoC rapido (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Su una build patchata `/etc/cron.d` non verrà toccato; il symlink viene estratto come link dentro /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` segue `../` e voci ZIP symlinkate, scrivendo fuori da `outputDir`.
* **Sistemi interessati**: `github.com/mholt/archiver` ≤ 3.5.1 (progetto ora deprecato).
* **Fix**: Passare a `mholt/archives` ≥ 0.1.0 o implementare controlli sul percorso canonico prima della scrittura.
* **Riproduzione minima**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Suggerimenti per il rilevamento

* **Ispezione statica** – Elencare le voci dell'archivio e segnalare qualsiasi nome che contenga `../`, `..\\`, *percorsi assoluti* (`/`, `C:`) o voci di tipo *symlink* il cui target sia fuori dalla directory di estrazione.
* **Canonicalizzazione** – Assicurarsi che `realpath(join(dest, name))` inizi ancora con `dest`. Rifiutare altrimenti.
* **Estrazione in sandbox** – Decomprimere in una directory usa-e-getta usando un extractor *sicuro* (es., `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) e verificare che i percorsi risultanti rimangano all'interno della directory.
* **Monitoraggio endpoint** – Segnalare nuovi eseguibili scritti in `Startup`/`Run`/`cron` poco dopo che un archivio è stato aperto da WinRAR/7-Zip/etc.

## Mitigazione e Hardening

1. **Aggiornare l'extractor** – WinRAR 7.13+ e 7-Zip 25.00+ implementano la sanitizzazione di percorsi/symlink. Entrambi gli strumenti non hanno ancora auto-update.
2. Estrarre gli archivi con “**Do not extract paths**” / “**Ignore paths**” quando possibile.
3. Su Unix, abbassare i privilegi e montare un **chroot/namespace** prima dell'estrazione; su Windows, usare **AppContainer** o una sandbox.
4. Se si scrive codice custom, normalizzare con `realpath()`/`PathCanonicalize()` **prima** di creare/scrivere, e rifiutare qualsiasi voce che esca dalla destinazione.

## Altri casi interessati / Storici

* 2018 – Massivo avviso *Zip-Slip* di Snyk che ha interessato molte librerie Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011, traversal simile durante il merge `-ao`.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) traversal nell'estrazione TAR nei slug (patch in v1.2).
* Qualsiasi logica di estrazione custom che non chiami `PathCanonicalize` / `realpath` prima della scrittura.

## Riferimenti

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)

{{#include ../banners/hacktricks-training.md}}
