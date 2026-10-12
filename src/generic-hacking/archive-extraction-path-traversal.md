# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Panoramica

Molti formati di archivio (ZIP, RAR, TAR, 7-ZIP, ecc.) consentono a ogni voce di contenere un **percorso interno**. Quando un’utilità di estrazione rispetta ciecamente quel percorso, un nome file creato appositamente e contenente `..` o un **percorso assoluto** (ad es. `C:\Windows\System32\`) verrà scritto al di fuori della directory scelta dall’utente.  
Questa classe di vulnerabilità è ampiamente nota come *Zip-Slip* o **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Le conseguenze possono variare dalla sovrascrittura di file arbitrari all’esecuzione diretta di **codice remoto (RCE)**, inserendo un payload in una posizione di **avvio automatico**, come la cartella *Startup* di Windows.

## Causa principale

1. L’attaccante crea un archivio in cui una o più intestazioni di file contengono:
   * Sequenze di traversal relative (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
   * Percorsi assoluti (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
   * Oppure **symlink** creati appositamente che puntano al di fuori della directory di destinazione (comuni negli archivi ZIP/TAR su *nix*). 
2. La vittima estrae l’archivio con uno strumento vulnerabile che si fida del percorso incorporato (o segue i symlink), invece di sanificarlo o imporre l’estrazione all’interno della directory scelta.
3. Il file viene scritto nella posizione controllata dall’attaccante ed eseguito/caricato la volta successiva che il sistema o l’utente attiva quel percorso.

### Traversal con .NET `Path.Combine` + `ZipArchive`

Un anti-pattern comune in .NET consiste nel combinare la destinazione prevista con `ZipArchiveEntry.FullName` **controllato dall’utente** ed estrarre senza normalizzare il percorso:<sup>[[4]](#references)[[8]](#references)</sup>

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

- Se `entry.FullName` inizia con `..\\`, consente la traversal; se è un **percorso assoluto**, il componente a sinistra viene scartato del tutto, consentendo una **scrittura arbitraria di file** come destinazione dell'estrazione.
- Archivio proof-of-concept per scrivere in una directory `app` adiacente monitorata da uno scanner pianificato:

```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
    z.writestr("../app/0xdf.txt", "ABCD")
```

L'inserimento di quel ZIP nella cartella monitorata produce `C:\samples\app\0xdf.txt`, dimostrando la traversal al di fuori di `C:\samples\queue\` e consentendo primitive successive (ad es. DLL hijack).

### Root di estrazione controllata dall'utente

Verifica anche la **directory passata all'extractor**, non solo i nomi dei membri dell'archivio. Un'applicazione può ricavare tale directory da un titolo, dal nome di un progetto o da un altro campo della richiesta. Un valore come `../../../../app/module` può spostare la root di estrazione al di fuori dell'area di upload prima che l'extractor elabori qualsiasi membro. In questo caso, anche un archivio contenente solo il nome sicuro `api.py` può sovrascrivere il codice dell'applicazione.<sup>[[14]](#references)[[15]](#references)</sup>

```python
# Vulnerable pattern: the ZIP entries themselves need no ../ components.
extract_root = os.path.join(site_root, "public", "files", user_title)
archive.extractall(extract_root)
```

Questo è un confine di contenimento distinto dal classico Zip-Slip. Convalida sia la directory radice di estrazione risolta sia ogni percorso di membro risolto. Per controllare la directory radice, puoi usare i componenti del percorso invece di un prefisso di stringa:<sup>[[14]](#references)</sup>

```python
base = Path(site_root, "public", "files").resolve()
dest = (base / user_title).resolve()
if not dest.is_relative_to(base):
    raise ValueError("extraction root escapes its base")
```

Per un test sicuro, carica un archivio valido contenente un file canary e inserisci sequenze di path traversal in ogni campo che può selezionare la directory di estrazione. Monitora sia la directory prevista sia un percorso esterno usa-e-getta. Se la destinazione può raggiungere un modulo importato, sovrascriverlo può portare a code execution quando i worker si ricaricano; un HTTP 500 o una reimpostazione della connessione durante quel ricaricamento non dimostrano che la scrittura non sia riuscita.<sup>[[14]](#references)[[15]](#references)</sup> Vedi anche la più ampia [file upload methodology](../pentesting-web/file-upload/).

## Primitive avanzate per evadere dall'archivio

Considera l'estrazione come una sequenza di modifiche al filesystem, non come controlli indipendenti sui nomi dei file. Una voce sicura al momento dell'analisi può diventare non sicura dopo che un membro precedente crea o sostituisce un link; lo stesso problema si presenta quando un extractor memorizza in cache una directory come sicura e in seguito ne cambia il tipo.<sup>[[11]](#references)</sup>

### Pivot tramite link e collisioni tra voci

* **Symlink write-through**: crea `pivot -> /tmp`, poi estrai un membro normale come `pivot/PWNED.txt`. Se l'extractor segue il primo membro durante la materializzazione del secondo, la scrittura esce dalla directory senza che nel secondo nome sia presente `..`.
* **Directory-cache/TOCTOU collision**: crea la directory `d/sub/`, sostituisci `d/sub` con un symlink a `/tmp`, poi crea `d/sub/PWNED.txt`. Questo colpisce gli extractor che convalidano o memorizzano in cache la directory una sola volta e non la ricontrollano prima della scrittura finale.
* **Hardlink read/overwrite**: TAR e RAR possono rappresentare hardlink. Un hardlink a un file host esistente può esporne il contenuto se un componente successivo serve il nome estratto; una voce normale in collisione può invece sovrascrivere l'inode collegato. Questo è limitato dalle regole relative allo stesso filesystem e ai permessi degli hardlink del sistema operativo.
* **Pre-existing or cross-archive pivot**: riprova con una destinazione non vuota. Un archivio può inserire un link e un'estrazione successiva può scriverci attraverso, anche se ciascun archivio supera un controllo stateless del nome nell'header.<sup>[[11]](#references)</sup>

### Collisioni dovute all'equivalenza del filesystem

Confronta i nomi usando la semantica del filesystem che li riceverà. Casi differenziali utili includono `LINK` rispetto a `link` nei filesystem che non distinguono tra maiuscole e minuscole, le grafie Unicode NFC rispetto a NFD, nomi equivalenti per compatibilità come `ﬁle` rispetto a `file`, membri duplicati che trasformano un percorso da directory a symlink e backslash interpretati come separatori solo su Windows. Prova anche nomi contenenti ADS su NTFS. Questi casi possono indurre il validator a vedere due percorsi mentre il filesystem ne risolve uno solo.<sup>[[5]](#references)[[11]](#references)</sup>

Un corpus compatto dovrebbe quindi verificare combinazioni ordinate di **directory → symlink → child**, **symlink → regular file in collisione**, **hardlink → regular file in collisione**, `/` e `\` misti, nomi assoluti/con radice e wrapper compressi come `.tar.gz`. Esegui i test solo in una VM/container usa-e-getta e controlla sia la destinazione sia il percorso esterno previsto per il canary.<sup>[[11]](#references)</sup>

Le ambiguità strutturali specifiche di ZIP possono far sì che una pre-scansione e l'extractor effettivo rilevino nomi di voci o alberi diversi. Vedi [Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion) invece di fidarti dell'output di una sola libreria ZIP.

## Esempio reale – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR per Windows e i suoi componenti Windows RAR/UnRAR non convalidavano i nomi dei file durante l'estrazione. La falla sfruttava gli alternate data stream (ADS) di NTFS per aggirare il percorso di estrazione selezionato e scrivere file in posizioni non previste.<sup>[[5]](#references)</sup>
Un archivio RAR malevolo contenente una voce come:

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```

finirebbe **all’esterno** della directory di output selezionata e nella cartella *Startup* dell’utente. ESET ha osservato file LNK malevoli estratti in quella posizione ed eseguiti al logon dell’utente, garantendo persistenza e una via per ottenere RCE.<sup>[[5]](#references)</sup>

### Creazione di un archivio PoC (Linux/Mac)

Poiché CVE-2025-8088 usa un percorso traversal in un nome ADS, usa un generatore apposito per creare il RAR, quindi prova l’estrazione solo in un lab isolato con una build vulnerabile di WinRAR.<sup>[[5]](#references)</sup>

### Sfruttamento osservato in natura

ESET ha segnalato campagne di spear-phishing di RomCom (Storm-0978/UNC2596) che allegavano archivi RAR che sfruttavano CVE-2025-8088 per distribuire backdoor personalizzate e agevolare operazioni ransomware.<sup>[[5]](#references)</sup>

## Casi più recenti (2024–2026)

### Traversal di symlink ZIP in 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: le voci ZIP che erano **symlink** venivano dereferenziate durante l’estrazione, permettendo agli attaccanti di uscire dalla directory di destinazione e sovrascrivere percorsi arbitrari. L’interazione dell’utente consiste solo nell’*aprire/estrarre* l’archivio.<sup>[[1]](#references)</sup>
* **Versioni interessate**: build di 7-Zip precedenti alla **25.00**. Il difetto nell’elaborazione dei symlink è stato corretto nella **25.00** (luglio 2025) e nelle versioni successive.<sup>[[1]](#references)[[10]](#references)</sup>
* **Percorso di impatto**: sovrascrittura di `Start Menu/Programs/Startup` o di percorsi usati dai servizi → il codice viene eseguito al logon successivo o al riavvio del servizio.
* **Fixture rapida per la gestione dei symlink (Linux)**:
  ```bash
  mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
  ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
  cd /tmp/archive-slip-test
  zip -y exploit.zip evil   # -y preserves symlinks
  7z x exploit.zip -o/tmp/archive-slip-target
  ```
  Questo archivio contiene una voce symlink che punta fuori dalla directory di estrazione; usa una destinazione usa e getta e verifica che l'estrattore non la segua. Un test di scrittura tramite symlink richiede anche una voce file normale sotto il symlink.

### Collisione symlink in `Unarchive()` di Go mholt/archiver (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` può estrarre un symlink ZIP e dereferenziarlo quando un membro normale successivo ha lo stesso nome, trasformando una scrittura apparentemente interna alla directory in una scrittura esterna.<sup>[[2]](#references)</sup>
* **Versioni interessate**: `github.com/mholt/archiver` ≤ 3.5.1 (il progetto è ora deprecato).<sup>[[2]](#references)</sup>
* **Fix**: Passa a `mholt/archives` ≥ 0.1.0 oppure rifiuta i link e risolvi nuovamente ogni destinazione subito prima di aprirla.<sup>[[2]](#references)</sup>
* **Generatore minimo della collisione** (poi chiama `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
  ```python
  import zipfile

  with zipfile.ZipFile("exploit.zip", "w") as z:
      link = zipfile.ZipInfo("./x")
      link.create_system = 3
      link.external_attr = 0o120777 << 16
      z.writestr(link, "../../../tmp/PWNED")
      z.writestr("./x", b"owned\n")
  ```

### Bypass dell'estrazione TAR filtrata di CPython (CVE-2026-11940)

Anche `tarfile.extractall(filter="data")` e `filter="tar")` hanno avuto bypass basati sull'ordine dei link. In questo caso, un hardlink faceva riferimento a un symlink archiviato in un percorso più profondo; l'estrazione di fallback convalidava il symlink relativo in quella posizione profonda, ma lo ricreava nella posizione più superficiale dell'hardlink, dove lo stesso target relativo usciva dalla directory prevista. È un test generale utile: fare in modo che convalida e materializzazione non concordino sulla directory di base o sul tipo finale del membro.<sup>[[12]](#references)</sup>

### Fuga del target di un hardlink nel pacchetto Node `tar` tramite una catena di symlink (GHSA-83g3-92jg-28cx)

Il pacchetto Node.js `tar` accettava in `tar.extract()` un hardlink il cui target sembrava contenuto dal punto di vista lessicale, ma che tramite due symlink precedenti si risolveva al di fuori della directory di estrazione. L'attacco funziona con le opzioni di estrazione predefinite: i controlli sulla directory padre della destinazione verificavano il nome dell'hardlink all'interno della directory, mentre il target dell'hardlink veniva passato al filesystem senza risolvere l'intera catena per verificarne il contenimento. `tar` ≤ 7.5.7 è vulnerabile; la versione 7.5.8 corregge il problema.<sup>[[13]](#references)</sup>

L'elemento importante del fixture di test è la **relazione ordinata** tra i membri, non questi nomi letterali:<sup>[[13]](#references)</sup>

```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```

Se l'estrazione riesce, `exfil` rimane visibilmente all'interno dell'albero di output, ma condivide un inode con il file esterno scelto; leggerlo ne causa il leak e scriverci modifica l'originale. Questo bypass dimostra perché controllare solo il percorso finale, rimuovere i prefissi assoluti o bloccare `..` nell'header dell'hardlink non è sufficiente: convalida i target dei link dopo aver applicato tutto lo stato del filesystem creato in precedenza.<sup>[[13]](#references)</sup>

## Suggerimenti per il rilevamento

* **Ispezione statica** – Elenca sia i nomi dei membri sia i target dei link. Segnala `../`, `..\\`, percorsi assoluti o con radice, symlink, hardlink, file speciali, nomi duplicati, cambi di tipo e collisioni tra nomi equivalenti ignorando maiuscole/minuscole o differenze Unicode. Mantieni l'ordine delle voci durante la revisione, perché l'exploit potrebbe dipendere da membri precedenti.<sup>[[11]](#references)</sup>

  ```bash
  bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
  7z l -slt suspect.7z          # technical metadata, one field per line
  zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
  ```

* **Canonicalizzazione** – Assicurati che la directory padre risolta e il nome base finale rimangano all'interno della destinazione risolta (confronta i componenti del percorso, non un prefisso di stringa semplice). Ripeti il controllo dopo ogni elemento precedente; un test `realpath(join(dest, name))` eseguito una sola volta è vulnerabile alla sostituzione dei link e potrebbe non funzionare per una destinazione finale non ancora creata.<sup>[[3]](#references)[[11]](#references)</sup>
* **Estrazione in sandbox** – Decomprimi in una directory nuova e temporanea usando un estrattore con controlli su percorsi e symlink (ad esempio, i controlli sicuri predefiniti di bsdtar o 7-Zip ≥ 25.00), quindi verifica che l'albero risultante non contenga link verso l'esterno. L'isolamento deve impedire che una fuga già innescata raggiunga i percorsi dell'host.<sup>[[1]](#references)[[9]](#references)</sup>
* **Anche le letture successive sono importanti** – Un symlink o hardlink rimasto può diventare una primitiva di lettura di file arbitrari quando in seguito un'anteprima, una CDN, un browser di file o una pipeline di pacchettizzazione apre o serve il nome estratto, anche se l'estrazione stessa non ha creato file esterni.<sup>[[11]](#references)</sup>
* **Monitoraggio degli endpoint** – Genera un avviso se vengono scritti nuovi eseguibili in percorsi `Startup`/`Run`/`cron` poco dopo l'apertura di un archivio con WinRAR/7-Zip/ecc.

## Mitigazione e hardening

1. **Aggiorna l'estrattore** – WinRAR 7.13+, 7-Zip 25.00+ e Node `tar` 7.5.8+ includono correzioni per i problemi citati relativi a percorsi, symlink e destinazioni dei link.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Quando possibile, estrai gli archivi usando “**Do not extract paths**” / “**Ignore paths**”. Per input non attendibili, rifiuta symlink, hardlink, device e FIFO, a meno che l'applicazione non ne abbia esplicitamente bisogno.<sup>[[9]](#references)[[11]](#references)</sup>
3. Estrai in una **nuova directory vuota**. Non unire elementi non attendibili a un albero contenente percorsi che l'attaccante può sostituire e non riutilizzare una directory creata da un archivio precedente.<sup>[[11]](#references)</sup>
4. Su Unix, riduci i privilegi e isola la destinazione in un **chroot/mount namespace**; su Windows, usa **AppContainer** o una sandbox. Una scansione successiva all'estrazione non è sufficiente, perché la scrittura all'esterno avviene prima della scansione.<sup>[[11]](#references)</sup>
5. Nel codice personalizzato, applica le regole del sistema operativo di destinazione per separatori, maiuscole/minuscole e Unicode e convalida sia l'elemento sia la destinazione del link. Risolvi e apri la destinazione senza seguire i link; non separare un controllo di contenimento da una successiva operazione di creazione/sostituzione. Il validatore deve usare esattamente la stessa directory di base e la stessa semantica di emulazione dei link del percorso di scrittura.<sup>[[11]](#references)[[12]](#references)</sup>

## Altri casi interessati / storici

* 2018 – Ampio avviso *Zip-Slip* di Snyk, relativo a numerose librerie Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): traversal durante l'estrazione TAR negli slug (corretto nella v0.16.3).<sup>[[7]](#references)</sup>
* Qualsiasi logica di estrazione personalizzata che convalidi le stringhe degli header ma non le destinazioni dei link e il percorso finale del filesystem usato per ogni scrittura.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – traversal ZIP tramite symlink in 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Ricerca JFrog – Zip-Slip in mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevenire Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Catena HTB Bruno ZipSlip → hijack di DLL](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Ricerca ESET – Aggiorna subito gli strumenti WinRAR: RomCom e altri sfruttano una vulnerabilità zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgazione pubblica di una vulnerabilità critica di sovrascrittura arbitraria di file: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug è vulnerabile a un attacco Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Metodo Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – flag di estrazione sicura di bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Segnalato un exploit Proof-of-Concept per CVE-2025-11001 in 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Divertirsi con zip-slip, tar-slip, symlink, hardlink, collisioni e altro](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Annuncio Python Security – Bypass del filtro di estrazione tarfile CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [Avviso di sicurezza GitHub – fuga dalla destinazione di un hardlink in node-tar tramite una catena di symlink](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
- [14] [Rhino Security Labs – PoC CVE: directory radice di estrazione SCORM controllabile dall'utente](https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/master/CVE-2026-39405/README.md)
- [15] [Rhino Security Labs – Vulnerabilità multiple in Frappe LMS che portano all'esecuzione di codice remoto](https://rhinosecuritylabs.com/research/multiple-vulnerabilities-in-frappe-lms-leading-to-remote-code-execution/)
{{#include ../banners/hacktricks-training.md}}
