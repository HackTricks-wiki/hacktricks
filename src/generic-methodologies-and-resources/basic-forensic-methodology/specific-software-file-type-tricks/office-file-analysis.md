# Analisi dei file Office

{{#include ../../../banners/hacktricks-training.md}}


Per ulteriori informazioni, consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Questo è solo un riepilogo:<sup>[[4]](#references)</sup>

Microsoft ha creato numerosi formati di documenti Office, i cui due tipi principali sono i **formati OLE** (come RTF, DOC, XLS, PPT) e i **formati Office Open XML (OOXML)** (come DOCX, XLSX, PPTX). Questi formati possono includere macro, diventando così obiettivi per phishing e malware. I file OOXML sono strutturati come contenitori zip, consentendo di esaminarli tramite decompressione e rivelando la gerarchia di file e cartelle, oltre al contenuto dei file XML.

Per esplorare la struttura dei file OOXML, vengono forniti il comando per decomprimere un documento e la struttura dell'output. Sono state documentate tecniche per nascondere dati in questi file, a dimostrazione della continua innovazione nelle tecniche di occultamento dei dati all'interno delle challenge CTF.

Per l'analisi, **oletools** e **OfficeDissector** offrono set di strumenti completi per esaminare documenti OLE e OOXML. Questi strumenti aiutano a identificare e analizzare le macro incorporate, che spesso fungono da vettori per la distribuzione di malware, scaricando ed eseguendo in genere ulteriori payload malevoli. L'analisi delle macro VBA può essere eseguita senza Microsoft Office utilizzando Libre Office, che consente il debugging con breakpoint e variabili watch.

L'installazione e l'utilizzo di **oletools** sono semplici, con comandi forniti per l'installazione tramite pip e l'estrazione delle macro dai documenti. L'esecuzione automatica delle macro viene attivata da funzioni come `AutoOpen`, `AutoExec` o `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ricalcolo ECC e gzip controllato

I modelli Revit RFA sono archiviati come [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (ovvero CFBF). Il modello serializzato si trova nello storage/stream:<sup>[[1]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Struttura principale di `Global\Latest` (osservata in Revit 2025):

- Intestazione
- Payload compresso con GZIP (il grafo di oggetti serializzato effettivo)
- Padding a zero
- Trailer dell'Error-Correcting Code (ECC)

Revit esegue automaticamente la riparazione di piccole alterazioni nello stream usando il trailer ECC e rifiuta gli stream che non corrispondono all'ECC. Pertanto, modificare ingenuamente i byte compressi non produce modifiche persistenti: le modifiche vengono ripristinate oppure il file viene rifiutato. Per garantire un controllo accurato a livello di byte su ciò che vede il deserializzatore, è necessario:

- Ricomprimere con un'implementazione gzip compatibile con Revit (in modo che i byte compressi prodotti/accettati da Revit corrispondano a quelli previsti).
- Ricalcolare il trailer ECC sullo stream con padding, affinché Revit accetti lo stream modificato senza ripararlo automaticamente.

Workflow pratico per applicare patch o eseguire fuzzing sui contenuti RFA:<sup>[[1]](#references)</sup>

1) Espandere il documento compound OLE
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Modifica `Global\Latest` seguendo le regole di gzip/ECC

- Scomponi `Global/Latest`: mantieni l’header, decomprimi con gunzip il payload, modifica i byte, quindi ricomprimilo con i parametri deflate compatibili con Revit.
- Mantieni il padding a zero e ricalcola il trailer ECC affinché i nuovi byte vengano accettati da Revit.
- Se ti serve una riproduzione deterministica byte per byte, crea un wrapper minimale attorno alle DLL di Revit per richiamare i percorsi gzip/gunzip e il calcolo ECC (come dimostrato nella ricerca), oppure riutilizza un helper disponibile che replichi questa semantica.

3) Ricostruisci il documento composto OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Note:<sup>[[1]](#references)</sup>

- CompoundFileTool scrive storage/stream nel filesystem con escaping per i caratteri non validi nei nomi NTFS; il percorso dello stream desiderato è esattamente `Global/Latest` nell’albero di output.
- Quando si distribuiscono mass attacks tramite plugin dell’ecosistema che recuperano RFA dal cloud storage, assicurarsi che l’RFA patchato superi prima localmente i controlli di integrità di Revit (gzip/ECC corretti), prima di tentare l’injection tramite network.

Exploitation insight (per stabilire quali byte inserire nel payload gzip):<sup>[[1]](#references)</sup>

- Il deserializer di Revit legge un class index a 16 bit e costruisce un oggetto. Alcuni tipi sono non-polymorphic e privi di vtable; abusare della gestione del destructor produce una type confusion in cui il motore esegue una indirect call tramite un puntatore controllato dall’attacker.
- Scegliendo `AString` (class index `0x1F`) si inserisce un heap pointer controllato dall’attacker all’offset 0 dell’oggetto. Durante il destructor loop, Revit esegue di fatto:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Inserisci più oggetti di questo tipo nel grafo serializzato, in modo che ogni iterazione del ciclo del distruttore esegua un gadget (“weird machine”), e organizza uno stack pivot verso una catena ROP x64 convenzionale.

Vedi qui i dettagli sulla creazione di pivot/gadget per Windows x64:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

e qui una guida generale alla ROP:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Strumenti:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) per espandere/ricostruire file compound OLE: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD per reverse engineering/taint analysis; disabilita page heap con TTD per mantenere le tracce compatte.
- Un proxy locale (ad esempio Fiddler) può simulare la distribuzione tramite supply chain sostituendo gli RFA nel traffico dei plugin a scopo di testing.

## Riferimenti

- [1] [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
