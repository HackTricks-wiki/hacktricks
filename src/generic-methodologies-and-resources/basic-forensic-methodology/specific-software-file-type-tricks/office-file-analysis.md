# Analisi dei file Office

{{#include ../../../banners/hacktricks-training.md}}


Per ulteriori informazioni consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Questa è solo una sintesi:

Microsoft ha creato molti formati di documenti Office, con due tipi principali: i formati **OLE** (come RTF, DOC, XLS, PPT) e i formati **Office Open XML (OOXML)** (come DOCX, XLSX, PPTX). Questi formati possono includere macro, rendendoli obiettivi per phishing e malware. I file OOXML sono strutturati come contenitori zip, consentendo l'ispezione tramite decompressione, rivelando la gerarchia di file e cartelle e il contenuto dei file XML.

Per esplorare la struttura dei file OOXML viene mostrato il comando per decomprimere un documento e la struttura di output risultante. Sono state documentate tecniche per nascondere dati in questi file, indicando una continua innovazione nelle tecniche di occultamento dei dati nelle sfide CTF.

Per l'analisi, **oletools** e **OfficeDissector** offrono set di strumenti completi per esaminare sia documenti OLE che OOXML. Questi strumenti aiutano a identificare e analizzare le macro incorporate, che spesso fungono da vettori per la diffusione di malware, tipicamente scaricando ed eseguendo payload maligni aggiuntivi. L'analisi delle macro VBA può essere condotta senza Microsoft Office utilizzando Libre Office, che permette il debug con breakpoint e variabili di watch.

L'installazione e l'uso di **oletools** sono semplici, con comandi forniti per l'installazione via pip e l'estrazione delle macro dai documenti. L'esecuzione automatica delle macro è innescata da funzioni come `AutoOpen`, `AutoExec`, o `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

I modelli Revit RFA sono memorizzati come un [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). Il modello serializzato si trova sotto storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Layout chiave di `Global\Latest` (osservato su Revit 2025):

- Intestazione
- Payload compresso con gzip (il grafo di oggetti serializzati effettivo)
- Padding con zeri
- Trailer Error-Correcting Code (ECC)

Revit effettua l’auto-riparazione di piccole perturbazioni dello stream usando il trailer ECC e rifiuta gli stream che non corrispondono all’ECC. Pertanto, modificare ingenuamente i byte compressi non persisterà: le tue modifiche vengono o ripristinate o il file viene rifiutato. Per garantire il controllo byte-accurato su ciò che il deserializzatore vede devi:

- Ricomprimere con un’implementazione gzip compatibile con Revit (in modo che i byte compressi che Revit produce/accetta corrispondano a quanto si aspetta).
- Ricalcolare il trailer ECC sullo stream con padding in modo che Revit accetti lo stream modificato senza auto-ripararlo.

Practical workflow for patching/fuzzing RFA contents:

1) Espandere il documento OLE compound
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Modificare Global\Latest seguendo la disciplina gzip/ECC

- Deconstruct `Global/Latest`: conservare l'header, gunzip del payload, modificare i byte, poi ricomprimere con gzip usando parametri di deflate compatibili con Revit.
- Preservare il padding di zeri e ricomputare il trailer ECC in modo che i nuovi byte siano accettati da Revit.
- Se è necessaria una riproduzione deterministica byte-per-byte, creare un wrapper minimo attorno alle DLL di Revit per invocare i suoi percorsi gzip/gunzip e la computazione ECC (come dimostrato nella ricerca), oppure riutilizzare qualsiasi helper disponibile che replichi queste semantiche.

3) Ricostruire il documento composto OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Note:

- CompoundFileTool scrive storages/streams nel filesystem applicando l'escaping per i caratteri non validi nei nomi NTFS; il percorso dello stream che ti interessa è esattamente `Global/Latest` nell'albero di output.
- Quando consegni attacchi di massa tramite ecosystem plugins che recuperano RFA da cloud storage, assicurati che la RFA patchata superi prima localmente i controlli di integrità di Revit (gzip/ECC corretti) prima di tentare la network injection.

Exploitation insight (to guide what bytes to place in the gzip payload):

- Il deserializzatore di Revit legge un indice di classe a 16 bit e costruisce un oggetto. Alcuni tipi sono non‑polimorfici e privi di vtable; abusare della gestione dei distruttori provoca una type confusion in cui il motore esegue una chiamata indiretta attraverso un puntatore controllato dall'attaccante.
- Scegliere `AString` (class index `0x1F`) posiziona un puntatore heap controllato dall'attaccante all'offset 0 dell'oggetto. Durante il ciclo dei distruttori, Revit esegue effettivamente:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Inserire più oggetti di questo tipo nel grafo serializzato in modo che ogni iterazione del ciclo del distruttore esegua un gadget (“weird machine”), e predisporre uno stack pivot in una convenzionale x64 ROP chain.

Vedi i dettagli su Windows x64 pivot/gadget building qui:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

e indicazioni generali su ROP qui:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Strumenti:

- CompoundFileTool (OSS) per espandere/ricostruire OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD per reverse/taint; disabilitare page heap con TTD per mantenere le tracce compatte.
- Un proxy locale (es. Fiddler) può simulare la delivery supply-chain sostituendo RFAs nel traffico dei plugin per i test.

## Riferimenti

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
