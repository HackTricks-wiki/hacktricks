# Analisi dei file Office

{{#include ../../../banners/hacktricks-training.md}}


Per ulteriori informazioni consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Questo è solo un riassunto:

Microsoft ha creato molti formati di documenti Office, con due tipi principali: **OLE formats** (come RTF, DOC, XLS, PPT) e **Office Open XML (OOXML) formats** (come DOCX, XLSX, PPTX). Questi formati possono includere macros, rendendoli bersagli per phishing e malware. I file OOXML sono strutturati come contenitori zip, il che permette l’ispezione tramite unzip, rivelando la gerarchia di file e cartelle e il contenuto dei file XML.

Per esplorare la struttura dei file OOXML, viene mostrato il comando per unzip di un documento e la struttura di output. Sono state documentate tecniche per nascondere dati in questi file, indicando un’innovazione continua nelle tecniche di occultamento dati nelle sfide CTF.

Per l’analisi, **oletools** e **OfficeDissector** offrono set di strumenti completi per esaminare sia documenti OLE che OOXML. Questi strumenti aiutano a identificare e analizzare macro incorporate, che spesso fungono da vettori per la distribuzione di malware, tipicamente scaricando ed eseguendo payload malevoli aggiuntivi. L’analisi delle macro VBA può essere eseguita senza Microsoft Office utilizzando Libre Office, che permette il debugging con breakpoints e watch variables.

L’installazione e l’uso di **oletools** sono diretti, con comandi forniti per l’installazione via pip e l’estrazione delle macro dai documenti. L’esecuzione automatica delle macro è innescata da funzioni come `AutoOpen`, `AutoExec`, o `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Sfruttamento OLE Compound File: Autodesk Revit RFA – ricalcolo ECC e gzip controllato

I modelli Revit RFA sono memorizzati come un [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). Il modello serializzato è sotto storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Struttura chiave di `Global\Latest` (osservato su Revit 2025):

- Header
- GZIP-compressed payload (the actual serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit ripara automaticamente piccole perturbazioni dello stream usando il trailer ECC e rigetta gli stream che non corrispondono all'ECC. Pertanto, modificare ingenuamente i byte compressi non persisterà: le tue modifiche vengono o ripristinate o il file viene rifiutato. Per garantire un controllo esatto a livello di byte su ciò che il deserializzatore vede devi:

- Ricomprimere con un'implementazione gzip compatibile con Revit (in modo che i byte compressi che Revit produce/accetta corrispondano a quanto si aspetta).
- Ricalcolare il trailer ECC sull'intero stream con padding in modo che Revit accetti lo stream modificato senza ripararlo automaticamente.

Workflow pratico per patching/fuzzing dei contenuti RFA:

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Modifica Global\Latest con disciplina gzip/ECC

- Decomponi `Global/Latest`: conserva l'header, gunzip il payload, modifica i byte, quindi gzip di nuovo usando parametri di deflate compatibili con Revit.
- Preserva lo zero-padding e ricalcola il trailer ECC in modo che i nuovi byte vengano accettati da Revit.
- Se hai bisogno di una riproduzione deterministica byte-per-byte, costruisci un wrapper minimale attorno alle DLL di Revit per invocare i suoi percorsi gzip/gunzip e il calcolo ECC (come dimostrato nella ricerca), oppure riusa qualsiasi helper disponibile che replichi queste semantiche.

3) Ricostruisci il documento composto OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:

- CompoundFileTool scrive storages/streams nel filesystem con escaping per i caratteri non validi nei nomi NTFS; il percorso dello stream che ti interessa è esattamente `Global/Latest` nell'albero di output.
- Quando lanci attacchi di massa tramite plugin dell'ecosistema che recuperano RFAs da cloud storage, assicurati che la RFA patchata superi localmente le verifiche di integrità di Revit prima (gzip/ECC corretto) prima di tentare l'iniezione in rete.

Exploitation insight (to guide what bytes to place in the gzip payload):

- Il Revit deserializer legge un indice di classe a 16 bit e costruisce un oggetto. Alcuni tipi sono non‑polimorfici e privi di vtable; abusare della gestione del distruttore produce una type confusion in cui il motore esegue una chiamata indiretta tramite un puntatore controllato dall'attaccante.
- Scegliere `AString` (indice di classe `0x1F`) posiziona un puntatore heap controllato dall'attaccante all'offset 0 dell'oggetto. Durante il ciclo del distruttore, Revit esegue effettivamente:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Posiziona più oggetti di questo tipo nel grafo serializzato in modo che ogni iterazione del ciclo del distruttore esegua un gadget (“weird machine”), e disponi uno stack pivot in una convenzionale x64 ROP chain.

Vedi i dettagli sulla costruzione di pivot/gadget per Windows x64 qui:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

e le linee guida generali sul ROP qui:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Strumenti:

- CompoundFileTool (OSS) per espandere/ricostruire OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD per reverse/taint; disabilita page heap con TTD per mantenere le tracce compatte.
- Un proxy locale (es., Fiddler) può simulare la delivery della supply-chain sostituendo RFAs nel traffico del plugin per i test.

## Riferimenti

- [Creazione di un exploit RCE completo a partire da un crash nell'analisi dei file RFA di Autodesk Revit (blog ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [Documentazione OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
