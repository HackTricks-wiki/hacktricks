# Analisi dei file Office

{{#include ../../../banners/hacktricks-training.md}}


Per ulteriori informazioni consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Questa è solo una sintesi:

Microsoft ha creato molti formati di documenti Office, con due tipi principali: **OLE formats** (come RTF, DOC, XLS, PPT) e **Office Open XML (OOXML) formats** (come DOCX, XLSX, PPTX). Questi formati possono includere macros, rendendoli obiettivi per phishing e malware. I file OOXML sono strutturati come zip containers, permettendo l'ispezione tramite unzip, che rivela la gerarchia di file e cartelle e il contenuto dei file XML.

Per esplorare la struttura dei file OOXML, viene mostrato il comando per effettuare l'unzip di un documento e la struttura di output. Sono documentate tecniche per nascondere dati in questi file, che indicano una continua innovazione nelle tecniche di occultamento dei dati nelle sfide CTF.

Per l'analisi, oletools e OfficeDissector offrono set di strumenti completi per esaminare sia documenti OLE che OOXML. Questi strumenti aiutano a identificare e analizzare macros incorporate, che spesso fungono da vettori per la distribuzione di malware, tipicamente scaricando ed eseguendo payload aggiuntivi malicious. L'analisi delle VBA macros può essere condotta senza Microsoft Office utilizzando Libre Office, che permette il debugging con breakpoint e variabili di watch.

L'installazione e l'uso di oletools sono semplici, con comandi forniti per l'installazione via pip e per estrarre macros dai documenti. L'esecuzione automatica delle macros è attivata da funzioni come AutoOpen, AutoExec o Document_Open.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Sfruttamento di OLE Compound File: Autodesk Revit RFA – ricomputazione ECC e gzip controllato

I modelli Revit RFA sono memorizzati come un [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). Il modello serializzato si trova sotto storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Layout chiave di `Global\Latest` (osservato su Revit 2025):

- Intestazione
- GZIP-compressed payload (il grafo di oggetti serializzato effettivo)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit auto-ripara piccole perturbazioni allo stream usando il trailer ECC e rifiuta gli stream che non corrispondono all'ECC. Di conseguenza, modificare ingenuamente i byte compressi non persisterà: le tue modifiche o vengono revertite o il file viene rifiutato. Per assicurare il controllo byte-accurato su ciò che il deserializer vede devi:

- Ricomprimere con una implementazione gzip compatibile con Revit (in modo che i byte compressi che Revit produce/accetta corrispondano a ciò che si aspetta).
- Ricalcolare il trailer ECC sullo stream paddato così Revit accetterà lo stream modificato senza auto-ripararlo.

Flusso pratico di lavoro per patching/fuzzing dei contenuti RFA:

1) Espandi il documento OLE Compound
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Modificare Global\Latest seguendo la disciplina gzip/ECC

- Decomporre `Global/Latest`: mantenere l'header, gunzip il payload, modificare i byte, quindi gzip di nuovo usando parametri di deflate compatibili con Revit.
- Conservare il zero-padding e ricalcolare il trailer ECC in modo che i nuovi byte siano accettati da Revit.
- Se è necessaria una riproduzione deterministica byte-for-byte, costruire un wrapper minimale attorno alle DLL di Revit per invocare i suoi percorsi gzip/gunzip e il calcolo ECC (come dimostrato nella ricerca), oppure riutilizzare qualsiasi helper disponibile che replichi queste semantiche.

3) Ricostruire il documento composto OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Note:

- CompoundFileTool scrive storages/streams sul filesystem applicando escaping per i caratteri non validi nei nomi NTFS; il percorso dello stream che ti interessa è esattamente `Global/Latest` nell'albero di output.
- Quando consegni attacchi di massa tramite plugin dell'ecosistema che recuperano RFAs dall'archiviazione cloud, assicurati che la tua RFA patchata superi prima localmente i controlli di integrità di Revit (gzip/ECC corretti) prima di tentare l'iniezione in rete.

Exploitation insight (to guide what bytes to place in the gzip payload):

- Il deserializer di Revit legge un class index a 16 bit e costruisce un object. Alcuni tipi sono non‑polymorphic e privi di vtables; abusare della gestione dei destructor comporta una type confusion in cui il motore esegue una indirect call attraverso un attacker-controlled pointer.
- Scegliere `AString` (class index `0x1F`) posiziona un attacker-controlled heap pointer all'offset 0 dell'object. Durante il destructor loop, Revit esegue effettivamente:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Posiziona più oggetti di questo tipo nel grafo serializzato in modo che ogni iterazione del ciclo del distruttore esegua un gadget (“weird machine”), e organizza uno stack pivot in una conventional x64 ROP chain.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Strumenti:

- CompoundFileTool (OSS) per espandere/ricostruire OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD per reverse/taint; disabilita page heap con TTD per mantenere le tracce compatte.
- Un proxy locale (es. Fiddler) può simulare la distribuzione nella supply chain sostituendo RFAs nel traffico del plugin per i test.

## Riferimenti

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
