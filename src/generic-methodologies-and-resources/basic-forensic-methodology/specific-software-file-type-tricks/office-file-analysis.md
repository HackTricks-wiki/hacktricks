# Analisi dei file Office

{{#include ../../../banners/hacktricks-training.md}}


Per ulteriori informazioni, consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Questo è solo un riepilogo:<sup>[[4]](#references)</sup>

Microsoft ha creato numerosi formati di documenti Office, i due principali sono i **formati OLE** (come RTF, DOC, XLS, PPT) e i **formati Office Open XML (OOXML)** (come DOCX, XLSX, PPTX). Questi formati possono includere macro, diventando così obiettivi per phishing e malware. I file OOXML sono strutturati come contenitori zip, consentendo l'ispezione tramite decompressione e rivelando la gerarchia di file e cartelle e il contenuto dei file XML.

Per esplorare le strutture dei file OOXML, vengono forniti il comando per decomprimere un documento e la struttura dell'output. Sono state documentate tecniche per nascondere dati in questi file, a indicare una continua innovazione nel nascondimento dei dati nelle challenge CTF.

Per l'analisi, **oletools** e **OfficeDissector** offrono set completi di strumenti per esaminare sia i documenti OLE sia quelli OOXML. Questi strumenti aiutano a identificare e analizzare le macro incorporate, che spesso fungono da vettori per la distribuzione di malware, scaricando ed eseguendo in genere ulteriori payload malevoli. L'analisi delle macro VBA può essere eseguita senza Microsoft Office utilizzando Libre Office, che consente il debugging con breakpoint e variabili da osservare.

L'installazione e l'utilizzo di **oletools** sono semplici, con comandi forniti per l'installazione tramite pip e l'estrazione delle macro dai documenti. L'esecuzione automatica delle macro viene attivata da funzioni come `AutoOpen`, `AutoExec` o `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Exploitation di file OLE Compound: Autodesk Revit RFA – ricalcolo ECC e gzip controllato

I modelli Revit RFA sono archiviati come [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (noto anche come CFBF). Il modello serializzato si trova nello storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Struttura principale di `Global\Latest` (osservata su Revit 2025):

- Header
- Payload compresso con GZIP (il grafo di oggetti serializzato effettivo)
- Padding composto da zeri
- Trailer Error-Correcting Code (ECC)

Revit ripara automaticamente piccole perturbazioni nello stream utilizzando il trailer ECC e rifiuta gli stream che non corrispondono all’ECC. Pertanto, modificare ingenuamente i byte compressi non produrrà effetti persistenti: le modifiche vengono annullate oppure il file viene rifiutato. Per garantire un controllo byte-accurate su ciò che il deserializer riceve, è necessario:

- Ricomprimere con un’implementazione gzip compatibile con Revit (in modo che i byte compressi prodotti/accettati da Revit corrispondano a quelli previsti).
- Ricalcolare il trailer ECC sullo stream sottoposto a padding, così Revit accetterà lo stream modificato senza ripararlo automaticamente.

Workflow pratico per il patching/fuzzing dei contenuti RFA:<sup>[[1]](#references)</sup>

1) Espandere il documento OLE compound
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Modifica Global\Latest rispettando gzip/ECC

- Scomponi `Global/Latest`: mantieni l’header, decomprimi il payload con gunzip, modifica i byte, quindi ricomprimilo con gzip usando parametri deflate compatibili con Revit.
- Mantieni il padding a zero e ricalcola il trailer ECC affinché i nuovi byte vengano accettati da Revit.
- Se ti serve una riproduzione deterministica byte per byte, crea un wrapper minimale intorno alle DLL di Revit per invocare i relativi percorsi gzip/gunzip e il calcolo ECC (come dimostrato nella ricerca), oppure riutilizza qualsiasi helper disponibile che replichi queste semantiche.

3) Ricostruisci il documento composto OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Note:<sup>[[1]](#references)</sup>

- CompoundFileTool scrive storages/streams nel filesystem con escaping per i caratteri non validi nei nomi NTFS; il percorso dello stream desiderato è esattamente `Global/Latest` nell'albero di output.
- Quando si eseguono mass attacks tramite ecosystem plugins che recuperano RFA dal cloud storage, assicurati che l'RFA patched superi prima localmente i controlli di integrità di Revit (gzip/ECC corretti), prima di tentare la network injection.

Exploitation insight (per guidare quali byte inserire nel gzip payload):<sup>[[1]](#references)</sup>

- Il deserializer di Revit legge un class index a 16 bit e costruisce un oggetto. Alcuni tipi sono non-polymorphic e non hanno vtables; abusare del destructor handling produce una type confusion in cui il motore esegue una indirect call tramite un attacker-controlled pointer.
- La scelta di `AString` (class index `0x1F`) colloca un attacker-controlled heap pointer all'object offset 0. Durante il destructor loop, Revit esegue di fatto:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Inserire molteplici oggetti di questo tipo nel grafo serializzato, in modo che ogni iterazione del loop del distruttore esegua un gadget (“weird machine”), e organizzare uno stack pivot verso una catena ROP x64 convenzionale.

Dettagli sulla costruzione di pivot/gadget Windows x64 qui:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

e indicazioni generali sul ROP qui:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Strumenti:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) per espandere/ricostruire file compound OLE: https://github.com/thezdi/CompoundFileTool<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD per reverse/taint; disabilitare page heap con TTD per mantenere le tracce compatte.
- Un proxy locale (ad es., Fiddler) può simulare la distribuzione supply-chain sostituendo gli RFA nel traffico dei plugin a scopo di testing.

## Riferimenti

- [1] [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
