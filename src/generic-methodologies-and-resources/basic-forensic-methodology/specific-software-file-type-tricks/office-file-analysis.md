# Analisi dei file Office

Per ulteriori informazioni, consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Questo è solo un riepilogo:<sup>[[4]](#references)</sup>

I documenti Microsoft Office si presentano comunemente come formati legacy, ad esempio RTF e DOC, XLS e PPT basati su OLE/CFBF, oppure come formati più recenti **Office Open XML (OOXML)**, come DOCX, XLSX e PPTX. I documenti Office possono contenere active content, come le macro, rendendoli vettori comuni per phishing e malware. I file OOXML sono contenitori ZIP, la cui gerarchia dei file e i cui contenuti XML possono essere esaminati decomprimendoli.<sup>[[3]](#references)[[4]](#references)</sup>

Per esplorare le strutture dei file OOXML, vengono forniti il comando per decomprimere un documento e la struttura dell'output. Sono state documentate tecniche per nascondere dati in questi file, indicando una continua innovazione nel concealment dei dati all'interno delle challenge CTF.<sup>[[4]](#references)</sup>

Per l'analisi, **oletools** e **OfficeDissector** offrono toolset completi per esaminare sia documenti OLE sia OOXML. Questi strumenti aiutano a identificare e analizzare le macro incorporate, che spesso fungono da vettori per la distribuzione di malware, scaricando ed eseguendo in genere ulteriori payload dannosi. L'analisi delle macro VBA può essere eseguita senza Microsoft Office utilizzando Libre Office, che consente il debugging con breakpoint e watch variables.<sup>[[4]](#references)</sup>

L'installazione e l'utilizzo di **oletools** sono semplici, con comandi forniti per l'installazione tramite pip e l'estrazione delle macro dai documenti. In Word, le macro automatiche includono `AutoExec` e `AutoOpen`, mentre `Document_Open` è una procedura di evento di apertura.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Sfruttamento di OLE Compound File: Autodesk Revit RFA – ricalcolo ECC e gzip controllato

I modelli Revit RFA sono archiviati come [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (detto anche CFBF). Il modello serializzato si trova in storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Struttura principale di `Global\Latest` (osservata su Revit 2025):

- Header
- Payload compresso con GZIP (il grafo effettivo degli oggetti serializzati)
- Padding a zero
- Trailer dell'Error-Correcting Code (ECC)

Revit ripara automaticamente piccole perturbazioni dello stream utilizzando il trailer ECC e rifiuta gli stream che non corrispondono all'ECC. Pertanto, modificare ingenuamente i byte compressi non sarà permanente: le modifiche vengono ripristinate oppure il file viene rifiutato. Per garantire un controllo byte-accurate su ciò che vede il deserializzatore è necessario:<sup>[[1]](#references)</sup>

- Ricomprimere con un'implementazione gzip compatibile con Revit (in modo che i byte compressi prodotti/accettati da Revit corrispondano a quelli attesi).
- Ricalcolare il trailer ECC sullo stream con padding, affinché Revit accetti lo stream modificato senza ripararlo automaticamente.

Workflow pratico per il patching/fuzzing dei contenuti RFA:<sup>[[1]](#references)</sup>

1) Espandere il documento OLE compound.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Modifica `Global\Latest` seguendo le procedure gzip/ECC

- Scomponi `Global/Latest`: conserva l’header, esegui il gunzip del payload, modifica i byte, quindi esegui nuovamente il gzip usando parametri deflate compatibili con Revit.
- Mantieni il padding a zero e ricalcola il trailer ECC affinché i nuovi byte vengano accettati da Revit.
- Se ti serve una riproduzione deterministica byte per byte, crea un wrapper minimale attorno alle DLL di Revit per richiamare i relativi percorsi gzip/gunzip e il calcolo ECC (come dimostrato nella ricerca), oppure riutilizza qualsiasi helper disponibile che replichi queste semantiche.

3) Ricostruisci il documento composto OLE.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Note:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool scrive storage/stream nel filesystem eseguendo l’escaping dei caratteri non validi nei nomi NTFS; il percorso dello stream desiderato è esattamente `Global/Latest` nell’albero di output.
- Quando si distribuiscono mass attacks tramite plugin dell’ecosystem che recuperano RFA dal cloud storage, assicurarsi che l’RFA sottoposto a patch superi prima localmente i controlli di integrità di Revit (gzip/ECC corretti), prima di tentare la network injection.

Insight sull’exploitation (per guidare quali byte inserire nel payload gzip):<sup>[[1]](#references)</sup>

- Il deserializer di Revit legge un class index a 16 bit e costruisce un object. Alcuni tipi non sono polymorphic e non hanno vtable; l’abuso della gestione del destructor produce una type confusion in cui il motore esegue una indirect call tramite un pointer controllato dall’attaccante.
- Selezionando `AString` (class index `0x1F`), si inserisce un heap pointer controllato dall’attaccante all’object offset 0. Durante il destructor loop, Revit esegue di fatto:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Inserisci più oggetti di questo tipo nel grafo serializzato, in modo che ogni iterazione del loop del destructor esegua un gadget (“weird machine”), e organizza uno stack pivot verso una catena ROP x64 convenzionale.

Consulta qui i dettagli sulla creazione di pivot/gadget per Windows x64:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

e qui la guida generale su ROP:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Strumenti:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) per espandere/ricostruire file compound OLE: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD per reverse engineering/taint analysis; disabilita page heap con TTD per mantenere compatte le tracce.
- Un proxy locale (ad es., Fiddler) può simulare la distribuzione supply-chain sostituendo gli RFA nel traffico del plugin a scopo di test.

## References

- [1] [Creazione di un exploit RCE completo a partire da un crash nel parsing di file RFA di Autodesk Revit (blog ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [File compound OLE (CFBF), documentazione](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Guida sul campo Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [Documentazione olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Macro automatiche (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Evento Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
