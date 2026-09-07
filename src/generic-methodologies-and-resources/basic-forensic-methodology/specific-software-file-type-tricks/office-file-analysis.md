# Analisi dei file Office

{{#include ../../../banners/hacktricks-training.md}}

Per ulteriori informazioni, consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Questo è solo un riepilogo:<sup>[[4]](#references)</sup>

I documenti Microsoft Office si presentano comunemente in formati legacy come RTF e DOC, XLS e PPT basati su OLE/CFBF, oppure nei più recenti formati **Office Open XML (OOXML)** come DOCX, XLSX e PPTX. I documenti Office possono contenere active content come le macro, rendendoli vettori comuni per phishing e malware. I file OOXML sono container ZIP, la cui gerarchia dei file e i cui contenuti XML possono essere esaminati decomprimendoli.<sup>[[3]](#references)[[4]](#references)</sup>

Per esplorare le strutture dei file OOXML, vengono forniti il comando per decomprimere un documento e la struttura dell'output. Sono state documentate tecniche per nascondere dati in questi file, a dimostrazione dell'innovazione continua nell'occultamento dei dati nelle challenge CTF.<sup>[[4]](#references)</sup>

Per l'analisi, **oletools** e **OfficeDissector** offrono toolset completi per esaminare sia i documenti OLE sia quelli OOXML. Questi tool aiutano a identificare e analizzare le macro incorporate, che spesso fungono da vettori per la distribuzione di malware, scaricando ed eseguendo solitamente ulteriori payload malevoli. L'analisi delle macro VBA può essere eseguita senza Microsoft Office utilizzando Libre Office, che consente il debugging con breakpoint e variabili osservate.<sup>[[4]](#references)</sup>

L'installazione e l'utilizzo di **oletools** sono semplici, con comandi per l'installazione tramite pip e l'estrazione delle macro dai documenti. In Word, le macro automatiche includono `AutoExec` e `AutoOpen`, mentre `Document_Open` è una procedura di evento di apertura.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
Per i documenti Office protetti da password, consulta il [grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Exploitation di OLE Compound File: Autodesk Revit RFA – ricalcolo ECC e gzip controllato

I modelli Revit RFA sono memorizzati come [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (noto anche come CFBF). Il modello serializzato si trova in storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Struttura principale di `Global\Latest` (osservata in Revit 2025):

- Header
- Payload compresso con GZIP (l'object graph serializzato effettivo)
- Padding di zeri
- Trailer dell'Error-Correcting Code (ECC)

Revit ripara automaticamente piccole alterazioni allo stream utilizzando il trailer ECC e rifiuta gli stream che non corrispondono all'ECC. Pertanto, modificare ingenuamente i byte compressi non rende persistenti le modifiche: le modifiche vengono ripristinate oppure il file viene rifiutato. Per garantire un controllo byte-accurate su ciò che vede il deserializer devi:<sup>[[1]](#references)</sup>

- Ricomprimere con un'implementazione gzip compatibile con Revit (in modo che i byte compressi prodotti/accettati da Revit corrispondano a quelli attesi).
- Ricalcolare il trailer ECC sullo stream con padding, così Revit accetterà lo stream modificato senza ripararlo automaticamente.

Workflow pratico per applicare patch o eseguire fuzzing sui contenuti RFA:<sup>[[1]](#references)</sup>

1) Espandere il documento OLE compound.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Modifica `Global\Latest` rispettando gzip/ECC

- Scomponi `Global/Latest`: mantieni l'header, esegui il gunzip del payload, modifica i bytes, quindi esegui nuovamente gzip usando parametri deflate compatibili con Revit.
- Conserva lo zero-padding e ricalcola il trailer ECC affinché i nuovi bytes vengano accettati da Revit.
- Se ti serve una riproduzione deterministica byte per byte, crea un wrapper minimale intorno alle DLL di Revit per richiamare i relativi percorsi gzip/gunzip e il calcolo ECC (come dimostrato nella ricerca), oppure riutilizza un helper disponibile che replichi queste semantiche.

3) Ricostruisci il documento composto OLE.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Note:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool scrive gli storage/stream nel filesystem eseguendo l’escaping dei caratteri non validi nei nomi NTFS; il percorso dello stream desiderato è esattamente `Global/Latest` nell’albero di output.
- Quando si eseguono mass attacks tramite ecosystem plugins che recuperano RFA dal cloud storage, assicurati che il tuo RFA patched superi prima localmente gli integrity checks di Revit (gzip/ECC corretti) prima di tentare l’injection sulla rete.

Exploitation insight (per guidare quali byte inserire nel payload gzip):<sup>[[1]](#references)</sup>

- Il deserializer di Revit legge un class index a 16 bit e costruisce un object. Alcuni tipi sono non-polymorphic e privi di vtable; l’abuso della gestione del destructor produce una type confusion in cui l’engine esegue una indirect call tramite un pointer controllato dall’attacker.
- La scelta di `AString` (class index `0x1F`) inserisce un heap pointer controllato dall’attacker all’object offset 0. Durante il destructor loop, Revit esegue di fatto:
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

e qui le indicazioni generali sulla ROP:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Strumenti:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) per espandere/ricostruire file compound OLE: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD per reverse engineering/taint analysis; disabilita il page heap con TTD per mantenere le tracce compatte.
- Un proxy locale (ad esempio Fiddler) può simulare la distribuzione supply-chain sostituendo gli RFA nel traffico dei plugin a scopo di test.

## References

- [1] [Creazione di un exploit RCE completo a partire da un crash nel parsing di file RFA di Autodesk Revit (blog ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [File compound OLE (CFBF), documentazione](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Guida pratica Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [Documentazione olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Macro automatiche (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Evento Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
