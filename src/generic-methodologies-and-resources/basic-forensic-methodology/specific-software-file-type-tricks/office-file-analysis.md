# Analisi dei file Office

{{#include ../../../banners/hacktricks-training.md}}

Per ulteriori informazioni, consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Questa è solo una sintesi:<sup>[[4]](#references)</sup>

I documenti Microsoft Office si presentano comunemente in formati legacy come RTF e DOC, XLS e PPT basati su OLE/CFBF, oppure nei più recenti formati **Office Open XML (OOXML)** come DOCX, XLSX e PPTX. I documenti Office possono contenere contenuti attivi come le macro, il che li rende vettori comuni per phishing e malware. I file OOXML sono archivi ZIP la cui gerarchia di file e i cui contenuti XML possono essere ispezionati decomprimendoli.<sup>[[3]](#references)[[4]](#references)</sup>

Per esplorare le strutture dei file OOXML, vengono forniti il comando per decomprimere un documento e la struttura risultante. Sono state documentate tecniche per nascondere dati in questi file, a indicare l'innovazione continua nelle tecniche di occultamento dei dati nelle challenge CTF.<sup>[[4]](#references)</sup>

Per l'analisi, **oletools** e **OfficeDissector** offrono set completi di strumenti per esaminare sia i documenti OLE sia quelli OOXML. Questi strumenti aiutano a identificare e analizzare le macro incorporate, che spesso fungono da vettori per la distribuzione di malware e in genere scaricano ed eseguono ulteriori payload dannosi. L'analisi delle macro VBA può essere eseguita senza Microsoft Office utilizzando LibreOffice, che consente il debugging con breakpoint e variabili di controllo.<sup>[[4]](#references)</sup>

L'installazione e l'utilizzo di **oletools** sono semplici: sono forniti comandi per installarlo tramite pip ed estrarre le macro dai documenti. In Word, le macro automatiche includono `AutoExec` e `AutoOpen`, mentre `Document_Open` è una procedura evento di apertura.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

Per i documenti Office crittografati con password, consulta il [flusso di lavoro offline di recupero basato sulla grammatica](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Sfruttamento di OLE Compound File: Autodesk Revit RFA – ricalcolo ECC e gzip controllato

I modelli Revit RFA sono archiviati come [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (detto anche CFBF). Il modello serializzato si trova in uno storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Struttura principale di `Global\Latest` (osservata in Revit 2025):

- Header
- Payload compresso con GZIP (il grafo degli oggetti serializzato effettivo)
- Padding con zeri
- Trailer ECC (codice di correzione degli errori)

Revit ripara automaticamente piccole alterazioni dello stream usando il trailer ECC e rifiuta gli stream che non corrispondono all’ECC. Pertanto, modificare ingenuamente i byte compressi non basta: le modifiche vengono annullate oppure il file viene rifiutato. Per controllare con precisione i byte che il deserializzatore riceve, è necessario:<sup>[[1]](#references)</sup>

- Ricomprimere con un’implementazione gzip compatibile con Revit, in modo che i byte compressi prodotti/accettati da Revit corrispondano a quelli previsti.
- Ricalcolare il trailer ECC sullo stream con padding, affinché Revit accetti lo stream modificato senza ripararlo automaticamente.

Flusso di lavoro pratico per modificare/fuzzare i contenuti RFA:<sup>[[1]](#references)</sup>

1) Espandere il documento OLE Compound.<sup>[[2]](#references)</sup>

```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```

2) Modifica Global\Latest seguendo le regole per gzip/ECC

- Scomponi `Global/Latest`: mantieni l’header, decomprimi il payload con gunzip, modifica i byte e ricomprimili con gzip usando parametri deflate compatibili con Revit.
- Mantieni il padding a zero e ricalcola il trailer ECC, così Revit accetterà i nuovi byte.
- Se ti serve una riproduzione deterministica byte per byte, crea un wrapper minimale attorno alle DLL di Revit per richiamare i suoi percorsi gzip/gunzip e il calcolo ECC (come illustrato nella ricerca), oppure riutilizza un helper disponibile che replichi queste semantiche.

3) Ricostruisci il documento composto OLE.<sup>[[2]](#references)</sup>

```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```

Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool scrive storage/stream sul filesystem, eseguendo l’escaping dei caratteri non validi nei nomi NTFS; il percorso dello stream desiderato nell’albero di output è esattamente `Global/Latest`.
- Quando distribuisci attacchi su larga scala tramite plugin dell’ecosistema che recuperano RFA dal cloud storage, assicurati prima che il file RFA patchato superi localmente i controlli di integrità di Revit (gzip/ECC corretti) prima di tentare l’iniezione di rete.

Exploitation insight (per guidare la scelta dei byte da inserire nel payload gzip):<sup>[[1]](#references)</sup>

- Il deserializer di Revit legge un indice di classe a 16 bit e istanzia un oggetto. Alcuni tipi non sono polimorfici e non hanno vtable; abusare della gestione dei distruttori genera una type confusion in cui il motore esegue una chiamata indiretta tramite un puntatore controllato dall’attaccante.
- Scegliendo `AString` (indice di classe `0x1F`), si inserisce un puntatore heap controllato dall’attaccante all’offset 0 dell’oggetto. Durante il ciclo dei distruttori, Revit esegue di fatto:

```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```

- Inserisci più oggetti di questo tipo nel grafo serializzato, in modo che ogni iterazione del ciclo del distruttore esegua un gadget («weird machine»), quindi organizza uno stack pivot verso una chain ROP x64 convenzionale.

Consulta qui i dettagli sulla creazione di stack pivot/gadget per Windows x64:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

e qui le indicazioni generali su ROP:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Strumenti:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) per espandere/ricostruire file OLE compound: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD per reverse engineering/taint analysis; disabilita page heap con TTD per mantenere compatte le tracce.
- Un proxy locale (ad es. Fiddler) può simulare la distribuzione tramite supply chain, sostituendo gli RFA nel traffico dei plugin a scopo di test.

## References

- [1] [Creare un exploit RCE completo partendo da un crash nell'analisi dei file RFA di Autodesk Revit (blog ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Documentazione sui file OLE Compound (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Guida pratica forense per CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [Documentazione di olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Macro automatiche (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Evento Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
