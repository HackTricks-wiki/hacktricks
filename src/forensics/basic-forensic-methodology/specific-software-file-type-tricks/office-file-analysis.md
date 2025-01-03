# Analisi dei file Office

{{#include ../../../banners/hacktricks-training.md}}

Per ulteriori informazioni controlla [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Questo è solo un riassunto:

Microsoft ha creato molti formati di documenti office, con due tipi principali che sono i **formati OLE** (come RTF, DOC, XLS, PPT) e i **formati Office Open XML (OOXML)** (come DOCX, XLSX, PPTX). Questi formati possono includere macro, rendendoli obiettivi per phishing e malware. I file OOXML sono strutturati come contenitori zip, consentendo l'ispezione tramite decompressione, rivelando la gerarchia di file e cartelle e i contenuti dei file XML.

Per esplorare le strutture dei file OOXML, viene fornito il comando per decomprimere un documento e la struttura di output. Tecniche per nascondere dati in questi file sono state documentate, indicando un'innovazione continua nella dissimulazione dei dati all'interno delle sfide CTF.

Per l'analisi, **oletools** e **OfficeDissector** offrono set di strumenti completi per esaminare sia i documenti OLE che OOXML. Questi strumenti aiutano a identificare e analizzare le macro incorporate, che spesso fungono da vettori per la consegna di malware, tipicamente scaricando ed eseguendo payload dannosi aggiuntivi. L'analisi delle macro VBA può essere condotta senza Microsoft Office utilizzando Libre Office, che consente il debug con punti di interruzione e variabili di osservazione.

L'installazione e l'uso di **oletools** sono semplici, con comandi forniti per l'installazione tramite pip e l'estrazione di macro dai documenti. L'esecuzione automatica delle macro è attivata da funzioni come `AutoOpen`, `AutoExec` o `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
{{#include ../../../banners/hacktricks-training.md}}
