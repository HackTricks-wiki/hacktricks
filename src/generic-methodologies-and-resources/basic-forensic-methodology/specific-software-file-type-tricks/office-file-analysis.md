# Analisi dei file Office

{{#include ../../../banners/hacktricks-training.md}}

Per ulteriori informazioni, consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Questa è solo una sintesi:<sup>[[2]](#references)</sup>

I documenti Microsoft Office si presentano comunemente in formati legacy come RTF e DOC, XLS e PPT basati su OLE/CFBF, oppure nei più recenti formati **Office Open XML (OOXML)**, come DOCX, XLSX e PPTX. I documenti Office possono contenere contenuti attivi come le macro, il che li rende vettori comuni per il phishing e il malware. I file OOXML sono archivi ZIP la cui gerarchia di file e i cui contenuti XML possono essere esaminati decomprimendoli.<sup>[[1]](#references)[[2]](#references)</sup>

Vengono forniti il comando per decomprimere un documento e la struttura risultante, così da esplorare la struttura dei file OOXML. Sono state documentate tecniche per nascondere dati in questi file, a dimostrazione della continua innovazione nell'occultamento dei dati nelle sfide CTF.<sup>[[2]](#references)</sup>

Per l'analisi, **oletools** e **OfficeDissector** offrono set completi di strumenti per esaminare documenti OLE e OOXML. Questi strumenti aiutano a individuare e analizzare le macro incorporate, che spesso fungono da vettori per la distribuzione di malware e in genere scaricano ed eseguono ulteriori payload malevoli. È possibile analizzare le macro VBA senza Microsoft Office utilizzando LibreOffice, che consente il debugging con breakpoint e variabili di controllo.<sup>[[2]](#references)</sup>

Installare e utilizzare **oletools** è semplice: sono forniti comandi per installarlo tramite pip e per estrarre le macro dai documenti. In Word, le macro automatiche includono `AutoExec` e `AutoOpen`, mentre `Document_Open` è una procedura associata all'evento di apertura.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## Analisi delle macro VBA: codice spazzatura e UserForms

## Codice spazzatura

Le macro possono contenere **codice irraggiungibile o irrilevante** progettato per rallentare l'analisi. Individua le condizioni costanti e ricostruisci il comportamento raggiungibile prima di dedicare tempo al reverse engineering di un ramo. L'esempio seguente usa una condizione `If` che non può mai essere vera per nascondere codice spazzatura.

![Una macro Word con un ramo condizionale irraggiungibile contenente codice spazzatura](<../../../images/image (369).png>)

## Form delle macro

I VBA UserForms possono memorizzare dati in controlli come le caselle di testo. Poiché form, frame e pagine possono esporre ciascuno una raccolta `Controls`, gli analisti dovrebbero enumerare l'intera gerarchia dei controlli, anziché basarsi solo su ciò che mostra il form. L'esempio seguente memorizza dati nascosti in caselle di testo sovrapposte.<sup>[[6]](#references)</sup>

Durante l'analisi dinamica, la funzione `GetObject` di VBA può recuperare un oggetto Automation da un file o collegarsi a un server Automation già in esecuzione. Le macro possono usare questo accesso agli oggetti per raggiungere dati non immediatamente visibili nel documento; esamina sia l'oggetto restituito sia l'albero dei controlli del UserForm.<sup>[[7]](#references)</sup>

![Un UserForm di una macro con dati nascosti in caselle di testo sovrapposte](<../../../images/image (344).png>)

Per i documenti Office protetti da password, consulta il [flusso di lavoro di recupero offline basato su grammatiche](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

Per i file Revit RFA che usano OLE/CFBF, consulta [ricalcolo ECC, gzip controllato e sfruttamento del deserializzatore](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md); questo flusso di lavoro di sfruttamento del parser è distinto dall'analisi preliminare dei documenti Office.

## References

- [1] [Documentazione di OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [Guida pratica forense per le CTF](https://trailofbits.github.io/ctf/forensics/)
- [3] [Documentazione di olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [Macro automatiche (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Evento Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn - Raccolte, controlli e oggetti (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn - Funzione `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../../../banners/hacktricks-training.md}}
