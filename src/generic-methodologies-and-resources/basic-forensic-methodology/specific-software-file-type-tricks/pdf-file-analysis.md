# Analisi dei file PDF

{{#include ../../../banners/hacktricks-training.md}}

**Per ulteriori dettagli controlla:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

Il formato PDF è noto per la sua complessità e il potenziale di nascondere dati, rendendolo un punto focale per le sfide forensi CTF. Combina elementi di testo semplice con oggetti binari, che potrebbero essere compressi o crittografati, e può includere script in linguaggi come JavaScript o Flash. Per comprendere la struttura del PDF, si può fare riferimento al [materiale introduttivo di Didier Stevens](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/), o utilizzare strumenti come un editor di testo o un editor specifico per PDF come Origami.

Per un'esplorazione o manipolazione approfondita dei PDF, sono disponibili strumenti come [qpdf](https://github.com/qpdf/qpdf) e [Origami](https://github.com/mobmewireless/origami-pdf). I dati nascosti all'interno dei PDF potrebbero essere celati in:

- Livelli invisibili
- Formato di metadati XMP di Adobe
- Generazioni incrementali
- Testo dello stesso colore dello sfondo
- Testo dietro immagini o immagini sovrapposte
- Commenti non visualizzati

Per un'analisi personalizzata dei PDF, si possono utilizzare librerie Python come [PeepDF](https://github.com/jesparza/peepdf) per creare script di parsing su misura. Inoltre, il potenziale del PDF per la memorizzazione di dati nascosti è così vasto che risorse come la guida della NSA sui rischi e le contromisure dei PDF, sebbene non più ospitata nella sua posizione originale, offrono ancora preziose informazioni. Una [copia della guida](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) e una raccolta di [trucchi sul formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) di Ange Albertini possono fornire ulteriori letture sull'argomento.

## Costrutti Maligni Comuni

Gli attaccanti abusano spesso di specifici oggetti e azioni PDF che vengono eseguiti automaticamente quando il documento viene aperto o interagito. Parole chiave da cercare:

* **/OpenAction, /AA** – azioni automatiche eseguite all'apertura o in eventi specifici.
* **/JS, /JavaScript** – JavaScript incorporato (spesso offuscato o suddiviso tra oggetti).
* **/Launch, /SubmitForm, /URI, /GoToE** – avviatori di processi esterni / URL.
* **/RichMedia, /Flash, /3D** – oggetti multimediali che possono nascondere payload.
* **/EmbeddedFile /Filespec** – allegati di file (EXE, DLL, OLE, ecc.).
* **/ObjStm, /XFA, /AcroForm** – flussi di oggetti o moduli comunemente abusati per nascondere shell-code.
* **Aggiornamenti incrementali** – più marcatori %%EOF o un offset **/Prev** molto grande possono indicare dati aggiunti dopo la firma per bypassare AV.

Quando uno dei token precedenti appare insieme a stringhe sospette (powershell, cmd.exe, calc.exe, base64, ecc.) il PDF merita un'analisi più approfondita.

---

## Scheda di riferimento per l'analisi statica
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – decompress/inspect the object tree
pdf-parser.py -f suspicious.pdf                # interactive
pdf-parser.py -a suspicious.pdf                # automatic report

# Search for JavaScript and pretty-print it
pdf-parser.py -search "/JS" -raw suspicious.pdf | js-beautify -

# Dump embedded files
peepdf "open suspicious.pdf" "objects embeddedfile" "extract 15 16 17" -o dumps/

# Remove passwords / encryptions before processing with other tools
qpdf --password='secret' --decrypt suspicious.pdf clean.pdf

# Lint the file with a Go verifier (checks structure violations)
pdfcpu validate -mode strict clean.pdf
```
Progetti utili aggiuntivi (attivamente mantenuti 2023-2025):
* **pdfcpu** – Libreria/CLI Go in grado di *lint*, *decriptare*, *estrarre*, *comprimere* e *sanitizzare* i PDF.
* **pdf-inspector** – Visualizzatore basato su browser che rende il grafo degli oggetti e i flussi.
* **PyMuPDF (fitz)** – Motore Python scriptabile che può rendere in modo sicuro le pagine in immagini per attivare JS incorporato in un sandbox rinforzato.

---

## Tecniche di attacco recenti (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC ha osservato attori minacciosi che aggiungono un documento Word basato su MHT con macro VBA dopo il finale **%%EOF**, producendo un file che è sia un PDF valido che un DOC valido. I motori AV che analizzano solo il livello PDF mancano la macro. Le parole chiave statiche del PDF sono pulite, ma `file` stampa ancora `%PDF`. Tratta qualsiasi PDF che contiene anche la stringa `<w:WordDocument>` come altamente sospetto.
* **Aggiornamenti incrementali shadow (2024)** – Gli avversari abusano della funzione di aggiornamento incrementale per inserire un secondo **/Catalog** con un `/OpenAction` malevolo mantenendo la prima revisione benigna firmata. Gli strumenti che ispezionano solo la prima tabella xref vengono elusi.
* **Catena UAF di parsing dei font – CVE-2024-30284 (Acrobat/Reader)** – Una funzione vulnerabile di **CoolType.dll** può essere raggiunta da font CIDType2 incorporati, consentendo l'esecuzione di codice remoto con i privilegi dell'utente una volta aperto un documento creato ad hoc. Corretto in APSB24-29, maggio 2024.

---

## Modello rapido di regola YARA
```yara
rule Suspicious_PDF_AutoExec {
meta:
description = "Generic detection of PDFs with auto-exec actions and JS"
author      = "HackTricks"
last_update = "2025-07-20"
strings:
$pdf_magic = { 25 50 44 46 }          // %PDF
$aa        = "/AA" ascii nocase
$openact   = "/OpenAction" ascii nocase
$js        = "/JS" ascii nocase
condition:
$pdf_magic at 0 and ( all of ($aa, $openact) or ($openact and $js) )
}
```
---

## Suggerimenti difensivi

1. **Aggiorna rapidamente** – mantieni Acrobat/Reader sulla versione più recente del Continuous track; la maggior parte delle catene RCE osservate in natura sfrutta vulnerabilità n-day risolte mesi prima.
2. **Rimuovi contenuti attivi al gateway** – usa `pdfcpu sanitize` o `qpdf --qdf --remove-unreferenced` per eliminare JavaScript, file incorporati e azioni di avvio dai PDF in entrata.
3. **Disarmo e ricostruzione dei contenuti (CDR)** – converti i PDF in immagini (o PDF/A) su un host sandbox per preservare la fedeltà visiva mentre scarti oggetti attivi.
4. **Blocca funzionalità raramente utilizzate** – le impostazioni di “Sicurezza avanzata” in Reader consentono di disabilitare JavaScript, multimedia e rendering 3D.
5. **Educazione degli utenti** – l'ingegneria sociale (inganni su fatture e curriculum) rimane il vettore iniziale; insegna ai dipendenti a inoltrare allegati sospetti all'IR.

## Riferimenti

* JPCERT/CC – “MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file” (Ago 2023)
* Adobe – Aggiornamento di sicurezza per Acrobat e Reader (APSB24-29, Mag 2024)

{{#include ../../../banners/hacktricks-training.md}}
