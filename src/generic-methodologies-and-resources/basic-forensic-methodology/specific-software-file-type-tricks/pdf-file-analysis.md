# Analisi dei file PDF

**Per ulteriori dettagli, consulta:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Il formato PDF è noto per la sua complessità e per il potenziale di occultamento dei dati, rendendolo un punto centrale nelle sfide di CTF forensics. Combina elementi in testo semplice con oggetti binari, che potrebbero essere compressi o cifrati, e può includere script in linguaggi come JavaScript o Flash. Per comprendere la struttura dei PDF, è possibile consultare il [materiale introduttivo](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) di Didier Stevens oppure utilizzare strumenti come un editor di testo o un editor specifico per PDF, come Origami.

Per un'analisi o una manipolazione approfondita dei PDF, sono disponibili strumenti come [qpdf](https://github.com/qpdf/qpdf) e [Origami](https://github.com/mobmewireless/origami-pdf). I dati nascosti all'interno dei PDF potrebbero essere occultati in:

- Livelli invisibili
- Formato dei metadati XMP di Adobe
- Generazioni incrementali
- Testo dello stesso colore dello sfondo
- Testo dietro immagini o immagini sovrapposte
- Commenti non visualizzati

Per l'analisi personalizzata dei PDF, è possibile utilizzare librerie Python come [PeepDF](https://github.com/jesparza/peepdf) per creare script di parsing su misura. Inoltre, il potenziale dei PDF come contenitori di dati nascosti è così vasto che risorse come la guida della NSA sui rischi dei PDF e sulle contromisure, sebbene non sia più ospitata nella sua posizione originale, continuano a offrire informazioni preziose. Una [copia della guida](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) e una raccolta di [trucchi per il formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) di Ange Albertini possono fornire ulteriori approfondimenti sull'argomento.<sup>[[4]](#references)[[5]](#references)</sup>

## Costrutti malevoli comuni

Gli attaccanti spesso abusano di oggetti e azioni PDF specifici che vengono eseguiti automaticamente quando il documento viene aperto o utilizzato. Parole chiave da cercare:

* **/OpenAction, /AA** – azioni automatiche eseguite all'apertura o in occasione di eventi specifici.
* **/JS, /JavaScript** – JavaScript incorporato (spesso offuscato o suddiviso tra più oggetti).
* **/Launch, /SubmitForm, /URI, /GoToE** – launcher di processi esterni / URL.
* **/RichMedia, /Flash, /3D** – oggetti multimediali che possono nascondere payload.
* **/EmbeddedFile /Filespec** – allegati di file (EXE, DLL, OLE, ecc.).
* **/ObjStm, /XFA, /AcroForm** – stream di oggetti o moduli comunemente abusati per nascondere shell-code.
* **Aggiornamenti incrementali** – più marcatori %%EOF o un offset **/Prev** molto grande possono indicare dati aggiunti dopo la firma per eludere l'AV.

Quando uno qualsiasi dei token precedenti compare insieme a stringhe sospette (powershell, cmd.exe, calc.exe, base64, ecc.), il PDF merita un'analisi più approfondita.

---

## Cheat sheet per l'analisi statica

Gli esempi seguenti utilizzano le interfacce a riga di comando documentate di `pdf-parser.py`, qpdf e pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – pass supported streams through their declared filters
pdf-parser.py -f suspicious.pdf
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
Progetti aggiuntivi utili (attivamente mantenuti nel periodo 2023-2025):
* **pdfcpu** – libreria/CLI Go in grado di validare, decrittografare, estrarre, ottimizzare e manipolare PDF.<sup>[[9]](#references)</sup>
* **pdf-inspector** – visualizzatore basato su browser che esegue il rendering del grafo degli oggetti e degli stream.
* **PyMuPDF** – binding Python programmabili per ispezionare PDF ed eseguire il rendering delle pagine in immagini raster. Considera il parser/renderer una superficie di attacco costituita da file non attendibili ed eseguilo all'interno di un ambiente di analisi adeguatamente isolato.<sup>[[8]](#references)</sup>

---

## Tecniche di attacco recenti (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC ha segnalato una tecnica che aggiunge a un PDF un file MHT creato con Word e contenente macro VBA, mantenendo la magic del PDF e aprendosi anche in Word. Gli strumenti di analisi che analizzano solo PDF, le sandbox o gli antivirus potrebbero non rilevare la macro, perché il comportamento malevolo si verifica quando il file viene aperto come documento Word; cerca il marker `<w:WordDocument>` insieme ad altri indicatori MHT.<sup>[[2]](#references)</sup>
* **Shadow attacks su PDF firmati** – gli attaccanti possono inserire contenuti nascosti in un PDF prima che venga firmato, quindi aggiungere un aggiornamento incrementale che modifica i riferimenti al catalogo o agli oggetti, in modo che i visualizzatori mostrino il contenuto nascosto mentre la firma originale rimane valida. La tecnica può eludere i visualizzatori che classificano tali aggiornamenti come innocui.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe valuta questa vulnerabilità critica come una use-after-free che può portare all'esecuzione di codice arbitrario; APSB24-29 è stato pubblicato il 14 maggio 2024.<sup>[[3]](#references)</sup>

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

1. **Applicare rapidamente le patch** – mantenere Acrobat/Reader sul più recente ramo Continuous; la maggior parte delle catene RCE osservate in the wild sfrutta vulnerabilità n-day corrette mesi prima.
2. **Rimuovere i contenuti attivi al gateway** – utilizzare un sanitizer o un prodotto CDR appositamente progettato e controllato da policy che rimuova esplicitamente JavaScript, file incorporati, azioni di avvio, moduli e contenuti multimediali. `qpdf --qdf` facilita l'ispezione degli oggetti PDF, mentre pdfcpu offre funzionalità di validazione e manipolazione; nessuno dei due comandi, da solo, dimostra che il contenuto attivo sia stato rimosso.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – convertire i PDF in immagini (o PDF/A) su un sandbox host per preservare la fedeltà visiva eliminando al contempo gli oggetti attivi.
4. **Bloccare le funzionalità utilizzate raramente** – le impostazioni enterprise di “Enhanced Security” in Reader consentono di disabilitare JavaScript, contenuti multimediali e rendering 3D.
5. **Formazione degli utenti** – la social engineering (esche con fatture e curriculum) rimane il vettore iniziale; insegnare ai dipendenti a inoltrare gli allegati sospetti al team IR.

## References

- [1] [Guida sul campo Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Bypass del rilevamento tramite incorporamento di un file Word malevolo in un file PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Bollettino di sicurezza Adobe – Aggiornamento di sicurezza disponibile per Adobe Acrobat e Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - copia della guida](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - trucchi del formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: occultamento e sostituzione dei contenuti nei PDF firmati](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [Tutorial di PyMuPDF](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Opzioni della riga di comando di qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
