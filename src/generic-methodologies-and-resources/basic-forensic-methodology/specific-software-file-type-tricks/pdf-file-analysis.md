# Analisi dei file PDF

{{#include ../../../banners/hacktricks-training.md}}

**Per ulteriori dettagli, consulta:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

Il formato PDF è noto per la sua complessità e per il potenziale di nascondere dati, il che lo rende un elemento centrale nelle challenge di CTF forensics. Combina elementi in testo semplice con oggetti binari, che possono essere compressi o crittografati, e può includere script in linguaggi come JavaScript o Flash. Per comprendere la struttura dei PDF, è possibile consultare il [materiale introduttivo](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) di Didier Stevens oppure usare strumenti come un editor di testo o un editor specifico per PDF come Origami.

Per un'esplorazione o una manipolazione approfondita dei PDF, sono disponibili strumenti come [qpdf](https://github.com/qpdf/qpdf) e [Origami](https://github.com/mobmewireless/origami-pdf). I dati nascosti nei PDF possono essere occultati in:

- Livelli invisibili
- Formato dei metadati XMP di Adobe
- Generazioni incrementali
- Testo dello stesso colore dello sfondo
- Testo dietro immagini o immagini sovrapposte
- Commenti non visualizzati

Per un'analisi personalizzata dei PDF, è possibile usare librerie Python come [PeepDF](https://github.com/jesparza/peepdf) per creare script di parsing su misura. Inoltre, il potenziale dei PDF come archivio di dati nascosti è così vasto che risorse come la guida dell'NSA sui rischi dei PDF e sulle contromisure, sebbene non sia più ospitata nella sua posizione originale, offrono ancora indicazioni preziose. Una [copia della guida](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) e una raccolta di [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) di Ange Albertini possono fornire ulteriori approfondimenti sull'argomento.<sup>[[4]](#references)[[5]](#references)</sup>

## Costrutti malevoli comuni

Gli attaccanti spesso abusano di oggetti e azioni PDF specifici che vengono eseguiti automaticamente quando il documento viene aperto o utilizzato. Le keyword da cercare includono:

* **/OpenAction, /AA** – azioni automatiche eseguite all'apertura o in occasione di eventi specifici.
* **/JS, /JavaScript** – JavaScript incorporato (spesso offuscato o suddiviso tra più oggetti).
* **/Launch, /SubmitForm, /URI, /GoToE** – launcher di processi esterni / URL.
* **/RichMedia, /Flash, /3D** – oggetti multimediali che possono nascondere payload.
* **/EmbeddedFile /Filespec** – allegati di file (EXE, DLL, OLE, ecc.).
* **/ObjStm, /XFA, /AcroForm** – object stream o form spesso abusati per nascondere shell-code.
* **Aggiornamenti incrementali** – più marcatori %%EOF o un offset **/Prev** molto grande possono indicare dati aggiunti dopo la firma per eludere l'AV.

Quando uno qualsiasi dei token precedenti compare insieme a stringhe sospette (powershell, cmd.exe, calc.exe, base64, ecc.), il PDF merita un'analisi più approfondita.

---

## Cheat-sheet per l'analisi statica
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
Progetti aggiuntivi utili (mantenuti attivamente nel periodo 2023-2025):
* **pdfcpu** – libreria/CLI Go in grado di eseguire *lint*, *decrypt*, *extract*, *compress* e *sanitize* dei PDF.
* **pdf-inspector** – visualizzatore basato su browser che esegue il rendering del grafo degli oggetti e degli stream.
* **PyMuPDF (fitz)** – motore Python scriptable in grado di eseguire il rendering sicuro delle pagine in immagini per detonare JavaScript incorporato in una sandbox hardened.

---

## Tecniche di attacco recenti (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC ha osservato threat actor aggiungere un documento Word basato su MHT con macro VBA dopo l'ultimo **%%EOF**, producendo un file che è sia un PDF valido sia un DOC valido. I motori AV che analizzano solo il layer PDF non rilevano la macro. Le keyword PDF statiche risultano pulite, ma `file` continua a stampare `%PDF`. Considerare altamente sospetto qualsiasi PDF che contenga anche la stringa `<w:WordDocument>`.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – gli adversary abusano della funzionalità di aggiornamento incrementale per inserire un secondo **/Catalog** con un `/OpenAction` malicious, mantenendo al contempo firmata la prima revisione benigna. Gli strumenti che ispezionano solo la prima tabella xref possono essere bypassati.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – una funzione vulnerabile di **CoolType.dll** può essere raggiunta tramite font CIDType2 incorporati, consentendo remote code execution con i privilegi dell'utente una volta aperto un documento crafted. Patchato in APSB24-29, maggio 2024.<sup>[[3]](#references)</sup>

---

## Template rapido per una regola YARA
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

## Consigli difensivi

1. **Applicare rapidamente le patch** – mantenere Acrobat/Reader sull'ultimo Continuous track; la maggior parte delle catene RCE osservate in the wild sfrutta vulnerabilità n-day corrette mesi prima.
2. **Rimuovere i contenuti attivi al gateway** – usare `pdfcpu sanitize` o `qpdf --qdf --remove-unreferenced` per eliminare JavaScript, file incorporati e azioni di avvio dai PDF in ingresso.
3. **Content Disarm & Reconstruction (CDR)** – convertire i PDF in immagini (o PDF/A) su un host sandbox per preservare la fedeltà visiva eliminando al contempo gli oggetti attivi.
4. **Bloccare le funzionalità utilizzate raramente** – le impostazioni enterprise “Enhanced Security” in Reader consentono di disabilitare JavaScript, contenuti multimediali e rendering 3D.
5. **Formazione degli utenti** – il social engineering (lure con fatture e curriculum) rimane il vettore iniziale; insegnare ai dipendenti a inoltrare gli allegati sospetti al team IR.

## Riferimenti

- [1] [Guida pratica alla Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Bypass del rilevamento tramite l'inserimento di un file Word malevolo in un file PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Bollettino di sicurezza Adobe – Aggiornamento di sicurezza disponibile per Adobe Acrobat e Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - copia della guida](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - tecniche per il formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)

{{#include ../../../banners/hacktricks-training.md}}
