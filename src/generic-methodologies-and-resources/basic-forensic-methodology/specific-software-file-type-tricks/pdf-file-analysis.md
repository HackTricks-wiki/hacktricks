# Analisi dei file PDF

{{#include ../../../banners/hacktricks-training.md}}

**Per ulteriori dettagli, consulta:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

Il formato PDF è noto per la sua complessità e per il potenziale di occultamento dei dati, caratteristiche che lo rendono un obiettivo frequente nelle challenge di forensics dei CTF. Combina elementi in testo semplice con oggetti binari, che possono essere compressi o cifrati, e può includere script in linguaggi come JavaScript o Flash. Per comprendere la struttura dei PDF, è possibile consultare il [materiale introduttivo](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) di Didier Stevens oppure usare strumenti come un editor di testo o un editor specifico per PDF, come Origami.

Per un'analisi o una manipolazione approfondita dei PDF, sono disponibili strumenti come [qpdf](https://github.com/qpdf/qpdf) e [Origami](https://github.com/mobmewireless/origami-pdf). I dati nascosti all'interno dei PDF possono essere celati in:

- Livelli invisibili
- Formato dei metadati XMP di Adobe
- Generazioni incrementali
- Testo dello stesso colore dello sfondo
- Testo dietro le immagini o immagini sovrapposte
- Commenti non visualizzati

Per un'analisi personalizzata dei PDF, è possibile usare librerie Python come [PeepDF](https://github.com/jesparza/peepdf) per creare script di parsing su misura. Inoltre, il potenziale dei PDF come sistema di archiviazione di dati nascosti è così ampio che risorse come la guida dell'NSA sui rischi e sulle contromisure dei PDF, sebbene non sia più ospitata nella posizione originale, offrono ancora informazioni preziose. Una [copia della guida](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) e una raccolta di [trucchi per il formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) di Ange Albertini possono fornire ulteriori approfondimenti sull'argomento.

## Costrutti malevoli comuni

Gli attacker spesso abusano di specifici oggetti e azioni PDF che vengono eseguiti automaticamente quando il documento viene aperto o utilizzato. Le keyword da ricercare includono:

* **/OpenAction, /AA** – azioni automatiche eseguite all'apertura o in risposta a eventi specifici.
* **/JS, /JavaScript** – JavaScript embedded (spesso offuscato o suddiviso tra più oggetti).
* **/Launch, /SubmitForm, /URI, /GoToE** – launcher di processi esterni o URL.
* **/RichMedia, /Flash, /3D** – oggetti multimediali che possono nascondere payload.
* **/EmbeddedFile /Filespec** – allegati (EXE, DLL, OLE, ecc.).
* **/ObjStm, /XFA, /AcroForm** – object stream o form comunemente abusati per nascondere shell-code.
* **Aggiornamenti incrementali** – più marker %%EOF o un offset **/Prev** molto grande possono indicare dati aggiunti dopo la firma per eludere gli AV.

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
Additional useful projects (actively maintained 2023-2025):
* **pdfcpu** – libreria/CLI Go in grado di eseguire *lint*, *decrypt*, *extract*, *compress* e *sanitize* dei PDF.
* **pdf-inspector** – visualizzatore basato su browser che esegue il rendering del grafo degli oggetti e degli stream.
* **PyMuPDF (fitz)** – motore Python scriptable in grado di eseguire in sicurezza il rendering delle pagine in immagini per detonare JS incorporato in una sandbox hardened.

---

## Recent attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC ha osservato threat actors aggiungere un documento Word basato su MHT con macro VBA dopo l'ultimo **%%EOF**, producendo un file che è contemporaneamente un PDF valido e un DOC valido. I motori AV che analizzano solo il livello PDF non rilevano la macro. Le keyword statiche del PDF risultano pulite, ma `file` stampa comunque `%PDF`. Considerare altamente sospetto qualsiasi PDF che contenga anche la stringa `<w:WordDocument>`.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – gli adversaries abusano della funzionalità di incremental update per inserire un secondo **/Catalog** con un `/OpenAction` malicious, mantenendo firmata la prima revisione benigna. Gli strumenti che ispezionano solo la prima tabella xref vengono bypassati.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – una funzione vulnerabile di **CoolType.dll** può essere raggiunta tramite font CIDType2 incorporati, consentendo remote code execution con i privilegi dell'utente una volta aperto un documento crafted. Corretta in APSB24-29, maggio 2024.<sup>[[3]](#references)</sup>

---

## YARA quick rule template
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

1. **Applica rapidamente le patch** – mantieni Acrobat/Reader sul track Continuous più recente; la maggior parte delle catene RCE osservate in the wild sfrutta vulnerabilità n-day corrette mesi prima.
2. **Rimuovi i contenuti attivi al gateway** – usa `pdfcpu sanitize` o `qpdf --qdf --remove-unreferenced` per eliminare JavaScript, file incorporati e azioni di avvio dai PDF in ingresso.
3. **Content Disarm & Reconstruction (CDR)** – converti i PDF in immagini (o PDF/A) su un sandbox host per preservare la fedeltà visiva eliminando al contempo gli oggetti attivi.
4. **Blocca le funzionalità usate raramente** – le impostazioni enterprise “Enhanced Security” in Reader consentono di disabilitare JavaScript, contenuti multimediali e rendering 3D.
5. **Formazione degli utenti** – la social engineering (esche basate su fatture e curriculum) rimane il vettore iniziale; insegna ai dipendenti a inoltrare gli allegati sospetti al team IR.

## Riferimenti

- [1] [Guida pratica alla Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Bypass del rilevamento tramite l'incorporamento di un file Word malevolo in un file PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Bollettino di sicurezza Adobe – Aggiornamento di sicurezza disponibile per Adobe Acrobat e Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)

{{#include ../../../banners/hacktricks-training.md}}
