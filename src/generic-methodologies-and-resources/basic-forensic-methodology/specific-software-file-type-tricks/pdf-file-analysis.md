# Analisi dei file PDF

{{#include ../../../banners/hacktricks-training.md}}

**Per ulteriori dettagli, consulta:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Il formato PDF è noto per la sua complessità e per la possibilità di nascondere dati, caratteristiche che lo rendono un elemento centrale nelle sfide di digital forensics dei CTF. Combina elementi di testo semplice con oggetti binari, che possono essere compressi o crittografati, e può includere script in linguaggi come JavaScript o Flash. Per comprendere la struttura dei PDF, si può consultare il [materiale introduttivo](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) di Didier Stevens oppure usare strumenti come un editor di testo o un editor specifico per PDF, come Origami.

Per analizzare o manipolare i PDF in modo approfondito, sono disponibili strumenti come [qpdf](https://github.com/qpdf/qpdf) e [Origami](https://github.com/mobmewireless/origami-pdf). I dati nascosti nei PDF possono trovarsi in:

- Livelli invisibili
- Il formato di metadati XMP di Adobe
- Generazioni incrementali
- Testo dello stesso colore dello sfondo
- Testo dietro le immagini o immagini sovrapposte
- Commenti non visualizzati

Per analizzare PDF in modo personalizzato, si possono usare librerie Python come [PeepDF](https://github.com/jesparza/peepdf) per creare script di parsing su misura. Inoltre, il potenziale dei PDF per l'archiviazione di dati nascosti è così vasto che risorse come la guida dell'NSA sui rischi dei PDF e le relative contromisure, sebbene non sia più ospitata nella sua posizione originale, offrono ancora spunti preziosi. Una [copia della guida](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) e una raccolta di [trucchi per il formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) di Ange Albertini possono offrire ulteriori approfondimenti sull'argomento.<sup>[[4]](#references)[[5]](#references)</sup>

## Costrutti malevoli comuni

Gli attacker spesso abusano di specifici oggetti e azioni PDF che vengono eseguiti automaticamente all'apertura o durante l'interazione con il documento. Ecco alcune keyword da cercare:

* **/OpenAction, /AA** – azioni automatiche eseguite all'apertura o in risposta a eventi specifici.
* **/JS, /JavaScript** – JavaScript incorporato (spesso offuscato o suddiviso tra più oggetti).
* **/Launch, /SubmitForm, /URI, /GoToE** – strumenti per avviare processi esterni o aprire URL.
* **/RichMedia, /Flash, /3D** – oggetti multimediali che possono nascondere payload.
* **/EmbeddedFile /Filespec** – allegati (EXE, DLL, OLE ecc.).
* **/ObjStm, /XFA, /AcroForm** – stream di oggetti o moduli spesso abusati per nascondere shell-code.
* **Aggiornamenti incrementali** – più marcatori %%EOF o un offset **/Prev** molto grande possono indicare dati aggiunti dopo la firma per eludere gli antivirus.

Quando uno qualsiasi dei token precedenti compare insieme a stringhe sospette (powershell, cmd.exe, calc.exe, base64 ecc.), il PDF merita un'analisi più approfondita.

---

## Scheda di riferimento per l'analisi statica

Gli esempi seguenti usano le interfacce a riga di comando documentate di `pdf-parser.py`, qpdf e pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>

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

La pixelatura di un’immagine all’interno di un PDF non rimuove i pixel sottostanti. Se un documento leggibile sembra nascondere una credenziale in questo modo, estrai l’immagine incorporata per un’ispezione offline autorizzata; il risultato dipende dall’immagine e dalla disponibilità di un riferimento adeguato, e il recupero visivo non è garantito. Una password recuperata deve comunque essere verificata separatamente rispetto all’account di cui interessano i privilegi. Non includere l’estrazione di PDF o il recupero di immagini in una scansione di routine per l’enumerazione degli host.

Altri progetti utili (attivamente mantenuti nel periodo 2023-2025):
* **pdfcpu** – libreria/CLI Go in grado di convalidare, decrittare, estrarre, ottimizzare e manipolare PDF.<sup>[[9]](#references)</sup>
* **pdf-inspector** – visualizzatore basato su browser che rappresenta graficamente il grafo degli oggetti e gli stream.
* **PyMuPDF** – binding Python scriptabili per ispezionare PDF e renderizzare le pagine in immagini raster. Considera il parser/renderer una superficie di attacco costituita da file non attendibili ed eseguilo in un ambiente di analisi adeguatamente isolato.<sup>[[8]](#references)</sup>

---

## Tecniche di attacco recenti (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC ha segnalato una tecnica che aggiunge a un PDF un file MHT creato con Word e contenente macro VBA, mantenendo la firma magica PDF e consentendo anche l’apertura in Word. Gli strumenti di analisi che esaminano solo i PDF, le sandbox o gli antivirus potrebbero non rilevare la macro, perché il comportamento malevolo si verifica quando il file viene aperto con Word; cerca il marcatore `<w:WordDocument>` insieme ad altri indicatori MHT.<sup>[[2]](#references)</sup>
* **Attacchi shadow ai PDF firmati** – gli attaccanti possono inserire contenuti nascosti in un PDF prima che venga firmato, quindi aggiungere un aggiornamento incrementale che modifica i riferimenti al catalogo o agli oggetti, in modo che i visualizzatori mostrino i contenuti nascosti mentre la firma originale rimane valida. La tecnica può eludere i visualizzatori che classificano tali aggiornamenti come innocui.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe valuta questa vulnerabilità critica come una use-after-free che può portare all’esecuzione di codice arbitrario; APSB24-29 è stato pubblicato il 14 maggio 2024.<sup>[[3]](#references)</sup>

---

## Modello di regola YARA rapida

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

1. **Applicare rapidamente le patch** – mantenere Acrobat/Reader aggiornati all’ultima Continuous track; la maggior parte delle catene RCE osservate in circolazione sfrutta vulnerabilità n-day corrette mesi prima.
2. **Rimuovere i contenuti attivi al gateway** – usare un prodotto di sanitizzazione o CDR appositamente progettato e controllato da policy, che rimuova esplicitamente JavaScript, file incorporati, azioni di avvio, moduli e contenuti multimediali. `qpdf --qdf` semplifica l’ispezione degli oggetti PDF, mentre pdfcpu offre funzionalità di convalida e manipolazione; nessuno dei due comandi, da solo, dimostra che i contenuti attivi siano stati rimossi.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – convertire i PDF in immagini (o PDF/A) su un host sandbox per preservarne la fedeltà visiva ed eliminare gli oggetti attivi.
4. **Bloccare le funzionalità usate di rado** – le impostazioni enterprise “Enhanced Security” di Reader consentono di disabilitare JavaScript, i contenuti multimediali e il rendering 3D.
5. **Formazione degli utenti** – il social engineering (esche con fatture e curriculum) resta il vettore iniziale; insegnare ai dipendenti a inoltrare gli allegati sospetti al team IR.

## References

- [1] [Guida pratica CTF di informatica forense](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Bypass del rilevamento tramite incorporamento di un file Word dannoso in un file PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Bollettino di sicurezza Adobe – Disponibile un aggiornamento di sicurezza per Adobe Acrobat e Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - copia della guida](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - trucchi del formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Attacchi Shadow: nascondere e sostituire contenuti nei PDF firmati](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [Tutorial di PyMuPDF](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Opzioni della riga di comando di qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
