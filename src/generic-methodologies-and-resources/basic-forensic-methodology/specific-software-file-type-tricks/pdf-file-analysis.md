# PDF File विश्लेषण

{{#include ../../../banners/hacktricks-training.md}}

**अधिक विवरण के लिए देखें:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

PDF format अपनी जटिलता और data छिपाने की क्षमता के लिए जाना जाता है, जिससे यह CTF forensics challenges का एक प्रमुख विषय बन गया है। इसमें plain-text elements को binary objects के साथ जोड़ा जाता है, जिन्हें compress या encrypt किया जा सकता है, और इसमें JavaScript या Flash जैसी languages में scripts भी शामिल हो सकती हैं। PDF structure को समझने के लिए Didier Stevens की [introductory material](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) देखी जा सकती है, या text editor अथवा Origami जैसे PDF-specific editor का उपयोग किया जा सकता है।

PDFs की गहन जांच या manipulation के लिए [qpdf](https://github.com/qpdf/qpdf) और [Origami](https://github.com/mobmewireless/origami-pdf) जैसे tools उपलब्ध हैं। PDFs के भीतर hidden data निम्न स्थानों पर छिपा हो सकता है:

- Invisible layers
- Adobe का XMP metadata format
- Incremental generations
- Background के समान color वाला text
- Images के पीछे या overlapping images के रूप में text
- Non-displayed comments

Custom PDF analysis के लिए [PeepDF](https://github.com/jesparza/peepdf) जैसी Python libraries का उपयोग bespoke parsing scripts बनाने के लिए किया जा सकता है। इसके अतिरिक्त, PDF में hidden data store करने की संभावनाएं इतनी व्यापक हैं कि PDF risks और countermeasures पर NSA guide, जो अब अपने original location पर hosted नहीं है, फिर भी valuable insights प्रदान करती है। [guide की एक copy](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) और Ange Albertini द्वारा तैयार किए गए [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) का collection इस विषय पर आगे पढ़ने के लिए उपयोगी हो सकता है।

## सामान्य Malicious Constructs

Attackers अक्सर specific PDF objects और actions का दुरुपयोग करते हैं, जो document के open होने या उसके साथ interaction होने पर automatically execute होते हैं। खोजे जाने योग्य keywords:

* **/OpenAction, /AA** – open होने पर या specific events पर execute होने वाले automatic actions।
* **/JS, /JavaScript** – embedded JavaScript, जो अक्सर obfuscated होता है या objects में split किया जाता है।
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launchers।
* **/RichMedia, /Flash, /3D** – multimedia objects, जो payloads छिपा सकते हैं।
* **/EmbeddedFile /Filespec** – file attachments (EXE, DLL, OLE, आदि)।
* **/ObjStm, /XFA, /AcroForm** – object streams या forms, जिनका shell-code छिपाने के लिए अक्सर दुरुपयोग किया जाता है।
* **Incremental updates** – कई %%EOF markers या बहुत बड़ा **/Prev** offset यह संकेत दे सकता है कि AV को bypass करने के लिए signing के बाद data append किया गया है।

जब पिछले tokens में से कोई भी suspicious strings (powershell, cmd.exe, calc.exe, base64, आदि) के साथ दिखाई दे, तो PDF की अधिक गहन analysis की जानी चाहिए।

---

## Static analysis cheat-sheet
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
अतिरिक्त उपयोगी projects (सक्रिय रूप से 2023-2025 में maintained):
* **pdfcpu** – Go library/CLI, जो PDFs को *lint*, *decrypt*, *extract*, *compress* और *sanitize* कर सकता है।
* **pdf-inspector** – browser-based visualizer, जो object graph और streams को render करता है।
* **PyMuPDF (fitz)** – scriptable Python engine, जो hardened sandbox में embedded JS को detonate करने के लिए pages को images में सुरक्षित रूप से render कर सकता है।

---

## हाल की attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC ने देखा कि threat actors अंतिम **%%EOF** के बाद VBA macros वाले MHT-based Word document को जोड़ रहे थे, जिससे ऐसी file बनती है जो valid PDF और valid DOC दोनों होती है। केवल PDF layer को parse करने वाले AV engines macro को miss कर देते हैं। Static PDF keywords clean होते हैं, लेकिन `file` फिर भी `%PDF` print करता है। ऐसे किसी भी PDF को अत्यधिक suspicious मानें जिसमें string `<w:WordDocument>` भी मौजूद हो।<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversaries incremental update feature का दुरुपयोग करके malicious `/OpenAction` वाला दूसरा **/Catalog** insert करते हैं, जबकि benign first revision signed रहती है। केवल पहली xref table का निरीक्षण करने वाले tools को bypass किया जाता है।
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – embedded CIDType2 fonts से vulnerable **CoolType.dll** function तक पहुंचा जा सकता है, जिससे crafted document खोलने के बाद user के privileges के साथ remote code execution संभव होता है। इसे APSB24-29, May 2024 में patch किया गया।<sup>[[3]](#references)</sup>

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

## सुरक्षा संबंधी सुझाव

1. **जल्दी Patch करें** – Acrobat/Reader को नवीनतम Continuous track पर रखें; wild में देखी गई अधिकांश RCE chains कई महीने पहले fixed की गई n-day vulnerabilities का लाभ उठाती हैं।
2. **Gateway पर active content हटाएँ** – inbound PDFs से JavaScript, embedded files और launch actions हटाने के लिए `pdfcpu sanitize` या `qpdf --qdf --remove-unreferenced` का उपयोग करें।
3. **Content Disarm & Reconstruction (CDR)** – visual fidelity बनाए रखते हुए active objects हटाने के लिए PDFs को sandbox host पर images (या PDF/A) में convert करें।
4. **कम उपयोग किए जाने वाले features को block करें** – Reader की enterprise “Enhanced Security” settings में JavaScript, multimedia और 3D rendering को disable किया जा सकता है।
5. **User education** – social engineering (invoice और resume lures) अभी भी initial vector बना हुआ है; कर्मचारियों को suspicious attachments को IR पर forward करना सिखाएँ।

## References

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Security update available for Adobe Acrobat and Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)

{{#include ../../../banners/hacktricks-training.md}}
