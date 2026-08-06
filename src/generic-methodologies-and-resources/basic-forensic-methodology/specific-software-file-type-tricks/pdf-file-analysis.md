# PDF File analysis

{{#include ../../../banners/hacktricks-training.md}}

**अधिक विवरण के लिए देखें:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

PDF format अपनी जटिलता और data छिपाने की क्षमता के लिए जाना जाता है, जिससे यह CTF forensics challenges का एक महत्वपूर्ण केंद्र बनता है। इसमें plain-text elements को binary objects के साथ संयोजित किया जाता है, जो compressed या encrypted हो सकते हैं, और इसमें JavaScript या Flash जैसी languages में scripts शामिल हो सकती हैं। PDF structure को समझने के लिए Didier Stevens की [introductory material](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) देखी जा सकती है, या text editor अथवा Origami जैसे PDF-specific editor का उपयोग किया जा सकता है।

PDFs की गहन जांच या manipulation के लिए [qpdf](https://github.com/qpdf/qpdf) और [Origami](https://github.com/mobmewireless/origami-pdf) जैसे tools उपलब्ध हैं। PDFs के भीतर hidden data को इन स्थानों पर छिपाया जा सकता है:

- Invisible layers
- Adobe का XMP metadata format
- Incremental generations
- Background के समान color वाला text
- Images के पीछे मौजूद text या overlapping images
- Non-displayed comments

Custom PDF analysis के लिए [PeepDF](https://github.com/jesparza/peepdf) जैसी Python libraries का उपयोग करके bespoke parsing scripts बनाए जा सकते हैं। इसके अलावा, PDF में hidden data storage की संभावना इतनी व्यापक है कि PDF risks और countermeasures पर NSA guide, हालांकि अब अपने original location पर hosted नहीं है, फिर भी valuable insights प्रदान करती है। [Guide की एक copy](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) और Ange Albertini द्वारा तैयार किए गए [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) का collection इस विषय पर आगे पढ़ने के लिए उपयोगी है।<sup>[[4]](#references)[[5]](#references)</sup>

## Common Malicious Constructs

Attackers अक्सर specific PDF objects और actions का दुरुपयोग करते हैं, जो document को open करने या उसके साथ interact करने पर automatically execute होते हैं। इन keywords को खोजना उपयोगी है:

* **/OpenAction, /AA** – open होने पर या specific events पर execute होने वाली automatic actions।
* **/JS, /JavaScript** – embedded JavaScript (अक्सर obfuscated या objects में split किया हुआ)।
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launchers।
* **/RichMedia, /Flash, /3D** – multimedia objects जो payloads छिपा सकते हैं।
* **/EmbeddedFile /Filespec** – file attachments (EXE, DLL, OLE, आदि)।
* **/ObjStm, /XFA, /AcroForm** – object streams या forms, जिनका उपयोग अक्सर shell-code छिपाने के लिए किया जाता है।
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
Additional useful projects (actively maintained 2023-2025):
* **pdfcpu** – Go library/CLI जो PDFs को *lint*, *decrypt*, *extract*, *compress* और *sanitize* कर सकता है।
* **pdf-inspector** – browser-based visualizer जो object graph और streams को render करता है।
* **PyMuPDF (fitz)** – scriptable Python engine जो pages को images में safely render कर सकता है, ताकि embedded JS को hardened sandbox में detonate किया जा सके।

---

## Recent attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC ने threat actors को अंतिम **%%EOF** के बाद MHT-based Word document with VBA macros जोड़ते हुए देखा, जिससे ऐसी file बनती है जो valid PDF और valid DOC दोनों होती है। केवल PDF layer को parse करने वाले AV engines macro को miss कर देते हैं। Static PDF keywords clean रहते हैं, लेकिन `file` फिर भी `%PDF` print करता है। किसी भी ऐसे PDF को highly suspicious मानें जिसमें string `<w:WordDocument>` भी मौजूद हो।<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversaries incremental update feature का abuse करके malicious `/OpenAction` वाला दूसरा **/Catalog** insert करते हैं, जबकि benign first revision signed रहती है। केवल first xref table को inspect करने वाले tools bypass हो जाते हैं।
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – vulnerable **CoolType.dll** function को embedded CIDType2 fonts से reach किया जा सकता है, जिससे crafted document खोलने के बाद user के privileges के साथ remote code execution संभव हो जाता है। APSB24-29 में May 2024 में patch किया गया।<sup>[[3]](#references)</sup>

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

## Defensive tips

1. **Patch fast** – Acrobat/Reader को नवीनतम Continuous track पर रखें; wild में देखी गई अधिकांश RCE chains महीनों पहले fixed की गई n-day vulnerabilities का लाभ उठाती हैं।
2. **Strip active content at the gateway** – inbound PDFs से JavaScript, embedded files और launch actions हटाने के लिए `pdfcpu sanitize` या `qpdf --qdf --remove-unreferenced` का उपयोग करें।
3. **Content Disarm & Reconstruction (CDR)** – visual fidelity बनाए रखते हुए active objects हटाने के लिए sandbox host पर PDFs को images (या PDF/A) में convert करें।
4. **Block rarely-used features** – Reader की enterprise “Enhanced Security” settings में JavaScript, multimedia और 3D rendering को disable किया जा सकता है।
5. **User education** – social engineering (invoice और resume lures) अब भी initial vector बना हुआ है; कर्मचारियों को suspicious attachments IR को forward करना सिखाएँ।

## References

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – PDF file में malicious Word file embed करके Detection bypass](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Adobe Acrobat और Reader के लिए Security update available (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - guide की copy](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)

{{#include ../../../banners/hacktricks-training.md}}
