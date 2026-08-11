# PDF File analysis

{{#include ../../../banners/hacktricks-training.md}}

**अधिक जानकारी के लिए देखें:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

PDF format अपनी जटिलता और data छिपाने की क्षमता के लिए जाना जाता है, जिससे यह CTF forensics challenges का एक प्रमुख विषय बन जाता है। इसमें plain-text elements को binary objects के साथ संयोजित किया जाता है, जो compressed या encrypted हो सकते हैं, और इसमें JavaScript या Flash जैसी languages में scripts शामिल हो सकती हैं। PDF structure को समझने के लिए Didier Stevens की [introductory material](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) देखी जा सकती है, या text editor अथवा Origami जैसे PDF-specific editor का उपयोग किया जा सकता है।

PDFs की गहन जांच या manipulation के लिए [qpdf](https://github.com/qpdf/qpdf) और [Origami](https://github.com/mobmewireless/origami-pdf) जैसे tools उपलब्ध हैं। PDFs के भीतर hidden data निम्न स्थानों पर छिपा हो सकता है:

- Invisible layers
- Adobe का XMP metadata format
- Incremental generations
- Background के समान color वाला text
- Images के पीछे का text या overlapping images
- Non-displayed comments

Custom PDF analysis के लिए [PeepDF](https://github.com/jesparza/peepdf) जैसी Python libraries का उपयोग bespoke parsing scripts बनाने के लिए किया जा सकता है। इसके अलावा, PDF में hidden data storage की संभावनाएं इतनी व्यापक हैं कि PDF risks और countermeasures पर NSA guide, जो अब अपने original location पर hosted नहीं है, फिर भी उपयोगी जानकारी प्रदान करती है। [इस guide की copy](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) और Ange Albertini द्वारा तैयार किए गए [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) का संग्रह इस विषय पर आगे पढ़ने के लिए उपयोगी हैं।<sup>[[4]](#references)[[5]](#references)</sup>

## Common Malicious Constructs

Attackers अक्सर specific PDF objects और actions का दुरुपयोग करते हैं, जो document खोलने या उसमें interaction करने पर automatically execute होते हैं। खोजने योग्य keywords:

* **/OpenAction, /AA** – open होने पर या specific events पर execute होने वाली automatic actions।
* **/JS, /JavaScript** – embedded JavaScript (अक्सर obfuscated या objects में split किया हुआ)।
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launchers।
* **/RichMedia, /Flash, /3D** – multimedia objects जो payloads छिपा सकते हैं।
* **/EmbeddedFile /Filespec** – file attachments (EXE, DLL, OLE, आदि)।
* **/ObjStm, /XFA, /AcroForm** – object streams या forms जिनका उपयोग shell-code छिपाने के लिए अक्सर किया जाता है।
* **Incremental updates** – कई %%EOF markers या बहुत बड़ा **/Prev** offset यह संकेत दे सकता है कि AV को bypass करने के लिए signing के बाद data append किया गया है।

जब पिछले tokens में से कोई भी suspicious strings (powershell, cmd.exe, calc.exe, base64, आदि) के साथ दिखाई दे, तो PDF की अधिक गहन analysis की जानी चाहिए।

---

## Static analysis cheat-sheet

नीचे दिए गए examples documented `pdf-parser.py`, qpdf और pdfcpu command-line interfaces का उपयोग करते हैं।<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
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
अतिरिक्त उपयोगी projects (actively maintained 2023-2025):
* **pdfcpu** – PDFs को validate, decrypt, extract, optimize और manipulate करने में सक्षम Go library/CLI।<sup>[[9]](#references)</sup>
* **pdf-inspector** – browser-based visualizer जो object graph और streams को render करता है।
* **PyMuPDF** – PDFs का निरीक्षण करने और pages को raster images में render करने के लिए scriptable Python bindings। parser/renderer को untrusted-file attack surface मानें और इसे उचित रूप से isolated analysis environment के अंदर चलाएँ।<sup>[[8]](#references)</sup>

---

## हालिया attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC ने एक technique की report की जिसमें Word-created MHT file with VBA macros को PDF में append किया जाता है, जिससे PDF magic बना रहता है और file Word में भी खुलती है। PDF-only analysis tools, sandboxes या antivirus macro को miss कर सकते हैं क्योंकि malicious behavior Word के रूप में खोलने पर होता है; अन्य MHT indicators के साथ `<w:WordDocument>` marker देखें।<sup>[[2]](#references)</sup>
* **Signed PDFs पर Shadow attacks** – attackers PDF को sign किए जाने से पहले उसमें hidden content रख सकते हैं, फिर एक incremental update append कर सकते हैं जो catalog या object references को बदल देता है, ताकि viewers hidden content display करें जबकि original signature valid रहे। यह technique उन viewers को evade कर सकती है जो ऐसे updates को harmless classify करते हैं।<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe इस critical vulnerability को use-after-free के रूप में rate करता है, जिससे arbitrary code execution हो सकता है; APSB24-29 को May 14, 2024 को publish किया गया था।<sup>[[3]](#references)</sup>

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

1. **तेजी से Patch करें** – Acrobat/Reader को नवीनतम Continuous track पर रखें; wild में देखी गई अधिकांश RCE chains उन n-day vulnerabilities का लाभ उठाती हैं जिन्हें महीनों पहले fix किया जा चुका है।
2. **Gateway पर active content हटाएँ** – purpose-built, policy-controlled sanitizer या CDR product का उपयोग करें, जो JavaScript, embedded files, launch actions, forms और multimedia को स्पष्ट रूप से हटाता हो। `qpdf --qdf` PDF objects को inspect करना आसान बनाता है, जबकि pdfcpu validation और manipulation features प्रदान करता है; केवल इनमें से कोई एक command active content हटाए जाने का प्रमाण नहीं है।<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – visual fidelity बनाए रखने और active objects को हटाने के लिए sandbox host पर PDFs को images (या PDF/A) में convert करें।
4. **कम उपयोग किए जाने वाले features को Block करें** – Reader में enterprise “Enhanced Security” settings JavaScript, multimedia और 3D rendering को disable करने की अनुमति देती हैं।
5. **User education** – social engineering (invoice और resume lures) initial vector बना हुआ है; employees को suspicious attachments IR को forward करना सिखाएँ।

## References

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – PDF file में malicious Word file embed करके Detection bypass](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Adobe Acrobat और Reader के लिए Security update उपलब्ध (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - guide की copy](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: Signed PDFs में Content को छिपाना और बदलना](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF Tutorial](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdf command-line options](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
