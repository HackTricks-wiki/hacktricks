# PDF फ़ाइल का विश्लेषण

{{#include ../../../banners/hacktricks-training.md}}

**अधिक जानकारी के लिए देखें:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

PDF फ़ॉर्मैट अपनी जटिलता और डेटा छिपाने की क्षमता के लिए जाना जाता है, इसलिए CTF forensics चुनौतियों में इस पर विशेष ध्यान दिया जाता है। इसमें सादे टेक्स्ट वाले तत्वों के साथ बाइनरी ऑब्जेक्ट भी होते हैं, जिन्हें संपीड़ित या एन्क्रिप्ट किया जा सकता है। इसमें JavaScript या Flash जैसी भाषाओं में स्क्रिप्ट भी हो सकती हैं। PDF की संरचना समझने के लिए Didier Stevens की [परिचयात्मक सामग्री](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) देखी जा सकती है या टेक्स्ट एडिटर अथवा Origami जैसे PDF-विशिष्ट एडिटर का उपयोग किया जा सकता है।

PDF की गहराई से जाँच या उनमें बदलाव करने के लिए [qpdf](https://github.com/qpdf/qpdf) और [Origami](https://github.com/mobmewireless/origami-pdf) जैसे टूल उपलब्ध हैं। PDF में छिपा डेटा इन जगहों पर हो सकता है:

- अदृश्य लेयर्स
- Adobe का XMP metadata फ़ॉर्मैट
- Incremental generations
- बैकग्राउंड के समान रंग वाला टेक्स्ट
- इमेज के पीछे का टेक्स्ट या एक-दूसरे पर ओवरलैप होती इमेज
- न दिखने वाली टिप्पणियाँ

कस्टम PDF विश्लेषण के लिए, Python लाइब्रेरी [PeepDF](https://github.com/jesparza/peepdf) का इस्तेमाल करके अपनी ज़रूरत के अनुसार parsing scripts बनाई जा सकती हैं। इसके अलावा, PDF में छिपा डेटा रखने की संभावनाएँ इतनी व्यापक हैं कि PDF जोखिमों और countermeasures पर NSA की गाइड—हालाँकि अब अपने मूल स्थान पर उपलब्ध नहीं है—फिर भी उपयोगी जानकारी देती है। इस विषय पर आगे पढ़ने के लिए [गाइड की एक कॉपी](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) और Ange Albertini के [PDF फ़ॉर्मैट ट्रिक्स](https://github.com/corkami/docs/blob/master/PDF/PDF.md) का संग्रह देखें।<sup>[[4]](#references)[[5]](#references)</sup>

## आम दुर्भावनापूर्ण संरचनाएँ

हमलावर अक्सर कुछ PDF objects और actions का दुरुपयोग करते हैं, जो दस्तावेज़ खोलने या उसके साथ इंटरैक्ट करने पर अपने-आप चलते हैं। इन keywords को खोजें:

* **/OpenAction, /AA** – खुलने पर या किसी खास घटना के दौरान अपने-आप चलने वाली actions।
* **/JS, /JavaScript** – एम्बेडेड JavaScript (अक्सर obfuscated या कई objects में बाँटी हुई)।
* **/Launch, /SubmitForm, /URI, /GoToE** – बाहरी process या URL लॉन्च करने वाले।
* **/RichMedia, /Flash, /3D** – मल्टीमीडिया objects, जिनमें payloads छिपाए जा सकते हैं।
* **/EmbeddedFile /Filespec** – फ़ाइल attachments (EXE, DLL, OLE आदि)।
* **/ObjStm, /XFA, /AcroForm** – object streams या forms, जिनका shell-code छिपाने के लिए अक्सर दुरुपयोग होता है।
* **Incremental updates** – कई %%EOF markers या बहुत बड़ा **/Prev** offset इस बात का संकेत हो सकता है कि AV को चकमा देने के लिए signing के बाद डेटा जोड़ा गया है।

जब ऊपर दिए गए tokens के साथ संदिग्ध strings (powershell, cmd.exe, calc.exe, base64 आदि) दिखें, तो PDF की गहराई से जाँच की जानी चाहिए।

---

## Static analysis की त्वरित संदर्भ-सूची

नीचे दिए गए उदाहरण, दस्तावेज़ीकृत `pdf-parser.py`, qpdf और pdfcpu command-line interfaces का उपयोग करते हैं।<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>

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

PDF के अंदर किसी image को pixelate करने से उसके underlying pixels नहीं हटते। अगर कोई readable document इस तरह किसी credential को छिपाता हुआ दिखाई दे, तो authorized offline inspection के लिए embedded image extract करें; परिणाम image और उपयुक्त reference पर निर्भर करता है, और visual recovery की गारंटी नहीं है। Recovered password को उस account के विरुद्ध अलग से verify करना होगा जिसके privileges मायने रखते हैं। Routine host-enumeration scan में PDF extraction या image-recovery pass शामिल न करें।

अतिरिक्त उपयोगी projects (2023-2025 में सक्रिय रूप से maintained):
* **pdfcpu** – Go library/CLI, जो PDFs को validate, decrypt, extract, optimize और manipulate कर सकती है।<sup>[[9]](#references)</sup>
* **pdf-inspector** – browser-based visualizer, जो object graph और streams को render करता है।
* **PyMuPDF** – PDFs की जाँच करने और pages को raster images में render करने के लिए scriptable Python bindings। Parser/renderer को untrusted-file attack surface मानें और इसे उपयुक्त रूप से isolated analysis environment के अंदर चलाएँ।<sup>[[8]](#references)</sup>

---

## हाल की attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC ने ऐसी technique की रिपोर्ट की जिसमें VBA macros वाली Word-created MHT file को PDF के अंत में जोड़ा जाता है। इससे PDF magic बना रहता है, जबकि file Word में भी खुलती है। PDF-only analysis tools, sandboxes या antivirus macro को miss कर सकते हैं, क्योंकि malicious behavior तब होता है जब file Word के रूप में खोली जाती है; अन्य MHT indicators के साथ `<w:WordDocument>` marker भी देखें।<sup>[[2]](#references)</sup>
* **Signed PDFs पर Shadow attacks** – attackers किसी PDF पर हस्ताक्षर होने से पहले उसमें hidden content रख सकते हैं, फिर एक incremental update जोड़ सकते हैं जो catalog या object references बदल देता है, ताकि viewers hidden content दिखाएँ, जबकि original signature valid बनी रहती है। यह technique उन viewers को evade कर सकती है जो ऐसे updates को harmless classify करते हैं।<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe इस critical vulnerability को use-after-free के रूप में rating देता है, जिससे arbitrary code execution हो सकता है; APSB24-29 को 14 मई, 2024 को प्रकाशित किया गया था।<sup>[[3]](#references)</sup>

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

## रक्षात्मक सुझाव

1. **तेज़ी से पैच करें** – Acrobat/Reader को नवीनतम Continuous track पर रखें; जंगल में देखी गई ज़्यादातर RCE chains उन n-day vulnerabilities का फ़ायदा उठाती हैं जिन्हें महीनों पहले ठीक किया जा चुका होता है।
2. **Gateway पर active content हटाएँ** – ऐसा purpose-built, policy-controlled sanitizer या CDR product इस्तेमाल करें जो JavaScript, embedded files, launch actions, forms और multimedia को स्पष्ट रूप से हटाता हो। `qpdf --qdf` से PDF objects का निरीक्षण करना आसान होता है, जबकि pdfcpu में validation और manipulation की सुविधाएँ हैं; इनमें से कोई भी command अकेले इस बात का प्रमाण नहीं है कि active content हटा दिया गया है।<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – दृश्य रूप को सुरक्षित रखते हुए active objects हटाने के लिए sandbox host पर PDFs को images (या PDF/A) में बदलें।
4. **कम इस्तेमाल होने वाली सुविधाएँ ब्लॉक करें** – Reader की enterprise “Enhanced Security” settings से JavaScript, multimedia और 3D rendering को बंद किया जा सकता है।
5. **उपयोगकर्ताओं को जागरूक करें** – social engineering (invoice और resume के बहाने भेजे गए संदेश) अब भी शुरुआती attack vector है; कर्मचारियों को सिखाएँ कि वे संदिग्ध attachments IR टीम को भेजें।

## References

- [1] [Forensics CTF की फील्ड गाइड](https://trailofbits.github.io/ctf/forensics/)
- [2] [PDF में MalDoc – PDF फ़ाइल में malicious Word फ़ाइल embed करके detection को bypass करना](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Adobe Acrobat और Reader के लिए security update उपलब्ध (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - गाइड की प्रति](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF format की तरकीबें](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: signed PDFs में content छिपाना और बदलना](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF Tutorial](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdf के command-line विकल्प](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
