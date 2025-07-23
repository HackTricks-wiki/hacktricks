# PDF फ़ाइल विश्लेषण

{{#include ../../../banners/hacktricks-training.md}}

**अधिक जानकारी के लिए देखें:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

PDF प्रारूप अपनी जटिलता और डेटा को छिपाने की क्षमता के लिए जाना जाता है, जो इसे CTF फॉरेंसिक्स चुनौतियों के लिए एक केंद्र बिंदु बनाता है। यह प्लेन-टेक्स्ट तत्वों को बाइनरी ऑब्जेक्ट्स के साथ मिलाता है, जो संकुचित या एन्क्रिप्टेड हो सकते हैं, और इसमें JavaScript या Flash जैसी भाषाओं में स्क्रिप्ट शामिल हो सकती हैं। PDF संरचना को समझने के लिए, कोई Didier Stevens के [परिचयात्मक सामग्री](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) का संदर्भ ले सकता है, या टेक्स्ट संपादक या Origami जैसे PDF-विशिष्ट संपादक का उपयोग कर सकता है।

PDFs के गहन अन्वेषण या हेरफेर के लिए, [qpdf](https://github.com/qpdf/qpdf) और [Origami](https://github.com/mobmewireless/origami-pdf) जैसे उपकरण उपलब्ध हैं। PDFs के भीतर छिपा डेटा निम्नलिखित में छिपा हो सकता है:

- अदृश्य परतें
- Adobe द्वारा XMP मेटाडेटा प्रारूप
- वृद्धिशील पीढ़ियाँ
- पृष्ठभूमि के समान रंग का पाठ
- छवियों के पीछे या ओवरलैपिंग छवियों के पीछे पाठ
- गैर-प्रदर्शित टिप्पणियाँ

कस्टम PDF विश्लेषण के लिए, Python पुस्तकालय जैसे [PeepDF](https://github.com/jesparza/peepdf) का उपयोग करके विशेष पार्सिंग स्क्रिप्ट बनाई जा सकती हैं। इसके अलावा, PDF के छिपे डेटा भंडारण की क्षमता इतनी विशाल है कि PDF जोखिमों और प्रतिकृतियों पर NSA गाइड जैसे संसाधन, हालांकि अब इसके मूल स्थान पर होस्ट नहीं किए गए हैं, फिर भी मूल्यवान अंतर्दृष्टि प्रदान करते हैं। [गाइड की एक प्रति](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%Bútmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) और Ange Albertini द्वारा [PDF प्रारूप ट्रिक्स](https://github.com/corkami/docs/blob/master/PDF/PDF.md) का एक संग्रह इस विषय पर आगे पढ़ने के लिए प्रदान कर सकता है।

## सामान्य दुर्भावनापूर्ण संरचनाएँ

हमलावर अक्सर विशिष्ट PDF ऑब्जेक्ट्स और क्रियाओं का दुरुपयोग करते हैं जो दस्तावेज़ खोले जाने या बातचीत करने पर स्वचालित रूप से निष्पादित होते हैं। खोजने के लिए महत्वपूर्ण कीवर्ड:

* **/OpenAction, /AA** – खोले जाने पर या विशिष्ट घटनाओं पर स्वचालित क्रियाएँ।
* **/JS, /JavaScript** – एम्बेडेड JavaScript (अक्सर अस्पष्ट या ऑब्जेक्ट्स के बीच विभाजित)।
* **/Launch, /SubmitForm, /URI, /GoToE** – बाहरी प्रक्रिया / URL लॉन्चर।
* **/RichMedia, /Flash, /3D** – मल्टीमीडिया ऑब्जेक्ट्स जो पेलोड्स को छिपा सकते हैं।
* **/EmbeddedFile /Filespec** – फ़ाइल अटैचमेंट (EXE, DLL, OLE, आदि)।
* **/ObjStm, /XFA, /AcroForm** – ऑब्जेक्ट स्ट्रीम या फ़ॉर्म जो आमतौर पर शेल-कोड छिपाने के लिए दुरुपयोग किए जाते हैं।
* **Incremental updates** – कई %%EOF मार्कर या एक बहुत बड़ा **/Prev** ऑफसेट डेटा को संकेत कर सकता है जो साइनिंग के बाद जोड़ा गया है ताकि AV को बायपास किया जा सके।

जब पिछले किसी भी टोकन के साथ संदिग्ध स्ट्रिंग्स (powershell, cmd.exe, calc.exe, base64, आदि) एक साथ दिखाई देते हैं, तो PDF को गहन विश्लेषण की आवश्यकता होती है।

---

## स्थैतिक विश्लेषण चीट-शीट
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
अतिरिक्त उपयोगी प्रोजेक्ट (सक्रिय रूप से बनाए रखा गया 2023-2025):
* **pdfcpu** – Go लाइब्रेरी/CLI जो PDFs को *lint*, *decrypt*, *extract*, *compress* और *sanitize* कर सकती है।
* **pdf-inspector** – ब्राउज़र-आधारित विज़ुअलाइज़र जो ऑब्जेक्ट ग्राफ और स्ट्रीम को रेंडर करता है।
* **PyMuPDF (fitz)** – स्क्रिप्ट करने योग्य Python इंजन जो सुरक्षित रूप से पृष्ठों को छवियों में रेंडर कर सकता है ताकि एक हार्डन किए गए सैंडबॉक्स में एम्बेडेड JS को डिटोनेट किया जा सके।

---

## हाल की हमले की तकनीकें (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC ने देखा कि खतरे के अभिनेता अंतिम **%%EOF** के बाद VBA मैक्रोज़ के साथ MHT-आधारित Word दस्तावेज़ को जोड़ रहे हैं, जिससे एक ऐसा फ़ाइल बनती है जो एक मान्य PDF और एक मान्य DOC दोनों है। AV इंजन केवल PDF परत को पार्स करते समय मैक्रो को छोड़ देते हैं। स्थैतिक PDF कीवर्ड साफ होते हैं, लेकिन `file` अभी भी `%PDF` प्रिंट करता है। किसी भी PDF को जो `<w:WordDocument>` स्ट्रिंग भी शामिल करता है, अत्यधिक संदिग्ध मानें।
* **Shadow-incremental updates (2024)** – प्रतिकूल पक्ष इंक्रीमेंटल अपडेट फीचर का दुरुपयोग करके एक दूसरा **/Catalog** डालते हैं जिसमें दुर्भावनापूर्ण `/OpenAction` होता है जबकि पहले संशोधन को बेनिग्न साइन किया गया रहता है। केवल पहले xref तालिका की जांच करने वाले उपकरणों को बायपास किया जाता है।
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – एक कमजोर **CoolType.dll** फ़ंक्शन एम्बेडेड CIDType2 फॉन्ट्स से पहुँचा जा सकता है, जिससे एक तैयार दस्तावेज़ खोले जाने पर उपयोगकर्ता के विशेषाधिकारों के साथ दूरस्थ कोड निष्पादन की अनुमति मिलती है। APSB24-29 में पैच किया गया, मई 2024।

---

## YARA त्वरित नियम टेम्पलेट
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

1. **Patch fast** – Acrobat/Reader को नवीनतम Continuous track पर रखें; अधिकांश RCE श्रृंखलाएँ जो जंगली में देखी गई हैं, वे n-day कमजोरियों का लाभ उठाती हैं जो महीनों पहले ठीक की गई थीं।
2. **Strip active content at the gateway** – JavaScript, एम्बेडेड फ़ाइलें और इनबाउंड PDFs से लॉन्च क्रियाओं को हटाने के लिए `pdfcpu sanitize` या `qpdf --qdf --remove-unreferenced` का उपयोग करें।
3. **Content Disarm & Reconstruction (CDR)** – सक्रिय वस्तुओं को त्यागते हुए दृश्य सत्यता को बनाए रखने के लिए PDFs को इमेज (या PDF/A) में एक सैंडबॉक्स होस्ट पर परिवर्तित करें।
4. **Block rarely-used features** – Reader में एंटरप्राइज “Enhanced Security” सेटिंग्स JavaScript, मल्टीमीडिया और 3D रेंडरिंग को अक्षम करने की अनुमति देती हैं।
5. **User education** – सामाजिक इंजीनियरिंग (इनवॉइस और रिज़्यूमे लूर्स) प्रारंभिक वेक्टर बनी रहती है; कर्मचारियों को संदिग्ध अटैचमेंट को IR को अग्रेषित करने के लिए सिखाएं।

## References

* JPCERT/CC – “MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file” (Aug 2023)
* Adobe – Security update for Acrobat and Reader (APSB24-29, May 2024)


{{#include ../../../banners/hacktricks-training.md}}
