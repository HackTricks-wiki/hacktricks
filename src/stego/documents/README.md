# Document Steganography

{{#include ../../banners/hacktricks-training.md}}

दस्तावेज़ अक्सर सिर्फ कंटेनर होते हैं:

- PDF (embedded files, streams)
- Office OOXML (`.docx/.xlsx/.pptx` are ZIPs)
- RTF / OLE पुराने फॉर्मैट

## PDF

### तकनीक

PDF एक संरचित कंटेनर है जिसमें objects, streams, और वैकल्पिक embedded files होते हैं। CTFs में आपको अक्सर निम्न करना होता है:

- embedded attachments निकालें
- Decompress/flatten object streams ताकि आप सामग्री खोज सकें
- छुपे हुए objects की पहचान करें (JS, embedded images, odd streams)

### त्वरित जाँच
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
फिर `out.pdf` के अंदर संदेहजनक ऑब्जेक्ट/स्ट्रिंग्स खोजें।

## Office OOXML

### तकनीक

OOXML को एक ZIP + XML relationship graph के रूप में समझें; payloads अक्सर media, relationships, या असामान्य custom parts में छिपे होते हैं।

OOXML फ़ाइलें ZIP containers होती हैं। इसका मतलब:

- दस्तावेज़ XML और assets का directory tree होता है।
- `_rels/` relationship फ़ाइलें external resources या hidden parts की ओर इशारा कर सकती हैं।
- Embedded डेटा अक्सर `word/media/`, custom XML parts, या असामान्य relationships में रहता है।

### त्वरित जांच
```bash
7z l file.docx
7z x file.docx -oout
```
फिर जाँच करें:

- `word/document.xml`
- `word/_rels/` बाहरी संबंधों के लिए
- `word/media/` में एम्बेडेड मीडिया

{{#include ../../banners/hacktricks-training.md}}
