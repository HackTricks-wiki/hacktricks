# Document Steganography

{{#include ../../banners/hacktricks-training.md}}

Documents अक्सर केवल containers होते हैं:

- PDF (embedded files, streams)
- Office OOXML (`.docx/.xlsx/.pptx` ZIPs होते हैं)
- RTF / OLE legacy formats

## PDF

### Technique

PDF objects, streams और optional embedded files वाला एक structured container है। CTFs में आपको अक्सर यह करना पड़ता है:

- Embedded attachments extract करना
- Object streams को decompress/flatten करना ताकि आप content में search कर सकें
- Hidden objects (JS, embedded images, असामान्य streams) identify करना

### Quick checks
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
फिर संदिग्ध objects/strings के लिए `out.pdf` के अंदर search करें।

## Office OOXML

### Technique

OOXML को ZIP + XML relationship graph की तरह समझें; payloads अक्सर media, relationships या अजीब custom parts में छिपे होते हैं।

OOXML files ZIP containers होती हैं। इसका मतलब है:

- Document XML और assets की directory tree होता है।
- `_rels/` relationship files external resources या hidden parts की ओर point कर सकती हैं।
- Embedded data अक्सर `word/media/`, custom XML parts या unusual relationships में रहती है।

### Quick checks
```bash
7z l file.docx
7z x file.docx -oout
```
फिर निरीक्षण करें:

- `word/document.xml`
- बाहरी relationships के लिए `word/_rels/`
- `word/media/` में embedded media


{{#include ../../banners/hacktricks-training.md}}
