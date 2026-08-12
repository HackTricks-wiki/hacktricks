# Document Steganography

{{#include ../../banners/hacktricks-training.md}}

कई document formats एकल data streams के बजाय structured containers होते हैं:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (embedded files, streams)
- Office OOXML (`.docx/.xlsx/.pptx` ZIPs होते हैं)
- Legacy RTF और OLE/Compound File Binary documents। RTF control words और groups को text-oriented format में store करता है, जबकि OLE compound files storage objects और streams की file-system-like hierarchy को expose करते हैं; दोनों में hidden या embedded data के लिए format-specific inspection आवश्यक है।<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Technique

PDF files में objects, streams, JavaScript और embedded files हो सकते हैं। Analysis के दौरान सामान्य tasks में शामिल हैं:

- Embedded attachments को extract करना।
- Objects को inspect करना आसान बनाने के लिए object streams को expand करना।
- JavaScript, embedded images और unusual streams की पहचान करना।<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Quick checks
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
`--qdf --object-streams=disable` combination अधिक पठनीय representation बनाता है और object streams हटा देता है, जिससे manual inspection आसान हो जाती है।<sup>[[2]](#references)</sup> फिर suspicious objects और strings के लिए `out.pdf` में search करें।

## Office OOXML

### तकनीक

Office Open XML files (`.docx`, `.xlsx`, और `.pptx`) Open Packaging Conventions का उपयोग करती हैं: यह parts और XML relationship files से बना ZIP-based package होता है।<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Package को relationship graph मानें और media, external relationships, तथा unusual custom parts का निरीक्षण करें।

व्यवहार में:

- Document XML और assets की directory tree होता है।
- `_rels/` relationship files external resources या hidden parts की ओर point कर सकती हैं।
- Embedded data अक्सर `word/media/`, custom XML parts, या unusual relationships में रहता है।

### त्वरित जाँचें
```bash
7z l file.docx
7z x file.docx -oout
```
फिर निरीक्षण करें:

- `word/document.xml`
- बाहरी relationships के लिए `word/_rels/`
- `word/media/` में embedded media

## References

- [1] [Poppler pdfdetach manual](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [qpdf documentation - QDF mode and object streams](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Open Packaging Conventions fundamentals](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Office Open XML file formats](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Compound File Binary File Format introduction](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - RTF specification reference](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
