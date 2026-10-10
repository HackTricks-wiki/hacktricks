# दस्तावेज़ स्टेगनोग्राफी

{{#include ../../banners/hacktricks-training.md}}

कई दस्तावेज़ फ़ॉर्मैट एकल डेटा स्ट्रीम के बजाय संरचित कंटेनर होते हैं:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (एम्बेड की गई फ़ाइलें, स्ट्रीम)
- Office OOXML (`.docx/.xlsx/.pptx` ZIP फ़ाइलें हैं)
- Legacy RTF और OLE/Compound File Binary दस्तावेज़। RTF, कंट्रोल वर्ड और ग्रुप को टेक्स्ट-आधारित फ़ॉर्मैट में संग्रहीत करता है, जबकि OLE compound files स्टोरेज ऑब्जेक्ट और स्ट्रीम की फ़ाइल-सिस्टम जैसी पदानुक्रम संरचना उपलब्ध कराते हैं; छिपे या एम्बेड किए गए डेटा की जाँच के लिए दोनों का फ़ॉर्मैट-विशिष्ट निरीक्षण आवश्यक है।<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### तकनीक

PDF फ़ाइलों में ऑब्जेक्ट, स्ट्रीम, JavaScript और एम्बेड की गई फ़ाइलें हो सकती हैं। विश्लेषण के दौरान आम कार्यों में शामिल हैं:

- एम्बेड किए गए अटैचमेंट निकालना।
- ऑब्जेक्ट स्ट्रीम को विस्तार करना, ताकि ऑब्जेक्ट का निरीक्षण करना आसान हो।
- JavaScript, एम्बेड की गई इमेज और असामान्य स्ट्रीम की पहचान करना।<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### त्वरित जाँचें

```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```

`--qdf --object-streams=disable` संयोजन अधिक पठनीय रूप देता है और object streams हटाता है, जिससे मैन्युअल निरीक्षण आसान हो जाता है।<sup>[[2]](#references)</sup> फिर संदिग्ध objects और strings के लिए `out.pdf` में खोजें।

## Office OOXML

### तकनीक

Office Open XML फ़ाइलें (`.docx`, `.xlsx`, और `.pptx`) Open Packaging Conventions का उपयोग करती हैं: यह parts और XML relationship फ़ाइलों से बना ZIP-आधारित पैकेज होता है।<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> पैकेज को relationships के graph के रूप में देखें और media, external relationships, तथा असामान्य custom parts का निरीक्षण करें।

व्यवहार में:

- दस्तावेज़ XML और assets का एक directory tree होता है।
- `_rels/` relationship फ़ाइलें external resources या hidden parts की ओर संकेत कर सकती हैं।
- एम्बेड किया गया डेटा अक्सर `word/media/`, custom XML parts, या असामान्य relationships में होता है।

### त्वरित जाँचें

```bash
7z l file.docx
7z x file.docx -oout
```

फिर निरीक्षण करें:

- `word/document.xml`
- `word/_rels/` for external relationships
- embedded media in `word/media/`

## References

- [1] [Poppler pdfdetach मैनुअल](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [qpdf दस्तावेज़ - QDF mode और object streams](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Open Packaging Conventions की मूल बातें](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Office Open XML फ़ाइल फ़ॉर्मैट](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Compound File Binary File Format का परिचय](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - RTF specification संदर्भ](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
