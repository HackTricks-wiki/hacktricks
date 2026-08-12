# Dokument-steganografie

{{#include ../../banners/hacktricks-training.md}}

Baie dokumentformate is gestruktureerde houers eerder as enkele datastrome:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (ingebedde lêers, strome)
- Office OOXML (`.docx/.xlsx/.pptx` is ZIP-lêers)
- Verouderde RTF- en OLE/Compound File Binary-dokumente. RTF stoor beheerswoorde en groepe in 'n teksgeoriënteerde formaat, terwyl OLE-saamgestelde lêers 'n lêerstelselagtige hiërargie van stoorobjekte en strome blootstel; albei vereis formaatspesifieke inspeksie vir versteekte of ingebedde data.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Tegniek

PDF-lêers kan objekte, strome, JavaScript en ingebedde lêers bevat. Tydens ontleding sluit algemene take die volgende in:

- Onttrekking van ingebedde aanhegsels.
- Uitbreiding van objekstrome om objekte makliker te kan inspekteer.
- Identifisering van JavaScript, ingebedde beelde en ongewone strome.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Vinnige kontroles
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Die `--qdf --object-streams=disable`-kombinasie lewer ’n meer leesbare voorstelling en verwyder object streams, wat handmatige inspeksie makliker maak.<sup>[[2]](#references)</sup> Soek dan in `out.pdf` vir verdagte objects en strings.

## Office OOXML

### Tegniek

Office Open XML-lêers (`.docx`, `.xlsx`, en `.pptx`) gebruik Open Packaging Conventions: ’n ZIP-gebaseerde pakket wat uit parts en XML relationship files bestaan.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Behandel die pakket as ’n relationship graph en inspekteer media, external relationships, en ongewone custom parts.

In die praktyk:

- Die dokument is ’n gidsboom van XML en assets.
- Die `_rels/` relationship files kan na eksterne resources of versteekte parts verwys.
- Embedded data word dikwels in `word/media/`, custom XML parts, of ongewone relationships gestoor.

### Vinnige kontroles
```bash
7z l file.docx
7z x file.docx -oout
```
Inspekteer dan:

- `word/document.xml`
- `word/_rels/` vir eksterne relationships
- ingebedde media in `word/media/`

## References

- [1] [Poppler pdfdetach-handleiding](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [qpdf-dokumentasie - QDF-modus en object streams](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - grondbeginsels van Open Packaging Conventions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Office Open XML-lêerformate](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - inleiding tot Compound File Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - RTF-spesifikasieverwysing](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
