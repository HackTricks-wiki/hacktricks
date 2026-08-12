# Steganografia ya Hati

{{#include ../../banners/hacktricks-training.md}}

Miundo mingi ya hati ni structured containers badala ya data streams moja:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (embedded files, streams)
- Office OOXML (`.docx/.xlsx/.pptx` ni ZIPs)
- Legacy RTF na OLE/Compound File Binary documents. RTF huhifadhi control words na groups katika format inayolenga maandishi, huku OLE compound files ikifichua hierarchy inayofanana na file system ya storage objects na streams; zote zinahitaji ukaguzi unaolenga format husika ili kubaini data iliyofichwa au iliyopachikwa.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Technique

PDF files zinaweza kuwa na objects, streams, JavaScript, na embedded files. Wakati wa analysis, kazi za kawaida zinajumuisha:

- Kutoa embedded attachments.
- Kupanua object streams ili kurahisisha ukaguzi wa objects.
- Kubaini JavaScript, embedded images, na streams zisizo za kawaida.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Ukaguzi wa haraka
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Mchanganyiko wa `--qdf --object-streams=disable` hutokeza uwakilishi unaosomeka zaidi na huondoa object streams, jambo linalorahisisha ukaguzi wa mikono.<sup>[[2]](#references)</sup> Kisha tafuta objects na strings zinazotiliwa shaka ndani ya `out.pdf`.

## Office OOXML

### Mbinu

Faili za Office Open XML (`.docx`, `.xlsx`, na `.pptx`) hutumia Open Packaging Conventions: package inayotegemea ZIP iliyoundwa na parts na faili za XML relationship.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Ichukulie package kama relationship graph na kagua media, external relationships, na custom parts zisizo za kawaida.

Kwa vitendo:

- Document ni mti wa directories wenye XML na assets.
- Faili za relationships za `_rels/` zinaweza kuelekeza kwenye external resources au parts zilizofichwa.
- Data iliyopachikwa mara nyingi hupatikana katika `word/media/`, custom XML parts, au relationships zisizo za kawaida.

### Ukaguzi wa haraka
```bash
7z l file.docx
7z x file.docx -oout
```
Kisha chunguza:

- `word/document.xml`
- `word/_rels/` kwa external relationships
- media zilizopachikwa katika `word/media/`

## References

- [1] [Mwongozo wa Poppler pdfdetach](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [Nyaraka za qpdf - QDF mode na object streams](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Misingi ya Open Packaging Conventions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Miundo ya faili ya Office Open XML](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Utangulizi wa Compound File Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - Rejeleo la RTF specification](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
