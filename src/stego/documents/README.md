# Steganografia ya Hati

{{#include ../../banners/hacktricks-training.md}}

Miundo mingi ya hati ni kontena zenye muundo badala ya mitiririko moja ya data:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (faili zilizopachikwa, streams)
- Office OOXML (`.docx/.xlsx/.pptx` ni ZIP)
- RTF za zamani na hati za OLE/Compound File Binary. RTF huhifadhi maneno ya udhibiti na vikundi katika muundo unaolenga maandishi, huku faili za OLE compound zikiwa na mpangilio wa vitu vya hifadhi na streams unaofanana na mfumo wa faili; zote zinahitaji ukaguzi mahususi wa umbizo ili kugundua data iliyofichwa au kupachikwa.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Mbinu

Faili za PDF zinaweza kuwa na objects, streams, JavaScript na faili zilizopachikwa. Wakati wa uchanganuzi, kazi za kawaida ni pamoja na:

- Kutoa viambatisho vilivyopachikwa.
- Kupanua object streams ili kurahisisha ukaguzi wa objects.
- Kutambua JavaScript, picha zilizopachikwa na streams zisizo za kawaida.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Ukaguzi wa haraka

```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```

Mchanganyiko wa `--qdf --object-streams=disable` hutoa uwakilishi unaosomeka zaidi na kuondoa object streams, hivyo kurahisisha ukaguzi wa mikono.<sup>[[2]](#references)</sup> Kisha tafuta objects na strings zinazotia shaka katika `out.pdf`.

## Office OOXML

### Mbinu

Faili za Office Open XML (`.docx`, `.xlsx`, na `.pptx`) hutumia Open Packaging Conventions: kifurushi kinachotegemea ZIP na kinachoundwa na sehemu na faili za XML za relationships.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Chukulia kifurushi kama grafu ya relationships na kagua media, relationships za nje, na sehemu maalum zisizo za kawaida.

Kwa vitendo:

- Hati ni mti wa saraka wenye XML na assets.
- Faili za relationships za `_rels/` zinaweza kuelekeza kwenye rasilimali za nje au sehemu zilizofichwa.
- Data iliyopachikwa mara nyingi huwa katika `word/media/`, sehemu za custom XML, au relationships zisizo za kawaida.

### Ukaguzi wa haraka

```bash
7z l file.docx
7z x file.docx -oout
```

Kisha kagua:

- `word/document.xml`
- `word/_rels/` kwa external relationships
- media zilizopachikwa katika `word/media/`

## References

- [1] [Mwongozo wa Poppler pdfdetach](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [Nyaraka za qpdf - mode ya QDF na object streams](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Misingi ya Open Packaging Conventions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Miundo ya faili za Office Open XML](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Utangulizi wa Compound File Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - Rejeleo la specification ya RTF](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
