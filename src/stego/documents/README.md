# Steganografija dokumenata

{{#include ../../banners/hacktricks-training.md}}

Mnogi formati dokumenata su strukturirani kontejneri, a ne pojedinačni tokovi podataka:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (ugrađene datoteke, tokovi)
- Office OOXML (`.docx/.xlsx/.pptx` su ZIP datoteke)
- Legacy RTF i OLE/Compound File Binary dokumenti. RTF čuva kontrolne reči i grupe u tekstualno orijentisanom formatu, dok OLE compound files izlažu hijerarhiju storage objekata i streamova nalik sistemu datoteka; oba zahtevaju inspekciju specifičnu za format radi pronalaženja skrivenih ili ugrađenih podataka.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Tehnika

PDF datoteke mogu da sadrže objekte, streamove, JavaScript i ugrađene datoteke. Tokom analize, uobičajeni zadaci uključuju:

- Ekstrakciju ugrađenih priloga.
- Proširivanje object streamova kako bi se objekti lakše pregledali.
- Identifikaciju JavaScript-a, ugrađenih slika i neuobičajenih streamova.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Brze provere
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Kombinacija `--qdf --object-streams=disable` daje čitljiviji prikaz i uklanja object streams, što olakšava ručnu proveru.<sup>[[2]](#references)</sup> Zatim pretražite `out.pdf` u potrazi za sumnjivim objektima i stringovima.

## Office OOXML

### Tehnika

Office Open XML datoteke (`.docx`, `.xlsx` i `.pptx`) koriste Open Packaging Conventions: paket zasnovan na ZIP formatu, sastavljen od delova i XML relationship datoteka.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Tretirajte paket kao relationship graph i pregledajte medije, external relationships i neuobičajene custom parts.

U praksi:

- Dokument je stablo direktorijuma sa XML datotekama i assetima.
- Relationship datoteke u `_rels/` mogu upućivati na external resources ili skrivene delove.
- Embedded data se često nalazi u `word/media/`, custom XML parts ili neuobičajenim relationships.

### Brze provere
```bash
7z l file.docx
7z x file.docx -oout
```
Zatim pregledajte:

- `word/document.xml`
- `word/_rels/` za eksterne relacije
- ugrađene medije u `word/media/`

## References

- [1] [Poppler pdfdetach priručnik](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [qpdf dokumentacija - QDF režim i tokovi objekata](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - osnove Open Packaging Conventions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Office Open XML formati datoteka](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - uvod u Compound File Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - referenca za RTF specifikaciju](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
