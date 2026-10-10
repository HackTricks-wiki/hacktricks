# Steganografija dokumenata

{{#include ../../banners/hacktricks-training.md}}

Mnogi formati dokumenata predstavljaju strukturirane kontejnere, a ne pojedinačne tokove podataka:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (ugrađene datoteke, tokovi)
- Office OOXML (`.docx/.xlsx/.pptx` su ZIP arhive)
- Stariji RTF i OLE/Compound File Binary dokumenti. RTF čuva kontrolne reči i grupe u formatu orijentisanom na tekst, dok OLE složene datoteke izlažu hijerarhiju objekata za skladištenje i tokova nalik sistemu datoteka; oba formata zahtevaju namensku proveru u potrazi za skrivenim ili ugrađenim podacima.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Tehnika

PDF datoteke mogu sadržati objekte, tokove, JavaScript i ugrađene datoteke. Uobičajeni zadaci tokom analize uključuju:

- Izdvajanje ugrađenih priloga.
- Proširivanje tokova objekata kako bi se objekti lakše pregledali.
- Pronalaženje JavaScript-a, ugrađenih slika i neuobičajenih tokova.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Brze provere

```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```

Kombinacija `--qdf --object-streams=disable` daje čitljiviji prikaz i uklanja object streams, što olakšava ručnu proveru.<sup>[[2]](#references)</sup> Zatim potražite sumnjive objekte i stringove u `out.pdf`.

## Office OOXML

### Tehnika

Office Open XML datoteke (`.docx`, `.xlsx` i `.pptx`) koriste Open Packaging Conventions: ZIP-paket sastavljen od delova i XML datoteka relacija.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Tretirajte paket kao graf relacija i pregledajte medije, spoljne relacije i neuobičajene prilagođene delove.

U praksi:

- Dokument je stablo direktorijuma sastavljeno od XML-a i resursa.
- Datoteke relacija `_rels/` mogu upućivati na spoljne resurse ili skrivene delove.
- Ugrađeni podaci se često nalaze u `word/media/`, prilagođenim XML delovima ili neuobičajenim relacijama.

### Brze provere

```bash
7z l file.docx
7z x file.docx -oout
```

Zatim pregledajte:

- `word/document.xml`
- `word/_rels/` za spoljne relacije
- ugrađene medije u `word/media/`

## References

- [1] [Priručnik za Poppler pdfdetach](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [qpdf dokumentacija - QDF režim i tokovi objekata](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Osnove Open Packaging Conventions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Formati datoteka Office Open XML](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Uvod u Compound File Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - Referenca za RTF specifikaciju](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
