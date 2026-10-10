# Steganografia dokumentów

{{#include ../../banners/hacktricks-training.md}}

Wiele formatów dokumentów to uporządkowane kontenery, a nie pojedyncze strumienie danych:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (osadzone pliki, strumienie)
- Office OOXML (`.docx/.xlsx/.pptx` to pliki ZIP)
- Starsze dokumenty RTF i OLE/Compound File Binary. RTF przechowuje słowa sterujące i grupy w formacie tekstowym, natomiast pliki złożone OLE udostępniają hierarchię obiektów magazynujących i strumieni przypominającą system plików; oba formaty wymagają inspekcji dostosowanej do danego formatu w celu wykrycia ukrytych lub osadzonych danych.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Technika

Pliki PDF mogą zawierać obiekty, strumienie, JavaScript i osadzone pliki. Typowe zadania podczas analizy obejmują:

- Wyodrębnianie osadzonych załączników.
- Rozpakowywanie strumieni obiektów, aby ułatwić inspekcję obiektów.
- Identyfikowanie JavaScriptu, osadzonych obrazów i nietypowych strumieni.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Szybkie kontrole

```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```

Połączenie `--qdf --object-streams=disable` tworzy bardziej czytelną reprezentację i usuwa strumienie obiektów, co ułatwia ręczną inspekcję.<sup>[[2]](#references)</sup> Następnie wyszukaj podejrzane obiekty i ciągi znaków w `out.pdf`.

## Office OOXML

### Technika

Pliki Office Open XML (`.docx`, `.xlsx` i `.pptx`) korzystają z Open Packaging Conventions: pakietu opartego na ZIP-ie, złożonego z części i plików XML z relacjami.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Traktuj pakiet jako graf relacji i sprawdzaj media, zewnętrzne relacje oraz nietypowe części niestandardowe.

W praktyce:

- Dokument to drzewo katalogów z plikami XML i zasobami.
- Pliki relacji w `_rels/` mogą wskazywać na zasoby zewnętrzne lub ukryte części.
- Osadzone dane często znajdują się w `word/media/`, częściach niestandardowego XML-a lub nietypowych relacjach.

### Szybkie kontrole

```bash
7z l file.docx
7z x file.docx -oout
```

Następnie sprawdź:

- `word/document.xml`
- `word/_rels/` pod kątem relacji zewnętrznych
- osadzone multimedia w `word/media/`

## References

- [1] [Podręcznik Poppler pdfdetach](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [Dokumentacja qpdf - tryb QDF i strumienie obiektów](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - podstawy Open Packaging Conventions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - formaty plików Office Open XML](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - wprowadzenie do formatu Compound File Binary File](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - opis specyfikacji RTF](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
