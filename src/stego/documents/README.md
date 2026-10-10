# Steganografia nei documenti

{{#include ../../banners/hacktricks-training.md}}

Molti formati di documento sono contenitori strutturati, anziché singoli flussi di dati:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (file incorporati, flussi)
- Office OOXML (`.docx/.xlsx/.pptx` sono archivi ZIP)
- Documenti RTF legacy e OLE/Compound File Binary. RTF memorizza parole di controllo e gruppi in un formato orientato al testo, mentre i file composti OLE espongono una gerarchia di oggetti di archiviazione e flussi simile a un file system; entrambi richiedono un’ispezione specifica del formato per individuare dati nascosti o incorporati.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Tecnica

I file PDF possono contenere oggetti, flussi, JavaScript e file incorporati. Durante l’analisi, le attività comuni includono:

- Estrarre gli allegati incorporati.
- Espandere i flussi di oggetti per facilitare l’ispezione degli oggetti.
- Individuare JavaScript, immagini incorporate e flussi insoliti.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Controlli rapidi

```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```

La combinazione `--qdf --object-streams=disable` produce una rappresentazione più leggibile e rimuove gli object stream, facilitando l’ispezione manuale.<sup>[[2]](#references)</sup> Cerca quindi in `out.pdf` oggetti e stringhe sospetti.

## Office OOXML

### Tecnica

I file Office Open XML (`.docx`, `.xlsx` e `.pptx`) usano Open Packaging Conventions: un pacchetto basato su ZIP composto da parti e file XML di relazione.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Considera il pacchetto come un grafo di relazioni e ispeziona i media, le relazioni esterne e le parti personalizzate insolite.

In pratica:

- Il documento è un albero di directory composto da XML e risorse.
- I file di relazione in `_rels/` possono puntare a risorse esterne o a parti nascoste.
- I dati incorporati si trovano spesso in `word/media/`, in parti XML personalizzate o in relazioni insolite.

### Controlli rapidi

```bash
7z l file.docx
7z x file.docx -oout
```

Quindi ispeziona:

- `word/document.xml`
- `word/_rels/` per le relazioni esterne
- i media incorporati in `word/media/`

## References

- [1] [Manuale di Poppler pdfdetach](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [Documentazione di qpdf - modalità QDF e flussi di oggetti](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Fondamenti di Open Packaging Conventions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Formati di file Office Open XML](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Introduzione al formato Compound File Binary](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - Riferimento alle specifiche RTF](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
