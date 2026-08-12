# Document Steganography

{{#include ../../banners/hacktricks-training.md}}

Many document formats are structured containers rather than single data streams:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (embedded files, streams)
- Office OOXML (`.docx/.xlsx/.pptx` are ZIPs)
- Legacy RTF and OLE/Compound File Binary documents. RTF stores control words and groups in a text-oriented format, while OLE compound files expose a file-system-like hierarchy of storage objects and streams; both warrant format-specific inspection for hidden or embedded data.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Technique

PDF files can contain objects, streams, JavaScript, and embedded files. During analysis, common tasks include:

- Extracting embedded attachments.
- Expanding object streams to make objects easier to inspect.
- Identifying JavaScript, embedded images, and unusual streams.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Quick checks

```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```

The `--qdf --object-streams=disable` combination produces a more readable representation and removes object streams, which makes manual inspection easier.<sup>[[2]](#references)</sup> Then search `out.pdf` for suspicious objects and strings.

## Office OOXML

### Technique

Office Open XML files (`.docx`, `.xlsx`, and `.pptx`) use Open Packaging Conventions: a ZIP-based package made of parts and XML relationship files.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Treat the package as a relationship graph and inspect media, external relationships, and unusual custom parts.

In practice:

- The document is a directory tree of XML and assets.
- The `_rels/` relationship files can point to external resources or hidden parts.
- Embedded data frequently lives in `word/media/`, custom XML parts, or unusual relationships.

### Quick checks

```bash
7z l file.docx
7z x file.docx -oout
```

Then inspect:

- `word/document.xml`
- `word/_rels/` for external relationships
- embedded media in `word/media/`

## References

- [1] [Poppler pdfdetach manual](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [qpdf documentation - QDF mode and object streams](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Open Packaging Conventions fundamentals](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Office Open XML file formats](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Compound File Binary File Format introduction](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - RTF specification reference](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)

{{#include ../../banners/hacktricks-training.md}}
