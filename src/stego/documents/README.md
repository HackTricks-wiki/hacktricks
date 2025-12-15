# Document Steganography

{{#include ../../banners/hacktricks-training.md}}

Los documentos a menudo son solo contenedores:

- PDF (archivos incrustados, flujos)
- Office OOXML (`.docx/.xlsx/.pptx` son ZIPs)
- RTF / OLE formatos heredados

## PDF

### Técnica

PDF es un contenedor estructurado con objetos, flujos y archivos incrustados opcionales. En CTFs a menudo necesitas:

- Extraer adjuntos incrustados
- Descomprimir/aplanar flujos de objetos para poder buscar contenido
- Identificar objetos ocultos (JS, imágenes incrustadas, flujos extraños)

### Comprobaciones rápidas
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Luego busca dentro de `out.pdf` objetos/cadenas sospechosas.

## Office OOXML

### Técnica

Trata OOXML como un grafo de relaciones ZIP + XML; los payloads a menudo se ocultan en media, en relaciones o en partes personalizadas inusuales.

OOXML files are ZIP containers. That means:

- The document is a directory tree of XML and assets.
- The `_rels/` relationship files can point to external resources or hidden parts.
- Embedded data frequently lives in `word/media/`, custom XML parts, or unusual relationships.

### Comprobaciones rápidas
```bash
7z l file.docx
7z x file.docx -oout
```
A continuación, inspecciona:

- `word/document.xml`
- `word/_rels/` para relaciones externas
- medios incrustados en `word/media/`

{{#include ../../banners/hacktricks-training.md}}
