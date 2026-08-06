# Esteganografía de documentos

{{#include ../../banners/hacktricks-training.md}}

A menudo, los documentos son simplemente contenedores:

- PDF (archivos incrustados, streams)
- Office OOXML (`.docx/.xlsx/.pptx` son ZIPs)
- Formatos legacy RTF / OLE

## PDF

### Técnica

PDF es un contenedor estructurado con objetos, streams y archivos incrustados opcionales. En los CTFs, a menudo necesitas:

- Extraer los attachments incrustados
- Descomprimir/aplanar los object streams para poder buscar contenido
- Identificar objetos ocultos (JS, imágenes incrustadas, streams inusuales)

### Comprobaciones rápidas
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Luego busca objetos/cadenas sospechosos dentro de `out.pdf`.

## Office OOXML

### Técnica

Trata OOXML como un grafo de relaciones ZIP + XML; los payloads suelen ocultarse en media, relaciones o custom parts poco habituales.

Los archivos OOXML son contenedores ZIP. Esto significa que:

- El documento es un árbol de directorios de XML y recursos.
- Los archivos de relaciones `_rels/` pueden apuntar a recursos externos o a partes ocultas.
- Los datos embebidos suelen encontrarse en `word/media/`, custom XML parts o relaciones inusuales.

### Comprobaciones rápidas
```bash
7z l file.docx
7z x file.docx -oout
```
Luego inspecciona:

- `word/document.xml`
- `word/_rels/` para las relaciones externas
- medios incrustados en `word/media/`


{{#include ../../banners/hacktricks-training.md}}
