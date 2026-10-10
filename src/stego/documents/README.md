# Esteganografía en documentos

{{#include ../../banners/hacktricks-training.md}}

Muchos formatos de documentos son contenedores estructurados, en lugar de flujos de datos únicos:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (archivos incrustados, streams)
- Office OOXML (`.docx/.xlsx/.pptx` son ZIPs)
- Documentos RTF y OLE/Compound File Binary heredados. RTF almacena palabras de control y grupos en un formato orientado a texto, mientras que los archivos compuestos OLE exponen una jerarquía de objetos de almacenamiento y streams similar a un sistema de archivos; ambos requieren una inspección específica del formato para detectar datos ocultos o incrustados.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Técnica

Los archivos PDF pueden contener objetos, streams, JavaScript y archivos incrustados. Durante el análisis, las tareas habituales incluyen:

- Extraer archivos adjuntos incrustados.
- Expandir los streams de objetos para facilitar la inspección de los objetos.
- Identificar JavaScript, imágenes incrustadas y streams inusuales.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Comprobaciones rápidas

```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```

La combinación `--qdf --object-streams=disable` produce una representación más legible y elimina los flujos de objetos, lo que facilita la inspección manual.<sup>[[2]](#references)</sup> Luego, busca objetos y cadenas sospechosos en `out.pdf`.

## Office OOXML

### Técnica

Los archivos Office Open XML (`.docx`, `.xlsx` y `.pptx`) usan Open Packaging Conventions: un paquete basado en ZIP compuesto por partes y archivos XML de relaciones.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Trata el paquete como un grafo de relaciones e inspecciona los medios, las relaciones externas y las partes personalizadas inusuales.

En la práctica:

- El documento es un árbol de directorios con XML y recursos.
- Los archivos de relaciones `_rels/` pueden apuntar a recursos externos o partes ocultas.
- Los datos incrustados suelen estar en `word/media/`, en partes XML personalizadas o en relaciones inusuales.

### Comprobaciones rápidas

```bash
7z l file.docx
7z x file.docx -oout
```

Luego inspecciona:

- `word/document.xml`
- `word/_rels/` para las relaciones externas
- los archivos multimedia incrustados en `word/media/`

## References

- [1] [Manual de pdfdetach de Poppler](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [Documentación de qpdf: modo QDF y flujos de objetos](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn: fundamentos de Open Packaging Conventions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376: formatos de archivo Office Open XML](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications: introducción al formato de archivo binario compuesto](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications: referencia de la especificación RTF](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
