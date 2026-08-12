# Stego

{{#include ../banners/hacktricks-training.md}}

Esta sección se centra en **encontrar y extraer datos ocultos** de imágenes, audio, vídeo, documentos, archivos y texto. La esteganografía oculta la existencia de una comunicación incrustando datos dentro de otros datos.<sup>[[1]](#references)</sup>

Si buscas ataques criptográficos, ve a la sección **Crypto**.

## Entry Point

Aborda la esteganografía como un problema forense: identifica el contenedor real, enumera las ubicaciones con mayor probabilidad de contener información (metadatos, datos añadidos, archivos incrustados) y solo después aplica técnicas de extracción a nivel de contenido.

### Workflow & triage

Un flujo de trabajo estructurado que prioriza la identificación del contenedor, la inspección de metadatos y cadenas, el carving y la ramificación específica del formato.

{{#ref}}
workflow/README.md
{{#endref}}

### Images

Aquí se encuentra la mayor parte de la esteganografía en CTF: LSB/planos de bits (PNG/BMP), peculiaridades de chunks y formatos de archivo, herramientas para JPEG y trucos con GIF de varios frames.

{{#ref}}
images/README.md
{{#endref}}

### Audio

Los mensajes en espectrogramas, la incrustación LSB en muestras y los tonos del teclado telefónico (DTMF) son patrones recurrentes.

{{#ref}}
audio/README.md
{{#endref}}

### Text

Si el texto se muestra con normalidad, pero se comporta de forma inesperada, considera homoglifos Unicode, caracteres de ancho cero o codificación basada en espacios en blanco.

{{#ref}}
text/README.md
{{#endref}}

### Documents

Los PDF y archivos de Office son, ante todo, contenedores; los ataques suelen centrarse en archivos/streams incrustados, grafos de objetos/relaciones y extracción de ZIP.

{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

La entrega de payloads puede utilizar archivos con apariencia válida, como imágenes GIF o PNG, que contienen payloads de texto delimitados por marcadores en lugar de ocultar datos en los píxeles.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [Glosario de NIST CSRC - Esteganografía](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
