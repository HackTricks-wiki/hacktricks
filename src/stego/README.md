# Estego

{{#include ../banners/hacktricks-training.md}}

Esta sección se centra en **encontrar y extraer datos ocultos** de imágenes, audio, video, documentos, archivos comprimidos y texto. La esteganografía oculta la existencia de una comunicación al incrustar datos dentro de otros datos.<sup>[[1]](#references)</sup>

Si buscas ataques criptográficos, ve a la sección **Crypto**.

## Punto de partida

Aborda la esteganografía como un problema forense: identifica el contenedor real, examina las ubicaciones con más probabilidades de contener datos (metadatos, datos añadidos al final, archivos incrustados) y solo entonces aplica técnicas de extracción a nivel de contenido.

### Flujo de trabajo y análisis inicial

Un flujo de trabajo estructurado que prioriza la identificación del contenedor, la inspección de metadatos y cadenas, el carving y la ramificación según el formato.

{{#ref}}
workflow/README.md
{{#endref}}

### Imágenes

Donde se encuentra la mayor parte de la esteganografía de CTF: LSB/planos de bits (PNG/BMP), peculiaridades de fragmentos y formatos de archivo, herramientas para JPEG y trucos con GIF multiframe.

{{#ref}}
images/README.md
{{#endref}}

### Audio

Los mensajes en espectrogramas, la incrustación en LSB de muestras y los tonos de teclado telefónico (DTMF) son patrones recurrentes.

{{#ref}}
audio/README.md
{{#endref}}

### Texto

Si el texto se muestra con normalidad, pero se comporta de forma inesperada, considera los homoglifos Unicode, los caracteres de ancho cero o la codificación basada en espacios en blanco.

{{#ref}}
text/README.md
{{#endref}}

### Documentos

Los PDF y archivos de Office son, ante todo, contenedores; los ataques suelen girar en torno a archivos o flujos incrustados, grafos de objetos y relaciones, y la extracción de ZIP.

{{#ref}}
documents/README.md
{{#endref}}

### Malware y esteganografía para la entrega de payloads

La entrega de payloads puede usar archivos que parecen válidos, como imágenes GIF o PNG, que contienen payloads de texto delimitados por marcadores en lugar de ocultar datos en los píxeles.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [Glosario NIST CSRC - Esteganografía](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
