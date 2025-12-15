# Stego

{{#include ../banners/hacktricks-training.md}}

Esta sección se centra en **encontrar y extraer datos ocultos** de archivos (imágenes/audio/video/documentos/archivos) y de esteganografía basada en texto.

Si estás aquí por ataques criptográficos, ve a la sección **Crypto**.

## Entry Point

Aborda la esteganografía como un problema forense: identifica el contenedor real, enumera las ubicaciones de alta señal (metadatos, datos añadidos, archivos embebidos), y solo entonces aplica técnicas de extracción a nivel de contenido.

### Workflow & triage

Un flujo de trabajo estructurado que prioriza la identificación del contenedor, la inspección de metadatos/strings, carving, y la ramificación específica por formato.
{{#ref}}
workflow/README.md
{{#endref}}

### Images

Donde vive la mayor parte del stego en CTF: LSB/bit-planes (PNG/BMP), rarezas en chunks/formatos de archivo, herramientas JPEG y trucos con GIF multi-frame.
{{#ref}}
images/README.md
{{#endref}}

### Audio

Mensajes en espectrograma, sample LSB embedding, y tonos de teclado telefónico (DTMF) son patrones recurrentes.
{{#ref}}
audio/README.md
{{#endref}}

### Text

Si el texto se muestra normalmente pero se comporta de forma inesperada, considera Unicode homoglyphs, zero-width characters, o codificación basada en espacios en blanco.
{{#ref}}
text/README.md
{{#endref}}

### Documents

PDFs y archivos Office son contenedores ante todo; los ataques suelen girar en torno a archivos/streams embebidos, grafos de objetos/relaciones, y extracción ZIP.
{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

La entrega de payloads frecuentemente usa archivos con apariencia válida (p.ej., GIF/PNG) que contienen payloads de texto delimitados por marcadores, en vez de ocultación a nivel de píxeles.
{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
